"""Scan orchestration worker (arq).

Pipeline per scan:
  ingest (materialize + index) -> static scan (Semgrep + enabled MCP servers)
  -> agentic AI review (Foundry) -> persist findings + summary.

Every step emits an event that is (a) published to Redis for live SSE and
(b) persisted to AgentEvent for replay.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone

from arq.connections import RedisSettings
from sqlalchemy import select

from app import events
from app.ai.agent import run_review
from app.ai.foundry import get_foundry_client
from app.config import settings
from app.db import SessionLocal, init_models
from app.ingestion import index_files, materialize
from app.models import (
    Artifact,
    ArtifactFile,
    ArtifactStatus,
    AgentEvent,
    Finding,
    FindingSource,
    FindingState,
    McpServer,
    Scan,
    ScanStatus,
    Severity,
)
from app.runtime_config import get_foundry_config, get_scanner_config
from app.scanners.endpoints import extract_endpoints
from app.scanners.mcp_client import McpClient
from app.scanners.semgrep import SemgrepScanner
from app.scanners.sonarqube import SonarScanner
from app.storage import get_storage


def _now() -> datetime:
    return datetime.now(timezone.utc)


# Default pipeline when a scan doesn't specify: all static scanners + AI review.
# Each is independently gated (semgrep/sonarqube need their app-level enable too).
_DEFAULT_SCANNERS = ["semgrep", "sonarqube", "mcp", "ai"]

# Re-runnable stages (UI buttons). Static scanners replace their own findings;
# "ai" re-runs the reviewer/judge/exploit pipeline over current static candidates.
RERUNNABLE_STAGES = ("semgrep", "sonarqube", "ai")

_RISK_WEIGHT = {"critical": 10.0, "high": 6.0, "medium": 3.0, "low": 1.0, "info": 0.2}


async def _ai_review(session, scan: Scan, artifact: Artifact, workdir: str,
                     candidates: list[dict], emit) -> dict:
    """Run the AI reviewer/judge/exploit pipeline. Returns run_review's result."""
    async def read_file(rel: str) -> str | None:
        return _safe_read(workdir, rel)

    cfg = await get_foundry_config(session)
    client = get_foundry_client(cfg)
    reviewer_override = (scan.config or {}).get("model") or None
    roles = cfg.resolve_roles(reviewer_override=reviewer_override)
    mode = "MOCK (no endpoint)" if cfg.mock else f"LIVE → {cfg.endpoint}"
    reviewers = ", ".join(r.deployment for r in roles.reviewers)
    judge = roles.judge.deployment if roles.judge else "none"
    await emit({"type": "log", "message": (
        f"AI pipeline [{mode}] — chat={roles.chat.deployment} "
        f"reviewers=[{reviewers}] judge={judge}")})

    artifact_files = (await session.execute(
        select(ArtifactFile).where(
            ArtifactFile.artifact_id == artifact.id, ArtifactFile.included.is_(True)
        )
    )).scalars().all()

    selected_paths = (scan.config or {}).get("file_paths")
    if selected_paths:
        artifact_files = [
            f for f in artifact_files
            if any(f.path == p or f.path.startswith(p.rstrip("/") + "/")
                   for p in selected_paths)
        ]
        await emit({"type": "log", "message":
                    f"Scoped to {len(artifact_files)} files ({len(selected_paths)} selections)"})

    files = [{"path": f.path, "language": f.language, "size": f.size_bytes}
             for f in artifact_files]

    return await run_review(
        client=client,
        roles=roles,
        instructions=(scan.config or {}).get("instructions"),
        files=files,
        candidates=candidates,
        read_file=read_file,
        emit=emit,
    )


async def run_scan(ctx: dict, scan_id: str) -> None:
    async with SessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if scan is None:
            return
        seq = {"n": 0}
        # Reviewers now run batches concurrently, so emit() can be called from
        # several tasks at once. The SQLAlchemy AsyncSession (one asyncpg
        # connection) can only do one operation at a time — serialize the DB
        # write to avoid "another operation is in progress" crashes.
        emit_lock = asyncio.Lock()

        async def emit(event: dict) -> None:
            event = {"ts": _now().isoformat(), **event}
            await events.publish(scan_id, event)
            if event.get("type") not in {"token", "heartbeat"}:  # tokens stay live-only
                async with emit_lock:
                    seq["n"] += 1
                    session.add(AgentEvent(scan_id=scan_id, seq=seq["n"],
                                           type=event.get("type", "log"), payload=event))
                    await session.commit()

        scan.status = ScanStatus.running
        scan.started_at = _now()
        await session.commit()
        await emit({"type": "status", "status": "running"})

        requested = set((scan.config or {}).get("scanners", _DEFAULT_SCANNERS))
        try:
            artifact = await session.get(Artifact, scan.artifact_id)
            workdir = await _ingest(session, artifact, emit)

            candidates = await _static_scan(session, scan, artifact, workdir, emit)

            await emit({"type": "status", "status": "extracting endpoints"})
            endpoints = await extract_endpoints(workdir)
            await emit({"type": "log", "message":
                        f"Extracted {len(endpoints)} endpoints"})

            if "ai" in requested:
                result = await _ai_review(
                    session, scan, artifact, workdir, candidates, emit
                )
                await _persist_findings(session, scan, result["findings"])
                scan.summary = {**result["summary"], "endpoints": endpoints}
                needs_review = result["summary"].get("needs_review")
            else:
                # No AI requested — persist the raw static candidates directly so
                # "just Semgrep" / "just SonarQube" runs surface their findings.
                findings = [_candidate_to_finding(c) for c in candidates]
                await _persist_findings(session, scan, findings)
                scan.summary = {**_summary_from_finding_dicts(findings),
                                "endpoints": endpoints}
                needs_review = False
                await emit({"type": "log", "message":
                            f"Static-only run: persisted {len(findings)} candidates "
                            f"as findings (no AI review requested)"})

            scan.status = ScanStatus.needs_review if needs_review else ScanStatus.completed
            scan.finished_at = _now()
            await session.commit()
            await emit({"type": "done", "status": scan.status.value, "summary": scan.summary})
        except Exception as exc:  # noqa: BLE001
            scan.status = ScanStatus.failed
            scan.error = str(exc)[:2000]
            scan.finished_at = _now()
            await session.commit()
            await emit({"type": "failed", "error": scan.error})
            raise


async def _ingest(session, artifact: Artifact, emit) -> str:
    await emit({"type": "status", "status": "ingesting"})
    artifact.status = ArtifactStatus.ingesting
    await session.commit()

    storage = get_storage()
    workdir = await materialize(artifact, storage)
    result = index_files(workdir)

    # delete old file index (explicit query — no lazy loading in async)
    old_files = (await session.execute(
        select(ArtifactFile).where(ArtifactFile.artifact_id == artifact.id)
    )).scalars().all()
    for f in old_files:
        await session.delete(f)

    session.add_all([
        ArtifactFile(
            artifact_id=artifact.id, path=f.path, size_bytes=f.size_bytes, language=f.language,
            sha256=f.sha256, is_binary=f.is_binary, is_vendored=f.is_vendored, included=f.included,
        )
        for f in result.files
    ])
    artifact.size_bytes = result.total_bytes
    artifact.file_count = len(result.files)
    artifact.analyzable_count = result.analyzable
    artifact.status = ArtifactStatus.ready
    artifact.meta = {**(artifact.meta or {}), "workdir": workdir}
    await session.commit()
    await emit({"type": "log", "message": f"Indexed {len(result.files)} files, "
                                          f"{result.analyzable} analyzable"})
    return workdir


async def _static_scan(session, scan: Scan, artifact: Artifact, workdir: str, emit) -> list[dict]:
    requested = set((scan.config or {}).get("scanners", _DEFAULT_SCANNERS))
    scfg = await get_scanner_config(session)
    candidates: list[dict] = []

    if scfg.semgrep_enabled and "semgrep" in requested:
        await emit({"type": "status", "status": "semgrep"})
        try:
            sem = await SemgrepScanner().scan(workdir)
            candidates.extend(sem)
            await emit({"type": "log", "message": f"Semgrep: {len(sem)} candidates"})
        except Exception as exc:  # noqa: BLE001
            await emit({"type": "log", "message": f"Semgrep error: {exc}"})

    # SonarQube is admin-gated (heavy, needs a server); run when enabled and
    # explicitly requested for this scan.
    if scfg.sonarqube_enabled and "sonarqube" in requested:
        await emit({"type": "status", "status": "sonarqube"})
        try:
            sonar = await SonarScanner(
                url=scfg.sonarqube_url, token=scfg.sonarqube_token
            ).scan(workdir)
            candidates.extend(sonar)
            await emit({"type": "log", "message": f"SonarQube: {len(sonar)} candidates"})
        except Exception as exc:  # noqa: BLE001
            await emit({"type": "log", "message": f"SonarQube error: {exc}"})

    if "mcp" in requested:
        mcp_rows = (await session.execute(
            select(McpServer).where(
                McpServer.enabled.is_(True),
                (McpServer.project_id == scan.project_id) | (McpServer.project_id.is_(None)),
            )
        )).scalars().all()
        for server in mcp_rows:
            await emit({"type": "status", "status": f"mcp:{server.name}"})
            try:
                found = await McpClient(server).scan(workdir)
                candidates.extend(found)
                await emit({"type": "log", "message": f"MCP {server.name}: {len(found)} candidates"})
            except Exception as exc:  # noqa: BLE001
                await emit({"type": "log", "message": f"MCP {server.name} error: {exc}"})

    return candidates


async def _persist_findings(session, scan: Scan, findings: list[dict]) -> None:
    for f in findings:
        session.add(Finding(
            scan_id=scan.id,
            title=f["title"],
            description=f.get("description", ""),
            severity=Severity(f["severity"]),
            confidence=f.get("confidence", 0.5),
            source=FindingSource(f.get("source", "ai")),
            state=FindingState(f.get("state", "proposed")),
            cwe=f.get("cwe"),
            owasp=f.get("owasp"),
            category=f.get("category"),
            file_path=f.get("file_path"),
            line_start=f.get("line_start"),
            line_end=f.get("line_end"),
            code_snippet=f.get("code_snippet"),
            # Prefer the exploit analyst's specific recommendation; fall back to
            # the reviewer's terser remediation. Full PoC/risk live in raw.
            remediation=f.get("recommendation") or f.get("remediation"),
            human_question=f.get("human_question"),
            triage_note=f.get("triage_note"),
            triaged_by=f.get("triaged_by"),
            raw=f,
        ))
    await session.commit()


# --------------------------------------------------------------------------- re-run
def _candidate_to_finding(c: dict) -> dict:
    """Turn a raw static-scanner Candidate into a persistable finding dict."""
    return {
        "title": c.get("title") or c.get("rule") or "Static-analysis finding",
        "description": c.get("message", ""),
        "severity": c.get("severity") or "medium",
        "confidence": 0.5,
        "source": c.get("source") if c.get("source") in {"semgrep", "sonarqube"} else "semgrep",
        "state": "proposed",
        "cwe": c.get("cwe"),
        "owasp": c.get("owasp"),
        "category": c.get("category"),
        "file_path": c.get("file_path"),
        "line_start": c.get("line_start"),
        "line_end": c.get("line_end"),
        "code_snippet": c.get("code_snippet"),
    }


def _summary_from_finding_dicts(findings: list[dict], prev: dict | None = None) -> dict:
    """Compute a scan summary (counts + risk score) from finding dicts."""
    by_sev = {s.value: 0 for s in Severity}
    by_cat: dict[str, int] = {}
    needs = dismissed = 0
    for f in findings:
        st = f.get("state", "proposed")
        if st == "dismissed":
            dismissed += 1
            continue
        sev = f.get("severity", "medium")
        by_sev[sev] = by_sev.get(sev, 0) + 1
        cat = f.get("category") or "uncategorized"
        by_cat[cat] = by_cat.get(cat, 0) + 1
        if st == "needs_info":
            needs += 1
    raw = sum(_RISK_WEIGHT.get(s, 0) * n for s, n in by_sev.items())
    risk = round(100 * (1 - 1 / (1 + raw / 25)), 1)
    return {**(prev or {}), "total": len(findings), "dismissed": dismissed,
            "needs_review": needs, "by_severity": by_sev, "by_category": by_cat,
            "risk_score": risk}


async def _delete_findings_by_source(session, scan_id: str, sources: set[str]) -> int:
    from sqlalchemy import delete as sql_delete
    rows = (await session.execute(
        select(Finding).where(
            Finding.scan_id == scan_id,
            Finding.source.in_([FindingSource(s) for s in sources]),
        )
    )).scalars().all()
    n = len(rows)
    await session.execute(
        sql_delete(Finding).where(
            Finding.scan_id == scan_id,
            Finding.source.in_([FindingSource(s) for s in sources]),
        )
    )
    await session.commit()
    return n


async def _candidates_from_findings(session, scan_id: str) -> list[dict]:
    """Rebuild static-scanner candidates from the findings currently in the DB
    (so an AI re-run sees the same SAST candidates without re-running them)."""
    rows = (await session.execute(
        select(Finding).where(
            Finding.scan_id == scan_id,
            Finding.source.in_([FindingSource.semgrep, FindingSource.sonarqube]),
        )
    )).scalars().all()
    out: list[dict] = []
    for f in rows:
        out.append({
            "source": f.source.value, "rule": (f.raw or {}).get("rule", ""),
            "title": f.title, "message": f.description, "severity": f.severity.value,
            "cwe": f.cwe, "owasp": f.owasp, "category": f.category,
            "file_path": f.file_path, "line_start": f.line_start,
            "line_end": f.line_end, "code_snippet": f.code_snippet,
        })
    return out


async def _ensure_workdir(session, artifact: Artifact, emit) -> str:
    """Reuse the materialized workdir if it still exists; else re-ingest."""
    workdir = (artifact.meta or {}).get("workdir")
    if workdir and os.path.isdir(workdir):
        return workdir
    await emit({"type": "log", "message": "Workdir missing; re-materializing artifact"})
    return await _ingest(session, artifact, emit)


async def rerun_stage(ctx: dict, scan_id: str, stage: str) -> None:
    """Re-run a single pipeline stage on an existing scan, replacing just that
    stage's findings. Triggered by the per-stage UI buttons."""
    async with SessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if scan is None:
            return
        seq = {"n": 0}
        emit_lock = asyncio.Lock()

        async def emit(event: dict) -> None:
            event = {"ts": _now().isoformat(), **event}
            await events.publish(scan_id, event)
            if event.get("type") not in {"token", "heartbeat"}:
                async with emit_lock:
                    seq["n"] += 1
                    session.add(AgentEvent(scan_id=scan_id, seq=seq["n"],
                                           type=event.get("type", "log"), payload=event))
                    await session.commit()

        scan.status = ScanStatus.running
        scan.started_at = _now()
        scan.error = None
        await session.commit()
        await emit({"type": "status", "status": f"re-running {stage}"})
        await emit({"type": "log", "message": f"Re-running stage: {stage}"})

        try:
            artifact = await session.get(Artifact, scan.artifact_id)
            workdir = await _ensure_workdir(session, artifact, emit)
            scfg = await get_scanner_config(session)
            needs_review = False

            if stage == "semgrep":
                await emit({"type": "status", "status": "semgrep"})
                sem = await SemgrepScanner().scan(workdir)
                await _delete_findings_by_source(session, scan_id, {"semgrep"})
                await _persist_findings(session, scan, [_candidate_to_finding(c) for c in sem])
                await emit({"type": "log", "message": f"Semgrep re-run: {len(sem)} findings"})

            elif stage == "sonarqube":
                if not scfg.sonarqube_enabled:
                    raise RuntimeError("SonarQube is not enabled in Settings")
                await emit({"type": "status", "status": "sonarqube"})
                sonar = await SonarScanner(
                    url=scfg.sonarqube_url, token=scfg.sonarqube_token
                ).scan(workdir)
                await _delete_findings_by_source(session, scan_id, {"sonarqube"})
                await _persist_findings(session, scan, [_candidate_to_finding(c) for c in sonar])
                await emit({"type": "log", "message": f"SonarQube re-run: {len(sonar)} findings"})

            elif stage == "ai":
                candidates = await _candidates_from_findings(session, scan_id)
                await emit({"type": "log", "message":
                            f"AI re-run over {len(candidates)} existing static candidates"})
                result = await _ai_review(session, scan, artifact, workdir, candidates, emit)
                # Replace prior AI-authored findings; keep raw static ones.
                await _delete_findings_by_source(session, scan_id, {"ai", "correlated"})
                await _persist_findings(session, scan, result["findings"])
                needs_review = bool(result["summary"].get("needs_review"))
            else:
                raise ValueError(f"unknown stage: {stage}")

            # Recompute the whole-scan summary from all surviving findings.
            all_findings = (await session.execute(
                select(Finding).where(Finding.scan_id == scan_id)
            )).scalars().all()
            fdicts = [{"severity": f.severity.value, "state": f.state.value,
                       "category": f.category} for f in all_findings]
            scan.summary = _summary_from_finding_dicts(
                fdicts, {**(scan.summary or {})})
            if any(f.state == FindingState.needs_info for f in all_findings):
                needs_review = True
            scan.status = ScanStatus.needs_review if needs_review else ScanStatus.completed
            scan.finished_at = _now()
            await session.commit()
            await emit({"type": "done", "status": scan.status.value, "summary": scan.summary})
        except Exception as exc:  # noqa: BLE001
            scan.status = ScanStatus.failed
            scan.error = str(exc)[:2000]
            scan.finished_at = _now()
            await session.commit()
            await emit({"type": "failed", "error": scan.error})
            raise


def _safe_read(workdir: str, rel: str) -> str | None:
    """Read a file's full text content. Returns None for binary/missing files."""
    target = os.path.realpath(os.path.join(workdir, rel))
    if not target.startswith(os.path.realpath(workdir) + os.sep):
        return None
    try:
        size = os.path.getsize(target)
        if size > settings.max_file_bytes_for_ai:
            return None
        with open(target, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


async def _startup(ctx: dict) -> None:
    await init_models()


class WorkerSettings:
    functions = [run_scan, rerun_stage]
    on_startup = _startup
    redis_settings = RedisSettings.from_dsn(settings.redis_url)
    max_jobs = 4
    job_timeout = 12 * 60 * 60  # 12h for very large repos (25k+ files)
