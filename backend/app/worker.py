"""Scan orchestration worker (arq).

Pipeline per scan:
  ingest (materialize + index) -> static scan (Semgrep + enabled MCP servers)
  -> agentic AI review (Foundry) -> persist findings + summary.

Every step emits an event that is (a) published to Redis for live SSE and
(b) persisted to AgentEvent for replay.
"""

from __future__ import annotations

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


async def run_scan(ctx: dict, scan_id: str) -> None:
    async with SessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if scan is None:
            return
        seq = {"n": 0}

        async def emit(event: dict) -> None:
            event = {"ts": _now().isoformat(), **event}
            await events.publish(scan_id, event)
            if event.get("type") not in {"token", "heartbeat"}:  # tokens stay live-only
                seq["n"] += 1
                session.add(AgentEvent(scan_id=scan_id, seq=seq["n"],
                                       type=event.get("type", "log"), payload=event))
                await session.commit()

        scan.status = ScanStatus.running
        scan.started_at = _now()
        await session.commit()
        await emit({"type": "status", "status": "running"})

        try:
            artifact = await session.get(Artifact, scan.artifact_id)
            workdir = await _ingest(session, artifact, emit)

            candidates = await _static_scan(session, scan, artifact, workdir, emit)

            await emit({"type": "status", "status": "extracting endpoints"})
            endpoints = await extract_endpoints(workdir)
            await emit({"type": "log", "message":
                        f"Extracted {len(endpoints)} endpoints"})

            async def read_file(rel: str) -> str | None:
                return _safe_read(workdir, rel)

            cfg = await get_foundry_config(session)
            client = get_foundry_client(cfg)
            roles = cfg.resolve_roles(reviewer_override=(scan.config or {}).get("model"))
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

            result = await run_review(
                client=client,
                roles=roles,
                instructions=(scan.config or {}).get("instructions"),
                files=files,
                candidates=candidates,
                read_file=read_file,
                emit=emit,
            )

            await _persist_findings(session, scan, result["findings"])
            scan.summary = {**result["summary"], "endpoints": endpoints}
            scan.status = (
                ScanStatus.needs_review if result["summary"].get("needs_review")
                else ScanStatus.completed
            )
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
    requested = set((scan.config or {}).get("scanners", ["semgrep", "ai"]))
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

    # SonarQube is admin-gated (heavy, needs a server); run whenever enabled and
    # not explicitly opted out of for this scan.
    if scfg.sonarqube_enabled and "no-sonar" not in requested:
        await emit({"type": "status", "status": "sonarqube"})
        try:
            sonar = await SonarScanner(
                url=scfg.sonarqube_url, token=scfg.sonarqube_token
            ).scan(workdir)
            candidates.extend(sonar)
            await emit({"type": "log", "message": f"SonarQube: {len(sonar)} candidates"})
        except Exception as exc:  # noqa: BLE001
            await emit({"type": "log", "message": f"SonarQube error: {exc}"})

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
            remediation=f.get("remediation"),
            human_question=f.get("human_question"),
            triage_note=f.get("triage_note"),
            triaged_by=f.get("triaged_by"),
            raw=f,
        ))
    await session.commit()


def _safe_read(workdir: str, rel: str, max_bytes: int = 1_048_576) -> str | None:
    target = os.path.realpath(os.path.join(workdir, rel))
    if not target.startswith(os.path.realpath(workdir) + os.sep):
        return None
    try:
        with open(target, encoding="utf-8", errors="replace") as fh:
            return fh.read(max_bytes)
    except OSError:
        return None


async def _startup(ctx: dict) -> None:
    await init_models()


class WorkerSettings:
    functions = [run_scan]
    on_startup = _startup
    redis_settings = RedisSettings.from_dsn(settings.redis_url)
    max_jobs = 4
    job_timeout = 60 * 60  # 1h for large repos
