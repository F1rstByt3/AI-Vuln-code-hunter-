"""run_dast — execute one authorized live access-control confirmation run.

Loads the scan's access-control findings, replays each against the live target
under the configured identities, and updates the finding to confirmed /
dismissed / inconclusive with sanitized evidence. Progress streams to the
scan's event channel so the existing scan page shows it live.

Active scanning (Burp) is a later phase; this runner covers the app-native
access-control confirmation, which needs no Burp.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import control, events
from app.config import settings
from app.control import ScanCanceledSignal
from app.dast import replay
from app.dast.client import LiveClient
from app.dast.identity import Identity
from app.dast.scope import Scope, ScopeError
from app.db import SessionLocal
from app.models import (
    DastCredential, DastRun, DastStatus, DastTarget, Finding, FindingSource,
    FindingState, McpServer, Scan, Severity,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def run_dast(ctx: dict, run_id: str) -> None:
    async with SessionLocal() as session:
        run = await session.get(DastRun, run_id)
        if run is None:
            return
        scan = await session.get(Scan, run.scan_id)
        target = await session.get(DastTarget, run.target_id)
        if scan is None or target is None:
            run.status = DastStatus.failed
            run.error = "scan or target missing"
            await session.commit()
            return

        async def emit(event: dict) -> None:
            await events.publish(run.scan_id, {"ts": _now().isoformat(),
                                               "dast_run": run_id, **event})

        await control.clear_control(run.scan_id + ":dast")
        run.status = DastStatus.running
        run.started_at = _now()
        await session.commit()
        await emit({"type": "status", "status": "dast: access-control confirmation"})
        await emit({"type": "log", "message":
                    f"DAST run against {target.base_url} "
                    f"(scope: {', '.join(target.allowed_hosts or [])}) — "
                    f"authorized by {run.authorized_by}"})

        # Identities: anonymous baseline is implicit; split configured roles.
        creds = (await session.execute(
            select(DastCredential).where(DastCredential.target_id == target.id)
        )).scalars().all()
        identities = [Identity.from_credential(c) for c in creds]
        usable = [i for i in identities if i.usable]
        low = [i for i in usable if not i.is_privileged]
        priv = [i for i in usable if i.is_privileged]
        if len(usable) < len(identities):
            await emit({"type": "log", "message":
                        f"{len(identities) - len(usable)} credential(s) unusable "
                        f"(secret missing or unsupported kind) — skipped"})

        # Endpoint matrix from the source scan, keyed for finding lookup.
        matrix = {e.get("id"): e for e in (scan.summary or {}).get("endpoints", [])
                  if isinstance(e, dict)}

        # Access findings that are still open (not already dismissed).
        findings = (await session.execute(
            select(Finding).where(
                Finding.scan_id == run.scan_id,
                Finding.source == FindingSource.access,
                Finding.state != FindingState.dismissed,
            )
        )).scalars().all()

        counts = {"confirmed": 0, "enforced": 0, "inconclusive": 0,
                  "untestable": 0, "requests": 0}
        scope = Scope(target.allowed_hosts or [])
        base = target.base_url.rstrip("/")
        total = len(findings)
        await emit({"type": "stage", "stage": "dast_access", "state": "running",
                    "done": 0, "total": total})

        try:
            async with LiveClient(scope, max_rps=target.max_rps or settings.dast_default_max_rps,
                                  allow_mutating=run.allow_mutating,
                                  capture_bodies=False) as client:
                for i, f in enumerate(findings):
                    if await control.get_control(run.scan_id + ":dast") == "cancel":
                        raise ScanCanceledSignal()
                    verdict = await _confirm_one(client, f, matrix, base, low, priv,
                                                 target.object_seeds or {})
                    if verdict is None:
                        counts["untestable"] += 1
                    else:
                        v, evidence = verdict
                        await _apply_verdict(session, f, v, evidence, run_id)
                        key = {"confirmed_vuln": "confirmed", "enforced": "enforced",
                               "inconclusive": "inconclusive"}[v]
                        counts[key] += 1
                        await emit({"type": "finding", "finding": {"_dast": True,
                                    "id": f.id, "verdict": v}})
                    await emit({"type": "stage", "stage": "dast_access", "state": "running",
                                "done": i + 1, "total": total})
                counts["requests"] = client.count
            await session.commit()

            # Active scan (Burp) — seed the authenticated surface and ingest issues.
            if run.config.get("active_scan") and target.burp_mcp_id:
                try:
                    await _run_active_scan(session, run, scan, target, scope, low, priv,
                                           emit, counts)
                except ScanCanceledSignal:
                    raise
                except Exception as exc:  # noqa: BLE001
                    await emit({"type": "stage", "stage": "dast_active", "state": "failed"})
                    await emit({"type": "log", "message": f"Active scan error: {exc}"})
            run.status = DastStatus.completed
        except ScanCanceledSignal:
            await session.commit()
            run.status = DastStatus.canceled
            await emit({"type": "log", "message": "DAST run canceled"})
        except ScopeError as exc:
            await session.rollback()
            run.status = DastStatus.failed
            run.error = str(exc)
            await emit({"type": "log", "message": f"DAST stopped: {exc}"})
        except Exception as exc:  # noqa: BLE001
            await session.rollback()
            run.status = DastStatus.failed
            run.error = str(exc)[:1000]
            await emit({"type": "log", "message": f"DAST error: {exc}"})

        run.summary = counts
        run.finished_at = _now()
        await session.commit()
        await emit({"type": "stage", "stage": "dast_access",
                    "state": "done" if run.status == DastStatus.completed else "failed",
                    "done": total, "total": total})
        await emit({"type": "log", "message":
                    f"DAST done: {counts['confirmed']} confirmed, "
                    f"{counts['enforced']} enforced (dismissed), "
                    f"{counts['inconclusive']} inconclusive, "
                    f"{counts['untestable']} untestable · {counts['requests']} requests"})
        await emit({"type": "dast_done", "status": run.status.value, "summary": counts})
        await control.clear_control(run.scan_id + ":dast")


async def _run_active_scan(session, run: DastRun, scan: Scan, target: DastTarget,
                           scope: Scope, low, priv, emit, counts: dict) -> None:
    """Seed the discovered request surface into Burp, run an active scan, and
    ingest issues as ``dast`` findings. Gracefully degrades when the Burp MCP
    server exposes no scan tool (the surface is still seeded)."""
    from app.dast.burp import BurpClient, issue_to_finding, wait_and_fetch_issues

    server = await session.get(McpServer, target.burp_mcp_id)
    if server is None:
        await emit({"type": "log", "message": "Active scan skipped: Burp MCP server not found"})
        return
    await emit({"type": "stage", "stage": "dast_active", "state": "running"})
    await emit({"type": "status", "status": "dast: active scan (Burp)"})
    burp = BurpClient(server)
    try:
        caps = await burp.capabilities()
    except Exception as exc:  # noqa: BLE001
        await emit({"type": "stage", "stage": "dast_active", "state": "failed"})
        await emit({"type": "log", "message":
                    f"Active scan skipped: Burp MCP unreachable ({exc})"})
        return
    if not caps.get("send"):
        await emit({"type": "stage", "stage": "dast_active", "state": "skipped"})
        await emit({"type": "log", "message":
                    "Active scan skipped: Burp MCP exposes no request-sending tool"})
        return

    # Seed the authenticated surface: every discovered endpoint, using the most
    # privileged usable identity so Burp scans behind auth.
    ident = (priv or low or [Identity.anonymous()])[0]
    base = target.base_url.rstrip("/")
    seeded_urls: list[str] = []
    skipped_mut = 0
    for e in (scan.summary or {}).get("endpoints", []):
        if not isinstance(e, dict):
            continue
        method = (e.get("method") or "GET").upper()
        if method in ("ANY", "ALL"):
            method = "GET"
        if method not in ("GET", "HEAD", "OPTIONS") and not run.allow_mutating:
            skipped_mut += 1
            continue
        url = base + replay.fill_path(e.get("path") or "/", None)
        if not scope.permits(url):
            continue
        if await burp.seed_request(method, url, ident.headers):
            seeded_urls.append(url)
    await emit({"type": "log", "message":
                f"Seeded {len(seeded_urls)} requests into Burp"
                + (f" ({skipped_mut} mutating skipped)" if skipped_mut else "")})

    if not caps.get("scan"):
        await emit({"type": "stage", "stage": "dast_active", "state": "done"})
        await emit({"type": "log", "message":
                    "Burp has no active-scan tool over MCP — surface seeded; run "
                    "the active scan inside Burp against the populated site map"})
        counts["seeded"] = len(seeded_urls)
        return

    await burp.active_scan(seeded_urls or [base])
    await emit({"type": "log", "message":
                f"Burp active scan started on {len(seeded_urls) or 1} URL(s); "
                f"polling for issues…"})

    async def _canceled():
        return await control.get_control(run.scan_id + ":dast") == "cancel"

    issues = await wait_and_fetch_issues(burp, is_canceled=_canceled)
    # Ingest (dedupe against existing dast findings by title+endpoint).
    existing = {(f.title, (f.raw or {}).get("endpoint")) for f in (await session.execute(
        select(Finding).where(Finding.scan_id == run.scan_id,
                              Finding.source == FindingSource.dast)
    )).scalars().all()}
    added = 0
    for issue in issues:
        fd = issue_to_finding(run.scan_id, issue)
        if (fd["title"], fd.get("endpoint")) in existing:
            continue
        session.add(_dast_finding(run.scan_id, fd))
        existing.add((fd["title"], fd.get("endpoint")))
        added += 1
    await session.commit()
    counts["active_issues"] = added
    counts["seeded"] = len(seeded_urls)
    await emit({"type": "stage", "stage": "dast_active", "state": "done"})
    await emit({"type": "finding", "finding": {"_dast": True, "active": added}})
    await emit({"type": "log", "message":
                f"Burp active scan: ingested {added} issue(s) as findings"})


def _dast_finding(scan_id: str, fd: dict) -> Finding:
    def trunc(v, n):
        return v[:n] if isinstance(v, str) and len(v) > n else v
    sev = fd.get("severity", "medium")
    return Finding(
        scan_id=scan_id, title=trunc(fd.get("title") or "Burp issue", 300),
        description=fd.get("description", ""),
        severity=Severity(sev if sev in {s.value for s in Severity} else "medium"),
        confidence=fd.get("confidence", 0.7),
        source=FindingSource.dast, state=FindingState.proposed,
        cwe=trunc(fd.get("cwe"), 200), category=trunc(fd.get("category"), 200),
        remediation=fd.get("remediation"), code_snippet=fd.get("code_snippet"),
        raw={k: v for k, v in fd.items() if k not in ("severity",)},
    )


async def _confirm_one(client, f: Finding, matrix: dict, base: str,
                       low: list[Identity], priv: list[Identity], seeds: dict):
    """Return (verdict, evidence) or None if the finding isn't live-testable."""
    raw = f.raw or {}
    kind = replay.classify({"rule": raw.get("rule"), "cwe": f.cwe, "raw": raw})
    ep = matrix.get(raw.get("endpoint_id"))
    label = raw.get("endpoint") or (f"{ep['method']} {ep['path']}" if ep else None)
    if kind is None or not label:
        return None
    method, _, path = label.partition(" ")
    method = method.upper()
    if method in ("ANY", "ALL"):
        method = "GET"
    id_params = (ep or {}).get("id_params") or []

    if kind == "missing_authn":
        url = base + replay.fill_path(path, None)
        return await replay.probe_missing_authn(client, url, method)
    if kind == "bfla":
        url = base + replay.fill_path(path, None)
        return await replay.probe_bfla(client, url, method, low, priv)
    if kind == "idor":
        actors = low or priv
        return await replay.probe_idor(client, path, method, base, id_params,
                                        seeds, actors)
    return None


async def _apply_verdict(session: AsyncSession, f: Finding, verdict: str,
                         evidence: dict, run_id: str) -> None:
    raw = dict(f.raw or {})
    raw["dast"] = {"verdict": verdict, "evidence": evidence, "run_id": run_id,
                   "tested_at": _now().isoformat(), "by": "access-replay"}
    if verdict == "confirmed_vuln":
        f.state = FindingState.confirmed
        f.confidence = max(float(f.confidence or 0.5), 0.9)
        raw["dast_confirmed"] = True
    elif verdict == "enforced":
        f.state = FindingState.dismissed
        f.confidence = min(float(f.confidence or 0.5), 0.2)
        f.triage_note = ("DAST: the application enforces access control here — "
                         + str(evidence.get("reason", ""))[:300])
    # inconclusive: leave state; record the attempt.
    f.raw = raw
