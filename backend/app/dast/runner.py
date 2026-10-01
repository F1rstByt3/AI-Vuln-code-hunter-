"""run_dast — execute one authorized live access-control confirmation run.

Loads the scan's access-control findings, replays each against the live target
under the configured identities, and updates the finding to confirmed /
dismissed / inconclusive with sanitized evidence. Progress streams to the
scan's event channel so the existing scan page shows it live.

Flow: resolve identities (including scripted logins) -> harvest object ids for
IDOR -> confirm each access finding -> optionally run a Burp active scan and
ingest its issues as ``dast`` findings.
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
                    f"authorised by {run.authorized_by}"})

        # Identities: anonymous baseline is implicit; split configured roles.
        creds = (await session.execute(
            select(DastCredential).where(DastCredential.target_id == target.id)
        )).scalars().all()
        identities = [Identity.from_credential(c) for c in creds]

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
        checks = run.config.get("checks") or {}
        do_access = checks.get("access_control", True)
        do_active = checks.get("active_scan", bool(run.config.get("active_scan")))
        inc = [p for p in (run.config.get("include_paths") or []) if p]
        exc = [p for p in (run.config.get("exclude_paths") or []) if p]

        def in_path_scope(path: str) -> bool:
            path = path or ""
            if inc and not any(path.startswith(p) for p in inc):
                return False
            return not any(path.startswith(p) for p in exc)

        # Apply the operator's path filters to the endpoint surface + findings.
        all_eps = [e for e in matrix.values() if in_path_scope(e.get("path", ""))]
        if inc or exc:
            findings = [f for f in findings
                        if in_path_scope(((f.raw or {}).get("endpoint") or "")
                                         .partition(" ")[2] or (f.file_path or ""))
                        or not (f.raw or {}).get("endpoint")]
        if not do_access:
            findings = []

        req_log: list[dict] = []          # audit trail across all phases
        by_purpose: dict[str, int] = {}

        def absorb(client) -> None:
            req_log.extend(client.log)
            for k, v in client.by_purpose.items():
                by_purpose[k] = by_purpose.get(k, 0) + v
            counts["requests"] = sum(by_purpose.values())

        low: list = []
        priv: list = []
        scope = Scope(target.allowed_hosts or [])
        base = target.base_url.rstrip("/")
        total = len(findings)
        await emit({"type": "stage", "stage": "dast_access", "state": "running",
                    "done": 0, "total": total})

        try:
            async with LiveClient(scope, max_rps=target.max_rps or settings.dast_default_max_rps,
                                  allow_mutating=run.allow_mutating,
                                  capture_bodies=False) as client:
                # Resolve scripted logins (login_form) now that we have a client.
                from app.dast.login import perform_login
                for idx, ident in enumerate(identities):
                    if ident.login_spec:
                        identities[idx] = await perform_login(
                            client, base, ident.role, ident.is_privileged, ident.login_spec)
                usable = [i for i in identities if i.usable]
                low = [i for i in usable if not i.is_privileged]
                priv = [i for i in usable if i.is_privileged]
                if len(usable) < len(identities):
                    await emit({"type": "log", "message":
                                f"{len(identities) - len(usable)} credential(s) unusable "
                                f"(login failed / secret missing / unsupported) — skipped"})

                # Harvest object ids for IDOR from list endpoints (GET only),
                # keyed per collection; resolved per-endpoint in _confirm_one.
                from app.dast.harvest import harvest_object_ids
                harvested = await harvest_object_ids(
                    client, base, list(matrix.values()), usable, emit=emit)
                operator_seeds = target.object_seeds or {}

                by_role = {i.role: i for i in usable}
                for i, f in enumerate(findings):
                    if await control.get_control(run.scan_id + ":dast") == "cancel":
                        raise ScanCanceledSignal()
                    verdict = await _confirm_one(client, f, matrix, base, low, priv,
                                                 harvested, operator_seeds, by_role)
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
                absorb(client)
            await session.commit()

            # Active scan — native checks (and Burp if attached).
            if do_active:
                try:
                    await _run_active_scan(session, run, scan, target, scope, low, priv,
                                           emit, counts, all_eps, absorb)
                except ScanCanceledSignal:
                    raise
                except Exception as exc:  # noqa: BLE001
                    await emit({"type": "stage", "stage": "dast_active", "state": "failed"})
                    await emit({"type": "log", "message": f"Active scan error: {exc}"})
            run.status = DastStatus.completed
        except ScanCanceledSignal:
            await session.commit()
            run.status = DastStatus.canceled
            await emit({"type": "log", "message": "DAST run cancelled"})
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

        # Persist the audit trail (bounded) so the operator can see what was
        # sent, where, and why.
        counts["by_purpose"] = by_purpose
        counts["requests_log"] = req_log[:1000]
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
                           scope: Scope, low, priv, emit, counts: dict,
                           endpoints: list, absorb) -> None:
    """Native active checks (needs no Burp) over *endpoints*, then — if a Burp
    MCP server is attached — seed the surface into Burp and ingest its issues."""
    from app.config import settings as cfg
    from app.dast.active import native_active_scan

    ident = (priv or low or [Identity.anonymous()])[0]
    base = target.base_url.rstrip("/")
    await emit({"type": "stage", "stage": "dast_active", "state": "running"})
    await emit({"type": "status", "status": "dast: active scan"})

    async def _canceled():
        return await control.get_control(run.scan_id + ":dast") == "cancel"

    # --- native active scan (always; no Burp required) ---
    try:
        async with LiveClient(scope, max_rps=target.max_rps or cfg.dast_default_max_rps,
                              allow_mutating=run.allow_mutating, capture_bodies=True) as nclient:
            native = await native_active_scan(nclient, base, endpoints, ident, emit,
                                              is_canceled=_canceled)
        absorb(nclient)
    except Exception as exc:  # noqa: BLE001
        native = []
        await emit({"type": "log", "message": f"Native active scan error: {exc}"})
    added = await _persist_dast_findings(session, run.scan_id, native)
    counts["active_issues"] = added
    await emit({"type": "finding", "finding": {"_dast": True, "active": added}})

    if not target.burp_mcp_id:
        await emit({"type": "stage", "stage": "dast_active", "state": "done"})
        return

    from app.dast.burp import BurpClient, issue_to_finding, wait_and_fetch_issues
    server = await session.get(McpServer, target.burp_mcp_id)
    if server is None:
        await emit({"type": "log", "message": "Burp step skipped: MCP server not found"})
        await emit({"type": "stage", "stage": "dast_active", "state": "done"})
        return
    await emit({"type": "status", "status": "dast: Burp active scan"})
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
    for e in endpoints:
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

    issues = await wait_and_fetch_issues(burp, is_canceled=_canceled)
    burp_dicts = [issue_to_finding(run.scan_id, issue) for issue in issues]
    added = await _persist_dast_findings(session, run.scan_id, burp_dicts)
    counts["burp_issues"] = added
    counts["seeded"] = len(seeded_urls)
    await emit({"type": "stage", "stage": "dast_active", "state": "done"})
    await emit({"type": "finding", "finding": {"_dast": True, "active": added}})
    await emit({"type": "log", "message":
                f"Burp active scan: ingested {added} issue(s) as findings"})


async def _persist_dast_findings(session, scan_id: str, finding_dicts: list[dict]) -> int:
    """Persist dast findings, deduped against existing ones by (title, endpoint)."""
    existing = {(f.title, (f.raw or {}).get("endpoint")) for f in (await session.execute(
        select(Finding).where(Finding.scan_id == scan_id,
                              Finding.source == FindingSource.dast)
    )).scalars().all()}
    added = 0
    for fd in finding_dicts:
        key = (fd.get("title"), fd.get("endpoint"))
        if key in existing:
            continue
        session.add(_dast_finding(scan_id, fd))
        existing.add(key)
        added += 1
    if added:
        await session.commit()
    return added


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
        cwe=trunc(fd.get("cwe"), 200), owasp=trunc(fd.get("owasp"), 200),
        category=trunc(fd.get("category"), 200),
        remediation=fd.get("remediation"), code_snippet=fd.get("code_snippet"),
        raw={k: v for k, v in fd.items() if k not in ("severity",)},
    )


async def _confirm_one(client, f: Finding, matrix: dict, base: str,
                       low: list[Identity], priv: list[Identity], harvested: dict,
                       operator_seeds: dict, by_role: dict | None = None):
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
        from app.dast.harvest import collection_path, endpoint_seeds
        actors = low or priv
        seeds = endpoint_seeds(harvested, operator_seeds, collection_path(path))
        return await replay.probe_idor(client, path, method, base, id_params,
                                        seeds, actors, by_role)
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
