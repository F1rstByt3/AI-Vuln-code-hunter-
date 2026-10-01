"""Burp manual testing: Repeater/Intruder-ready requests and MCP hand-off."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import burp_manual as bm
from app.api.deps import get_or_404
from app.auth import require_role
from app.dast.burp import BurpClient
from app.db import get_session
from app.models import DastTarget, Finding, FindingState, McpServer, Role, Scan

router = APIRouter(tags=["burp"])

_RISK = {"high": 0, "medium": 1, "low": 2}


async def _base_url(session: AsyncSession, scan: Scan, base_url: str | None) -> str:
    """Explicit base URL, else the project's first live-test target, else a placeholder."""
    if base_url and base_url.strip() not in ("", "https://", "http://"):
        return base_url.strip()
    t = (await session.execute(
        select(DastTarget).where(DastTarget.project_id == scan.project_id)
        .order_by(DastTarget.created_at))).scalars().first()
    return t.base_url if t else "https://target.example"


def _endpoints(scan: Scan) -> list[dict]:
    return [e for e in (scan.summary or {}).get("endpoints") or [] if isinstance(e, dict)]


@router.get("/scans/{scan_id}/export/burp-pack")
async def export_burp_pack(
    scan_id: str, base_url: str | None = None, min_risk: str = "low",
    with_findings_only: bool = False, session: AsyncSession = Depends(get_session),
) -> Response:
    """ZIP of Intruder-ready raw requests (ids wrapped in § markers), payload
    lists and a how-to, for manual BAC testing in Burp."""
    scan = await get_or_404(session, Scan, scan_id)
    base = await _base_url(session, scan, base_url)
    findings = (await session.execute(
        select(Finding).where(Finding.scan_id == scan_id))).scalars().all()
    by_label: dict[str, list[str]] = {}
    for f in findings:
        label = (f.raw or {}).get("endpoint")
        if label and f.state != FindingState.dismissed and not (f.raw or {}).get("unverified"):
            by_label.setdefault(" ".join(label.upper().split()), []).append(
                f"[{f.severity.value}] {f.title}")
    cutoff = _RISK.get(min_risk, 2)
    eps = []
    for e in _endpoints(scan):
        if _RISK.get(e.get("risk") or e.get("heuristic_risk") or "low", 2) > cutoff:
            continue
        label = " ".join(f"{(e.get('method') or 'GET').upper()} {e.get('path')}".upper().split())
        if with_findings_only and label not in by_label:
            continue
        eps.append(e)
    if not eps:
        raise HTTPException(404, "No endpoints match — lower min_risk or untick findings-only")
    data = bm.build_pack(eps, base, findings_by_label=by_label)
    return Response(content=data, media_type="application/zip", headers={
        "Content-Disposition": f'attachment; filename="scan_{scan_id[:8]}_burp_pack.zip"'})


async def _finding_request(session: AsyncSession, finding_id: str,
                           base_url: str | None) -> dict:
    f = await get_or_404(session, Finding, finding_id)
    label = (f.raw or {}).get("endpoint")
    if not label:
        raise HTTPException(400, "This finding has no HTTP endpoint to build a request for")
    scan = await session.get(Scan, f.scan_id)
    base = await _base_url(session, scan, base_url)
    ep = bm.endpoint_for_label(_endpoints(scan), label) or {}
    raw = bm.raw_request(ep, base, note=f.title)
    host, port, https = bm.target_parts(base)
    return {"raw": raw, "host": host, "port": port, "https": https,
            "endpoint": label, "title": f.title, "base_url": base}


@router.get("/findings/{finding_id}/burp-request")
async def finding_burp_request(finding_id: str, base_url: str | None = None,
                               session: AsyncSession = Depends(get_session)) -> dict:
    """The finding's endpoint as a raw request (Intruder markers on ids)."""
    return await _finding_request(session, finding_id, base_url)


class BurpSendIn(BaseModel):
    mcp_id: str
    tool: str = "repeater"                 # repeater | intruder
    finding_ids: list[str] = Field(default_factory=list, max_length=50)
    base_url: str | None = None


@router.post("/burp/send", dependencies=[Depends(require_role(Role.reviewer))])
async def burp_send(body: BurpSendIn, session: AsyncSession = Depends(get_session)) -> dict:
    """Open findings' requests in Burp Repeater / Intruder via the Burp MCP
    server. Placeholder auth only — no stored credentials leave the app."""
    if body.tool not in ("repeater", "intruder"):
        raise HTTPException(400, "tool must be repeater or intruder")
    if not body.finding_ids:
        raise HTTPException(400, "finding_ids is empty")
    server = await get_or_404(session, McpServer, body.mcp_id)
    client = BurpClient(server)
    sent, errors = 0, []
    for fid in body.finding_ids:
        try:
            r = await _finding_request(session, fid, body.base_url)
            await client.send_to_tool(body.tool, r["raw"], r["host"], r["port"], r["https"],
                                      tab_name=f"Hunter: {r['endpoint']}")
            sent += 1
        except HTTPException as exc:
            errors.append(f"{fid[:8]}: {exc.detail}")
        except Exception as exc:  # noqa: BLE001 — surface the Burp/MCP error
            errors.append(f"{fid[:8]}: {exc}"[:300])
            if "exposes no" in str(exc):
                break  # unsupported tool: no point trying the rest
    return {"sent": sent, "errors": errors}
