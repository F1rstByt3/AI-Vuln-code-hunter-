"""MCP server registry — plug in Semgrep / SonarQube / custom MCP servers that the
agent and static phase can call as tools."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_or_404
from app.auth import require_role
from app.db import get_session
from app.models import McpServer, Role
from app.scanners.mcp_client import McpClient
from app.schemas import McpServerCreate, McpServerOut

router = APIRouter(prefix="/mcp-servers", tags=["mcp"])


@router.get("", response_model=list[McpServerOut])
async def list_servers(project_id: str | None = None, session: AsyncSession = Depends(get_session)):
    stmt = select(McpServer)
    if project_id:
        stmt = stmt.where(or_(McpServer.project_id == project_id, McpServer.project_id.is_(None)))
    rows = (await session.execute(stmt)).scalars().all()
    return rows


@router.post("", response_model=McpServerOut, dependencies=[Depends(require_role(Role.reviewer))])
async def create_server(
    body: McpServerCreate,
    project_id: str | None = None,
    session: AsyncSession = Depends(get_session),
):
    server = McpServer(project_id=project_id, **body.model_dump())
    session.add(server)
    await session.commit()
    await session.refresh(server)
    return server


@router.delete("/{server_id}", status_code=204, dependencies=[Depends(require_role(Role.reviewer))])
async def delete_server(server_id: str, session: AsyncSession = Depends(get_session)):
    server = await get_or_404(session, McpServer, server_id)
    await session.delete(server)
    await session.commit()


_BURP_CAP_LABEL = {
    "send": "seed requests", "scan": "active scan", "issues": "read issues",
    "history": "proxy history", "scan_status": "scan status",
    "repeater": "→ Repeater", "intruder": "→ Intruder",
}


@router.post("/{server_id}/test", dependencies=[Depends(require_role(Role.reviewer))])
async def test_server(server_id: str, session: AsyncSession = Depends(get_session)):
    """Health-check a registered MCP server: confirm it is reachable, list the
    tools it exposes, and — for a Burp server — which DAST capabilities
    (active scan, Repeater/Intruder hand-off) are actually available."""
    import time

    server = await get_or_404(session, McpServer, server_id)
    if server.transport == "stdio":
        return {"ok": False, "detail": "stdio transport can't be tested from the API "
                "(it's launched locally by the worker). Use http or sse."}
    if not server.url:
        return {"ok": False, "detail": "no URL set for this server"}

    started = time.monotonic()
    try:
        tools = await McpClient(server).list_tools()
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "detail": f"{type(exc).__name__}: {exc}"[:400],
                "hint": _reach_hint(server)}
    ms = int((time.monotonic() - started) * 1000)
    names = [t.get("name") for t in tools if isinstance(t, dict) and t.get("name")]
    out: dict = {"ok": True, "detail": f"reachable · {len(names)} tools · {ms}ms",
                 "tools": names, "elapsed_ms": ms, "kind": server.kind}

    if server.kind == "burp":
        from app.dast.burp import BurpClient
        try:
            caps = await BurpClient(server).capabilities()  # cap -> tool name | None
        except Exception as exc:  # noqa: BLE001
            caps = {}
            out["detail"] += f" · capability probe failed: {exc}"[:200]
        have = {c: bool(t) for c, t in caps.items()}
        out["capabilities"] = have
        out["ready"] = {
            "active_scan": have.get("send", False),      # seeding is the minimum
            "active_scan_issues": have.get("scan", False) and have.get("issues", False),
            "manual_repeater": have.get("repeater", False),
            "manual_intruder": have.get("intruder", False),
        }
        missing = [lbl for c, lbl in _BURP_CAP_LABEL.items() if c in caps and not have.get(c)]
        if not have.get("send"):
            out["warn"] = ("Burp exposes no request-sending tool — DAST can't seed or "
                           "active-scan through it. Update the Burp MCP Server extension.")
        elif missing:
            out["note"] = "unavailable over MCP: " + ", ".join(missing)
    return out


def _reach_hint(server: McpServer) -> str:
    url = server.url or ""
    if "localhost" in url or "127.0.0.1" in url:
        return ("From inside Docker, 'localhost' is the container itself. Point the URL "
                "at host.docker.internal to reach a tool running on your machine.")
    return "Check the server is running and the URL/transport are correct."
