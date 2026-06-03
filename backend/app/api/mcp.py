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


@router.post("/{server_id}/test", dependencies=[Depends(require_role(Role.reviewer))])
async def test_server(server_id: str, session: AsyncSession = Depends(get_session)):
    server = await get_or_404(session, McpServer, server_id)
    try:
        tools = await McpClient(server).list_tools()
        return {"ok": True, "tools": [t.get("name") for t in tools]}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "detail": str(exc)}
