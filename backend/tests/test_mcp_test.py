"""The MCP server health-check endpoint: reachability, tool listing, and — for
a Burp server — which DAST capabilities are actually available."""

from __future__ import annotations

import httpx
import pytest

from app.db import SessionLocal, init_models
from app.main import app
from app.models import McpServer


def _mock_mcp(tools: list[str]):
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    async def rpc(request):
        body = await request.json()
        result = {"tools": [{"name": n} for n in tools]} if body["method"] == "tools/list" else {}
        return JSONResponse({"jsonrpc": "2.0", "id": body["id"], "result": result})

    return Starlette(routes=[Route("/mcp", rpc, methods=["POST"])])


async def _register(kind: str, url: str = "http://mcp.mock/mcp", transport: str = "http") -> str:
    await init_models()
    async with SessionLocal() as s:
        m = McpServer(name=kind, kind=kind, transport=transport, url=url)
        s.add(m); await s.commit()
        return m.id


def _patch_transport(monkeypatch, mock_app):
    """Route both MCP clients' HTTP at the in-process mock app."""
    async def fake_rpc(self, method, params=None, timeout=120):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=mock_app),
                                     base_url="http://mcp.mock") as h:
            r = await h.post("/mcp", json={"jsonrpc": "2.0", "id": 1,
                                           "method": method, "params": params or {}})
            return r.json().get("result", {})
    import app.scanners.mcp_client as mc
    import app.dast.burp as burp
    monkeypatch.setattr(mc.McpClient, "_rpc", fake_rpc)
    monkeypatch.setattr(burp.BurpClient, "_rpc", fake_rpc)


@pytest.mark.asyncio
async def test_generic_mcp_reports_tools(monkeypatch):
    mid = await _register("semgrep")
    _patch_transport(monkeypatch, _mock_mcp(["scan", "list_rules"]))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t") as client:
        r = (await client.post(f"/api/mcp-servers/{mid}/test")).json()
    assert r["ok"] and set(r["tools"]) == {"scan", "list_rules"}
    assert "reachable" in r["detail"] and "ready" not in r


@pytest.mark.asyncio
async def test_burp_mcp_reports_capabilities(monkeypatch):
    mid = await _register("burp", transport="sse")
    _patch_transport(monkeypatch,
                     _mock_mcp(["send_http1_request", "create_scan_task",
                                "get_scan_issues", "create_repeater_tab"]))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t") as client:
        r = (await client.post(f"/api/mcp-servers/{mid}/test")).json()
    assert r["ok"] and r["kind"] == "burp"
    assert r["ready"]["active_scan"] is True            # send tool present
    assert r["ready"]["active_scan_issues"] is True     # scan + issues present
    assert r["ready"]["manual_repeater"] is True
    assert r["ready"]["manual_intruder"] is False       # no intruder tool
    assert "note" in r                                   # intruder unavailable


@pytest.mark.asyncio
async def test_burp_without_send_tool_warns(monkeypatch):
    mid = await _register("burp", transport="sse")
    _patch_transport(monkeypatch, _mock_mcp(["get_proxy_history"]))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t") as client:
        r = (await client.post(f"/api/mcp-servers/{mid}/test")).json()
    assert r["ok"] and r["ready"]["active_scan"] is False
    assert "no request-sending tool" in r["warn"]


@pytest.mark.asyncio
async def test_stdio_and_unreachable(monkeypatch):
    await init_models()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t") as client:
        stdio = await _register("custom", transport="stdio")
        r1 = (await client.post(f"/api/mcp-servers/{stdio}/test")).json()
        assert r1["ok"] is False and "stdio" in r1["detail"]

        bad = await _register("custom", url="http://localhost:9/mcp")

        async def boom(self, *a, **k):
            raise RuntimeError("connection refused")
        import app.scanners.mcp_client as mc
        monkeypatch.setattr(mc.McpClient, "_rpc", boom)
        r2 = (await client.post(f"/api/mcp-servers/{bad}/test")).json()
    assert r2["ok"] is False and "host.docker.internal" in r2["hint"]
