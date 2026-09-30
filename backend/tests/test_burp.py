"""Burp MCP integration: tool discovery, request seeding, active scan and issue
ingestion — against an in-process mock MCP server (no real Burp needed)."""

from __future__ import annotations

import httpx
import pytest

from app.dast.burp import BurpClient, issue_to_finding


class _FakeServer:
    """Stands in for an McpServer row."""
    url = "http://burp.mock/mcp"
    config: dict = {}


def _mock_burp(tools, *, seeded, issues):
    """An ASGI app speaking MCP JSON-RPC, emulating the Burp MCP server."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    async def rpc(request):
        body = await request.json()
        method, params = body["method"], body.get("params", {})
        rid = body["id"]
        if method == "tools/list":
            result = {"tools": [{"name": n} for n in tools]}
        elif method == "tools/call":
            name = params["name"]
            if "send" in name:
                seeded.append(params["arguments"].get("url"))
                result = {"ok": True}
            elif "issue" in name:
                result = {"issues": issues}
            elif "scan" in name:
                result = {"task_id": "t1"}
            else:
                result = {}
        else:
            result = {}
        return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": result})

    return Starlette(routes=[Route("/mcp", rpc, methods=["POST"])])


def _client_for(app):
    c = BurpClient(_FakeServer())
    # route the client's HTTP at the in-process app
    async def _rpc(method, params=None, timeout=120):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://burp.mock") as h:
            r = await h.post("/mcp", json={"jsonrpc": "2.0", "id": 1,
                                           "method": method, "params": params or {}})
            data = r.json()
            if "error" in data:
                raise RuntimeError(data["error"])
            return data.get("result", {})
    c._rpc = _rpc
    return c


@pytest.mark.asyncio
async def test_capability_discovery_and_seed_and_issues():
    seeded: list = []
    issues = [
        {"name": "SQL injection", "severity": "High", "confidence": "Firm",
         "url": "http://app.test/x", "issue_detail": "<b>tainted</b> param",
         "cwe": ["CWE-89"], "remediation": "parameterize"},
        {"name": "Reflected XSS", "severity": "Medium", "url": "http://app.test/y"},
    ]
    app = _mock_burp(["send_http1_request", "create_scan_task", "get_scan_issues"],
                     seeded=seeded, issues=issues)
    c = _client_for(app)

    caps = await c.capabilities()
    assert caps["send"] == "send_http1_request"
    assert caps["scan"] == "create_scan_task"
    assert caps["issues"] == "get_scan_issues"

    assert await c.seed_request("GET", "http://app.test/x", {"Authorization": "Bearer t"})
    assert seeded == ["http://app.test/x"]

    assert await c.active_scan(["http://app.test/x"]) == "t1"
    got = await c.fetch_issues()
    assert len(got) == 2


def test_issue_normalisation():
    f = issue_to_finding("s1", {"name": "SQL injection", "severity": "High",
                                "confidence": "Certain", "url": "http://app.test/x",
                                "issue_detail": "<p>tainted</p>", "cwe": ["CWE-89"]})
    assert f["source"] == "dast" and f["severity"] == "high"
    assert f["cwe"] == "CWE-89" and f["confidence"] == 0.95
    assert "tainted" in f["description"] and "<p>" not in f["description"]
    assert f["endpoint"] == "http://app.test/x"


@pytest.mark.asyncio
async def test_no_scan_tool_degrades_gracefully():
    seeded: list = []
    app = _mock_burp(["send_http1_request"], seeded=seeded, issues=[])
    c = _client_for(app)
    caps = await c.capabilities()
    assert caps["send"] and caps["scan"] is None      # only seeding available
    assert await c.active_scan(["http://app.test/"]) is None
