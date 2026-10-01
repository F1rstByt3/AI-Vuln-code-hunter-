"""Manual Burp hand-off: Intruder-ready raw requests, the request pack, and
sending to Repeater/Intruder through the Burp MCP server."""

from __future__ import annotations

import io
import zipfile

import httpx
import pytest

from app import burp_manual as bm
from app.db import SessionLocal, init_models
from app.main import app
from app.models import (
    Artifact,
    ArtifactKind,
    Client,
    DastTarget,
    Finding,
    FindingSource,
    FindingState,
    Project,
    Scan,
    ScanStatus,
    Severity,
)


def test_raw_request_marks_ids_and_uses_placeholder_auth():
    raw = bm.raw_request({"method": "DELETE", "path": "/api/orders/:orderId/items/<int:pk>",
                          "id_params": ["orderId", "pk"]}, "https://shop.test:8443/v2")
    head, _, body = raw.partition("\r\n\r\n")
    lines = head.split("\r\n")
    assert lines[0] == "DELETE /v2/api/orders/§1§/items/§1§ HTTP/1.1"
    assert "Host: shop.test:8443" in lines
    assert f"Authorization: {bm.AUTH_PLACEHOLDER}" in lines
    assert body == ""


def test_uuid_ids_get_uuid_sample_and_bodies_are_json():
    raw = bm.raw_request({"method": "PUT", "path": "/docs/{docId}", "id_params": ["docId"],
                          "id_kind": "uuid"}, "http://h")
    assert "/docs/§00000000-0000-0000-0000-000000000001§ " in raw
    assert raw.endswith("\r\n\r\n{}") and "Content-Length: 2" in raw


async def _seed(with_target: bool = True) -> tuple[str, str]:
    await init_models()
    async with SessionLocal() as s:
        c = Client(name="C", slug=f"c-bm-{with_target}"); s.add(c); await s.flush()
        p = Project(client_id=c.id, name="P"); s.add(p); await s.flush()
        a = Artifact(project_id=p.id, kind=ArtifactKind.local); s.add(a); await s.flush()
        scan = Scan(project_id=p.id, artifact_id=a.id, status=ScanStatus.completed, summary={
            "endpoints": [
                {"id": "e0", "method": "GET", "path": "/orders/{id}", "risk": "high",
                 "id_params": ["id"], "id_kind": "numeric"},
                {"id": "e1", "method": "GET", "path": "/health", "risk": "low"},
            ]})
        s.add(scan); await s.flush()
        if with_target:
            s.add(DastTarget(project_id=p.id, label="stg", base_url="https://stg.test",
                             allowed_hosts=["stg.test"]))
        f = Finding(scan_id=scan.id, title="Possible IDOR on GET /orders/{id}",
                    severity=Severity.high, source=FindingSource.access,
                    state=FindingState.proposed, raw={"endpoint": "GET /orders/{id}"})
        s.add(f); await s.commit()
        return scan.id, f.id


@pytest.mark.asyncio
async def test_pack_and_finding_request_default_to_dast_target():
    sid, fid = await _seed()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t") as client:
        r = await client.get(f"/api/scans/{sid}/export/burp-pack",
                             params={"min_risk": "medium"})
        one = (await client.get(f"/api/findings/{fid}/burp-request")).json()
    assert r.status_code == 200
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = z.namelist()
    reqs = [n for n in names if n.startswith("requests/")]
    assert len(reqs) == 1 and "orders" in reqs[0]          # /health filtered by risk
    assert {"README.txt", "all-requests.txt", "payloads/numeric-ids.txt"} <= set(names)
    assert "Host: stg.test" in z.read(reqs[0]).decode()
    assert "finding: [high] Possible IDOR" in z.read("all-requests.txt").decode()
    assert one["raw"].startswith("GET /orders/§1§ HTTP/1.1")
    assert one["host"] == "stg.test" and one["port"] == 443 and one["https"] is True


@pytest.mark.asyncio
async def test_send_to_intruder_via_mcp(monkeypatch):
    sid, fid = await _seed(with_target=False)
    calls: list = []

    async def fake_rpc(self, method, params=None, timeout=120):
        if method == "tools/list":
            return {"tools": [{"name": "create_repeater_tab"}, {"name": "send_to_intruder"}]}
        calls.append(params)
        return {}

    from app.dast import burp
    monkeypatch.setattr(burp.BurpClient, "_rpc", fake_rpc)
    from app.models import McpServer
    async with SessionLocal() as s:
        m = McpServer(name="burp", kind="burp", transport="sse", url="http://burp/sse")
        s.add(m); await s.commit()
        mid = m.id
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t") as client:
        res = (await client.post("/api/burp/send", json={
            "mcp_id": mid, "tool": "intruder", "finding_ids": [fid],
            "base_url": "http://local.test:8080"})).json()
    assert res == {"sent": 1, "errors": []}
    assert calls[0]["name"] == "send_to_intruder"
    args = calls[0]["arguments"]
    assert args["targetHostname"] == "local.test" and args["targetPort"] == 8080
    assert args["usesHttps"] is False and "§1§" in args["content"]
    assert "REPLACE_WITH_YOUR_TOKEN" in args["content"]
