"""Native active scanner: detects real issues on an in-process target and
records a purpose-tagged audit trail; passive checks need no payloads."""

from __future__ import annotations

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from app.dast.active import native_active_scan
from app.dast.client import LiveClient
from app.dast.identity import Identity
from app.dast.scope import Scope


def _vuln_app():
    async def home(r: Request):
        return PlainTextResponse("ok")                       # no security headers
    async def item(r: Request):
        v = r.path_params["id"]
        if "'" in v:
            return PlainTextResponse("You have an error in your SQL syntax near '" + v, 500)
        if "etc/passwd" in v or "etc%2fpasswd" in v:
            return PlainTextResponse("root:x:0:0:root:/root:/bin/bash\n")
        if "<xss" in v:
            return Response("<html><body>" + v + "</body></html>", media_type="text/html")
        return JSONResponse({"id": v})
    return Starlette(routes=[Route("/", home), Route("/items/{id}", item)])


def _client():
    c = LiveClient(Scope(["app.test"]), max_rps=0, allow_mutating=False, capture_bodies=True)
    c._client = httpx.AsyncClient(transport=httpx.ASGITransport(app=_vuln_app()),
                                  follow_redirects=False)
    return c


@pytest.mark.asyncio
async def test_native_scan_finds_sqli_traversal_xss_and_headers():
    eps = [{"id": "e0", "method": "GET", "path": "/items/{id}", "id_params": ["id"]}]
    async with _client() as c:
        findings = await native_active_scan(c, "http://app.test", eps, Identity.anonymous())
    rules = {f["rule"] for f in findings}
    assert "dast.sqli" in rules
    assert "dast.reflected-xss" in rules
    assert "dast.missing-headers" in rules
    assert all(f["source"] == "dast" for f in findings)
    # audit trail records purpose for every request
    assert c.by_purpose.get("active:sqli", 0) >= 1
    assert c.by_purpose.get("passive:headers", 0) == 1
    assert all("url" in e and "purpose" in e for e in c.log)


@pytest.mark.asyncio
async def test_native_scan_respects_request_cap():
    eps = [{"id": f"e{i}", "method": "GET", "path": f"/items/{{id}}", "id_params": ["id"]}
           for i in range(3)]
    c = LiveClient(Scope(["app.test"]), max_rps=0, allow_mutating=False,
                   capture_bodies=True, max_requests=3)
    c._client = httpx.AsyncClient(transport=httpx.ASGITransport(app=_vuln_app()))
    from app.dast.client import RequestCapExceeded
    async with c:
        with pytest.raises(RequestCapExceeded):
            await native_active_scan(c, "http://app.test", eps, Identity.anonymous(),
                                     max_endpoints=50)


@pytest.mark.asyncio
async def test_dast_plan_is_zero_traffic_and_describes_scope():
    from app.db import SessionLocal, init_models
    from app.main import app as fastapi_app
    from app.models import (Artifact, ArtifactKind, Client, Finding, FindingSource,
                            FindingState, Project, Scan, ScanStatus, Severity)
    await init_models()
    async with SessionLocal() as s:
        c = Client(name="C", slug="c-plan"); s.add(c); await s.flush()
        p = Project(client_id=c.id, name="P"); s.add(p); await s.flush()
        a = Artifact(project_id=p.id, kind=ArtifactKind.local); s.add(a); await s.flush()
        scan = Scan(project_id=p.id, artifact_id=a.id, status=ScanStatus.completed, summary={
            "endpoints": [{"id": "e0", "method": "GET", "path": "/admin"},
                          {"id": "e1", "method": "GET", "path": "/users/{id}", "id_params": ["id"]}]})
        s.add(scan); await s.flush()
        s.add(Finding(scan_id=scan.id, title="Missing auth", severity=Severity.high,
            source=FindingSource.access, state=FindingState.proposed, cwe="CWE-306",
            raw={"rule": "access.missing-authn", "endpoint": "GET /admin"}))
        from app.models import DastTarget
        t = DastTarget(project_id=p.id, label="t", base_url="http://app.test",
                       allowed_hosts=["app.test"]); s.add(t); await s.flush()
        await s.commit(); sid, tid = scan.id, t.id

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fastapi_app),
                                 base_url="http://t") as client:
        plan = (await client.post(f"/api/scans/{sid}/dast/plan",
                                  json={"target_id": tid, "access_control": True,
                                        "active_scan": True})).json()
    assert plan["endpoints_in_scope"] == 2
    assert plan["access_findings_to_confirm"] == 1
    assert plan["checks"]["active_scan"] is True
    assert plan["estimated_requests"] > 0
    assert plan["target"]["allowed_hosts"] == ["app.test"]
    # with a path filter, only /users is in scope
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fastapi_app),
                                 base_url="http://t") as client:
        plan2 = (await client.post(f"/api/scans/{sid}/dast/plan",
                                   json={"target_id": tid, "include_paths": ["/users"]})).json()
    assert plan2["endpoints_in_scope"] == 1
