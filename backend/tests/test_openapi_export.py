"""OpenAPI export for Burp: framework route syntax → OpenAPI templates, BAC
annotations, risk filtering."""

from __future__ import annotations

import httpx
import pytest

from app.api.export import _oas_path
from app.db import SessionLocal, init_models
from app.main import app
from app.models import Artifact, ArtifactKind, Client, Project, Scan, ScanStatus


def test_route_syntax_normalised():
    assert _oas_path("/users/:userId") == ("/users/{userId}", ["userId"])
    assert _oas_path("/invoices/<int:pk>/") == ("/invoices/{pk}/", ["pk"])
    assert _oas_path("/api/[id]/items/{itemId:int}") == ("/api/{id}/items/{itemId}",
                                                         ["id", "itemId"])
    assert _oas_path("^orders/(?P<order_id>\\d+)/$") == ("/orders/{order_id}/", ["order_id"])


@pytest.mark.asyncio
async def test_openapi_export_annotates_bac():
    await init_models()
    async with SessionLocal() as s:
        c = Client(name="C", slug="c-oas"); s.add(c); await s.flush()
        p = Project(client_id=c.id, name="P"); s.add(p); await s.flush()
        a = Artifact(project_id=p.id, kind=ArtifactKind.local); s.add(a); await s.flush()
        scan = Scan(project_id=p.id, artifact_id=a.id, status=ScanStatus.completed, summary={
            "endpoints": [
                {"id": "e0", "method": "DELETE", "path": "/users/:id", "file_path": "u.js",
                 "line": 3, "framework": "express", "handler": "del", "auth_hints": [],
                 "authn": "none", "authz": "none", "risk": "high", "id_params": ["id"],
                 "state_changing": True},
                {"id": "e1", "method": "GET", "path": "/health", "file_path": "u.js",
                 "line": 9, "framework": "express", "handler": "h", "auth_hints": [],
                 "authn": "public", "authz": "none", "risk": "low"},
            ]})
        s.add(scan); await s.commit()
        sid = scan.id
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t") as client:
        spec = (await client.get(f"/api/scans/{sid}/export/openapi",
                                 params={"base_url": "https://app.test/"})).json()
        risky = (await client.get(f"/api/scans/{sid}/export/openapi",
                                  params={"min_risk": "medium"})).json()
    assert spec["servers"] == [{"url": "https://app.test"}]
    op = spec["paths"]["/users/{id}"]["delete"]
    assert op["tags"][0] == "risk-high"
    assert op["parameters"][0]["name"] == "id"
    assert any("IDOR" in t for t in op["x-bac-tests"])
    assert spec["paths"]["/health"]["get"]["security"] == []
    assert "/health" not in risky["paths"] and "/users/{id}" in risky["paths"]
