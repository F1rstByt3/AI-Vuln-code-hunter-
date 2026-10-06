"""DAST: encryption, scope guard, the replay client, and the confirmation loop
against a real in-process ASGI target (no external network)."""

from __future__ import annotations

import os

os.environ.setdefault("DAST_SECRET_KEY", "test-passphrase-for-dast-secrets")

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from app import secrets
from app.dast import replay
from app.dast.client import LiveClient
from app.dast.identity import Identity, redact_headers
from app.dast.scope import Scope, ScopeError, normalize_hosts


# --------------------------------------------------------------- unit: crypto
def test_encrypt_roundtrip_and_never_plaintext():
    token = secrets.encrypt("s3cr3t-token")
    assert "s3cr3t-token" not in token
    assert secrets.decrypt(token) == "s3cr3t-token"
    assert secrets.try_decrypt("garbage") is None


def test_redaction_hides_auth():
    red = redact_headers({"Authorization": "Bearer abc", "Accept": "json"})
    assert red["Authorization"] == "<redacted>" and red["Accept"] == "json"


# --------------------------------------------------------------- unit: scope
def test_scope_allows_only_listed_hosts():
    hosts = normalize_hosts("https://app.test:8080/x", ["api.test", "https://cdn.test/y"])
    assert set(hosts) == {"app.test", "api.test", "cdn.test"}
    scope = Scope(hosts)
    assert scope.permits("https://api.test/users")
    assert not scope.permits("https://evil.test/")
    with pytest.raises(ScopeError):
        scope.check("http://evil.test/")


def test_fill_path():
    assert replay.fill_path("/users/{id}/posts/{pid}", {"id": "7"}) == "/users/7/posts/1"


# ------------------------------------------------- integration: a live target
def _target_app():
    """A tiny app modelling an access-control bug and a correct control.

    /public            — open
    /admin/stats       — should require auth; here it DOESN'T (vuln)
    /orders/{id}       — requires auth AND ownership; enforces it (safe)
    """
    async def public(r: Request):
        return JSONResponse({"ok": True})

    async def admin_stats(r: Request):        # BUG: no auth check
        return JSONResponse({"secret": "stats"})

    async def get_order(r: Request):          # SAFE: enforces auth + ownership
        token = r.headers.get("authorization", "")
        user = {"Bearer tokenA": "A", "Bearer tokenB": "B"}.get(token)
        if not user:
            return JSONResponse({"error": "unauthenticated"}, status_code=401)
        owner = {"1": "A", "2": "B"}.get(r.path_params["id"])
        if owner != user:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        return JSONResponse({"id": r.path_params["id"], "owner": owner})

    async def get_doc(r: Request):            # BUG: authenticated but no ownership check
        if not r.headers.get("authorization"):
            return JSONResponse({"error": "unauthenticated"}, status_code=401)
        return JSONResponse({"id": r.path_params["id"], "body": f"contents of {r.path_params['id']}"})

    return Starlette(routes=[
        Route("/public", public),
        Route("/admin/stats", admin_stats),
        Route("/orders/{id}", get_order),
        Route("/docs/{id}", get_doc),
    ])


def _client_for(app):
    """A LiveClient whose transport is the in-process ASGI app (any in-scope host)."""
    scope = Scope(["app.test"])
    lc = LiveClient(scope, max_rps=0, allow_mutating=False)
    lc._client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                   follow_redirects=False)
    return lc


@pytest.mark.asyncio
async def test_probe_confirms_missing_auth():
    async with _client_for(_target_app()) as c:
        verdict, ev = await replay.probe_missing_authn(
            c, "http://app.test/admin/stats", "GET")
    assert verdict == "confirmed_vuln"
    assert ev["requests"][0]["status"] == 200


@pytest.mark.asyncio
async def test_probe_confirms_idor_and_enforcement():
    idA = Identity(role="userA", headers={"Authorization": "Bearer tokenA"})
    idB = Identity(role="userB", headers={"Authorization": "Bearer tokenB"})
    seeds = {"userB": {"id": ["2"]}}  # object 2 belongs to B
    async with _client_for(_target_app()) as c:
        # userA tries to read B's order -> the app enforces ownership (403)
        verdict, ev = await replay.probe_idor(
            c, "/orders/{id}", "GET", "http://app.test", ["id"], seeds, [idA])
    assert verdict == "enforced"
    assert any(r["status"] == 403 for r in ev["requests"])


@pytest.mark.asyncio
async def test_probe_confirms_idor_by_body_match():
    # /docs/{id} has no ownership check: userA reads userB's doc, identical body.
    idA = Identity(role="userA", headers={"Authorization": "Bearer tokenA"})
    idB = Identity(role="userB", headers={"Authorization": "Bearer tokenB"})
    seeds = {"userB": {"id": ["77"]}}
    by_role = {"userA": idA, "userB": idB}
    async with _client_for(_target_app()) as c:
        verdict, ev = await replay.probe_idor(
            c, "/docs/{id}", "GET", "http://app.test", ["id"], seeds, [idA], by_role)
    assert verdict == "confirmed_vuln"
    assert "byte-for-byte" in ev["reason"]
    assert any(r.get("baseline") for r in ev["requests"])  # owner baseline captured


@pytest.mark.asyncio
async def test_idor_2xx_without_body_match_is_inconclusive():
    # A 200 whose body differs from the owner's must NOT auto-confirm.
    idA = Identity(role="userA", headers={"Authorization": "Bearer tokenA"})
    idB = Identity(role="userB", headers={"Authorization": "Bearer tokenB"})
    seeds = {"userB": {"id": ["2"]}}       # /orders/2 is B's; A gets 403 there
    by_role = {"userA": idA, "userB": idB}
    async with _client_for(_target_app()) as c:
        verdict, _ = await replay.probe_idor(
            c, "/orders/{id}", "GET", "http://app.test", ["id"], seeds, [idA], by_role)
    assert verdict == "enforced"           # A denied → enforced, not confirmed


@pytest.mark.asyncio
async def test_scope_blocks_out_of_scope_request():
    async with _client_for(_target_app()) as c:
        with pytest.raises(ScopeError):
            await c.send("GET", "http://evil.test/", Identity.anonymous())


@pytest.mark.asyncio
async def test_mutating_blocked_unless_allowed():
    async with _client_for(_target_app()) as c:
        r = await c.send("DELETE", "http://app.test/orders/1", Identity.anonymous())
    assert r.error and "allow_mutating" in r.error


# ------------------------------------------------- API: targets & creds masked
@pytest.mark.asyncio
async def test_target_and_credential_api_masks_secrets():
    from app.db import init_models
    from app.main import app
    from app.db import SessionLocal
    from app.models import Client, Project

    await init_models()
    async with SessionLocal() as s:
        c = Client(name="C", slug="c-dast"); s.add(c); await s.flush()
        p = Project(client_id=c.id, name="P"); s.add(p); await s.flush()
        pid = p.id
        await s.commit()

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t") as client:
        t = (await client.post(f"/api/projects/{pid}/dast-targets", json={
            "base_url": "https://app.example.com", "label": "Staging",
            "allowed_hosts": ["api.example.com"]})).json()
        assert set(t["allowed_hosts"]) == {"app.example.com", "api.example.com"}

        cr = await client.post(f"/api/dast-targets/{t['id']}/credentials", json={
            "role_label": "userA", "auth_kind": "bearer", "secret": "super-secret-token"})
        assert cr.status_code == 200, cr.text
        assert "super-secret-token" not in cr.text
        assert cr.json()["secret_set"] is True

        listed = (await client.get(f"/api/projects/{pid}/dast-targets")).json()
        assert "super-secret-token" not in str(listed)
        assert listed[0]["credentials"][0]["secret_set"] is True

        # launching a run without authorize is refused
        scans = await _make_scan(pid)
        r = await client.post(f"/api/scans/{scans}/dast",
                              json={"target_id": t["id"], "authorize": False})
        assert r.status_code == 400 and "authorisation" in r.text.lower()


async def _make_scan(project_id: str) -> str:
    from app.db import SessionLocal
    from app.models import Artifact, ArtifactKind, Scan, ScanStatus
    async with SessionLocal() as s:
        a = Artifact(project_id=project_id, kind=ArtifactKind.local); s.add(a); await s.flush()
        scan = Scan(project_id=project_id, artifact_id=a.id, status=ScanStatus.completed,
                    summary={"endpoints": []})
        s.add(scan); await s.commit()
        return scan.id
