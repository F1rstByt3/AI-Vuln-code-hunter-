"""AI profiles: save / activate / pin-per-scan, with secrets never echoed back.

Runs the real FastAPI routes against in-memory SQLite (no Postgres/Redis)."""

from __future__ import annotations

import httpx
import pytest

from app.db import SessionLocal, init_models
from app.main import app
from app.runtime_config import get_foundry_config
from app.worker import _planned_stages


class _Scfg:
    semgrep_enabled = True
    sonarqube_enabled = False


def test_planned_stages_follow_checks():
    all_on = _planned_stages({"semgrep", "ai"}, _Scfg())
    assert all_on.index("access_control") < all_on.index("ai_plan")
    assert all_on.index("ai_coverage") < all_on.index("ai_access") < all_on.index("ai_judge")
    assert all_on.index("ai_judge") < all_on.index("ai_verify") < all_on.index("ai_exploit")

    off = _planned_stages({"semgrep", "ai"}, _Scfg(),
                          {"coverage": False, "verify": False, "access_control": False})
    assert not {"access_control", "ai_coverage", "ai_access", "ai_verify"} & set(off)

    static = _planned_stages({"semgrep"}, _Scfg())
    assert "access_control" in static and "ai_access" not in static


@pytest.fixture
async def client():
    await init_models()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_profile_lifecycle(client):
    # Configure the active settings as a cloud deployment with a secret key.
    r = await client.put("/api/settings/foundry", json={
        "endpoint": "https://my-foundry.services.ai.azure.com/openai/v1",
        "api_key": "sk-cloud-secret", "deployment": "gpt-5-codex",
        "roles": {"reviewers": [{"deployment": "gpt-5-codex"}],
                  "judge": {"deployment": "gpt-5"}, "verifier": {"deployment": "o4-mini"}},
    })
    assert r.status_code == 200, r.text
    assert r.json()["kind"] == "cloud"

    # Snapshot it as a profile — the key is copied server-side, never returned.
    r = await client.post("/api/settings/profiles", json={"name": "Azure prod"})
    assert r.status_code == 200, r.text
    cloud = r.json()
    assert cloud["api_key_set"] is True and "sk-cloud-secret" not in r.text
    assert cloud["roles"]["verifier"]["deployment"] == "o4-mini"
    assert cloud["active"] is False

    # Duplicate names are rejected.
    r = await client.post("/api/settings/profiles", json={"name": "Azure prod"})
    assert r.status_code == 409

    # A local profile from a template, activated immediately.
    r = await client.post("/api/settings/profiles", json={
        "name": "Local Ollama", "from_current": False, "activate": True,
        "settings": {"endpoint": "http://host.docker.internal:11434", "api_style": "local",
                     "deployment": "qwen2.5-coder:32b", "context_tokens": 32768,
                     "concurrency": 1},
    })
    assert r.status_code == 200, r.text
    local = r.json()
    assert local["kind"] == "local" and local["active"] is True
    assert local["api_key_set"] is False

    fs = (await client.get("/api/settings/foundry")).json()
    assert fs["active_profile_name"] == "Local Ollama"
    assert fs["endpoint"] == "http://host.docker.internal:11434"
    assert fs["context_tokens"] == 32768 and fs["concurrency"] == 1

    # Editing the active config writes back to the active profile.
    r = await client.put("/api/settings/foundry", json={"deployment": "llama3.1:70b"})
    assert r.status_code == 200
    profiles = {p["name"]: p for p in (await client.get("/api/settings/profiles")).json()}
    assert profiles["Local Ollama"]["deployment"] == "llama3.1:70b"
    assert profiles["Azure prod"]["deployment"] == "gpt-5-codex"

    # A scan can pin a non-active profile; the worker resolves its config.
    async with SessionLocal() as s:
        pinned = await get_foundry_config(s, profile_id=cloud["id"])
        active = await get_foundry_config(s)
    assert pinned.api_key == "sk-cloud-secret" and not pinned.is_local
    assert pinned.resolve_roles().verifier.deployment == "o4-mini"
    assert active.is_local and active.resolve_roles().concurrency == 1

    # A profile with no endpoint is mock mode; testing it needs no network.
    r = await client.post("/api/settings/profiles", json={
        "name": "Mock", "from_current": False, "settings": {"deployment": "mock"}})
    mock = r.json()
    assert mock["kind"] == "mock"
    r = await client.post(f"/api/settings/profiles/{mock['id']}/test")
    assert r.status_code == 200 and r.json()["ok"] is True

    # Deleting the active profile keeps the active config, just detaches it.
    r = await client.delete(f"/api/settings/profiles/{local['id']}")
    assert r.status_code == 204
    fs = (await client.get("/api/settings/foundry")).json()
    assert fs["active_profile_id"] is None
    assert fs["deployment"] == "llama3.1:70b"

    # Re-activating the cloud profile restores its secret for scans.
    r = await client.post(f"/api/settings/profiles/{cloud['id']}/activate")
    assert r.status_code == 200 and r.json()["kind"] == "cloud"
    async with SessionLocal() as s:
        assert (await get_foundry_config(s)).api_key == "sk-cloud-secret"
