"""Deleting files/scans/projects/clients removes the DB rows (by cascade) and
reclaims stored artifact blobs + working trees."""

from __future__ import annotations

import os
import uuid

import httpx
import pytest
from sqlalchemy import func, select

from app.db import SessionLocal, init_models
from app.main import app
from app.models import (
    Artifact,
    ArtifactKind,
    Client,
    Finding,
    FindingSource,
    FindingState,
    Project,
    Scan,
    ScanStatus,
    Severity,
)


class _FakeStorage:
    deleted: list = []

    async def delete_object(self, key):
        _FakeStorage.deleted.append(key)


@pytest.fixture(autouse=True)
def fake_storage(monkeypatch):
    _FakeStorage.deleted = []
    import app.api.artifacts as art
    monkeypatch.setattr(art, "get_storage", lambda: _FakeStorage())


async def _seed(scan_status=ScanStatus.completed, with_workdir=False):
    await init_models()
    async with SessionLocal() as s:
        c = Client(name="C", slug=f"c-del-{uuid.uuid4().hex[:8]}"); s.add(c); await s.flush()
        p = Project(client_id=c.id, name="P"); s.add(p); await s.flush()
        meta = {}
        a = Artifact(project_id=p.id, kind=ArtifactKind.local,
                     storage_key=f"artifacts/{p.id}/blob.zip", meta=meta)
        s.add(a); await s.flush()
        if with_workdir:
            from app.ingestion import WORKROOT
            wd = os.path.join(WORKROOT, a.id)
            os.makedirs(os.path.join(wd, "src"), exist_ok=True)
            open(os.path.join(wd, "src", "x.py"), "w").close()
        scan = Scan(project_id=p.id, artifact_id=a.id, status=scan_status, summary={})
        s.add(scan); await s.flush()
        s.add(Finding(scan_id=scan.id, title="f", severity=Severity.low,
                      source=FindingSource.ai, state=FindingState.proposed, raw={}))
        await s.commit()
        return {"client": c.id, "project": p.id, "artifact": a.id, "scan": scan.id,
                "storage_key": a.storage_key}


async def _count(model, **where):
    async with SessionLocal() as s:
        stmt = select(func.count()).select_from(model)
        for k, v in where.items():
            stmt = stmt.where(getattr(model, k) == v)
        return (await s.execute(stmt)).scalar_one()


@pytest.mark.asyncio
async def test_delete_artifact_purges_blob_and_cascades_scans():
    ids = await _seed(with_workdir=True)
    from app.ingestion import WORKROOT
    wd = os.path.join(WORKROOT, ids["artifact"])
    assert os.path.isdir(wd)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t") as client:
        r = await client.delete(f"/api/artifacts/{ids['artifact']}")
    assert r.status_code == 204
    assert ids["storage_key"] in _FakeStorage.deleted
    assert not os.path.isdir(wd)                                  # workdir removed
    assert await _count(Artifact, id=ids["artifact"]) == 0
    assert await _count(Scan, id=ids["scan"]) == 0               # cascaded
    assert await _count(Finding, scan_id=ids["scan"]) == 0


@pytest.mark.asyncio
async def test_delete_scan_keeps_artifact():
    ids = await _seed()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t") as client:
        r = await client.delete(f"/api/scans/{ids['scan']}")
    assert r.status_code == 204
    assert await _count(Scan, id=ids["scan"]) == 0
    assert await _count(Finding, scan_id=ids["scan"]) == 0
    assert await _count(Artifact, id=ids["artifact"]) == 1       # artifact kept
    assert _FakeStorage.deleted == []                            # no blob touched


@pytest.mark.asyncio
async def test_delete_running_scan_refused():
    ids = await _seed(scan_status=ScanStatus.running)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t") as client:
        r = await client.delete(f"/api/scans/{ids['scan']}")
    assert r.status_code == 409 and "cancel" in r.text
    assert await _count(Scan, id=ids["scan"]) == 1


@pytest.mark.asyncio
async def test_delete_project_purges_artifacts():
    ids = await _seed()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t") as client:
        r = await client.delete(f"/api/projects/{ids['project']}")
    assert r.status_code == 204
    assert ids["storage_key"] in _FakeStorage.deleted
    assert await _count(Project, id=ids["project"]) == 0
    assert await _count(Artifact, id=ids["artifact"]) == 0
    assert await _count(Scan, id=ids["scan"]) == 0


@pytest.mark.asyncio
async def test_delete_client_purges_descendant_artifacts():
    ids = await _seed()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t") as client:
        r = await client.delete(f"/api/clients/{ids['client']}")
    assert r.status_code == 204
    assert ids["storage_key"] in _FakeStorage.deleted
    assert await _count(Client, id=ids["client"]) == 0
    assert await _count(Project, id=ids["project"]) == 0
    assert await _count(Artifact, id=ids["artifact"]) == 0
