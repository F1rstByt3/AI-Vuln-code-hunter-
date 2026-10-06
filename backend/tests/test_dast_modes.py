"""Per-target DAST mode: allowed checks, approval queue, auto-run after scan."""

from __future__ import annotations

import httpx
import pytest

from app.dast.modes import check_allowed, normalize_mode
from app.db import SessionLocal, init_models
from app.main import app
from app.models import (
    Artifact,
    ArtifactKind,
    Client,
    DastStatus,
    DastTarget,
    Project,
    Scan,
    ScanStatus,
)


def test_normalize_mode_defaults_and_clamps():
    m = normalize_mode(None)
    assert m == {"auto_run": False, "auto_run_active": False,
                 "require_approval": False, "allowed_checks": ["access_control"]}
    # unknown checks dropped; empty falls back to access_control
    m = normalize_mode({"allowed_checks": ["active_scan", "bogus"], "auto_run": 1})
    assert m["allowed_checks"] == ["active_scan"] and m["auto_run"] is True
    assert normalize_mode({"allowed_checks": []})["allowed_checks"] == ["access_control"]
    assert check_allowed({"allowed_checks": ["access_control"]}, "active_scan") is False


async def _seed(mode: dict):
    await init_models()
    async with SessionLocal() as s:
        c = Client(name="C", slug=f"c-mode-{id(mode)}"); s.add(c); await s.flush()
        p = Project(client_id=c.id, name="P"); s.add(p); await s.flush()
        a = Artifact(project_id=p.id, kind=ArtifactKind.local); s.add(a); await s.flush()
        scan = Scan(project_id=p.id, artifact_id=a.id, status=ScanStatus.completed,
                    summary={"endpoints": []})
        s.add(scan); await s.flush()
        t = DastTarget(project_id=p.id, label="t", base_url="https://stg.test",
                       allowed_hosts=["stg.test"], mode_config=mode)
        s.add(t); await s.commit()
        return scan.id, t.id, p.id


@pytest.mark.asyncio
async def test_active_scan_blocked_when_not_in_allowed_checks(monkeypatch):
    sid, tid, _ = await _seed({"allowed_checks": ["access_control"]})
    jobs = []
    monkeypatch.setattr("app.api.dast.get_arq",
                        lambda: _fake_arq(jobs))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t") as client:
        # active_scan also needs target.active_scan_enabled; set it so the mode
        # check is what trips.
        await client.put(f"/api/dast-targets/{tid}", json={"active_scan_enabled": True})
        r = await client.post(f"/api/scans/{sid}/dast", json={
            "target_id": tid, "authorize": True, "active_scan": True})
    assert r.status_code == 400 and "disabled for this target" in r.text


@pytest.mark.asyncio
async def test_approval_queue_flow(monkeypatch):
    sid, tid, _ = await _seed({"require_approval": True})
    jobs: list = []
    monkeypatch.setattr("app.api.dast.get_arq", lambda: _fake_arq(jobs))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t") as client:
        r = await client.post(f"/api/scans/{sid}/dast",
                              json={"target_id": tid, "authorize": True})
        run = r.json()
        assert run["status"] == "pending_approval" and jobs == []   # not enqueued
        rid = run["id"]
        # a second launch is refused while one is pending
        r2 = await client.post(f"/api/scans/{sid}/dast",
                               json={"target_id": tid, "authorize": True})
        assert r2.status_code == 409
        approved = (await client.post(f"/api/dast-runs/{rid}/approve")).json()
        assert approved["status"] == "queued" and jobs == [rid]      # now enqueued


@pytest.mark.asyncio
async def test_reject_run(monkeypatch):
    sid, tid, _ = await _seed({"require_approval": True})
    monkeypatch.setattr("app.api.dast.get_arq", lambda: _fake_arq([]))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t") as client:
        rid = (await client.post(f"/api/scans/{sid}/dast",
                                 json={"target_id": tid, "authorize": True})).json()["id"]
        rejected = (await client.post(f"/api/dast-runs/{rid}/reject")).json()
    assert rejected["status"] == "rejected"


@pytest.mark.asyncio
async def test_autorun_creates_safe_run(monkeypatch):
    sid, tid, _ = await _seed({"auto_run": True})
    jobs: list = []
    monkeypatch.setattr("app.worker.get_arq", lambda: _fake_arq(jobs))
    emitted: list = []

    async def emit(e):
        emitted.append(e)

    from app import worker
    async with SessionLocal() as s:
        scan = await s.get(Scan, sid)
        await worker._maybe_autorun_dast(s, scan, emit)
        from sqlalchemy import select

        from app.models import DastRun
        runs = (await s.execute(select(DastRun).where(DastRun.scan_id == sid))).scalars().all()
    assert len(runs) == 1
    run = runs[0]
    assert run.status == DastStatus.queued and jobs == [run.id]
    assert run.authorized_by == "auto (mode_config)"
    assert run.allow_mutating is False and run.config["active_scan"] is False
    assert run.config["source"] == "auto"


@pytest.mark.asyncio
async def test_autorun_respects_approval(monkeypatch):
    sid, tid, _ = await _seed({"auto_run": True, "require_approval": True})
    monkeypatch.setattr("app.worker.get_arq", lambda: _fake_arq([]))
    from app import worker
    async with SessionLocal() as s:
        scan = await s.get(Scan, sid)
        await worker._maybe_autorun_dast(s, scan, lambda e: _noop())
        from sqlalchemy import select

        from app.models import DastRun
        run = (await s.execute(select(DastRun).where(DastRun.scan_id == sid))).scalars().one()
    assert run.status == DastStatus.pending_approval


class _fake_arq:
    def __init__(self, sink):
        self.sink = sink

    def __await__(self):
        async def _self():
            return self
        return _self().__await__()

    async def enqueue_job(self, name, *args):
        self.sink.append(args[0])


async def _noop():
    return None
