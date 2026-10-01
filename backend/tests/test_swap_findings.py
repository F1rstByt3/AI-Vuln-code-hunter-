"""The final AI findings are swapped in atomically: a failure while building /
inserting the new set must leave the OLD findings intact, never wipe them."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app import worker
from app.db import SessionLocal, init_models
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


async def _seed(n_old: int = 5) -> str:
    await init_models()
    async with SessionLocal() as s:
        c = Client(name="C", slug=f"c-swap-{id(object())}-{n_old}"); s.add(c); await s.flush()
        p = Project(client_id=c.id, name="P"); s.add(p); await s.flush()
        a = Artifact(project_id=p.id, kind=ArtifactKind.local); s.add(a); await s.flush()
        scan = Scan(project_id=p.id, artifact_id=a.id, status=ScanStatus.completed, summary={})
        s.add(scan); await s.flush()
        for i in range(n_old):
            s.add(Finding(scan_id=scan.id, title=f"old {i}", severity=Severity.high,
                          source=FindingSource.ai, state=FindingState.confirmed, raw={}))
        # a non-AI finding that must never be touched by an AI swap
        s.add(Finding(scan_id=scan.id, title="semgrep hit", severity=Severity.low,
                      source=FindingSource.semgrep, state=FindingState.proposed, raw={}))
        await s.commit()
        return scan.id


async def _count(scan_id, source=None):
    async with SessionLocal() as s:
        stmt = select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)
        if source:
            stmt = stmt.where(Finding.source == source)
        return (await s.execute(stmt)).scalar_one()


@pytest.mark.asyncio
async def test_swap_replaces_only_target_source():
    sid = await _seed(5)
    async with SessionLocal() as s:
        scan = await s.get(Scan, sid)
        await worker._swap_findings(s, scan, worker._AI_SOURCES, [
            {"title": "new A", "severity": "high", "source": "ai", "state": "proposed"},
            {"title": "new B", "severity": "medium", "source": "ai", "state": "proposed"},
        ])
    assert await _count(sid, FindingSource.ai) == 2          # 5 old → 2 new
    titles = {f for f in ["new A", "new B"]}
    async with SessionLocal() as s:
        rows = (await s.execute(select(Finding.title).where(
            Finding.scan_id == sid, Finding.source == FindingSource.ai))).scalars().all()
    assert set(rows) == titles
    assert await _count(sid, FindingSource.semgrep) == 1     # untouched


@pytest.mark.asyncio
async def test_failed_swap_keeps_old_findings(monkeypatch):
    sid = await _seed(5)

    # Make building the 2nd new finding blow up, mid-insert, after the DELETE.
    calls = {"n": 0}
    real = worker._finding_from_dict

    def boom(scan_id, f):
        calls["n"] += 1
        if calls["n"] == 2:
            raise ValueError("simulated bad finding")
        return real(scan_id, f)

    monkeypatch.setattr(worker, "_finding_from_dict", boom)

    async with SessionLocal() as s:
        scan = await s.get(Scan, sid)
        with pytest.raises(ValueError):
            await worker._swap_findings(s, scan, worker._AI_SOURCES, [
                {"title": "new A", "severity": "high", "source": "ai"},
                {"title": "new B", "severity": "high", "source": "ai"},
            ])
        await s.rollback()   # caller's exception handler does this

    # The DELETE was never committed → the 5 old AI findings are still there.
    assert await _count(sid, FindingSource.ai) == 5
    assert await _count(sid, FindingSource.semgrep) == 1
