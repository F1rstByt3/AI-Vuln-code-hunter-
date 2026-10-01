"""The 'access' re-run stage: rebuilds the access-control map for an existing
scan, gets an AI verdict for every heuristic flag, and replaces only that
scan's access-control findings (the old noisy flags go away)."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

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

APP_PY = '''\
from flask import Flask
app = Flask(__name__)

@app.route("/orders/<int:order_id>", methods=["GET"])
def get_order(order_id):
    return Order.query.get(order_id).to_dict()

@app.route("/invoices/<int:invoice_id>", methods=["DELETE"])
def delete_invoice(invoice_id):
    Invoice.query.filter_by(id=invoice_id).delete()
    return "", 204
'''


class _Model:
    """Rejects every IDOR flag on GET, confirms the rest."""

    async def complete_json(self, messages, **kw):
        user = messages[-1]["content"]
        payload = json.loads(user.split("_JSON>>", 1)[1].split("<<END>>")[0])
        flags = payload.get("heuristic_flags") or payload.get("flags") or []
        verdicts = [{"flag_id": f["flag_id"],
                     "verdict": "rejected" if f.get("endpoint", "").startswith("GET")
                     else "confirmed",
                     "reason": "test verdict"} for f in flags]
        if "<<ACCESS_JSON>>" in user:
            return {"endpoints": [{"id": e["id"], "authn": "unclear", "authz": "unclear",
                                   "risk": "medium"} for e in payload["endpoints"]],
                    "flags": verdicts, "findings": []}
        return {"flags": verdicts}


@pytest.mark.asyncio
async def test_access_rerun_replaces_noisy_flags(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text(APP_PY)

    async def noop(*_a, **_k):
        return None

    monkeypatch.setattr(worker.events, "publish", noop)
    monkeypatch.setattr(worker.control, "clear_control", noop)
    monkeypatch.setattr(worker.Controller, "checkpoint", noop)
    monkeypatch.setattr(worker, "get_foundry_client", lambda cfg: _Model())

    endpoints = await worker.extract_endpoints(str(tmp_path))
    assert len(endpoints) == 2
    await init_models()
    async with SessionLocal() as s:
        c = Client(name="C", slug="c-rerun-access"); s.add(c); await s.flush()
        p = Project(client_id=c.id, name="P"); s.add(p); await s.flush()
        a = Artifact(project_id=p.id, kind=ArtifactKind.local,
                     meta={"workdir": str(tmp_path)})
        s.add(a); await s.flush()
        scan = Scan(project_id=p.id, artifact_id=a.id, status=ScanStatus.completed,
                    summary={"endpoints": endpoints})
        s.add(scan); await s.flush()
        # 30 stale, unverified heuristic flags from an old run + one AI finding.
        for i in range(30):
            s.add(Finding(scan_id=scan.id, title=f"old flag {i}", severity=Severity.medium,
                          source=FindingSource.access, state=FindingState.proposed, raw={}))
        s.add(Finding(scan_id=scan.id, title="SQLi", severity=Severity.high,
                      source=FindingSource.ai, state=FindingState.confirmed, raw={}))
        await s.commit()
        sid = scan.id

    await worker._rerun_stage({}, sid, "access")

    async with SessionLocal() as s:
        scan = await s.get(Scan, sid)
        rows = (await s.execute(select(Finding).where(Finding.scan_id == sid))).scalars().all()
    access = [f for f in rows if f.source == FindingSource.access]
    assert scan.status in (ScanStatus.completed, ScanStatus.needs_review), scan.error
    assert any(f.title == "SQLi" for f in rows)                 # other stages untouched
    assert not any(f.title.startswith("old flag") for f in access)
    assert access and all(f.raw.get("ai_verdict") == "confirmed" for f in access)
    assert all("DELETE" in (f.raw.get("endpoint") or "") for f in access)
    ac = scan.summary["access_control"]
    assert ac["flags_rejected"] >= 1 and ac["flags_confirmed"] >= 1
    assert all(e.get("id_kind") == "numeric" for e in scan.summary["endpoints"])
