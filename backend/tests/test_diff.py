"""Scan-to-scan diff: new / fixed / still-open, matching across line drift."""

from __future__ import annotations

import httpx
import pytest

from app.db import SessionLocal, init_models
from app.diffing import diff_findings, fingerprint
from app.main import app
from app.models import (Artifact, ArtifactKind, Client, Finding, FindingSource,
                        FindingState, Project, Scan, ScanStatus, Severity)


def _f(scan_id, title, sev, state="proposed", cwe=None, fp="a.py", line=1, source="ai", raw=None):
    return Finding(scan_id=scan_id, title=title, severity=Severity(sev),
                   state=FindingState(state), source=FindingSource(source), cwe=cwe,
                   file_path=fp, line_start=line, raw=raw or {})


def test_fingerprint_ignores_line_drift():
    a = _f("s", "SQLi", "high", cwe="CWE-89", fp="db.py", line=10)
    b = _f("s", "SQL injection here", "high", cwe="CWE-89", fp="db.py", line=88)
    assert fingerprint(a) == fingerprint(b)   # same CWE + file, different line/title


def test_diff_classifies():
    base = [
        _f("b", "SQLi", "high", cwe="CWE-89", fp="db.py", line=10),          # stays
        _f("b", "Weak hash", "medium", cwe="CWE-328", fp="auth.py"),         # fixed
    ]
    cur = [
        _f("c", "SQLi moved", "critical", cwe="CWE-89", fp="db.py", line=55),  # still open, sev up
        _f("c", "XSS", "high", cwe="CWE-79", fp="views.py"),                   # new
        _f("c", "Old FP", "low", cwe="CWE-200", fp="x.py", state="dismissed"), # ignored (dismissed)
    ]
    d = diff_findings(cur, base)
    assert d["counts"] == {"new": 1, "fixed": 1, "still_open": 1}
    assert d["new"][0]["cwe"] == "CWE-79"
    assert d["fixed"][0]["cwe"] == "CWE-328"
    assert d["still_open"][0]["severity_changed_from"] == "high"


@pytest.mark.asyncio
async def test_diff_endpoint_picks_previous_scan():
    await init_models()
    async with SessionLocal() as s:
        c = Client(name="C", slug="c-diff"); s.add(c); await s.flush()
        p = Project(client_id=c.id, name="P"); s.add(p); await s.flush()
        a = Artifact(project_id=p.id, kind=ArtifactKind.local); s.add(a); await s.flush()
        old = Scan(project_id=p.id, artifact_id=a.id, status=ScanStatus.completed, summary={})
        s.add(old); await s.flush()
        s.add(_f(old.id, "SQLi", "high", cwe="CWE-89", fp="db.py"))
        s.add(_f(old.id, "Weak hash", "medium", cwe="CWE-328", fp="auth.py"))
        new = Scan(project_id=p.id, artifact_id=a.id, status=ScanStatus.completed, summary={})
        s.add(new); await s.flush()
        s.add(_f(new.id, "SQLi", "high", cwe="CWE-89", fp="db.py"))
        s.add(_f(new.id, "SSRF", "high", cwe="CWE-918", fp="net.py"))
        await s.commit()
        new_id = new.id

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t") as client:
        d = (await client.get(f"/api/scans/{new_id}/diff")).json()
    assert d["baseline"]["id"]
    assert d["counts"] == {"new": 1, "fixed": 1, "still_open": 1}
    assert d["new"][0]["cwe"] == "CWE-918"
