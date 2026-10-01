"""HTML report: renders, and escapes untrusted finding content (no injection)."""

from __future__ import annotations

import pytest

from app.db import SessionLocal, init_models
from app.main import app
from app.models import (Artifact, ArtifactKind, Client, Finding, FindingSource,
                        FindingState, Project, Scan, ScanStatus, Severity)
import httpx


@pytest.mark.asyncio
async def test_report_renders_and_escapes():
    await init_models()
    async with SessionLocal() as s:
        c = Client(name="C", slug="c-rep"); s.add(c); await s.flush()
        p = Project(client_id=c.id, name="Acme <Corp>"); s.add(p); await s.flush()
        a = Artifact(project_id=p.id, kind=ArtifactKind.local); s.add(a); await s.flush()
        scan = Scan(project_id=p.id, artifact_id=a.id, status=ScanStatus.completed, summary={
            "risk_score": 72.5, "by_severity": {"high": 1, "medium": 0},
            "endpoints": [{"method": "GET", "path": "/admin", "authn": "none",
                           "authz": "none", "risk": "high"}],
            "coverage": {"files_loaded": 10, "files_total": 10, "files_unreviewed": 0,
                         "verification": {"true_positive": 1, "false_positive": 0}}})
        s.add(scan); await s.flush()
        # a finding carrying an XSS-y payload in several fields
        s.add(Finding(scan_id=scan.id, title="XSS <script>alert(1)</script>",
            description="tainted <img src=x onerror=alert(1)>", severity=Severity.high,
            source=FindingSource.access, state=FindingState.confirmed, cwe="CWE-79",
            code_snippet="<script>evil()</script>",
            raw={"endpoint": "GET /admin", "dast": {"verdict": "confirmed_vuln",
                 "by": "access-replay", "evidence": {"reason": "anon got 200",
                 "requests": [{"role": "none", "status": 200, "target": "http://t/admin"}]}}}))
        s.add(Finding(scan_id=scan.id, title="Dismissed thing", severity=Severity.low,
            source=FindingSource.semgrep, state=FindingState.dismissed,
            triage_note="false positive"))
        await s.commit()
        sid = scan.id

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t") as client:
        r = await client.get(f"/api/scans/{sid}/export/report")
    assert r.status_code == 200
    body = r.text
    assert body.startswith("<!doctype html>")
    # untrusted content is escaped, never live markup
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert "onerror=alert(1)" not in body or "&lt;img" in body
    assert "Acme &lt;Corp&gt;" in body
    # the substance is present
    assert "72.5" in body and "confirmed live" in body
    assert "Access-control matrix" in body and "/admin" in body
    assert "Dismissed (1)" in body
