"""The agentic review loop should run end-to-end against the mock Foundry client
with no Azure, DB, or Redis — turning static candidates into findings, emitting a
human-review item, and computing a risk score."""

from __future__ import annotations

import pytest

from app.ai.agent import run_review
from app.ai.foundry import MockFoundryClient


@pytest.mark.asyncio
async def test_run_review_mock_pipeline():
    candidates = [
        {
            "source": "semgrep", "title": "SQL injection", "message": "tainted query",
            "severity": "high", "cwe": "CWE-89", "owasp": "A03:2021",
            "file_path": "app/db.py", "line_start": 12, "code_snippet": "cur.execute(q)",
        }
    ]
    files = [{"path": "app/db.py", "language": "python", "size": 200}]
    emitted: list[dict] = []

    async def emit(event):
        emitted.append(event)

    async def read_file(_path):
        return "line1\nline2\ncur.execute(q)\n"

    result = await run_review(
        client=MockFoundryClient(),
        model="gpt-codex",
        instructions="focus on injection",
        files=files,
        candidates=candidates,
        read_file=read_file,
        emit=emit,
    )

    findings = result["findings"]
    assert len(findings) >= 2
    assert any(f["state"] == "needs_info" and f["human_question"] for f in findings)
    assert any(f["cwe"] == "CWE-89" for f in findings)

    summary = result["summary"]
    assert summary["risk_score"] > 0
    assert summary["needs_review"] >= 1

    # streamed narration + finding events were emitted
    assert any(e["type"] == "token" for e in emitted)
    assert any(e["type"] == "finding" for e in emitted)


@pytest.mark.asyncio
async def test_evidence_policy_demotes_unconfirmed():
    """A 'confirmed' finding with no file evidence must be demoted to 'proposed'."""
    from app.ai.agent import _normalize

    f = _normalize({"title": "x", "state": "confirmed", "severity": "high", "confidence": 0.9})
    assert f["state"] == "proposed"
    assert f["confidence"] <= 0.4
