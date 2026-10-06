"""The agentic review loop should run end-to-end against the mock Foundry client
with no Azure, DB, or Redis — turning static candidates into findings, emitting a
human-review item, and computing a risk score."""

from __future__ import annotations

import pytest

from app.ai.agent import run_review
from app.ai.foundry import MockFoundryClient, ModelRole, ReviewRoles


def _roles(reviewers=("gpt-codex",), judge=None):
    return ReviewRoles(
        chat=ModelRole(deployment="gpt-4o"),
        reviewers=[ModelRole(deployment=r) for r in reviewers],
        judge=ModelRole(deployment=judge) if judge else None,
    )


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
        roles=_roles(),
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
async def test_ensemble_with_judge_confirms_and_dismisses():
    """Two reviewers + a judge: the judge confirms evidence-backed findings, dismisses
    the no-evidence one, and dedupes identical findings from both reviewers."""
    candidates = [{
        "source": "semgrep", "title": "SQL injection", "severity": "high", "cwe": "CWE-89",
        "file_path": "app/db.py", "line_start": 12, "code_snippet": "cur.execute(q)",
    }]
    files = [{"path": "app/db.py", "language": "python", "size": 200}]
    statuses: list[str] = []

    async def emit(event):
        if event.get("type") == "status":
            statuses.append(event["status"])

    async def read_file(_path):
        return "x\n" * 20

    result = await run_review(
        client=MockFoundryClient(),
        roles=_roles(reviewers=("gpt-5-codex", "gpt-5"), judge="o4-mini"),
        instructions=None, files=files, candidates=candidates,
        read_file=read_file, emit=emit,
    )

    assert "judging" in statuses
    findings = result["findings"]
    # the SQLi (has file evidence) gets confirmed by the judge
    assert any(f["state"] == "confirmed" and f["triaged_by"] for f in findings)
    # the no-evidence access-control item is dismissed or routed to a human
    assert any(f["state"] in ("dismissed", "needs_info") for f in findings)
    # dedupe: identical SQLi from both reviewers collapses to one confirmed entry
    sqli = [f for f in findings if f.get("cwe") == "CWE-89"]
    assert len(sqli) == 1


@pytest.mark.asyncio
async def test_resume_skips_checkpointed_units():
    """With a checkpoint store wired in, a re-run reuses completed reviewer
    batches/judge chunks instead of re-calling the model — and saves the work it
    does so a subsequent run skips it too."""
    candidates = [{
        "source": "semgrep", "title": "SQL injection", "severity": "high",
        "cwe": "CWE-89", "file_path": "app/db.py", "line_start": 12,
        "code_snippet": "cur.execute(q)",
    }]
    files = [{"path": "app/db.py", "language": "python", "size": 200}]

    # An in-memory stand-in for the DB-backed _CheckpointStore.
    store: dict[str, dict[str, list]] = {}

    async def load_chunks(phase):
        return dict(store.get(phase, {}))

    async def save_chunk(phase, key, items):
        store.setdefault(phase, {})[key] = items

    async def emit(_event):
        return None

    async def read_file(_path):
        return "x\n" * 20

    kw = dict(
        roles=_roles(reviewers=("gpt-5-codex",), judge="o4-mini"),
        instructions=None, files=files, candidates=candidates,
        read_file=read_file, emit=emit,
        load_chunks=load_chunks, save_chunk=save_chunk,
    )

    # First run: populates the checkpoint store.
    first = MockFoundryClient()
    r1 = await run_review(client=first, **kw)
    assert store.get("review")          # reviewer batches were checkpointed
    calls_first = first.usage.to_dict()["calls"]
    assert calls_first > 0

    # Second run with the same store: reviewer/judge units are cached, so the
    # only model calls left are the plan narration — far fewer than the first run.
    second = MockFoundryClient()
    r2 = await run_review(client=second, **kw)
    calls_second = second.usage.to_dict()["calls"]
    assert calls_second < calls_first
    # The findings are reproduced from cache, not lost.
    assert len(r2["findings"]) == len(r1["findings"])


@pytest.mark.asyncio
async def test_evidence_policy_demotes_unconfirmed():
    """A 'confirmed' finding with no file evidence must be demoted to 'proposed'."""
    from app.ai.agent import _normalize

    f = _normalize(
        {"title": "x", "state": "confirmed", "severity": "high", "confidence": 0.9}, None
    )
    assert f["state"] == "proposed"
    assert f["confidence"] <= 0.4
