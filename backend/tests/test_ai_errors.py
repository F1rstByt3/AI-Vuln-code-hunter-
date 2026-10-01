"""AI error classification + preflight: a failed scan should say *why* (auth,
model name, rate limit, endpoint …), not just a generic message."""

from __future__ import annotations

import pytest

from app.ai.agent import ReviewRoles, run_review
from app.ai.foundry import MockFoundryClient, ModelRole, ai_error_summary, classify_ai_error


class _Err(Exception):
    def __init__(self, msg, status=None):
        super().__init__(msg)
        self.status_code = status


@pytest.mark.parametrize("msg,status,expect", [
    ("Error code: 401 - invalid_api_key", 401, "auth"),
    ("permission denied for this resource", 403, "auth"),
    ("The model 'gpt-5-codex' does not exist or you don't have access", 404, "model"),
    ("DeploymentNotFound", 404, "model"),
    ("429 Too Many Requests: rate limit exceeded", 429, "rate_limit"),
    ("This model's maximum context length is 8192 tokens", None, "context"),
    ("Request timed out after 600s", None, "timeout"),
    ("Connection error: [Errno -2] Name or service not known", None, "endpoint"),
    ("model returned no parseable JSON", None, "bad_output"),
    ("something totally unexpected happened", None, "unknown"),
])
def test_classify(msg, status, expect):
    assert classify_ai_error(_Err(msg, status))[0] == expect
    s = ai_error_summary(_Err(msg, status))
    assert s.startswith(f"[{expect}]") and "—" in s


class _PreflightFails(MockFoundryClient):
    def __init__(self, exc):
        super().__init__()
        self._exc = exc

    async def preflight(self, *, model=None, transport="auto"):
        raise self._exc


async def _emit(_e):
    return None


@pytest.mark.asyncio
async def test_preflight_auth_error_fails_fast():
    roles = ReviewRoles(chat=ModelRole("c"), reviewers=[ModelRole("gpt-5-codex")], judge=None)
    with pytest.raises(RuntimeError) as ei:
        await run_review(
            client=_PreflightFails(_Err("401 invalid_api_key", 401)),
            roles=roles, instructions=None, files=[{"path": "a.py"}], candidates=[],
            read_file=lambda p: None, emit=_emit,
            checks={"coverage": False, "verify": False, "access_control": False})
    msg = str(ei.value)
    assert "preflight failed" in msg.lower() and "[auth]" in msg and "gpt-5-codex" in msg


@pytest.mark.asyncio
async def test_preflight_timeout_is_non_fatal(tmp_path):
    import asyncio

    (tmp_path / "db.py").write_text("q = 'SELECT * FROM t WHERE id=' + user_id\n")

    async def read_file(rel):
        p = tmp_path / rel
        return p.read_text() if p.is_file() else None

    class _Slow(MockFoundryClient):
        async def preflight(self, *, model=None, transport="auto"):
            raise TimeoutError()

    roles = ReviewRoles(chat=ModelRole("c"), reviewers=[ModelRole("r")], judge=None)
    # A timeout on preflight must NOT abort — the review proceeds (mock produces
    # output), proving a slow model isn't mistaken for a broken one.
    result = await asyncio.wait_for(run_review(
        client=_Slow(), roles=roles, instructions=None,
        files=[{"path": "db.py"}], candidates=[], read_file=read_file, emit=_emit,
        checks={"coverage": False, "verify": False, "access_control": False}), timeout=30)
    assert "summary" in result
