"""A truncated prompt (profile context window > what the server really loads)
comes back as unusable JSON. The reviewer must split the batch smaller and
retry — self-healing the context mismatch — not just give up."""

from __future__ import annotations

import pytest

from app.ai.agent import _is_bad_output, _review_with_adaptive_split, _split_mode
from app.ai.foundry import ModelRole


class _TruncatingClient:
    """Returns junk ( -> 'no parseable JSON') until a batch is small enough
    (<= max_files source files), mimicking a too-small real context window."""

    def __init__(self, max_files: int):
        self.max_files = max_files
        self.calls = 0

    async def complete_json(self, messages, **kw):
        self.calls += 1
        import json
        user = messages[-1]["content"]
        payload = json.loads(user.split("<<CONTEXT_JSON>>")[1].split("<<END>>")[0])
        n = len(payload["source_files"])
        if n > self.max_files:
            return {}                       # truncated → unparseable (raises ValueError)
        # Small enough to "fit": return one finding per file so we can count.
        return {"findings": [{"title": f"f{i}", "severity": "low",
                              "file_path": sf["path"], "line_start": 1}
                             for i, sf in enumerate(payload["source_files"])]}


def test_split_mode_bad_output_is_shallow_and_file_only():
    bad = ValueError('model returned no parseable {"findings": [...]} JSON')
    assert _is_bad_output(bad)
    # bad output: split multi-file, shallowly; never slice a single file, never deep
    assert _split_mode(bad, depth=0, n_files=4) == "file"
    assert _split_mode(bad, depth=2, n_files=4) == ""      # past the shallow limit
    assert _split_mode(bad, depth=0, n_files=1) == ""      # don't slice a lone file
    # a definite overflow splits deeper and can slice a single file
    overflow = ValueError("context_length_exceeded")
    assert _split_mode(overflow, depth=3, n_files=4) == "file"
    assert _split_mode(overflow, depth=0, n_files=1) == "slice"
    assert _split_mode(ValueError("401 unauthorized"), depth=0, n_files=4) == ""


@pytest.mark.asyncio
async def test_batch_splits_down_on_truncation():
    files = [{"path": f"f{i}.py", "content": f"x = {i}\n"} for i in range(8)]
    batch = {"source_files": files, "candidates": []}
    client = _TruncatingClient(max_files=2)   # only batches of <=2 files "fit"

    async def emit(_e):
        return None

    fails: list = []
    out = await _review_with_adaptive_split(
        client, ModelRole("qwen"), batch, 0, 1, None, emit, failed=fails)
    # All 8 files reviewed via smaller sub-batches; nothing left as failed.
    assert {f["file_path"] for f in out} == {f"f{i}.py" for i in range(8)}
    assert fails == []
    assert client.calls > 1                   # it actually split instead of giving up


@pytest.mark.asyncio
async def test_persistent_bad_output_gives_up_bounded():
    files = [{"path": f"f{i}.py", "content": f"x = {i}\n"} for i in range(4)]
    batch = {"source_files": files, "candidates": []}
    client = _TruncatingClient(max_files=0)   # never fits → always junk

    async def emit(_e):
        return None

    fails: list = []
    out = await _review_with_adaptive_split(
        client, ModelRole("qwen"), batch, 0, 1, None, emit, failed=fails)
    assert out == [] and fails            # reported as failed, not silently empty
    assert client.calls < 50              # bounded by the depth<4 split limit
