"""Semgrep is memory-bounded (jobs / max-memory) and reports an OOM clearly so
a killed engine doesn't silently yield zero findings."""

from __future__ import annotations

import json

import pytest

from app.scanners import semgrep as sg


class _FakeProc:
    def __init__(self, stdout=b"", stderr=b"", rc=0):
        self._out, self._err, self.returncode = stdout, stderr, rc

    async def communicate(self):
        return self._out, self._err


def _patch_proc(monkeypatch, proc, captured):
    async def fake_exec(*cmd, **kw):
        captured.append(list(cmd))
        return proc
    monkeypatch.setattr(sg.asyncio, "create_subprocess_exec", fake_exec)
    # skip the `semgrep whoami` login probe (would be a second subprocess)
    monkeypatch.setattr(sg.SemgrepScanner, "_check_semgrep_login",
                        staticmethod(lambda: _true()))


async def _true():
    return True


@pytest.mark.asyncio
async def test_memory_flags_present(monkeypatch):
    captured: list = []
    _patch_proc(monkeypatch, _FakeProc(stdout=b'{"results":[],"errors":[]}'), captured)
    await sg.SemgrepScanner().scan("/tmp")
    cmd = captured[-1]
    assert "--jobs" in cmd and cmd[cmd.index("--jobs") + 1] == "1"
    assert "--max-memory" in cmd and cmd[cmd.index("--max-memory") + 1] == "2000"


@pytest.mark.asyncio
async def test_oom_in_errors_is_reported(monkeypatch):
    out = json.dumps({"results": [], "errors": [
        {"message": "Error while running rules: the engine was killed. "
                    "used too much memory."}]}).encode()
    captured: list = []
    _patch_proc(monkeypatch, _FakeProc(stdout=out, rc=2), captured)
    logs: list = []

    async def emit(e):
        logs.append(e["message"])

    res = await sg.SemgrepScanner().scan("/tmp", emit=emit)
    assert res == []
    assert any("ran out of memory" in m for m in logs)


@pytest.mark.asyncio
async def test_oom_with_no_stdout_still_reports(monkeypatch):
    captured: list = []
    _patch_proc(monkeypatch, _FakeProc(stdout=b"", stderr=b"engine was killed (OOM)", rc=137),
                captured)
    logs: list = []

    async def emit(e):
        logs.append(e["message"])

    assert await sg.SemgrepScanner().scan("/tmp", emit=emit) == []
    assert any("ran out of memory" in m for m in logs)


@pytest.mark.asyncio
async def test_clean_run_does_not_warn(monkeypatch):
    _patch_proc(monkeypatch, _FakeProc(stdout=b'{"results":[],"errors":[]}'), [])
    logs: list = []

    async def emit(e):
        logs.append(e["message"])

    await sg.SemgrepScanner().scan("/tmp", emit=emit)
    assert not any("memory" in m for m in logs)
