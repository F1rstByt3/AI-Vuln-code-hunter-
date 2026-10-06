"""Cancel must interrupt a job mid-operation (e.g. a minutes-long model call),
not wait for the next cooperative checkpoint."""

from __future__ import annotations

import asyncio
import time

import pytest

from app import worker


@pytest.mark.asyncio
async def test_cancel_interrupts_long_running_job(monkeypatch):
    flag = {"v": None}

    async def fake_get_control(scan_id, r=None):
        return flag["v"]

    monkeypatch.setattr(worker.control, "get_control", fake_get_control)
    monkeypatch.setattr(worker, "_CANCEL_POLL_SECONDS", 0.05)
    seen = {"handled": False}

    async def body():
        try:
            await asyncio.sleep(60)  # e.g. a slow local-model call
        except asyncio.CancelledError:
            seen["handled"] = True  # the job's own handler marks the scan canceled

    async def press_cancel():
        await asyncio.sleep(0.1)
        flag["v"] = "cancel"

    t0 = time.monotonic()
    await asyncio.gather(worker._interruptible("s1", body()), press_cancel())
    assert seen["handled"]
    assert time.monotonic() - t0 < 2
