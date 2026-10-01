"""Cooperative scan control: pause / resume / skip-stage / cancel.

A scan job runs as an in-process async task in the worker, so it cannot be
"paused" by the OS. Instead the worker polls a tiny Redis key at safe
checkpoints (between pipeline stages and between AI review batches) and reacts:

    pause   -> block at the next checkpoint until resumed/canceled
    resume  -> clear the key; the worker continues
    skip    -> abort the *current* stage and move to the next
    cancel  -> abort the whole scan

The API writes the key (``set_control``); the worker reads it (``Controller``).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from app.config import settings

if TYPE_CHECKING:
    import redis.asyncio as aioredis

CONTROL_ACTIONS = {"pause", "resume", "skip", "cancel"}


def _redis():
    # Imported lazily so modules that only need the control *signals* (e.g. the
    # agent) don't pull in redis — keeps unit tests dependency-light.
    import redis.asyncio as aioredis

    return aioredis.from_url(settings.redis_url)


def _key(scan_id: str) -> str:
    return f"scan:{scan_id}:control"


async def set_control(scan_id: str, action: str) -> None:
    """Record a control action for a scan (resume clears any pause)."""
    r = _redis()
    try:
        if action == "resume":
            await r.delete(_key(scan_id))
        else:
            await r.set(_key(scan_id), action, ex=86_400)
    finally:
        await r.aclose()


async def get_control(scan_id: str, r: "aioredis.Redis | None" = None) -> str | None:
    own = r is None
    r = r or _redis()
    try:
        v = await r.get(_key(scan_id))
        return v.decode() if isinstance(v, bytes) else v
    finally:
        if own:
            await r.aclose()


async def clear_control(scan_id: str, r: "aioredis.Redis | None" = None) -> None:
    own = r is None
    r = r or _redis()
    try:
        await r.delete(_key(scan_id))
    finally:
        if own:
            await r.aclose()


# --------------------------------------------------------------------------- signals
class ScanControlSignal(Exception):
    """Base class for cooperative control signals raised at checkpoints."""


class ScanCanceledSignal(ScanControlSignal):
    """User asked to cancel the whole scan."""


class StageSkippedSignal(ScanControlSignal):
    """User asked to skip the stage currently running."""

    def __init__(self, stage: str | None = None) -> None:
        self.stage = stage
        super().__init__(f"stage skipped: {stage}")


# --------------------------------------------------------------------------- controller
class Controller:
    """Polls the control key at checkpoints and enforces pause/skip/cancel.

    ``checkpoint()`` is the only thing the pipeline calls. It returns normally
    when the scan should proceed, blocks while paused, and raises a control
    signal for skip/cancel. ``emit`` is used to surface state to the live UI.
    """

    def __init__(self, scan_id: str, emit) -> None:
        self.scan_id = scan_id
        self.emit = emit
        self._stage: str | None = None
        self._paused = False

    def set_stage(self, stage: str | None) -> None:
        self._stage = stage

    async def checkpoint(self, stage: str | None = None) -> None:
        stage = stage or self._stage
        r = _redis()
        try:
            while True:
                action = await get_control(self.scan_id, r)
                if action == "cancel":
                    raise ScanCanceledSignal()
                if action == "skip":
                    await clear_control(self.scan_id, r)
                    await self.emit({"type": "log", "message": f"⏭ Skipping stage: {stage}"})
                    raise StageSkippedSignal(stage)
                if action == "pause":
                    if not self._paused:
                        self._paused = True
                        await self.emit({"type": "control", "control": "paused", "stage": stage})
                        await self.emit({"type": "log", "message": f"⏸ Paused at {stage}"})
                    await asyncio.sleep(2)
                    continue
                if self._paused:
                    self._paused = False
                    await self.emit({"type": "control", "control": "resumed", "stage": stage})
                    await self.emit({"type": "log", "message": f"▶ Resumed: {stage}"})
                return
        finally:
            await r.aclose()
