"""Live, in-flight control of a running DAST run.

A run executes as an async task in the worker; it cannot be steered by the OS.
Instead every outbound request passes through a *gate* (``LiveControl.gate``)
that reads a tiny Redis document the API writes, and reacts before the request
leaves:

    pause      -> block here until resumed / cancelled (no traffic while paused)
    throttle   -> lower the request rate on the fly (tighten only)
    mutating   -> turn state-changing requests OFF mid-run (tighten only)
    exclude    -> add path prefixes to skip from here on
    intercept  -> hold before each request (all, or only mutating) and wait for
                  an explicit approve / skip decision from the operator

Safety is one-directional: live edits can only make a run *tighter* or pause it
— never loosen it (you cannot switch mutating back on, or raise the rate above
the launch ceiling). Loosening requires a new, freshly-authorised run.

The document lives at ``dast:{run_id}:ctl``; per-request decisions at
``dast:{run_id}:decision`` (a hash seq -> verdict); pending held requests at
``dast:{run_id}:pending`` (a hash seq -> JSON) so a reconnecting UI can see what
is waiting. Everything is best-effort and bounded by TTL, so a crashed run
leaves no stuck keys.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from app.config import settings
from app.control import ScanCanceledSignal, get_control

_TTL = 86_400
_CACHE_MS = 400            # don't hammer Redis: re-read the doc at most this often
_PAUSE_POLL = 1.5
_DECISION_POLL = 1.0
# How long a held (intercepted) request waits for a decision before the safe
# default (skip) is applied, so a run can't hang forever on an absent operator.
_INTERCEPT_TIMEOUT = 900

# Purposes that are app-internal plumbing (login, id harvesting, scope probes)
# rather than attack traffic. Pause/throttle/cancel still apply to them, but
# they are never path-excluded, mutating-blocked or intercepted — skipping a
# login would wreck the rest of the run.
_INTERNAL_PURPOSES = {"login", "internal", "harvest"}

GATE_SEND = "send"
GATE_SKIP = "skip"


def _redis():
    import redis.asyncio as aioredis

    return aioredis.from_url(settings.redis_url)


def _ctl_key(run_id: str) -> str:
    return f"dast:{run_id}:ctl"


def _pending_key(run_id: str) -> str:
    return f"dast:{run_id}:pending"


def _decision_key(run_id: str) -> str:
    return f"dast:{run_id}:decision"


DEFAULT_DOC: dict[str, Any] = {
    "status": "running",        # running | paused | canceled
    "max_rps": None,            # live rate override (<= launch ceiling)
    "allow_mutating": None,     # live tighten to False; None = keep launch value
    "exclude_paths": [],        # additive path-prefix skips
    "intercept": "off",         # off | mutating | all
}


async def read_doc(run_id: str, r=None) -> dict:
    own = r is None
    r = r or _redis()
    try:
        raw = await r.get(_ctl_key(run_id))
    finally:
        if own:
            await r.aclose()
    if not raw:
        return dict(DEFAULT_DOC)
    try:
        doc = json.loads(raw)
    except (ValueError, TypeError):
        return dict(DEFAULT_DOC)
    return {**DEFAULT_DOC, **(doc if isinstance(doc, dict) else {})}


async def write_patch(run_id: str, patch: dict, *, launch_max_rps: float | None = None) -> dict:
    """Apply an operator patch, enforcing tighten-only semantics. Returns the
    new document."""
    r = _redis()
    try:
        doc = await read_doc(run_id, r)
        if "status" in patch and patch["status"] in ("running", "paused", "canceled"):
            doc["status"] = patch["status"]
        if "intercept" in patch and patch["intercept"] in ("off", "mutating", "all"):
            doc["intercept"] = patch["intercept"]
        if patch.get("allow_mutating") is False:   # tighten only; never re-enable
            doc["allow_mutating"] = False
        if "max_rps" in patch and patch["max_rps"] is not None:
            try:
                rps = float(patch["max_rps"])
            except (TypeError, ValueError):
                rps = None
            if rps and rps > 0:
                ceiling = launch_max_rps or rps
                doc["max_rps"] = min(rps, ceiling)   # cannot exceed launch ceiling
        for p in patch.get("exclude_paths") or []:  # additive
            if isinstance(p, str) and p and p not in doc["exclude_paths"]:
                doc["exclude_paths"].append(p)
        await r.set(_ctl_key(run_id), json.dumps(doc), ex=_TTL)
        return doc
    finally:
        await r.aclose()


async def set_decision(run_id: str, seq: int, verdict: str) -> None:
    r = _redis()
    try:
        await r.hset(_decision_key(run_id), str(seq), verdict)
        await r.expire(_decision_key(run_id), _TTL)
    finally:
        await r.aclose()


async def list_pending(run_id: str) -> list[dict]:
    r = _redis()
    try:
        raw = await r.hgetall(_pending_key(run_id))
    finally:
        await r.aclose()
    out = []
    for v in (raw or {}).values():
        try:
            out.append(json.loads(v))
        except (ValueError, TypeError):
            continue
    out.sort(key=lambda e: e.get("seq", 0))
    return out


async def clear(run_id: str) -> None:
    r = _redis()
    try:
        await r.delete(_ctl_key(run_id), _pending_key(run_id), _decision_key(run_id))
    finally:
        await r.aclose()


class LiveControl:
    """Per-run gate. One instance per run, shared by every LiveClient it uses.

    The client calls :meth:`gate` before each request. ``apply_to`` lets a fresh
    client inherit the current live overrides (rate, mutating) at creation."""

    def __init__(self, run_id: str, scan_id: str, emit, *,
                 launch_max_rps: float | None = None,
                 intercept_timeout: float = _INTERCEPT_TIMEOUT) -> None:
        self.run_id = run_id
        self.scan_id = scan_id
        self.emit = emit
        self.launch_max_rps = launch_max_rps
        self.intercept_timeout = intercept_timeout
        self._seq = 0
        self._paused = False
        self._doc: dict = dict(DEFAULT_DOC)
        self._doc_at = 0.0
        self._clients: list = []

    def attach(self, client) -> None:
        """Register a client so live rate/mutating edits reach it immediately."""
        self._clients.append(client)
        self._apply_to(client, self._doc)

    def _apply_to(self, client, doc: dict) -> None:
        if doc.get("max_rps"):
            client.set_rps(doc["max_rps"])
        if doc.get("allow_mutating") is False:
            client.allow_mutating = False

    async def _fresh_doc(self, r) -> dict:
        now = time.monotonic() * 1000
        if now - self._doc_at < _CACHE_MS:
            return self._doc
        doc = await read_doc(self.run_id, r)
        self._doc, self._doc_at = doc, now
        for c in self._clients:
            self._apply_to(c, doc)
        return doc

    async def _canceled(self, r) -> bool:
        # New run-doc cancel, or the legacy scan-level cancel key (cancel button).
        if self._doc.get("status") == "canceled":
            return True
        return await get_control(self.scan_id + ":dast", r) == "cancel"

    async def gate(self, method: str, url: str, purpose: str, role: str,
                   mutating: bool) -> str:
        """Called before every outbound request. Returns ``"send"`` or
        ``"skip"``. Blocks while paused and while an intercepted request waits
        for a decision. Raises :class:`ScanCanceledSignal` on cancel."""
        r = _redis()
        try:
            # 1. pause / cancel loop
            while True:
                doc = await self._fresh_doc(r)
                if await self._canceled(r):
                    raise ScanCanceledSignal()
                if doc.get("status") == "paused":
                    if not self._paused:
                        self._paused = True
                        await self.emit({"type": "dast_control", "control": "paused"})
                        await self.emit({"type": "log", "message": "⏸ DAST paused"})
                    await asyncio.sleep(_PAUSE_POLL)
                    self._doc_at = 0.0           # force a re-read next loop
                    continue
                if self._paused:
                    self._paused = False
                    await self.emit({"type": "dast_control", "control": "resumed"})
                    await self.emit({"type": "log", "message": "▶ DAST resumed"})
                break

            internal = purpose in _INTERNAL_PURPOSES
            if not internal:
                # 2. live path exclusions
                path = _path_of(url)
                if any(path.startswith(p) for p in doc.get("exclude_paths") or []):
                    return GATE_SKIP
                # 3. mutating turned off live
                if mutating and doc.get("allow_mutating") is False:
                    return GATE_SKIP
                # 4. intercept hold
                mode = doc.get("intercept") or "off"
                if mode == "all" or (mode == "mutating" and mutating):
                    return await self._hold(r, method, url, purpose, role, mutating)
            return GATE_SEND
        finally:
            await r.aclose()

    async def _hold(self, r, method: str, url: str, purpose: str, role: str,
                    mutating: bool) -> str:
        self._seq += 1
        seq = self._seq
        entry = {"seq": seq, "method": method, "url": url, "purpose": purpose,
                 "role": role, "mutating": mutating, "ts": time.time()}
        await r.hset(_pending_key(self.run_id), str(seq), json.dumps(entry))
        await r.expire(_pending_key(self.run_id), _TTL)
        await self.emit({"type": "dast_intercept", "request": entry})
        waited = 0.0
        verdict = "skip"
        try:
            while waited < self.intercept_timeout:
                if await self._canceled(r):
                    raise ScanCanceledSignal()
                raw = await r.hget(_decision_key(self.run_id), str(seq))
                d = (raw.decode() if isinstance(raw, bytes) else raw) if raw else None
                if d in ("allow", "skip"):
                    verdict = d
                    break
                if d in ("allow_rest", "skip_rest"):
                    # Stop intercepting; apply this verdict to this request too.
                    await write_patch(self.run_id, {"intercept": "off"})
                    self._doc_at = 0.0
                    verdict = "allow" if d == "allow_rest" else "skip"
                    break
                await asyncio.sleep(_DECISION_POLL)
                waited += _DECISION_POLL
            else:
                await self.emit({"type": "log", "message":
                                 f"⚠ intercept timed out on {method} {url} — skipped"})
        finally:
            await r.hdel(_pending_key(self.run_id), str(seq))
            await r.hdel(_decision_key(self.run_id), str(seq))
        await self.emit({"type": "dast_intercept_done", "seq": seq, "verdict": verdict})
        return GATE_SEND if verdict == "allow" else GATE_SKIP


def _path_of(url: str) -> str:
    # Cheap path extraction without importing urllib per request.
    i = url.find("://")
    rest = url[i + 3:] if i != -1 else url
    slash = rest.find("/")
    if slash == -1:
        return "/"
    path = rest[slash:]
    for cut in ("?", "#"):
        j = path.find(cut)
        if j != -1:
            path = path[:j]
    return path or "/"
