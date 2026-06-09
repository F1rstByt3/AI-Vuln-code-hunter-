"""Live event bus backed by Redis Streams.

The worker XADDs agent events to ``scan:{id}:events``; SSE subscribers XREAD
(blocking) so they get live output *and* can replay recent history on reconnect.
A permanent copy is also written to the AgentEvent table for full replay.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator

import redis.asyncio as aioredis

from app.config import settings

_TERMINAL_TYPES = {"done", "failed", "canceled"}


def _key(scan_id: str) -> str:
    return f"scan:{scan_id}:events"


async def publish(scan_id: str, event: dict) -> None:
    r = aioredis.from_url(settings.redis_url)
    try:
        await r.xadd(_key(scan_id), {"data": json.dumps(event)}, maxlen=10000, approximate=True)
    finally:
        await r.aclose()


async def subscribe(scan_id: str, last_id: str = "0") -> AsyncIterator[dict]:
    """Yield events from the stream, blocking for new ones. Stops after a terminal event."""
    r = aioredis.from_url(settings.redis_url)
    try:
        while True:
            resp = await r.xread({_key(scan_id): last_id}, count=100, block=15000)
            if not resp:
                yield {"type": "heartbeat"}
                continue
            for _stream, entries in resp:
                for entry_id, fields in entries:
                    last_id = entry_id.decode() if isinstance(entry_id, bytes) else entry_id
                    event = json.loads(fields[b"data"])
                    yield event
                    if event.get("type") in _TERMINAL_TYPES:
                        return
    finally:
        await r.aclose()
