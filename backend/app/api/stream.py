"""Server-Sent Events: live stream of an in-progress (or replayed) scan.

Reads the scan's Redis stream from the beginning of its retained buffer, so a
client that connects mid-scan gets recent history then live updates. Closes after
a terminal event.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from app import events

router = APIRouter(tags=["stream"])


@router.get("/scans/{scan_id}/events")
async def scan_events(scan_id: str, last_id: str = "0") -> StreamingResponse:
    async def gen() -> AsyncIterator[bytes]:
        async for event in events.subscribe(scan_id, last_id=last_id):
            yield f"data: {json.dumps(event)}\n\n".encode()

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # disable proxy buffering
        },
    )
