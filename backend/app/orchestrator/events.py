"""
In-process pub/sub for live scan events.

The orchestrator publishes stage/progress events for an assessment; the
WebSocket endpoint subscribes and streams them to the dashboard. This is a
single-process bus (fine for one backend instance / dev + demo). For a
multi-worker deployment the same interface would be backed by Redis pub/sub
instead — callers don't change.
"""
from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

_MAX_QUEUE = 1000


def make_event(type_: str, **payload: Any) -> dict:
    return {
        "type": type_,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "payload": payload,
    }


class ScanEventBus:
    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue]] = defaultdict(set)

    async def publish(self, assessment_id: str, event: dict) -> None:
        for queue in list(self._subscribers.get(assessment_id, ())):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:  # pragma: no cover - slow consumer
                pass

    def subscribe(self, assessment_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=_MAX_QUEUE)
        self._subscribers[assessment_id].add(queue)
        return queue

    def unsubscribe(self, assessment_id: str, queue: asyncio.Queue) -> None:
        subs = self._subscribers.get(assessment_id)
        if subs:
            subs.discard(queue)
            if not subs:
                self._subscribers.pop(assessment_id, None)


# Process-wide singleton used by the orchestrator and the WS endpoint.
scan_event_bus = ScanEventBus()
