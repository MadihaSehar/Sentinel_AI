"""
Redis pub/sub bridge for scan events.

In Celery mode the scan runs in a worker process while the WebSocket lives in
the web process, so the in-process event bus can't carry events between them.
This bridge publishes events to a Redis channel and lets the WebSocket
subscribe to it, so the live dashboard works across processes.

Everything here is best-effort: if Redis is unreachable, publishing is a
no-op (the scan still runs) and the WebSocket falls back to heartbeats.
A fresh client is used per publish so it never binds to a stale event loop
(the Celery task runs each scan in its own ``asyncio.run`` loop).
"""
from __future__ import annotations

import json
import logging
from typing import Any

from app.core.config import get_settings

logger = logging.getLogger("sentinel.orchestrator.redis_events")


def channel(assessment_id: str) -> str:
    return f"scan-events:{assessment_id}"


def _client():
    import redis.asyncio as aioredis

    return aioredis.from_url(get_settings().REDIS_URL, decode_responses=True)


async def publish(assessment_id: str, event: dict[str, Any]) -> None:
    client = None
    try:
        client = _client()
        await client.publish(channel(assessment_id), json.dumps(event))
    except Exception as exc:  # noqa: BLE001 - never let event delivery break a scan
        logger.warning("redis event publish failed: %s", exc)
    finally:
        if client is not None:
            try:
                await client.aclose()
            except Exception:  # noqa: BLE001
                pass


async def iter_events(assessment_id: str):
    """Yield events published to this assessment's channel (web process)."""
    import redis.asyncio as aioredis

    client = aioredis.from_url(get_settings().REDIS_URL, decode_responses=True)
    pubsub = client.pubsub()
    await pubsub.subscribe(channel(assessment_id))
    try:
        async for message in pubsub.listen():
            if message.get("type") != "message":
                continue
            try:
                yield json.loads(message["data"])
            except (ValueError, TypeError):
                continue
    finally:
        try:
            await pubsub.unsubscribe(channel(assessment_id))
            await pubsub.aclose()
            await client.aclose()
        except Exception:  # noqa: BLE001
            pass
