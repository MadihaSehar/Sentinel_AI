"""WebSocket endpoint for live scan events (Section 19).

Streams events published by the orchestrator for an assessment. In in-process
mode it reads the local event bus; in Celery mode (USE_CELERY) it reads the
Redis pub/sub bridge so it sees events from the worker process. A periodic
heartbeat keeps the connection alive during quiet periods.
"""
import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.config import get_settings
from app.orchestrator.events import make_event, scan_event_bus

router = APIRouter(tags=["websocket"])

_HEARTBEAT_SECONDS = 30


async def _stream_local(websocket: WebSocket, assessment_id: str) -> None:
    queue = scan_event_bus.subscribe(assessment_id)
    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=_HEARTBEAT_SECONDS)
                await websocket.send_json(event)
            except asyncio.TimeoutError:
                await websocket.send_json(make_event("heartbeat"))
    finally:
        scan_event_bus.unsubscribe(assessment_id, queue)


async def _stream_redis(websocket: WebSocket, assessment_id: str) -> None:
    from app.orchestrator import redis_events

    async for event in redis_events.iter_events(assessment_id):
        await websocket.send_json(event)


@router.websocket("/assessments/{assessment_id}/events")
async def assessment_events(websocket: WebSocket, assessment_id: str):
    await websocket.accept()
    await websocket.send_json(make_event("log", message="Subscribed to scan events."))
    try:
        if get_settings().USE_CELERY:
            await _stream_redis(websocket, assessment_id)
        else:
            await _stream_local(websocket, assessment_id)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
