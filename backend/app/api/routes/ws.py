"""WebSocket endpoint for live scan events (Section 19).

Subscribes the client to the in-process scan event bus for an assessment and
streams events published by the orchestrator (stage progress, findings count,
completion). A periodic heartbeat keeps the connection alive during quiet
periods so proxies don't drop it.
"""
import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.orchestrator.events import make_event, scan_event_bus

router = APIRouter(tags=["websocket"])

_HEARTBEAT_SECONDS = 30


@router.websocket("/assessments/{assessment_id}/events")
async def assessment_events(websocket: WebSocket, assessment_id: str):
    await websocket.accept()
    queue = scan_event_bus.subscribe(assessment_id)
    await websocket.send_json(
        make_event("log", message="Subscribed to scan events.")
    )
    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=_HEARTBEAT_SECONDS)
                await websocket.send_json(event)
            except asyncio.TimeoutError:
                await websocket.send_json(make_event("heartbeat"))
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        scan_event_bus.unsubscribe(assessment_id, queue)
