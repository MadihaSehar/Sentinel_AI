"""WebSocket endpoint for live scan events (Section 19)."""
import json
import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from datetime import datetime, timezone

router = APIRouter(tags=["websocket"])


@router.websocket("/assessments/{assessment_id}/events")
async def assessment_events(websocket: WebSocket, assessment_id: str):
    """Live scan event stream. In production this would be fed by the
    Celery workers / orchestrator. For now, accepts the connection
    and sends a heartbeat to keep the connection alive."""
    await websocket.accept()
    try:
        while True:
            # Send heartbeat every 30 seconds to keep connection alive
            await websocket.send_json({
                "type": "log",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "payload": {"message": "Connection alive. Waiting for scan events."}
            })
            await asyncio.sleep(30)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
