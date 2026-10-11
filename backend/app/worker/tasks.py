"""
Celery tasks.

The scan task bridges Celery's synchronous task model to the async
orchestrator: it runs ``run_scan`` inside a fresh event loop with a fresh
async engine (so asyncpg connections are never shared across loops/tasks).
"""
from __future__ import annotations

import asyncio
import logging
import uuid

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings
from app.worker.celery_app import celery_app

logger = logging.getLogger("sentinel.worker")


def _maybe_ai_service():
    try:
        from app.ai.service import AIAnalysisService

        return AIAnalysisService.from_env()
    except Exception:  # noqa: BLE001 - no providers configured is fine
        return None


async def _run(assessment_id: uuid.UUID) -> None:
    from app.orchestrator.scan_orchestrator import run_scan

    settings = get_settings()
    engine = create_async_engine(settings.DATABASE_URL)
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)
    try:
        await run_scan(session_factory, assessment_id, ai_service=_maybe_ai_service())
    finally:
        await engine.dispose()


@celery_app.task(name="sentinelai.run_scan", bind=True, max_retries=0)
def run_scan_task(self, assessment_id: str) -> str:
    """Run a full scan for the given assessment id."""
    logger.info("worker running scan for assessment %s", assessment_id)
    asyncio.run(_run(uuid.UUID(assessment_id)))
    return assessment_id
