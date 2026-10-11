"""
Celery application for running scans out-of-process.

Broker + result backend both use the configured Redis. Run a worker with:

    celery -A app.worker.celery_app worker --loglevel=info

Scans are dispatched here only when ``USE_CELERY=true`` (see
``scan_orchestrator.launch_scan``); otherwise the backend runs them in-process.
"""
from __future__ import annotations

from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "sentinelai",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["app.worker.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,  # a scan is long-running; don't hoard tasks
)
