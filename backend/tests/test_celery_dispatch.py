"""
Tests for scan dispatch: Celery when USE_CELERY, in-process otherwise.
No running broker is required — the Celery task's .delay is monkeypatched.
"""
from __future__ import annotations

import uuid

from app.core.config import Settings
from app.orchestrator import scan_orchestrator


def test_celery_task_is_registered():
    import app.worker.tasks  # noqa: F401 — registers the task on the app
    from app.worker.celery_app import celery_app

    assert "sentinelai.run_scan" in celery_app.tasks


def test_launch_scan_dispatches_to_celery_when_enabled(monkeypatch):
    aid = uuid.uuid4()
    sent: dict = {}

    class _FakeTask:
        def delay(self, assessment_id):
            sent["assessment_id"] = assessment_id

    # Force USE_CELERY on.
    monkeypatch.setattr(scan_orchestrator, "get_settings", None, raising=False)
    monkeypatch.setattr(
        "app.core.config.get_settings",
        lambda: Settings(USE_CELERY=True),
    )
    # Replace the worker task with a fake so no broker is contacted.
    import app.worker.tasks as tasks_mod

    monkeypatch.setattr(tasks_mod, "run_scan_task", _FakeTask())

    # asyncio.create_task must NOT be called in Celery mode.
    import asyncio

    def _boom(*a, **k):  # pragma: no cover - should not run
        raise AssertionError("create_task should not be called when USE_CELERY=true")

    monkeypatch.setattr(asyncio, "create_task", _boom)

    scan_orchestrator.launch_scan(aid)
    assert sent["assessment_id"] == str(aid)


def test_launch_scan_runs_in_process_when_disabled(monkeypatch):
    aid = uuid.uuid4()
    created: dict = {}

    monkeypatch.setattr(
        "app.core.config.get_settings",
        lambda: Settings(USE_CELERY=False),
    )

    import asyncio

    def _capture(coro, *a, **k):
        created["coro"] = coro
        coro.close()  # don't actually run it; just prove it was scheduled
        return None

    monkeypatch.setattr(asyncio, "create_task", _capture)

    scan_orchestrator.launch_scan(aid)
    assert "coro" in created


def test_redis_event_publish_degrades_gracefully():
    """With no Redis running, publishing must not raise (best-effort)."""
    import asyncio

    from app.orchestrator import redis_events

    # Default REDIS_URL points at a port with nothing listening in tests.
    asyncio.run(redis_events.publish("aid-x", {"type": "stage", "payload": {}}))
