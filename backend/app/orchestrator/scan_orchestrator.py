"""
Scan orchestrator — drives an authorized assessment through the scanning
stages and persists the result.

Flow:  recon → discovery → vulnerability → analyze → promote_and_persist
Along the way it updates ``Assessment.status`` (RUNNING → COMPLETED/FAILED)
and publishes live events to the scan event bus (consumed by the WebSocket
dashboard). Each stage is isolated: a stage that fails (e.g. a scanning tool
isn't installed) records an error event and the scan continues with whatever
was gathered, rather than aborting the whole run.

The stage implementations are injectable (``ScanStages``) so the orchestrator
logic — status lifecycle, event emission, persistence — is unit-testable with
fakes, independent of whether the real external tools are present.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.models.assessment import Assessment, AssessmentStatus
from app.orchestrator.events import make_event, scan_event_bus
from app.orchestrator.finding_promotion import promote_and_persist
from app.orchestrator.scope_builder import build_scope_engine
from app.schemas.discovery import DiscoveryResult
from app.schemas.finding import FindingCandidate
from app.schemas.recon import ReconResult
from app.schemas.vulnerability import VulnerabilityScanResult
from app.tools.registry import ToolRegistry, build_default_registry

logger = logging.getLogger("sentinel.orchestrator.scan")


# --------------------------------------------------------------------------- #
# Injectable stage implementations
# --------------------------------------------------------------------------- #
ReconFn = Callable[[Assessment, object, ToolRegistry], Awaitable[ReconResult]]
DiscoveryFn = Callable[[list[str], object, ToolRegistry], Awaitable[DiscoveryResult]]
VulnFn = Callable[[list[str], object, ToolRegistry], Awaitable[VulnerabilityScanResult]]
AnalyzeFn = Callable[[Assessment], Awaitable[list[FindingCandidate]]]


async def _default_recon(assessment, scope, registry) -> ReconResult:
    from app.orchestrator.recon_pipeline import ReconPipeline

    return await ReconPipeline(scope, registry).run(assessment.target)


async def _default_discovery(seeds, scope, registry) -> DiscoveryResult:
    from app.orchestrator.discovery_pipeline import DiscoveryPipeline

    return await DiscoveryPipeline(scope, registry).run(seeds)


async def _default_vulnerability(urls, scope, registry) -> VulnerabilityScanResult:
    from app.orchestrator.vulnerability_pipeline import VulnerabilityPipeline

    return await VulnerabilityPipeline(scope, registry).run(urls)


async def _default_analyze(assessment) -> list[FindingCandidate]:
    # Analyzer candidates come from captured request/response exchanges. That
    # capture isn't wired into this flow yet, so there are none to analyze;
    # nuclei findings (vulnerability stage) still flow through to persistence.
    return []


@dataclass
class ScanStages:
    recon: ReconFn = _default_recon
    discovery: DiscoveryFn = _default_discovery
    vulnerability: VulnFn = _default_vulnerability
    analyze: AnalyzeFn = _default_analyze


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #
def _seed_urls_from_recon(recon: ReconResult, target: str) -> list[str]:
    urls = [s.url for s in recon.http_services if getattr(s, "url", None)]
    if not urls:
        # Fall back to the bare target so later stages still have something.
        urls = [f"https://{target}"]
    return urls


def _urls_from_discovery(discovery: DiscoveryResult, seeds: list[str]) -> list[str]:
    urls: list[str] = list(seeds)
    urls += [u.url for u in discovery.crawled_urls if getattr(u, "url", None)]
    urls += [u.url for u in discovery.historical_urls if getattr(u, "url", None)]
    urls += [p.url for p in discovery.discovered_paths if getattr(p, "url", None)]
    # De-dup, preserve order.
    seen: dict[str, None] = {}
    for u in urls:
        seen.setdefault(u, None)
    return list(seen)


async def run_scan(
    session_factory,
    assessment_id: uuid.UUID,
    *,
    registry: Optional[ToolRegistry] = None,
    ai_service=None,
    stages: Optional[ScanStages] = None,
    bus=scan_event_bus,
) -> None:
    """Run the full scan for ``assessment_id``. Safe to run as a background task."""
    stages = stages or ScanStages()
    registry = registry or build_default_registry()
    aid = str(assessment_id)

    from app.core.config import get_settings

    _use_redis = get_settings().USE_CELERY

    async def emit(type_: str, **payload):
        event = make_event(type_, **payload)
        await bus.publish(aid, event)
        if _use_redis:
            # Cross-process delivery so the web process's WebSocket sees
            # events from the worker process.
            from app.orchestrator import redis_events

            await redis_events.publish(aid, event)

    try:
        await _run_scan_body(session_factory, assessment_id, aid, registry, ai_service, stages, emit)
    except Exception as exc:  # noqa: BLE001 - background task: never raise out
        logger.exception("scan %s aborted before/within session setup", aid)
        await emit("scan", status="failed", message=str(exc))


async def _run_scan_body(session_factory, assessment_id, aid, registry, ai_service, stages, emit) -> None:
    async with session_factory() as db:
        result = await db.execute(
            select(Assessment)
            .where(Assessment.id == assessment_id)
            .options(selectinload(Assessment.scope_rules))
        )
        assessment = result.scalar_one_or_none()
        if assessment is None:
            await emit("error", message=f"assessment {aid} not found")
            return
        if not assessment.authorization_confirmed:
            await emit("error", message="assessment is not authorized")
            return

        assessment.status = AssessmentStatus.RUNNING
        await db.commit()
        await emit("scan", status="running", target=assessment.target)

        errors: list[str] = []
        nuclei_findings: list = []
        candidates: list = []

        try:
            scope = build_scope_engine(assessment)

            # -- Recon --
            await emit("stage", stage="recon", status="running")
            try:
                recon = await stages.recon(assessment, scope, registry)
                errors += recon.tool_errors
                await emit(
                    "stage", stage="recon", status="done",
                    subdomains=len(recon.subdomains), services=len(recon.http_services),
                )
            except Exception as exc:  # noqa: BLE001
                recon = ReconResult(target=assessment.target)
                errors.append(f"recon: {exc}")
                await emit("stage", stage="recon", status="error", message=str(exc))

            seeds = _seed_urls_from_recon(recon, assessment.target)

            # -- Discovery --
            await emit("stage", stage="discovery", status="running")
            try:
                discovery = await stages.discovery(seeds, scope, registry)
                errors += discovery.tool_errors
                await emit(
                    "stage", stage="discovery", status="done",
                    crawled=len(discovery.crawled_urls), historical=len(discovery.historical_urls),
                )
            except Exception as exc:  # noqa: BLE001
                discovery = DiscoveryResult(target=seeds[0] if seeds else assessment.target)
                errors.append(f"discovery: {exc}")
                await emit("stage", stage="discovery", status="error", message=str(exc))

            urls = _urls_from_discovery(discovery, seeds)

            # -- Vulnerability --
            await emit("stage", stage="vulnerability", status="running")
            try:
                vuln = await stages.vulnerability(urls, scope, registry)
                errors += vuln.tool_errors
                nuclei_findings = list(vuln.findings)
                await emit(
                    "stage", stage="vulnerability", status="done",
                    findings=len(nuclei_findings), targets=vuln.target_count,
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(f"vulnerability: {exc}")
                await emit("stage", stage="vulnerability", status="error", message=str(exc))

            # -- Analyzers --
            await emit("stage", stage="analyze", status="running")
            try:
                candidates = await stages.analyze(assessment)
                await emit("stage", stage="analyze", status="done", candidates=len(candidates))
            except Exception as exc:  # noqa: BLE001
                errors.append(f"analyze: {exc}")
                await emit("stage", stage="analyze", status="error", message=str(exc))

            # -- Promote + persist --
            await emit("stage", stage="report", status="running")
            rows = await promote_and_persist(
                db, assessment_id,
                candidates=candidates, nuclei_findings=nuclei_findings, ai_service=ai_service,
            )
            await emit("stage", stage="report", status="done", findings=len(rows))

            assessment.status = AssessmentStatus.COMPLETED
            await db.commit()
            await emit("scan", status="completed", findings=len(rows), errors=errors)
        except Exception as exc:  # noqa: BLE001 - truly fatal
            logger.exception("scan %s failed", aid)
            assessment.status = AssessmentStatus.FAILED
            await db.commit()
            await emit("scan", status="failed", message=str(exc), errors=errors)


def launch_scan(assessment_id: uuid.UUID) -> None:
    """
    Start the scan for an assessment. Dispatches to a Celery worker when
    ``USE_CELERY`` is set, otherwise runs it in-process as a background
    asyncio task. Called by the start endpoint.
    """
    from app.core.config import get_settings

    if get_settings().USE_CELERY:
        from app.worker.tasks import run_scan_task

        run_scan_task.delay(str(assessment_id))
        return

    import asyncio

    from app.core.db import AsyncSessionLocal

    ai_service = None
    try:
        from app.ai.service import AIAnalysisService

        ai_service = AIAnalysisService.from_env()
    except Exception:  # noqa: BLE001 - no providers configured is fine
        ai_service = None

    asyncio.create_task(
        run_scan(AsyncSessionLocal, assessment_id, ai_service=ai_service)
    )
