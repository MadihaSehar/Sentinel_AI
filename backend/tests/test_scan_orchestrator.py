"""
Tests for the scan orchestrator: stage sequencing, status lifecycle, event
emission and persistence — driven with injected fake stages so no real
external tools are needed.
"""
from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.orchestrator.events import ScanEventBus
from app.orchestrator.scan_orchestrator import ScanStages, run_scan
from app.schemas.discovery import DiscoveryResult
from app.schemas.finding import (
    EvidenceItem,
    FindingCandidate,
    RiskScore,
    Severity,
    VulnerabilityCategory,
)
from app.schemas.recon import ReconResult
from app.schemas.vulnerability import Finding as NucleiFinding
from app.schemas.vulnerability import Severity as NucleiSeverity
from app.schemas.vulnerability import VulnerabilityScanResult
from app.tools.registry import ToolRegistry


async def _authorized_assessment(client: AsyncClient) -> str:
    pr = await client.post("/api/projects", json={"name": "Orch Co"})
    project_id = pr.json()["id"]
    ar = await client.post(
        f"/api/projects/{project_id}/assessments",
        json={"name": "s", "target": "example.com", "assessment_type": "bug_bounty", "scope_rules": []},
    )
    assessment_id = ar.json()["id"]
    auth = await client.post(
        f"/api/projects/{project_id}/assessments/{assessment_id}/authorize",
        json={"confirmation_phrase": "I CONFIRM AUTHORIZATION", "acknowledgement": True},
    )
    assert auth.status_code == 200
    return assessment_id


def _nuclei_finding() -> NucleiFinding:
    return NucleiFinding(
        title="Exposed panel",
        category="exposed-panel",
        severity=NucleiSeverity.MEDIUM,
        confidence=0.6,
        endpoint="https://example.com/admin",
        evidence=["matched admin form"],
        source_tool="nuclei",
    )


def _candidate() -> FindingCandidate:
    return FindingCandidate(
        title="Reflected XSS",
        category=VulnerabilityCategory.XSS_REFLECTED,
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
        severity=Severity.HIGH,
        risk=RiskScore(evidence_score=0.8, confidence_score=0.8, exploitability_score=0.7, impact_score=0.7),
        endpoint="https://example.com/search",
        method="GET",
        parameter="q",
        evidence=[EvidenceItem(description="reflected")],
        recommendation="encode",
        analyzer_name="reflected_xss",
    )


def _fakes(*, recon_raises: bool = False) -> ScanStages:
    async def recon(assessment, scope, registry):
        if recon_raises:
            raise RuntimeError("subfinder not installed")
        return ReconResult(target=assessment.target)

    async def discovery(seeds, scope, registry):
        return DiscoveryResult(target=seeds[0])

    async def vulnerability(urls, scope, registry):
        return VulnerabilityScanResult(findings=[_nuclei_finding()], target_count=len(urls))

    async def analyze(assessment):
        return [_candidate()]

    return ScanStages(recon=recon, discovery=discovery, vulnerability=vulnerability, analyze=analyze)


@pytest.mark.asyncio
async def test_run_scan_completes_and_persists(authed_client: AsyncClient, _async_engine):
    assessment_id = uuid.UUID(await _authorized_assessment(authed_client))
    Session = async_sessionmaker(bind=_async_engine, expire_on_commit=False, class_=AsyncSession)
    bus = ScanEventBus()
    queue = bus.subscribe(str(assessment_id))

    await run_scan(Session, assessment_id, registry=ToolRegistry(), stages=_fakes(), bus=bus)

    # Two findings persisted (1 nuclei + 1 analyzer candidate).
    listed = (await authed_client.get(f"/api/assessments/{assessment_id}/findings")).json()
    assert len(listed) == 2

    # Status flipped to completed.
    detail = await authed_client.get(f"/api/assessments/{assessment_id}")
    # assessment detail route is project-scoped; fall back to the report, which 200s only if readable.
    report = await authed_client.get(f"/api/reports/assessments/{assessment_id}")
    assert report.status_code == 200
    assert "Reflected XSS" in report.text

    # Events: a running scan, stage transitions, and a completed scan.
    events = []
    while not queue.empty():
        events.append(queue.get_nowait())
    types = [(e["type"], e["payload"].get("status") or e["payload"].get("stage")) for e in events]
    assert ("scan", "running") in types
    assert ("scan", "completed") in types
    assert any(e["type"] == "stage" and e["payload"].get("stage") == "report" for e in events)


@pytest.mark.asyncio
async def test_run_scan_isolates_stage_failure(authed_client: AsyncClient, _async_engine):
    """A failing stage (e.g. a missing tool) must not abort the whole scan."""
    assessment_id = uuid.UUID(await _authorized_assessment(authed_client))
    Session = async_sessionmaker(bind=_async_engine, expire_on_commit=False, class_=AsyncSession)
    bus = ScanEventBus()
    queue = bus.subscribe(str(assessment_id))

    await run_scan(Session, assessment_id, registry=ToolRegistry(), stages=_fakes(recon_raises=True), bus=bus)

    # Recon failed but vulnerability findings still persisted and scan completed.
    listed = (await authed_client.get(f"/api/assessments/{assessment_id}/findings")).json()
    assert len(listed) == 2

    events = []
    while not queue.empty():
        events.append(queue.get_nowait())
    assert any(e["type"] == "stage" and e["payload"].get("stage") == "recon"
               and e["payload"].get("status") == "error" for e in events)
    assert any(e["type"] == "scan" and e["payload"].get("status") == "completed" for e in events)


@pytest.mark.asyncio
async def test_run_scan_refuses_unauthorized(authed_client: AsyncClient, _async_engine):
    pr = await authed_client.post("/api/projects", json={"name": "NoAuth Co"})
    project_id = pr.json()["id"]
    ar = await authed_client.post(
        f"/api/projects/{project_id}/assessments",
        json={"name": "s", "target": "example.com", "assessment_type": "bug_bounty", "scope_rules": []},
    )
    assessment_id = uuid.UUID(ar.json()["id"])  # never authorized
    Session = async_sessionmaker(bind=_async_engine, expire_on_commit=False, class_=AsyncSession)
    bus = ScanEventBus()
    queue = bus.subscribe(str(assessment_id))

    await run_scan(Session, assessment_id, registry=ToolRegistry(), stages=_fakes(), bus=bus)

    listed = (await authed_client.get(f"/api/assessments/{assessment_id}/findings")).json()
    assert listed == []
    events = [queue.get_nowait() for _ in range(queue.qsize())]
    assert any(e["type"] == "error" for e in events)


@pytest.mark.asyncio
async def test_event_bus_pub_sub():
    bus = ScanEventBus()
    q = bus.subscribe("aid-1")
    await bus.publish("aid-1", {"type": "x", "payload": {}})
    await bus.publish("other", {"type": "y", "payload": {}})  # different aid, not delivered
    assert q.get_nowait()["type"] == "x"
    assert q.empty()
    bus.unsubscribe("aid-1", q)
