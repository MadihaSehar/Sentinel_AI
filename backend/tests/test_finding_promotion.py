"""
Tests for the finding-promotion glue: analyzer/nuclei findings → (consensus)
→ persisted findings.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.ai.providers.base import AIAnalysisResult, AIProvider, AIUsage
from app.ai.providers.factory import AIProviderRouter
from app.ai.service import AIAnalysisService
from app.orchestrator.finding_promotion import (
    candidate_to_finding_in,
    nuclei_finding_to_finding_in,
    promote_and_persist,
)
from app.schemas.finding import (
    EvidenceItem,
    FindingCandidate,
    RiskScore,
    Severity,
    VulnerabilityCategory,
)
from app.schemas.vulnerability import Finding as NucleiFinding
from app.schemas.vulnerability import Severity as NucleiSeverity


class _ScriptedProvider(AIProvider):
    def __init__(self, name: str, finding: str | None, severity: str | None, confidence: float):
        self.name = name
        self.model = f"{name}-model"
        self._finding, self._severity, self._confidence = finding, severity, confidence

    async def _call(self, system_prompt, user_prompt):  # pragma: no cover
        raise NotImplementedError

    async def analyze(self, prompt, context):
        return AIAnalysisResult(
            provider=self.name,
            model=self.model,
            finding=self._finding,
            severity=self._severity,
            confidence=self._confidence,
            reasoning_summary=f"{self.name} says so",
            evidence=[f"{self.name}-evidence"],
            usage=AIUsage(),
            success=True,
        )


def _candidate() -> FindingCandidate:
    return FindingCandidate(
        title="Reflected XSS in q",
        category=VulnerabilityCategory.XSS_REFLECTED,
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
        severity=Severity.HIGH,
        risk=RiskScore(
            evidence_score=0.8, confidence_score=0.8, exploitability_score=0.7, impact_score=0.7
        ),
        endpoint="https://example.com/search",
        method="GET",
        parameter="q",
        evidence=[EvidenceItem(description="payload reflected unescaped")],
        recommendation="Encode output.",
        analyzer_name="reflected_xss",
    )


def _nuclei_finding() -> NucleiFinding:
    return NucleiFinding(
        title="Exposed admin panel",
        category="exposed-panel",
        cwe="CWE-200",
        severity=NucleiSeverity.MEDIUM,
        confidence=0.6,
        endpoint="https://example.com/admin",
        evidence=["matched: admin login form"],
        source_tool="nuclei",
    )


def test_candidate_mapping():
    item = candidate_to_finding_in(_candidate())
    assert item.title == "Reflected XSS in q"
    assert item.category == "Xss Reflected"
    assert item.cwe == "CWE-79"
    assert item.severity == "high"
    assert item.evidence == ["payload reflected unescaped"]
    assert item.analyzer_name == "reflected_xss"


def test_nuclei_mapping():
    item = nuclei_finding_to_finding_in(_nuclei_finding())
    assert item.severity == "medium"
    assert item.endpoint == "https://example.com/admin"
    assert item.analyzer_name == "nuclei"


async def _make_assessment(client: AsyncClient) -> str:
    pr = await client.post("/api/projects", json={"name": "Promote Co"})
    project_id = pr.json()["id"]
    ar = await client.post(
        f"/api/projects/{project_id}/assessments",
        json={"name": "s", "target": "example.com", "assessment_type": "bug_bounty", "scope_rules": []},
    )
    return ar.json()["id"]


@pytest.mark.asyncio
async def test_promote_without_ai_persists_deterministically(authed_client, _async_engine):
    import uuid as _uuid

    assessment_id = _uuid.UUID(await _make_assessment(authed_client))
    Session = async_sessionmaker(bind=_async_engine, expire_on_commit=False, class_=AsyncSession)
    async with Session() as db:
        rows = await promote_and_persist(
            db, assessment_id, candidates=[_candidate()], nuclei_findings=[_nuclei_finding()]
        )
    assert len(rows) == 2
    # No AI service → verdict stays the conservative default.
    xss = next(r for r in rows if "XSS" in r.title)
    assert xss.consensus_status == "requires_manual_review"
    assert xss.participating_models == []

    listed = (await authed_client.get(f"/api/assessments/{assessment_id}/findings")).json()
    assert len(listed) == 2


@pytest.mark.asyncio
async def test_promote_with_ai_consensus_populates_verdict(authed_client, _async_engine):
    import uuid as _uuid

    assessment_id = _uuid.UUID(await _make_assessment(authed_client))
    ai = AIAnalysisService(
        AIProviderRouter(
            [
                _ScriptedProvider("gemini", "XSS confirmed", "high", 0.9),
                _ScriptedProvider("deepseek", "XSS confirmed", "high", 0.88),
            ]
        )
    )
    Session = async_sessionmaker(bind=_async_engine, expire_on_commit=False, class_=AsyncSession)
    async with Session() as db:
        rows = await promote_and_persist(
            db, assessment_id, candidates=[_candidate()], ai_service=ai
        )
    assert len(rows) == 1
    row = rows[0]
    assert row.consensus_status == "confirmed"
    assert row.agreement_score > 0.9
    assert set(row.participating_models) == {"gemini", "deepseek"}

    # And the report now reflects the consensus-reviewed finding.
    report = await authed_client.get(f"/api/reports/assessments/{assessment_id}")
    assert "Reflected XSS in q" in report.text
