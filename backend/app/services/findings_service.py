"""
Persistence + mapping for vulnerability findings.

One code path writes findings (``set_findings`` — replace semantics, so a
re-scan doesn't duplicate rows) and one reads them (``list_findings``). The
mappers turn a persisted :class:`Finding` into the report's ``ReportFinding``
(for HTML/PDF/SARIF/diff) so reports and diffs run off real stored data.
"""
from __future__ import annotations

import uuid

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.assessment import Assessment
from app.models.finding import Finding
from app.reports import ReportData
from app.reports.schemas import ConsensusStatus, ReportFinding, Severity
from app.schemas.finding_ingest import FindingIn


async def set_findings(
    db: AsyncSession, assessment_id: uuid.UUID, items: list[FindingIn]
) -> list[Finding]:
    """Replace all findings for an assessment with ``items``."""
    await db.execute(delete(Finding).where(Finding.assessment_id == assessment_id))
    rows = [
        Finding(
            assessment_id=assessment_id,
            title=i.title,
            category=i.category,
            cwe=i.cwe,
            owasp=i.owasp,
            severity=i.severity,
            status=i.status,
            endpoint=i.endpoint,
            method=i.method,
            parameter=i.parameter,
            description=i.description,
            evidence=i.evidence,
            recommendation=i.recommendation,
            references=i.references,
            affected_assets=i.affected_assets,
            consensus_status=i.consensus_status,
            agreement_score=i.agreement_score,
            consensus_confidence=i.consensus_confidence,
            participating_models=i.participating_models,
            analyzer_name=i.analyzer_name,
        )
        for i in items
    ]
    db.add_all(rows)
    await db.commit()
    for r in rows:
        await db.refresh(r)
    return rows


async def list_findings(db: AsyncSession, assessment_id: uuid.UUID) -> list[Finding]:
    result = await db.execute(
        select(Finding).where(Finding.assessment_id == assessment_id)
    )
    return list(result.scalars().all())


def _safe_severity(value: str) -> Severity:
    try:
        return Severity(value.strip().lower())
    except ValueError:
        return Severity.INFO


def _safe_consensus(value: str) -> ConsensusStatus:
    try:
        return ConsensusStatus(value.strip().lower())
    except ValueError:
        return ConsensusStatus.REQUIRES_MANUAL_REVIEW


def to_report_finding(f: Finding) -> ReportFinding:
    return ReportFinding(
        title=f.title,
        severity=_safe_severity(f.severity),
        category=f.category,
        cwe=f.cwe,
        owasp=f.owasp,
        endpoint=f.endpoint,
        method=f.method,
        parameter=f.parameter,
        description=f.description or "",
        evidence=list(f.evidence or []),
        recommendation=f.recommendation or "",
        references=list(f.references or []),
        consensus_status=_safe_consensus(f.consensus_status),
        agreement_score=f.agreement_score or 0.0,
        consensus_confidence=f.consensus_confidence or 0.0,
        participating_models=list(f.participating_models or []),
    )


async def build_report_data(db: AsyncSession, assessment: Assessment) -> ReportData:
    """Assemble a ReportData snapshot from a persisted assessment + findings."""
    findings = await list_findings(db, assessment.id)
    return ReportData(
        target=assessment.target,
        assessment_name=assessment.name,
        assessment_type=getattr(
            assessment.assessment_type, "value", str(assessment.assessment_type)
        ),
        authorization_statement=(
            "Authorization confirmed" if assessment.authorization_confirmed else None
        ),
        findings=[to_report_finding(f) for f in findings],
    )
