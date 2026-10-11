"""
Finding promotion: the glue between the scanning stages and persistence.

The scanning stages produce two shapes of finding:
  * the vulnerability pipeline (nuclei) → ``app.schemas.vulnerability.Finding``
  * the analyzers                       → ``app.schemas.finding.FindingCandidate``

This module normalizes both into the persistence ``FindingIn`` shape, runs
each through the multi-model AI consensus engine (when an AI service with at
least one active provider is supplied), and writes the result with
``findings_service.set_findings``. This is what an orchestrator calls at the
end of a scan so that findings, reports and the scan-to-scan diff all reflect
real, consensus-reviewed data.

When no AI provider is configured, promotion still works: it keeps the
deterministic analyzer/tool confidence and marks findings as
``requires_manual_review`` rather than inventing a consensus verdict.
"""
from __future__ import annotations

import logging
import uuid
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.service import AIAnalysisService
from app.models.finding import Finding
from app.schemas.finding import FindingCandidate
from app.schemas.finding_ingest import FindingIn
from app.schemas.vulnerability import Finding as NucleiFinding
from app.services import findings_service

logger = logging.getLogger("sentinel.orchestrator.promotion")

# Map a finding's category to the most specific analysis prompt available,
# falling back to the generic severity prompt.
_CATEGORY_PROMPT = {
    "sql_injection": "sqli_analysis",
    "sqli": "sqli_analysis",
    "xss_reflected": "xss_analysis",
    "xss": "xss_analysis",
    "idor": "idor_analysis",
    "ssrf": "ssrf_analysis",
}


def _prompt_for(category: str) -> str:
    key = category.strip().lower()
    for needle, prompt in _CATEGORY_PROMPT.items():
        if needle in key:
            return prompt
    return "severity_analysis"


def _category_label(category: str) -> str:
    return category.replace("_", " ").title()


def candidate_to_finding_in(c: FindingCandidate) -> FindingIn:
    return FindingIn(
        title=c.title,
        category=_category_label(c.category.value),
        cwe=c.cwe,
        owasp=c.owasp,
        severity=c.severity.value,
        status=c.status.value,
        endpoint=c.endpoint,
        method=c.method,
        parameter=c.parameter,
        description=c.title,
        evidence=[e.description for e in c.evidence],
        recommendation=c.recommendation,
        references=list(c.references),
        affected_assets=list(c.affected_assets),
        consensus_confidence=c.confidence,
        analyzer_name=c.analyzer_name,
    )


def nuclei_finding_to_finding_in(f: NucleiFinding) -> FindingIn:
    return FindingIn(
        title=f.title,
        category=_category_label(f.category),
        cwe=f.cwe,
        owasp=f.owasp,
        severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
        endpoint=f.endpoint,
        method=f.method,
        parameter=f.parameter,
        description=f.title,
        evidence=list(f.evidence),
        recommendation=f.recommendation or "",
        references=list(f.references),
        affected_assets=list(f.affected_assets),
        consensus_confidence=f.confidence,
        analyzer_name=f.source_tool,
    )


def _consensus_context(item: FindingIn) -> dict:
    return {
        "title": item.title,
        "category": item.category,
        "severity": item.severity,
        "endpoint": item.endpoint,
        "parameter": item.parameter,
        "evidence": item.evidence,
    }


async def _apply_consensus(item: FindingIn, ai_service: AIAnalysisService) -> FindingIn:
    """Run one finding through the consensus engine and fold the verdict in."""
    try:
        result = await ai_service.analyze_with_consensus(
            _prompt_for(item.category), _consensus_context(item)
        )
    except Exception as exc:  # noqa: BLE001 - a model error must not drop the finding
        logger.warning("Consensus failed for %r; keeping deterministic verdict: %s", item.title, exc)
        return item

    item.consensus_status = result.status.value
    item.agreement_score = result.agreement_score
    item.consensus_confidence = result.consensus_confidence
    item.participating_models = list(result.participating_models)
    return item


async def promote_and_persist(
    db: AsyncSession,
    assessment_id: uuid.UUID,
    *,
    candidates: Optional[list[FindingCandidate]] = None,
    nuclei_findings: Optional[list[NucleiFinding]] = None,
    ai_service: Optional[AIAnalysisService] = None,
) -> list[Finding]:
    """
    Normalize + (optionally) consensus-review + persist findings for an
    assessment. Returns the persisted rows.
    """
    items: list[FindingIn] = [candidate_to_finding_in(c) for c in (candidates or [])]
    items += [nuclei_finding_to_finding_in(f) for f in (nuclei_findings or [])]

    run_consensus = ai_service is not None and bool(ai_service.active_providers)
    if run_consensus:
        items = [await _apply_consensus(item, ai_service) for item in items]
    elif ai_service is not None:
        logger.info("No active AI providers; persisting findings with deterministic confidence only.")

    return await findings_service.set_findings(db, assessment_id, items)
