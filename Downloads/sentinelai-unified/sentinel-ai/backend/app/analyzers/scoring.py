"""
SentinelAI - Phase 7: Vulnerability Analyzers
Shared scoring helpers (Section 13).

Centralizing this keeps every analyzer's scoring philosophy consistent:
more independent pieces of evidence -> higher evidence_score; but
confidence_score is capped unless evidence comes from more than one
*kind* of indicator (the whole point of Section 13 -- "a reflected
parameter alone should NOT automatically mean exploitable XSS").
"""

from __future__ import annotations

from app.schemas.finding import RiskScore

# A single indicator kind alone is never enough to be "confident".
_SINGLE_EVIDENCE_CONFIDENCE_CAP = 0.55


def score_from_indicator_kinds(
    kinds: list[str],
    exploitability_score: float,
    impact_score: float,
) -> RiskScore:
    """Build a RiskScore from the distinct indicator kinds backing a
    finding. More distinct kinds => higher evidence + confidence, with a
    hard cap when only one kind of evidence exists."""
    distinct = set(kinds)
    evidence_score = min(1.0, 0.3 + 0.25 * len(distinct))

    base_confidence = min(1.0, 0.2 + 0.3 * len(distinct))
    if len(distinct) <= 1:
        base_confidence = min(base_confidence, _SINGLE_EVIDENCE_CONFIDENCE_CAP)

    return RiskScore(
        evidence_score=round(evidence_score, 4),
        confidence_score=round(base_confidence, 4),
        exploitability_score=round(exploitability_score, 4),
        impact_score=round(impact_score, 4),
    )
