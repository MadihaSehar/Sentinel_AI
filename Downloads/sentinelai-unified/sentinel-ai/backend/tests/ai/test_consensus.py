"""
Unit tests for ConsensusEngine (Phase 10 / section 12).

Pure logic over AIAnalysisResult lists — no HTTP, no mocking needed.
"""
from __future__ import annotations

from app.ai.consensus.engine import ConsensusEngine, ConsensusStatus
from app.ai.providers.base import AIAnalysisResult, AIUsage


def _result(
    provider: str,
    finding: str | None,
    severity: str | None,
    confidence: float,
    evidence: list[str] | None = None,
    success: bool = True,
) -> AIAnalysisResult:
    return AIAnalysisResult(
        provider=provider,
        model=f"{provider}-model",
        finding=finding,
        severity=severity,
        confidence=confidence,
        reasoning_summary=f"{provider} reasoning",
        evidence=evidence or [],
        usage=AIUsage(),
        success=success,
    )


def test_unanimous_high_confidence_finding_is_confirmed():
    results = [
        _result("gemini", "Reflected XSS in q param", "medium", 0.91, ["evidence A"]),
        _result("grok", "Reflected XSS in q param", "medium", 0.84, ["evidence B"]),
        _result("deepseek", "Reflected XSS in q param", "high", 0.88, ["evidence A"]),
    ]
    engine = ConsensusEngine()
    consensus = engine.evaluate(results)

    assert consensus.status == ConsensusStatus.CONFIRMED
    assert consensus.confidence == round((0.91 + 0.84 + 0.88) / 3, 4)
    assert consensus.severity == "high"  # conservative: highest reported among agreeing models
    assert consensus.model_count == 3
    assert set(consensus.evidence) == {"evidence A", "evidence B"}  # deduped union


def test_unanimous_no_finding_is_no_finding_status():
    results = [
        _result("gemini", None, None, 0.1),
        _result("grok", None, None, 0.05),
        _result("deepseek", None, None, 0.0),
    ]
    engine = ConsensusEngine()
    consensus = engine.evaluate(results)

    assert consensus.status == ConsensusStatus.NO_FINDING
    assert consensus.finding is None


def test_disagreement_triggers_manual_review():
    # Mirrors the worked example in section 12: one model says potential
    # SQLi, one calls it a likely false positive, one is inconclusive.
    results = [
        _result("gemini", "Potential SQL injection", "high", 0.85),
        _result("grok", None, None, 0.15),  # "likely false positive"
        _result("deepseek", None, None, 0.3),  # "inconclusive", below threshold
    ]
    engine = ConsensusEngine()
    consensus = engine.evaluate(results)

    assert consensus.status == ConsensusStatus.REQUIRES_MANUAL_REVIEW
    assert consensus.disagreement_notes  # at least one note explaining why


def test_unanimous_but_wide_confidence_spread_still_needs_review():
    # All three agree a finding exists, but conviction ranges from 0.55 to
    # 0.98 — too wide a spread to auto-confirm even though nobody dissented.
    results = [
        _result("gemini", "Open redirect via `next` param", "low", 0.98),
        _result("grok", "Open redirect via `next` param", "low", 0.72),
        _result("deepseek", "Open redirect via `next` param", "low", 0.55),
    ]
    engine = ConsensusEngine(disagreement_stdev_threshold=0.1)
    consensus = engine.evaluate(results)

    assert consensus.status == ConsensusStatus.REQUIRES_MANUAL_REVIEW
    assert any("spread" in note for note in consensus.disagreement_notes)


def test_low_confidence_finding_counts_as_absent_vote():
    # A finding reported at 0.2 confidence should NOT count toward
    # "finding present" — it's effectively noise, matching section 13's
    # false-positive-reduction intent.
    results = [
        _result("gemini", "maybe something", "low", 0.2),
        _result("grok", None, None, 0.1),
        _result("deepseek", None, None, 0.05),
    ]
    engine = ConsensusEngine(finding_confidence_threshold=0.5)
    consensus = engine.evaluate(results)

    assert consensus.status == ConsensusStatus.NO_FINDING


def test_all_providers_failing_is_insufficient_data():
    results = [
        _result("gemini", None, None, 0.0, success=False),
        _result("grok", None, None, 0.0, success=False),
    ]
    engine = ConsensusEngine()
    consensus = engine.evaluate(results)

    assert consensus.status == ConsensusStatus.INSUFFICIENT_DATA
    assert consensus.model_count == 0


def test_single_successful_model_cannot_auto_confirm():
    results = [
        _result("gemini", "Possible IDOR", "high", 0.95),
        _result("grok", None, None, 0.0, success=False),
    ]
    engine = ConsensusEngine(min_models_for_auto_confirm=2)
    consensus = engine.evaluate(results)

    assert consensus.status == ConsensusStatus.REQUIRES_MANUAL_REVIEW
    assert consensus.model_count == 1


def test_failed_providers_are_excluded_from_scoring_but_kept_in_per_model():
    results = [
        _result("gemini", "SSRF via webhook url", "high", 0.9),
        _result("grok", "SSRF via webhook url", "high", 0.88),
        _result("deepseek", None, None, 0.0, success=False),
    ]
    engine = ConsensusEngine()
    consensus = engine.evaluate(results)

    assert consensus.model_count == 2  # only successful ones count
    assert len(consensus.per_model) == 3  # but nothing is dropped from the audit trail
    assert consensus.status == ConsensusStatus.CONFIRMED


def test_severity_aggregation_prefers_highest_not_average():
    results = [
        _result("gemini", "Broken access control", "critical", 0.9),
        _result("grok", "Broken access control", "low", 0.85),
    ]
    engine = ConsensusEngine()
    consensus = engine.evaluate(results)

    assert consensus.severity == "critical"


def test_agreement_score_is_1_for_identical_confidences():
    results = [
        _result("gemini", "X", "low", 0.8),
        _result("grok", "X", "low", 0.8),
    ]
    engine = ConsensusEngine()
    consensus = engine.evaluate(results)

    assert consensus.agreement_score == 1.0
