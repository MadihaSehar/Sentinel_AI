import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.evidence import (  # noqa: E402
    EvidenceItem,
    EvidenceType as E,
    FalsePositiveEngine,
    FalsePositiveVerdict,
    VulnCategory as C,
)


def ev(etype, detail="x", source="test_analyzer", strength=1.0):
    return EvidenceItem(type=etype, detail=detail, source=source, strength=strength)


@dataclass
class FakeConsensus:
    """Minimal stand-in for Section 12's ConsensusResult (duck-typed)."""
    is_vulnerable_consensus: bool
    consensus_confidence: float


class TestSpecExamples:
    def test_db_error_alone_is_not_sqli(self):
        """
        Spec: "A database-looking error alone should NOT automatically
        mean SQL injection."
        """
        result = FalsePositiveEngine().evaluate(
            C.SQL_INJECTION, [ev(E.DB_ERROR_SIGNATURE, strength=0.9)]
        )
        assert result.verdict == FalsePositiveVerdict.INSUFFICIENT_EVIDENCE
        assert result.scores.final_risk_score <= 0.35

    def test_reflected_param_alone_is_not_exploitable_xss(self):
        """
        Spec: "A reflected parameter alone should NOT automatically mean
        exploitable XSS."
        """
        result = FalsePositiveEngine().evaluate(
            C.XSS_REFLECTED, [ev(E.REFLECTED_PARAM, strength=0.8)]
        )
        assert result.verdict == FalsePositiveVerdict.INSUFFICIENT_EVIDENCE

    def test_different_response_alone_is_not_idor(self):
        """
        Spec: "A different HTTP response alone should NOT automatically
        mean IDOR."
        """
        result = FalsePositiveEngine().evaluate(
            C.IDOR_BOLA, [ev(E.DIFFERENT_RESPONSE_FOR_OTHER_IDENTITY, strength=0.7)]
        )
        assert result.verdict == FalsePositiveVerdict.INSUFFICIENT_EVIDENCE
        assert E.SENSITIVE_DATA_IN_RESPONSE in result.missing_evidence


class TestSufficientEvidence:
    def test_sqli_error_plus_structural_diff_passes_gate(self):
        result = FalsePositiveEngine().evaluate(
            C.SQL_INJECTION,
            [
                ev(E.DB_ERROR_SIGNATURE, strength=0.9),
                ev(E.STRUCTURAL_DIFF, strength=0.85),
            ],
        )
        assert result.verdict == FalsePositiveVerdict.SUFFICIENT_EVIDENCE
        assert result.scores.evidence_score > 0.5
        assert result.scores.final_risk_score > 0.35

    def test_idor_full_combo_passes(self):
        result = FalsePositiveEngine().evaluate(
            C.IDOR_BOLA,
            [
                ev(E.DIFFERENT_RESPONSE_FOR_OTHER_IDENTITY, strength=0.9),
                ev(E.SENSITIVE_DATA_IN_RESPONSE, strength=0.95),
                ev(E.STATUS_CODE_DIFF, strength=0.8),
            ],
        )
        assert result.verdict == FalsePositiveVerdict.SUFFICIENT_EVIDENCE


class TestConsensusBlending:
    def test_sufficient_evidence_plus_agreeing_high_confidence_ai_raises_risk(self):
        engine = FalsePositiveEngine()
        evidence = [ev(E.DB_ERROR_SIGNATURE, strength=0.9), ev(E.STRUCTURAL_DIFF, strength=0.85)]

        without_ai = engine.evaluate(C.SQL_INJECTION, evidence)
        with_ai = engine.evaluate(
            C.SQL_INJECTION, evidence, consensus=FakeConsensus(True, 0.95)
        )
        assert with_ai.scores.confidence_score >= without_ai.scores.confidence_score
        assert with_ai.scores.final_risk_score >= without_ai.scores.final_risk_score

    def test_sufficient_evidence_but_ai_disagrees_does_not_auto_confirm_high(self):
        engine = FalsePositiveEngine()
        evidence = [ev(E.DB_ERROR_SIGNATURE, strength=0.9), ev(E.STRUCTURAL_DIFF, strength=0.85)]
        result = engine.evaluate(
            C.SQL_INJECTION, evidence, consensus=FakeConsensus(False, 0.9)
        )
        # Evidence passed the gate, but AI pushback should prevent a
        # falsely high confidence score.
        assert result.scores.confidence_score <= 0.4

    def test_no_evidence_and_ai_says_not_vulnerable_is_likely_false_positive(self):
        engine = FalsePositiveEngine()
        result = engine.evaluate(
            C.XSS_REFLECTED, [ev(E.REFLECTED_PARAM, strength=0.5)],
            consensus=FakeConsensus(False, 0.8),
        )
        assert result.verdict == FalsePositiveVerdict.LIKELY_FALSE_POSITIVE
        assert result.scores.final_risk_score <= 0.15


class TestNoEvidence:
    def test_empty_evidence_list_is_insufficient_and_zero_scored(self):
        result = FalsePositiveEngine().evaluate(C.COMMAND_INJECTION, [])
        assert result.verdict == FalsePositiveVerdict.INSUFFICIENT_EVIDENCE
        assert result.scores.evidence_score == 0.0


class TestExploitabilityBoost:
    def test_strong_confirmation_evidence_boosts_exploitability(self):
        engine = FalsePositiveEngine()
        baseline = engine.evaluate(
            C.SSRF, [ev(E.OUTBOUND_CALLBACK_RECEIVED, strength=0.9)]
        )
        weaker = engine.evaluate(
            C.SSRF,
            [ev(E.INTERNAL_SERVICE_RESPONSE_LEAKED, strength=0.9), ev(E.STRUCTURAL_DIFF, strength=0.8)],
        )
        assert baseline.scores.exploitability_score >= weaker.scores.exploitability_score


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
