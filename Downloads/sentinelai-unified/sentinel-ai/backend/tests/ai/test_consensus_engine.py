import sys
from pathlib import Path

import pytest

# Allow running this test file standalone without a full package install.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.ai.consensus import (  # noqa: E402
    ConsensusEngine,
    ConsensusStatus,
    ModelFinding,
    Severity,
)


def mf(model_name, is_vulnerable, severity, confidence, finding="candidate SQLi"):
    return ModelFinding(
        model_name=model_name,
        finding=finding,
        is_vulnerable=is_vulnerable,
        severity=severity,
        confidence=confidence,
        reasoning_summary="test summary",
        evidence=["evidence item"],
    )


class TestUnanimousConfirmed:
    def test_all_agree_high_confidence_confirms(self):
        findings = [
            mf("gemini", True, Severity.HIGH, 0.91),
            mf("grok", True, Severity.HIGH, 0.88),
            mf("deepseek", True, Severity.HIGH, 0.90),
        ]
        result = ConsensusEngine().analyze(findings)
        assert result.status == ConsensusStatus.CONFIRMED
        assert result.is_vulnerable_consensus is True
        assert result.severity == Severity.HIGH
        assert result.consensus_confidence > 0.8
        assert result.dissenting_models == []


class TestDisagreementRequiresReview:
    def test_spec_example_sqli_disagreement(self):
        """
        Mirrors the exact spec example:
        Gemini: Potential SQLi
        Grok: Likely false positive
        DeepSeek: Inconclusive
        -> Manual validation required
        """
        findings = [
            mf("gemini", True, Severity.HIGH, 0.75, finding="Potential SQLi"),
            mf("grok", False, Severity.LOW, 0.30, finding="Likely false positive"),
            mf("deepseek", False, Severity.MEDIUM, 0.50, finding="Inconclusive"),
        ]
        result = ConsensusEngine().analyze(findings)
        assert result.status == ConsensusStatus.REQUIRES_MANUAL_REVIEW
        assert "gemini" in result.dissenting_models

    def test_split_vote_goes_to_manual_review(self):
        findings = [
            mf("gemini", True, Severity.HIGH, 0.85),
            mf("grok", False, Severity.LOW, 0.80),
        ]
        result = ConsensusEngine().analyze(findings)
        assert result.status == ConsensusStatus.REQUIRES_MANUAL_REVIEW


class TestFalsePositive:
    def test_unanimous_not_vulnerable_low_confidence_is_likely_fp(self):
        findings = [
            mf("gemini", False, Severity.INFO, 0.10),
            mf("grok", False, Severity.INFO, 0.15),
            mf("deepseek", False, Severity.LOW, 0.20),
        ]
        result = ConsensusEngine().analyze(findings)
        assert result.status == ConsensusStatus.LIKELY_FALSE_POSITIVE
        assert result.is_vulnerable_consensus is False


class TestSingleModel:
    def test_single_model_never_auto_confirms(self):
        findings = [mf("gemini", True, Severity.CRITICAL, 0.99)]
        result = ConsensusEngine().analyze(findings)
        assert result.status == ConsensusStatus.REQUIRES_MANUAL_REVIEW
        assert result.participating_models == ["gemini"]


class TestMajorityLikely:
    def test_two_of_three_agree_moderate_confidence(self):
        findings = [
            mf("gemini", True, Severity.MEDIUM, 0.70),
            mf("grok", True, Severity.MEDIUM, 0.65),
            mf("deepseek", True, Severity.MEDIUM, 0.68),
        ]
        result = ConsensusEngine().analyze(findings)
        assert result.status in (ConsensusStatus.CONFIRMED, ConsensusStatus.LIKELY)
        assert result.is_vulnerable_consensus is True


class TestEmptyInput:
    def test_raises_on_no_findings(self):
        with pytest.raises(ValueError):
            ConsensusEngine().analyze([])


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
