"""
Multi-Model Consensus Engine  (Section 12 of the SentinelAI spec)

Purpose
-------
Independent AI providers (Gemini, Grok, DeepSeek, ...) each analyze the same
evidence bundle for a candidate vulnerability and return a ModelFinding.
This engine combines those independent judgments into one ConsensusResult,
and is the primary mechanism SentinelAI uses to reduce false positives
(Section 13): a single model's hallucination should not become a reported
finding; agreement across independently-prompted models is required.

Design notes
------------
- Deterministic, auditable math only. No LLM call happens in this file --
  the engine consumes AI output, it does not produce it. This keeps the
  false-positive-reduction logic testable and reproducible.
- "Agreement" blends three signals:
    1. Verdict agreement   -- do models agree it's even a real vulnerability?
    2. Severity agreement  -- how far apart are their severity ratings?
    3. Confidence agreement -- how far apart are their confidence scores?
- A single dissenting model (especially at low participant counts) is
  enough to force REQUIRES_MANUAL_REVIEW -- we'd rather over-flag for a
  human than silently drop or silently confirm a disputed finding.
- Thresholds are configurable via ConsensusConfig so they can be tuned
  per the research experiment framework in Section 37 (Nuclei-only vs.
  Nuclei+1-model vs. Nuclei+N-model-consensus).
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations
from statistics import mean, pstdev

from .schemas import (
    ConsensusResult,
    ConsensusStatus,
    ModelFinding,
    PairwiseDisagreement,
    Severity,
)


@dataclass
class ConsensusConfig:
    """Tunable thresholds. Defaults are deliberately conservative."""

    # Minimum number of models that must agree it IS a vulnerability
    # (as a fraction of participants) to call it CONFIRMED/LIKELY.
    min_agreement_for_confirmed: float = 1.0   # unanimous required for CONFIRMED
    min_agreement_for_likely: float = 0.66     # 2/3 majority required for LIKELY

    # Severity gap (in ranks, 0-4 scale) above which we force manual review
    # even if verdicts agree.
    max_severity_gap_for_auto: int = 1

    # Confidence gap (0-1) above which we force manual review.
    max_confidence_gap_for_auto: float = 0.35

    # Minimum mean confidence required to auto-confirm at all.
    min_mean_confidence_for_confirmed: float = 0.80
    min_mean_confidence_for_likely: float = 0.60

    # Below this mean confidence (with verdict agreement on "not vulnerable"),
    # we call it a likely false positive rather than just "low confidence".
    false_positive_ceiling_confidence: float = 0.35

    # If fewer than this many models responded, never auto-confirm --
    # always require manual review. Single-model "consensus" is not consensus.
    min_models_for_auto_decision: int = 2


class ConsensusEngine:
    """
    Combine independent ModelFindings for one candidate vulnerability into
    a single ConsensusResult.
    """

    def __init__(self, config: ConsensusConfig | None = None):
        self.config = config or ConsensusConfig()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def analyze(self, findings: list[ModelFinding]) -> ConsensusResult:
        if not findings:
            raise ValueError("ConsensusEngine.analyze() requires at least one ModelFinding")

        if len(findings) == 1:
            return self._single_model_result(findings[0])

        disagreements = self._pairwise_disagreements(findings)
        agreement_score = self._agreement_score(findings, disagreements)
        consensus_confidence = self._weighted_confidence(findings, agreement_score)
        consensus_severity = self._consensus_severity(findings)
        vulnerable_votes = [f for f in findings if f.is_vulnerable]
        vote_fraction = len(vulnerable_votes) / len(findings)

        status, is_vulnerable_consensus = self._decide_status(
            findings=findings,
            vote_fraction=vote_fraction,
            agreement_score=agreement_score,
            consensus_confidence=consensus_confidence,
            disagreements=disagreements,
        )

        dissenting = self._dissenting_models(findings, is_vulnerable_consensus)

        return ConsensusResult(
            status=status,
            is_vulnerable_consensus=is_vulnerable_consensus,
            severity=consensus_severity,
            consensus_confidence=round(consensus_confidence, 4),
            agreement_score=round(agreement_score, 4),
            participating_models=[f.model_name for f in findings],
            dissenting_models=dissenting,
            disagreements=disagreements,
            model_findings=findings,
            summary=self._build_summary(
                status, findings, vote_fraction, consensus_confidence, dissenting
            ),
        )

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _single_model_result(self, finding: ModelFinding) -> ConsensusResult:
        """
        One model only (e.g. others failed/timed out, see Section 28 -
        model failure handling). Never auto-confirm on a single opinion.
        """
        return ConsensusResult(
            status=ConsensusStatus.REQUIRES_MANUAL_REVIEW,
            is_vulnerable_consensus=finding.is_vulnerable,
            severity=finding.severity,
            consensus_confidence=finding.confidence,
            agreement_score=1.0,  # trivially "agrees with itself"
            participating_models=[finding.model_name],
            dissenting_models=[],
            disagreements=[],
            model_findings=[finding],
            summary=(
                f"Only one model ({finding.model_name}) returned a result; "
                f"single-model output is never auto-confirmed. Manual review required."
            ),
        )

    def _pairwise_disagreements(
        self, findings: list[ModelFinding]
    ) -> list[PairwiseDisagreement]:
        results = []
        for a, b in combinations(findings, 2):
            results.append(
                PairwiseDisagreement(
                    model_a=a.model_name,
                    model_b=b.model_name,
                    verdict_disagrees=(a.is_vulnerable != b.is_vulnerable),
                    severity_gap=abs(a.severity.rank - b.severity.rank),
                    confidence_gap=round(abs(a.confidence - b.confidence), 4),
                )
            )
        return results

    def _agreement_score(
        self, findings: list[ModelFinding], disagreements: list[PairwiseDisagreement]
    ) -> float:
        """
        Blend verdict / severity / confidence agreement into one 0-1 score.
        1.0 = every model fully agrees on everything.
        """
        if not disagreements:
            return 1.0

        verdict_agree_fraction = 1 - (
            sum(1 for d in disagreements if d.verdict_disagrees) / len(disagreements)
        )
        # Max possible severity gap is 4 (info..critical)
        severity_agree_fraction = 1 - (mean(d.severity_gap for d in disagreements) / 4)
        confidence_agree_fraction = 1 - mean(d.confidence_gap for d in disagreements)

        # Verdict agreement matters most -- two models disagreeing on
        # "is this even real" is worse than disagreeing on exact severity.
        score = (
            0.5 * verdict_agree_fraction
            + 0.25 * severity_agree_fraction
            + 0.25 * confidence_agree_fraction
        )
        return max(0.0, min(1.0, score))

    def _weighted_confidence(self, findings: list[ModelFinding], agreement_score: float) -> float:
        """
        Mean confidence, discounted by disagreement. High individual
        confidence scores from models that contradict each other should
        NOT average out to a falsely high consensus confidence.
        """
        raw_mean = mean(f.confidence for f in findings)
        spread_penalty = pstdev(f.confidence for f in findings) if len(findings) > 1 else 0.0
        return max(0.0, raw_mean * agreement_score - spread_penalty * 0.5)

    def _consensus_severity(self, findings: list[ModelFinding]) -> Severity:
        avg_rank = mean(f.severity.rank for f in findings)
        return Severity.from_rank(avg_rank)

    def _decide_status(
        self,
        findings: list[ModelFinding],
        vote_fraction: float,
        agreement_score: float,
        consensus_confidence: float,
        disagreements: list[PairwiseDisagreement],
    ) -> tuple[ConsensusStatus, bool]:
        cfg = self.config
        max_sev_gap = max((d.severity_gap for d in disagreements), default=0)
        max_conf_gap = max((d.confidence_gap for d in disagreements), default=0.0)
        enough_models = len(findings) >= cfg.min_models_for_auto_decision

        # Hard gate: any excessive pairwise gap forces manual review,
        # regardless of averaged scores.
        if (
            not enough_models
            or max_sev_gap > cfg.max_severity_gap_for_auto
            or max_conf_gap > cfg.max_confidence_gap_for_auto
        ):
            return ConsensusStatus.REQUIRES_MANUAL_REVIEW, (vote_fraction >= 0.5)

        # Unanimous "not vulnerable" with low confidence -> likely FP
        if (
            vote_fraction == 0.0
            and consensus_confidence <= cfg.false_positive_ceiling_confidence
        ):
            return ConsensusStatus.LIKELY_FALSE_POSITIVE, False

        # Unanimous "vulnerable", high confidence -> confirmed
        if (
            vote_fraction >= cfg.min_agreement_for_confirmed
            and consensus_confidence >= cfg.min_mean_confidence_for_confirmed
        ):
            return ConsensusStatus.CONFIRMED, True

        # Majority "vulnerable", decent confidence -> likely, still flagged
        # for a human to confirm before it ships in a report.
        if (
            vote_fraction >= cfg.min_agreement_for_likely
            and consensus_confidence >= cfg.min_mean_confidence_for_likely
        ):
            return ConsensusStatus.LIKELY, True

        # Anything else (split votes, mediocre confidence) -> human decides.
        return ConsensusStatus.REQUIRES_MANUAL_REVIEW, (vote_fraction >= 0.5)

    def _dissenting_models(
        self, findings: list[ModelFinding], consensus_verdict: bool
    ) -> list[str]:
        return [f.model_name for f in findings if f.is_vulnerable != consensus_verdict]

    def _build_summary(
        self,
        status: ConsensusStatus,
        findings: list[ModelFinding],
        vote_fraction: float,
        consensus_confidence: float,
        dissenting: list[str],
    ) -> str:
        models = ", ".join(f"{f.model_name}={f.confidence:.2f}" for f in findings)
        lines = [f"{len(findings)} model(s) analyzed: {models}."]
        lines.append(
            f"{round(vote_fraction * 100)}% voted 'vulnerable', "
            f"blended confidence {consensus_confidence:.2f}."
        )
        if dissenting:
            lines.append(f"Dissenting: {', '.join(dissenting)}.")
        lines.append(f"Status: {status.value}.")
        return " ".join(lines)
