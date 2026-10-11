"""
False Positive Engine  (Section 13 of the SentinelAI spec)

Two-stage design:

  Stage 1 -- Deterministic gate (this module, no LLM involved)
      A candidate finding must satisfy a minimum-evidence rule for its
      category (see rules.py) before it is even eligible to be called
      "sufficient evidence". A single suspicious signal (one DB error
      string, one reflected parameter, one differing response) can never
      pass this gate alone.

  Stage 2 -- AI-assisted scoring (this module, consumes ConsensusResult
      from Section 12 if available)
      Once/if a candidate clears the deterministic gate, its Evidence
      Score is blended with the multi-model Consensus confidence to
      produce a final Confidence Score. Evidence quality always caps how
      much the AI's opinion can move the needle -- strong AI confidence
      cannot manufacture evidence that was never collected.

Output: a FalsePositiveAssessment carrying the five scores requested in
the spec: Evidence Score, Confidence Score, Exploitability Score,
Impact Score, Final Risk Score -- plus a human-readable explanation.
"""

from __future__ import annotations

from statistics import mean

from .rules import CategoryProfile, get_profile
from .schemas import (
    EvidenceItem,
    EvidenceType,
    FalsePositiveAssessment,
    FalsePositiveVerdict,
    ScoreBreakdown,
    VulnCategory,
)

# Evidence types that represent a near-direct confirmation (e.g. actual
# script execution, actual command output, actual outbound callback hit)
# rather than an indirect/inferential signal. Presence of these pushes
# exploitability toward the category's upper bound.
_STRONG_CONFIRMATION_TYPES: frozenset[EvidenceType] = frozenset(
    {
        EvidenceType.SCRIPT_EXECUTION_CONFIRMED,
        EvidenceType.OUTBOUND_CALLBACK_RECEIVED,
        EvidenceType.OS_COMMAND_OUTPUT_OBSERVED,
        EvidenceType.FILE_CONTENT_DISCLOSED,
        EvidenceType.STATE_CHANGE_CONFIRMED,
        EvidenceType.TEMPLATE_EXPRESSION_EVALUATED,
        EvidenceType.DESERIALIZATION_GADGET_TRIGGERED,
        EvidenceType.OPEN_REDIRECT_CONFIRMED,
    }
)


class FalsePositiveEngine:
    """
    Evaluate a bundle of EvidenceItems for one candidate finding against
    its category's minimum-evidence rules, optionally blended with a
    multi-model ConsensusResult, to produce a full ScoreBreakdown.
    """

    # Minimal duck-typed protocol so this module does not hard-depend on
    # app.ai.consensus -- callers pass any object exposing these attributes
    # (typically a ConsensusResult from Section 12).
    ConsensusLike = object

    def evaluate(
        self,
        category: VulnCategory,
        evidence: list[EvidenceItem],
        consensus: "FalsePositiveEngine.ConsensusLike | None" = None,
    ) -> FalsePositiveAssessment:
        profile = get_profile(category)
        found_types = {item.type for item in evidence}

        matched_rule, missing = self._match_best_rule(profile, found_types)
        coverage = self._coverage(profile, found_types)

        if matched_rule is not None:
            verdict = FalsePositiveVerdict.SUFFICIENT_EVIDENCE
        elif self._contradicted_by_consensus(consensus):
            verdict = FalsePositiveVerdict.LIKELY_FALSE_POSITIVE
        else:
            verdict = FalsePositiveVerdict.INSUFFICIENT_EVIDENCE

        evidence_score = self._evidence_score(
            matched_rule=matched_rule,
            evidence=evidence,
            found_types=found_types,
            coverage=coverage,
        )
        confidence_score = self._confidence_score(verdict, evidence_score, consensus)
        exploitability_score = self._exploitability_score(
            profile=profile, matched_rule=matched_rule, found_types=found_types, coverage=coverage
        )
        impact_score = self._impact_score(profile=profile, found_types=found_types, matched=matched_rule is not None)
        final_risk_score = self._final_risk_score(
            verdict, confidence_score, evidence_score, exploitability_score, impact_score
        )

        scores = ScoreBreakdown(
            evidence_score=round(evidence_score, 4),
            confidence_score=round(confidence_score, 4),
            exploitability_score=round(exploitability_score, 4),
            impact_score=round(impact_score, 4),
            final_risk_score=round(final_risk_score, 4),
        )

        return FalsePositiveAssessment(
            category=category,
            verdict=verdict,
            matched_rule=self._rule_name(matched_rule) if matched_rule else None,
            missing_evidence=sorted(missing, key=lambda e: e.value) if missing else [],
            evidence=evidence,
            scores=scores,
            explanation=self._explain(category, verdict, matched_rule, missing, scores, evidence),
        )

    # ------------------------------------------------------------------ #
    # Stage 1: deterministic rule matching
    # ------------------------------------------------------------------ #

    def _match_best_rule(
        self, profile: CategoryProfile, found_types: set[EvidenceType]
    ) -> tuple[frozenset[EvidenceType] | None, set[EvidenceType]]:
        """
        Return (matched_rule, missing) where matched_rule is the first
        fully-satisfied AND-set, or None. When nothing is fully satisfied,
        `missing` holds the gap for the *closest* rule (highest coverage,
        then smallest rule) so callers/report authors know what else is
        needed to confirm the finding.
        """
        best_missing: set[EvidenceType] = set()
        best_coverage = -1.0

        for rule in profile.rules:
            if rule.issubset(found_types):
                return rule, set()
            matched = rule & found_types
            cov = len(matched) / len(rule)
            if cov > best_coverage or (cov == best_coverage and len(rule) < len(best_missing) + len(matched)):
                best_coverage = cov
                best_missing = rule - found_types

        return None, best_missing

    def _coverage(self, profile: CategoryProfile, found_types: set[EvidenceType]) -> float:
        """Best coverage fraction across all rules (0 if no evidence at all)."""
        if not found_types:
            return 0.0
        best = 0.0
        for rule in profile.rules:
            cov = len(rule & found_types) / len(rule)
            best = max(best, cov)
        return best

    def _contradicted_by_consensus(self, consensus: "FalsePositiveEngine.ConsensusLike | None") -> bool:
        if consensus is None:
            return False
        is_vulnerable = getattr(consensus, "is_vulnerable_consensus", None)
        confidence = getattr(consensus, "consensus_confidence", 0.0)
        return is_vulnerable is False and confidence >= 0.6

    @staticmethod
    def _rule_name(rule: frozenset[EvidenceType]) -> str:
        return "+".join(sorted(t.value for t in rule))

    # ------------------------------------------------------------------ #
    # Stage 2: scoring
    # ------------------------------------------------------------------ #

    def _evidence_score(
        self,
        matched_rule: frozenset[EvidenceType] | None,
        evidence: list[EvidenceItem],
        found_types: set[EvidenceType],
        coverage: float,
    ) -> float:
        if not evidence:
            return 0.0

        strength_by_type = {}
        for item in evidence:
            # If a type appears multiple times, keep the strongest observation.
            strength_by_type[item.type] = max(strength_by_type.get(item.type, 0.0), item.strength)

        if matched_rule is not None:
            core_strengths = [strength_by_type[t] for t in matched_rule if t in strength_by_type]
            core = mean(core_strengths) if core_strengths else 0.0
            extra_corroborating = len(found_types - matched_rule)
            bonus = min(0.15, 0.03 * extra_corroborating)
            return min(1.0, core * 0.85 + bonus)

        # Below threshold: evidence exists but doesn't clear the bar.
        # Scaled down hard so this can never masquerade as "sufficient".
        present_strengths = [s for s in strength_by_type.values()]
        avg_strength = mean(present_strengths) if present_strengths else 0.0
        return min(0.45, coverage * avg_strength)

    def _confidence_score(
        self,
        verdict: FalsePositiveVerdict,
        evidence_score: float,
        consensus: "FalsePositiveEngine.ConsensusLike | None",
    ) -> float:
        if verdict != FalsePositiveVerdict.SUFFICIENT_EVIDENCE:
            # Evidence didn't clear the deterministic gate -- AI opinion
            # alone cannot push confidence into "actionable" territory.
            ai_component = getattr(consensus, "consensus_confidence", 0.0) if consensus else 0.0
            return min(0.35, max(evidence_score, ai_component * 0.3))

        if consensus is None:
            return evidence_score

        ai_confidence = getattr(consensus, "consensus_confidence", evidence_score)
        ai_agrees = getattr(consensus, "is_vulnerable_consensus", True)
        if not ai_agrees:
            # Deterministic evidence says yes, AI consensus says no --
            # don't silently average; pull down hard and let this surface
            # for manual review via a middling score rather than a
            # falsely confident one.
            return min(evidence_score, 0.4)

        return round(0.55 * evidence_score + 0.45 * ai_confidence, 4)

    def _exploitability_score(
        self,
        profile: CategoryProfile,
        matched_rule: frozenset[EvidenceType] | None,
        found_types: set[EvidenceType],
        coverage: float,
    ) -> float:
        if matched_rule is None:
            return round(profile.base_exploitability * coverage * 0.5, 4)

        has_strong_confirmation = bool(found_types & _STRONG_CONFIRMATION_TYPES)
        score = profile.base_exploitability
        if has_strong_confirmation:
            score = min(1.0, score + 0.15)
        return round(score, 4)

    def _impact_score(
        self, profile: CategoryProfile, found_types: set[EvidenceType], matched: bool
    ) -> float:
        base = profile.base_impact if matched else profile.base_impact * 0.5
        if EvidenceType.SENSITIVE_DATA_IN_RESPONSE in found_types:
            base = min(1.0, base + 0.05)
        return round(base, 4)

    def _final_risk_score(
        self,
        verdict: FalsePositiveVerdict,
        confidence_score: float,
        evidence_score: float,
        exploitability_score: float,
        impact_score: float,
    ) -> float:
        raw = (
            0.30 * confidence_score
            + 0.25 * evidence_score
            + 0.20 * exploitability_score
            + 0.25 * impact_score
        )
        if verdict == FalsePositiveVerdict.LIKELY_FALSE_POSITIVE:
            return min(raw, 0.15)
        if verdict == FalsePositiveVerdict.INSUFFICIENT_EVIDENCE:
            return min(raw, 0.35)
        return min(1.0, raw)

    # ------------------------------------------------------------------ #
    # Explanation
    # ------------------------------------------------------------------ #

    def _explain(
        self,
        category: VulnCategory,
        verdict: FalsePositiveVerdict,
        matched_rule: frozenset[EvidenceType] | None,
        missing: set[EvidenceType],
        scores: ScoreBreakdown,
        evidence: list[EvidenceItem],
    ) -> str:
        parts = [f"Category: {category.value}.", f"{len(evidence)} evidence item(s) collected."]
        if verdict == FalsePositiveVerdict.SUFFICIENT_EVIDENCE:
            parts.append(
                f"Minimum-evidence rule satisfied ({self._rule_name(matched_rule)}); "
                f"eligible for AI/consensus review."
            )
        elif verdict == FalsePositiveVerdict.LIKELY_FALSE_POSITIVE:
            parts.append(
                "Evidence did not meet the minimum bar and multi-model consensus "
                "independently assessed this as not vulnerable."
            )
        else:
            missing_str = ", ".join(sorted(e.value for e in missing)) or "additional evidence"
            parts.append(f"Insufficient evidence; closest gap requires: {missing_str}.")
        parts.append(
            f"Scores -- evidence: {scores.evidence_score:.2f}, confidence: {scores.confidence_score:.2f}, "
            f"exploitability: {scores.exploitability_score:.2f}, impact: {scores.impact_score:.2f}, "
            f"final risk: {scores.final_risk_score:.2f}."
        )
        return " ".join(parts)
