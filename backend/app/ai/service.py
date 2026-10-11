"""
High-level AI analysis service — the entrypoint vulnerability analyzers
and the orchestrator (Phase 10+) should import. Wraps prompt loading +
provider routing/fallback behind two calls: `analyze()` for "give me one
answer" and `analyze_multi()` for "give me every provider's independent
opinion" (the latter feeds the Phase 10 consensus engine).

This is intentionally the ONLY module outside `providers/` that other
parts of the codebase should need to import from Phase 9.
"""
from __future__ import annotations

from typing import Any, Optional

from .consensus.engine import ConsensusEngine
from .consensus.schemas import (
    ConsensusResult,
    ConsensusStatus,
    ModelFinding,
    Severity,
)
from .prompt_loader import load_prompt
from .providers.base import AIAnalysisResult
from .providers.factory import AIProviderRouter
from .settings import AISettings


def _severity_from_str(value: Optional[str]) -> Severity:
    """Map a provider's free-form severity string to the Severity enum.

    Unknown or missing severities fall back to INFO, which is the safe,
    non-alarming default for a result that carries no real signal.
    """
    if not value:
        return Severity.INFO
    try:
        return Severity(value.strip().lower())
    except ValueError:
        return Severity.INFO


def _to_model_finding(result: AIAnalysisResult) -> ModelFinding:
    """Normalize a single provider's result into the consensus engine's
    ModelFinding shape. A result with no (or empty) ``finding`` is treated
    as a "not vulnerable" vote."""
    has_finding = bool(result.finding and result.finding.strip())
    return ModelFinding(
        model_name=result.provider,
        finding=result.finding if has_finding else "No vulnerability indicated",
        is_vulnerable=has_finding,
        severity=_severity_from_str(result.severity),
        confidence=max(0.0, min(1.0, result.confidence)),
        reasoning_summary=result.reasoning_summary or "",
        evidence=list(result.evidence),
    )


class AIAnalysisService:
    def __init__(self, router: AIProviderRouter) -> None:
        self._router = router

    @classmethod
    def from_env(cls) -> "AIAnalysisService":
        """Build the service from environment variables / `.env` (section 31)."""
        return cls(AIProviderRouter.from_settings(AISettings()))

    async def analyze(self, prompt_name: str, context: dict[str, Any]) -> AIAnalysisResult:
        """
        Run a single named prompt (e.g. "sqli_analysis") against
        structured evidence, using the first provider in the fallback
        chain that succeeds (section 28).
        """
        prompt_text = load_prompt(prompt_name)
        return await self._router.analyze(prompt_text, context)

    async def analyze_multi(
        self, prompt_name: str, context: dict[str, Any]
    ) -> list[AIAnalysisResult]:
        """
        Run a named prompt against every configured provider
        independently. Feeds Phase 10's consensus engine (section 12).
        """
        prompt_text = load_prompt(prompt_name)
        return await self._router.analyze_all(prompt_text, context)

    async def analyze_with_consensus(
        self,
        prompt_name: str,
        context: dict[str, Any],
        engine: Optional[ConsensusEngine] = None,
    ) -> ConsensusResult:
        """
        Run a named prompt against every configured provider (Phase 9) and
        reduce their independent results to one verdict (Phase 10). This is
        what the orchestrator should call for anything that will become a
        `findings` row — never `analyze()` alone, which only reflects a
        single model's opinion.
        """
        results = await self.analyze_multi(prompt_name, context)
        engine = engine or ConsensusEngine()

        # Only successful provider calls participate in consensus scoring;
        # failed/timed-out providers are excluded rather than counted as a
        # "not vulnerable" vote (which would skew the result).
        successful = [r for r in results if r.success]
        findings = [_to_model_finding(r) for r in successful]

        if not findings:
            # Every provider failed — there is nothing to reason over.
            return ConsensusResult(
                status=ConsensusStatus.REQUIRES_MANUAL_REVIEW,
                is_vulnerable_consensus=False,
                severity=Severity.INFO,
                consensus_confidence=0.0,
                agreement_score=0.0,
                participating_models=[],
                model_findings=[],
                evidence=[],
                summary="No AI provider returned a successful result; manual review required.",
            )

        return engine.analyze(findings)

    @property
    def active_providers(self) -> list[str]:
        return self._router.provider_names
