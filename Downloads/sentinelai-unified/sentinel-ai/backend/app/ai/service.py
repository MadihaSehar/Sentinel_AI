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

from .consensus.engine import ConsensusEngine, ConsensusResult
from .prompt_loader import load_prompt
from .providers.base import AIAnalysisResult
from .providers.factory import AIProviderRouter
from .settings import AISettings


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
        return engine.evaluate(results)

    @property
    def active_providers(self) -> list[str]:
        return self._router.provider_names
