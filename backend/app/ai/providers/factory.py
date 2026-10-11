"""
Provider factory + fallback router.

Implements section 28 of the master prompt ("Model Failure Handling"):
AI must enhance the platform, never become a single point of failure.
`AIProviderRouter.analyze()` tries providers in a configured order and
returns the first successful result. If every provider fails, it
returns a clearly-marked failed AIAnalysisResult rather than raising, so
the deterministic scanner pipeline can continue regardless.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Optional

from .base import AIAnalysisResult, AIProvider
from .deepseek_provider import DeepSeekProvider
from .gemini_provider import GeminiProvider
from .grok_provider import GrokProvider
from .local_provider import LocalModelProvider

if TYPE_CHECKING:
    from ..settings import AISettings

logger = logging.getLogger("sentinel.ai.providers")

_REGISTRY: dict[str, type[AIProvider]] = {
    "gemini": GeminiProvider,
    "grok": GrokProvider,
    "deepseek": DeepSeekProvider,
    "local": LocalModelProvider,
}


def build_provider(
    name: str, *, api_key: str, model: Optional[str] = None, **kwargs: Any
) -> AIProvider:
    try:
        cls = _REGISTRY[name]
    except KeyError as exc:
        raise ValueError(f"Unknown AI provider '{name}'. Known providers: {list(_REGISTRY)}") from exc
    return cls(api_key=api_key, model=model, **kwargs)


class AIProviderRouter:
    """
    Wraps an ordered list of providers and applies cloud -> cloud -> local
    fallback. `analyze()` returns the first success for callers that just
    need *an* answer; `analyze_all()` runs every provider independently,
    which is what Phase 10's consensus engine will consume.
    """

    def __init__(self, providers: list[AIProvider]) -> None:
        if not providers:
            raise ValueError("AIProviderRouter requires at least one configured provider")
        self._providers = providers

    @classmethod
    def from_settings(cls, settings: "AISettings") -> "AIProviderRouter":
        providers: list[AIProvider] = []
        if settings.gemini_api_key:
            providers.append(
                build_provider(
                    "gemini",
                    api_key=settings.gemini_api_key,
                    model=settings.gemini_model,
                    timeout_seconds=settings.ai_timeout_seconds,
                    max_output_tokens=settings.ai_max_output_tokens,
                )
            )
        if settings.xai_api_key:
            providers.append(
                build_provider(
                    "grok",
                    api_key=settings.xai_api_key,
                    model=settings.grok_model,
                    timeout_seconds=settings.ai_timeout_seconds,
                    max_output_tokens=settings.ai_max_output_tokens,
                )
            )
        if settings.deepseek_api_key:
            providers.append(
                build_provider(
                    "deepseek",
                    api_key=settings.deepseek_api_key,
                    model=settings.deepseek_model,
                    timeout_seconds=settings.ai_timeout_seconds,
                    max_output_tokens=settings.ai_max_output_tokens,
                )
            )
        if settings.local_model_base_url:
            providers.append(
                build_provider(
                    "local",
                    api_key=settings.local_model_api_key or "local",
                    model=settings.local_model_name,
                    timeout_seconds=settings.ai_timeout_seconds,
                    max_output_tokens=settings.ai_max_output_tokens,
                    base_url=settings.local_model_base_url,
                )
            )
        return cls(providers)

    async def analyze(self, prompt: str, context: dict[str, Any]) -> AIAnalysisResult:
        """Return the first successful result, trying providers in configured order."""
        last_result: Optional[AIAnalysisResult] = None
        for provider in self._providers:
            result = await provider.analyze(prompt, context)
            if result.success:
                return result
            logger.warning(
                "ai_provider_failed",
                extra={"provider": provider.name, "error": result.error},
            )
            last_result = result
        assert last_result is not None
        return last_result

    async def analyze_all(self, prompt: str, context: dict[str, Any]) -> list[AIAnalysisResult]:
        """Run every configured provider independently (feeds Phase 10 consensus)."""
        results: list[AIAnalysisResult] = []
        for provider in self._providers:
            results.append(await provider.analyze(prompt, context))
        return results

    @property
    def provider_names(self) -> list[str]:
        return [p.name for p in self._providers]
