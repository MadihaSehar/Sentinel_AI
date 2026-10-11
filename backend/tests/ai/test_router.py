"""
Unit tests for AIProviderRouter fallback behavior (section 28 of the
master prompt, "Model Failure Handling"): if a higher-priority provider
fails, the router must move on to the next one, and only report failure
if every provider fails.
"""
from __future__ import annotations

import pytest

from app.ai.providers.base import AIAnalysisResult, AIProvider, AIUsage
from app.ai.providers.factory import AIProviderRouter


class _FakeProvider(AIProvider):
    """Test double — skips real HTTP, returns a scripted result."""

    def __init__(self, name: str, succeed: bool):
        # Deliberately bypass AIProvider.__init__ (no real API key needed).
        self.name = name
        self.model = "fake-model"
        self._succeed = succeed
        self.calls = 0

    async def _call(self, system_prompt, user_prompt):  # pragma: no cover - unused
        raise NotImplementedError

    async def analyze(self, prompt, context):
        self.calls += 1
        if self._succeed:
            return AIAnalysisResult(
                provider=self.name,
                model=self.model,
                finding="fake finding",
                severity="low",
                confidence=0.5,
                reasoning_summary="fake",
                usage=AIUsage(),
                success=True,
            )
        return AIAnalysisResult(
            provider=self.name,
            model=self.model,
            finding=None,
            severity=None,
            confidence=0.0,
            reasoning_summary="",
            success=False,
            error="simulated failure",
        )


@pytest.mark.asyncio
async def test_router_falls_back_to_next_provider_on_failure():
    gemini = _FakeProvider("gemini", succeed=False)
    grok = _FakeProvider("grok", succeed=True)
    router = AIProviderRouter([gemini, grok])

    result = await router.analyze("prompt", {})

    assert result.success is True
    assert result.provider == "grok"
    assert gemini.calls == 1
    assert grok.calls == 1


@pytest.mark.asyncio
async def test_router_reports_failure_when_all_providers_fail():
    gemini = _FakeProvider("gemini", succeed=False)
    grok = _FakeProvider("grok", succeed=False)
    deepseek = _FakeProvider("deepseek", succeed=False)
    router = AIProviderRouter([gemini, grok, deepseek])

    result = await router.analyze("prompt", {})

    assert result.success is False
    assert gemini.calls == grok.calls == deepseek.calls == 1


@pytest.mark.asyncio
async def test_router_does_not_call_providers_after_first_success():
    first = _FakeProvider("first", succeed=True)
    second = _FakeProvider("second", succeed=True)
    router = AIProviderRouter([first, second])

    result = await router.analyze("prompt", {})

    assert result.provider == "first"
    assert first.calls == 1
    assert second.calls == 0


@pytest.mark.asyncio
async def test_router_analyze_all_runs_every_provider_independently():
    a = _FakeProvider("a", succeed=True)
    b = _FakeProvider("b", succeed=False)
    router = AIProviderRouter([a, b])

    results = await router.analyze_all("prompt", {})

    assert len(results) == 2
    assert {r.provider for r in results} == {"a", "b"}
    assert a.calls == 1 and b.calls == 1


def test_router_requires_at_least_one_provider():
    with pytest.raises(ValueError):
        AIProviderRouter([])


def test_router_from_settings_only_builds_configured_providers():
    from app.ai.settings import AISettings

    settings = AISettings(
        gemini_api_key="g-key",
        xai_api_key="",
        deepseek_api_key="d-key",
        local_model_base_url="",
    )
    router = AIProviderRouter.from_settings(settings)

    assert router.provider_names == ["gemini", "deepseek"]
