"""
Integration test for AIAnalysisService.analyze_with_consensus() — verifies
Phase 9's router and Phase 10's consensus engine are correctly wired
together through the service layer, using fake providers (no real HTTP).
"""
from __future__ import annotations

import pytest

from app.ai.consensus.engine import ConsensusStatus
from app.ai.providers.base import AIAnalysisResult, AIProvider, AIUsage
from app.ai.providers.factory import AIProviderRouter
from app.ai.service import AIAnalysisService


class _ScriptedProvider(AIProvider):
    def __init__(self, name: str, finding: str | None, severity: str | None, confidence: float):
        self.name = name
        self.model = f"{name}-model"
        self._finding = finding
        self._severity = severity
        self._confidence = confidence

    async def _call(self, system_prompt, user_prompt):  # pragma: no cover - unused
        raise NotImplementedError

    async def analyze(self, prompt, context):
        return AIAnalysisResult(
            provider=self.name,
            model=self.model,
            finding=self._finding,
            severity=self._severity,
            confidence=self._confidence,
            reasoning_summary=f"{self.name} says so",
            evidence=[f"{self.name}-evidence"],
            usage=AIUsage(),
            success=True,
        )


@pytest.mark.asyncio
async def test_analyze_with_consensus_confirms_on_agreement():
    router = AIProviderRouter(
        [
            _ScriptedProvider("gemini", "SQLi indicator", "high", 0.9),
            _ScriptedProvider("grok", "SQLi indicator", "high", 0.85),
        ]
    )
    service = AIAnalysisService(router)

    consensus = await service.analyze_with_consensus("sqli_analysis", {"param": "id"})

    assert consensus.status == ConsensusStatus.CONFIRMED
    assert consensus.severity == "high"
    assert set(consensus.evidence) == {"gemini-evidence", "grok-evidence"}


@pytest.mark.asyncio
async def test_analyze_with_consensus_flags_disagreement():
    router = AIProviderRouter(
        [
            _ScriptedProvider("gemini", "SQLi indicator", "high", 0.9),
            _ScriptedProvider("grok", None, None, 0.1),
        ]
    )
    service = AIAnalysisService(router)

    consensus = await service.analyze_with_consensus("sqli_analysis", {"param": "id"})

    assert consensus.status == ConsensusStatus.REQUIRES_MANUAL_REVIEW
