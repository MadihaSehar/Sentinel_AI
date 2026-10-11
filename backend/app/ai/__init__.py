"""
SentinelAI Phase 9 — AI Integration.

Public surface:
    AIAnalysisService   — high-level entrypoint (service.py)
    AIProviderRouter     — fallback-ordered multi-provider router
    AIAnalysisResult     — normalized result shape every provider returns
    ConsensusEngine       — multi-model agreement / verdict reducer (Phase 10)
    ConsensusResult / ConsensusStatus
    GeminiProvider / GrokProvider / DeepSeekProvider / LocalModelProvider
"""
from .consensus.engine import ConsensusEngine, ConsensusResult, ConsensusStatus
from .providers.base import AIAnalysisResult, AIProvider, AIProviderError
from .providers.deepseek_provider import DeepSeekProvider
from .providers.factory import AIProviderRouter, build_provider
from .providers.gemini_provider import GeminiProvider
from .providers.grok_provider import GrokProvider
from .providers.local_provider import LocalModelProvider
from .service import AIAnalysisService
from .settings import AISettings

__all__ = [
    "AIAnalysisResult",
    "AIProvider",
    "AIProviderError",
    "AIProviderRouter",
    "build_provider",
    "AIAnalysisService",
    "AISettings",
    "ConsensusEngine",
    "ConsensusResult",
    "ConsensusStatus",
    "GeminiProvider",
    "GrokProvider",
    "DeepSeekProvider",
    "LocalModelProvider",
]
