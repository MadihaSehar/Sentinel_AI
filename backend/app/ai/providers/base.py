"""
AI Provider abstraction layer for SentinelAI (Phase 9).

Every LLM backend (Gemini, Grok, DeepSeek, local models) implements this
interface. The orchestrator and vulnerability analyzers depend only on
`AIProvider`, never on a concrete vendor SDK, so new providers can be
added without touching call sites (section 4 of the master prompt).
"""
from __future__ import annotations

import abc
import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional


class AIProviderError(Exception):
    """Base exception for all AI provider failures."""


class AIProviderTimeoutError(AIProviderError):
    """Raised when a provider call exceeds its configured timeout."""


class AIProviderRateLimitError(AIProviderError):
    """Raised when a provider reports a rate limit / quota error."""


class AIProviderAuthError(AIProviderError):
    """Raised when a provider rejects credentials."""


class AIProviderResponseError(AIProviderError):
    """Raised when a provider returns a response we cannot parse."""


@dataclass
class AIUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: int = 0
    estimated_cost_usd: float = 0.0


@dataclass
class AIAnalysisResult:
    """
    Normalized output of a single provider's analyze() call.

    This is the ONLY shape that flows out of this module. Vendor-specific
    response formats are parsed and discarded inside each provider;
    nothing vendor-shaped leaks upward to the orchestrator or the
    Phase 10 consensus engine. Mirrors the schema in section 11 of the
    master prompt.
    """

    provider: str
    model: str
    finding: Optional[str]
    severity: Optional[str]  # "critical" | "high" | "medium" | "low" | "info" | None
    confidence: float  # 0.0 - 1.0
    reasoning_summary: str
    evidence: list[str] = field(default_factory=list)
    raw_json: dict[str, Any] = field(default_factory=dict)
    usage: AIUsage = field(default_factory=AIUsage)
    success: bool = True
    error: Optional[str] = None


class AIProvider(abc.ABC):
    """
    Abstract base for every AI backend used by SentinelAI.

    Implementations MUST:
      - never raise a raw SDK/HTTP exception out of `analyze()`; wrap it
        in one of the AIProviderError subclasses above inside `_call()`
        so the fallback router (section 28) can react uniformly.
      - enforce `timeout_seconds` themselves (via the HTTP client's own
        timeout), not rely on the caller.
      - return AIAnalysisResult, never a raw dict, from `analyze()`.
      - never log API keys or full prompts containing secrets.
    """

    name: str = "base"
    default_model: str = ""

    def __init__(
        self,
        api_key: str,
        model: Optional[str] = None,
        timeout_seconds: float = 30.0,
        max_output_tokens: int = 1024,
    ) -> None:
        if not api_key:
            raise AIProviderAuthError(f"{self.name}: missing API key")
        self._api_key = api_key
        self.model = model or self.default_model
        self.timeout_seconds = timeout_seconds
        self.max_output_tokens = max_output_tokens

    @abc.abstractmethod
    async def _call(
        self, system_prompt: str, user_prompt: str
    ) -> tuple[dict[str, Any], AIUsage]:
        """
        Perform the actual vendor HTTP call and return
        (parsed_json_response, usage). Must raise an AIProviderError
        subclass on any failure. Transport only — no business logic.
        """
        raise NotImplementedError

    async def analyze(self, prompt: str, context: dict[str, Any]) -> AIAnalysisResult:
        """
        Public entrypoint used by the orchestrator (section 4/10 of the
        master prompt: `AIProvider.analyze(prompt, context)`).

        `context` must already be pre-built, trimmed structured evidence
        — never raw, unbounded scan output. Trimming/dedup is the cost
        control layer's job (section 29), not this method's.
        """
        system_prompt = self._build_system_prompt()
        user_prompt = self._render_user_prompt(prompt, context)

        start = time.monotonic()
        try:
            raw_json, usage = await self._call(system_prompt, user_prompt)
        except AIProviderError as exc:
            return AIAnalysisResult(
                provider=self.name,
                model=self.model,
                finding=None,
                severity=None,
                confidence=0.0,
                reasoning_summary="",
                success=False,
                error=str(exc),
            )
        usage.latency_ms = usage.latency_ms or int((time.monotonic() - start) * 1000)

        try:
            return self._parse_result(raw_json, usage)
        except AIProviderResponseError as exc:
            return AIAnalysisResult(
                provider=self.name,
                model=self.model,
                finding=None,
                severity=None,
                confidence=0.0,
                reasoning_summary="",
                success=False,
                error=str(exc),
            )

    def _build_system_prompt(self) -> str:
        return (
            "You are a security analysis engine inside an authorized "
            "penetration testing platform. You only ever reason over the "
            "structured evidence you are given. You never invent "
            "evidence, never claim a finding without supporting evidence, "
            "and never suggest unauthorized or out-of-scope actions. "
            "Respond with STRICT JSON ONLY: no markdown fences, no "
            "preamble, matching exactly this schema: "
            '{"finding": string|null, "severity": "critical"|"high"|'
            '"medium"|"low"|"info"|null, "confidence": number (0-1), '
            '"reasoning_summary": string, "evidence": [string, ...]}'
        )

    def _render_user_prompt(self, prompt: str, context: dict[str, Any]) -> str:
        # Cap the serialized evidence so a single call can't blow the
        # token budget (section 29: cost control).
        evidence_json = json.dumps(context, default=str)[:12000]
        return f"{prompt}\n\n--- STRUCTURED EVIDENCE (JSON) ---\n{evidence_json}"

    def _parse_result(self, raw_json: dict[str, Any], usage: AIUsage) -> AIAnalysisResult:
        try:
            confidence = float(raw_json.get("confidence", 0.0))
        except (TypeError, ValueError) as exc:
            raise AIProviderResponseError(
                f"{self.name}: malformed 'confidence' field: {exc}"
            ) from exc

        return AIAnalysisResult(
            provider=self.name,
            model=self.model,
            finding=raw_json.get("finding"),
            severity=raw_json.get("severity"),
            confidence=max(0.0, min(1.0, confidence)),
            reasoning_summary=str(raw_json.get("reasoning_summary", "")),
            evidence=list(raw_json.get("evidence", []) or []),
            raw_json=raw_json,
            usage=usage,
            success=True,
        )
