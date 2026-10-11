"""
Google Gemini provider.

Uses the Generative Language API (v1beta) `generateContent` endpoint
directly over HTTP so this module has no hard dependency on Google's SDK.
"""
from __future__ import annotations

import json
import re
from typing import Any

import httpx

from .base import (
    AIProvider,
    AIProviderAuthError,
    AIProviderRateLimitError,
    AIProviderResponseError,
    AIProviderTimeoutError,
    AIUsage,
)

_JSON_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def _strip_fences(text: str) -> str:
    return _JSON_FENCE_RE.sub("", text).strip()


class GeminiProvider(AIProvider):
    name = "gemini"
    default_model = "gemini-2.0-flash"

    BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"

    async def _call(
        self, system_prompt: str, user_prompt: str
    ) -> tuple[dict[str, Any], AIUsage]:
        url = f"{self.BASE_URL}/{self.model}:generateContent?key={self._api_key}"
        payload = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {
                "temperature": 0.1,
                "maxOutputTokens": self.max_output_tokens,
                "responseMimeType": "application/json",
            },
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = await client.post(url, json=payload)
        except httpx.TimeoutException as exc:
            raise AIProviderTimeoutError(f"gemini: request timed out: {exc}") from exc
        except httpx.HTTPError as exc:
            raise AIProviderResponseError(f"gemini: transport error: {exc}") from exc

        if resp.status_code in (401, 403):
            raise AIProviderAuthError(f"gemini: auth rejected ({resp.status_code})")
        if resp.status_code == 429:
            raise AIProviderRateLimitError("gemini: rate limited")
        if resp.status_code >= 400:
            raise AIProviderResponseError(
                f"gemini: HTTP {resp.status_code}: {resp.text[:300]}"
            )

        try:
            body = resp.json()
        except ValueError as exc:
            raise AIProviderResponseError(f"gemini: non-JSON HTTP body: {exc}") from exc

        try:
            text = body["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, TypeError) as exc:
            # A blocked / empty response (e.g. safety filtering) lands here too.
            raise AIProviderResponseError(
                f"gemini: unexpected response shape: {exc}"
            ) from exc

        usage_meta = body.get("usageMetadata", {}) or {}
        usage = AIUsage(
            prompt_tokens=usage_meta.get("promptTokenCount", 0),
            completion_tokens=usage_meta.get("candidatesTokenCount", 0),
            total_tokens=usage_meta.get("totalTokenCount", 0),
        )

        try:
            parsed = json.loads(_strip_fences(text))
        except json.JSONDecodeError as exc:
            raise AIProviderResponseError(f"gemini: non-JSON content: {exc}") from exc

        return parsed, usage
