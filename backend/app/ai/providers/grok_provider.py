"""
xAI Grok provider. Uses the OpenAI-compatible `/v1/chat/completions` endpoint.
"""
from __future__ import annotations

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
from ._openai_compat import parse_openai_style_response


class GrokProvider(AIProvider):
    name = "grok"
    default_model = "grok-2-latest"

    BASE_URL = "https://api.x.ai/v1/chat/completions"

    async def _call(
        self, system_prompt: str, user_prompt: str
    ) -> tuple[dict[str, Any], AIUsage]:
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "temperature": 0.1,
            "max_tokens": self.max_output_tokens,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = await client.post(self.BASE_URL, headers=headers, json=payload)
        except httpx.TimeoutException as exc:
            raise AIProviderTimeoutError(f"grok: request timed out: {exc}") from exc
        except httpx.HTTPError as exc:
            raise AIProviderResponseError(f"grok: transport error: {exc}") from exc

        if resp.status_code in (401, 403):
            raise AIProviderAuthError(f"grok: auth rejected ({resp.status_code})")
        if resp.status_code == 429:
            raise AIProviderRateLimitError("grok: rate limited")
        if resp.status_code >= 400:
            raise AIProviderResponseError(f"grok: HTTP {resp.status_code}: {resp.text[:300]}")

        try:
            body = resp.json()
        except ValueError as exc:
            raise AIProviderResponseError(f"grok: non-JSON HTTP body: {exc}") from exc

        return parse_openai_style_response(body, provider_name="grok")
