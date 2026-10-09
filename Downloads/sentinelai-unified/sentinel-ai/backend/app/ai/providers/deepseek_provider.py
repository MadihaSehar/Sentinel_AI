"""
DeepSeek provider. Uses the OpenAI-compatible `/chat/completions` endpoint.
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


class DeepSeekProvider(AIProvider):
    name = "deepseek"
    default_model = "deepseek-chat"

    BASE_URL = "https://api.deepseek.com/chat/completions"

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
            raise AIProviderTimeoutError(f"deepseek: request timed out: {exc}") from exc
        except httpx.HTTPError as exc:
            raise AIProviderResponseError(f"deepseek: transport error: {exc}") from exc

        if resp.status_code in (401, 403):
            raise AIProviderAuthError(f"deepseek: auth rejected ({resp.status_code})")
        if resp.status_code == 429:
            raise AIProviderRateLimitError("deepseek: rate limited")
        if resp.status_code >= 400:
            raise AIProviderResponseError(
                f"deepseek: HTTP {resp.status_code}: {resp.text[:300]}"
            )

        try:
            body = resp.json()
        except ValueError as exc:
            raise AIProviderResponseError(f"deepseek: non-JSON HTTP body: {exc}") from exc

        return parse_openai_style_response(body, provider_name="deepseek")
