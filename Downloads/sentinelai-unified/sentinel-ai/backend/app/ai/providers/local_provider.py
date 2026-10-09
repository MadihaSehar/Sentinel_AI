"""
Local model provider — talks to any OpenAI-compatible local inference
server (Ollama's /v1 endpoint, vLLM, LM Studio, text-generation-webui).

This is the final link in the fallback chain described in section 28 of
the master prompt: if every cloud provider fails, deterministic scanning
continues regardless, and where a local model is configured, AI-assisted
analysis can keep running without any internet-facing API call at all.
"""
from __future__ import annotations

from typing import Any, Optional

import httpx

from .base import AIProvider, AIProviderResponseError, AIProviderTimeoutError, AIUsage
from ._openai_compat import parse_openai_style_response


class LocalModelProvider(AIProvider):
    name = "local"
    default_model = "llama3.1"
    DEFAULT_BASE_URL = "http://localhost:11434/v1/chat/completions"

    def __init__(
        self,
        api_key: str = "local",
        model: Optional[str] = None,
        timeout_seconds: float = 60.0,
        max_output_tokens: int = 1024,
        base_url: Optional[str] = None,
    ) -> None:
        # Local servers usually don't require a real credential; default
        # to a placeholder so the base class's "missing key" guard still
        # passes rather than forcing callers to invent a fake secret.
        super().__init__(api_key or "local", model, timeout_seconds, max_output_tokens)
        self.base_url = base_url or self.DEFAULT_BASE_URL

    async def _call(
        self, system_prompt: str, user_prompt: str
    ) -> tuple[dict[str, Any], AIUsage]:
        headers = {"Content-Type": "application/json"}
        if self._api_key and self._api_key != "local":
            headers["Authorization"] = f"Bearer {self._api_key}"

        payload = {
            "model": self.model,
            "temperature": 0.1,
            "max_tokens": self.max_output_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = await client.post(self.base_url, headers=headers, json=payload)
        except httpx.TimeoutException as exc:
            raise AIProviderTimeoutError(f"local: request timed out: {exc}") from exc
        except httpx.HTTPError as exc:
            raise AIProviderResponseError(
                f"local: transport error: {exc} "
                f"(is a local inference server running at {self.base_url}?)"
            ) from exc

        if resp.status_code >= 400:
            raise AIProviderResponseError(f"local: HTTP {resp.status_code}: {resp.text[:300]}")

        try:
            body = resp.json()
        except ValueError as exc:
            raise AIProviderResponseError(f"local: non-JSON HTTP body: {exc}") from exc

        return parse_openai_style_response(body, provider_name="local")
