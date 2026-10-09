"""
Shared parsing helpers for OpenAI-compatible chat completion responses.

Grok (xAI), DeepSeek, and most local inference servers (Ollama's /v1
endpoint, vLLM, LM Studio, text-generation-webui) all speak the same
`/chat/completions` response shape, so this module factors out the one
bit of parsing logic they share. It is intentionally private (`_` prefix)
— only providers in this package should import it.
"""
from __future__ import annotations

import json
import re
from typing import Any

from .base import AIProviderResponseError, AIUsage

_JSON_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def strip_fences(text: str) -> str:
    """Defensively strip markdown code fences some models add despite instructions."""
    return _JSON_FENCE_RE.sub("", text).strip()


def parse_openai_style_response(
    body: dict[str, Any], provider_name: str
) -> tuple[dict[str, Any], AIUsage]:
    try:
        text = body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise AIProviderResponseError(
            f"{provider_name}: unexpected response shape: {exc}"
        ) from exc

    usage_raw = body.get("usage", {}) or {}
    usage = AIUsage(
        prompt_tokens=usage_raw.get("prompt_tokens", 0),
        completion_tokens=usage_raw.get("completion_tokens", 0),
        total_tokens=usage_raw.get("total_tokens", 0),
    )

    try:
        parsed = json.loads(strip_fences(text))
    except json.JSONDecodeError as exc:
        raise AIProviderResponseError(
            f"{provider_name}: model did not return valid JSON: {exc}"
        ) from exc

    return parsed, usage
