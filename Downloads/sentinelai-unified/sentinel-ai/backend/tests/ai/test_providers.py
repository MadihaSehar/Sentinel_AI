"""
Unit tests for individual AI providers. All HTTP calls are mocked — no
real network access or API keys needed to run these.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.ai.providers.deepseek_provider import DeepSeekProvider
from app.ai.providers.gemini_provider import GeminiProvider
from app.ai.providers.grok_provider import GrokProvider
from app.ai.providers.local_provider import LocalModelProvider


def _mock_response(status_code: int, json_body: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body
    resp.text = json.dumps(json_body)
    return resp


def _patched_client(response: MagicMock):
    client = AsyncMock()
    client.post = AsyncMock(return_value=response)
    client.__aenter__.return_value = client
    client.__aexit__.return_value = False
    return patch("httpx.AsyncClient", return_value=client)


GEMINI_OK_BODY = {
    "candidates": [
        {
            "content": {
                "parts": [
                    {
                        "text": json.dumps(
                            {
                                "finding": "Reflected parameter without encoding",
                                "severity": "medium",
                                "confidence": 0.62,
                                "reasoning_summary": "Parameter reflected unencoded in response body.",
                                "evidence": ["param 'q' reflected raw in HTML context"],
                            }
                        )
                    }
                ]
            }
        }
    ],
    "usageMetadata": {
        "promptTokenCount": 120,
        "candidatesTokenCount": 40,
        "totalTokenCount": 160,
    },
}

OPENAI_STYLE_OK_BODY = {
    "choices": [
        {
            "message": {
                "content": json.dumps(
                    {
                        "finding": None,
                        "severity": None,
                        "confidence": 0.1,
                        "reasoning_summary": "No indicators of SQL injection in provided evidence.",
                        "evidence": [],
                    }
                )
            }
        }
    ],
    "usage": {"prompt_tokens": 200, "completion_tokens": 30, "total_tokens": 230},
}

FENCED_BODY = {
    "choices": [
        {
            "message": {
                "content": "```json\n"
                + json.dumps(
                    {
                        "finding": "possible IDOR",
                        "severity": "high",
                        "confidence": 0.7,
                        "reasoning_summary": "Returned another tenant's record.",
                        "evidence": ["swapped id returned foreign user data"],
                    }
                )
                + "\n```"
            }
        }
    ],
    "usage": {"prompt_tokens": 50, "completion_tokens": 20, "total_tokens": 70},
}


@pytest.mark.asyncio
async def test_gemini_success_parses_result():
    with _patched_client(_mock_response(200, GEMINI_OK_BODY)):
        provider = GeminiProvider(api_key="test-key")
        result = await provider.analyze("Analyze this parameter for XSS.", {"param": "q"})

    assert result.success is True
    assert result.provider == "gemini"
    assert result.severity == "medium"
    assert 0.0 <= result.confidence <= 1.0
    assert result.usage.total_tokens == 160


@pytest.mark.asyncio
async def test_gemini_auth_error_is_wrapped_not_raised():
    with _patched_client(_mock_response(401, {"error": "bad key"})):
        provider = GeminiProvider(api_key="bad-key")
        result = await provider.analyze("prompt", {})

    assert result.success is False
    assert result.error is not None
    assert "401" in result.error or "auth" in result.error.lower()


@pytest.mark.asyncio
async def test_grok_rate_limit_is_wrapped_not_raised():
    with _patched_client(_mock_response(429, {"error": "rate limited"})):
        provider = GrokProvider(api_key="test-key")
        result = await provider.analyze("prompt", {})

    assert result.success is False
    assert "rate" in result.error.lower()


@pytest.mark.asyncio
async def test_deepseek_success_parses_openai_style_result():
    with _patched_client(_mock_response(200, OPENAI_STYLE_OK_BODY)):
        provider = DeepSeekProvider(api_key="test-key")
        result = await provider.analyze("Analyze for SQLi.", {"param": "id"})

    assert result.success is True
    assert result.finding is None
    assert result.confidence == pytest.approx(0.1)


@pytest.mark.asyncio
async def test_markdown_fenced_json_is_stripped_and_parsed():
    with _patched_client(_mock_response(200, FENCED_BODY)):
        provider = DeepSeekProvider(api_key="test-key")
        result = await provider.analyze("Analyze for IDOR.", {})

    assert result.success is True
    assert result.severity == "high"
    assert result.evidence == ["swapped id returned foreign user data"]


@pytest.mark.asyncio
async def test_local_provider_uses_configured_base_url():
    with _patched_client(_mock_response(200, OPENAI_STYLE_OK_BODY)) as mock_client:
        provider = LocalModelProvider(base_url="http://localhost:8000/v1/chat/completions")
        result = await provider.analyze("prompt", {})
        instance = mock_client.return_value
        called_url = instance.post.call_args.args[0]

    assert result.success is True
    assert called_url == "http://localhost:8000/v1/chat/completions"


@pytest.mark.asyncio
async def test_malformed_json_content_is_reported_as_failure():
    bad_body = {"choices": [{"message": {"content": "not json at all"}}], "usage": {}}
    with _patched_client(_mock_response(200, bad_body)):
        provider = DeepSeekProvider(api_key="test-key")
        result = await provider.analyze("prompt", {})

    assert result.success is False
    assert "json" in result.error.lower()


def test_provider_requires_api_key():
    with pytest.raises(Exception):
        GeminiProvider(api_key="")


def test_confidence_is_clamped_into_0_1_range():
    from app.ai.providers.base import AIProvider, AIUsage

    class _Dummy(AIProvider):
        name = "dummy"
        default_model = "dummy-model"

        async def _call(self, system_prompt, user_prompt):  # pragma: no cover
            raise NotImplementedError

    provider = _Dummy(api_key="k")
    result = provider._parse_result({"confidence": 5.0}, AIUsage())
    assert result.confidence == 1.0
