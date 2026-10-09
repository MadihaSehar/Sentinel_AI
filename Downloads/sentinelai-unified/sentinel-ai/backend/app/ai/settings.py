"""
AI subsystem configuration, loaded from environment variables / `.env`
(section 31 of the master prompt). Keys are read once at process start,
never logged, never persisted to the database.
"""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class AISettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.0-flash"

    xai_api_key: str = ""
    grok_model: str = "grok-2-latest"

    deepseek_api_key: str = ""
    deepseek_model: str = "deepseek-chat"

    # Not in the master prompt's original .env.example, but required to
    # wire up LocalModelProvider (section 4's AI stack explicitly lists
    # "optional local models"). Left blank = local fallback disabled.
    local_model_base_url: str = ""
    local_model_api_key: str = ""
    local_model_name: str = "llama3.1"

    ai_timeout_seconds: float = 30.0
    ai_max_output_tokens: int = 1024
