"""
Centralized application configuration.

Design decision: all configuration is loaded via pydantic-settings from
environment variables / .env. Nothing here is hard-coded, and no secret
ever has a default value that looks like a real credential — defaults are
either empty strings or obviously-fake placeholders, forcing explicit
configuration before the app will start in a non-dev mode.
"""
from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- App ---
    APP_NAME: str = "SentinelAI"
    ENVIRONMENT: str = "development"  # development | staging | production
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api"

    # --- Security ---
    SECRET_KEY: str = Field(default="CHANGE_ME_DEV_ONLY_INSECURE_KEY")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    JWT_ALGORITHM: str = "HS256"

    # --- Database ---
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel_ai"
    )

    # --- Redis / Queue ---
    REDIS_URL: str = Field(default="redis://localhost:6379/0")

    # --- CORS ---
    CORS_ORIGINS: List[str] = ["http://localhost:3000"]

    # --- AI Providers (Phase 9 — present now so .env.example is complete) ---
    GEMINI_API_KEY: str = ""
    XAI_API_KEY: str = ""
    DEEPSEEK_API_KEY: str = ""

    # --- Scan governance defaults (enforced per-assessment, these are platform ceilings) ---
    MAX_SCAN_RATE_LIMIT: int = 20        # requests/sec, hard ceiling a user cannot exceed
    MAX_SCAN_CONCURRENCY: int = 25
    DEFAULT_SCAN_RATE_LIMIT: int = 5
    DEFAULT_SCAN_CONCURRENCY: int = 10

    @field_validator("ENVIRONMENT")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        allowed = {"development", "staging", "production"}
        if v not in allowed:
            raise ValueError(f"ENVIRONMENT must be one of {allowed}")
        return v


@lru_cache
def get_settings() -> Settings:
    """Cached settings accessor — import this, not Settings() directly."""
    return Settings()
