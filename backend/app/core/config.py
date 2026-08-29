"""
Application configuration using pydantic-settings.
Reads from environment variables and .env file.
"""
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator
import json


class Settings(BaseSettings):
    # ── Application ────────────────────────────────────────
    app_name: str = "AI-SOC Platform"
    app_version: str = "1.0.0"
    app_env: str = "development"
    debug: bool = True

    # ── Database ───────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./soc.db"

    # ── Security ───────────────────────────────────────────
    secret_key: str = "dev-secret-key-change-in-production-min-32-chars"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # ── CORS ───────────────────────────────────────────────
    cors_origins: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
    ]

    # ── AI / LLM ───────────────────────────────────────────
    llm_provider: str = "gemini"
    gemini_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    llm_model: str = "gemini-1.5-flash"

    # ── ML ─────────────────────────────────────────────────
    ml_model_path: str = "./ml/models"
    anomaly_contamination: float = 0.05
    min_training_samples: int = 100

    # ── Simulation ─────────────────────────────────────────
    simulation_events_per_second: float = 2.0

    # ── Rate Limiting ──────────────────────────────────────
    rate_limit_per_minute: int = 200

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            try:
                return json.loads(v)
            except Exception:
                return [o.strip() for o in v.split(",")]
        return v

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


settings = Settings()
