"""Central configuration surface for SecureOps AI.

Every module reads from the single ``settings`` object exported here; no module
reads ``os.environ`` directly. Values load from the process environment and an
optional ``.env`` file (pydantic-settings). Configuration is validated at import
time so an invalid deployment fails fast at startup rather than deep inside an
agent run.

Usage::

    from src.core.config import settings
    print(settings.LLM_PROVIDER)
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed, validated view of all SecureOps AI environment variables.

    Grouped to mirror the configuration domains documented in
    ``docs/M1-scaffold/system-design.md``.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # --- LLM ---------------------------------------------------------------
    LLM_PROVIDER: Literal["groq", "openai", "anthropic"] = "groq"
    GROQ_API_KEY: str = ""
    GROQ_MODEL: str = "llama-3.3-70b-versatile"
    GROQ_MODEL_FAST: str = "llama-3.1-8b-instant"
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"
    ANTHROPIC_API_KEY: str = ""
    ANTHROPIC_MODEL: str = "claude-3-5-haiku-20241022"

    # --- Embeddings --------------------------------------------------------
    EMBEDDING_PROVIDER: Literal["huggingface", "openai"] = "huggingface"
    EMBEDDING_MODEL: str = "all-MiniLM-L6-v2"
    EMBEDDING_DIMENSION: int = 384

    # --- Pinecone ----------------------------------------------------------
    PINECONE_API_KEY: str = ""
    PINECONE_INDEX_NAME: str = "secureops-runbooks"
    PINECONE_ENVIRONMENT: str = "us-east-1-aws"

    # --- Redis -------------------------------------------------------------
    REDIS_URL: str = "redis://localhost:6379"
    REDIS_STREAM_NAME: str = "secureops:events"
    REDIS_STREAM_DLQ: str = "secureops:dlq"
    WORKER_COUNT: int = 3

    # --- NVD ---------------------------------------------------------------
    NVD_API_KEY: str = ""          # raises rate limit from 5 to 50 req/30s

    # --- PostgreSQL --------------------------------------------------------
    # Individual components are the primary source of truth; docker-compose and
    # the app both read these from .env. DATABASE_URL is computed from them
    # unless explicitly overridden (e.g. for a managed cloud DSN).
    POSTGRES_USER: str = "secureops"
    POSTGRES_PASSWORD: str = "secureops"
    POSTGRES_DB: str = "secureops"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    DATABASE_URL: str = ""              # computed by the validator below if empty

    @model_validator(mode="after")
    def _compute_database_url(self) -> "Settings":
        """Build DATABASE_URL from POSTGRES_* components when not set directly."""
        if not self.DATABASE_URL:
            self.DATABASE_URL = (
                f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
                f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
            )
        return self

    # --- JWT ---------------------------------------------------------------
    JWT_SECRET_KEY: str = "change-this-in-production-use-openssl-rand-hex-32"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60

    # --- Observability -----------------------------------------------------
    LANGFUSE_SECRET_KEY: str = ""
    LANGFUSE_PUBLIC_KEY: str = ""
    LANGFUSE_HOST: str = "http://localhost:3000"
    OTEL_EXPORTER_OTLP_ENDPOINT: str = "http://localhost:4317"

    # --- Security ----------------------------------------------------------
    INJECTION_L2_ENABLED: bool = False   # enable LLM judge for near-miss inputs

    # --- App ---------------------------------------------------------------
    APP_ENV: Literal["development", "production"] = "development"
    LOG_LEVEL: str = "INFO"

    @property
    def is_production(self) -> bool:
        """True when running under the production environment profile."""
        return self.APP_ENV == "production"


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide cached Settings singleton.

    Cached so configuration is parsed once. Tests can clear the cache via
    ``get_settings.cache_clear()`` after patching the environment.
    """
    return Settings()


# Module-level singleton imported throughout the codebase.
settings: Settings = get_settings()
