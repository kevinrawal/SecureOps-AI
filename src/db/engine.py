"""SQLAlchemy async engine factory.

One engine per process; asyncpg connection pool shared across all callers.
Used by both Alembic (migrations) and runtime DB access (audit log inserts).
No ORM models are defined here — callers use Core text() queries or op.execute().
"""
from __future__ import annotations

from functools import lru_cache

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from src.core.config import settings


@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    return create_async_engine(
        settings.DATABASE_URL,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,
        echo=False,
    )
