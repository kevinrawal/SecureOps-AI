"""Route: GET /health — liveness and readiness check for all platform components."""
from __future__ import annotations

import asyncio
from typing import Any

import structlog
from fastapi import APIRouter
from sqlalchemy import text

from src.core.config import settings
from src.db.engine import get_engine
from src.rag.pinecone_store import init_pinecone

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["health"])


async def _check_postgres() -> str:
    """Return "ok" or "error: <message>" for PostgreSQL connectivity."""
    try:
        async with get_engine().connect() as conn:
            await asyncio.wait_for(
                conn.execute(text("SELECT 1")),
                timeout=3.0,
            )
        return "ok"
    except Exception as exc:  # noqa: BLE001
        return f"error: {exc}"


async def _check_redis() -> str:
    """Return "ok" or "error: <message>" for Redis connectivity."""
    try:
        import redis.asyncio as aioredis

        client: aioredis.Redis = aioredis.from_url(settings.REDIS_URL)
        await asyncio.wait_for(client.ping(), timeout=3.0)
        await client.aclose()
        return "ok"
    except Exception as exc:  # noqa: BLE001
        return f"error: {exc}"


async def _check_pinecone() -> str:
    """Return "ok" or "error: <message>" for Pinecone connectivity."""
    try:
        index = await asyncio.wait_for(init_pinecone(), timeout=5.0)
        await asyncio.to_thread(index.describe_index_stats)
        return "ok"
    except Exception as exc:  # noqa: BLE001
        return f"error: {exc}"


@router.get("/health")
async def health_check() -> dict[str, Any]:
    """Run concurrent health checks for PostgreSQL, Redis, and Pinecone.

    Always returns HTTP 200. Callers should inspect the ``status`` field:
        ``"ok"``       — all components healthy.
        ``"degraded"`` — one or more components unreachable.

    Individual component results are under ``checks``.
    """
    postgres_status, redis_status, pinecone_status = await asyncio.gather(
        _check_postgres(),
        _check_redis(),
        _check_pinecone(),
    )

    checks: dict[str, str] = {
        "postgres": postgres_status,
        "redis": redis_status,
        "pinecone": pinecone_status,
    }
    overall = "ok" if all(v == "ok" for v in checks.values()) else "degraded"

    logger.info("health_check", status=overall, checks=checks)
    return {"status": overall, "checks": checks}
