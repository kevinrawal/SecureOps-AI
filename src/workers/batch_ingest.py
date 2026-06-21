"""Scheduled NVD CVE batch pull: fetch recent CVEs and publish to the event stream.

Intended to be invoked once per day by a scheduler (APScheduler, cron, etc.).
SSRFGuard validates the fetch URL before every HTTP call as defence-in-depth for
any future dynamic feed URL support.

Run as a module for a one-shot ingest:
    uv run python -m src.workers.batch_ingest
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import structlog

from src.core.config import settings
from src.core.schema import SecureEvent
from src.ingestion.adapters.nvd_adapter import NVD_API_URL, NVDAdapter
from src.ingestion.producer import publish
from src.observability.otel_setup import setup_tracing
from src.security.guardrails.ssrf_guard import SSRFGuard

logger = structlog.get_logger(__name__)

_ssrf_guard = SSRFGuard()
_adapter = NVDAdapter()


async def fetch_recent_nvd_cves(days_back: int = 1) -> list[SecureEvent]:
    """Pull CVEs published in the last N days from NVD API 2.0.

    Validates the fetch URL through SSRFGuard before making the HTTP request
    (defence-in-depth; the URL is currently static but the guard must hold for
    any future dynamic feed URL support).

    Rate limits: 5 req/30s without ``NVD_API_KEY``, 50 req/30s with it.

    Args:
        days_back: Number of calendar days to look back from now (UTC).

    Returns:
        List of normalised :class:`~src.core.schema.SecureEvent` objects.

    Raises:
        ValueError: If the constructed URL is blocked by SSRFGuard.
        httpx.HTTPStatusError: If NVD returns a non-2xx response.
    """
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days_back)

    pub_start = start.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end = end.strftime("%Y-%m-%dT%H:%M:%S.000")
    url = f"{NVD_API_URL}?pubStartDate={pub_start}&pubEndDate={pub_end}"

    guard_result = await _ssrf_guard.check({"url": url})
    if not guard_result.passed:
        raise ValueError(f"NVD feed URL blocked by SSRFGuard: {guard_result.blocked_reason}")

    headers: dict[str, str] = {}
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY

    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    vulnerabilities: list[dict] = data.get("vulnerabilities", [])
    logger.info("nvd_batch_fetch", count=len(vulnerabilities), days_back=days_back)

    events: list[SecureEvent] = []
    for vuln in vulnerabilities:
        event = await _adapter.parse(vuln)
        events.append(event)

    return events


async def run_batch_ingest() -> None:
    """Fetch recent CVEs from NVD and publish each to the Redis event stream.

    Workers in the consumer pool will pick up each published event and run it
    through the full agent pipeline.
    """
    events = await fetch_recent_nvd_cves(days_back=1)
    for event in events:
        await publish(event)
    logger.info("nvd_batch_ingest_complete", count=len(events))


if __name__ == "__main__":
    setup_tracing("secureops-batch")
    asyncio.run(run_batch_ingest())
