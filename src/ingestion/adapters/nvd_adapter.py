"""NVD (National Vulnerability Database) CVE adapter.

Maps a single CVE object from the NVD 2.0 API into a :class:`SecureEvent`.
Parsing (offline, testable) is separated from fetching (network) so the mapping
can be tested against fixtures without hitting the API.

NVD 2.0 per-CVE shape (abridged)::

    {"cve": {
        "id": "CVE-2021-44228",
        "descriptions": [{"lang": "en", "value": "..."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0}, ...}]},
        "configurations": [...],
        "published": "2021-12-10T10:15Z"
    }}
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import httpx
import structlog

from src.core.config import settings
from src.core.schema import EventSourceType, SecureEvent
from src.ingestion.adapters.base import BaseAdapter

logger = structlog.get_logger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDAdapter(BaseAdapter):
    """Adapter for NVD CVE records."""

    source_type = EventSourceType.CVE

    async def parse(self, raw_data: dict[str, Any]) -> SecureEvent:
        """Map one NVD CVE object to a :class:`SecureEvent`.

        Accepts either a top-level ``{"cve": {...}}`` wrapper or a bare ``cve``
        object. CVSS v3.1/v3.0 base score drives severity; affected products and
        the CVE id become assets/indicators.
        """
        cve = raw_data.get("cve", raw_data)
        cve_id = cve.get("id", "UNKNOWN-CVE")

        description = self._extract_description(cve)
        score = self._extract_cvss(cve)
        assets = self._extract_assets(cve)

        return SecureEvent(
            timestamp=self._parse_timestamp(cve.get("published")),
            source_type=self.source_type,
            source_name="NVD",
            severity=self.cvss_to_severity(score),
            title=f"{cve_id}: {description[:120]}" if description else cve_id,
            description=self._truncate(description),
            affected_assets=assets,
            indicators=[cve_id],
            raw_data=raw_data,
            tags=["vulnerability", "cve"],
            metadata={"cvss_base_score": score} if score is not None else {},
        )

    # -- extraction helpers ------------------------------------------------
    @staticmethod
    def _extract_description(cve: dict[str, Any]) -> str:
        """Return the English description, or the first available one."""
        descriptions = cve.get("descriptions", []) or []
        for desc in descriptions:
            if desc.get("lang") == "en":
                return desc.get("value", "")
        return descriptions[0].get("value", "") if descriptions else ""

    @staticmethod
    def _extract_cvss(cve: dict[str, Any]) -> float | None:
        """Return the CVSS v3.1 (then v3.0, then v2) base score if present."""
        metrics = cve.get("metrics", {}) or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                data = entries[0].get("cvssData", {})
                score = data.get("baseScore")
                if score is not None:
                    return float(score)
        return None

    @staticmethod
    def _extract_assets(cve: dict[str, Any]) -> list[str]:
        """Collect affected product CPE criteria from the configurations block."""
        assets: list[str] = []
        for config in cve.get("configurations", []) or []:
            for node in config.get("nodes", []) or []:
                for match in node.get("cpeMatch", []) or []:
                    criteria = match.get("criteria")
                    if criteria:
                        assets.append(criteria)
        return assets[:50]  # bound list size

    @staticmethod
    def _parse_timestamp(value: str | None) -> datetime:
        """Parse an NVD ISO timestamp; fall back to now() on failure."""
        if not value:
            return BaseAdapter._now_utc()
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return BaseAdapter._now_utc()

    # -- network fetch (used by scheduled ingest in M10) -------------------
    async def fetch_recent(self, results_per_page: int = 20) -> list[dict[str, Any]]:
        """Fetch recent CVE objects from the NVD 2.0 API.

        Kept separate from :meth:`parse` so parsing stays offline-testable.
        Returns the raw per-CVE wrapper dicts ready to pass to :meth:`parse`.
        """
        headers: dict[str, str] = {}
        timeout = httpx.Timeout(30.0)
        async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
            resp = await client.get(
                NVD_API_URL, params={"resultsPerPage": results_per_page}
            )
            resp.raise_for_status()
            data = resp.json()
        vulns = data.get("vulnerabilities", [])
        logger.info("nvd_fetch", count=len(vulns))
        return vulns
