"""Source adapter base class.

A :class:`BaseAdapter` subclass isolates *one* source's shape and maps it to the
common :class:`~src.core.schema.SecureEvent`. Adapters are pure
``dict -> SecureEvent`` transforms (no network, no LLM) so they unit-test offline
against fixtures. Network fetching, where needed, lives in adapter-specific
methods used only by scheduled ingest (M10).

Adding a new source is a 2-step change (design principle #2):
  1. Subclass :class:`BaseAdapter` and implement :meth:`parse`.
  2. Register it in ``ADAPTER_REGISTRY`` (see ``src/ingestion/normalizer.py``).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from src.core.schema import EventSourceType, SecureEvent, SeverityLevel

# Defensive cap to bound oversized/malformed text fields (DoS hardening).
MAX_TEXT_LEN = 20_000


class BaseAdapter(ABC):
    """Abstract base for all source adapters.

    Subclasses declare :attr:`source_type` and implement async :meth:`parse`.
    Helper methods provide consistent severity mapping and UTC timestamps so
    every adapter normalizes the same way.
    """

    #: The source category this adapter produces; set by each subclass.
    source_type: EventSourceType

    @abstractmethod
    async def parse(self, raw_data: dict[str, Any]) -> SecureEvent:
        """Map one raw source payload to a :class:`SecureEvent`.

        Implementations must preserve the original payload unchanged in
        ``SecureEvent.raw_data`` for forensics/audit.
        """

    # -- shared helpers ----------------------------------------------------
    @staticmethod
    def _now_utc() -> datetime:
        """Current time as a timezone-aware UTC datetime."""
        return datetime.now(timezone.utc)

    @staticmethod
    def _truncate(text: str | None) -> str:
        """Coerce to a stripped, length-bounded string (None → '')."""
        if not text:
            return ""
        return str(text).strip()[:MAX_TEXT_LEN]

    @staticmethod
    def cvss_to_severity(score: float | None) -> SeverityLevel:
        """Map a CVSS v3 base score (0–10) to a :class:`SeverityLevel`."""
        if score is None:
            return SeverityLevel.INFO
        if score >= 9.0:
            return SeverityLevel.CRITICAL
        if score >= 7.0:
            return SeverityLevel.HIGH
        if score >= 4.0:
            return SeverityLevel.MEDIUM
        if score > 0.0:
            return SeverityLevel.LOW
        return SeverityLevel.INFO

    @staticmethod
    def label_to_severity(label: str | None) -> SeverityLevel:
        """Map a free-text severity/priority label to a :class:`SeverityLevel`."""
        if not label:
            return SeverityLevel.INFO
        key = str(label).strip().upper()
        aliases = {
            "CRIT": SeverityLevel.CRITICAL,
            "CRITICAL": SeverityLevel.CRITICAL,
            "P1": SeverityLevel.CRITICAL,
            "SEV1": SeverityLevel.CRITICAL,
            "HIGH": SeverityLevel.HIGH,
            "P2": SeverityLevel.HIGH,
            "SEV2": SeverityLevel.HIGH,
            "MED": SeverityLevel.MEDIUM,
            "MEDIUM": SeverityLevel.MEDIUM,
            "MODERATE": SeverityLevel.MEDIUM,
            "P3": SeverityLevel.MEDIUM,
            "LOW": SeverityLevel.LOW,
            "P4": SeverityLevel.LOW,
            "INFO": SeverityLevel.INFO,
            "INFORMATIONAL": SeverityLevel.INFO,
        }
        return aliases.get(key, SeverityLevel.INFO)
