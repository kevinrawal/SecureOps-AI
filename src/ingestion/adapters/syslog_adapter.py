"""Syslog adapter.

Parses a syslog line (RFC 3164 / 5424-ish) into a :class:`SecureEvent`. The
leading ``<PRI>`` value encodes facility and severity: ``severity = PRI % 8``,
``facility = PRI // 8``. The textual remainder becomes title/description.

Input contract: a dict carrying the raw line under one of ``line`` / ``message``
/ ``raw`` (the normalizer wraps plain strings into ``{"line": ...}``).
"""

from __future__ import annotations

import re
from typing import Any

from src.core.schema import EventSourceType, SecureEvent, SeverityLevel
from src.ingestion.adapters.base import BaseAdapter

# Maps syslog numeric severity (0=emerg … 7=debug) to our SeverityLevel.
_SYSLOG_SEVERITY = {
    0: SeverityLevel.CRITICAL,  # Emergency
    1: SeverityLevel.CRITICAL,  # Alert
    2: SeverityLevel.CRITICAL,  # Critical
    3: SeverityLevel.HIGH,      # Error
    4: SeverityLevel.MEDIUM,    # Warning
    5: SeverityLevel.LOW,       # Notice
    6: SeverityLevel.INFO,      # Informational
    7: SeverityLevel.INFO,      # Debug
}

_PRI_RE = re.compile(r"^<(\d{1,3})>")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class SyslogAdapter(BaseAdapter):
    """Adapter for syslog text lines."""

    source_type = EventSourceType.SYSLOG

    async def parse(self, raw_data: dict[str, Any]) -> SecureEvent:
        """Map a syslog line to a :class:`SecureEvent`."""
        line = str(raw_data.get("line") or raw_data.get("message")
                   or raw_data.get("raw") or "").strip()

        severity, remainder = self._decode_pri(line)
        indicators = _IP_RE.findall(remainder)

        return SecureEvent(
            source_type=self.source_type,
            source_name=str(raw_data.get("source_name", "syslog")),
            severity=severity,
            title=self._truncate(remainder[:120] or "Syslog message"),
            description=self._truncate(remainder),
            affected_assets=[str(raw_data["host"])] if raw_data.get("host") else [],
            indicators=indicators,
            raw_data=raw_data,
            tags=["syslog"],
            metadata={},
        )

    @staticmethod
    def _decode_pri(line: str) -> tuple[SeverityLevel, str]:
        """Split the ``<PRI>`` prefix from ``line``; return (severity, remainder)."""
        match = _PRI_RE.match(line)
        if not match:
            return SeverityLevel.INFO, line
        pri = int(match.group(1))
        severity = _SYSLOG_SEVERITY.get(pri % 8, SeverityLevel.INFO)
        return severity, line[match.end():].strip()
