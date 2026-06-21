"""Generic SIEM webhook adapter.

SIEM products (Splunk, Sentinel, QRadar, Elastic, …) post alerts with wildly
varying field names. This adapter does best-effort mapping across the common
aliases with safe fallbacks, so an unknown-but-reasonable webhook still produces
a valid :class:`SecureEvent` rather than failing.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from src.core.schema import EventSourceType, SecureEvent
from src.ingestion.adapters.base import BaseAdapter


def _first(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Return the first present, non-empty value among ``keys`` in ``data``."""
    for key in keys:
        value = data.get(key)
        if value not in (None, "", [], {}):
            return value
    return default


def _as_list(value: Any) -> list[str]:
    """Coerce a scalar or iterable into a list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value]
    return [str(value)]


class SIEMAdapter(BaseAdapter):
    """Adapter for generic SIEM webhook JSON payloads."""

    source_type = EventSourceType.SIEM_ALERT

    async def parse(self, raw_data: dict[str, Any]) -> SecureEvent:
        """Best-effort map a SIEM webhook payload to a :class:`SecureEvent`."""
        title = _first(raw_data, "title", "rule_name", "signature", "name",
                       "alert_name", default="SIEM Alert")
        description = _first(raw_data, "description", "message", "summary",
                             "detail", default="")
        severity_label = _first(raw_data, "severity", "priority", "level",
                                "risk", default="INFO")
        source_name = _first(raw_data, "source", "product", "vendor",
                             "siem", default="SIEM")

        assets = _as_list(_first(raw_data, "host", "hosts", "asset", "assets",
                                 "dest_host", "src_host", default=[]))
        indicators = _as_list(_first(raw_data, "ip", "src_ip", "dest_ip",
                                     "indicators", "user", "username", default=[]))

        return SecureEvent(
            timestamp=self._parse_timestamp(_first(raw_data, "timestamp", "time",
                                                   "@timestamp", "created_at")),
            source_type=self.source_type,
            source_name=self._truncate(str(source_name)),
            severity=self.label_to_severity(str(severity_label)),
            title=self._truncate(str(title)),
            description=self._truncate(str(description)),
            affected_assets=assets,
            indicators=indicators,
            raw_data=raw_data,
            tags=_as_list(_first(raw_data, "tags", "categories", default=["siem"])),
            metadata={"original_severity": str(severity_label)},
        )

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime:
        """Parse an ISO/epoch timestamp; fall back to now() on failure."""
        if value in (None, ""):
            return BaseAdapter._now_utc()
        try:
            if isinstance(value, (int, float)):
                return datetime.fromtimestamp(float(value))
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (ValueError, OSError, TypeError):
            return BaseAdapter._now_utc()
