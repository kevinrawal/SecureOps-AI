"""Source normalizer — routes raw payloads to the right adapter.

The :data:`ADAPTER_REGISTRY` maps a source hint to an adapter class. This is the
extension point: adding a source means adding one registry entry, never editing
a central ``if/elif`` chain (design principle #2, "source-agnostic").
"""

from __future__ import annotations

from typing import Any

import structlog

from src.core.schema import EventSourceType, SecureEvent
from src.ingestion.adapters.base import BaseAdapter
from src.ingestion.adapters.nvd_adapter import NVDAdapter
from src.ingestion.adapters.siem_adapter import SIEMAdapter
from src.ingestion.adapters.syslog_adapter import SyslogAdapter

logger = structlog.get_logger(__name__)

#: Registry of source hint -> adapter class. The sole place new sources are wired.
ADAPTER_REGISTRY: dict[EventSourceType, type[BaseAdapter]] = {
    EventSourceType.CVE: NVDAdapter,
    EventSourceType.SIEM_ALERT: SIEMAdapter,
    EventSourceType.SYSLOG: SyslogAdapter,
}


class Normalizer:
    """Resolves the correct adapter for a source hint and normalizes payloads.

    Adapter instances are cached per source type so repeated normalization does
    not reconstruct them.
    """

    def __init__(self) -> None:
        """Initialize an empty adapter instance cache."""
        self._instances: dict[EventSourceType, BaseAdapter] = {}

    def _get_adapter(self, source_type: EventSourceType) -> BaseAdapter:
        """Return (and memoize) the adapter for ``source_type``."""
        if source_type not in self._instances:
            try:
                adapter_cls = ADAPTER_REGISTRY[source_type]
            except KeyError as exc:
                raise ValueError(
                    f"No adapter registered for source_type={source_type!r}. "
                    f"Known: {list(ADAPTER_REGISTRY)}"
                ) from exc
            self._instances[source_type] = adapter_cls()
        return self._instances[source_type]

    async def normalize(
        self,
        raw_data: dict[str, Any],
        source_hint: EventSourceType | str,
    ) -> SecureEvent:
        """Normalize ``raw_data`` to a :class:`SecureEvent` via the hinted adapter.

        Args:
            raw_data: The original source payload (dict). Plain syslog strings
                should be wrapped as ``{"line": "<...>"}`` before calling.
            source_hint: An :class:`EventSourceType` or its string value naming
                which adapter to use.

        Returns:
            The normalized :class:`SecureEvent`.
        """
        source_type = (
            source_hint if isinstance(source_hint, EventSourceType)
            else EventSourceType(source_hint)
        )
        adapter = self._get_adapter(source_type)
        event = await adapter.parse(raw_data)
        logger.info(
            "event_normalized",
            event_id=event.event_id,
            source_type=event.source_type.value,
            severity=event.severity.value,
        )
        return event
