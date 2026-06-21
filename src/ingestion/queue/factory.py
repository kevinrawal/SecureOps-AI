"""Queue backend factory — the single place transport is selected.

Mirrors the model factory pattern: callers ask for *a* queue backend and get the
configured implementation. Swapping Redis Streams for Kafka means adding a
``KafkaBackend`` and one branch here; no producer/consumer changes.
"""

from __future__ import annotations

from src.ingestion.queue.base import QueueBackend
from src.ingestion.queue.redis_backend import RedisStreamBackend

# Process-wide singleton so connections are reused across producers/consumers.
_backend: QueueBackend | None = None


def get_queue_backend() -> QueueBackend:
    """Return the configured :class:`QueueBackend` singleton.

    Currently always Redis Streams. To introduce another transport, branch on a
    config value (e.g. ``settings.QUEUE_BACKEND``) here and return the new impl.
    """
    global _backend
    if _backend is None:
        _backend = RedisStreamBackend()
    return _backend
