"""Redis Streams implementation of :class:`QueueBackend`.

Uses ``redis.asyncio`` with XADD / XREADGROUP / XACK. Payloads are JSON-encoded
into a single ``data`` field so arbitrarily nested ``SecureEvent`` dicts survive
the round trip (Redis stream values are flat string maps).
"""

from __future__ import annotations

import json
from typing import Any

import redis.asyncio as redis
import structlog

from src.core.config import settings
from src.ingestion.queue.base import QueueBackend, QueueMessage

logger = structlog.get_logger(__name__)

_PAYLOAD_FIELD = "data"


class RedisStreamBackend(QueueBackend):
    """Async Redis Streams transport.

    A single client is created lazily and reused. Consumer-group reads start
    from new messages (``>``) so each event is delivered to exactly one worker.
    """

    def __init__(self, url: str | None = None) -> None:
        """Create a backend bound to ``url`` (defaults to ``settings.REDIS_URL``)."""
        self._url = url or settings.REDIS_URL
        self._client: redis.Redis | None = None

    def _conn(self) -> redis.Redis:
        """Return the lazily-initialized Redis client (decoding responses to str)."""
        if self._client is None:
            self._client = redis.from_url(self._url, decode_responses=True)
        return self._client

    async def publish(self, stream: str, payload: dict[str, Any]) -> str:
        """JSON-encode ``payload`` and XADD it to ``stream``; return the id."""
        message_id = await self._conn().xadd(
            stream, {_PAYLOAD_FIELD: json.dumps(payload, default=str)}
        )
        logger.debug("queue_publish", stream=stream, message_id=message_id)
        return message_id

    async def ensure_group(self, stream: str, group: str) -> None:
        """Create ``group`` on ``stream`` (MKSTREAM); ignore if it already exists."""
        try:
            await self._conn().xgroup_create(stream, group, id="0", mkstream=True)
            logger.info("queue_group_created", stream=stream, group=group)
        except redis.ResponseError as exc:  # BUSYGROUP = already exists
            if "BUSYGROUP" not in str(exc):
                raise

    async def consume(
        self,
        stream: str,
        group: str,
        consumer: str,
        count: int = 1,
        block_ms: int = 5000,
    ) -> list[QueueMessage]:
        """Read up to ``count`` undelivered messages, blocking up to ``block_ms``."""
        resp = await self._conn().xreadgroup(
            group, consumer, {stream: ">"}, count=count, block=block_ms
        )
        messages: list[QueueMessage] = []
        for _stream_name, entries in resp or []:
            for message_id, fields in entries:
                raw = fields.get(_PAYLOAD_FIELD, "{}")
                messages.append(QueueMessage(message_id=message_id, payload=json.loads(raw)))
        return messages

    async def ack(self, stream: str, group: str, message_id: str) -> None:
        """XACK ``message_id`` in ``group`` on ``stream``."""
        await self._conn().xack(stream, group, message_id)

    async def close(self) -> None:
        """Close the Redis connection if one was opened."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
