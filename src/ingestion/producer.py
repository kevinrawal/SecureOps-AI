"""Event producer — publishes normalized events onto the queue.

The producer depends only on the :class:`QueueBackend` interface (obtained from
the queue factory), so it is unaware of Redis vs Kafka vs anything else. It
serializes a :class:`SecureEvent` and appends it to the configured stream.

Run as a module for a quick smoke test against the compose Redis::

    uv run python -m src.ingestion.producer
"""

from __future__ import annotations

import asyncio

import structlog

from src.core.config import settings
from src.core.schema import EventSourceType, SecureEvent, SeverityLevel
from src.ingestion.queue.base import QueueBackend
from src.ingestion.queue.factory import get_queue_backend

logger = structlog.get_logger(__name__)


async def publish(event: SecureEvent, backend: QueueBackend | None = None) -> str:
    """Publish a :class:`SecureEvent` to the configured event stream.

    Args:
        event: The normalized event to enqueue.
        backend: Optional explicit backend (mainly for tests); defaults to the
            process-wide configured backend.

    Returns:
        The queue message id assigned to the published event.
    """
    backend = backend or get_queue_backend()
    payload = event.model_dump(mode="json")
    message_id = await backend.publish(settings.REDIS_STREAM_NAME, payload)
    logger.info(
        "event_published",
        event_id=event.event_id,
        stream=settings.REDIS_STREAM_NAME,
        message_id=message_id,
    )
    return message_id


async def _smoke_test() -> None:
    """Publish one demo event and print its message id (manual verification)."""
    demo = SecureEvent(
        source_type=EventSourceType.SIEM_ALERT,
        source_name="demo",
        severity=SeverityLevel.HIGH,
        title="Demo: suspicious login",
        description="Smoke-test event published by producer __main__.",
        affected_assets=["host-01"],
        indicators=["10.0.0.5"],
    )
    backend = get_queue_backend()
    try:
        message_id = await publish(demo, backend)
        logger.info("smoke_test_ok", message_id=message_id, event_id=demo.event_id)
    finally:
        await backend.close()


if __name__ == "__main__":
    asyncio.run(_smoke_test())
