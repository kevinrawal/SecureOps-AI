"""Queue backend abstraction.

The platform's transport is hidden behind :class:`QueueBackend`. Producers and
consumers depend on this interface, never on a concrete client, so the current
Redis Streams implementation can be replaced by Kafka / SQS / NATS by adding a
new backend and changing one factory line — no producer/consumer code changes
(design principle #3, "async-first / transport-swappable").
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class QueueMessage:
    """A message read from the queue.

    Attributes:
        message_id: Backend-native id (Redis stream id, Kafka offset, …).
        payload: The decoded message body (the serialized ``SecureEvent``).
    """

    message_id: str
    payload: dict[str, Any]


class QueueBackend(ABC):
    """Transport-agnostic async message queue.

    Implementations wrap a concrete broker. All methods are async; ``publish``
    is used by the producer (M3), the remaining methods by the worker pool (M10).
    """

    @abstractmethod
    async def publish(self, stream: str, payload: dict[str, Any]) -> str:
        """Append ``payload`` to ``stream`` and return the new message id."""

    @abstractmethod
    async def ensure_group(self, stream: str, group: str) -> None:
        """Create the consumer group on ``stream`` if it does not yet exist."""

    @abstractmethod
    async def consume(
        self,
        stream: str,
        group: str,
        consumer: str,
        count: int = 1,
        block_ms: int = 5000,
    ) -> list[QueueMessage]:
        """Read up to ``count`` new messages for ``consumer`` in ``group``."""

    @abstractmethod
    async def ack(self, stream: str, group: str, message_id: str) -> None:
        """Acknowledge successful processing of ``message_id``."""

    @abstractmethod
    async def close(self) -> None:
        """Release the underlying connection/resources."""
