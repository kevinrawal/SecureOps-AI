"""Redis Stream consumer pool: N async workers running the agent graph per event.

Each worker reads from the ``secureops-workers`` consumer group, invokes the
LangGraph agent pipeline, and acks on success. After MAX_RETRIES failures the
message is moved to the dead-letter stream and acked.

Run as a module to start the pool:
    uv run python -m src.workers.consumer
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import structlog
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

from src.core.config import settings
from src.core.schema import Role, ThreatState
from src.graph.builder import build_graph
from src.ingestion.queue.base import QueueMessage
from src.ingestion.queue.redis_backend import RedisStreamBackend
from src.observability.otel_setup import setup_tracing

if TYPE_CHECKING:
    from langgraph.graph.graph import CompiledGraph

logger = structlog.get_logger(__name__)

MAX_RETRIES: int = 3
_CONSUMER_GROUP: str = "secureops-workers"

# Process-level retry counter: message_id → consecutive failure count.
# Resets on process restart; sufficient for the portfolio use case.
_retry_counts: dict[str, int] = {}


async def _process_message(
    backend: RedisStreamBackend,
    graph: "CompiledGraph",
    msg: QueueMessage,
) -> None:
    """Process one queued event: run the agent graph, ack on success.

    On failure the retry counter is incremented. Once it reaches MAX_RETRIES the
    message is published to the DLQ stream, then acked on the main stream so it
    is removed from the Pending Entries List.
    """
    event_dict = msg.payload
    event_id = str(event_dict.get("event_id", msg.message_id))
    log = logger.bind(event_id=event_id, message_id=msg.message_id)

    try:
        state = ThreatState(
            event_id=event_id,
            secure_event=event_dict,
            user_id=str(event_dict.get("user_id", "system")),
            role=Role.ANALYST.value,
            audit_trail=[],
        )
        config: dict = {"configurable": {"thread_id": event_id}}
        await graph.ainvoke(state, config=config)
        await backend.ack(settings.REDIS_STREAM_NAME, _CONSUMER_GROUP, msg.message_id)
        _retry_counts.pop(msg.message_id, None)
        log.info("worker_event_processed")

    except Exception as exc:
        _retry_counts[msg.message_id] = _retry_counts.get(msg.message_id, 0) + 1
        retries = _retry_counts[msg.message_id]
        log.warning("worker_event_failed", error=str(exc), retries=retries)

        if retries >= MAX_RETRIES:
            dlq_payload: dict = {
                "original_message_id": msg.message_id,
                "error": str(exc),
                "retries": retries,
                **event_dict,
            }
            await backend.publish(settings.REDIS_STREAM_DLQ, dlq_payload)
            await backend.ack(settings.REDIS_STREAM_NAME, _CONSUMER_GROUP, msg.message_id)
            _retry_counts.pop(msg.message_id, None)
            log.error("worker_event_dlq", retries=retries)


async def run_worker(worker_id: int, graph: "CompiledGraph") -> None:
    """Single consumer loop: block on the Redis Stream, process one event at a time.

    Runs indefinitely until cancelled. The consumer group is created on first
    call (MKSTREAM ensures the stream also exists). CancelledError is re-raised
    after the backend connection is closed so asyncio.gather() propagates it.

    Args:
        worker_id: Unique integer label used as the consumer name (``worker-N``).
        graph: Compiled LangGraph instance shared across all workers in the pool.
    """
    backend = RedisStreamBackend()
    consumer_name = f"worker-{worker_id}"
    try:
        await backend.ensure_group(settings.REDIS_STREAM_NAME, _CONSUMER_GROUP)
        logger.info("worker_started", worker_id=worker_id, consumer=consumer_name)

        while True:
            messages = await backend.consume(
                stream=settings.REDIS_STREAM_NAME,
                group=_CONSUMER_GROUP,
                consumer=consumer_name,
                count=1,
                block_ms=5000,
            )
            for msg in messages:
                await _process_message(backend, graph, msg)

    except asyncio.CancelledError:
        logger.info("worker_cancelled", worker_id=worker_id)
        raise
    finally:
        await backend.close()


async def run_worker_pool() -> None:
    """Start N concurrent workers sharing one compiled graph.

    Builds the graph with ``AsyncPostgresSaver`` so HITL interrupt state persists
    across worker restarts. ``WORKER_COUNT`` env var sets concurrency.
    """
    dsn = (
        f"postgresql://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}"
        f"@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}"
    )
    async with AsyncPostgresSaver.from_conn_string(dsn) as checkpointer:
        await checkpointer.setup()
        graph = build_graph(checkpointer=checkpointer)
        logger.info("worker_pool_starting", count=settings.WORKER_COUNT)
        await asyncio.gather(
            *[run_worker(i, graph) for i in range(settings.WORKER_COUNT)]
        )


if __name__ == "__main__":
    setup_tracing("secureops-workers")
    asyncio.run(run_worker_pool())
