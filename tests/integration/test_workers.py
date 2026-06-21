"""Integration tests for M10 workers.

All Redis, PostgreSQL, and graph calls are mocked so tests run offline.
Tests exercise _process_message directly (unit-style) and run_worker /
run_worker_pool through controlled side-effects.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.config import settings
from src.ingestion.queue.base import QueueMessage
from src.workers import consumer


# ── Helpers ───────────────────────────────────────────────────────────────────

def _msg(message_id: str = "1-0", event_id: str = "evt-001") -> QueueMessage:
    return QueueMessage(
        message_id=message_id,
        payload={"event_id": event_id, "title": "ssh brute force"},
    )


def _mock_graph(*, fail: bool = False, error: str = "boom") -> AsyncMock:
    g = AsyncMock()
    if fail:
        g.ainvoke = AsyncMock(side_effect=RuntimeError(error))
    else:
        g.ainvoke = AsyncMock(return_value={})
    return g


# ── _process_message: success ─────────────────────────────────────────────────

class TestProcessMessageSuccess:
    async def test_acks_after_successful_invocation(self) -> None:
        """Successful graph run → XACK called with correct args."""
        consumer._retry_counts.clear()
        backend = AsyncMock()
        msg = _msg()

        await consumer._process_message(backend, _mock_graph(), msg)

        backend.ack.assert_awaited_once_with(
            settings.REDIS_STREAM_NAME, consumer._CONSUMER_GROUP, msg.message_id
        )

    async def test_retry_count_cleared_on_success(self) -> None:
        """Pre-existing retry entry is removed after a successful run."""
        consumer._retry_counts.clear()
        consumer._retry_counts["1-0"] = 2
        backend = AsyncMock()

        await consumer._process_message(backend, _mock_graph(), _msg())

        assert "1-0" not in consumer._retry_counts

    async def test_no_dlq_publish_on_success(self) -> None:
        """Successful run must not write to the DLQ stream."""
        consumer._retry_counts.clear()
        backend = AsyncMock()

        await consumer._process_message(backend, _mock_graph(), _msg())

        backend.publish.assert_not_awaited()


# ── _process_message: failure / DLQ ──────────────────────────────────────────

class TestProcessMessageFailure:
    async def test_no_ack_on_first_failure(self) -> None:
        """First failure increments retry count but does not ack or DLQ."""
        consumer._retry_counts.clear()
        backend = AsyncMock()
        msg = _msg("msg-f1", "evt-f1")

        await consumer._process_message(backend, _mock_graph(fail=True), msg)

        backend.ack.assert_not_awaited()
        backend.publish.assert_not_awaited()
        assert consumer._retry_counts["msg-f1"] == 1

    async def test_no_ack_on_second_failure(self) -> None:
        """Second failure (below MAX_RETRIES) still does not ack or DLQ."""
        consumer._retry_counts.clear()
        consumer._retry_counts["msg-f2"] = 1
        backend = AsyncMock()
        msg = _msg("msg-f2", "evt-f2")

        await consumer._process_message(backend, _mock_graph(fail=True), msg)

        backend.ack.assert_not_awaited()
        assert consumer._retry_counts["msg-f2"] == 2

    async def test_routes_to_dlq_at_max_retries(self) -> None:
        """At MAX_RETRIES consecutive failures the message is DLQ'd and acked."""
        consumer._retry_counts.clear()
        consumer._retry_counts["msg-dlq"] = consumer.MAX_RETRIES - 1
        backend = AsyncMock()
        msg = _msg("msg-dlq", "evt-dlq")

        await consumer._process_message(backend, _mock_graph(fail=True, error="persistent"), msg)

        backend.publish.assert_awaited_once()
        dlq_stream = backend.publish.call_args[0][0]
        assert dlq_stream == settings.REDIS_STREAM_DLQ

        dlq_payload = backend.publish.call_args[0][1]
        assert dlq_payload["original_message_id"] == "msg-dlq"
        assert "persistent" in dlq_payload["error"]

        backend.ack.assert_awaited_once_with(
            settings.REDIS_STREAM_NAME, consumer._CONSUMER_GROUP, "msg-dlq"
        )
        assert "msg-dlq" not in consumer._retry_counts

    async def test_dlq_payload_includes_original_event(self) -> None:
        """DLQ entry carries the original event fields for post-mortem analysis."""
        consumer._retry_counts.clear()
        consumer._retry_counts["msg-pp"] = consumer.MAX_RETRIES - 1
        backend = AsyncMock()
        msg = QueueMessage(
            message_id="msg-pp",
            payload={"event_id": "evt-pp", "title": "poison pill"},
        )

        await consumer._process_message(backend, _mock_graph(fail=True), msg)

        payload = backend.publish.call_args[0][1]
        assert payload["event_id"] == "evt-pp"
        assert payload["title"] == "poison pill"


# ── run_worker ────────────────────────────────────────────────────────────────

class TestRunWorker:
    async def test_cleans_up_backend_on_cancellation(self) -> None:
        """run_worker closes its Redis connection cleanly when cancelled."""
        consumer._retry_counts.clear()
        msg = _msg()
        mock_backend = AsyncMock()
        mock_backend.consume = AsyncMock(
            side_effect=[[msg], asyncio.CancelledError()]
        )
        mock_graph = _mock_graph()

        with patch("src.workers.consumer.RedisStreamBackend", return_value=mock_backend):
            with pytest.raises(asyncio.CancelledError):
                await consumer.run_worker(0, mock_graph)

        mock_backend.close.assert_awaited_once()

    async def test_processes_message_before_cancelling(self) -> None:
        """run_worker acks the message it received before the cancel fires."""
        consumer._retry_counts.clear()
        msg = _msg()
        mock_backend = AsyncMock()
        mock_backend.consume = AsyncMock(
            side_effect=[[msg], asyncio.CancelledError()]
        )
        mock_graph = _mock_graph()

        with patch("src.workers.consumer.RedisStreamBackend", return_value=mock_backend):
            with pytest.raises(asyncio.CancelledError):
                await consumer.run_worker(0, mock_graph)

        mock_backend.ack.assert_awaited_once()

    async def test_ensures_consumer_group_on_startup(self) -> None:
        """run_worker calls ensure_group before entering the read loop."""
        consumer._retry_counts.clear()
        mock_backend = AsyncMock()
        mock_backend.consume = AsyncMock(side_effect=asyncio.CancelledError())

        with patch("src.workers.consumer.RedisStreamBackend", return_value=mock_backend):
            with pytest.raises(asyncio.CancelledError):
                await consumer.run_worker(2, _mock_graph())

        mock_backend.ensure_group.assert_awaited_once_with(
            settings.REDIS_STREAM_NAME, consumer._CONSUMER_GROUP
        )


# ── run_worker_pool ───────────────────────────────────────────────────────────

class TestRunWorkerPool:
    async def test_spawns_worker_count_workers(self) -> None:
        """run_worker_pool launches exactly WORKER_COUNT concurrent workers."""
        mock_checkpointer = AsyncMock()
        mock_checkpointer.__aenter__ = AsyncMock(return_value=mock_checkpointer)
        mock_checkpointer.__aexit__ = AsyncMock(return_value=False)
        mock_graph = MagicMock()

        with (
            patch("src.workers.consumer.AsyncPostgresSaver") as mock_saver_cls,
            patch("src.workers.consumer.build_graph", return_value=mock_graph),
            patch(
                "src.workers.consumer.run_worker", new_callable=AsyncMock
            ) as mock_run_worker,
        ):
            mock_saver_cls.from_conn_string.return_value = mock_checkpointer
            await consumer.run_worker_pool()

        assert mock_run_worker.call_count == settings.WORKER_COUNT

    async def test_pool_uses_postgres_checkpointer(self) -> None:
        """run_worker_pool passes AsyncPostgresSaver to build_graph."""
        mock_checkpointer = AsyncMock()
        mock_checkpointer.__aenter__ = AsyncMock(return_value=mock_checkpointer)
        mock_checkpointer.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("src.workers.consumer.AsyncPostgresSaver") as mock_saver_cls,
            patch(
                "src.workers.consumer.build_graph", return_value=MagicMock()
            ) as mock_build,
            patch("src.workers.consumer.run_worker", new_callable=AsyncMock),
        ):
            mock_saver_cls.from_conn_string.return_value = mock_checkpointer
            await consumer.run_worker_pool()

        mock_build.assert_called_once_with(checkpointer=mock_checkpointer)

    async def test_pool_calls_checkpointer_setup(self) -> None:
        """run_worker_pool calls setup() on the checkpointer to create PG tables."""
        mock_checkpointer = AsyncMock()
        mock_checkpointer.__aenter__ = AsyncMock(return_value=mock_checkpointer)
        mock_checkpointer.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("src.workers.consumer.AsyncPostgresSaver") as mock_saver_cls,
            patch("src.workers.consumer.build_graph", return_value=MagicMock()),
            patch("src.workers.consumer.run_worker", new_callable=AsyncMock),
        ):
            mock_saver_cls.from_conn_string.return_value = mock_checkpointer
            await consumer.run_worker_pool()

        mock_checkpointer.setup.assert_awaited_once()


# ── fetch_recent_nvd_cves ─────────────────────────────────────────────────────

class TestFetchRecentNvdCves:
    async def test_parses_nvd_response_into_secure_events(self) -> None:
        """Successful NVD API response is parsed into a SecureEvent list."""
        from src.workers.batch_ingest import fetch_recent_nvd_cves

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-9999",
                        "descriptions": [{"lang": "en", "value": "Critical RCE"}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                        "published": "2024-01-15T00:00:00.000",
                    }
                }
            ]
        }

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("src.workers.batch_ingest.httpx.AsyncClient", return_value=mock_client):
            events = await fetch_recent_nvd_cves(days_back=1)

        assert len(events) == 1
        assert "CVE-2024-9999" in events[0].title

    async def test_returns_empty_list_for_no_results(self) -> None:
        """Empty NVD response produces an empty list without error."""
        from src.workers.batch_ingest import fetch_recent_nvd_cves

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"vulnerabilities": []}

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("src.workers.batch_ingest.httpx.AsyncClient", return_value=mock_client):
            events = await fetch_recent_nvd_cves(days_back=1)

        assert events == []

    async def test_ssrf_guard_is_called_before_http_request(self) -> None:
        """SSRFGuard.check() is invoked before any HTTP call is made."""
        from src.workers import batch_ingest

        with patch.object(
            batch_ingest._ssrf_guard, "check", new_callable=AsyncMock
        ) as mock_check:
            from src.security.guardrails.base import GuardrailResult

            mock_check.return_value = GuardrailResult(passed=True)

            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            mock_resp.json.return_value = {"vulnerabilities": []}
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_resp)

            with patch("src.workers.batch_ingest.httpx.AsyncClient", return_value=mock_client):
                await batch_ingest.fetch_recent_nvd_cves(days_back=1)

        mock_check.assert_awaited_once()

    async def test_ssrf_guard_block_raises_value_error(self) -> None:
        """A blocked SSRFGuard result raises ValueError before any HTTP call."""
        from src.security.guardrails.base import GuardrailResult
        from src.workers import batch_ingest

        with patch.object(
            batch_ingest._ssrf_guard, "check", new_callable=AsyncMock
        ) as mock_check:
            mock_check.return_value = GuardrailResult(
                passed=False, blocked_reason="SSRF blocked: test"
            )
            with pytest.raises(ValueError, match="SSRFGuard"):
                await batch_ingest.fetch_recent_nvd_cves(days_back=1)

    async def test_sets_api_key_header_when_configured(self) -> None:
        """NVD_API_KEY is forwarded as a request header when set."""
        from src.workers.batch_ingest import fetch_recent_nvd_cves

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"vulnerabilities": []}
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        with (
            patch("src.workers.batch_ingest.httpx.AsyncClient", return_value=mock_client),
            patch.object(settings, "NVD_API_KEY", "test-nvd-key"),
        ):
            await fetch_recent_nvd_cves(days_back=1)

        call_kwargs = mock_client.get.call_args[1]
        assert call_kwargs["headers"]["apiKey"] == "test-nvd-key"


# ── run_batch_ingest ──────────────────────────────────────────────────────────

class TestRunBatchIngest:
    async def test_publishes_one_event_per_cve(self) -> None:
        """run_batch_ingest calls publish() exactly once per fetched CVE."""
        from src.core.schema import EventSourceType, SecureEvent, SeverityLevel
        from src.workers.batch_ingest import run_batch_ingest

        mock_events = [
            SecureEvent(
                source_type=EventSourceType.CVE,
                source_name="NVD",
                severity=SeverityLevel.HIGH,
                title="CVE-2024-0001: RCE in test lib",
                description="Remote code execution",
            ),
            SecureEvent(
                source_type=EventSourceType.CVE,
                source_name="NVD",
                severity=SeverityLevel.MEDIUM,
                title="CVE-2024-0002: XSS in test app",
                description="Cross-site scripting",
            ),
        ]

        with (
            patch(
                "src.workers.batch_ingest.fetch_recent_nvd_cves",
                new_callable=AsyncMock,
                return_value=mock_events,
            ),
            patch(
                "src.workers.batch_ingest.publish", new_callable=AsyncMock
            ) as mock_publish,
        ):
            await run_batch_ingest()

        assert mock_publish.call_count == 2

    async def test_publishes_nothing_when_no_cves(self) -> None:
        """run_batch_ingest publishes nothing when NVD returns zero results."""
        from src.workers.batch_ingest import run_batch_ingest

        with (
            patch(
                "src.workers.batch_ingest.fetch_recent_nvd_cves",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "src.workers.batch_ingest.publish", new_callable=AsyncMock
            ) as mock_publish,
        ):
            await run_batch_ingest()

        mock_publish.assert_not_awaited()
