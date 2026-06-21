"""Integration tests for M9 API layer.

Uses httpx.AsyncClient with ASGITransport to exercise routes without starting a
real server. Heavy dependencies (Redis, Pinecone, PostgreSQL) are mocked so tests
run offline. The lifespan is bypassed via ASGITransport (no startup hooks fire).
"""
from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from src.core.schema import Role
from src.security.rbac import create_access_token


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def analyst_token() -> str:
    return create_access_token("test-analyst", Role.ANALYST)


@pytest.fixture()
def engineer_token() -> str:
    return create_access_token("test-engineer", Role.ENGINEER)


@pytest.fixture()
def admin_token() -> str:
    return create_access_token("test-admin", Role.ADMIN)


@pytest.fixture()
async def client():
    """Async HTTP client backed by the FastAPI app (no real server, no lifespan)."""
    from src.api.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c


# ── /auth/token ───────────────────────────────────────────────────────────────

class TestAuthToken:
    async def test_valid_credentials_return_jwt(self, client: AsyncClient) -> None:
        """POST /auth/token with valid credentials returns a bearer token."""
        response = await client.post(
            "/auth/token",
            data={"username": "analyst", "password": "analyst"},
        )
        assert response.status_code == 200
        body = response.json()
        assert "access_token" in body
        assert body["token_type"] == "bearer"

    async def test_invalid_credentials_return_401(self, client: AsyncClient) -> None:
        """POST /auth/token with wrong password returns 401."""
        response = await client.post(
            "/auth/token",
            data={"username": "analyst", "password": "wrong"},
        )
        assert response.status_code == 401

    async def test_unknown_user_returns_401(self, client: AsyncClient) -> None:
        """POST /auth/token with unknown username returns 401."""
        response = await client.post(
            "/auth/token",
            data={"username": "ghost", "password": "ghost"},
        )
        assert response.status_code == 401

    async def test_token_is_decodable(self, client: AsyncClient) -> None:
        """The returned JWT can be decoded and contains expected claims."""
        from src.security.rbac import decode_jwt_token

        response = await client.post(
            "/auth/token",
            data={"username": "engineer", "password": "engineer"},
        )
        token = response.json()["access_token"]
        payload = decode_jwt_token(token)
        assert payload["sub"] == "engineer"
        assert payload["role"] == Role.ENGINEER.value


# ── POST /events/ingest ───────────────────────────────────────────────────────

class TestEventsIngest:
    async def test_ingest_returns_202_with_event_id(
        self, client: AsyncClient, analyst_token: str
    ) -> None:
        """POST /events/ingest normalises and enqueues the event."""
        mock_event = MagicMock()
        mock_event.event_id = "evt-test-001"

        with (
            patch(
                "src.api.routes.events._normalizer.normalize",
                new_callable=AsyncMock,
                return_value=mock_event,
            ),
            patch(
                "src.api.routes.events.publish",
                new_callable=AsyncMock,
            ),
        ):
            response = await client.post(
                "/events/ingest",
                json={
                    "source_type": "SIEM_ALERT",
                    "data": {"title": "SSH brute force", "host": "web-01"},
                },
                headers={"Authorization": f"Bearer {analyst_token}"},
            )

        assert response.status_code == 202
        body = response.json()
        assert body["event_id"] == "evt-test-001"
        assert body["queued"] is True

    async def test_ingest_without_token_returns_401(
        self, client: AsyncClient
    ) -> None:
        """POST /events/ingest with no Authorization header returns 401."""
        response = await client.post(
            "/events/ingest",
            json={"source_type": "SIEM_ALERT", "data": {}},
        )
        assert response.status_code == 401

    async def test_ingest_blocks_ssrf_url_in_payload(
        self, client: AsyncClient, analyst_token: str
    ) -> None:
        """POST /events/ingest blocks payloads containing internal SSRF URLs."""
        response = await client.post(
            "/events/ingest",
            json={
                "source_type": "SIEM_ALERT",
                "data": {"callback": "http://169.254.169.254/latest/meta-data/"},
            },
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert response.status_code == 400
        assert "SSRF" in response.json()["detail"]

    async def test_ingest_blocks_private_ip_url(
        self, client: AsyncClient, analyst_token: str
    ) -> None:
        """POST /events/ingest blocks RFC1918 addresses in payload URLs."""
        response = await client.post(
            "/events/ingest",
            json={
                "source_type": "SIEM_ALERT",
                "data": {"webhook": "http://10.0.0.1/internal"},
            },
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert response.status_code == 400

    async def test_ingest_unknown_source_type_returns_422(
        self, client: AsyncClient, analyst_token: str
    ) -> None:
        """POST /events/ingest with an unknown source_type returns 422."""
        response = await client.post(
            "/events/ingest",
            json={"source_type": "UNKNOWN_SOURCE", "data": {"key": "value"}},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert response.status_code == 422

    async def test_ingest_allows_public_url_in_payload(
        self, client: AsyncClient, analyst_token: str
    ) -> None:
        """POST /events/ingest allows public URLs in the payload (not SSRF)."""
        mock_event = MagicMock()
        mock_event.event_id = "evt-public"

        with (
            patch(
                "src.api.routes.events._normalizer.normalize",
                new_callable=AsyncMock,
                return_value=mock_event,
            ),
            patch("src.api.routes.events.publish", new_callable=AsyncMock),
        ):
            response = await client.post(
                "/events/ingest",
                json={
                    "source_type": "CVE",
                    "data": {"reference": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"},
                },
                headers={"Authorization": f"Bearer {analyst_token}"},
            )

        assert response.status_code == 202


# ── GET /events/{event_id} ────────────────────────────────────────────────────

class TestGetEvent:
    async def test_returns_queued_when_no_audit_entries(
        self, client: AsyncClient, analyst_token: str
    ) -> None:
        """GET /events/{id} returns 'queued' when no audit entries exist."""
        mock_conn = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchall.return_value = []
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)
        mock_conn.execute = AsyncMock(return_value=mock_result)

        with patch("src.api.routes.events.get_engine") as mock_engine:
            mock_engine.return_value.connect.return_value = mock_conn
            response = await client.get(
                "/events/evt-missing-001",
                headers={"Authorization": f"Bearer {analyst_token}"},
            )

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "queued"
        assert body["event_id"] == "evt-missing-001"

    async def test_requires_auth(self, client: AsyncClient) -> None:
        """GET /events/{id} requires authentication."""
        response = await client.get("/events/some-id")
        assert response.status_code == 401


# ── POST /threats/{event_id}/approve ─────────────────────────────────────────

class TestThreatsApprove:
    async def test_requires_engineer_role(
        self, client: AsyncClient, analyst_token: str
    ) -> None:
        """POST /threats/{id}/approve rejects ANALYST token with 403."""
        response = await client.post(
            "/threats/evt-001/approve",
            json={"approved": True, "reviewer_id": "alice"},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert response.status_code == 403

    async def test_engineer_can_approve(
        self, client: AsyncClient, engineer_token: str
    ) -> None:
        """POST /threats/{id}/approve succeeds with ENGINEER token."""
        mock_report = {"report_id": "rpt-001", "title": "SSH brute force"}

        with patch(
            "src.api.routes.threats._graph.ainvoke",
            new_callable=AsyncMock,
            return_value={"report": mock_report},
        ):
            response = await client.post(
                "/threats/evt-001/approve",
                json={"approved": True, "reviewer_id": "engineer-alice"},
                headers={"Authorization": f"Bearer {engineer_token}"},
            )

        assert response.status_code == 200
        body = response.json()
        assert body["event_id"] == "evt-001"
        assert body["report"] == mock_report

    async def test_unauthenticated_returns_401(self, client: AsyncClient) -> None:
        """POST /threats/{id}/approve requires authentication."""
        response = await client.post(
            "/threats/evt-001/approve",
            json={"approved": True},
        )
        assert response.status_code == 401


# ── /runbooks ─────────────────────────────────────────────────────────────────

class TestRunbooks:
    async def test_create_runbook_requires_admin(
        self, client: AsyncClient, analyst_token: str
    ) -> None:
        """POST /runbooks rejects ANALYST token with 403."""
        response = await client.post(
            "/runbooks",
            json={"title": "SSH runbook", "text": "content here"},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert response.status_code == 403

    async def test_admin_can_create_runbook(
        self, client: AsyncClient, admin_token: str
    ) -> None:
        """POST /runbooks succeeds with ADMIN token and returns vector ID."""
        with patch(
            "src.api.routes.runbooks.upsert_runbook",
            new_callable=AsyncMock,
            return_value="vec-abc123",
        ):
            response = await client.post(
                "/runbooks",
                json={"title": "SSH Brute Force Runbook", "text": "Isolate the host..."},
                headers={"Authorization": f"Bearer {admin_token}"},
            )

        assert response.status_code == 201
        body = response.json()
        assert body["id"] == "vec-abc123"
        assert body["title"] == "SSH Brute Force Runbook"

    async def test_analyst_can_list_runbooks(
        self, client: AsyncClient, analyst_token: str
    ) -> None:
        """GET /runbooks is accessible to ANALYST role."""
        mock_results = [
            {"id": "vec-1", "score": 0.9, "text": "content", "metadata": {"title": "Log4Shell"}},
        ]
        with patch(
            "src.api.routes.runbooks.pinecone_query",
            new_callable=AsyncMock,
            return_value=mock_results,
        ):
            response = await client.get(
                "/runbooks",
                headers={"Authorization": f"Bearer {analyst_token}"},
            )

        assert response.status_code == 200
        body = response.json()
        assert "runbooks" in body
        assert body["count"] == 1

    async def test_delete_runbook_requires_admin(
        self, client: AsyncClient, analyst_token: str
    ) -> None:
        """DELETE /runbooks/{id} rejects ANALYST token with 403."""
        response = await client.delete(
            "/runbooks/vec-001",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert response.status_code == 403

    async def test_admin_can_delete_runbook(
        self, client: AsyncClient, admin_token: str
    ) -> None:
        """DELETE /runbooks/{id} succeeds with ADMIN token."""
        mock_index = MagicMock()
        with (
            patch(
                "src.api.routes.runbooks.init_pinecone",
                new_callable=AsyncMock,
                return_value=mock_index,
            ),
            patch("src.api.routes.runbooks.asyncio.to_thread", new_callable=AsyncMock),
        ):
            response = await client.delete(
                "/runbooks/vec-001",
                headers={"Authorization": f"Bearer {admin_token}"},
            )

        assert response.status_code == 204


# ── GET /health ───────────────────────────────────────────────────────────────

class TestHealth:
    async def test_health_returns_200_always(self, client: AsyncClient) -> None:
        """GET /health always returns 200 regardless of component status."""
        with (
            patch(
                "src.api.routes.health._check_postgres",
                new_callable=AsyncMock,
                return_value="ok",
            ),
            patch(
                "src.api.routes.health._check_redis",
                new_callable=AsyncMock,
                return_value="ok",
            ),
            patch(
                "src.api.routes.health._check_pinecone",
                new_callable=AsyncMock,
                return_value="ok",
            ),
        ):
            response = await client.get("/health")

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["checks"]["postgres"] == "ok"
        assert body["checks"]["redis"] == "ok"
        assert body["checks"]["pinecone"] == "ok"

    async def test_health_reports_degraded_on_component_failure(
        self, client: AsyncClient
    ) -> None:
        """GET /health returns status='degraded' when any component is down."""
        with (
            patch(
                "src.api.routes.health._check_postgres",
                new_callable=AsyncMock,
                return_value="error: connection refused",
            ),
            patch(
                "src.api.routes.health._check_redis",
                new_callable=AsyncMock,
                return_value="ok",
            ),
            patch(
                "src.api.routes.health._check_pinecone",
                new_callable=AsyncMock,
                return_value="ok",
            ),
        ):
            response = await client.get("/health")

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "degraded"
        assert "error" in body["checks"]["postgres"]

    async def test_health_no_auth_required(self, client: AsyncClient) -> None:
        """GET /health is a public endpoint — no token needed."""
        with (
            patch(
                "src.api.routes.health._check_postgres",
                new_callable=AsyncMock,
                return_value="ok",
            ),
            patch(
                "src.api.routes.health._check_redis",
                new_callable=AsyncMock,
                return_value="ok",
            ),
            patch(
                "src.api.routes.health._check_pinecone",
                new_callable=AsyncMock,
                return_value="ok",
            ),
        ):
            response = await client.get("/health")

        assert response.status_code == 200


# ── RBAC cross-cutting tests ──────────────────────────────────────────────────

class TestRBACEnforcement:
    async def test_expired_token_returns_401(self, client: AsyncClient) -> None:
        """A tampered/invalid JWT returns 401."""
        response = await client.post(
            "/events/ingest",
            json={"source_type": "SIEM_ALERT", "data": {}},
            headers={"Authorization": "Bearer not.a.real.token"},
        )
        assert response.status_code == 401

    async def test_engineer_can_ingest_events(
        self, client: AsyncClient, engineer_token: str
    ) -> None:
        """ENGINEER role satisfies the ANALYST minimum for /events/ingest."""
        mock_event = MagicMock()
        mock_event.event_id = "evt-eng-001"

        with (
            patch(
                "src.api.routes.events._normalizer.normalize",
                new_callable=AsyncMock,
                return_value=mock_event,
            ),
            patch("src.api.routes.events.publish", new_callable=AsyncMock),
        ):
            response = await client.post(
                "/events/ingest",
                json={"source_type": "SIEM_ALERT", "data": {"title": "test"}},
                headers={"Authorization": f"Bearer {engineer_token}"},
            )

        assert response.status_code == 202

    async def test_admin_can_ingest_events(
        self, client: AsyncClient, admin_token: str
    ) -> None:
        """ADMIN role satisfies the ANALYST minimum for /events/ingest."""
        mock_event = MagicMock()
        mock_event.event_id = "evt-adm-001"

        with (
            patch(
                "src.api.routes.events._normalizer.normalize",
                new_callable=AsyncMock,
                return_value=mock_event,
            ),
            patch("src.api.routes.events.publish", new_callable=AsyncMock),
        ):
            response = await client.post(
                "/events/ingest",
                json={"source_type": "SIEM_ALERT", "data": {"title": "test"}},
                headers={"Authorization": f"Bearer {admin_token}"},
            )

        assert response.status_code == 202
