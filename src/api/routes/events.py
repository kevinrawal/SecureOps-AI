"""Routes: POST /events/ingest, GET /events/{event_id}."""
from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import text

from src.api.limiter import limiter
from src.core.schema import Role
from src.db.engine import get_engine
from src.ingestion.normalizer import Normalizer
from src.ingestion.producer import publish
from src.security.guardrails.ssrf_guard import SSRFGuard
from src.security.rbac import require_role

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/events", tags=["events"])

_normalizer = Normalizer()
_ssrf_guard = SSRFGuard()

_URL_PREFIXES = ("http://", "https://", "file://", "ftp://", "gopher://")


class IngestRequest(BaseModel):
    """Payload for POST /events/ingest."""

    source_type: str
    data: dict[str, Any]


class IngestResponse(BaseModel):
    """Response body for POST /events/ingest."""

    event_id: str
    queued: bool


def _extract_url_values(data: dict[str, Any]) -> list[str]:
    """Return all string values from ``data`` that look like URLs (top-level only)."""
    return [
        v for v in data.values()
        if isinstance(v, str) and v.startswith(_URL_PREFIXES)
    ]


@router.post(
    "/ingest",
    response_model=IngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
@limiter.limit("100/minute")
async def ingest_event(
    request: Request,
    body: IngestRequest,
    _auth: dict[str, Any] = Depends(require_role(Role.ANALYST)),
) -> IngestResponse:
    """Normalise a raw security event payload and publish it to the Redis Stream.

    SSRFGuard scans all URL-like string values in ``data`` before normalisation.
    Blocked URLs return HTTP 400. Unknown ``source_type`` returns HTTP 422.

    Returns HTTP 202 Accepted with the assigned ``event_id``.
    """
    for url in _extract_url_values(body.data):
        guard_result = await _ssrf_guard.check({"url": url})
        if not guard_result.passed:
            logger.warning("ssrf_blocked_at_ingest", url=url[:200], reason=guard_result.blocked_reason)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=guard_result.blocked_reason,
            )

    try:
        event = await _normalizer.normalize(body.data, body.source_type)
    except (ValueError, KeyError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )

    await publish(event)
    logger.info("event_ingested", event_id=event.event_id, source_type=body.source_type)
    return IngestResponse(event_id=event.event_id, queued=True)


@router.get("/{event_id}")
async def get_event(
    event_id: str,
    _auth: dict[str, Any] = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Return the processing status for an event by querying the audit log.

    Status values:
        ``queued``      — event published but not yet processed by a worker.
        ``processing``  — workers have started but not completed.
        ``completed``   — reporter_node has run; report is in the audit trail.
    """
    async with get_engine().connect() as conn:
        result = await conn.execute(
            text(
                "SELECT action, timestamp FROM audit_entries "
                "WHERE event_id = :eid ORDER BY timestamp ASC"
            ),
            {"eid": event_id},
        )
        rows = result.fetchall()

    if not rows:
        return {"event_id": event_id, "status": "queued", "actions": []}

    actions = [
        {"action": r.action, "timestamp": r.timestamp.isoformat()}
        for r in rows
    ]
    last_action = rows[-1].action
    processing_status = "completed" if last_action == "report_generated" else "processing"
    return {"event_id": event_id, "status": processing_status, "actions": actions}
