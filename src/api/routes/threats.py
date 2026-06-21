"""Route: POST /threats/{event_id}/approve — resume a HITL-interrupted graph."""
from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command
from pydantic import BaseModel

from src.api.limiter import limiter
from src.core.schema import Role
from src.graph.builder import build_graph
from src.security.rbac import require_role

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/threats", tags=["threats"])

# In-process checkpointer for M9. M10 replaces this with AsyncPostgresSaver
# so state persists across process restarts and scales across workers.
_checkpointer = MemorySaver()
_graph = build_graph(checkpointer=_checkpointer)


class ApproveRequest(BaseModel):
    """Payload for POST /threats/{event_id}/approve."""

    approved: bool
    reviewer_id: str = "api-reviewer"


@router.post("/{event_id}/approve")
@limiter.limit("20/minute")
async def approve_threat(
    request: Request,
    event_id: str,
    body: ApproveRequest,
    auth: dict[str, Any] = Depends(require_role(Role.ENGINEER)),
) -> dict[str, Any]:
    """Resume a graph that was suspended at ``human_review_node`` for a CRITICAL event.

    The graph looks up its interrupted state by ``thread_id = event_id`` via the
    checkpointer. Pass ``approved=True`` to continue to report generation;
    ``approved=False`` terminates the pipeline without a report.

    Requires ENGINEER role — analysts may view events but cannot approve remediation.
    """
    config: dict[str, Any] = {"configurable": {"thread_id": event_id}}
    resume_payload = {"approved": body.approved, "reviewer_id": body.reviewer_id}

    logger.info(
        "hitl_approve_request",
        event_id=event_id,
        approved=body.approved,
        reviewer=body.reviewer_id,
        approver=auth.get("sub"),
    )

    try:
        result = await _graph.ainvoke(Command(resume=resume_payload), config=config)
    except Exception as exc:
        logger.error("hitl_resume_failed", event_id=event_id, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Graph resume failed: {exc}",
        )

    return {"event_id": event_id, "report": result.get("report")}
