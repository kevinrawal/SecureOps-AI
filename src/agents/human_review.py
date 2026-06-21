"""Agent node: human-in-the-loop review via LangGraph interrupt.

For CRITICAL severity events, the graph suspends here and waits for a human
reviewer to approve or reject the AI-generated remediation steps.

Mechanism:
  interrupt() from langgraph.types suspends graph execution and returns control
  to the caller. The caller notifies the reviewer, collects a decision, then
  resumes the graph with:
      graph.ainvoke(Command(resume={"approved": bool, "reviewer_id": str}), config)

  The return value of interrupt() becomes the resume payload, which is used to
  set state["human_approved"].

Requires a checkpointer (e.g. MemorySaver or AsyncPostgresSaver) to be attached
to the compiled graph - without one, interrupt() raises a runtime error.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog
from langgraph.types import interrupt

from src.core.schema import Role, ThreatState
from src.security.rbac import assert_graph_role

logger = structlog.get_logger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def human_review_node(state: ThreatState) -> dict[str, Any]:
    """Suspend graph execution for human approval of remediation steps.

    The interrupt payload is visible to the reviewer in the graph state.
    Resume with Command(resume={"approved": True/False, "reviewer_id": "<id>"}).

    Writes: ``human_approved`` and one ``audit_trail`` entry.
    """
    assert_graph_role(state, Role.ANALYST)

    event_id: str = state.get("event_id", "")
    secure_event: dict[str, Any] = state.get("secure_event", {})

    payload = {
        "event_id": event_id,
        "title": secure_event.get("title", ""),
        "severity": state.get("severity", "CRITICAL"),
        "remediation_steps": state.get("remediation_steps", []),
        "retrieval_score": state.get("retrieval_score", 0.0),
        "message": (
            "CRITICAL event requires human approval before report generation. "
            "Resume with: Command(resume={'approved': True/False, "
            "'reviewer_id': '<your-id>'})"
        ),
    }

    logger.info("human_review_interrupt", event_id=event_id)
    resume_value = interrupt(payload)

    approved: bool = False
    reviewer_id: str = "human"
    if isinstance(resume_value, dict):
        approved = bool(resume_value.get("approved", False))
        reviewer_id = resume_value.get("reviewer_id", "human")
    else:
        approved = bool(resume_value)

    logger.info(
        "human_review_resumed",
        event_id=event_id,
        approved=approved,
        reviewer_id=reviewer_id,
    )

    return {
        "human_approved": approved,
        "audit_trail": [
            {
                "actor": reviewer_id,
                "action": "human_approved" if approved else "human_rejected",
                "timestamp": _now_iso(),
                "detail": {"event_id": event_id, "approved": approved},
            }
        ],
    }
