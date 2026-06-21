"""Agent node: structured incident report generation.

Aggregates all pipeline state into a final JSON report, writes it to
state["report"], and flushes the accumulated audit trail to PostgreSQL.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from src.core.schema import ThreatState
from src.observability.metrics import instrument_node
from src.security.audit import flush_audit_trail

logger = structlog.get_logger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _extract_sources(docs: list[dict[str, Any]]) -> list[str]:
    seen: set[str] = set()
    sources: list[str] = []
    for doc in docs:
        title = doc.get("metadata", {}).get("title", "")
        if title and title not in seen:
            seen.add(title)
            sources.append(title)
    return sources


@instrument_node("reporter")
async def reporter_node(state: ThreatState) -> dict[str, Any]:
    """Compile the final incident report and flush the audit trail to PostgreSQL.

    Reads all populated state fields. Writes ``report`` (structured dict) and
    appends one final audit entry for the report generation event itself.
    """
    secure_event: dict[str, Any] = state.get("secure_event", {})
    event_id: str = state.get("event_id", secure_event.get("event_id", ""))
    docs: list[dict[str, Any]] = state.get("retrieved_docs", [])

    report: dict[str, Any] = {
        "report_id": str(uuid.uuid4()),
        "event_id": event_id,
        "title": secure_event.get("title", ""),
        "severity": state.get("severity", secure_event.get("severity", "UNKNOWN")),
        "summary": (
            f"Security event '{secure_event.get('title', '')}' processed by "
            f"SecureOps AI pipeline. Retrieval score: "
            f"{state.get('retrieval_score', 0.0):.2f}. "
            f"Rewrite iterations: {state.get('rewrite_count', 0)}."
        ),
        "remediation_steps": state.get("remediation_steps", []),
        "sources": _extract_sources(docs),
        "retrieval_score": state.get("retrieval_score", 0.0),
        "rewrite_count": state.get("rewrite_count", 0),
        "human_approved": state.get("human_approved"),
        "generated_at": _now_iso(),
    }

    logger.info(
        "report_generated",
        event_id=event_id,
        report_id=report["report_id"],
        step_count=len(report["remediation_steps"]),
        human_approved=report["human_approved"],
    )

    reporter_entry: dict[str, Any] = {
        "actor": "agent:reporter",
        "action": "report_generated",
        "timestamp": _now_iso(),
        "detail": {"report_id": report["report_id"]},
    }

    trail: list[dict[str, Any]] = state.get("audit_trail", []) + [reporter_entry]
    try:
        await flush_audit_trail(trail, event_id)
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "audit_flush_failed",
            event_id=event_id,
            error=str(exc),
        )

    return {
        "report": report,
        "audit_trail": [reporter_entry],
    }
