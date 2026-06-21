"""Immutable audit log persistence to PostgreSQL.

Every agent action is accumulated append-only into ThreatState.audit_trail
(operator.add reducer). At the reporter node the full trail is flushed to the
audit_entries table via a single async transaction.

Table schema: Alembic migration 001_create_audit_entries (run
``uv run alembic upgrade head`` before first use).

Threat classes served:
  Every action leaves a permanent, tamper-evident record — required for
  security incident forensics and compliance (audit trail principle #4).
"""
from __future__ import annotations

import json
from typing import Any

import structlog
from sqlalchemy import text

from src.core.schema import AuditEntry
from src.db.engine import get_engine

logger = structlog.get_logger(__name__)


async def flush_audit_trail(
    trail: list[dict[str, Any]],
    event_id: str,
) -> None:
    """Persist a full audit trail list to the audit_entries table.

    Called once per graph run from reporter_node after the pipeline completes.
    All entries are written in a single transaction — either all succeed or
    none do (append-only atomicity).

    Args:
        trail: The accumulated ``ThreatState["audit_trail"]`` list.
        event_id: The event UUID; used as fallback when an entry omits it.
    """
    if not trail:
        return

    engine = get_engine()
    insert_sql = text(
        """
        INSERT INTO audit_entries (event_id, actor, action, detail)
        VALUES (:event_id, :actor, :action, :detail::jsonb)
        """
    )

    rows = [
        {
            "event_id": entry.get("event_id") or event_id,
            "actor": entry.get("actor", "unknown"),
            "action": entry.get("action", "unknown"),
            "detail": json.dumps(entry.get("detail", {})),
        }
        for entry in trail
    ]

    async with engine.begin() as conn:
        await conn.execute(insert_sql, rows)

    logger.info(
        "audit_trail_flushed",
        event_id=event_id,
        entries=len(rows),
    )


async def append_audit_entry(entry: AuditEntry) -> None:
    """Persist a single AuditEntry to the audit_entries table.

    Used outside the graph (e.g. from API middleware for auth events).
    """
    engine = get_engine()
    insert_sql = text(
        """
        INSERT INTO audit_entries (event_id, actor, action, detail)
        VALUES (:event_id, :actor, :action, :detail::jsonb)
        """
    )
    async with engine.begin() as conn:
        await conn.execute(
            insert_sql,
            {
                "event_id": entry.event_id,
                "actor": entry.actor,
                "action": entry.action,
                "detail": json.dumps(entry.detail),
            },
        )
    logger.debug(
        "audit_entry_written",
        event_id=entry.event_id,
        actor=entry.actor,
        action=entry.action,
    )
