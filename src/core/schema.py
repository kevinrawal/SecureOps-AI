"""Core data contracts for SecureOps AI.

Everything downstream pivots on these types:

* :class:`SecureEvent` — the normalized, source-agnostic representation of any
  security event. Agents, RAG, audit, and the API all speak this schema; raw
  source payloads never travel past ingestion.
* :class:`ThreatState` — the LangGraph working memory carried node-to-node.
* :class:`AuditEntry` — one immutable audit-log record.
* The enums (:class:`EventSourceType`, :class:`SeverityLevel`, :class:`Role`).
"""

from __future__ import annotations

import operator
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Optional, TypedDict

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class EventSourceType(str, Enum):
    """Category of the originating security source."""

    CVE = "CVE"
    SIEM_ALERT = "SIEM_ALERT"
    SYSLOG = "SYSLOG"
    AUTH = "AUTH"
    NETWORK = "NETWORK"
    CLOUD = "CLOUD"


class SeverityLevel(str, Enum):
    """Normalized severity, ordered CRITICAL (worst) → INFO (lowest)."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Role(str, Enum):
    """RBAC roles. ADMIN ⊃ ENGINEER ⊃ ANALYST in privilege (enforced in M7)."""

    ANALYST = "ANALYST"
    ENGINEER = "ENGINEER"
    ADMIN = "ADMIN"


# ---------------------------------------------------------------------------
# SecureEvent — the universal normalized contract
# ---------------------------------------------------------------------------
def _new_event_id() -> str:
    """Return a fresh UUID4 string for a newly ingested event."""
    return str(uuid.uuid4())


def _utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


class SecureEvent(BaseModel):
    """A single security event normalized to the platform's common shape.

    Adapters (``src/ingestion/adapters``) are the only producers of this type.
    ``raw_data`` preserves the original payload verbatim for forensics/audit but
    is quarantined — agents read normalized fields (notably ``description``),
    never ``raw_data`` directly.
    """

    event_id: str = Field(default_factory=_new_event_id)
    timestamp: datetime = Field(default_factory=_utc_now)
    source_type: EventSourceType
    source_name: str
    severity: SeverityLevel = SeverityLevel.INFO
    title: str
    description: str = ""
    affected_assets: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# ThreatState — LangGraph working memory (filled across M5–M6)
# ---------------------------------------------------------------------------
class ThreatState(TypedDict, total=False):
    """Mutable state threaded through the LangGraph agent pipeline.

    ``audit_trail`` uses the ``operator.add`` reducer so node contributions
    accumulate append-only (immutable audit semantics inside the graph).
    """

    # Input
    event_id: str
    secure_event: dict[str, Any]      # serialized SecureEvent
    user_id: str
    role: str                          # Role value

    # Processing state
    sanitized_description: str         # post injection-check
    injection_blocked: bool
    retrieved_docs: list[dict[str, Any]]
    retrieval_score: float             # 0.0–1.0 from grader
    rewrite_count: int                 # loop guard, max 2
    rewritten_query: str

    # Output
    severity: str
    remediation_steps: list[str]
    human_approved: Optional[bool]
    report: Optional[dict[str, Any]]

    # Immutable append-only audit trail
    audit_trail: Annotated[list[dict[str, Any]], operator.add]


# ---------------------------------------------------------------------------
# AuditEntry — one immutable audit-log record (persisted in M7)
# ---------------------------------------------------------------------------
class AuditEntry(BaseModel):
    """An append-only audit record describing one actor action on one event."""

    entry_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=_utc_now)
    event_id: str
    actor: str                         # user_id or agent/node name
    action: str                        # e.g. "retrieve", "grade", "approve"
    detail: dict[str, Any] = Field(default_factory=dict)
