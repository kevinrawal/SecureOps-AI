"""Agent node: prompt-injection check (L1 regex + optional L2 LLM judge).

This node runs before any LLM sees external data — it is not optional and
cannot be bypassed (design principle #4, security-by-design).

Delegates to :class:`src.security.injection.InjectionCheck` which owns the
full 59-pattern L1 corpus and the L2 LLM judge. L2 is enabled when
``settings.INJECTION_L2_ENABLED`` is True (default: False, to avoid Groq
rate-limit burn on every event).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog

from src.core.config import settings
from src.core.schema import ThreatState
from src.security.injection import InjectionCheck

logger = structlog.get_logger(__name__)

_checker = InjectionCheck(l2_enabled=getattr(settings, "INJECTION_L2_ENABLED", False))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def injection_check_node(state: ThreatState) -> dict[str, Any]:
    """Run L1 (and optionally L2) injection check on the event description.

    Reads ``state["secure_event"]["description"]`` and writes:
        sanitized_description: clean description or empty string if blocked.
        injection_blocked: True when an injection was detected.
        rewrite_count: initialised to 0 on first entry.
        audit_trail: one entry recording the check outcome.
    """
    secure_event: dict[str, Any] = state.get("secure_event", {})
    description: str = secure_event.get("description", "")
    event_id: str = state.get("event_id", secure_event.get("event_id", ""))

    result = await _checker.check({"text": description})
    blocked = not result.passed

    if blocked:
        logger.warning(
            "injection_blocked",
            event_id=event_id,
            reason=result.blocked_reason,
            detail=result.detail,
        )
    else:
        logger.info("injection_check_passed", event_id=event_id)

    return {
        "injection_blocked": blocked,
        "sanitized_description": "" if blocked else description,
        "rewrite_count": state.get("rewrite_count", 0),
        "audit_trail": [
            {
                "actor": "agent:injection_check",
                "action": "injection_blocked" if blocked else "injection_check_passed",
                "timestamp": _now_iso(),
                "detail": result.detail if blocked else {},
            }
        ],
    }
