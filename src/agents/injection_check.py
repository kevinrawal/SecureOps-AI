"""Agent node: prompt-injection check + PII masking.

This node runs before any LLM sees external data — it is not optional and
cannot be bypassed (design principle #4, security-by-design).

Two guardrails run in order:
  1. InjectionCheck (L1 regex + optional L2 LLM judge) — blocks adversarial input.
  2. PIIMasker — redacts PII from the description before it reaches any LLM,
     addressing Sensitive Information Disclosure and Cross-User Context Leakage.

L2 is enabled when ``settings.INJECTION_L2_ENABLED`` is True (default: False).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog

from src.core.config import settings
from src.core.schema import ThreatState
from src.security.guardrails.injection import InjectionCheck
from src.security.guardrails.pii_masker import PIIMasker

logger = structlog.get_logger(__name__)

_checker = InjectionCheck(l2_enabled=getattr(settings, "INJECTION_L2_ENABLED", False))
_masker = PIIMasker()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def injection_check_node(state: ThreatState) -> dict[str, Any]:
    """Run injection check then PII masking on the event description.

    Order:
        1. InjectionCheck — block and halt pipeline on adversarial input.
        2. PIIMasker — redact PII from clean input before LLM sees it.

    Reads ``state["secure_event"]["description"]`` and writes:
        sanitized_description: PII-masked description, or empty string if blocked.
        injection_blocked: True when an injection was detected.
        rewrite_count: initialised to 0 on first entry.
        audit_trail: one entry recording the check outcome.
    """
    secure_event: dict[str, Any] = state.get("secure_event", {})
    description: str = secure_event.get("description", "")
    event_id: str = state.get("event_id", secure_event.get("event_id", ""))

    injection_result = await _checker.check({"text": description})
    blocked = not injection_result.passed

    if blocked:
        logger.warning(
            "injection_blocked",
            event_id=event_id,
            reason=injection_result.blocked_reason,
            detail=injection_result.detail,
        )
        return {
            "injection_blocked": True,
            "sanitized_description": "",
            "rewrite_count": state.get("rewrite_count", 0),
            "audit_trail": [
                {
                    "actor": "agent:injection_check",
                    "action": "injection_blocked",
                    "timestamp": _now_iso(),
                    "detail": injection_result.detail,
                }
            ],
        }

    pii_ctx: dict[str, Any] = {"text": description}
    await _masker.check(pii_ctx)
    clean_description: str = pii_ctx["masked_text"]
    pii_detected: list[str] = pii_ctx["pii_detected"]

    if pii_detected:
        logger.info(
            "pii_masked_in_description",
            event_id=event_id,
            patterns=pii_detected,
        )
    logger.info("injection_check_passed", event_id=event_id)

    return {
        "injection_blocked": False,
        "sanitized_description": clean_description,
        "rewrite_count": state.get("rewrite_count", 0),
        "audit_trail": [
            {
                "actor": "agent:injection_check",
                "action": "injection_check_passed",
                "timestamp": _now_iso(),
                "detail": {"pii_masked": pii_detected} if pii_detected else {},
            }
        ],
    }
