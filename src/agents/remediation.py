"""Agent node: grounded remediation step generation.

Produces a numbered list of remediation steps that are grounded in the
retrieved runbooks. The LLM is instructed to cite sources and flag uncertainty
if retrieved docs are weak - it must not fabricate steps without grounding.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog
from langchain_core.messages import HumanMessage, SystemMessage

from src.core.models_factory import get_llm
from src.core.schema import ThreatState
from src.security.guardrails.output_filter import OutputFilter

logger = structlog.get_logger(__name__)

_output_filter = OutputFilter()

_SYSTEM_PROMPT = """\
You are a senior security incident responder. Your job is to produce a numbered
list of concrete remediation steps for a security event.

Rules:
1. Base every step on the provided runbooks. Cite the runbook name in brackets,
   e.g. "Isolate the affected host [log4shell runbook]."
2. If the runbooks do not cover a step, write "NOTE: No runbook guidance found
   for this step - manual review required."
3. Be specific and actionable. Avoid vague language like "monitor the system."
4. Return ONLY the numbered list - no preamble or summary."""

_USER_TEMPLATE = """\
Security Event:
  Title: {title}
  Severity: {severity}
  Description: {description}

Retrieved Runbooks:
{docs}

Provide the remediation steps:"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _format_docs(docs: list[dict[str, Any]]) -> str:
    if not docs:
        return "(no runbooks retrieved - proceed with caution)"
    parts = []
    for i, doc in enumerate(docs, 1):
        title = doc.get("metadata", {}).get("title", f"Runbook {i}")
        text = doc.get("text", "")[:2000]
        parts.append(f"--- [{i}] {title} ---\n{text}")
    return "\n\n".join(parts)


def _parse_steps(content: str) -> list[str]:
    """Split numbered list response into individual step strings."""
    lines = content.strip().splitlines()
    steps: list[str] = []
    current: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped[0].isdigit() and len(stripped) > 1 and stripped[1] in ".):":
            if current:
                steps.append(" ".join(current))
            current = [stripped]
        elif current:
            current.append(stripped)
        else:
            current = [stripped]
    if current:
        steps.append(" ".join(current))
    return steps or [content.strip()]


async def remediation_node(state: ThreatState) -> dict[str, Any]:
    """Generate grounded remediation steps from retrieved runbooks.

    Reads: ``secure_event``, ``sanitized_description``, ``retrieved_docs``.
    Writes: ``remediation_steps``, ``severity`` (surfaced from event).
    """
    secure_event: dict[str, Any] = state.get("secure_event", {})
    description: str = state.get("sanitized_description", "")
    docs: list[dict[str, Any]] = state.get("retrieved_docs", [])
    severity: str = secure_event.get("severity", "MEDIUM")
    event_id: str = state.get("event_id", "")

    llm = get_llm(task="default")

    user_msg = _USER_TEMPLATE.format(
        title=secure_event.get("title", ""),
        severity=severity,
        description=description[:1500],
        docs=_format_docs(docs),
    )
    response = await llm.ainvoke(
        [SystemMessage(content=_SYSTEM_PROMPT), HumanMessage(content=user_msg)]
    )
    content = response.content if hasattr(response, "content") else str(response)

    filter_result = await _output_filter.check({
        "llm_output": content,
        "retrieval_score": state.get("retrieval_score", 0.0),
    })
    if not filter_result.passed:
        logger.warning(
            "remediation_output_filtered",
            event_id=event_id,
            reason=filter_result.blocked_reason,
            detail=filter_result.detail,
        )
        content = f"[Output filtered: {filter_result.blocked_reason}]"

    steps = _parse_steps(content)

    logger.info(
        "remediation_done",
        event_id=event_id,
        severity=severity,
        step_count=len(steps),
    )

    return {
        "severity": severity,
        "remediation_steps": steps,
        "audit_trail": [
            {
                "actor": "agent:remediation",
                "action": "remediation_generated",
                "timestamp": _now_iso(),
                "detail": {
                    "step_count": len(steps),
                    "severity": severity,
                    "retrieval_score": state.get("retrieval_score", 0.0),
                },
            }
        ],
    }
