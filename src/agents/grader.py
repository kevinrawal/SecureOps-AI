"""Agent node: LLM-as-judge retrieval quality grading (0.0-1.0).

Uses the fast/cheap model (task="grading") to judge whether the retrieved
runbooks contain actionable guidance for the event. Returns a float score;
the router uses GRADE_PASS_THRESHOLD to decide whether to rewrite or proceed.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

import structlog
from langchain_core.messages import HumanMessage, SystemMessage

from src.core.models_factory import get_llm
from src.core.schema import ThreatState
from src.observability.langfuse_setup import get_langfuse_handler
from src.observability.metrics import GRADE_SCORE_HISTOGRAM, instrument_node

logger = structlog.get_logger(__name__)

GRADE_PASS_THRESHOLD: float = 0.7

_SYSTEM_PROMPT = """\
You are a security runbook relevance judge.
Given a security event description and a list of retrieved runbooks, rate how
well the runbooks cover the event on a scale of 0.0 to 1.0.

Scoring guide:
  1.0  The runbooks contain specific, directly applicable remediation steps.
  0.7  The runbooks are relevant and provide useful partial guidance.
  0.4  The runbooks are tangentially related but mostly off-topic.
  0.0  The runbooks are unrelated to the event.

Respond ONLY with valid JSON - no explanation outside the JSON object:
{"score": <float 0.0-1.0>, "reasoning": "<one sentence>"}"""

_USER_TEMPLATE = """\
Event: {title} - {description}

Retrieved runbooks:
{docs}"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _format_docs_for_grading(docs: list[dict[str, Any]]) -> str:
    if not docs:
        return "(no runbooks retrieved)"
    parts = []
    for i, doc in enumerate(docs, 1):
        title = doc.get("metadata", {}).get("title", f"Runbook {i}")
        snippet = doc.get("text", "")[:500]
        parts.append(f"[{i}] {title}: {snippet}")
    return "\n\n".join(parts)


def _parse_grade_response(content: str) -> tuple[float, str]:
    """Return (score, reasoning), fault-tolerant against malformed LLM output."""
    try:
        data = json.loads(content)
        score = float(data["score"])
        return max(0.0, min(1.0, score)), data.get("reasoning", "")
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        pass

    match = re.search(r"\b(1(\.0+)?|0(\.\d+)?)\b", content)
    if match:
        return float(match.group()), "score extracted from unstructured response"

    logger.warning("grade_parse_failed", content_snippet=content[:200])
    return 0.0, "failed to parse grader response"


@instrument_node("grade")
async def grade_node(state: ThreatState) -> dict[str, Any]:
    """Score the retrieved runbooks against the event description.

    Uses ``get_llm(task="grading")`` (fast/cheap model). The resulting
    ``retrieval_score`` drives the conditional edge in ``graph/routers.py``.
    Passes a Langfuse callback handler so every grading call is traced in
    the AI observability layer.

    Returns:
        Partial ThreatState with ``retrieval_score`` and one ``audit_trail`` entry.
    """
    secure_event: dict[str, Any] = state.get("secure_event", {})
    description: str = state.get("sanitized_description", "")
    docs: list[dict[str, Any]] = state.get("retrieved_docs", [])
    event_id: str = state.get("event_id", "")

    llm = get_llm(task="grading")
    user_msg = _USER_TEMPLATE.format(
        title=secure_event.get("title", ""),
        description=description[:1000],
        docs=_format_docs_for_grading(docs),
    )

    handler = get_langfuse_handler()
    callbacks = [handler] if handler else []

    response = await llm.ainvoke(
        [SystemMessage(content=_SYSTEM_PROMPT), HumanMessage(content=user_msg)],
        config={"callbacks": callbacks},
    )
    content = response.content if hasattr(response, "content") else str(response)
    score, reasoning = _parse_grade_response(content)

    GRADE_SCORE_HISTOGRAM.observe(score)

    logger.info(
        "grade_done",
        event_id=event_id,
        score=score,
        passed=score >= GRADE_PASS_THRESHOLD,
    )

    return {
        "retrieval_score": score,
        "audit_trail": [
            {
                "actor": "agent:grade",
                "action": "retrieval_graded",
                "timestamp": _now_iso(),
                "detail": {
                    "score": score,
                    "passed": score >= GRADE_PASS_THRESHOLD,
                    "reasoning": reasoning,
                    "rewrite_count": state.get("rewrite_count", 0),
                },
            }
        ],
    }
