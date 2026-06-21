"""Agent node: HyDE query rewriting when retrieval grade fails.

HyDE (Hypothetical Document Embedding): instead of re-querying with the raw
alert description, the LLM generates a *hypothetical runbook excerpt* that
would ideally match the event. Embedding that synthetic text and querying
Pinecone closes the vocabulary gap between alert language and runbook language.

Loop guard: rewrite_count is incremented here and checked by the router.
MAX_REWRITES = 2 is enforced in graph/routers.py, not inside this node.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog
from langchain_core.messages import HumanMessage, SystemMessage

from src.core.models_factory import get_llm
from src.core.schema import ThreatState
from src.observability.langfuse_setup import get_langfuse_handler
from src.observability.metrics import instrument_node

logger = structlog.get_logger(__name__)

_SYSTEM_PROMPT = """\
You are a cybersecurity expert. Your task is to help improve a vector search
query by generating a hypothetical runbook excerpt.

Given a security event, write a 3-5 sentence hypothetical runbook excerpt that
WOULD contain the ideal remediation steps for this event. Use technical language
typical of security runbooks. Do not explain what you are doing - just write
the hypothetical excerpt directly."""

_USER_TEMPLATE = """\
Security event:
Title: {title}
Description: {description}

Write a hypothetical runbook excerpt for this event:"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@instrument_node("rewrite")
async def rewrite_node(state: ThreatState) -> dict[str, Any]:
    """Generate a HyDE rewritten query to improve retrieval on the next attempt.

    Reads ``secure_event`` and ``sanitized_description``; writes
    ``rewritten_query`` and increments ``rewrite_count``.
    Passes a Langfuse callback handler so the HyDE generation call is traced
    in the AI observability layer.

    Returns:
        Partial ThreatState with updated ``rewritten_query``,
        ``rewrite_count``, and one ``audit_trail`` entry.
    """
    secure_event: dict[str, Any] = state.get("secure_event", {})
    description: str = state.get("sanitized_description", "")
    rewrite_count: int = state.get("rewrite_count", 0)
    event_id: str = state.get("event_id", "")

    llm = get_llm(task="default")

    user_msg = _USER_TEMPLATE.format(
        title=secure_event.get("title", ""),
        description=description[:1000],
    )

    handler = get_langfuse_handler()
    callbacks = [handler] if handler else []

    response = await llm.ainvoke(
        [SystemMessage(content=_SYSTEM_PROMPT), HumanMessage(content=user_msg)],
        config={"callbacks": callbacks},
    )
    rewritten = response.content if hasattr(response, "content") else str(response)
    new_count = rewrite_count + 1

    logger.info(
        "rewrite_done",
        event_id=event_id,
        rewrite_count=new_count,
        rewritten_snippet=rewritten[:100],
    )

    return {
        "rewritten_query": rewritten.strip(),
        "rewrite_count": new_count,
        "audit_trail": [
            {
                "actor": "agent:rewrite",
                "action": "hyde_rewrite",
                "timestamp": _now_iso(),
                "detail": {
                    "rewrite_count": new_count,
                    "rewritten_snippet": rewritten[:200],
                },
            }
        ],
    }
