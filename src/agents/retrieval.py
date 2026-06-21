"""Agent node: Pinecone runbook retrieval for the current threat event."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog

from src.core.schema import ThreatState
from src.rag.pinecone_store import query as pinecone_query

logger = structlog.get_logger(__name__)

_TOP_K = 5


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def retrieve_node(state: ThreatState) -> dict[str, Any]:
    """Query Pinecone for runbooks relevant to the current event.

    Prefers ``rewritten_query`` (set by the rewriter after a failed grade)
    over ``sanitized_description`` so HyDE rewrites improve recall on retry.

    Returns:
        Partial ThreatState with ``retrieved_docs`` and one ``audit_trail`` entry.
    """
    query_text: str = (
        state.get("rewritten_query")
        or state.get("sanitized_description")
        or ""
    )
    event_id: str = state.get("event_id", "")

    logger.info("retrieve_start", event_id=event_id, query=query_text[:80])
    docs = await pinecone_query(query_text, top_k=_TOP_K)
    logger.info("retrieve_done", event_id=event_id, hits=len(docs))

    return {
        "retrieved_docs": docs,
        "audit_trail": [
            {
                "actor": "agent:retrieve",
                "action": "runbook_retrieval",
                "timestamp": _now_iso(),
                "detail": {
                    "query": query_text[:200],
                    "hits": len(docs),
                    "top_score": docs[0]["score"] if docs else None,
                },
            }
        ],
    }
