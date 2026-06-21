"""Pinecone vector store wrapper for the runbook knowledge base.

A thin async layer over the Pinecone client. Embeddings always come from the M2
factory (:func:`get_embeddings`), so the index dimension and the embedding model
stay consistent by construction. Runbook text is stored in vector metadata so a
single query returns displayable, citable content.

RAG guardrails (design principle #4) are first-class: ``query`` accepts a
metadata ``filter`` so retrieval can be constrained to trusted sources/tags,
mitigating retrieval poisoning.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import structlog
from pinecone import Pinecone, ServerlessSpec

from src.core.config import settings
from src.core.models_factory import get_embeddings

logger = structlog.get_logger(__name__)

# Pinecone clients are synchronous; we run their calls in a thread to keep the
# public API of this module async (design principle #3, "async-first").
_index = None
_embeddings = None


def _get_pinecone_client():
    """Construct a Pinecone client from configured credentials."""
    return Pinecone(api_key=settings.PINECONE_API_KEY)


def _get_embeddings_cached():
    """Return a process-cached embeddings client (loads the local model once)."""
    global _embeddings
    if _embeddings is None:
        _embeddings = get_embeddings()
    return _embeddings


async def init_pinecone():
    """Create the runbook index if missing and return a handle to it.

    Idempotent: creating an existing index is skipped. Dimension and metric come
    from config (``EMBEDDING_DIMENSION``, cosine). Returns the index handle,
    which is also cached module-side for reuse.
    """
    global _index
    if _index is not None:
        return _index

    def _init():
        pc = _get_pinecone_client()
        existing = {idx["name"] for idx in pc.list_indexes()}
        if settings.PINECONE_INDEX_NAME not in existing:
            logger.info("pinecone_create_index", name=settings.PINECONE_INDEX_NAME,
                        dimension=settings.EMBEDDING_DIMENSION)
            region = settings.PINECONE_ENVIRONMENT.replace("-aws", "")
            pc.create_index(
                name=settings.PINECONE_INDEX_NAME,
                dimension=settings.EMBEDDING_DIMENSION,
                metric="cosine",
                spec=ServerlessSpec(cloud="aws", region=region),
            )
        return pc.Index(settings.PINECONE_INDEX_NAME)

    _index = await asyncio.to_thread(_init)
    logger.info("pinecone_ready", name=settings.PINECONE_INDEX_NAME)
    return _index


async def upsert_runbook(text: str, metadata: dict[str, Any]) -> str:
    """Embed ``text`` and upsert it as one vector with ``metadata``.

    The runbook text is stored under metadata key ``text`` so queries return the
    content directly. Returns the generated vector id.
    """
    index = await init_pinecone()
    embeddings = _get_embeddings_cached()

    vector_id = metadata.get("id", str(uuid.uuid4()))
    vector = await asyncio.to_thread(embeddings.embed_query, text)
    meta = {**metadata, "text": text}

    await asyncio.to_thread(
        index.upsert, vectors=[{"id": vector_id, "values": vector, "metadata": meta}]
    )
    logger.info("runbook_upserted", id=vector_id, title=metadata.get("title"))
    return vector_id


async def query(
    query_text: str,
    top_k: int = 5,
    metadata_filter: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Embed ``query_text`` and return the top-``k`` matching runbooks.

    Args:
        query_text: The natural-language query (event description or rewrite).
        top_k: Number of matches to return.
        metadata_filter: Optional Pinecone metadata filter — a retrieval
            guardrail to scope results to trusted sources/tags.

    Returns:
        A list of ``{id, score, text, metadata}`` dicts, highest score first.
    """
    index = await init_pinecone()
    embeddings = _get_embeddings_cached()

    vector = await asyncio.to_thread(embeddings.embed_query, query_text)
    result = await asyncio.to_thread(
        index.query,
        vector=vector,
        top_k=top_k,
        include_metadata=True,
        filter=metadata_filter,
    )

    matches: list[dict[str, Any]] = []
    for match in result.get("matches", []):
        meta = match.get("metadata", {}) or {}
        matches.append(
            {
                "id": match.get("id"),
                "score": match.get("score"),
                "text": meta.get("text", ""),
                "metadata": {k: v for k, v in meta.items() if k != "text"},
            }
        )
    logger.info("runbook_query", query=query_text[:80], hits=len(matches))
    return matches
