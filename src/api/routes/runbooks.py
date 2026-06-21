"""Routes: GET /runbooks, POST /runbooks, DELETE /runbooks/{id} — RBAC-gated."""
from __future__ import annotations

import asyncio
from typing import Any

import structlog
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel

from src.core.schema import Role
from src.rag.pinecone_store import init_pinecone, query as pinecone_query, upsert_runbook
from src.security.rbac import require_role

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/runbooks", tags=["runbooks"])


class RunbookUpsertRequest(BaseModel):
    """Payload for POST /runbooks."""

    title: str
    text: str
    tags: list[str] = []
    source: str = "api"


@router.get("")
async def list_runbooks(
    _auth: dict[str, Any] = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Return up to 20 runbooks from the Pinecone index.

    Uses a broad security query to surface all indexed runbooks.
    Pinecone does not expose a native list API, so results are similarity-ranked.
    """
    results = await pinecone_query("security incident remediation runbook", top_k=20)
    runbooks = [
        {"id": r["id"], **r["metadata"]}
        for r in results
    ]
    return {"runbooks": runbooks, "count": len(runbooks)}


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_runbook(
    body: RunbookUpsertRequest,
    _auth: dict[str, Any] = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Embed and upsert a runbook into Pinecone. ADMIN only.

    The runbook text is embedded via the configured embedding model and stored
    with metadata (``title``, ``tags``, ``source``) in the vector index.
    """
    metadata: dict[str, Any] = {
        "title": body.title,
        "tags": body.tags,
        "source": body.source,
    }
    vector_id = await upsert_runbook(body.text, metadata)
    logger.info("runbook_created", id=vector_id, title=body.title)
    return {"id": vector_id, "title": body.title}


@router.delete("/{runbook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_runbook(
    runbook_id: str,
    _auth: dict[str, Any] = Depends(require_role(Role.ADMIN)),
) -> None:
    """Delete a runbook from Pinecone by vector ID. ADMIN only."""
    index = await init_pinecone()
    await asyncio.to_thread(index.delete, ids=[runbook_id])
    logger.info("runbook_deleted", id=runbook_id)
