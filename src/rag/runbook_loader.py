"""Seed the Pinecone runbook index from local ``.txt`` playbooks.

Reads every file under ``data/seed_runbooks/``, derives lightweight metadata
(title, source, tags), embeds the content via the M2 factory, and upserts each
as a vector. This is the *trusted* write path — only this loader and the future
ADMIN-gated runbook CRUD (M9) may add vectors, keeping the knowledge base
trustworthy (retrieval-poisoning mitigation).

Run::

    uv run python -m src.rag.runbook_loader
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import structlog

from src.rag.pinecone_store import init_pinecone, query, upsert_runbook

logger = structlog.get_logger(__name__)

SEED_DIR = Path(__file__).resolve().parents[2] / "data" / "seed_runbooks"

# Keyword → tag map used to attach coarse tags from filename/content.
_TAG_KEYWORDS = {
    "log4shell": ["vulnerability", "java", "rce"],
    "ssh": ["authentication", "brute-force", "network"],
    "brute_force": ["authentication", "brute-force"],
    "sql_injection": ["web", "injection", "database"],
    "ransomware": ["malware", "incident-response"],
    "privilege_escalation": ["privilege-escalation", "endpoint"],
}


def _derive_metadata(path: Path, text: str) -> dict[str, list[str] | str]:
    """Build vector metadata (id, title, source, tags) for a runbook file."""
    first_line = text.strip().splitlines()[0] if text.strip() else path.stem
    title = first_line.lstrip("# ").strip() or path.stem.replace("_", " ").title()

    tags: list[str] = []
    name_lower = path.stem.lower()
    for keyword, keyword_tags in _TAG_KEYWORDS.items():
        if keyword in name_lower:
            tags.extend(keyword_tags)
    tags = sorted(set(tags)) or ["runbook"]

    return {"id": path.stem, "title": title, "source": "seed", "tags": tags}


async def load_runbooks(seed_dir: Path = SEED_DIR) -> int:
    """Embed and upsert all seed runbooks; return the count loaded."""
    await init_pinecone()
    files = sorted(seed_dir.glob("*.txt"))
    if not files:
        logger.warning("no_runbooks_found", dir=str(seed_dir))
        return 0

    count = 0
    for path in files:
        text = path.read_text(encoding="utf-8")
        metadata = _derive_metadata(path, text)
        await upsert_runbook(text, metadata)
        count += 1

    logger.info("runbooks_loaded", count=count, dir=str(seed_dir))
    return count


async def _main() -> None:
    """Seed the index, then run a sanity query for the Log4Shell runbook."""
    loaded = await load_runbooks()
    logger.info("seed_complete", loaded=loaded)
    if loaded:
        results = await query("log4shell remediation steps", top_k=3)
        for rank, hit in enumerate(results, start=1):
            logger.info("sanity_hit", rank=rank, id=hit["id"], score=hit["score"])


if __name__ == "__main__":
    asyncio.run(_main())
