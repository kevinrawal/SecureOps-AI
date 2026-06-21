# M4 — RAG & Runbook Seeding · System Design

## Purpose
Stand up the retrieval knowledge base: a Pinecone vector index seeded with security **runbooks**
(playbooks describing how to respond to a given threat). Later, the retrieval agent (M5) queries this
index with the event description to ground remediation in vetted, human-authored procedures rather
than model "memory" (mitigating hallucination exploitation).

## Components
1. **`pinecone_store.py`** — a thin async wrapper over the Pinecone client.
   - `init_pinecone()` — create the index if missing (dimension = `EMBEDDING_DIMENSION` = 384,
     metric = cosine, serverless on `PINECONE_ENVIRONMENT`). Idempotent.
   - `upsert_runbook(text, metadata) -> id` — embed via `get_embeddings()` (M2) and upsert with the
     text stored in metadata for retrieval-time display.
   - `query(query_text, top_k=5, filter=None) -> list[dict]` — embed the query, search, return
     `{id, score, text, metadata}`. `filter` enables metadata-scoped retrieval (a RAG guardrail —
     restrict to trusted sources / tags, mitigating retrieval poisoning).
2. **`runbook_loader.py`** — reads every `.txt` under `data/seed_runbooks/`, derives metadata
   (title from filename/first line, `source="seed"`, `tags` from a small keyword map), embeds, and
   upserts. Runnable as `python -m src.rag.runbook_loader`.
3. **Seed runbooks** — 5 realistic playbooks: Log4Shell, SSH brute force, SQL injection, ransomware,
   privilege escalation. Each 200–400 words of actionable response content.

## Why embeddings are local
`all-MiniLM-L6-v2` (384-dim) runs on CPU with no API cost and no Denial-of-Wallet exposure for the
embedding path. Pinecone free tier supports 384-dim cosine indexes. Swapping to OpenAI embeddings is
an env change (`EMBEDDING_PROVIDER`, `EMBEDDING_DIMENSION`) + re-seed.

## RAG security baked in from the start (principle #4)
- **Source validation / metadata filtering** — every vector carries `source` and `tags`; `query()`
  accepts a metadata `filter` so the retrieval agent can constrain to trusted content.
- **Provenance** — `text` + `title` + `source` returned with each hit so the remediation agent can
  cite, and the grader (M5) can judge relevance.
- **No untrusted upsert path yet** — only the seed loader and (later) ADMIN-gated runbook CRUD (M9)
  may write vectors, preventing arbitrary retrieval poisoning.

## Acceptance criteria
- `init_pinecone()` creates a 384-dim cosine index named `settings.PINECONE_INDEX_NAME` if absent;
  re-running is a no-op.
- Loader seeds all 5 runbooks; each vector has `title`, `source`, `tags`, `text` metadata.
- `query("log4shell remediation")` returns the Log4Shell runbook as the top hit.
