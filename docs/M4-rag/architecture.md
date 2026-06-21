# M4 — RAG & Runbook Seeding · Architecture

## Seeding (write path) and retrieval (read path)

```mermaid
flowchart TB
    subgraph seed["Seeding (offline, ADMIN only)"]
        files["data/seed_runbooks/*.txt"] --> loader["runbook_loader.load_runbooks()"]
        loader --> emb1["get_embeddings()\nall-MiniLM-L6-v2 (384d)"]
        emb1 --> up["pinecone_store.upsert_runbook\n(vector + metadata: title/source/tags/text)"]
        up --> idx[("Pinecone index\nsecureops-runbooks\n384d · cosine")]
    end

    subgraph read["Retrieval (online, per event — used by M5)"]
        q["event.description / rewritten query"] --> emb2["get_embeddings()"]
        emb2 --> query["pinecone_store.query(top_k, filter)"]
        query --> idx
        idx --> hits["[{id, score, text, metadata}]"]
    end
```

## Index lifecycle

```mermaid
flowchart LR
    start(["init_pinecone()"]) --> exists{"index exists?"}
    exists -->|yes| ready["use existing"]
    exists -->|no| create["create_index\nname=settings.PINECONE_INDEX_NAME\ndim=settings.EMBEDDING_DIMENSION\nmetric=cosine"]
    create --> waitready["wait until ready"]
    waitready --> ready
```

## Key decisions
- **Embeddings via the M2 factory.** RAG never constructs an embedder directly — it calls
  `get_embeddings()`. Dimension flows from `settings.EMBEDDING_DIMENSION` into index creation, so
  model and index stay consistent by construction.
- **Text-in-metadata.** Pinecone stores vectors; we keep the runbook `text` in metadata so retrieval
  returns displayable, citable content in one round trip (no second store to join against).
- **Metadata filter is a first-class query arg.** Retrieval guardrails (trusted-source-only,
  tag-scoped) are available from day one, not retrofitted — directly addressing retrieval poisoning.
- **Write path is privileged.** Seeding + future runbook CRUD are the *only* vector writers and are
  ADMIN-gated (M9), keeping the knowledge base trustworthy.

## Interfaces consumed downstream
- M5 `retrieval` node → `pinecone_store.query(...)`
- M9 runbook routes (ADMIN) → `upsert_runbook(...)` / delete
- M11 eval → seeds a labeled set + measures retrieval/grounding quality
