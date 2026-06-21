# M2 — Core Schema & Model Factory · Architecture

## Schema relationships

```mermaid
classDiagram
    class SecureEvent {
        +str event_id
        +datetime timestamp
        +EventSourceType source_type
        +str source_name
        +SeverityLevel severity
        +str title
        +str description
        +list~str~ affected_assets
        +list~str~ indicators
        +dict raw_data
        +list~str~ tags
        +dict metadata
    }
    class ThreatState {
        <<TypedDict>>
        +str event_id
        +dict secure_event
        +str user_id
        +str role
        +str sanitized_description
        +bool injection_blocked
        +list retrieved_docs
        +float retrieval_score
        +int rewrite_count
        +list remediation_steps
        +bool human_approved
        +dict report
        +list audit_trail
    }
    class AuditEntry {
        +str entry_id
        +datetime timestamp
        +str event_id
        +str actor
        +str action
        +dict detail
    }
    SecureEvent --> EventSourceType
    SecureEvent --> SeverityLevel
    ThreatState ..> SecureEvent : serialized in
    ThreatState ..> AuditEntry : appends
```

## Model factory — the single swappable layer

```mermaid
flowchart TD
    caller["any agent node\n(retrieval, grader, remediation...)"] --> getllm["get_llm(task)"]
    getllm --> sw{"settings.LLM_PROVIDER"}
    sw -->|groq| groq["ChatGroq\nfast model if task=grading"]
    sw -->|openai| oai["ChatOpenAI"]
    sw -->|anthropic| ant["ChatAnthropic"]
    sw -->|unknown| err["raise ValueError"]

    caller2["RAG / runbook loader"] --> getemb["get_embeddings()"]
    getemb --> esw{"settings.EMBEDDING_PROVIDER"}
    esw -->|huggingface| hf["HuggingFaceEmbeddings\nall-MiniLM-L6-v2 · 384d · local"]
    esw -->|openai| oaie["OpenAIEmbeddings"]
```

## Key decisions
- **Lazy provider imports.** Each `if provider == ...` branch imports its SDK inside the branch.
  Base install depends only on `langchain-groq` + `langchain-huggingface`; OpenAI/Anthropic are extras
  documented in `docs/models.md`. This keeps Denial-of-Wallet surface minimal and install light.
- **`task` parameter, not separate functions.** Callers express *intent* ("grading" = cheap) and the
  factory maps intent → concrete model. Adding a new task tier touches one function.
- **Embeddings dimension is config, not code.** `EMBEDDING_DIMENSION=384` flows to Pinecone index
  creation (M4); swapping to a 1536-dim OpenAI embedder is an env change + reindex, no code change.
- **Schema is the boundary.** `raw_data` carried for forensics but flagged non-LLM-safe; the graph
  reads `sanitized_description`, never `raw_data`.

## Swap procedure (documented in docs/models.md)
1. `pip/uv add` the provider extra (e.g. `langchain-openai`).
2. Set `LLM_PROVIDER=openai` and `OPENAI_API_KEY=...` (and/or `EMBEDDING_PROVIDER=openai`).
3. If embedding dimension changes, update `EMBEDDING_DIMENSION` and re-seed Pinecone (M4 loader).
4. No application code changes.
