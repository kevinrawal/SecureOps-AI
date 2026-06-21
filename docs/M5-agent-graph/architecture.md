# M5 — Agent Graph (Part 1) · Architecture

## Graph topology (M5 scope)

```mermaid
flowchart TD
    START([START]) --> IC["injection_check_node\n[src/agents/injection_check.py]"]
    IC -->|injection_blocked=True| END1([END])
    IC -->|pass| RV["retrieve_node\n[src/agents/retrieval.py]"]
    RV --> GR["grade_node\n[src/agents/grader.py]"]
    GR -->|score ≥ 0.7| REM["→ remediation_node\n(M6)"]
    GR -->|score < 0.7\nrewrite_count < 2| RW["rewrite_node\n[src/agents/rewriter.py]"]
    RW -->|increments rewrite_count| RV
    GR -->|score < 0.7\nrewrite_count ≥ 2| REM
```

## State machine

```mermaid
stateDiagram-v2
    [*] --> injection_check
    injection_check --> retrieve : pass
    injection_check --> [*] : blocked
    retrieve --> grade
    grade --> rewrite : score < 0.7 ∧ rewrite_count < 2
    grade --> remediation : score ≥ 0.7 ∨ rewrite_count ≥ 2
    rewrite --> retrieve : loop (rewrite_count++)
    remediation --> [*] : (M6 continues)
```

## ThreatState field lifecycle (M5 nodes)

```mermaid
sequenceDiagram
    participant E as Event
    participant IC as injection_check
    participant RV as retrieve
    participant GR as grade
    participant RW as rewrite

    E->>IC: secure_event
    IC->>RV: sanitized_description, injection_blocked=False
    RV->>GR: retrieved_docs (list[{id,score,text,metadata}])
    GR->>RW: retrieval_score=0.4 (fail)
    RW->>RV: rewritten_query, rewrite_count=1
    RV->>GR: retrieved_docs (new results)
    GR->>GR: retrieval_score=0.8 (pass)
    GR-->>remediation: proceeds to M6
```

## Key module relationships

```mermaid
graph LR
    B["graph/builder.py\nbuild_graph()"] --> IC["agents/injection_check.py"]
    B --> RV["agents/retrieval.py"]
    B --> GR["agents/grader.py"]
    B --> RW["agents/rewriter.py"]
    B --> RT["graph/routers.py"]
    RV --> PS["rag/pinecone_store.query()"]
    GR --> MF["core/models_factory.get_llm(task='grading')"]
    RW --> MF2["core/models_factory.get_llm()"]
    IC --> SG["security/guardrails (M7)"]
```

## Decisions

- **All nodes are `async def`.** The graph is invoked via `ainvoke()`. Blocking
  calls (Pinecone) are wrapped in `asyncio.to_thread` inside `pinecone_store`.
- **Routers are pure functions** (`state → str`). No IO, no side effects, fully unit-testable.
- **`MemorySaver` is the default checkpointer.** In-process, zero deps. Production
  (M9+) replaces it with `AsyncPostgresSaver` — one argument to `build_graph()`.
- **The loop is expressed as a graph edge** (`rewrite → retrieve`), not recursion or
  a while loop inside a node. LangGraph handles the loop state transparently.
- **`rewrite_count` is initialized to 0 by the injection_check node** on first entry,
  eliminating the need for callers to pre-populate it.
