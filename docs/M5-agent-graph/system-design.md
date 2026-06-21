# M5 — Agent Graph (Part 1) · System Design

## Scope

Build the first half of the LangGraph pipeline over `ThreatState`:

```
injection_check → retrieve → grade → (rewrite loop, max 2) → [→ M6]
```

M6 extends this graph with remediation, HITL, and report generation.

## Why a StateGraph, not a chain

LangGraph `StateGraph` gives us:
- **Conditional edges** — grade routing, loop guard, severity branching (no if-else chains in nodes)
- **Append-only audit semantics** — `operator.add` reducer on `audit_trail`; no node can overwrite history
- **HITL via `interrupt()`** — graph suspends mid-run; resumes after human approval (M6)
- **Checkpointing** — state persisted to a `BaseCheckpointSaver`; required for interrupt/resume

## Node responsibilities

| Node | Input fields read | Output fields written |
|---|---|---|
| `injection_check` | `secure_event` | `sanitized_description`, `injection_blocked`, `audit_trail` |
| `retrieve` | `sanitized_description` OR `rewritten_query` | `retrieved_docs`, `audit_trail` |
| `grade` | `sanitized_description`, `retrieved_docs` | `retrieval_score`, `audit_trail` |
| `rewrite` | `sanitized_description`, `rewrite_count` | `rewritten_query`, `rewrite_count`, `audit_trail` |

## Routing logic

```
injection_check
    ├─ injection_blocked=True → END
    └─ pass → retrieve

grade
    ├─ score ≥ 0.7 → remediation (M6)
    ├─ score < 0.7 AND rewrite_count < 2 → rewrite → retrieve
    └─ score < 0.7 AND rewrite_count ≥ 2 → remediation (proceed with best results)
```

`GRADE_PASS_THRESHOLD = 0.7` and `MAX_REWRITES = 2` are module-level constants.

## Injection check (M5 implementation)

Layer 1 (regex) is implemented here — a baseline set of known injection patterns.
The full 50-pattern corpus and Layer 2 (LLM judge) are implemented in M7.

The node always produces `sanitized_description` from `secure_event["description"]`
regardless of outcome. If blocked, `injection_blocked=True` short-circuits the graph.

## Grader design (LLM-as-judge)

Uses `get_llm(task="grading")` — the smaller/faster model (e.g. `llama-3.1-8b-instant`).

Prompt asks for JSON `{"score": <float>, "reasoning": "<str>"}`.
Parsing is fault-tolerant: falls back to regex float extraction, then 0.0 on failure.

## HyDE rewriting

HyDE (Hypothetical Document Embedding): the rewriter asks the LLM to generate a
*hypothetical runbook excerpt* for the event, then uses that text as the new query.
This bridges the vocabulary gap between an alert description and how runbooks are written.

Each rewrite increments `rewrite_count`. The router checks this before allowing another loop.

## Acceptance criteria (M5)

- Graph compiles (`build_graph()` returns a `CompiledStateGraph`).
- Running `ainvoke()` on a seeded `ThreatState` transitions through all nodes.
- Grader returns a float 0.0–1.0 in `retrieval_score`.
- Score < 0.7 with `rewrite_count=0` routes to `rewrite`.
- Score < 0.7 with `rewrite_count=2` routes to remediation (loop guard respected).
- `injection_blocked=True` terminates the graph before retrieve.
- `audit_trail` grows with one entry per node.
