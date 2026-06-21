# M6 — Agent Graph (Part 2) · System Design

## Scope

Complete the LangGraph pipeline: add remediation, HITL interrupt, and report generation.
Full graph after M6:

```
injection_check → retrieve → grade → [rewrite loop]
    → remediation → [CRITICAL? human_review] → reporter → END
```

## Remediation agent

Receives: `sanitized_description`, `retrieved_docs`, `severity`.
Produces: `remediation_steps: list[str]`.

The LLM is instructed to:
1. Base every step on the retrieved runbooks (grounded, not hallucinated).
2. Cite the source runbook for each step.
3. Return a numbered list that can be inserted directly into the incident report.

Uses `get_llm(task="default")` (the more capable model) since remediation is a
high-stakes, context-heavy task.

## Human-in-the-loop (HITL)

**Trigger**: severity == CRITICAL in `route_after_remediation`.

**Mechanism**: `interrupt()` from `langgraph.types`. When called, the graph
suspends and returns control to the caller. The call site polls for state and
resumes with `graph.ainvoke(Command(resume={...}), config=thread_config)`.

The `interrupt()` payload includes event_id, title, severity, and remediation_steps
so the reviewer has full context. The resume value carries `{"approved": bool}`.

**Checkpointer requirement**: `interrupt()` only works when a `BaseCheckpointSaver`
is attached to the compiled graph. `build_graph()` defaults to `MemorySaver()`.
Production uses `AsyncPostgresSaver` (M9).

## Reporter

Aggregates all state into a structured JSON report:
```json
{
  "report_id": "<uuid>",
  "event_id": "<str>",
  "title": "<str>",
  "severity": "<str>",
  "summary": "<str>",
  "remediation_steps": ["<str>", ...],
  "sources": ["<runbook title>", ...],
  "retrieval_score": <float>,
  "rewrite_count": <int>,
  "human_approved": <bool|null>,
  "generated_at": "<ISO timestamp>"
}
```

The reporter also triggers a flush of `audit_trail` to PostgreSQL (stubbed in M6,
wired to the DB engine in M7).

## Routing summary

```
injection_check
    → blocked → END
    → pass → retrieve

grade
    → score ≥ 0.7 → remediation
    → score < 0.7 ∧ rewrite_count < 2 → rewrite → retrieve
    → score < 0.7 ∧ rewrite_count ≥ 2 → remediation

remediation
    → severity == CRITICAL → human_review
    → otherwise → reporter

human_review (HITL interrupt)
    → approved → reporter
    → rejected → END
```

## Acceptance criteria (M6)

- End-to-end `ainvoke()` on a non-CRITICAL event produces a `report` dict in state.
- CRITICAL severity routes to `human_review`; `interrupt()` suspends the graph.
- Resuming with `{"approved": True}` produces a report with `human_approved=True`.
- Resuming with `{"approved": False}` terminates at END with `human_approved=False`.
- `remediation_steps` all reference at least one retrieved runbook.
- `audit_trail` has one entry per node visited.
