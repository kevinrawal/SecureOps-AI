# M7 — Security Layer · System Design

> This doc covers the full security architecture. Stubs for all modules exist
> in `src/security/`; implementation happens in Milestone M7.

## Why a composed guardrail pipeline, not ad-hoc checks

Ingestion has a composable adapter registry (add source = one file). Security
needs the same pattern for its threat surface: each threat class is an
independent, testable guardrail; the pipeline chains them in order. Adding a
new check never changes the pipeline contract — it just adds a class and
registers it.

## Threat coverage map

| Threat | Guardrail(s) | Module |
|---|---|---|
| Indirect Prompt Injection | InjectionCheck Layer 1 (regex) + Layer 2 (LLM) | `injection.py` |
| Jailbreak Attacks | InjectionCheck Layer 2 | `injection.py` |
| System Prompt Leakage | InjectionCheck + OutputFilter | `injection.py`, `output_filter.py` |
| Unsafe Output Generation | OutputFilter | `output_filter.py` |
| Hallucination Exploitation | OutputFilter (grounding check) | `output_filter.py` |
| Sensitive Information Disclosure | PIIMasker | `pii_masker.py` |
| Cross-User Context Leakage | PIIMasker + RBAC tenant isolation | `pii_masker.py`, `rbac.py` |
| SSRF via AI Agents | SSRFGuard (IP allowlist) | `ssrf_guard.py` |
| Tool Injection | SSRFGuard (arg validation) | `ssrf_guard.py` |
| Function Calling Abuse | SSRFGuard (tool allowlist) | `ssrf_guard.py` |
| Agent-to-Agent Attacks | SSRFGuard (envelope validation) | `ssrf_guard.py` |
| Data Poisoning | Adapter field caps + source validation | `adapters/base.py` (M3) |
| Retrieval Poisoning | Pinecone metadata filter + trusted-source write gate | `pinecone_store.py` (M4) |
| Memory Poisoning | Append-only audit_trail reducer | `schema.ThreatState` (M2) |
| Vector Database Exposure | ADMIN-only write, metadata-filter on query | `rbac.py`, `pinecone_store.py` |
| Denial of Wallet (DoW) | Rate limiter + Groq free-tier budget guard | `middleware.py` (M9) |
| Denial of Service (DoS) | Rate limiter + worker pool bound | `middleware.py` (M9), workers (M10) |

## Pipeline execution order

```
Inbound text (event / user input)
  │
  ▼
1. InjectionCheck    ← regex (L1) then LLM judge (L2) — blocks on detect
  │
  ▼
2. PIIMasker         ← masks PII in-place, annotates context["masked_text"]
  │
  ▼  (agents run here — retrieve, grade, rewrite, remediate)
  │
  ▼
3. SSRFGuard         ← validates every tool invocation before execution
  │
  ▼  (LLM generates output)
  │
  ▼
4. OutputFilter      ← post-generation: leakage, unsafe content, grounding
  │
  ▼
audit log → API response
```

## RBAC

Three roles: `ANALYST ⊂ ENGINEER ⊂ ADMIN` (privilege ordering).

| Resource | ANALYST | ENGINEER | ADMIN |
|---|---|---|---|
| `GET /events` | ✓ | ✓ | ✓ |
| `POST /events/ingest` | ✗ | ✓ | ✓ |
| `POST /threats/{id}/approve` | ✗ | ✓ | ✓ |
| `GET /threats` | ✓ | ✓ | ✓ |
| Runbook CRUD | ✗ | ✗ | ✓ |
| Pinecone write | ✗ | ✗ | ✓ (loader only) |

JWT carries `sub` (user_id) and `role`; `require_role` is a FastAPI dependency
injected at the route level. The graph also checks role before invoking
human_review interrupt (HITL gated to ENGINEER+).

## Audit log

Every agent node action appended to `ThreatState.audit_trail` (LangGraph
`operator.add` — append-only inside the graph) and flushed to PostgreSQL as
`AuditEntry` rows at the report node. The table has no UPDATE/DELETE grants for
the application user — immutability enforced at the DB layer.

## Acceptance criteria (M7)
- Injection corpus (50+ samples) blocked at Layer 1 before any LLM call.
- At least 10% of corpus requires Layer 2 (tests LLM judge path).
- `require_role` rejects ANALYST on ENGINEER-only routes with 403.
- Every graph run produces one or more AuditEntry rows in Postgres.
- SSRFGuard blocks RFC1918 and 169.254.169.254 in tool URL args.
- PIIMasker redacts email/SSN/phone in event descriptions before storage.
- OutputFilter detects system-prompt echo in a crafted test response.
