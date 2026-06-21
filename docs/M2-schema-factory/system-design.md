# M2 — Core Schema & Model Factory · System Design

## Purpose
Define the two contracts the entire platform pivots on:
1. **`SecureEvent`** — the normalized, source-agnostic representation of *any* security event. Agents,
   RAG, audit, and API all speak this schema. Raw source payloads never travel past ingestion.
2. **The model factory** — the *single* place LLM and embedding clients are constructed, so the
   platform is model-swappable by environment variable alone.

## SecureEvent — the universal contract
Everything downstream consumes `SecureEvent`, so its shape is deliberately broad enough to losslessly
absorb CVEs, SIEM alerts, syslog, auth, network, and cloud events while staying flat and queryable.

| Field | Type | Role |
|---|---|---|
| `event_id` | str (UUID) | generated on ingest; primary key everywhere |
| `timestamp` | datetime (UTC) | normalized; all adapters convert to UTC |
| `source_type` | `EventSourceType` | CVE / SIEM_ALERT / SYSLOG / AUTH / NETWORK / CLOUD |
| `source_name` | str | "NVD", "Splunk", "CloudTrail", "Okta" … |
| `severity` | `SeverityLevel` | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| `title` | str | human summary |
| `description` | str | full text → the RAG retrieval query basis |
| `affected_assets` | list[str] | hosts, IPs, services, package names |
| `indicators` | list[str] | CVE IDs, IPs, domains, hashes, usernames |
| `raw_data` | dict | original payload, preserved unchanged (forensics) |
| `tags` | list[str] | "authentication", "network", "vulnerability" … |
| `metadata` | dict | source-specific extras |

`raw_data` is preserved but **quarantined** — it is for forensics/audit only and is never fed to an
LLM directly (principle #2 + #4). Only normalized, injection-checked fields reach the model.

## ThreatState — the LangGraph working memory
A `TypedDict` carrying an event through the agent graph: input (event + user/role), processing state
(sanitized text, retrieval docs + score, rewrite loop counter), output (severity, remediation,
approval, report), and an **append-only** `audit_trail` (LangGraph `operator.add` reducer) so node
actions accumulate immutably.

## Model factory — swappability contract
```
get_llm(task="default") -> BaseChatModel     # task lets cheap nodes (grading) use a faster model
get_embeddings() -> Embeddings
```
- Provider selected by `settings.LLM_PROVIDER` / `settings.EMBEDDING_PROVIDER`.
- Provider SDKs imported *lazily inside each branch* so unused providers need not be installed.
- `temperature=0` by default for deterministic security reasoning.
- A *functional* change (e.g. add retry, add cost cap, add callback) is made **once** here and applies
  to every call site.

## Acceptance criteria
- `SecureEvent` round-trips `model_dump_json()` → `model_validate_json()` losslessly.
- `get_llm()` returns the correct client for each provider; `get_llm("grading")` selects the fast model.
- `get_embeddings()` returns a 384-dim HuggingFace embedder by default.
- Unit tests cover enum membership and factory provider switching (SDK construction mocked).
