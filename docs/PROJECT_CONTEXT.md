# SecureOps AI — Project Context & Handoff

> **For the next chat session.** This document captures the complete current state of the
> project and the detailed plan for every remaining milestone. Read this before touching any code.

---

## What Is SecureOps AI

A production-grade **multi-agent security intelligence platform**. It ingests security events from
heterogeneous sources (CVE feeds, SIEM alerts, syslog, cloud), normalises them to a common
`SecureEvent` schema via source adapters, then runs each event through a LangGraph agent pipeline:

```
injection_check → retrieve → grade → (rewrite loop, max 2) → remediation → human_review (CRITICAL only) → reporter
```

Every node appends to an immutable audit trail flushed to PostgreSQL at the end of each run.

---

## Tech Stack

| Concern | Choice |
|---|---|
| Language | Python 3.12+ |
| Packaging | `uv` + `pyproject.toml` (`uv.lock` committed) |
| Agent framework | LangGraph `StateGraph` over `ThreatState` TypedDict |
| LLM (free/default) | Groq (`llama-3.3-70b-versatile` default, `llama-3.1-8b-instant` for grading) |
| Embeddings (free/default) | HuggingFace `all-MiniLM-L6-v2` (dim=384) |
| Vector store | Pinecone (serverless, cosine) |
| Observability (AI) | Langfuse v3 (ClickHouse + MinIO + Redis) |
| Observability (platform) | OpenTelemetry → Jaeger + Prometheus + Grafana |
| Database | PostgreSQL + asyncpg + SQLAlchemy Core (no ORM) |
| Migrations | Alembic (async) |
| Queue | Redis Streams via `QueueBackend` ABC |
| API | FastAPI + slowapi (rate limiting) |
| Auth | JWT HS256 via `python-jose` |
| Config | `pydantic-settings` `BaseSettings` singleton |
| Logging | `structlog` (JSON in prod) — **never `print()`** |
| Tests | pytest + pytest-asyncio (`asyncio_mode = "auto"`) |

---

## Non-Negotiable Constraints (enforce in every milestone)

These are from the original spec and must never be relaxed:

1. **Model swappable** — all LLM/embedding construction goes through `src/core/models_factory.py`
   (`get_llm(task)`, `get_embeddings()`). Provider = change env vars only.
2. **Source agnostic** — every raw payload normalised to `SecureEvent` by a `BaseAdapter` subclass.
   Agents never touch raw source data (`raw_data` field is quarantined).
3. **Async first** — all IO is `async/await`. Queue abstracted behind `QueueBackend` ABC.
4. **Security by design** — injection check runs before any LLM sees external data; RBAC at API
   and graph level; every agent action written to immutable audit log.
5. **Observability native** — every agent node instrumented with OTel spans AND Langfuse traces
   from the moment it is written, never bolted on later.

### Threat list (M7 addressed all of these at guardrail level)
Indirect Prompt Injection, Data Poisoning, Retrieval Poisoning, System Prompt Leakage,
Tool Injection, Agent-to-Agent Attacks, Memory Poisoning, Sensitive Information Disclosure,
Jailbreak Attacks, Function Calling Abuse, SSRF via AI Agents, Vector Database Exposure,
Denial of Wallet, Denial of Service, Hallucination Exploitation, Unsafe Output Generation,
Cross-User Context Leakage.

---

## Coding Standards (carry forward exactly)

- **Imports always at top of file.** No deferred imports inside functions or classes.
  - **Only exception:** optional provider SDKs in `src/core/models_factory.py`
    (`langchain_groq`, `langchain_openai`, `langchain_anthropic`) — these are extras that
    may not be installed. All other imports go at the top.
- `structlog` for all logging — `logger = structlog.get_logger(__name__)`.
- No `print()`, no hardcoded values — everything from `settings`.
- Full type hints on every function. Docstrings on every public function.
- Test file per non-trivial module.
- `uv run pytest` to run tests (uses `.venv` — never the system Python).

---

## Current Directory Structure

```
SecureOps AI/
├── pyproject.toml            # uv packaging, all deps, pytest config
├── uv.lock
├── requirements.txt          # exported for Docker compat
├── .env.example              # all env vars documented
├── docker-compose.yml        # 10 services (see below)
├── alembic.ini
├── alembic/
│   ├── env.py                # async engine + run_sync pattern
│   ├── script.py.mako
│   └── versions/
│       └── 001_create_audit_entries.py   # audit_entries table
├── data/
│   └── seed_runbooks/        # 5 .txt runbooks (log4shell, ssh, sql, ransomware, privesc)
├── docs/
│   ├── models.md             # LLM provider swap guide
│   ├── PROJECT_CONTEXT.md    # ← this file
│   ├── M1-scaffold/
│   ├── M2-schema-factory/
│   ├── M3-ingestion/
│   ├── M4-rag/
│   ├── M5-agent-graph/
│   ├── M6-agent-graph-2/
│   └── M7-security/          # system-design.md + architecture.md per milestone
├── infra/
│   ├── postgres-init.sql
│   └── prometheus.yml
├── src/
│   ├── core/
│   │   ├── config.py         # Settings singleton (pydantic-settings)
│   │   ├── schema.py         # SecureEvent, ThreatState, AuditEntry, enums
│   │   └── models_factory.py # get_llm(task), get_embeddings() — provider-swappable
│   ├── db/
│   │   └── engine.py         # get_engine() — lru_cache AsyncEngine singleton
│   ├── ingestion/
│   │   ├── adapters/
│   │   │   ├── base.py       # BaseAdapter ABC (async parse)
│   │   │   ├── nvd_adapter.py
│   │   │   ├── siem_adapter.py
│   │   │   └── syslog_adapter.py
│   │   ├── queue/
│   │   │   ├── base.py       # QueueBackend ABC
│   │   │   ├── redis_backend.py
│   │   │   └── factory.py
│   │   ├── normalizer.py     # routes by source_type via ADAPTER_REGISTRY
│   │   └── producer.py       # publishes SecureEvent to Redis Stream
│   ├── rag/
│   │   ├── pinecone_store.py # init_pinecone, upsert_runbook, query
│   │   └── runbook_loader.py # reads .txt files, embeds, upserts
│   ├── agents/               # one file per LangGraph node
│   │   ├── injection_check.py  # InjectionCheck + PIIMasker (L1+L2, PII mask)
│   │   ├── retrieval.py        # Pinecone query (prefers rewritten_query)
│   │   ├── grader.py           # LLM-as-judge (score 0-1, GRADE_PASS_THRESHOLD=0.7)
│   │   ├── rewriter.py         # HyDE query rewrite, increments rewrite_count
│   │   ├── remediation.py      # grounded steps + OutputFilter on LLM output
│   │   ├── human_review.py     # interrupt() HITL, assert_graph_role(ANALYST)
│   │   └── reporter.py         # builds report dict, flushes audit trail to PG
│   ├── graph/
│   │   ├── builder.py        # build_graph(checkpointer=None) → CompiledGraph
│   │   └── routers.py        # 4 pure router functions, MAX_REWRITES=2
│   ├── security/
│   │   ├── audit.py          # flush_audit_trail(), append_audit_entry()
│   │   ├── rbac.py           # ROLE_HIERARCHY, JWT, require_role(), assert_graph_role()
│   │   └── guardrails/
│   │       ├── base.py       # BaseGuardrail ABC, GuardrailResult dataclass
│   │       ├── pipeline.py   # GuardrailPipeline (ordered chain, stop-on-block)
│   │       ├── injection.py  # InjectionCheck (59 L1 patterns, L2 LLM judge)
│   │       ├── output_filter.py  # OutputFilter (injection echo, leakage, hallucination)
│   │       ├── pii_masker.py     # PIIMasker (email, phone, SSN, card, IP, token)
│   │       └── ssrf_guard.py     # SSRFGuard (RFC1918, blocked schemes, tool allowlist)
│   ├── observability/        # stubs — implemented in M8
│   │   ├── otel_setup.py
│   │   ├── langfuse_setup.py
│   │   └── metrics.py
│   ├── api/                  # stubs — implemented in M9
│   │   ├── main.py
│   │   ├── middleware.py
│   │   └── routes/
│   │       ├── events.py
│   │       ├── threats.py
│   │       ├── runbooks.py
│   │       └── health.py
│   └── workers/              # stubs — implemented in M10
│       ├── consumer.py
│       └── batch_ingest.py
└── tests/
    ├── unit/
    │   ├── test_adapters.py      # 7 tests — NVD, SIEM, syslog, normalizer
    │   ├── test_schema_factory.py # 5 tests — schema round-trip, enums, factory
    │   ├── test_grader.py        # 13 tests — parse, clamping, routing
    │   └── test_injection.py     # 104 tests — L1 corpus, L2, PII, SSRF, output filter, RBAC
    └── integration/
        └── test_graph.py         # 5 tests — full run, injection block, loop guard, HITL
```

**Total: 129 unit tests passing. 5 integration tests written (run offline, mocked).**

---

## Docker Compose Services (10 total)

```
postgres        :5432   — primary DB (audit_entries table via Alembic)
redis           :6379   — Redis Streams queue
jaeger          :16686  — OTel trace UI
prometheus      :9090   — metrics scrape
grafana         :3001   — dashboards
clickhouse      :8123   — Langfuse analytics backend (HTTP only exposed)
minio           :9000/:9001 — Langfuse media storage
minio-init      one-shot — creates langfuse bucket then exits
langfuse-worker         — Langfuse event processor
langfuse-web    :3000   — Langfuse UI
```

---

## Key Architectural Patterns

### ThreatState (LangGraph working memory)
```python
class ThreatState(TypedDict, total=False):
    event_id: str
    secure_event: dict          # serialised SecureEvent — agents read this
    user_id: str
    role: str                   # Role enum value, carried from JWT
    sanitized_description: str  # PII-masked, injection-clean description
    injection_blocked: bool
    retrieved_docs: list[dict]
    retrieval_score: float       # 0.0–1.0
    rewrite_count: int           # loop guard, MAX_REWRITES=2
    rewritten_query: str         # HyDE output
    severity: str
    remediation_steps: list[str]
    human_approved: Optional[bool]
    report: Optional[dict]
    audit_trail: Annotated[list[dict], operator.add]  # append-only
```

### Graph topology
```
injection_check
  ├─ blocked ──────────────────────────────────────────── END
  └─ passed ──► retrieve ──► grade
                               ├─ score ≥ 0.7 or rewrites exhausted ──► remediation
                               └─ score < 0.7 and rewrites left ──► rewrite ──► retrieve
                                                                        remediation
                               ├─ CRITICAL ──► human_review ──► reporter ──► END
                               │                    └─ rejected ──────────── END
                               └─ other ────► reporter ──► END
```

### RBAC enforcement points
- **API level** (`require_role(Role.X)` FastAPI dependency) — M9
- **Graph level** (`assert_graph_role(state, Role.ANALYST)`) — wired in `human_review_node` ✅

### Guardrails wiring (current)
| Guardrail | Where wired | What it guards |
|---|---|---|
| `InjectionCheck` | `injection_check_node` (first, always) | Adversarial input (59 L1 patterns + optional L2 LLM judge) |
| `PIIMasker` | `injection_check_node` (after L1 pass) | PII in event description before any LLM sees it |
| `OutputFilter` | `remediation_node` (after LLM response) | Injection echo, system-prompt leakage, hallucination risk |
| `SSRFGuard` | **Not yet wired** — M9 (API webhooks) + M10 (feed URLs) | SSRF URLs, tool allowlist, arg injection |

### Alembic + asyncpg pattern
```python
# env.py — sync wrapper required because Alembic runner is synchronous
async def run_migrations_online():
    engine = create_async_engine(get_url())
    async with engine.connect() as conn:
        await conn.run_sync(do_run_migrations)
```
Run: `uv run alembic upgrade head` (requires postgres running).

---

## Completed Milestones

| # | Milestone | Status |
|---|---|---|
| M1 | Project scaffold, config, docker-compose | ✅ Done |
| M2 | Schema (`SecureEvent`, `ThreatState`, enums) + model factory | ✅ Done |
| M3 | Ingestion adapters (NVD, SIEM, syslog) + Redis queue | ✅ Done |
| M4 | RAG: Pinecone store + runbook loader + 5 seed runbooks | ✅ Done |
| M5 | Agent graph: injection_check → retrieve → grade → rewrite loop | ✅ Done |
| M6 | Agent graph: remediation → HITL → reporter + all routers | ✅ Done |
| M7 | Security layer: 59-pattern injection corpus, RBAC+JWT, audit flush, OutputFilter, PIIMasker, SSRFGuard | ✅ Done |

---

## Remaining Milestones

### M8 — Observability (next up)

**Goal:** OTel TracerProvider + Jaeger exporter, Langfuse callback handler, custom Prometheus
metrics (retrieval latency, token/cost, queue depth). Every agent node instrumented.

**Stubs already exist at:**
- `src/observability/otel_setup.py`
- `src/observability/langfuse_setup.py`
- `src/observability/metrics.py`

**Design-first:** write `docs/M8-observability/system-design.md` + `architecture.md` before code.

**Implementation tasks:**

`src/observability/otel_setup.py`:
- `setup_tracing(service_name: str) -> TracerProvider`
- Configure `OTLPSpanExporter` → Jaeger at `settings.OTEL_EXPORTER_OTLP_ENDPOINT`
- Call once at app startup (FastAPI lifespan and worker startup)

`src/observability/langfuse_setup.py`:
- `get_langfuse_handler() -> CallbackHandler` — Langfuse v3 LangChain callback
- Reads `LANGFUSE_SECRET_KEY`, `LANGFUSE_PUBLIC_KEY`, `LANGFUSE_HOST` from settings
- Handler passed to every `llm.ainvoke(..., config={"callbacks": [handler]})` call

`src/observability/metrics.py`:
- Prometheus counters/histograms: `retrieval_latency_seconds`, `llm_tokens_total`,
  `injection_blocked_total`, `grade_score_histogram`, `queue_depth_gauge`
- `instrument_node(node_name: str)` decorator that wraps async node functions with
  an OTel span + records latency metric

**Instrument in each agent node** (add OTel span + Langfuse callback):
- `injection_check_node` — span: `secureops.injection_check`
- `retrieve_node` — span: `secureops.retrieve`, record retrieval latency
- `grade_node` — span: `secureops.grade`, pass Langfuse callback to LLM
- `rewrite_node` — span: `secureops.rewrite`, pass Langfuse callback
- `remediation_node` — span: `secureops.remediation`, pass Langfuse callback
- `human_review_node` — span: `secureops.human_review`
- `reporter_node` — span: `secureops.reporter`

**Acceptance criteria:**
- Single event → Jaeger shows one trace spanning all visited nodes
- Same event → Langfuse shows LLM calls with token counts
- `GET /metrics` (Prometheus) scrapes `retrieval_latency_seconds`, `grade_score_histogram`
- AI observability (Langfuse) and platform observability (OTel/Prometheus) are separate concerns

**Tests:** `tests/unit/test_observability.py` — mock TracerProvider, verify spans created
per node; verify Langfuse handler is passed to LLM calls.

---

### M9 — API Layer

**Goal:** FastAPI app with lifespan, middleware, all routes, slowapi rate limiting, JWT auth
at every protected endpoint.

**Stubs already exist at:**
- `src/api/main.py`
- `src/api/middleware.py`
- `src/api/routes/events.py`, `threats.py`, `runbooks.py`, `health.py`

**Design-first:** write `docs/M9-api/system-design.md` + `architecture.md` before code.

**`src/api/main.py`:**
```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_tracing("secureops-api")        # M8
    await init_pinecone()                  # warm Pinecone connection
    yield
    await get_engine().dispose()           # clean shutdown

app = FastAPI(lifespan=lifespan)
app.add_middleware(...)                    # CORS, RequestID, structlog context
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
```

**Routes:**

`POST /events/ingest` — ANALYST+
- Accept raw JSON payload + `source_type` hint
- Run through `Normalizer` → `SecureEvent`
- Publish to Redis Stream via `producer.publish()`
- Return `{event_id, queued: true}`

`GET /events/{event_id}` — ANALYST+
- Fetch event status from Redis or audit log

`POST /threats/{event_id}/approve` — ENGINEER+
- Resume a HITL-interrupted graph: `graph.ainvoke(Command(resume={...}), config)`
- `require_role(Role.ENGINEER)` dependency

`GET /runbooks` — ANALYST+
- List runbooks from Pinecone metadata

`POST /runbooks` — ADMIN only
- Upsert a runbook into Pinecone via `upsert_runbook()`
- `require_role(Role.ADMIN)` dependency

`DELETE /runbooks/{id}` — ADMIN only

`GET /health` — public
- Check postgres (try `SELECT 1`), Redis (`PING`), Pinecone (`describe_index_stats`)
- Return `{status: "ok"|"degraded", checks: {...}}`

**Wire `SSRFGuard`** — in the ingest route, validate any URL fields in the incoming payload
before normalisation. This is where SSRF from external data first enters the system.

**Rate limiting** (slowapi):
- `/events/ingest`: 100/minute per IP
- `/threats/*/approve`: 20/minute per user
- Default: 500/minute

**`src/api/middleware.py`:**
- `RequestIDMiddleware` — attach `X-Request-ID` to every request/response
- `StructlogMiddleware` — bind `request_id`, `user_id`, `path` to log context per request

**`POST /auth/token`** — public (needed for `oauth2_scheme` tokenUrl)
- Accept `{username, password}` (demo only; real auth is external IdP in prod)
- Return signed JWT with role from a hardcoded user store (dev only)

**Acceptance criteria:**
- `POST /events/ingest` normalises + enqueues; returns event_id
- `POST /threats/{id}/approve` resumes HITL graph and returns report
- `POST /runbooks` rejects ANALYST token with 403
- `GET /health` returns 200 with all checks passing (compose running)
- Rate limit returns 429 when exceeded

**Tests:** `tests/integration/test_api.py` — use `httpx.AsyncClient` with `TestClient`,
mock Redis/Pinecone, test all routes, test role enforcement, test rate limit.

---

### M10 — Workers

**Goal:** Async Redis Stream consumer pool + scheduled NVD batch ingestion.

**Stubs already exist at:**
- `src/workers/consumer.py`
- `src/workers/batch_ingest.py`

**Design-first:** write `docs/M10-workers/system-design.md` + `architecture.md` before code.

**`src/workers/consumer.py`:**
```python
async def run_worker(worker_id: int, graph: CompiledGraph) -> None:
    """Single consumer loop: read from Redis Stream consumer group, run graph, ack."""
    backend = RedisStreamBackend()
    while True:
        messages = await backend.consume(
            stream=settings.REDIS_STREAM_NAME,
            group="secureops-workers",
            consumer=f"worker-{worker_id}",
            count=1,
            block_ms=5000,
        )
        for msg_id, event_dict in messages:
            try:
                state = ThreatState(...)   # build from event_dict
                config = {"configurable": {"thread_id": event_dict["event_id"]}}
                await graph.ainvoke(state, config=config)
                await backend.ack(msg_id)
            except Exception:
                # DLQ: after MAX_RETRIES move to secureops:dlq stream
                ...

async def run_worker_pool() -> None:
    graph = build_graph(checkpointer=AsyncPostgresSaver.from_conn_string(...))
    await asyncio.gather(*[run_worker(i, graph) for i in range(settings.WORKER_COUNT)])
```

Key design points:
- Consumer group: `secureops-workers` (created on startup if missing)
- Each message processed by exactly one worker (Redis consumer group semantics)
- `ack` only after successful graph completion
- Dead-letter queue stream `secureops:dlq` after `MAX_RETRIES=3`
- Horizontal scale: raise `WORKER_COUNT` env var
- Checkpointer: `AsyncPostgresSaver` (replaces `MemorySaver` from M5/M6)

**`src/workers/batch_ingest.py`:**
```python
async def fetch_recent_nvd_cves(days_back: int = 1) -> list[SecureEvent]:
    """Pull CVEs published in the last N days from NVD API 2.0."""
    # GET https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=...
    # Rate limit: 5 req/30s without API key, 50 req/30s with key
    # NVD_API_KEY in settings

async def run_batch_ingest() -> None:
    """Scheduled job: fetch recent CVEs and publish to Redis Stream."""
    events = await fetch_recent_nvd_cves(days_back=1)
    producer = EventProducer()
    for event in events:
        await producer.publish(event)
```

Wire `SSRFGuard` here — validate the NVD API URL before each HTTP call (defence-in-depth;
the URL is hardcoded but the pattern must hold for dynamic feed URLs).

**Acceptance criteria:**
- N workers consume concurrently, run the agent graph per event, ack on success
- Simulate failure → message goes to DLQ after MAX_RETRIES
- Horizontal scale: `WORKER_COUNT=5` spins 5 concurrent consumers
- Batch ingest pulls yesterday's CVEs and publishes them to the stream
- `XLEN secureops:events` decreases as workers consume

**Tests:** `tests/integration/test_workers.py` — mock graph, verify ack on success,
verify DLQ routing on repeated failure, verify worker_count pool size.

---

### M11 — Evaluation & E2E Red-Team

**Goal:** Langfuse eval dataset + E2E AI red-team test suite covering the full threat list.

**Design-first:** write `docs/M11-eval/system-design.md` + `architecture.md` before code.

**Eval pipeline (`tests/eval/`):**
- Labeled dataset: `tests/eval/dataset.jsonl` — 20+ events with expected outcomes
  (which runbook should be retrieved top-1, expected remediation keywords, should_block flags)
- `tests/eval/run_eval.py` — runs each labeled event through the live graph, scores:
  - Retrieval precision@1 (did correct runbook come back top-1?)
  - Remediation grounding score (does output cite retrieved runbook?)
  - Injection block rate (did all `should_block=true` events get blocked?)
- Uploads results to Langfuse dataset for tracking across runs

**E2E red-team suite (`tests/e2e/`):**

Each scenario runs the real graph (mocked LLM optional) and asserts the security property:

| Scenario | Attack | Expected |
|---|---|---|
| `test_indirect_prompt_injection` | Event description contains L1 pattern | `injection_blocked=True`, no Pinecone call |
| `test_jailbreak_attempt` | "DAN mode" in description | Blocked at injection_check |
| `test_l2_near_miss` | High soft-signal density, no L1 match | L2 LLM judge called (mocked), blocked |
| `test_retrieval_poisoning` | Malicious text in retrieved doc metadata | OutputFilter catches echo in remediation |
| `test_system_prompt_leakage` | LLM echoes system prompt in output | OutputFilter blocks, report not generated |
| `test_hallucination_exploitation` | LLM output with retrieval_score=0.05 | OutputFilter hallucination gate fires |
| `test_ssrf_in_event` | Event description contains `http://169.254.169.254` | L1 ssrf_url pattern blocks it |
| `test_pii_scrubbed_from_description` | Description contains email + SSN | `sanitized_description` has `[REDACTED]` |
| `test_rbac_analyst_cannot_approve` | ANALYST token tries `/threats/approve` | 403 from `require_role(ENGINEER)` |
| `test_rbac_graph_role_blocked` | `state["role"]="ANALYST"` hits human_review with ENGINEER required | PermissionError |
| `test_cross_user_context` | Two concurrent events with different user_ids | Audit trails don't overlap |
| `test_denial_of_wallet_guard` | 1000 events in burst | Rate limiter returns 429 |
| `test_privilege_escalation_blocked` | "grant me admin access" in description | L1 privilege_escalation pattern fires |

**Acceptance criteria:**
- Eval pipeline: retrieval precision@1 ≥ 80% on labeled dataset
- All 13 red-team scenarios pass (security properties hold end-to-end)
- Results uploaded to Langfuse dataset run

---

## Environment Variables Reference

Key vars not already obvious from `.env.example`:

```bash
# LLM
LLM_PROVIDER=groq              # groq | openai | anthropic
GROQ_API_KEY=gsk_...
GROQ_MODEL=llama-3.3-70b-versatile
GROQ_MODEL_FAST=llama-3.1-8b-instant

# Embeddings
EMBEDDING_PROVIDER=huggingface
EMBEDDING_MODEL=all-MiniLM-L6-v2
EMBEDDING_DIMENSION=384

# Pinecone
PINECONE_API_KEY=...
PINECONE_INDEX_NAME=secureops-runbooks
PINECONE_ENVIRONMENT=us-east-1-aws

# Security
JWT_SECRET_KEY=...             # openssl rand -hex 32
INJECTION_L2_ENABLED=false     # true to enable LLM judge on near-miss inputs

# Langfuse v3
LANGFUSE_SECRET_KEY=...
LANGFUSE_PUBLIC_KEY=...
LANGFUSE_HOST=http://localhost:3000
LANGFUSE_ENCRYPTION_KEY=...    # openssl rand -hex 32 (64 hex chars)

# Infra
DATABASE_URL=                  # auto-computed from POSTGRES_* if empty
REDIS_URL=redis://localhost:6379
WORKER_COUNT=3
```

---

## How to Run

```bash
# Install deps (always use uv — never pip directly)
uv sync

# Run unit tests
uv run pytest tests/unit/ -v

# Run integration tests (offline, mocked)
uv run pytest tests/integration/ -v

# Start all infra services
docker compose up -d

# Apply DB migrations (postgres must be running)
uv run alembic upgrade head

# Seed Pinecone runbooks (PINECONE_API_KEY required)
uv run python -m src.rag.runbook_loader

# Start API server (M9)
uv run uvicorn src.api.main:app --reload

# Start worker pool (M10)
uv run python -m src.workers.consumer
```

---

## Current Test Counts

```
tests/unit/test_adapters.py        7 tests  ✅
tests/unit/test_schema_factory.py  5 tests  ✅
tests/unit/test_grader.py         13 tests  ✅
tests/unit/test_injection.py      104 tests ✅
─────────────────────────────────────────────
Unit total:                       129 tests ✅

tests/integration/test_graph.py    5 tests  ✅ (mocked, offline)
```

---

## What to Pick Up Next (M8)

1. Write `docs/M8-observability/system-design.md` and `architecture.md` first.
2. Implement `src/observability/otel_setup.py`, `langfuse_setup.py`, `metrics.py`.
3. Add `instrument_node` wrapper/decorator and apply to all 7 agent nodes.
4. Pass Langfuse callback handler to every `llm.ainvoke()` call in grader, rewriter, remediation.
5. Write `tests/unit/test_observability.py`.
6. Verify: single event → Jaeger trace + Langfuse trace, Prometheus scrapes custom metrics.
