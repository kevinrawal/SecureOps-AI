# M8 — Observability System Design

## Goal

Instrument every agent node with two complementary observability layers:

- **Platform observability** — OpenTelemetry (OTel) spans exported to Jaeger + Prometheus metrics
  scraped via `/metrics`.
- **AI observability** — Langfuse v3 traces for every LLM call (tokens, latency, prompt/response).

These are kept strictly separate: OTel tracks infrastructure concerns (latency, errors, request
flow); Langfuse tracks AI concerns (grading quality, rewrite loops, token costs). Neither layer
depends on the other.

---

## Concerns and Separation

| Layer | Tool | What it tracks | Who reads it |
|---|---|---|---|
| Platform tracing | OTel → Jaeger | Distributed spans per agent node | Ops / SRE |
| Platform metrics | Prometheus → Grafana | Counters, histograms, gauges | Ops / SRE |
| AI tracing | Langfuse | LLM calls: prompt, response, tokens | ML / Security team |

---

## OTel Tracing Design (`otel_setup.py`)

Single public function: `setup_tracing(service_name: str) -> TracerProvider`.

- Creates a `TracerProvider` with a `Resource` bearing `service.name`.
- Attaches a `BatchSpanProcessor` wrapping an `OTLPSpanExporter` pointed at
  `settings.OTEL_EXPORTER_OTLP_ENDPOINT` (default `http://localhost:4317`).
- Registers the provider globally via `trace.set_tracer_provider(provider)`.
- Called once at startup (FastAPI lifespan in M9, worker startup in M10).

Each agent node obtains a tracer via `trace.get_tracer("secureops.agents")` — this is cheap
because `get_tracer` returns a proxy; the span goes through the globally registered provider.

Span naming: `secureops.<node_name>` (e.g. `secureops.injection_check`).

Standard span attributes set per node:
- `event_id` — from `state["event_id"]`
- `node` — the node name string

---

## Langfuse Handler Design (`langfuse_setup.py`)

Single public function: `get_langfuse_handler() -> CallbackHandler | None`.

- Returns `None` when `LANGFUSE_SECRET_KEY` or `LANGFUSE_PUBLIC_KEY` is empty —
  safe in test environments with no Langfuse configured.
- Returns a fresh `CallbackHandler` instance on each call; handlers are lightweight
  and stateless wrappers — no pooling needed.
- Passed to `llm.ainvoke(..., config={"callbacks": [handler]})` in the three LLM nodes:
  `grade_node`, `rewrite_node`, `remediation_node`.

---

## Prometheus Metrics Design (`metrics.py`)

Module-level metric singletons (registered once at import time):

| Name | Type | Labels | Purpose |
|---|---|---|---|
| `secureops_retrieval_latency_seconds` | Histogram | — | Pinecone query time |
| `secureops_llm_tokens_total` | Counter | `node`, `token_type` | LLM token usage |
| `secureops_injection_blocked_total` | Counter | — | Adversarial inputs blocked |
| `secureops_grade_score` | Histogram | — | Grader score distribution |
| `secureops_queue_depth_total` | Gauge | — | Redis stream backlog |
| `secureops_node_latency_seconds` | Histogram | `node` | Per-node wall-clock time |

`instrument_node(node_name: str)` — decorator factory:
- Wraps any `async def node(state, ...) -> dict` with an OTel span.
- Records wall-clock duration in `NODE_LATENCY.labels(node=node_name)`.
- Records exceptions on the span and re-raises them.

---

## Instrumentation Per Node

| Node | OTel span | Langfuse callback | Extra metric |
|---|---|---|---|
| `injection_check_node` | `secureops.injection_check` | — | `INJECTION_BLOCKED_TOTAL.inc()` on block |
| `retrieve_node` | `secureops.retrieve` | — | `RETRIEVAL_LATENCY.observe()` around Pinecone call |
| `grade_node` | `secureops.grade` | ✅ | `GRADE_SCORE_HISTOGRAM.observe(score)` |
| `rewrite_node` | `secureops.rewrite` | ✅ | — |
| `remediation_node` | `secureops.remediation` | ✅ | — |
| `human_review_node` | `secureops.human_review` | — | — |
| `reporter_node` | `secureops.reporter` | — | — |

---

## Acceptance Criteria

1. Single event → Jaeger UI shows one trace with child spans for each visited node.
2. Same event → Langfuse UI shows LLM calls from grade/rewrite/remediation with token counts.
3. `GET /metrics` (Prometheus) returns `secureops_retrieval_latency_seconds` and
   `secureops_grade_score` buckets after at least one event is processed.
4. `INJECTION_BLOCKED_TOTAL` increments when an adversarial input is sent.
5. `setup_tracing` is idempotent — calling it twice does not duplicate processors.
