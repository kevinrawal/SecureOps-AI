# M8 — Observability Architecture

## Data Flow

```
Agent node called
      │
      ▼
instrument_node decorator
      ├── OTel span start  ─────────────────────────────────────────────────────┐
      │         (secureops.<node_name>)                                          │
      │         attributes: event_id, node                                       │
      │                                                                          │
      ├── [LLM nodes only] get_langfuse_handler()                               │
      │         └── llm.ainvoke(messages, config={"callbacks": [handler]})       │
      │               ├── Langfuse records: prompt, response, token counts       │
      │               └── Langfuse exports → Langfuse-worker → ClickHouse        │
      │                                                                          │
      ├── [retrieve_node only] RETRIEVAL_LATENCY.observe(duration)              │
      ├── [injection_check_node] INJECTION_BLOCKED_TOTAL.inc() on block         │
      ├── [grade_node] GRADE_SCORE_HISTOGRAM.observe(score)                     │
      │                                                                          │
      ├── NODE_LATENCY.labels(node=...).observe(wall_clock_seconds)             │
      └── OTel span end  ──────────────────────────────────────────────────────┘
                │
                ▼
        BatchSpanProcessor
                │
                ▼
        OTLPSpanExporter  ──► Jaeger (:4317 gRPC)  ──► Jaeger UI (:16686)
```

## Prometheus Scrape Path

```
prometheus_client (in-process)
        │
        ▼
  /metrics endpoint (added in M9 via make_asgi_app or generate_latest)
        │
        ▼
  Prometheus (:9090)  scrapes every 15s
        │
        ▼
  Grafana (:3001)  dashboards
```

## Langfuse Data Path

```
CallbackHandler (per LLM call)
        │  async flush
        ▼
Langfuse-web (:3000)  ──► Langfuse-worker  ──► ClickHouse (:8123) [analytics]
                                            └──► MinIO (:9000)     [media/files]
```

## Module Dependencies

```
src/observability/
    otel_setup.py       ← opentelemetry-sdk, opentelemetry-exporter-otlp-proto-grpc
    langfuse_setup.py   ← langfuse (CallbackHandler)
    metrics.py          ← prometheus-client, opentelemetry-api (trace)
                           ↑ imported by all 7 agent nodes
```

## Startup Sequence (M9 FastAPI lifespan)

```python
@asynccontextmanager
async def lifespan(app):
    setup_tracing("secureops-api")   # register OTel TracerProvider globally
    await init_pinecone()
    yield
    await get_engine().dispose()
```

`setup_tracing` must be called before any agent node is invoked so that
`trace.get_tracer("secureops.agents")` returns the real provider, not the
no-op default.

## Key Design Decisions

- **No-op until startup**: before `setup_tracing()` is called, OTel uses the default
  no-op tracer — spans are silently discarded. This means unit tests run without
  any OTel infrastructure.
- **Langfuse optional**: `get_langfuse_handler()` returns `None` when keys are absent.
  Nodes check for `None` before adding to the callbacks list — zero overhead in
  unconfigured environments.
- **Fresh handler per call**: `get_langfuse_handler()` creates a new `CallbackHandler`
  instance on every invocation. This is intentional — LangChain callbacks are
  single-use per invocation and must not be shared across concurrent calls.
- **Prometheus singletons**: all metric objects are module-level constants.
  `prometheus_client` raises `ValueError` on duplicate registration; the module
  is only imported once per process so this is safe.
