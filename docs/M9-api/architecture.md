# M9 — API Layer Architecture

## Module Structure

```
src/api/
    limiter.py          ← shared slowapi Limiter singleton
    main.py             ← FastAPI app, lifespan, middleware, router registration
    middleware.py       ← RequestIDMiddleware, StructlogMiddleware
    routes/
        auth.py         ← POST /auth/token (dev demo; prod uses external IdP)
        events.py       ← POST /events/ingest, GET /events/{id}
        threats.py      ← POST /threats/{id}/approve
        runbooks.py     ← GET/POST/DELETE /runbooks
        health.py       ← GET /health
```

## Request Data Flow (ingest)

```
Client
  POST /events/ingest
  Authorization: Bearer <JWT>
        │
        ▼
  OAuth2PasswordBearer extracts token
  require_role(ANALYST) validates JWT + role hierarchy
        │  403 on insufficient role
        ▼
  SSRFGuard scans data payload for SSRF URLs
        │  400 on blocked URL
        ▼
  Normalizer.normalize(raw_data, source_type)
        │  422 on unknown source_type / adapter error
        ▼
  producer.publish(SecureEvent)  ──► Redis Stream (secureops:events)
        │
        ▼
  202 Accepted {event_id, queued: true}
```

## Request Data Flow (HITL approve)

```
Client
  POST /threats/{event_id}/approve
  Authorization: Bearer <JWT>
        │
        ▼
  require_role(ENGINEER)
        │  403 on insufficient role
        ▼
  graph.ainvoke(Command(resume={approved, reviewer_id}), config={thread_id: event_id})
        │  reads suspended state from checkpointer
        │  resumes at human_review_node → reporter_node
        │  flushes audit trail to PostgreSQL
        ▼
  200 {event_id, report: {...}}
```

## Limiter Sharing Pattern

slowapi requires the same `Limiter` instance to be in `app.state.limiter` AND used
as the decorator source. The pattern:

```
src/api/limiter.py          defines `limiter = Limiter(...)`
        ↑ imported by
src/api/main.py             app.state.limiter = limiter
src/api/routes/events.py    @limiter.limit("100/minute")
src/api/routes/threats.py   @limiter.limit("20/minute")
```

## Middleware Order

Starlette's `add_middleware` prepends each call, so the last `add_middleware` call
produces the outermost wrapper. Adding in this order:

```python
app.add_middleware(CORSMiddleware, ...)      # [1] added first → innermost
app.add_middleware(RequestIDMiddleware)      # [2]
app.add_middleware(StructlogMiddleware)      # [3] added last  → outermost
```

Results in request order: `StructlogMiddleware → RequestIDMiddleware → CORSMiddleware → routes`

We want RequestID assigned BEFORE Structlog binds it, so add RequestID last:

```python
app.add_middleware(CORSMiddleware, ...)      # outermost: handle CORS preflight first
app.add_middleware(StructlogMiddleware)      # middle: bind log context
app.add_middleware(RequestIDMiddleware)      # innermost: assign ID first (StructlogMiddleware reads it)
```

Wait — the outermost runs first. To ensure RequestID is assigned before Structlog
uses it, RequestIDMiddleware must be the outermost wrapper (added last):

```python
app.add_middleware(CORSMiddleware, ...)
app.add_middleware(StructlogMiddleware)
app.add_middleware(RequestIDMiddleware)      # outermost → runs first
```

## Prometheus Metrics Endpoint

`prometheus_client.make_asgi_app()` is mounted at `/metrics`. This is a standard
ASGI app exposing all registered metrics in Prometheus text format. Prometheus
scrapes it every 15 seconds (configured in `infra/prometheus.yml`).
