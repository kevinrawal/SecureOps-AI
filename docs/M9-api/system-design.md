# M9 — API Layer System Design

## Goal

Expose the SecureOps AI pipeline over HTTP via a FastAPI application. Every route
is protected by JWT RBAC (enforced by `require_role` dependencies from M7), rate-limited
via slowapi, and instrumented with OTel tracing from M8. SSRFGuard is wired at the
ingest boundary — the first point external data enters the system.

---

## Routes

| Method | Path | Min role | Rate limit | Purpose |
|---|---|---|---|---|
| `POST` | `/auth/token` | public | — | Issue JWT (dev-only demo endpoint) |
| `POST` | `/events/ingest` | ANALYST | 100/min per IP | Normalise + enqueue event |
| `GET` | `/events/{event_id}` | ANALYST | — | Query audit log for event status |
| `POST` | `/threats/{event_id}/approve` | ENGINEER | 20/min per user | Resume HITL-interrupted graph |
| `GET` | `/runbooks` | ANALYST | — | List runbooks from Pinecone |
| `POST` | `/runbooks` | ADMIN | — | Upsert runbook into Pinecone |
| `DELETE` | `/runbooks/{id}` | ADMIN | — | Delete runbook from Pinecone |
| `GET` | `/health` | public | — | Liveness/readiness check |
| `GET` | `/metrics` | public | — | Prometheus scrape endpoint |

---

## Security Model

### JWT flow
1. Client `POST /auth/token` → receives `{"access_token": "...", "token_type": "bearer"}`.
2. All protected routes extract the token via `OAuth2PasswordBearer` (header: `Authorization: Bearer <token>`).
3. `require_role(min_role)` dependency decodes JWT, validates role hierarchy, raises 401/403 on failure.

### SSRFGuard at ingest
`POST /events/ingest` scans every string value in the raw `data` payload before
passing it to the Normalizer. Any value that looks like a URL (starts with `http://`,
`https://`, `file://`, etc.) is passed through `SSRFGuard.check()`. A blocked URL
returns HTTP 400 before any normalisation or queueing occurs.

---

## Middleware Stack (request → response order)

```
HTTP request
  → CORSMiddleware
  → RequestIDMiddleware  (assigns/reads X-Request-ID, writes to response header)
  → StructlogMiddleware  (binds request_id, method, path to structlog context)
  → route handler
```

---

## FastAPI Lifespan

```python
@asynccontextmanager
async def lifespan(app):
    setup_tracing("secureops-api")   # M8: register OTel TracerProvider
    await init_pinecone()            # warm Pinecone connection (avoid cold start on first request)
    yield
    await get_engine().dispose()     # drain SQLAlchemy connection pool
```

---

## Rate Limiting

slowapi is used with a shared `Limiter` instance (defined in `src/api/limiter.py`
and imported by both `main.py` and individual route modules).

- `POST /events/ingest`: `@limiter.limit("100/minute")` — per IP
- `POST /threats/{id}/approve`: `@limiter.limit("20/minute")` — per IP
- `RateLimitExceeded` handler returns HTTP 429

---

## Health Check Design

`GET /health` runs three concurrent checks and reports individual component status:

| Component | Check | Timeout |
|---|---|---|
| PostgreSQL | `SELECT 1` via AsyncEngine | 3 s |
| Redis | `PING` via redis-py asyncio | 3 s |
| Pinecone | `describe_index_stats()` via thread | 5 s |

Returns `{"status": "ok"|"degraded", "checks": {"postgres": "ok"|"error: ...", ...}}`.
Always returns HTTP 200 — callers check `status` field. A 5xx means the health
endpoint itself crashed.

---

## HITL Approve Endpoint

`POST /threats/{event_id}/approve` resumes a graph that was suspended at
`human_review_node`. The graph checkpointer maps `thread_id → event_id` to
look up the interrupted state.

In M9: `MemorySaver` is used (in-process, non-persistent). The approve endpoint
only works if the same process previously ran the graph to the HITL interrupt point.

In M10: replaced with `AsyncPostgresSaver` — persistent across processes.

---

## Acceptance Criteria

1. `POST /events/ingest` normalises + enqueues; returns `{event_id, queued: true}`.
2. `POST /threats/{id}/approve` with ENGINEER token resumes HITL graph and returns report.
3. `POST /runbooks` rejects ANALYST token with 403.
4. `GET /health` returns 200 with all checks passing when compose is running.
5. Rate limit returns 429 when exceeded.
6. Unauthenticated request returns 401.
