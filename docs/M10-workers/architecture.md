# M10 Workers — Architecture

## Component Map

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  External                                                                   │
│  ┌────────────────────┐       ┌─────────────────────────┐                  │
│  │  NVD API 2.0       │       │  POST /events/ingest     │ (M9 API)         │
│  │  (batch, 1×/day)   │       │  (real-time, ANALYST+)   │                  │
│  └─────────┬──────────┘       └───────────┬─────────────┘                  │
└────────────┼─────────────────────────────-┼────────────────────────────────┘
             │  fetch_recent_nvd_cves()      │  publish(event)
             │  SSRFGuard → NVDAdapter       │
             ▼                               ▼
     ┌───────────────────────────────────────────────┐
     │           Redis Stream  secureops:events       │
     │           (XADD / XREADGROUP / XACK)          │
     └───────────────────────┬───────────────────────┘
                             │  XREADGROUP (consumer group: secureops-workers)
          ┌──────────────────┼──────────────────┐
          ▼                  ▼                  ▼
    ┌──────────┐       ┌──────────┐       ┌──────────┐
    │ worker-0 │       │ worker-1 │       │ worker-N │
    └────┬─────┘       └────┬─────┘       └────┬─────┘
         │                  │                  │
         └──────────────────┼──────────────────┘
                            │  graph.ainvoke(ThreatState, config)
                            ▼
              ┌─────────────────────────┐
              │   CompiledGraph         │
              │   (AsyncPostgresSaver)  │
              │                         │
              │  injection_check        │
              │     → retrieve          │
              │     → grade             │
              │     → remediation       │
              │     → human_review ─── interrupt() ──► POST /threats/approve (M9)
              │     → reporter          │
              └──────────┬──────────────┘
                         │ success: XACK
                         │ failure (≥3): XADD secureops:dlq + XACK
                         ▼
              ┌─────────────────────────┐
              │  PostgreSQL             │
              │  audit_entries table    │
              │  + LG checkpoint tables │
              └─────────────────────────┘
```

## Retry / DLQ Sequence

```
Worker                      Redis                     DLQ stream
  │                           │                           │
  │── XREADGROUP ────────────►│                           │
  │◄─ msg (id=1-0) ───────────│                           │
  │── graph.ainvoke() ──FAIL  │                           │
  │   retry_count[1-0] = 1    │                           │
  │   (no ACK)                │                           │
  │                           │                           │
  │── XREADGROUP ────────────►│                           │
  │◄─ msg (id=1-0) ───────────│  (same msg from PEL)      │
  │── graph.ainvoke() ──FAIL  │                           │
  │   retry_count[1-0] = 2    │                           │
  │                           │                           │
  │── XREADGROUP ────────────►│                           │
  │◄─ msg (id=1-0) ───────────│                           │
  │── graph.ainvoke() ──FAIL  │                           │
  │   retry_count[1-0] = 3    │                           │
  │   (>= MAX_RETRIES)        │                           │
  │── XADD dlq payload ──────────────────────────────────►│
  │── XACK 1-0 ──────────────►│                           │
  │   retry_counts pop(1-0)   │                           │
```

## Data Flow: Batch Ingest

```
run_batch_ingest()
    │
    ├── fetch_recent_nvd_cves(days_back=1)
    │       │
    │       ├── SSRFGuard.check({"url": NVD_URL})  ← blocks SSRF, always passes for nvd.nist.gov
    │       ├── httpx GET NVD API 2.0 (pubStartDate / pubEndDate)
    │       ├── NVDAdapter.parse(vuln) × N  →  SecureEvent × N
    │       └── return [SecureEvent, ...]
    │
    └── publish(event) × N  →  XADD secureops:events
```

## Module Boundaries

| Module | Responsibility | Depends on |
|---|---|---|
| `src/workers/consumer.py` | Pool lifecycle, read-ack loop, DLQ routing | `RedisStreamBackend`, `build_graph`, `AsyncPostgresSaver` |
| `src/workers/batch_ingest.py` | NVD fetch, parse, publish | `NVDAdapter`, `SSRFGuard`, `publish`, `httpx` |
| `src/graph/builder.py` | Graph compilation (unchanged) | All agent nodes, checkpointer |
| `src/ingestion/queue/redis_backend.py` | Transport (unchanged) | `redis.asyncio` |
