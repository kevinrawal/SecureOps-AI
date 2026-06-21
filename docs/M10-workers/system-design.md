# M10 Workers — System Design

## Goal

Ship a horizontally-scalable async worker pool that drains the Redis Stream event queue
and a scheduled batch ingest job that pulls recent CVEs from the NVD API 2.0.

---

## Components

### 1. Redis Stream Consumer Pool (`src/workers/consumer.py`)

Each worker is an async coroutine that runs an infinite read-process-ack loop against the
`secureops:events` Redis Stream using consumer group semantics.

**Why consumer groups?**  
Redis consumer group delivery guarantees exactly-once processing across a pool: each
pending entry is assigned to one consumer. If that consumer crashes before acking, the
entry stays in the Pending Entries List (PEL) and can be reclaimed. This prevents both
duplicate and dropped events.

**Flow per message:**
```
XREADGROUP → _process_message() → graph.ainvoke() → XACK
                                        ↓ on exception
                               increment _retry_counts[msg_id]
                               if count >= MAX_RETRIES:
                                   XADD secureops:dlq
                                   XACK (remove from PEL)
```

**Dead-letter queue (DLQ):**  
After `MAX_RETRIES = 3` consecutive failures the message is appended to the
`secureops:dlq` stream with metadata (original_message_id, error, retries) and
acknowledged on the main stream. This prevents poison pills from blocking a worker
indefinitely while preserving the original payload for post-mortem analysis.

**Checkpointer upgrade — AsyncPostgresSaver:**  
M9 used `MemorySaver` (in-process, zero persistence). M10 replaces it with
`AsyncPostgresSaver` (`langgraph-checkpoint-postgres`), which persists HITL interrupt
state to PostgreSQL. This means `human_review` interrupts survive worker restarts.

**Horizontal scaling:**  
`WORKER_COUNT` env var controls the pool size. Each worker is an independent coroutine
in `asyncio.gather()`; raising the count to 10 requires only a config change and a
restart — no code changes.

### 2. NVD Batch Ingest (`src/workers/batch_ingest.py`)

Scheduled job that:
1. Queries NVD API 2.0 for CVEs published in the last N days.
2. Validates the fetch URL with SSRFGuard (defence-in-depth for dynamic feed URLs).
3. Parses each CVE through `NVDAdapter.parse()` → `SecureEvent`.
4. Publishes each event to the Redis Stream via the existing `publish()` producer.

Workers then pick up each CVE event and run it through the full agent pipeline.

---

## Security

| Concern | Mitigation |
|---|---|
| SSRF via feed URL | SSRFGuard validates every URL before HTTP call |
| Unvalidated NVD response | NVDAdapter.parse() defensive-extracts; no eval |
| Poison pill / infinite retry | DLQ after MAX_RETRIES=3 |
| HITL checkpoint tampering | AsyncPostgresSaver rows protected by DB RBAC |
| Agent graph RBAC | ThreatState carries `role=ANALYST` for all worker-dispatched events |

---

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `WORKER_COUNT` | `3` | Number of concurrent consumer coroutines |
| `REDIS_STREAM_NAME` | `secureops:events` | Main event stream |
| `REDIS_STREAM_DLQ` | `secureops:dlq` | Dead-letter stream |
| `NVD_API_KEY` | `` (empty) | Raises NVD rate limit from 5 to 50 req/30s |
| `DATABASE_URL` | computed | AsyncPostgresSaver connection string |

---

## Acceptance Criteria

- N workers consume concurrently; each acks only after successful `graph.ainvoke()`.
- 3 consecutive failures → message appears in `secureops:dlq`, removed from main PEL.
- `WORKER_COUNT=5` spins exactly 5 coroutines without code changes.
- `run_batch_ingest()` fetches yesterday's CVEs and publishes them to the stream.
- All 10+ integration tests pass offline (Redis/Postgres/graph mocked).
