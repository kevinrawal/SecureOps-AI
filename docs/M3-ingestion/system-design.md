# M3 — Ingestion & Adapters · System Design

## Purpose
Turn the platform **source-agnostic**. Any raw security payload — NVD CVE JSON, a SIEM webhook, a
syslog line — is normalized into a `SecureEvent` by a dedicated, swappable adapter, then published to
a queue through a backend-agnostic interface. This is the loosely-coupled module the spec marks as
"critical and a big chunk… if in future I want to replace it I can easily do that."

## Two independent abstractions
1. **Source abstraction (`BaseAdapter`)** — isolates *where the data came from* and *how it's shaped*.
2. **Queue abstraction (`QueueBackend`)** — isolates *how events are transported* (Redis Streams now,
   Kafka/SQS/NATS later).

Neither knows about the other; the producer wires them together.

## Adapter design
```
class BaseAdapter(ABC):
    source_type: EventSourceType          # declared by each subclass
    async def parse(raw_data: dict) -> SecureEvent
```
- Each adapter owns *only* its mapping logic: extract title/description/severity/indicators/assets
  and stuff the original payload into `raw_data` untouched.
- A **registry** (`{EventSourceType | source-hint: AdapterClass}`) lets `Normalizer` resolve the right
  adapter without `if/elif` chains. Adding a source = new file + one registry entry (principle #2).

### Adapters in this milestone
| Adapter | Input | Severity mapping |
|---|---|---|
| `NVDAdapter` | NVD CVE 2.0 JSON (per-CVE object) | CVSS v3 base score → CRITICAL≥9 / HIGH≥7 / MEDIUM≥4 / LOW>0 / INFO |
| `SIEMAdapter` | generic webhook JSON | best-effort field map (`severity`/`priority`) with safe fallbacks |
| `SyslogAdapter` | RFC3164/5424-ish text line | PRI facility/severity decode → SeverityLevel |

The NVD adapter also exposes a fetch helper hitting
`https://services.nvd.nist.gov/rest/json/cves/2.0` (used by batch ingest in M10); parsing and fetching
are separate so parsing is testable offline with fixtures.

## Queue design
```
class QueueBackend(ABC):
    async def publish(stream: str, payload: dict) -> str    # returns message id
    async def consume(stream, group, consumer, ...) -> ...   # used by workers (M10)
    async def ack(...) ; async def close()
```
`RedisStreamBackend` implements this over `redis.asyncio` XADD/XREADGROUP/XACK. The producer depends on
the **interface**; swapping to Kafka means writing `KafkaBackend` and changing a factory line — no
producer/consumer code changes (principle #3).

## Producer
`async publish(event: SecureEvent) -> str`: serializes the event (`model_dump_json`) and hands it to
the configured `QueueBackend` on `settings.REDIS_STREAM_NAME`, returning the message id.

## Security considerations entering here
- Adapters **never** invoke an LLM; they are pure transforms → no injection surface yet, but they
  preserve `raw_data` separately so later injection-checking (M7) operates on normalized text only.
- Field-size caps / defensive defaults guard against malformed or oversized payloads (DoS).

## Acceptance criteria
- Sample NVD, SIEM, and syslog payloads each parse to a valid `SecureEvent`.
- `Normalizer.normalize(raw, source_hint)` routes to the correct adapter via the registry.
- `producer.publish(event)` returns a Redis message id; `XLEN` confirms the entry.
- Adding a hypothetical new adapter is documented as a 2-step change.
