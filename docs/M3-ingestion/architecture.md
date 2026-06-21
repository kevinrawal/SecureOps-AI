# M3 — Ingestion & Adapters · Architecture

## Normalization + publish flow

```mermaid
flowchart LR
    subgraph sources["Raw sources"]
        nvd["NVD CVE JSON"]
        siem["SIEM webhook JSON"]
        sys["Syslog text"]
    end

    nvd --> norm
    siem --> norm
    sys --> norm

    subgraph ingestion["ingestion module (loosely coupled)"]
        norm["Normalizer\nlooks up registry"] --> reg{"ADAPTER_REGISTRY"}
        reg -->|CVE| a1["NVDAdapter.parse"]
        reg -->|SIEM_ALERT| a2["SIEMAdapter.parse"]
        reg -->|SYSLOG| a3["SyslogAdapter.parse"]
        a1 --> ev["SecureEvent"]
        a2 --> ev
        a3 --> ev
        ev --> prod["producer.publish"]
    end

    prod --> qb["QueueBackend (interface)"]
    qb -->|impl now| redis[("Redis Stream\nsecureops:events")]
    qb -. impl later .-> kafka[("Kafka / SQS / NATS")]
    redis --> workers["workers (M10)"]
```

## Adapter class hierarchy

```mermaid
classDiagram
    class BaseAdapter {
        <<abstract>>
        +EventSourceType source_type
        +parse(raw_data) SecureEvent*
        #_to_severity(...) SeverityLevel
        #_now_utc() datetime
    }
    class NVDAdapter {
        +parse(cve_json) SecureEvent
        +fetch_recent(...) list~dict~
    }
    class SIEMAdapter { +parse(webhook) SecureEvent }
    class SyslogAdapter { +parse(line) SecureEvent }
    BaseAdapter <|-- NVDAdapter
    BaseAdapter <|-- SIEMAdapter
    BaseAdapter <|-- SyslogAdapter

    class QueueBackend {
        <<abstract>>
        +publish(stream, payload) str*
        +consume(...)*
        +ack(...)*
        +close()*
    }
    class RedisStreamBackend
    QueueBackend <|-- RedisStreamBackend
```

## Key decisions
- **Registry over conditionals.** `ADAPTER_REGISTRY: dict[str, type[BaseAdapter]]`. `Normalizer`
  resolves by `source_type` hint; unknown hints raise a clear error. No central switch to edit per
  source — the registry is the extension point.
- **Parse ≠ fetch.** Adapters are pure `dict -> SecureEvent` so they unit-test offline against
  fixtures. Network fetching (NVD REST) lives in a separate method used only by scheduled ingest.
- **Queue behind an interface.** Producer signature never mentions Redis. `get_queue_backend()` (a
  small factory, mirroring the model factory pattern) returns the configured backend so transport is a
  one-line swap (principle #3).
- **`raw_data` quarantine.** Original payload is stored verbatim on the event for forensics/audit but
  is structurally separate from the normalized text the agents will consume.

## Adding a new source (the documented 2-step path)
1. Create `src/ingestion/adapters/<x>_adapter.py` with a `BaseAdapter` subclass implementing `parse`.
2. Register it: `ADAPTER_REGISTRY[EventSourceType.X] = XAdapter`.
No changes to `Normalizer`, `producer`, the queue, or any agent.
