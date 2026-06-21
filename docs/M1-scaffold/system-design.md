# M1 — Project Scaffold & Config · System Design

## Purpose
Establish the runnable skeleton, local infrastructure, and the single configuration surface that
every other module reads from. Nothing in SecureOps AI hardcodes a credential, host, or model name —
they all resolve through one typed `settings` object loaded from the environment.

## Goal
- A repository tree that matches the target architecture exactly (so later milestones only *fill in*
  files, never *move* them).
- Six local services running via Docker Compose: PostgreSQL, Redis, Jaeger, Langfuse, Prometheus,
  Grafana.
- A typed, validated configuration object (`src/core/config.py`) covering every environment variable.
- Reproducible dependency management via UV (`pyproject.toml` + `uv.lock`), with an exported
  `requirements.txt` for Docker images that don't use UV.

## Why this is its own milestone
Configuration and infrastructure are *foundational invariants*. If they are wrong, every subsequent
milestone inherits the breakage. By freezing the config contract and the service topology first, the
agent graph (M5+), security (M7), and observability (M8) milestones can assume their backing services
exist and their settings are reachable.

## Configuration domains (env var groups)
| Domain | Examples | Consumed by |
|---|---|---|
| LLM | `LLM_PROVIDER`, `GROQ_MODEL`, `OPENAI_MODEL` | `models_factory` (M2) |
| Embedding | `EMBEDDING_PROVIDER`, `EMBEDDING_MODEL`, `EMBEDDING_DIMENSION` | `models_factory`, RAG (M4) |
| Pinecone | `PINECONE_API_KEY`, `PINECONE_INDEX_NAME` | RAG (M4) |
| Redis | `REDIS_URL`, `REDIS_STREAM_NAME`, `WORKER_COUNT` | producer (M3), workers (M10) |
| Postgres | `DATABASE_URL` | audit (M7) |
| JWT | `JWT_SECRET_KEY`, `JWT_ALGORITHM`, `JWT_EXPIRE_MINUTES` | RBAC (M7) |
| Observability | `LANGFUSE_*`, `OTEL_EXPORTER_OTLP_ENDPOINT` | observability (M8) |
| App | `APP_ENV`, `LOG_LEVEL` | everywhere (logging) |

## Acceptance criteria
- `docker compose up -d` brings all six services to a healthy/reachable state.
- `uv sync` resolves the dependency graph.
- `from src.core.config import settings` loads and validates `.env`; missing required secrets fail
  loudly at startup (fail-fast), not at first use.
- README documents quick start + how to obtain free Groq / Pinecone / Langfuse keys.

## Risks & mitigations
- **Langfuse self-host complexity** — it needs its own Postgres DB. Mitigation: give Langfuse a
  dedicated database/URL inside the same Postgres container (or a separate one) and document it.
- **Secrets in the repo** — `.gitignore` excludes `.env`; only `.env.example` is committed.
- **Port collisions** (Grafana vs Langfuse both default to 3000) — Grafana is remapped to host 3001.
