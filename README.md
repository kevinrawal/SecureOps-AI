# SecureOps AI

A production-grade multi-agent security intelligence platform: it ingests security events from
heterogeneous sources (CVE feeds, SIEM alerts, syslog, cloud), normalizes them to a common schema, and
runs each through a LangGraph agent pipeline that retrieves vetted runbooks from Pinecone, grades the
retrieval, rewrites the query if needed, generates grounded remediation, and routes critical findings
to human review. Security, observability, and model-swappability are first-class from day one.

> **Status:** Foundation block (Milestones M1–M4) implemented. See
> [the build plan](docs/) and per-milestone design docs under `docs/M*/`.

## Architecture at a glance

```
sources ─► source adapters ─► SecureEvent ─► Redis Stream ─► async workers
                                                                   │
                                                                   ▼
   inject_check ─► retrieve(Pinecone) ─► grade ─►(rewrite loop)─► remediation
                                                                   │
                                                       human_review ─► report
                                                                   │
                                   PostgreSQL (audit) · Langfuse (AI) · Jaeger (sys)
```

Five non-negotiable design principles drive the codebase: **model-swappable** (one factory),
**source-agnostic** (adapter registry), **async-first** (queue behind an interface),
**security-by-design**, and **observability-native**. Details in [`docs/`](docs/).

## Quick start

### 1. Start infrastructure
```bash
docker compose up -d
```
Brings up Postgres (5432), Redis (6379), Jaeger UI (16686), Langfuse (3000), Prometheus (9090),
Grafana (3001 / admin / admin).

### 2. Install dependencies (UV)
```bash
# install uv: https://docs.astral.sh/uv/getting-started/installation/
uv sync                      # base install: free Groq + local HuggingFace embeddings
# optional paid providers:
uv sync --extra openai       # or --extra anthropic
uv sync --extra dev          # test tooling
```
No UV? `pip install -r requirements.txt` works too.

### 3. Configure
```bash
cp .env.example .env         # then fill in the keys below
```

### 4. Seed the runbook knowledge base
```bash
uv run python -m src.rag.runbook_loader
```

### 5. Run the API (available from Milestone M9)
```bash
uv run uvicorn src.api.main:app --reload --port 8000
```

## Getting the free API keys

| Service | Free tier | Where |
|---|---|---|
| **Groq** (LLM) | `llama-3.3-70b-versatile`, 30 req/min | https://console.groq.com → API Keys → `GROQ_API_KEY` |
| **Pinecone** (vectors) | 1 serverless index, 384-dim OK | https://app.pinecone.io → API Keys → `PINECONE_API_KEY` (note your region for `PINECONE_ENVIRONMENT`) |
| **Langfuse** (AI traces) | self-hosted here via Docker | open http://localhost:3000, create a project, copy the public/secret keys into `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` |

Embeddings (`all-MiniLM-L6-v2`) run locally on CPU — **no API key, no cost**.

## Swapping the model
Change `LLM_PROVIDER` (and the matching key) in `.env`. Nothing else changes — see
[`docs/models.md`](docs/models.md).

## Project layout
```
src/core         config, schema, model factory
src/ingestion    source adapters + queue producer
src/rag          Pinecone store + runbook loader
src/agents       LangGraph nodes            (M5–M6)
src/graph        StateGraph builder + routers (M5–M6)
src/security     RBAC, injection, audit     (M7)
src/observability OTel + Langfuse + metrics  (M8)
src/api          FastAPI app + routes       (M9)
src/workers      Redis stream consumers      (M10)
docs/            per-milestone design docs
data/seed_runbooks  seed knowledge base
tests/           unit + integration
```

## Development
```bash
uv run pytest                # run the test suite
```
