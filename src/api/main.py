"""FastAPI application: lifespan, middleware wiring, router registration."""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from src.api.limiter import limiter
from src.api.middleware import RequestIDMiddleware, StructlogMiddleware
from src.api.routes import auth, events, health, runbooks, threats
from src.db.engine import get_engine
from src.observability.otel_setup import setup_tracing
from src.rag.pinecone_store import init_pinecone

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application startup and shutdown hooks.

    Startup:
        1. Register OTel TracerProvider (must happen before any spans are created).
        2. Warm the Pinecone connection to avoid cold-start latency on first request.

    Shutdown:
        1. Drain the SQLAlchemy async connection pool cleanly.
    """
    setup_tracing("secureops-api")
    logger.info("secureops_api_startup")
    await init_pinecone()
    yield
    await get_engine().dispose()
    logger.info("secureops_api_shutdown")


def _rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={"detail": f"Rate limit exceeded: {exc.detail}"},
        headers={"Retry-After": "60"},
    )


def create_app() -> FastAPI:
    """Construct and configure the FastAPI application.

    Separated from module-level ``app`` instantiation so tests can call
    ``create_app()`` with patches applied before the instance is created.
    """
    application = FastAPI(
        title="SecureOps AI",
        description="Multi-agent security intelligence platform",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # ── Rate limiting ──────────────────────────────────────────────────────
    application.state.limiter = limiter
    application.add_exception_handler(RateLimitExceeded, _rate_limit_handler)
    application.add_middleware(SlowAPIMiddleware)

    # ── Middleware (last added = outermost = first to process requests) ────
    application.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
    application.add_middleware(StructlogMiddleware)
    application.add_middleware(RequestIDMiddleware)

    # ── Routers ───────────────────────────────────────────────────────────
    application.include_router(auth.router)
    application.include_router(events.router)
    application.include_router(threats.router)
    application.include_router(runbooks.router)
    application.include_router(health.router)

    # ── Prometheus metrics (mounted as a sub-app) ─────────────────────────
    metrics_app = make_asgi_app()
    application.mount("/metrics", metrics_app)

    return application


app: FastAPI = create_app()
