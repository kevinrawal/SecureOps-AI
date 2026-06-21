"""Request-level middleware: request ID assignment + structlog context binding."""
from __future__ import annotations

import uuid
from typing import Callable

import structlog
import structlog.contextvars
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = structlog.get_logger(__name__)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Assign a unique ``X-Request-ID`` to every request and echo it in the response.

    Reads ``X-Request-ID`` from the incoming request headers if present (allows
    upstream proxies to propagate their own IDs); generates a UUID4 otherwise.
    The ID is stored in ``request.state.request_id`` for downstream access.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


class StructlogMiddleware(BaseHTTPMiddleware):
    """Bind per-request fields to the structlog context for the duration of each request.

    Binds ``request_id``, ``method``, and ``path`` so every log line emitted
    during request processing carries these fields automatically. Clears the
    context after the response is sent to prevent cross-request contamination.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = getattr(request.state, "request_id", None) or request.headers.get(
            "X-Request-ID", ""
        )
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
        )
        try:
            response = await call_next(request)
            return response
        finally:
            structlog.contextvars.clear_contextvars()
