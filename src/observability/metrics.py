"""Custom Prometheus metrics and OTel node instrumentation decorator."""
from __future__ import annotations

import functools
import time
from typing import Any, Callable, TypeVar

import structlog
from opentelemetry import trace
from opentelemetry.trace import StatusCode
from prometheus_client import Counter, Gauge, Histogram

logger = structlog.get_logger(__name__)

# ── Prometheus metric singletons (registered once at import time) ─────────────

RETRIEVAL_LATENCY = Histogram(
    "secureops_retrieval_latency_seconds",
    "Wall-clock latency of the Pinecone vector-store retrieval call in seconds",
    buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0],
)

LLM_TOKENS_TOTAL = Counter(
    "secureops_llm_tokens_total",
    "Total LLM tokens consumed by the pipeline",
    labelnames=["node", "token_type"],
)

INJECTION_BLOCKED_TOTAL = Counter(
    "secureops_injection_blocked_total",
    "Total number of events blocked by the injection guardrail",
)

GRADE_SCORE_HISTOGRAM = Histogram(
    "secureops_grade_score",
    "Distribution of LLM retrieval grader scores (0.0–1.0)",
    buckets=[0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
)

QUEUE_DEPTH_GAUGE = Gauge(
    "secureops_queue_depth_total",
    "Current number of unprocessed events in the Redis stream",
)

NODE_LATENCY = Histogram(
    "secureops_node_latency_seconds",
    "Wall-clock latency per agent node in seconds",
    labelnames=["node"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

# ── instrument_node decorator ─────────────────────────────────────────────────

_NodeFn = TypeVar("_NodeFn", bound=Callable[..., Any])


def instrument_node(node_name: str) -> Callable[[_NodeFn], _NodeFn]:
    """Decorator factory: wrap an async agent node with an OTel span and latency metric.

    Creates a span named ``secureops.<node_name>`` using the globally registered
    TracerProvider (no-op until ``setup_tracing()`` is called at startup).
    Records wall-clock duration in ``NODE_LATENCY`` regardless of whether
    tracing is configured.

    Span attributes set on every call:
        - ``event_id``: extracted from ``state["event_id"]``
        - ``node``: the node name string

    On exception, records the exception on the span, sets status to ERROR,
    then re-raises so LangGraph sees the failure.

    Args:
        node_name: Short name for the node, e.g. ``"injection_check"``.
            Used for the span name and the ``node`` Prometheus label.

    Returns:
        A decorator that preserves the wrapped function's signature.
    """
    def decorator(fn: _NodeFn) -> _NodeFn:
        @functools.wraps(fn)
        async def wrapper(state: Any, *args: Any, **kwargs: Any) -> Any:
            tracer = trace.get_tracer("secureops.agents")
            event_id: str = state.get("event_id", "") if isinstance(state, dict) else ""
            t_start = time.perf_counter()

            with tracer.start_as_current_span(f"secureops.{node_name}") as span:
                span.set_attribute("event_id", event_id)
                span.set_attribute("node", node_name)
                try:
                    result = await fn(state, *args, **kwargs)
                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    span.record_exception(exc)
                    span.set_status(StatusCode.ERROR, str(exc))
                    raise
                finally:
                    NODE_LATENCY.labels(node=node_name).observe(
                        time.perf_counter() - t_start
                    )

        return wrapper  # type: ignore[return-value]

    return decorator
