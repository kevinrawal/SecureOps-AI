"""OpenTelemetry TracerProvider + OTLP/Jaeger exporter setup."""
from __future__ import annotations

import structlog
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from src.core.config import settings

logger = structlog.get_logger(__name__)


def setup_tracing(service_name: str) -> TracerProvider:
    """Create and globally register an OTel TracerProvider with OTLP/Jaeger export.

    Configures a BatchSpanProcessor that ships spans to the endpoint defined by
    ``settings.OTEL_EXPORTER_OTLP_ENDPOINT`` (default: ``http://localhost:4317``).

    Call once at application startup (FastAPI lifespan or worker entrypoint).
    Subsequent calls to ``trace.get_tracer(...)`` in agent nodes will use the
    registered provider automatically.

    Args:
        service_name: Value for the ``service.name`` OTel resource attribute.
            Use ``"secureops-api"`` for the FastAPI process and
            ``"secureops-worker"`` for the consumer pool.

    Returns:
        The configured ``TracerProvider`` instance.
    """
    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)

    exporter = OTLPSpanExporter(endpoint=settings.OTEL_EXPORTER_OTLP_ENDPOINT)
    processor = BatchSpanProcessor(exporter)
    provider.add_span_processor(processor)

    trace.set_tracer_provider(provider)
    logger.info(
        "otel_tracing_configured",
        service_name=service_name,
        endpoint=settings.OTEL_EXPORTER_OTLP_ENDPOINT,
    )
    return provider
