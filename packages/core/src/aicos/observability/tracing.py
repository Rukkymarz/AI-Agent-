"""OpenTelemetry + Langfuse wiring (both optional). Spans are no-ops if OTel is absent."""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
from typing import Any


def configure_tracing(service_name: str = "aicos-api") -> bool:  # pragma: no cover - needs collector
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        return False
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317")
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, insecure=True)))
    trace.set_tracer_provider(provider)
    return True


@contextlib.contextmanager
def span(name: str, **attributes: Any) -> Iterator[None]:
    try:
        from opentelemetry import trace
    except ImportError:
        yield
        return
    with trace.get_tracer("aicos").start_as_current_span(name) as s:  # pragma: no cover - optional
        for k, v in attributes.items():
            s.set_attribute(k, str(v))
        yield


def langfuse_callback() -> Any | None:  # pragma: no cover - optional
    """LangChain/LangGraph callback handler for Langfuse if configured."""
    if not os.environ.get("LANGFUSE_PUBLIC_KEY"):
        return None
    try:
        from langfuse.callback import CallbackHandler
    except ImportError:
        return None
    return CallbackHandler()
