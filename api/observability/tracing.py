"""OpenTelemetry distributed tracing for FrostGate.

Setup via setup_tracing() at ASGI startup. Degrades gracefully when
FG_OTEL_ENDPOINT is unset (no-op spans, zero cost).

Pipeline span helpers (span_ingestion, span_retrieval, etc.) wrap the
respective operations so traces cover the full request lifecycle end-to-end.

Supported exporters (selected by FG_OTEL_ENDPOINT):
  - OTLP/HTTP  — Jaeger, Grafana Tempo, Datadog, Honeycomb, CloudWatch ADOT
  - Console     — set FG_OTEL_CONSOLE=1 for local debugging

Propagation: W3C TraceContext + Baggage (compatible with Datadog, Zipkin B3
via vendor agents that translate at the collector level).
"""

from __future__ import annotations

import contextlib
import logging
import os
from typing import TYPE_CHECKING, Generator, Optional

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
)
from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased
from opentelemetry.propagate import set_global_textmap
from opentelemetry.propagators.composite import CompositePropagator
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from opentelemetry.baggage.propagation import W3CBaggagePropagator
from opentelemetry.trace import SpanKind, Status, StatusCode

if TYPE_CHECKING:
    from opentelemetry.trace import Span

_log = logging.getLogger("frostgate.observability")
_TRACER_PROVIDER: Optional[TracerProvider] = None


def setup_tracing(service_name: str = "frostgate-core") -> None:
    """Initialize the global TracerProvider. Idempotent — safe to call multiple times."""
    global _TRACER_PROVIDER
    if _TRACER_PROVIDER is not None:
        return

    resource = Resource.create(
        {
            "service.name": service_name,
            "service.version": os.getenv("FG_APP_VERSION", "0.8.0"),
            "deployment.environment": os.getenv("FG_ENV", "dev"),
        }
    )

    sample_rate = float(os.getenv("FG_OTEL_SAMPLE_RATE", "1.0"))
    sampler = ParentBased(TraceIdRatioBased(sample_rate))

    provider = TracerProvider(resource=resource, sampler=sampler)

    otlp_endpoint = os.getenv("FG_OTEL_ENDPOINT", "").strip()
    if otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )

            exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
            provider.add_span_processor(BatchSpanProcessor(exporter))
            _log.info("otel_otlp_configured endpoint=%s", otlp_endpoint)
        except ImportError:
            _log.warning(
                "opentelemetry-exporter-otlp-proto-http not installed; OTLP export disabled"
            )
    elif os.getenv("FG_OTEL_CONSOLE", "").strip().lower() in {"1", "true", "yes"}:
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
        _log.info("otel_console_exporter_enabled")

    trace.set_tracer_provider(provider)

    set_global_textmap(
        CompositePropagator(
            [
                TraceContextTextMapPropagator(),
                W3CBaggagePropagator(),
            ]
        )
    )

    _TRACER_PROVIDER = provider


def get_tracer(name: str = "frostgate") -> trace.Tracer:
    return trace.get_tracer(name)


def current_trace_id() -> Optional[str]:
    ctx = trace.get_current_span().get_span_context()
    return format(ctx.trace_id, "032x") if ctx.is_valid else None


def current_span_id() -> Optional[str]:
    ctx = trace.get_current_span().get_span_context()
    return format(ctx.span_id, "016x") if ctx.is_valid else None


@contextlib.contextmanager
def _pipeline_span(
    span_name: str,
    *,
    tracer_name: str = "frostgate.pipeline",
    **attributes: str,
) -> Generator["Span", None, None]:
    tracer = get_tracer(tracer_name)
    with tracer.start_as_current_span(span_name, kind=SpanKind.INTERNAL) as span:
        for k, v in attributes.items():
            if v:
                span.set_attribute(k, v)
        try:
            yield span
        except Exception as exc:
            span.record_exception(exc)
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            raise
        else:
            span.set_status(Status(StatusCode.OK))


@contextlib.contextmanager
def span_ingestion(
    tenant_id: str = "",
    doc_type: str = "",
) -> Generator["Span", None, None]:
    with _pipeline_span(
        "frostgate.ingestion",
        **{"tenant.id": tenant_id, "doc.type": doc_type},
    ) as span:
        yield span


@contextlib.contextmanager
def span_retrieval(
    tenant_id: str = "",
    retrieval_mode: str = "",
) -> Generator["Span", None, None]:
    with _pipeline_span(
        "frostgate.retrieval",
        **{"tenant.id": tenant_id, "retrieval.mode": retrieval_mode},
    ) as span:
        yield span


@contextlib.contextmanager
def span_provider_routing(
    provider_id: str = "",
    tenant_id: str = "",
) -> Generator["Span", None, None]:
    with _pipeline_span(
        "frostgate.provider_routing",
        **{"provider.id": provider_id, "tenant.id": tenant_id},
    ) as span:
        yield span


@contextlib.contextmanager
def span_provenance_validation(
    tenant_id: str = "",
    policy_version: str = "",
) -> Generator["Span", None, None]:
    with _pipeline_span(
        "frostgate.provenance_validation",
        **{"tenant.id": tenant_id, "policy.version": policy_version},
    ) as span:
        yield span


@contextlib.contextmanager
def span_audit_export(
    tenant_id: str = "",
    export_format: str = "",
) -> Generator["Span", None, None]:
    with _pipeline_span(
        "frostgate.audit_export",
        **{"tenant.id": tenant_id, "export.format": export_format},
    ) as span:
        yield span
