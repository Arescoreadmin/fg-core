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


def is_tracing_enabled() -> bool:
    """Return True unless FG_OTEL_ENABLED is explicitly set to a falsy value."""
    val = os.getenv("FG_OTEL_ENABLED", "1").strip().lower()
    return val not in {"0", "false", "no", "off"}


def setup_tracing(service_name: str = "frostgate-core") -> None:
    """Initialize the global TracerProvider. Idempotent — safe to call multiple times.

    Skipped entirely when FG_OTEL_ENABLED=0 (noop spans, zero overhead).
    """
    global _TRACER_PROVIDER
    if _TRACER_PROVIDER is not None:
        return

    if not is_tracing_enabled():
        _log.info("otel_tracing_disabled FG_OTEL_ENABLED=0")
        return

    resource = Resource.create(
        {
            "service.name": service_name,
            "service.version": os.getenv("FG_APP_VERSION", "0.8.0"),
            "deployment.environment": os.getenv("FG_ENV", "dev"),
        }
    )

    # FG_OTEL_SAMPLE_RATIO is canonical; FG_OTEL_SAMPLE_RATE is the legacy alias.
    raw_ratio = (
        os.getenv("FG_OTEL_SAMPLE_RATIO") or os.getenv("FG_OTEL_SAMPLE_RATE") or "1.0"
    )
    sample_rate = float(raw_ratio)
    sampler = ParentBased(TraceIdRatioBased(sample_rate))

    provider = TracerProvider(resource=resource, sampler=sampler)

    otlp_endpoint = os.getenv("FG_OTEL_ENDPOINT", "").strip()
    if otlp_endpoint:
        from api.observability.telemetry_policy import get_policy

        if not get_policy().allows_external_otlp():
            policy = get_policy()
            _log.warning(
                "otel_otlp_blocked_by_policy mode=%s disable_external_otlp=%s endpoint=%s",
                policy.mode,
                policy.disable_external_otlp,
                otlp_endpoint,
            )
        else:
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
    from opentelemetry.trace import NonRecordingSpan, INVALID_SPAN_CONTEXT

    from api.observability.telemetry_policy import get_policy

    policy = get_policy()

    # Per-tenant suppression: yield a non-recording span so the call site
    # works identically but nothing is exported for this tenant.
    tenant_id = attributes.get("tenant.id", "")
    if policy.is_tenant_suppressed(tenant_id):
        yield NonRecordingSpan(INVALID_SPAN_CONTEXT)
        return

    tracer = get_tracer(tracer_name)
    safe_attrs = policy.filter_span_attributes(dict(attributes))
    with tracer.start_as_current_span(span_name, kind=SpanKind.INTERNAL) as span:
        for k, v in safe_attrs.items():
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
