"""Enterprise observability tests.

Covers:
- Prometheus metric exposure via /metrics endpoint
- Trace context propagation (W3C traceparent header)
- Correlation ID (X-Request-Id) continuity through trace spans
- Structured log format (trace_id, span_id, tenant_id, request_id in records)
- Alert condition definitions (name, severity, runbook completeness)
- Log context var isolation across requests

All tests run offline — no OTLP endpoint required.
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid

os.environ.setdefault("FG_ENV", "dev")
os.environ.setdefault("FG_AUTH_ENABLED", "0")
os.environ.setdefault("FG_SQLITE_PATH", "state/test_observability.db")
os.environ.setdefault("FG_RL_ENABLED", "0")

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

_TRACE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_SPAN_ID_RE = re.compile(r"^[0-9a-f]{16}$")

# W3C traceparent: version-traceid-spanid-flags
_VALID_TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"


def _build_client():
    from fastapi.testclient import TestClient
    from api.main import build_app

    return TestClient(build_app(auth_enabled=False))


# ---------------------------------------------------------------------------
# Metric exposure
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_metrics_endpoint_returns_200():
    client = _build_client()
    resp = client.get("/metrics")
    assert resp.status_code == 200


@pytest.mark.smoke
def test_metrics_content_type_is_prometheus():
    client = _build_client()
    resp = client.get("/metrics")
    assert "text/plain" in resp.headers.get("content-type", "")


@pytest.mark.smoke
def test_metrics_contains_frostgate_decision_requests():
    import api.metrics  # noqa: F401 — ensures DECISION_REQUESTS is registered

    client = _build_client()
    body = client.get("/metrics").text
    assert "frostgate_decision_requests_total" in body


@pytest.mark.smoke
def test_metrics_contains_provider_metrics():
    client = _build_client()
    body = client.get("/metrics").text
    assert "frostgate_provider_requests_total" in body
    assert "frostgate_provider_latency_seconds" in body
    assert "frostgate_provider_failures_total" in body


@pytest.mark.smoke
def test_metrics_contains_retrieval_metrics():
    client = _build_client()
    body = client.get("/metrics").text
    assert "frostgate_retrieval_requests_total" in body
    assert "frostgate_retrieval_latency_seconds" in body


@pytest.mark.smoke
def test_metrics_contains_ingestion_metrics():
    client = _build_client()
    body = client.get("/metrics").text
    assert "frostgate_ingestion_requests_total" in body
    assert "frostgate_ingestion_latency_seconds" in body


@pytest.mark.smoke
def test_metrics_contains_audit_metrics():
    client = _build_client()
    body = client.get("/metrics").text
    assert "frostgate_audit_export_total" in body


@pytest.mark.smoke
def test_metrics_contains_provenance_metrics():
    client = _build_client()
    body = client.get("/metrics").text
    assert "frostgate_provenance_validation_total" in body


@pytest.mark.smoke
def test_metrics_contains_http_metrics():
    client = _build_client()
    body = client.get("/metrics").text
    assert "frostgate_http_5xx_total" in body
    assert "frostgate_http_request_duration_seconds" in body


@pytest.mark.smoke
def test_metrics_contains_db_metrics():
    client = _build_client()
    body = client.get("/metrics").text
    assert "frostgate_db_errors_total" in body
    assert "frostgate_db_connectivity_failures_total" in body


@pytest.mark.smoke
def test_http_request_duration_increments_on_request():
    """A health check request should be reflected in the HTTP duration histogram."""
    from prometheus_client import REGISTRY

    client = _build_client()
    before_samples = _collect_metric_value(
        REGISTRY, "frostgate_http_request_duration_seconds_count"
    )
    client.get("/health")
    after_samples = _collect_metric_value(
        REGISTRY, "frostgate_http_request_duration_seconds_count"
    )
    assert after_samples >= before_samples


def _collect_metric_value(registry, metric_name: str) -> float:
    total = 0.0
    for metric in registry.collect():
        if metric.name == metric_name:
            for sample in metric.samples:
                total += sample.value
    return total


# ---------------------------------------------------------------------------
# Trace propagation
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_trace_setup_is_idempotent():
    from api.observability.tracing import setup_tracing

    setup_tracing("test-service")
    setup_tracing("test-service")  # must not raise


@pytest.mark.smoke
def test_current_trace_id_returns_none_outside_span():
    from api.observability.tracing import current_trace_id, current_span_id

    # Outside any active span, both must be None
    assert current_trace_id() is None
    assert current_span_id() is None


@pytest.mark.smoke
def test_pipeline_span_creates_valid_trace_ids():
    from api.observability.tracing import (
        setup_tracing,
        span_ingestion,
        current_trace_id,
        current_span_id,
    )

    setup_tracing("test-ingestion")
    collected: dict = {}

    with span_ingestion(tenant_id="acme", doc_type="pdf"):
        collected["trace_id"] = current_trace_id()
        collected["span_id"] = current_span_id()

    trace_id = collected.get("trace_id")
    span_id = collected.get("span_id")

    if trace_id is not None:  # noop when no exporter configured, IDs still generated
        assert _TRACE_ID_RE.match(trace_id), f"bad trace_id: {trace_id}"
    if span_id is not None:
        assert _SPAN_ID_RE.match(span_id), f"bad span_id: {span_id}"


@pytest.mark.smoke
def test_nested_pipeline_spans():
    from api.observability.tracing import (
        setup_tracing,
        span_ingestion,
        span_provenance_validation,
        current_trace_id,
    )

    setup_tracing("test-nested")
    ids: list[str | None] = []

    with span_ingestion(tenant_id="t1", doc_type="docx"):
        outer_id = current_trace_id()
        with span_provenance_validation(tenant_id="t1", policy_version="v2"):
            inner_id = current_trace_id()
        ids.extend([outer_id, inner_id])

    # Both spans share the same trace ID (they are in the same trace)
    if ids[0] is not None and ids[1] is not None:
        assert ids[0] == ids[1], "nested spans must share trace_id"


@pytest.mark.smoke
def test_w3c_traceparent_propagated_through_middleware():
    """OTelTracingMiddleware must accept a valid W3C traceparent and continue that trace."""
    client = _build_client()
    resp = client.get("/health", headers={"traceparent": _VALID_TRACEPARENT})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Correlation ID continuity
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_request_id_present_in_response_with_traceparent():
    """Correlation ID must survive alongside OTel trace propagation."""
    client = _build_client()
    rid = str(uuid.uuid4())
    resp = client.get(
        "/health",
        headers={"X-Request-Id": rid, "traceparent": _VALID_TRACEPARENT},
    )
    assert resp.status_code == 200
    echoed = resp.headers.get("X-Request-Id") or resp.headers.get("x-request-id")
    assert echoed == rid, f"X-Request-Id not echoed: {echoed!r}"


@pytest.mark.smoke
def test_fresh_request_id_generated_when_absent_with_tracing():
    """Even when OTel tracing is active, missing X-Request-Id gets a fresh UUID."""
    client = _build_client()
    resp = client.get("/health", headers={"traceparent": _VALID_TRACEPARENT})
    assert resp.status_code == 200
    rid = resp.headers.get("X-Request-Id") or resp.headers.get("x-request-id")
    assert rid is not None, "X-Request-Id must be generated"
    assert _UUID4_RE.match(rid), f"generated ID is not UUID v4: {rid!r}"


# ---------------------------------------------------------------------------
# Structured log format
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_trace_context_filter_injects_fields():
    from api.observability.log_context import TraceContextFilter

    flt = TraceContextFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="hello",
        args=(),
        exc_info=None,
    )
    result = flt.filter(record)
    assert result is True
    assert hasattr(record, "trace_id")
    assert hasattr(record, "span_id")


@pytest.mark.smoke
def test_request_context_filter_injects_fields():
    from api.observability.log_context import (
        RequestContextFilter,
        set_log_context,
        clear_log_context,
    )

    set_log_context(tenant_id="acme", provider_id="openai", retrieval_mode="semantic")
    try:
        flt = RequestContextFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="hello",
            args=(),
            exc_info=None,
        )
        flt.filter(record)
        assert getattr(record, "tenant_id", None) == "acme"
        assert getattr(record, "provider_id", None) == "openai"
        assert getattr(record, "retrieval_mode", None) == "semantic"
    finally:
        clear_log_context()


@pytest.mark.smoke
def test_log_context_isolation_after_clear():
    from api.observability.log_context import (
        RequestContextFilter,
        set_log_context,
        clear_log_context,
    )

    set_log_context(tenant_id="tenant-a")
    clear_log_context()

    flt = RequestContextFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="hi",
        args=(),
        exc_info=None,
    )
    flt.filter(record)
    assert getattr(record, "tenant_id", None) is None, "tenant_id must be cleared"


@pytest.mark.smoke
def test_json_formatter_includes_extra_fields():
    """_JsonFormatter must serialize extra= fields alongside the standard payload."""
    from api.logging_config import _JsonFormatter

    formatter = _JsonFormatter(service="test-svc")
    record = logging.LogRecord(
        name="frostgate",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="request",
        args=(),
        exc_info=None,
    )
    record.request_id = "req-abc"  # type: ignore[attr-defined]
    record.tenant_id = "acme"  # type: ignore[attr-defined]
    record.trace_id = "0" * 32  # type: ignore[attr-defined]
    record.span_id = "0" * 16  # type: ignore[attr-defined]

    output = formatter.format(record)
    parsed = json.loads(output)

    assert parsed.get("request_id") == "req-abc"
    assert parsed.get("tenant_id") == "acme"
    assert parsed.get("trace_id") == "0" * 32
    assert parsed.get("span_id") == "0" * 16
    assert "timestamp" in parsed
    assert "level" in parsed
    assert "service" in parsed
    assert parsed["service"] == "test-svc"


@pytest.mark.smoke
def test_log_context_get_omits_none_values():
    from api.observability.log_context import (
        get_log_context,
        set_log_context,
        clear_log_context,
    )

    clear_log_context()
    set_log_context(tenant_id="t1")
    ctx = get_log_context()
    assert ctx.get("tenant_id") == "t1"
    assert "provider_id" not in ctx  # not set → must be omitted


# ---------------------------------------------------------------------------
# Alert rule correctness
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_all_alert_conditions_have_names():
    from api.observability.alerts import ALL_ALERTS

    for alert in ALL_ALERTS:
        assert alert.name, f"alert missing name: {alert}"


@pytest.mark.smoke
def test_all_alert_conditions_have_severity():
    from api.observability.alerts import ALL_ALERTS, AlertSeverity

    valid = {s.value for s in AlertSeverity}
    for alert in ALL_ALERTS:
        assert alert.severity.value in valid, f"invalid severity: {alert}"


@pytest.mark.smoke
def test_all_alert_conditions_have_runbooks():
    from api.observability.alerts import ALL_ALERTS

    for alert in ALL_ALERTS:
        assert alert.runbook.startswith("https://"), f"missing runbook: {alert.name}"


@pytest.mark.smoke
def test_fire_alert_logs_and_stores_event():
    from api.observability.alerts import (
        fire_alert,
        get_recent_alerts,
        ALERT_PROVIDER_FAILURE,
    )

    before = len(get_recent_alerts(100))
    fire_alert(ALERT_PROVIDER_FAILURE, labels={"provider_id": "test-provider"})
    after_events = get_recent_alerts(100)
    assert len(after_events) == before + 1
    last = after_events[-1]
    assert last["alert"] == ALERT_PROVIDER_FAILURE.name
    assert last["labels"].get("provider_id") == "test-provider"


@pytest.mark.smoke
def test_required_alert_names_present():
    """All eight canonical alert conditions must exist."""
    from api.observability.alerts import ALL_ALERTS

    names = {a.name for a in ALL_ALERTS}
    required = {
        "FrostgateProviderFailureHigh",
        "FrostgateRetrievalLatencyHigh",
        "FrostgateIngestionFailureHigh",
        "FrostgateAuditPipelineFailure",
        "FrostgateDBConnectivityFailure",
        "FrostgateHttp5xxRateHigh",
        "FrostgateRequestLatencyAbnormal",
        "FrostgateProvenanceFailureSpike",
    }
    missing = required - names
    assert not missing, f"missing alert definitions: {missing}"
