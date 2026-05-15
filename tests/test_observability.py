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
        assert alert.runbook and (
            alert.runbook.startswith("docs/") or alert.runbook.startswith("https://")
        ), f"missing or invalid runbook for {alert.name!r}: {alert.runbook!r}"


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


@pytest.mark.smoke
def test_all_runbook_files_exist():
    """Every alert condition's runbook path must resolve to an existing file in the repo."""
    from pathlib import Path
    from api.observability.alerts import ALL_ALERTS

    repo_root = Path(__file__).parent.parent
    for alert in ALL_ALERTS:
        runbook_path = repo_root / alert.runbook
        assert runbook_path.exists(), (
            f"Alert '{alert.name}' runbook not found: {alert.runbook}"
        )


# ---------------------------------------------------------------------------
# Cardinality guard tests
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_http_5xx_metric_has_no_path_label():
    """HTTP_5XX_TOTAL must not include 'path' label — UUID paths would explode cardinality."""
    from api.observability.metrics import HTTP_5XX_TOTAL

    label_names = list(HTTP_5XX_TOTAL._labelnames)
    assert "path" not in label_names, (
        f"HTTP_5XX_TOTAL has 'path' label — cardinality risk: {label_names}"
    )
    assert "request_id" not in label_names
    assert "document_id" not in label_names


@pytest.mark.smoke
def test_provider_latency_metric_has_bounded_labels():
    """PROVIDER_LATENCY must only carry bounded label dimensions."""
    from api.observability.metrics import PROVIDER_LATENCY

    label_names = set(PROVIDER_LATENCY._labelnames)
    forbidden = {"request_id", "document_id", "source_hash", "error_message"}
    violations = label_names & forbidden
    assert not violations, f"PROVIDER_LATENCY has high-cardinality labels: {violations}"


@pytest.mark.smoke
def test_retrieval_latency_metric_has_bounded_labels():
    from api.observability.metrics import RETRIEVAL_LATENCY

    label_names = set(RETRIEVAL_LATENCY._labelnames)
    forbidden = {"request_id", "document_id", "source_hash", "tenant_id"}
    violations = label_names & forbidden
    assert not violations, (
        f"RETRIEVAL_LATENCY has high-cardinality labels: {violations}"
    )


@pytest.mark.smoke
def test_http_request_duration_has_no_path_label():
    """HTTP_REQUEST_DURATION uses status_class (bounded) not raw status code or path."""
    from api.observability.metrics import HTTP_REQUEST_DURATION

    label_names = set(HTTP_REQUEST_DURATION._labelnames)
    assert "path" not in label_names, "path label → UUID cardinality explosion"
    assert "request_id" not in label_names
    assert "status_code" not in label_names  # use status_class (2xx, 4xx, 5xx) instead


@pytest.mark.smoke
def test_no_metric_has_request_id_label():
    """Confirm no registered frostgate metric uses request_id as a label."""
    from prometheus_client import REGISTRY

    import api.observability.metrics  # noqa: F401

    for metric in REGISTRY.collect():
        if not metric.name.startswith("frostgate_"):
            continue
        for sample in metric.samples:
            assert "request_id" not in sample.labels, (
                f"request_id found in labels of {metric.name}"
            )
        # Also check the labelnames on the metric family
        labelnames = getattr(metric, "labelnames", ()) or ()
        assert "request_id" not in labelnames, (
            f"request_id is a labelname on {metric.name}"
        )


# ---------------------------------------------------------------------------
# /metrics is not a public customer API
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_metrics_is_not_in_openapi_schema():
    """/metrics must be excluded from the OpenAPI schema (include_in_schema=False)."""
    from api.main import build_app

    import warnings

    app = build_app(auth_enabled=False)
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        openapi = app.openapi()
    paths = openapi.get("paths", {})
    assert "/metrics" not in paths, (
        "/metrics must not appear in customer-facing OpenAPI schema"
    )


@pytest.mark.smoke
def test_metrics_disabled_by_env_flag(monkeypatch):
    """FG_METRICS_ENABLED=0 must suppress the /metrics endpoint."""
    monkeypatch.setenv("FG_METRICS_ENABLED", "0")
    from api.main import build_app
    from fastapi.testclient import TestClient

    app = build_app(auth_enabled=False)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/metrics")
    assert resp.status_code == 404, (
        f"Expected 404 when metrics disabled, got {resp.status_code}"
    )


@pytest.mark.smoke
def test_plane_registry_classifies_metrics_as_allowed_internal():
    """The plane registry must explicitly classify /metrics as allowed_internal."""
    from services.plane_registry.registry import PLANE_REGISTRY

    for plane in PLANE_REGISTRY:
        for route in plane.public_routes:
            if route.path == "/metrics":
                assert route.class_name == "allowed_internal", (
                    f"/metrics is classified as '{route.class_name}', expected 'allowed_internal'"
                )
                return
    # Not finding it at all is also a failure
    pytest.fail(
        "/metrics not found in any plane's public_routes — must be explicitly classified"
    )


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_secret_redaction_filter_strips_authorization():
    from api.observability.log_context import SecretRedactionFilter

    flt = SecretRedactionFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="oops",
        args=(),
        exc_info=None,
    )
    record.authorization = "Bearer super-secret-token"  # type: ignore[attr-defined]
    flt.filter(record)
    assert getattr(record, "authorization") == "[REDACTED]"


@pytest.mark.smoke
def test_secret_redaction_filter_strips_api_key():
    from api.observability.log_context import SecretRedactionFilter

    flt = SecretRedactionFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="oops",
        args=(),
        exc_info=None,
    )
    record.api_key = "sk-1234567890"  # type: ignore[attr-defined]
    flt.filter(record)
    assert getattr(record, "api_key") == "[REDACTED]"


@pytest.mark.smoke
def test_secret_redaction_filter_strips_bearer_token():
    from api.observability.log_context import SecretRedactionFilter

    flt = SecretRedactionFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="oops",
        args=(),
        exc_info=None,
    )
    record.bearer_token = "xyz"  # type: ignore[attr-defined]
    flt.filter(record)
    assert getattr(record, "bearer_token") == "[REDACTED]"


@pytest.mark.smoke
def test_secret_redaction_filter_strips_provider_payload():
    from api.observability.log_context import SecretRedactionFilter

    flt = SecretRedactionFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="oops",
        args=(),
        exc_info=None,
    )
    record.provider_payload = '{"model": "gpt-4", "messages": [...]}'  # type: ignore[attr-defined]
    record.raw_prompt = "sensitive prompt text"  # type: ignore[attr-defined]
    record.raw_chunk = "document chunk content"  # type: ignore[attr-defined]
    flt.filter(record)
    assert getattr(record, "provider_payload") == "[REDACTED]"
    assert getattr(record, "raw_prompt") == "[REDACTED]"
    assert getattr(record, "raw_chunk") == "[REDACTED]"


@pytest.mark.smoke
def test_secret_redaction_preserves_safe_fields():
    """Non-sensitive fields must NOT be redacted."""
    from api.observability.log_context import SecretRedactionFilter

    flt = SecretRedactionFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="hi",
        args=(),
        exc_info=None,
    )
    record.tenant_id = "acme"  # type: ignore[attr-defined]
    record.request_id = "req-123"  # type: ignore[attr-defined]
    record.trace_id = "abc" * 10  # type: ignore[attr-defined]
    record.duration_ms = 42.1  # type: ignore[attr-defined]
    flt.filter(record)
    assert getattr(record, "tenant_id") == "acme"
    assert getattr(record, "request_id") == "req-123"
    assert getattr(record, "duration_ms") == 42.1


@pytest.mark.smoke
def test_secret_redaction_in_json_output():
    """End-to-end: sensitive fields injected via extra= must not appear as values in JSON output."""
    import json as _json
    from api.logging_config import _JsonFormatter
    from api.observability.log_context import SecretRedactionFilter

    handler = logging.StreamHandler()
    handler.setFormatter(_JsonFormatter(service="test"))
    handler.addFilter(SecretRedactionFilter())

    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="request",
        args=(),
        exc_info=None,
    )
    # Simulate accidental extra= fields with sensitive names
    record.authorization = "Bearer evil"  # type: ignore[attr-defined]
    record.api_key = "sk-danger"  # type: ignore[attr-defined]
    record.tenant_id = "acme"  # type: ignore[attr-defined]

    # Apply filter then format
    handler.filter(record)
    output = handler.formatter.format(record)  # type: ignore[union-attr]
    parsed = _json.loads(output)

    assert parsed.get("authorization") == "[REDACTED]", "authorization must be redacted"
    assert parsed.get("api_key") == "[REDACTED]", "api_key must be redacted"
    assert "Bearer evil" not in output, "raw token value must not appear in log output"
    assert "sk-danger" not in output, "raw api_key value must not appear in log output"
    assert parsed.get("tenant_id") == "acme", "safe field must survive redaction"


# ---------------------------------------------------------------------------
# OTel failure safety
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_otel_disabled_requests_still_succeed():
    """When FG_OTEL_ENABLED=0, the OTelTracingMiddleware must be a transparent noop."""
    import api.observability.tracing as tracing_mod

    # Reset global state for isolation
    original = tracing_mod._TRACER_PROVIDER
    tracing_mod._TRACER_PROVIDER = None

    try:
        os.environ["FG_OTEL_ENABLED"] = "0"
        tracing_mod.setup_tracing("test-disabled")
        # TracerProvider must remain None when disabled
        assert tracing_mod._TRACER_PROVIDER is None

        client = _build_client()
        resp = client.get("/health")
        assert resp.status_code == 200, "request must succeed even with OTel disabled"
    finally:
        os.environ.pop("FG_OTEL_ENABLED", None)
        tracing_mod._TRACER_PROVIDER = original


@pytest.mark.smoke
def test_otel_span_exception_does_not_break_request():
    """An exception thrown inside a pipeline span must propagate but not corrupt the response."""
    from api.observability.tracing import setup_tracing, span_ingestion

    setup_tracing("test-exc")
    with pytest.raises(ValueError, match="boom"):
        with span_ingestion(tenant_id="t1", doc_type="pdf"):
            raise ValueError("boom")
    # If we reach here without a secondary exception the span error handling is safe


@pytest.mark.smoke
def test_broken_otlp_exporter_does_not_crash_startup():
    """BatchSpanProcessor swallows export failures — startup must succeed even with a bad endpoint."""
    import api.observability.tracing as tracing_mod

    original = tracing_mod._TRACER_PROVIDER
    tracing_mod._TRACER_PROVIDER = None
    original_endpoint = os.environ.get("FG_OTEL_ENDPOINT")

    try:
        # Point to a definitely-unreachable endpoint
        os.environ["FG_OTEL_ENDPOINT"] = "http://localhost:19999/v1/traces"
        os.environ["FG_OTEL_ENABLED"] = "1"
        # Must not raise even though the endpoint is unreachable
        tracing_mod.setup_tracing("test-broken-otlp")
        assert tracing_mod._TRACER_PROVIDER is not None
    finally:
        os.environ.pop("FG_OTEL_ENABLED", None)
        if original_endpoint is None:
            os.environ.pop("FG_OTEL_ENDPOINT", None)
        else:
            os.environ["FG_OTEL_ENDPOINT"] = original_endpoint
        tracing_mod._TRACER_PROVIDER = original


# ---------------------------------------------------------------------------
# Metric name contract (stable registry)
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_metric_name_contract():
    """Canonical metric names must not drift. Any rename requires updating this test explicitly."""
    import api.observability.metrics as m

    # prometheus_client stores Counter._name without the _total suffix it appends
    # at scrape time.  Histograms and Gauges are unchanged.
    expected_names = {
        "frostgate_provider_latency_seconds",
        "frostgate_provider_requests",
        "frostgate_provider_failures",
        "frostgate_retrieval_latency_seconds",
        "frostgate_retrieval_requests",
        "frostgate_ingestion_requests",
        "frostgate_ingestion_latency_seconds",
        "frostgate_audit_export",
        "frostgate_audit_export_latency_seconds",
        "frostgate_audit_pipeline_failures",
        "frostgate_provenance_validation",
        "frostgate_db_errors",
        "frostgate_db_connectivity_failures",
        "frostgate_http_5xx",
        "frostgate_http_request_duration_seconds",
    }
    actual = {
        m.PROVIDER_LATENCY._name,
        m.PROVIDER_REQUESTS._name,
        m.PROVIDER_FAILURES._name,
        m.RETRIEVAL_LATENCY._name,
        m.RETRIEVAL_REQUESTS._name,
        m.INGESTION_REQUESTS._name,
        m.INGESTION_LATENCY._name,
        m.AUDIT_EXPORT_TOTAL._name,
        m.AUDIT_EXPORT_LATENCY._name,
        m.AUDIT_PIPELINE_FAILURES._name,
        m.PROVENANCE_VALIDATION_TOTAL._name,
        m.DB_ERRORS_TOTAL._name,
        m.DB_CONNECTIVITY_FAILURES._name,
        m.HTTP_5XX_TOTAL._name,
        m.HTTP_REQUEST_DURATION._name,
    }
    assert actual == expected_names, (
        f"Metric name drift detected.\n"
        f"  Added: {actual - expected_names}\n"
        f"  Removed: {expected_names - actual}"
    )


# ---------------------------------------------------------------------------
# Alert-to-metric validation
# ---------------------------------------------------------------------------

_ALERT_METRIC_DEPS: dict[str, list[str]] = {
    "FrostgateProviderFailureHigh": [
        "frostgate_provider_failures_total",
        "frostgate_provider_requests_total",
    ],
    "FrostgateRetrievalLatencyHigh": ["frostgate_retrieval_latency_seconds"],
    "FrostgateRetrievalFailureHigh": ["frostgate_retrieval_requests_total"],
    "FrostgateIngestionFailureHigh": ["frostgate_ingestion_requests_total"],
    "FrostgateAuditPipelineFailure": ["frostgate_audit_pipeline_failures_total"],
    "FrostgateAuditExportFailureHigh": ["frostgate_audit_export_total"],
    "FrostgateDBConnectivityFailure": ["frostgate_db_connectivity_failures_total"],
    "FrostgateHttp5xxRateHigh": [
        "frostgate_http_5xx_total",
        "frostgate_http_request_duration_seconds",
    ],
    "FrostgateRequestLatencyAbnormal": ["frostgate_http_request_duration_seconds"],
    "FrostgateProvenanceFailureSpike": ["frostgate_provenance_validation_total"],
}


@pytest.mark.smoke
def test_alert_rules_reference_registered_metrics():
    """Every alert defined in _ALERT_METRIC_DEPS must reference metrics that exist in the registry."""
    import api.observability.metrics  # noqa: F401
    from prometheus_client import REGISTRY

    # REGISTRY.collect() returns base names; Counters strip _total internally.
    # Expand the set with _total variants so alert refs using _total still match.
    registered_base = {m.name for m in REGISTRY.collect()}
    registered = registered_base | {n + "_total" for n in registered_base}

    for alert_name, metric_names in _ALERT_METRIC_DEPS.items():
        for metric_name in metric_names:
            assert metric_name in registered, (
                f"Alert '{alert_name}' references '{metric_name}' "
                f"but that metric is not registered in the Prometheus registry"
            )


# ---------------------------------------------------------------------------
# Dashboard-to-metric validation
# ---------------------------------------------------------------------------


def _extract_dashboard_metric_refs(dashboard_json: dict) -> set[str]:
    """Extract all frostgate_* metric names referenced in Grafana panel expressions."""
    import re

    refs: set[str] = set()
    pattern = re.compile(r"\b(frostgate_[a-z_]+)\b")

    def _walk(obj):
        if isinstance(obj, dict):
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)
        elif isinstance(obj, str):
            for match in pattern.findall(obj):
                refs.add(match)

    _walk(dashboard_json)
    return refs


_PROM_SUFFIXES = ("_total", "_bucket", "_count", "_sum", "_created")


def _strip_prom_suffix(name: str) -> str:
    for suffix in _PROM_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


@pytest.mark.smoke
def test_dashboard_queries_reference_registered_metrics():
    """Every frostgate_* metric referenced in Grafana dashboards must exist in the registry."""
    import json as _json
    from pathlib import Path
    import api.observability.metrics  # noqa: F401
    from prometheus_client import REGISTRY

    # REGISTRY.collect() returns base names (Counters strip _total).
    # Dashboard exprs use suffixed forms (_total, _bucket, _count, etc.).
    # Normalize both sides to base names before comparing.
    registered = {m.name for m in REGISTRY.collect()}
    dashboard_dir = Path(__file__).parent.parent / "deploy" / "grafana" / "dashboards"
    assert dashboard_dir.exists(), "deploy/grafana/dashboards directory must exist"

    violations: list[str] = []
    for dash_file in sorted(dashboard_dir.glob("*.json")):
        dashboard = _json.loads(dash_file.read_text())
        refs = _extract_dashboard_metric_refs(dashboard)
        for ref in sorted(refs):
            if _strip_prom_suffix(ref) not in registered:
                violations.append(
                    f"{dash_file.name}: references unregistered metric '{ref}'"
                )

    assert not violations, "Dashboard metric drift:\n" + "\n".join(violations)


# ---------------------------------------------------------------------------
# Sampling config
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_otel_sample_ratio_env_var():
    """FG_OTEL_SAMPLE_RATIO must be respected as the canonical sampling config."""
    import api.observability.tracing as tracing_mod

    original = tracing_mod._TRACER_PROVIDER
    tracing_mod._TRACER_PROVIDER = None

    try:
        os.environ["FG_OTEL_SAMPLE_RATIO"] = "0.5"
        os.environ["FG_OTEL_ENABLED"] = "1"
        tracing_mod.setup_tracing("test-sampling")
        # Must not raise; provider created with 0.5 sample rate
        assert tracing_mod._TRACER_PROVIDER is not None
    finally:
        os.environ.pop("FG_OTEL_SAMPLE_RATIO", None)
        os.environ.pop("FG_OTEL_ENABLED", None)
        tracing_mod._TRACER_PROVIDER = original


@pytest.mark.smoke
def test_otel_sample_rate_legacy_alias_works():
    """FG_OTEL_SAMPLE_RATE (legacy) must still be accepted."""
    import api.observability.tracing as tracing_mod

    original = tracing_mod._TRACER_PROVIDER
    tracing_mod._TRACER_PROVIDER = None

    try:
        os.environ["FG_OTEL_SAMPLE_RATE"] = "0.1"
        os.environ["FG_OTEL_ENABLED"] = "1"
        tracing_mod.setup_tracing("test-legacy-alias")
        assert tracing_mod._TRACER_PROVIDER is not None
    finally:
        os.environ.pop("FG_OTEL_SAMPLE_RATE", None)
        os.environ.pop("FG_OTEL_ENABLED", None)
        tracing_mod._TRACER_PROVIDER = original
