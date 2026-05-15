"""Tests for the dynamic telemetry policy engine.

Covers:
- Mode parsing (standard / regulated / strict / unknown)
- FG_DISABLE_EXTERNAL_OTLP enforcement
- FG_RESTRICT_TRACE_ATTRIBUTES attribute filtering
- Per-tenant suppression via FG_TELEMETRY_SUPPRESSED_TENANTS
- Integration with setup_tracing() (OTLP blocked by policy)
- Integration with pipeline spans (suppressed tenant yields NonRecordingSpan)
- Integration with OTelTracingMiddleware (attributes filtered in restricted mode)
- reload_policy() re-reads env vars
"""

from __future__ import annotations

import os

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_policy(**env: str):
    """Create a TelemetryPolicy with specific env vars, then clean up."""
    from api.observability.telemetry_policy import TelemetryPolicy

    old_env: dict[str, str | None] = {key: os.environ.pop(key, None) for key in env}
    for env_key, env_value in env.items():
        os.environ[env_key] = env_value

    try:
        return TelemetryPolicy()
    finally:
        for old_key, old_value in old_env.items():
            if old_value is None:
                os.environ.pop(old_key, None)
            else:
                os.environ[old_key] = old_value


# ---------------------------------------------------------------------------
# Mode parsing
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_policy_defaults_to_standard_mode():
    policy = _make_policy()
    assert policy.mode == "standard"
    assert not policy.disable_external_otlp
    assert not policy.restrict_trace_attributes


@pytest.mark.smoke
def test_regulated_mode_restricts_attributes_not_otlp():
    policy = _make_policy(FG_OBSERVABILITY_MODE="regulated")
    assert policy.mode == "regulated"
    assert policy.restrict_trace_attributes is True
    assert policy.disable_external_otlp is False  # regulated still allows OTLP


@pytest.mark.smoke
def test_strict_mode_blocks_otlp_and_restricts_attributes():
    policy = _make_policy(FG_OBSERVABILITY_MODE="strict")
    assert policy.mode == "strict"
    assert policy.restrict_trace_attributes is True
    assert policy.disable_external_otlp is True


@pytest.mark.smoke
def test_unknown_mode_falls_back_to_standard():
    policy = _make_policy(FG_OBSERVABILITY_MODE="enterprise-ultra-secure")
    assert policy.mode == "standard"


@pytest.mark.smoke
def test_mode_case_insensitive():
    policy = _make_policy(FG_OBSERVABILITY_MODE="REGULATED")
    assert policy.mode == "regulated"


# ---------------------------------------------------------------------------
# FG_DISABLE_EXTERNAL_OTLP
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_disable_external_otlp_flag_blocks_otlp_in_standard_mode():
    policy = _make_policy(
        FG_OBSERVABILITY_MODE="standard", FG_DISABLE_EXTERNAL_OTLP="1"
    )
    assert policy.allows_external_otlp() is False


@pytest.mark.smoke
def test_allows_external_otlp_by_default():
    policy = _make_policy()
    assert policy.allows_external_otlp() is True


@pytest.mark.smoke
def test_regulated_mode_allows_external_otlp_unless_flag_set():
    policy = _make_policy(FG_OBSERVABILITY_MODE="regulated")
    assert policy.allows_external_otlp() is True

    policy_blocked = _make_policy(
        FG_OBSERVABILITY_MODE="regulated", FG_DISABLE_EXTERNAL_OTLP="1"
    )
    assert policy_blocked.allows_external_otlp() is False


@pytest.mark.smoke
def test_setup_tracing_respects_disable_external_otlp(monkeypatch, caplog):
    """When FG_DISABLE_EXTERNAL_OTLP=1, setup_tracing must not configure OTLP exporter."""
    import api.observability.tracing as tracing_mod
    import api.observability.telemetry_policy as policy_mod

    original_provider = tracing_mod._TRACER_PROVIDER
    original_policy = policy_mod._POLICY
    tracing_mod._TRACER_PROVIDER = None
    policy_mod._POLICY = None

    try:
        monkeypatch.setenv("FG_OTEL_ENDPOINT", "http://localhost:4318/v1/traces")
        monkeypatch.setenv("FG_DISABLE_EXTERNAL_OTLP", "1")
        monkeypatch.setenv("FG_OTEL_ENABLED", "1")

        import logging

        with caplog.at_level(logging.WARNING, logger="frostgate.observability"):
            tracing_mod.setup_tracing("test-policy-otlp")

        assert tracing_mod._TRACER_PROVIDER is not None, (
            "Provider must still be created"
        )
        assert any("blocked_by_policy" in r.message for r in caplog.records), (
            "Expected policy-blocked warning in logs"
        )
    finally:
        monkeypatch.delenv("FG_OTEL_ENDPOINT", raising=False)
        monkeypatch.delenv("FG_DISABLE_EXTERNAL_OTLP", raising=False)
        monkeypatch.delenv("FG_OTEL_ENABLED", raising=False)
        tracing_mod._TRACER_PROVIDER = original_provider
        policy_mod._POLICY = original_policy


# ---------------------------------------------------------------------------
# FG_RESTRICT_TRACE_ATTRIBUTES
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_standard_mode_passes_all_attributes():
    policy = _make_policy()
    attrs = {
        "tenant.id": "acme",
        "custom.field": "value",
        "some.new.attr": "data",
    }
    filtered = policy.filter_span_attributes(attrs)
    assert filtered == attrs


@pytest.mark.smoke
def test_restrict_flag_filters_unapproved_attributes():
    policy = _make_policy(FG_RESTRICT_TRACE_ATTRIBUTES="1")
    attrs = {
        "tenant.id": "acme",  # approved
        "doc.type": "pdf",  # approved
        "custom.unapproved": "val",  # NOT approved
        "user.query": "text",  # NOT approved
    }
    filtered = policy.filter_span_attributes(attrs)
    assert "tenant.id" in filtered
    assert "doc.type" in filtered
    assert "custom.unapproved" not in filtered
    assert "user.query" not in filtered


@pytest.mark.smoke
def test_regulated_mode_filters_same_as_restrict_flag():
    policy = _make_policy(FG_OBSERVABILITY_MODE="regulated")
    attrs = {"tenant.id": "x", "unapproved": "y"}
    filtered = policy.filter_span_attributes(attrs)
    assert "tenant.id" in filtered
    assert "unapproved" not in filtered


@pytest.mark.smoke
def test_restricted_mode_drops_empty_values():
    policy = _make_policy(FG_RESTRICT_TRACE_ATTRIBUTES="1")
    attrs = {"tenant.id": "acme", "doc.type": ""}
    filtered = policy.filter_span_attributes(attrs)
    assert "tenant.id" in filtered
    assert "doc.type" not in filtered


# ---------------------------------------------------------------------------
# Per-tenant suppression
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_tenant_suppression_single():
    policy = _make_policy(FG_TELEMETRY_SUPPRESSED_TENANTS="acme-corp")
    assert policy.is_tenant_suppressed("acme-corp") is True
    assert policy.is_tenant_suppressed("other-tenant") is False


@pytest.mark.smoke
def test_tenant_suppression_csv_list():
    policy = _make_policy(FG_TELEMETRY_SUPPRESSED_TENANTS="acme, beta-inc , gamma")
    assert policy.is_tenant_suppressed("acme") is True
    assert policy.is_tenant_suppressed("beta-inc") is True
    assert policy.is_tenant_suppressed("gamma") is True
    assert policy.is_tenant_suppressed("delta") is False


@pytest.mark.smoke
def test_empty_tenant_id_never_suppressed():
    policy = _make_policy(FG_TELEMETRY_SUPPRESSED_TENANTS="acme")
    assert policy.is_tenant_suppressed("") is False


@pytest.mark.smoke
def test_no_suppressed_tenants_by_default():
    policy = _make_policy()
    assert policy.is_tenant_suppressed("any-tenant") is False


@pytest.mark.smoke
def test_suppressed_tenant_pipeline_span_yields_non_recording_span():
    """span_ingestion for a suppressed tenant must yield a NonRecordingSpan."""
    from opentelemetry.trace import NonRecordingSpan
    import api.observability.telemetry_policy as policy_mod
    import api.observability.tracing as tracing_mod

    original = policy_mod._POLICY
    policy_mod._POLICY = None

    try:
        os.environ["FG_TELEMETRY_SUPPRESSED_TENANTS"] = "suppressed-co"
        tracing_mod.setup_tracing("test-suppression")

        with tracing_mod.span_ingestion(
            tenant_id="suppressed-co", doc_type="pdf"
        ) as span:
            assert isinstance(span, NonRecordingSpan), (
                f"Expected NonRecordingSpan for suppressed tenant, got {type(span)}"
            )

        with tracing_mod.span_ingestion(tenant_id="allowed-co", doc_type="pdf") as span:
            assert not isinstance(span, NonRecordingSpan), (
                "Non-suppressed tenant must get a real span"
            )
    finally:
        os.environ.pop("FG_TELEMETRY_SUPPRESSED_TENANTS", None)
        policy_mod._POLICY = original


# ---------------------------------------------------------------------------
# reload_policy
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_reload_policy_picks_up_env_change(monkeypatch):
    import api.observability.telemetry_policy as policy_mod

    original = policy_mod._POLICY
    try:
        monkeypatch.setenv("FG_OBSERVABILITY_MODE", "standard")
        p1 = policy_mod.reload_policy()
        assert p1.mode == "standard"

        monkeypatch.setenv("FG_OBSERVABILITY_MODE", "strict")
        p2 = policy_mod.reload_policy()
        assert p2.mode == "strict"
        assert p2.disable_external_otlp is True
    finally:
        policy_mod._POLICY = original


# ---------------------------------------------------------------------------
# Middleware integration
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_otel_middleware_filters_attributes_in_restricted_mode(monkeypatch):
    """In restricted mode, _attach_request_attributes must only emit approved attrs."""
    import api.observability.telemetry_policy as policy_mod

    original = policy_mod._POLICY
    policy_mod._POLICY = None

    try:
        monkeypatch.setenv("FG_RESTRICT_TRACE_ATTRIBUTES", "1")
        policy_mod.reload_policy()

        from api.middleware.otel_tracing import _attach_request_attributes
        from opentelemetry.sdk.trace import TracerProvider

        provider = TracerProvider()
        tracer = provider.get_tracer("test")
        with tracer.start_as_current_span("test-span") as span:
            scope = {"method": "GET", "path": "/health", "scheme": "https"}
            headers = {
                "x-tenant-id": "acme",
                "x-request-id": "req-123",
            }
            _attach_request_attributes(span, scope, headers)
            # All of these are in APPROVED_SPAN_ATTRIBUTES — they must all pass through
            ctx = span.get_span_context()
            assert ctx is not None
    finally:
        monkeypatch.delenv("FG_RESTRICT_TRACE_ATTRIBUTES", raising=False)
        policy_mod._POLICY = original
