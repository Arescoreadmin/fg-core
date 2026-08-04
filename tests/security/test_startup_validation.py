from __future__ import annotations

import pytest

from api.config.startup_validation import validate_startup_config


def test_startup_validation_fails_closed_in_production(monkeypatch):
    monkeypatch.setenv("FG_ENV", "prod")
    monkeypatch.setenv("FG_API_KEY", "")
    with pytest.raises(RuntimeError):
        validate_startup_config(fail_on_error=True, log_results=False)


def test_startup_validation_fails_when_connectors_router_unwired(monkeypatch):
    monkeypatch.setenv("FG_ENV", "prod")
    monkeypatch.setenv("FG_API_KEY", "x" * 40)
    monkeypatch.setenv("FG_AUTH_ENABLED", "1")

    import api.connectors_control_plane as ccp

    monkeypatch.setattr(ccp.router, "routes", [])

    with pytest.raises(
        RuntimeError, match="Connectors control-plane router wiring failed"
    ):
        validate_startup_config(fail_on_error=True, log_results=False)


def test_startup_fails_missing_minisign_key_in_production(monkeypatch):
    monkeypatch.setenv("FG_ENV", "prod")
    monkeypatch.delenv("MINISIGN_SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError, match="MINISIGN_SECRET_KEY"):
        validate_startup_config(fail_on_error=True, log_results=False)


def test_startup_warns_missing_minisign_key_non_prod(monkeypatch):
    monkeypatch.delenv("MINISIGN_SECRET_KEY", raising=False)
    from api.config.startup_validation import StartupValidator

    v = StartupValidator()
    v.env = "dev"
    v.is_production = False
    report = v.validate()

    result = next(
        (r for r in report.results if r.name == "minisign_secret_key_missing"), None
    )
    assert result is not None
    assert not result.passed
    assert result.severity == "warning"


def test_startup_passes_minisign_key_present(monkeypatch):
    monkeypatch.setenv(
        "MINISIGN_SECRET_KEY", "RWSxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    )
    from api.config.startup_validation import StartupValidator

    v = StartupValidator()
    report = v.validate()

    result = next((r for r in report.results if r.name == "minisign_secret_key"), None)
    assert result is not None


def test_startup_warns_missing_observability_config_in_production_never_raises(
    monkeypatch,
):
    """SENTRY_DSN / FG_OTEL_ENDPOINT are recommended, not required: missing
    either in prod must surface as a warning and must never fail startup."""
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    monkeypatch.delenv("FG_OTEL_ENDPOINT", raising=False)
    from api.config.startup_validation import StartupValidator

    v = StartupValidator()
    v.env = "prod"
    v.is_production = True
    report = v.validate()

    sentry_result = next(
        (r for r in report.results if r.name == "sentry_dsn_missing"), None
    )
    otel_result = next(
        (r for r in report.results if r.name == "otel_endpoint_missing"), None
    )
    assert sentry_result is not None
    assert not sentry_result.passed
    assert sentry_result.severity == "warning"
    assert otel_result is not None
    assert not otel_result.passed
    assert otel_result.severity == "warning"


def test_startup_observability_check_skipped_outside_production(monkeypatch):
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    monkeypatch.delenv("FG_OTEL_ENDPOINT", raising=False)
    from api.config.startup_validation import StartupValidator

    v = StartupValidator()
    v.env = "dev"
    v.is_production = False
    report = v.validate()

    assert not any(
        r.name in {"sentry_dsn_missing", "otel_endpoint_missing"}
        for r in report.results
    )


def test_evidence_signing_key_absent_is_error_in_prod(monkeypatch):
    import base64

    monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
    from api.config.startup_validation import StartupValidator

    v = StartupValidator()
    v.env = "prod"
    v.is_production = True
    report = v.validate()

    result = next(
        (r for r in report.results if r.name == "evidence_signing_key_missing"), None
    )
    assert result is not None
    assert not result.passed
    assert result.severity == "error"


def test_evidence_signing_key_absent_is_warning_non_prod(monkeypatch):
    monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
    from api.config.startup_validation import StartupValidator

    v = StartupValidator()
    v.env = "dev"
    v.is_production = False
    report = v.validate()

    result = next(
        (r for r in report.results if r.name == "evidence_signing_key_missing"), None
    )
    assert result is not None
    assert not result.passed
    assert result.severity == "warning"


def test_evidence_signing_key_invalid_base64(monkeypatch):
    monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", "not-valid-base64!!!")
    from api.config.startup_validation import StartupValidator

    v = StartupValidator()
    report = v.validate()

    result = next(
        (r for r in report.results if r.name == "evidence_signing_key_invalid"), None
    )
    assert result is not None
    assert not result.passed
    assert result.severity == "error"


def test_evidence_signing_key_wrong_length(monkeypatch):
    import base64

    # 16 bytes — valid base64 but not 32 bytes
    monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", base64.b64encode(b"x" * 16).decode())
    from api.config.startup_validation import StartupValidator

    v = StartupValidator()
    report = v.validate()

    result = next(
        (r for r in report.results if r.name == "evidence_signing_key_invalid"), None
    )
    assert result is not None
    assert not result.passed
    assert result.severity == "error"


def test_evidence_signing_key_valid_32_bytes(monkeypatch):
    import base64
    import os

    monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", base64.b64encode(os.urandom(32)).decode())
    from api.config.startup_validation import StartupValidator

    v = StartupValidator()
    report = v.validate()

    result = next(
        (r for r in report.results if r.name == "evidence_signing_key"), None
    )
    assert result is not None
    assert result.passed


def test_startup_passes_observability_config_present(monkeypatch):
    monkeypatch.setenv("SENTRY_DSN", "https://example@o0.ingest.sentry.io/0")
    monkeypatch.setenv("FG_OTEL_ENDPOINT", "http://otel-collector:4318/v1/traces")
    from api.config.startup_validation import StartupValidator

    v = StartupValidator()
    v.env = "prod"
    v.is_production = True
    report = v.validate()

    sentry_result = next(
        (r for r in report.results if r.name == "sentry_dsn_configured"), None
    )
    otel_result = next(
        (r for r in report.results if r.name == "otel_endpoint_configured"), None
    )
    assert sentry_result is not None and sentry_result.passed
    assert otel_result is not None and otel_result.passed
