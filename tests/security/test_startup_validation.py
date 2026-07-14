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
    assert result.passed
