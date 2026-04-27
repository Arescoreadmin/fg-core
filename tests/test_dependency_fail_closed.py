"""
tests/test_dependency_fail_closed.py

Verifies fail-closed behavior for enabled external dependencies with missing URLs.

Coverage:
- Redis: FG_RL_BACKEND=redis + no FG_REDIS_URL → RuntimeError in non-dev
- NATS:  FG_NATS_ENABLED=1  + no FG_NATS_URL  → RuntimeError in non-dev
- OIDC:  prod environment   + no OIDC config   → validation error
- Startup validation: NATS/Redis URL missing reported as error in production
- Localhost URLs rejected in production via startup validation

Dev-only fallbacks are explicit and environment-gated:
- Redis dev fallback: redis://localhost:6379/0 (only when FG_ENV=dev)
- NATS  dev fallback: nats://localhost:4222    (only when FG_ENV=dev)
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Redis — ratelimit.load_config()
# ---------------------------------------------------------------------------


def test_redis_dependency_fail_closed_in_non_dev(monkeypatch):
    """FG_RL_BACKEND=redis + no FG_REDIS_URL in staging raises RuntimeError."""
    monkeypatch.setenv("FG_RL_BACKEND", "redis")
    monkeypatch.delenv("FG_REDIS_URL", raising=False)
    monkeypatch.setenv("FG_ENV", "staging")

    from api.ratelimit import load_config

    with pytest.raises(RuntimeError, match="FG_REDIS_URL must be set"):
        load_config()


def test_redis_dependency_fail_closed_in_prod(monkeypatch):
    """FG_RL_BACKEND=redis + no FG_REDIS_URL in prod raises RuntimeError."""
    monkeypatch.setenv("FG_RL_BACKEND", "redis")
    monkeypatch.delenv("FG_REDIS_URL", raising=False)
    monkeypatch.setenv("FG_ENV", "prod")

    from api.ratelimit import load_config

    with pytest.raises(RuntimeError, match="FG_REDIS_URL must be set"):
        load_config()


def test_redis_dependency_dev_fallback_explicit(monkeypatch):
    """FG_RL_BACKEND=redis + no FG_REDIS_URL in dev uses explicit localhost fallback."""
    monkeypatch.setenv("FG_RL_BACKEND", "redis")
    monkeypatch.delenv("FG_REDIS_URL", raising=False)
    monkeypatch.setenv("FG_ENV", "dev")

    from api.ratelimit import load_config

    config = load_config()
    assert config.redis_url == "redis://localhost:6379/0"


def test_redis_dependency_dev_test_fallback_explicit(monkeypatch):
    """FG_RL_BACKEND=redis + no FG_REDIS_URL in test uses explicit localhost fallback."""
    monkeypatch.setenv("FG_RL_BACKEND", "redis")
    monkeypatch.delenv("FG_REDIS_URL", raising=False)
    monkeypatch.setenv("FG_ENV", "test")

    from api.ratelimit import load_config

    config = load_config()
    assert config.redis_url == "redis://localhost:6379/0"


# ---------------------------------------------------------------------------
# NATS — api.ingest_bus._resolve_nats_url()
# ---------------------------------------------------------------------------


def test_nats_dependency_fail_closed_in_non_dev():
    """NATS enabled + no URL in staging raises RuntimeError (fail-closed)."""
    from api.ingest_bus import _resolve_nats_url

    with pytest.raises(RuntimeError, match="FG_NATS_URL must be set"):
        _resolve_nats_url(enabled=True, url="", env="staging")


def test_nats_dependency_fail_closed_in_prod():
    """NATS enabled + no URL in prod raises RuntimeError (fail-closed)."""
    from api.ingest_bus import _resolve_nats_url

    with pytest.raises(RuntimeError, match="FG_NATS_URL must be set"):
        _resolve_nats_url(enabled=True, url="", env="prod")


def test_nats_dependency_fail_closed_in_production_env():
    """NATS enabled + no URL in 'production' raises RuntimeError."""
    from api.ingest_bus import _resolve_nats_url

    with pytest.raises(RuntimeError):
        _resolve_nats_url(enabled=True, url="", env="production")


def test_nats_dependency_dev_fallback_explicit():
    """NATS enabled + no URL in dev returns explicit localhost fallback."""
    from api.ingest_bus import _resolve_nats_url

    result = _resolve_nats_url(enabled=True, url="", env="dev")
    assert result == "nats://localhost:4222"


def test_nats_dependency_local_fallback_explicit():
    """NATS enabled + no URL in local returns explicit localhost fallback."""
    from api.ingest_bus import _resolve_nats_url

    result = _resolve_nats_url(enabled=True, url="", env="local")
    assert result == "nats://localhost:4222"


def test_nats_dependency_test_fallback_explicit():
    """NATS enabled + no URL in test returns explicit localhost fallback."""
    from api.ingest_bus import _resolve_nats_url

    result = _resolve_nats_url(enabled=True, url="", env="test")
    assert result == "nats://localhost:4222"


def test_nats_dependency_development_env_fallback_explicit():
    """NATS enabled + no URL in 'development' (long form) returns explicit localhost fallback."""
    from api.ingest_bus import _resolve_nats_url

    result = _resolve_nats_url(enabled=True, url="", env="development")
    assert result == "nats://localhost:4222"


def test_nats_dependency_unknown_env_is_fail_closed():
    """NATS enabled + no URL + unknown env string raises RuntimeError (fail-closed)."""
    from api.ingest_bus import _resolve_nats_url

    # Unknown/empty env must never silently fall back to localhost.
    for unknown_env in ("", "PROD", "STAGING", "qa", "uat", "preprod"):
        with pytest.raises(RuntimeError, match="FG_NATS_URL must be set"):
            _resolve_nats_url(enabled=True, url="", env=unknown_env)


def test_nats_dependency_disabled_no_url_returns_empty():
    """NATS disabled + no URL returns empty string (not an error)."""
    from api.ingest_bus import _resolve_nats_url

    result = _resolve_nats_url(enabled=False, url="", env="prod")
    assert result == ""


def test_nats_dependency_enabled_with_url_returns_url():
    """NATS enabled + URL set passes through the provided URL."""
    from api.ingest_bus import _resolve_nats_url

    result = _resolve_nats_url(
        enabled=True, url="nats://user:pass@nats.internal:4222", env="prod"
    )
    assert result == "nats://user:pass@nats.internal:4222"


# ---------------------------------------------------------------------------
# OIDC — admin_gateway.auth.config.AuthConfig.validate()
# ---------------------------------------------------------------------------


def test_oidc_dependency_fail_closed_in_production():
    """AuthConfig.validate() returns errors when OIDC is not configured in prod."""
    from admin_gateway.auth.config import AuthConfig

    cfg = AuthConfig(env="prod")
    errors = cfg.validate()
    assert any("oidc must be configured" in e.lower() for e in errors), (
        f"Expected OIDC error in prod, got: {errors}"
    )


def test_oidc_dependency_staging_requires_no_bypass():
    """Dev bypass is rejected in staging (prod-like)."""
    from admin_gateway.auth.config import AuthConfig

    cfg = AuthConfig(env="staging", dev_auth_bypass=True)
    errors = cfg.validate()
    assert any("bypass" in e.lower() for e in errors)


def test_oidc_dependency_partial_config_fails():
    """Partial OIDC configuration (some fields set, not all) raises an error."""
    from admin_gateway.auth.config import AuthConfig

    cfg = AuthConfig(
        env="dev",
        oidc_issuer="https://idp.example.com/realms/fg",
        # client_id, secret, redirect missing
    )
    errors = cfg.validate()
    assert any("partially configured" in e.lower() for e in errors)


def test_oidc_dependency_dev_does_not_require_oidc():
    """AuthConfig.validate() does not require OIDC in dev."""
    from admin_gateway.auth.config import AuthConfig

    cfg = AuthConfig(env="dev")
    errors = cfg.validate()
    # No OIDC-required error in dev
    assert not any("oidc must be configured" in e.lower() for e in errors), (
        f"Unexpected OIDC error in dev: {errors}"
    )


# ---------------------------------------------------------------------------
# Startup validation — NATS + Redis URLs
# ---------------------------------------------------------------------------


def test_startup_nats_url_missing_is_error_in_production(monkeypatch):
    """Startup validation reports severity=error for NATS enabled + no URL in production."""
    monkeypatch.setenv("FG_ENV", "prod")
    monkeypatch.setenv("FG_NATS_ENABLED", "1")
    monkeypatch.delenv("FG_NATS_URL", raising=False)

    from api.config.startup_validation import StartupValidator

    report = StartupValidator().validate()
    nats_results = [r for r in report.results if r.name == "nats_url_missing"]
    assert nats_results, "Expected nats_url_missing check in report"
    assert not nats_results[0].passed
    assert nats_results[0].severity == "error"


def test_startup_nats_url_missing_is_warning_in_dev(monkeypatch):
    """Startup validation reports severity=warning for NATS enabled + no URL in dev."""
    monkeypatch.setenv("FG_ENV", "dev")
    monkeypatch.setenv("FG_NATS_ENABLED", "1")
    monkeypatch.delenv("FG_NATS_URL", raising=False)

    from api.config.startup_validation import StartupValidator

    report = StartupValidator().validate()
    nats_results = [r for r in report.results if r.name == "nats_url_missing"]
    assert nats_results, "Expected nats_url_missing check in report"
    assert not nats_results[0].passed
    assert nats_results[0].severity == "warning"


def test_startup_redis_url_missing_is_error_in_production(monkeypatch):
    """Startup validation reports error when FG_RL_BACKEND=redis but no URL in production."""
    monkeypatch.setenv("FG_ENV", "prod")
    monkeypatch.setenv("FG_RL_BACKEND", "redis")
    monkeypatch.delenv("FG_REDIS_URL", raising=False)

    from api.config.startup_validation import StartupValidator

    report = StartupValidator().validate()
    redis_results = [r for r in report.results if r.name == "redis_url_missing"]
    assert redis_results, "Expected redis_url_missing check in report"
    assert not redis_results[0].passed
    assert redis_results[0].severity == "error"


def test_startup_fail_closed_actually_raises_on_nats_url_missing_in_prod(monkeypatch):
    """validate_startup_config(fail_on_error=True) raises RuntimeError when NATS enabled+no URL in prod."""
    monkeypatch.setenv("FG_ENV", "prod")
    monkeypatch.setenv("FG_NATS_ENABLED", "1")
    monkeypatch.delenv("FG_NATS_URL", raising=False)

    from api.config.startup_validation import validate_startup_config

    with pytest.raises(RuntimeError, match="FG_NATS_URL"):
        validate_startup_config(fail_on_error=True, log_results=False)


def test_startup_fail_closed_actually_raises_on_redis_url_missing_in_prod(monkeypatch):
    """validate_startup_config(fail_on_error=True) raises RuntimeError when Redis backend+no URL in prod."""
    monkeypatch.setenv("FG_ENV", "prod")
    monkeypatch.setenv("FG_RL_BACKEND", "redis")
    monkeypatch.delenv("FG_REDIS_URL", raising=False)

    from api.config.startup_validation import validate_startup_config

    with pytest.raises(RuntimeError, match="FG_REDIS_URL"):
        validate_startup_config(fail_on_error=True, log_results=False)


# ---------------------------------------------------------------------------
# Startup validation — localhost URLs rejected in production
# ---------------------------------------------------------------------------


def test_startup_localhost_url_rejected_in_production_redis(monkeypatch):
    """Startup validation rejects a localhost FG_REDIS_URL in production."""
    monkeypatch.setenv("FG_ENV", "prod")
    monkeypatch.setenv("FG_REDIS_URL", "redis://localhost:6379/0")

    from api.config.startup_validation import StartupValidator

    report = StartupValidator().validate()
    localhost_results = [
        r
        for r in report.results
        if "localhost_url_fg_redis_url" in r.name and not r.passed
    ]
    assert localhost_results, "Expected localhost FG_REDIS_URL rejection in production"
    assert localhost_results[0].severity == "error"


def test_startup_localhost_url_rejected_in_production_nats(monkeypatch):
    """Startup validation rejects a localhost FG_NATS_URL in production."""
    monkeypatch.setenv("FG_ENV", "prod")
    monkeypatch.setenv("FG_NATS_URL", "nats://localhost:4222")

    from api.config.startup_validation import StartupValidator

    report = StartupValidator().validate()
    localhost_results = [
        r
        for r in report.results
        if "localhost_url_fg_nats_url" in r.name and not r.passed
    ]
    assert localhost_results, "Expected localhost FG_NATS_URL rejection in production"
    assert localhost_results[0].severity == "error"


def test_startup_localhost_url_allowed_in_dev(monkeypatch):
    """Startup validation does not reject localhost URLs in dev (localhost check is prod-only)."""
    monkeypatch.setenv("FG_ENV", "dev")
    monkeypatch.setenv("FG_REDIS_URL", "redis://localhost:6379/0")

    from api.config.startup_validation import StartupValidator

    report = StartupValidator().validate()
    localhost_errors = [
        r
        for r in report.results
        if "localhost_url" in r.name and r.severity == "error" and not r.passed
    ]
    assert not localhost_errors, (
        f"Unexpected localhost error in dev: {localhost_errors}"
    )
