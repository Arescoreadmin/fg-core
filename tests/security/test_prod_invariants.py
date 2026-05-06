from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.config.prod_invariants import ProdInvariantViolation, assert_prod_invariants
from api.main import build_app

_VALID_PROD_ENV: dict[str, str] = {
    "FG_ENV": "production",
    "FG_AUTH_ENABLED": "1",
    "FG_DB_URL": "postgresql://x",
    "FG_DB_BACKEND": "postgres",
    "FG_ENFORCEMENT_MODE": "enforce",
    "DATABASE_URL": "postgresql://x",
    "FG_SIGNING_SECRET": "test-signing-secret",
    "FG_INTERNAL_AUTH_SECRET": "test-internal-secret",
    "FG_API_KEY": "test-api-key",
    "STRIPE_SECRET_KEY": "test-stripe-secret-key",
    "STRIPE_WEBHOOK_SECRET": "test-stripe-webhook-secret",
    "FG_ANTHROPIC_API_KEY": "test-anthropic-api-key",
}


def test_prod_invariants_fail_on_auth_disabled() -> None:
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(
            {
                "FG_ENV": "prod",
                "FG_AUTH_ENABLED": "0",
                "FG_DB_URL": "postgresql://x",
                "FG_DB_BACKEND": "postgres",
                "FG_ENFORCEMENT_MODE": "enforce",
            }
        )
    assert exc.value.code == "FG-PROD-001"


def test_prod_invariants_fail_on_missing_db_url() -> None:
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(
            {
                "FG_ENV": "staging",
                "FG_AUTH_ENABLED": "1",
                "FG_DB_BACKEND": "postgres",
                "FG_ENFORCEMENT_MODE": "enforce",
            }
        )
    assert exc.value.code == "FG-PROD-003"


@pytest.mark.parametrize("fg_env", ["prod", "staging"])
def test_prod_invariants_fail_when_enforcement_mode_unset(fg_env: str) -> None:
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(
            {
                "FG_ENV": fg_env,
                "FG_AUTH_ENABLED": "1",
                "FG_DB_URL": "postgresql://x",
                "FG_DB_BACKEND": "postgres",
            }
        )
    assert exc.value.code == "FG-PROD-007"


@pytest.mark.parametrize("fg_env", ["prod", "staging"])
def test_prod_invariants_fail_when_enforcement_mode_observe(fg_env: str) -> None:
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(
            {
                "FG_ENV": fg_env,
                "FG_AUTH_ENABLED": "1",
                "FG_DB_URL": "postgresql://x",
                "FG_DB_BACKEND": "postgres",
                "FG_ENFORCEMENT_MODE": "observe",
            }
        )
    assert exc.value.code == "FG-PROD-007"


@pytest.mark.parametrize("fg_env", ["prod", "staging"])
def test_prod_invariants_allow_enforcement_mode_enforce(fg_env: str) -> None:
    assert_prod_invariants(
        {
            "FG_ENV": fg_env,
            "FG_AUTH_ENABLED": "1",
            "FG_DB_URL": "postgresql://x",
            "FG_DB_BACKEND": "postgres",
            "FG_ENFORCEMENT_MODE": "enforce",
            "DATABASE_URL": "postgresql://x",
            "FG_SIGNING_SECRET": "test-signing-secret",
            "FG_INTERNAL_AUTH_SECRET": "test-internal-secret",
            "FG_API_KEY": "test-api-key",
            "STRIPE_SECRET_KEY": "test-stripe-secret-key",
            "STRIPE_WEBHOOK_SECRET": "test-stripe-webhook-secret",
            "FG_ANTHROPIC_API_KEY": "test-anthropic-api-key",
        }
    )


def test_dev_allows_local_bypass_flags() -> None:
    assert_prod_invariants({"FG_ENV": "dev", "FG_AUTH_ENABLED": "0"})


def test_prod_startup_crashes_on_unsafe_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FG_ENV", "prod")
    monkeypatch.setenv("FG_AUTH_ENABLED", "1")
    monkeypatch.setenv("FG_DB_BACKEND", "postgres")
    monkeypatch.setenv("FG_DB_URL", "postgresql://user:pass@localhost/db")
    monkeypatch.setenv("FG_ENFORCEMENT_MODE", "enforce")
    monkeypatch.setenv("FG_AUTH_ALLOW_FALLBACK", "true")

    with pytest.raises(ProdInvariantViolation) as exc:
        with TestClient(build_app()):
            pass

    assert exc.value.code == "FG-PROD-002"


# ---------------------------------------------------------------------------
# Auth fail-closed invariant tests (FG-PROD-001)
# ---------------------------------------------------------------------------


def test_dev_allows_auth_disabled_for_local_config() -> None:
    """Dev environment must not raise when auth is disabled."""
    assert_prod_invariants({"FG_ENV": "dev", "FG_AUTH_ENABLED": "0"})


def test_test_env_allows_auth_disabled_for_local_config() -> None:
    """Test environment must not raise when auth is disabled."""
    assert_prod_invariants({"FG_ENV": "test", "FG_AUTH_ENABLED": "0"})


def test_prod_startup_fails_when_auth_disabled() -> None:
    """Prod environment must raise FG-PROD-001 when auth is disabled."""
    env = {**_VALID_PROD_ENV, "FG_ENV": "prod", "FG_AUTH_ENABLED": "0"}
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(env)
    assert exc.value.code == "FG-PROD-001"


def test_staging_startup_fails_when_auth_disabled() -> None:
    """Staging environment must raise FG-PROD-001 when auth is disabled."""
    env = {**_VALID_PROD_ENV, "FG_ENV": "staging", "FG_AUTH_ENABLED": "0"}
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(env)
    assert exc.value.code == "FG-PROD-001"


def test_prod_startup_allows_auth_enabled() -> None:
    """Prod environment with auth enabled and all required vars must not raise."""
    env = {**_VALID_PROD_ENV, "FG_ENV": "prod"}
    assert_prod_invariants(env)


def test_auth_disabled_prod_error_message_is_stable() -> None:
    """Error message must contain AUTH_DISABLED_IN_PROD for stable alerting."""
    env = {**_VALID_PROD_ENV, "FG_ENV": "prod", "FG_AUTH_ENABLED": "0"}
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(env)
    assert "AUTH_DISABLED_IN_PROD" in str(exc.value)
