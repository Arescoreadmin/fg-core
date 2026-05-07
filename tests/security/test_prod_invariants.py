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
    # Admin gateway OIDC enforcement — required in prod/staging.
    "FG_OIDC_ISSUER": "https://oidc.example.com",
    "FG_DEV_AUTH_BYPASS": "0",
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
            "FG_OIDC_ISSUER": "https://oidc.example.com",
            "FG_DEV_AUTH_BYPASS": "0",
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


# ---------------------------------------------------------------------------
# Admin OIDC / dev-auth enforcement tests (FG-PROD-008, FG-PROD-009)
# ---------------------------------------------------------------------------


def test_dev_allows_admin_dev_mode_for_local_config() -> None:
    """Dev environment must not raise when FG_DEV_AUTH_BYPASS is enabled."""
    assert_prod_invariants({"FG_ENV": "dev", "FG_DEV_AUTH_BYPASS": "true"})


def test_prod_rejects_admin_dev_mode() -> None:
    """Prod must raise FG-PROD-008 when FG_DEV_AUTH_BYPASS is enabled."""
    env = {**_VALID_PROD_ENV, "FG_ENV": "prod", "FG_DEV_AUTH_BYPASS": "true"}
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(env)
    assert exc.value.code == "FG-PROD-008"


def test_staging_rejects_admin_dev_mode() -> None:
    """Staging must raise FG-PROD-008 when FG_DEV_AUTH_BYPASS is enabled."""
    env = {**_VALID_PROD_ENV, "FG_ENV": "staging", "FG_DEV_AUTH_BYPASS": "true"}
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(env)
    assert exc.value.code == "FG-PROD-008"


def test_prod_requires_admin_oidc_config() -> None:
    """Prod must raise FG-PROD-009 when FG_OIDC_ISSUER is missing."""
    env = {**_VALID_PROD_ENV, "FG_ENV": "prod", "FG_OIDC_ISSUER": ""}
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(env)
    assert exc.value.code == "FG-PROD-009"


def test_staging_requires_admin_oidc_config() -> None:
    """Staging must raise FG-PROD-009 when FG_OIDC_ISSUER is missing."""
    env = {**_VALID_PROD_ENV, "FG_ENV": "staging", "FG_OIDC_ISSUER": ""}
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(env)
    assert exc.value.code == "FG-PROD-009"


def test_blank_admin_oidc_config_is_rejected() -> None:
    """Blank FG_OIDC_ISSUER must be rejected in prod (FG-PROD-009)."""
    env = {**_VALID_PROD_ENV, "FG_ENV": "prod", "FG_OIDC_ISSUER": "   "}
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(env)
    assert exc.value.code == "FG-PROD-009"


def test_change_me_admin_oidc_config_is_rejected() -> None:
    """CHANGE_ME placeholder in FG_OIDC_ISSUER must be rejected in prod (FG-PROD-009)."""
    env = {
        **_VALID_PROD_ENV,
        "FG_ENV": "prod",
        "FG_OIDC_ISSUER": "CHANGE_ME_OIDC_ISSUER",
    }
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(env)
    assert exc.value.code == "FG-PROD-009"


def test_valid_prod_admin_oidc_config_passes() -> None:
    """Valid FG_OIDC_ISSUER with dev-bypass off must not raise in prod."""
    env = {
        **_VALID_PROD_ENV,
        "FG_ENV": "prod",
        "FG_OIDC_ISSUER": "https://auth.example.com",
        "FG_DEV_AUTH_BYPASS": "0",
    }
    assert_prod_invariants(env)


def test_admin_dev_auth_forbidden_error_message_is_stable() -> None:
    """Error message must contain ADMIN_DEV_AUTH_FORBIDDEN_IN_PROD for stable alerting."""
    env = {**_VALID_PROD_ENV, "FG_ENV": "prod", "FG_DEV_AUTH_BYPASS": "true"}
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(env)
    assert "ADMIN_DEV_AUTH_FORBIDDEN_IN_PROD" in str(exc.value)


def test_admin_oidc_required_error_message_is_stable() -> None:
    """Error message must contain ADMIN_OIDC_CONFIG_REQUIRED for stable alerting."""
    env = {**_VALID_PROD_ENV, "FG_ENV": "prod", "FG_OIDC_ISSUER": ""}
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(env)
    assert "ADMIN_OIDC_CONFIG_REQUIRED" in str(exc.value)


# ---------------------------------------------------------------------------
# Keycloak-derived OIDC issuer tests (FG-PROD-009, Option B)
# ---------------------------------------------------------------------------

# Base env without FG_OIDC_ISSUER — Keycloak path must satisfy FG-PROD-009.
_VALID_PROD_ENV_NO_ISSUER: dict[str, str] = {
    k: v for k, v in _VALID_PROD_ENV.items() if k != "FG_OIDC_ISSUER"
}


def test_prod_passes_with_keycloak_base_url_and_realm() -> None:
    """FG_KEYCLOAK_BASE_URL + FG_KEYCLOAK_REALM satisfies FG-PROD-009 in prod."""
    env = {
        **_VALID_PROD_ENV_NO_ISSUER,
        "FG_ENV": "prod",
        "FG_KEYCLOAK_BASE_URL": "https://idp.example.com",
        "FG_KEYCLOAK_REALM": "frostgate",
    }
    assert_prod_invariants(env)


def test_prod_fails_with_only_keycloak_base_url() -> None:
    """FG_KEYCLOAK_BASE_URL without FG_KEYCLOAK_REALM must still fail FG-PROD-009."""
    env = {
        **_VALID_PROD_ENV_NO_ISSUER,
        "FG_ENV": "prod",
        "FG_KEYCLOAK_BASE_URL": "https://idp.example.com",
    }
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(env)
    assert exc.value.code == "FG-PROD-009"


def test_prod_fails_with_only_keycloak_realm() -> None:
    """FG_KEYCLOAK_REALM without FG_KEYCLOAK_BASE_URL must still fail FG-PROD-009."""
    env = {
        **_VALID_PROD_ENV_NO_ISSUER,
        "FG_ENV": "prod",
        "FG_KEYCLOAK_REALM": "frostgate",
    }
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(env)
    assert exc.value.code == "FG-PROD-009"


def test_prod_fails_with_change_me_keycloak_base_url() -> None:
    """CHANGE_ME placeholder in FG_KEYCLOAK_BASE_URL must fail FG-PROD-009."""
    env = {
        **_VALID_PROD_ENV_NO_ISSUER,
        "FG_ENV": "prod",
        "FG_KEYCLOAK_BASE_URL": "CHANGE_ME_KEYCLOAK_BASE_URL",
        "FG_KEYCLOAK_REALM": "frostgate",
    }
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(env)
    assert exc.value.code == "FG-PROD-009"


def test_prod_fails_with_change_me_keycloak_realm() -> None:
    """CHANGE_ME placeholder in FG_KEYCLOAK_REALM must fail FG-PROD-009."""
    env = {
        **_VALID_PROD_ENV_NO_ISSUER,
        "FG_ENV": "prod",
        "FG_KEYCLOAK_BASE_URL": "https://idp.example.com",
        "FG_KEYCLOAK_REALM": "CHANGE_ME_REALM",
    }
    with pytest.raises(ProdInvariantViolation) as exc:
        assert_prod_invariants(env)
    assert exc.value.code == "FG-PROD-009"


def test_staging_passes_with_keycloak_derived_issuer() -> None:
    """Staging also accepts Keycloak-derived issuer (Option B) for FG-PROD-009."""
    env = {
        **_VALID_PROD_ENV_NO_ISSUER,
        "FG_ENV": "staging",
        "FG_KEYCLOAK_BASE_URL": "https://idp.example.com",
        "FG_KEYCLOAK_REALM": "frostgate",
    }
    assert_prod_invariants(env)
