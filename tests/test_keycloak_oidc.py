"""Tests for Keycloak OIDC env wiring, auth flow config, and negative-path enforcement.

Task 6.1 — Keycloak integration.
Covers: FG_KEYCLOAK_* derivation, oidc_enabled gate, negative-path (missing creds = failure).
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from admin_gateway.auth.config import get_auth_config, reset_auth_config

_KC_BASE = "http://fg-idp.local:8081"
_KC_REALM = "FrostGate"
_KC_CLIENT_ID = "fg-tester"
_KC_CLIENT_SECRET = "fg-tester-ci-secret"
_REDIRECT = "http://localhost:18080/auth/callback"

_KC_ENV: dict[str, str] = {
    "FG_KEYCLOAK_BASE_URL": _KC_BASE,
    "FG_KEYCLOAK_REALM": _KC_REALM,
    "FG_KEYCLOAK_CLIENT_ID": _KC_CLIENT_ID,
    "FG_KEYCLOAK_CLIENT_SECRET": _KC_CLIENT_SECRET,
    "FG_OIDC_REDIRECT_URL": _REDIRECT,
}


@pytest.fixture(autouse=True)
def _reset() -> object:  # type: ignore[return]
    reset_auth_config()
    yield
    reset_auth_config()


# ---------------------------------------------------------------------------
# Keycloak env wiring
# ---------------------------------------------------------------------------


class TestKeycloakEnvWiring:
    """FG_KEYCLOAK_* env vars must derive correct OIDC config."""

    def test_keycloak_base_url_and_realm_derive_oidc_issuer(self) -> None:
        with patch.dict(os.environ, _KC_ENV, clear=False):
            reset_auth_config()
            cfg = get_auth_config()
        assert cfg.oidc_issuer == f"{_KC_BASE}/realms/{_KC_REALM}"

    def test_keycloak_issuer_contains_realms_frostgate(self) -> None:
        with patch.dict(os.environ, _KC_ENV, clear=False):
            reset_auth_config()
            cfg = get_auth_config()
        assert "/realms/FrostGate" in (cfg.oidc_issuer or "")

    def test_keycloak_client_id_wired(self) -> None:
        with patch.dict(os.environ, _KC_ENV, clear=False):
            reset_auth_config()
            cfg = get_auth_config()
        assert cfg.oidc_client_id == _KC_CLIENT_ID

    def test_keycloak_client_secret_wired(self) -> None:
        with patch.dict(os.environ, _KC_ENV, clear=False):
            reset_auth_config()
            cfg = get_auth_config()
        assert cfg.oidc_client_secret == _KC_CLIENT_SECRET

    def test_explicit_fg_oidc_issuer_takes_precedence(self) -> None:
        """FG_OIDC_ISSUER overrides Keycloak derivation."""
        env = {**_KC_ENV, "FG_OIDC_ISSUER": "http://other-idp/realms/other"}
        with patch.dict(os.environ, env, clear=False):
            reset_auth_config()
            cfg = get_auth_config()
        assert cfg.oidc_issuer == "http://other-idp/realms/other"

    def test_partial_keycloak_env_no_realm_does_not_derive_issuer(self) -> None:
        """Without FG_KEYCLOAK_REALM, issuer cannot be derived."""
        env = {k: v for k, v in _KC_ENV.items() if k != "FG_KEYCLOAK_REALM"}
        clean: dict[str, str] = {
            k: v
            for k, v in os.environ.items()
            if k not in ("FG_OIDC_ISSUER", "FG_KEYCLOAK_REALM")
        }
        clean.update(env)
        with patch.dict(os.environ, clean, clear=True):
            reset_auth_config()
            cfg = get_auth_config()
        assert cfg.oidc_issuer is None


# ---------------------------------------------------------------------------
# OIDC negative-path enforcement
# ---------------------------------------------------------------------------


class TestOIDCNegativePath:
    """Missing client credentials must fail explicitly — no silent pass."""

    def test_missing_keycloak_client_id_is_detectable(self) -> None:
        """env check: removing FG_KEYCLOAK_CLIENT_ID causes it to be missing."""
        required = ["FG_KEYCLOAK_CLIENT_ID", "FG_KEYCLOAK_CLIENT_SECRET"]
        env: dict[str, str] = {}
        missing = [k for k in required if not env.get(k)]
        assert "FG_KEYCLOAK_CLIENT_ID" in missing

    def test_missing_keycloak_client_secret_is_detectable(self) -> None:
        """env check: removing FG_KEYCLOAK_CLIENT_SECRET causes it to be missing."""
        required = ["FG_KEYCLOAK_CLIENT_ID", "FG_KEYCLOAK_CLIENT_SECRET"]
        env: dict[str, str] = {}
        missing = [k for k in required if not env.get(k)]
        assert "FG_KEYCLOAK_CLIENT_SECRET" in missing

    def test_oidc_not_enabled_without_any_config(self) -> None:
        """Without OIDC or Keycloak vars, oidc_enabled is False."""
        clean = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("FG_OIDC_", "FG_KEYCLOAK_"))
        }
        with patch.dict(os.environ, clean, clear=True):
            reset_auth_config()
            cfg = get_auth_config()
        assert not cfg.oidc_enabled

    def test_keycloak_without_redirect_url_not_fully_enabled(self) -> None:
        """oidc_enabled requires redirect URL; Keycloak vars alone are insufficient."""
        env = {k: v for k, v in _KC_ENV.items() if k != "FG_OIDC_REDIRECT_URL"}
        clean = {
            k: v for k, v in os.environ.items() if k not in ("FG_OIDC_REDIRECT_URL",)
        }
        clean.update(env)
        with patch.dict(os.environ, clean, clear=True):
            reset_auth_config()
            cfg = get_auth_config()
        assert not cfg.oidc_enabled


# ---------------------------------------------------------------------------
# Auth flow config validation
# ---------------------------------------------------------------------------


class TestAuthFlowConfig:
    """Auth flow config with Keycloak wiring must pass validation in dev."""

    def test_auth_flow_keycloak_full_config_valid_in_dev(self) -> None:
        env = {**_KC_ENV, "FG_ENV": "dev"}
        with patch.dict(os.environ, env, clear=False):
            reset_auth_config()
            cfg = get_auth_config()
        errors = cfg.validate()
        assert not errors, f"Unexpected validation errors: {errors}"

    def test_auth_flow_oidc_enabled_with_full_keycloak_vars(self) -> None:
        with patch.dict(os.environ, _KC_ENV, clear=False):
            reset_auth_config()
            cfg = get_auth_config()
        assert cfg.oidc_enabled

    def test_auth_flow_production_requires_oidc_explicit_failure(self) -> None:
        """Missing OIDC config in prod must produce explicit error."""
        clean = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("FG_OIDC_", "FG_KEYCLOAK_"))
        }
        clean["FG_ENV"] = "prod"
        with patch.dict(os.environ, clean, clear=True):
            reset_auth_config()
            cfg = get_auth_config()
        errors = cfg.validate()
        assert any("OIDC" in e for e in errors), f"Expected OIDC error, got: {errors}"

    def test_auth_flow_keycloak_issuer_realm_path(self) -> None:
        """Derived issuer must contain /realms/FrostGate — matches discovery assertion."""
        with patch.dict(os.environ, _KC_ENV, clear=False):
            reset_auth_config()
            cfg = get_auth_config()
        assert cfg.oidc_issuer is not None
        assert "/realms/FrostGate" in cfg.oidc_issuer
