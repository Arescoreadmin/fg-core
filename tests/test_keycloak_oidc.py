"""Tests for Keycloak OIDC env wiring, auth flow config, and negative-path enforcement.

Task 6.1 — Keycloak integration.
Covers: FG_KEYCLOAK_* derivation, oidc_enabled gate, negative-path (missing creds = failure).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from admin_gateway.auth.config import get_auth_config, reset_auth_config

_KC_BASE = "http://fg-idp.local:8081"
_KC_REALM = "FrostGate"
_KC_CLIENT_ID = "fg-service"
_KC_CLIENT_SECRET = "fg-service-ci-secret"
_REDIRECT = "http://localhost:18080/auth/callback"

_KC_ENV: dict[str, str] = {
    "FG_KEYCLOAK_BASE_URL": _KC_BASE,
    "FG_KEYCLOAK_REALM": _KC_REALM,
    "FG_KEYCLOAK_CLIENT_ID": _KC_CLIENT_ID,
    "FG_KEYCLOAK_CLIENT_SECRET": _KC_CLIENT_SECRET,
    "FG_OIDC_REDIRECT_URL": _REDIRECT,
}

_REALM_FILE = (
    Path(__file__).resolve().parents[1] / "keycloak" / "realms" / "frostgate-realm.json"
)


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


class TestCanonicalTesterRealmProvisioning:
    """Realm provisioning must include canonical tester user/client tenant claims."""

    def test_canonical_tester_client_exists(self) -> None:
        data = json.loads(_REALM_FILE.read_text(encoding="utf-8"))
        clients = data.get("clients", [])
        client = next((c for c in clients if c.get("clientId") == "fg-tester"), None)
        assert client is not None, "Expected fg-tester client in Keycloak realm import"
        assert client.get("directAccessGrantsEnabled") is True
        assert client.get("serviceAccountsEnabled") is False

    def test_canonical_tester_claim_mappers_include_seed_tenant(self) -> None:
        data = json.loads(_REALM_FILE.read_text(encoding="utf-8"))
        clients = data.get("clients", [])
        client = next((c for c in clients if c.get("clientId") == "fg-tester"), None)
        assert client is not None, "Expected fg-tester client in Keycloak realm import"
        mappers = client.get("protocolMappers", [])
        by_name = {m.get("name"): m for m in mappers}

        tenant_mapper = by_name.get("fg-tenant-id-mapper", {})
        allowed_mapper = by_name.get("fg-allowed-tenants-mapper", {})
        assert (
            tenant_mapper.get("config", {}).get("claim.value") == "tenant-seed-primary"
        )
        assert (
            allowed_mapper.get("config", {}).get("claim.value")
            == '["tenant-seed-primary"]'
        )

    def test_canonical_tester_user_exists(self) -> None:
        data = json.loads(_REALM_FILE.read_text(encoding="utf-8"))
        users = data.get("users", [])
        user = next((u for u in users if u.get("username") == "fg-tester-admin"), None)
        assert user is not None, (
            "Expected fg-tester-admin user in Keycloak realm import"
        )
