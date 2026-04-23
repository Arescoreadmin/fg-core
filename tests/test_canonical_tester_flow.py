"""Canonical tester flow — structural and HTTP-layer assertions.

Task 10.2 Addendum — verifies that the canonical tester path is structurally
complete and that the HTTP flow enforces tenant isolation correctly.

Two test classes:

RealmStructure — pure JSON inspection of keycloak/realms/frostgate-realm.json.
  No running services required. Proves the realm can support the canonical path.

CanonicalTesterHTTP — HTTP-layer tests using TestClient + patched OIDC verification.
  The external OIDC verification call is stubbed (requires live Keycloak); all session
  management, scope expansion, and tenant enforcement run for real.
  Canonical claims: fg-tester client, allowed_tenants=[tenant-seed-primary], frostgate-admin role.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
REALM_FILE = REPO_ROOT / "keycloak" / "realms" / "frostgate-realm.json"

_CANONICAL_TENANT = "tenant-seed-primary"
_WRONG_TENANT = "tenant-does-not-exist-intentionally"
_ISSUER = "http://fg-idp.test:8080/realms/FrostGate"
_CLIENT_ID = "fg-tester"
_CLIENT_SECRET = "fg-tester-ci-secret"
_TESTER_USER = "fg-tester-admin"

_OIDC_ENV: dict[str, str] = {
    "FG_ENV": "dev",
    "FG_SESSION_SECRET": "canonical-tester-test-secret-32c",
    "FG_OIDC_ISSUER": _ISSUER,
    "FG_OIDC_CLIENT_ID": _CLIENT_ID,
    "FG_OIDC_CLIENT_SECRET": _CLIENT_SECRET,
    "FG_OIDC_REDIRECT_URL": "http://localhost:18080/auth/callback",
    "FG_DEV_AUTH_BYPASS": "false",
    "AG_CORE_BASE_URL": "http://core.local",
    # Internal token: activates admin_internal_token auth path in core so
    # bind_tenant_id() accepts an explicit tenant_id from query params.
    "AG_CORE_INTERNAL_TOKEN": "test-internal-token-value",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _canonical_claims(**overrides: Any) -> dict[str, Any]:
    """Claims representing a valid fg-tester-admin token.

    Mirrors what the Keycloak fg-tester client protocol mappers emit:
      fg_scopes         → ["console:admin"]  (gateway scope path)
      tenant_id         → "tenant-seed-primary"  (session.tenant_id → current_tenant)
      allowed_tenants   → ["tenant-seed-primary"]  (multi-tenant access list)
    """
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": _TESTER_USER,
        "iss": _ISSUER,
        "aud": _CLIENT_ID,
        "exp": now + 300,
        "iat": now,
        "preferred_username": _TESTER_USER,
        "fg_scopes": ["console:admin"],
        "tenant_id": _CANONICAL_TENANT,
        "allowed_tenants": [_CANONICAL_TENANT],
    }
    claims.update(overrides)
    return claims


def _patch_verify(claims: dict[str, Any]) -> Any:
    return patch(
        "admin_gateway.auth.oidc.OIDCClient.verify_access_token",
        new=AsyncMock(return_value=claims),
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def oidc_app(tmp_path, monkeypatch):
    """Admin gateway with OIDC configured for canonical tester client."""
    db_path = tmp_path / "canonical_tester.db"
    env = {**_OIDC_ENV, "AG_SQLITE_PATH": str(db_path)}
    for k, v in env.items():
        monkeypatch.setenv(k, v)

    mods = [m for m in sys.modules if m.startswith("admin_gateway")]
    for m in mods:
        del sys.modules[m]

    from admin_gateway.auth.config import reset_auth_config
    from admin_gateway.main import build_app
    from admin_gateway.routers import admin as admin_router

    reset_auth_config()
    app = build_app()

    # Mock core proxy — not testing core API, testing gateway enforcement.
    # Must accept session and tenant_id kwargs added by the gateway proxy layer.
    async def _mock_proxy(
        request, method, path, params=None, json_body=None, session=None, tenant_id=None
    ):
        if "audit/search" in path:
            tenant = (params or {}).get("tenant_id", _CANONICAL_TENANT)
            return {
                "items": [
                    {
                        "id": "1",
                        "ts": "2024-01-01T00:00:00Z",
                        "tenant_id": tenant,
                        "actor": "fg-tester-admin",
                        "action": "auth_success",
                        "status": "success",
                        "resource_type": "security",
                        "resource_id": "/admin/login",
                        "request_id": "req-1",
                        "ip": "127.0.0.1",
                        "user_agent": "test",
                        "meta": {},
                    }
                ],
                "next_cursor": None,
            }
        return {}

    monkeypatch.setattr(admin_router, "_proxy_to_core", _mock_proxy, raising=False)
    return app


@pytest.fixture()
def oidc_client(oidc_app):
    with TestClient(oidc_app, raise_server_exceptions=False) as c:
        yield c


# ---------------------------------------------------------------------------
# Part 1 — Realm structure (no services required)
# ---------------------------------------------------------------------------


class TestRealmStructure:
    """Keycloak realm JSON must define fg-tester client and fg-tester-admin user."""

    @pytest.fixture(autouse=True)
    def _realm(self) -> None:
        assert REALM_FILE.exists(), f"Realm file missing: {REALM_FILE}"
        self.realm: dict[str, Any] = json.loads(REALM_FILE.read_text(encoding="utf-8"))
        self.clients: list[dict[str, Any]] = self.realm.get("clients", [])
        self.tester_client: dict[str, Any] = next(
            (c for c in self.clients if c.get("clientId") == "fg-tester"), {}
        )
        self.users: list[dict[str, Any]] = self.realm.get("users", [])
        self.tester_user: dict[str, Any] = next(
            (u for u in self.users if u.get("username") == _TESTER_USER), {}
        )

    def test_realm_contains_fg_tester_client(self) -> None:
        assert self.tester_client, "Realm must define fg-tester client"

    def test_fg_tester_has_direct_grants_enabled(self) -> None:
        assert self.tester_client.get("directAccessGrantsEnabled") is True, (
            "fg-tester must have directAccessGrantsEnabled=true for password grant"
        )

    def test_fg_tester_is_not_service_account(self) -> None:
        assert self.tester_client.get("serviceAccountsEnabled") is not True, (
            "fg-tester must not be a service account — canonical tester uses password grant"
        )

    def test_fg_tester_has_allowed_tenants_claim_mapper(self) -> None:
        mappers: list[dict[str, Any]] = self.tester_client.get("protocolMappers", [])
        claim_names = [m.get("config", {}).get("claim.name", "") for m in mappers]
        assert "allowed_tenants" in claim_names, (
            "fg-tester client must have a protocol mapper for 'allowed_tenants' claim"
        )

    def test_fg_tester_allowed_tenants_includes_canonical_seed_tenant(self) -> None:
        mappers: list[dict[str, Any]] = self.tester_client.get("protocolMappers", [])
        at_mapper = next(
            (
                m
                for m in mappers
                if m.get("config", {}).get("claim.name") == "allowed_tenants"
            ),
            None,
        )
        assert at_mapper is not None, "allowed_tenants mapper not found"
        raw_value: str = at_mapper.get("config", {}).get("claim.value", "")
        try:
            value = json.loads(raw_value)
        except json.JSONDecodeError:
            value = [raw_value]
        assert _CANONICAL_TENANT in value, (
            f"allowed_tenants mapper must include {_CANONICAL_TENANT!r}, got: {value}"
        )

    def test_fg_tester_has_fg_scopes_mapper(self) -> None:
        mappers: list[dict[str, Any]] = self.tester_client.get("protocolMappers", [])
        claim_names = [m.get("config", {}).get("claim.name", "") for m in mappers]
        assert "fg_scopes" in claim_names, (
            "fg-tester client must have a protocol mapper for 'fg_scopes' "
            "(needed for console:admin → audit:read scope expansion)"
        )

    def test_fg_tester_fg_scopes_value_is_console_admin(self) -> None:
        mappers: list[dict[str, Any]] = self.tester_client.get("protocolMappers", [])
        scopes_mapper = next(
            (
                m
                for m in mappers
                if m.get("config", {}).get("claim.name") == "fg_scopes"
            ),
            None,
        )
        assert scopes_mapper is not None, "fg_scopes mapper not found"
        raw_value: str = scopes_mapper.get("config", {}).get("claim.value", "")
        try:
            value = json.loads(raw_value)
        except json.JSONDecodeError:
            value = [raw_value]
        assert "console:admin" in value, (
            f"fg_scopes mapper must include 'console:admin', got: {value}\n"
            f"'console:admin' expands via SCOPE_HIERARCHY to include audit:read"
        )

    def test_fg_tester_has_tenant_id_claim_mapper(self) -> None:
        """tenant_id claim required so session.tenant_id is set → current_tenant in /admin/me."""
        mappers: list[dict[str, Any]] = self.tester_client.get("protocolMappers", [])
        claim_names = [m.get("config", {}).get("claim.name", "") for m in mappers]
        assert "tenant_id" in claim_names, (
            "fg-tester client must have a 'tenant_id' protocol mapper; "
            "without it session.tenant_id=None and /admin/me returns current_tenant=null"
        )

    def test_fg_tester_tenant_id_maps_to_canonical_seed_tenant(self) -> None:
        mappers: list[dict[str, Any]] = self.tester_client.get("protocolMappers", [])
        tid_mapper = next(
            (
                m
                for m in mappers
                if m.get("config", {}).get("claim.name") == "tenant_id"
            ),
            None,
        )
        assert tid_mapper is not None, "tenant_id mapper not found"
        value: str = tid_mapper.get("config", {}).get("claim.value", "")
        assert value == _CANONICAL_TENANT, (
            f"tenant_id mapper must be {_CANONICAL_TENANT!r}, got: {value!r}"
        )

    def test_realm_contains_fg_tester_admin_user(self) -> None:
        assert self.tester_user, f"Realm must define user '{_TESTER_USER}'"

    def test_fg_tester_admin_user_is_enabled(self) -> None:
        assert self.tester_user.get("enabled") is True, (
            f"User '{_TESTER_USER}' must be enabled"
        )

    def test_fg_tester_admin_has_credentials(self) -> None:
        creds: list[dict[str, Any]] = self.tester_user.get("credentials", [])
        has_password = any(c.get("type") == "password" for c in creds)
        assert has_password, (
            f"User '{_TESTER_USER}' must have a password credential defined"
        )

    def test_fg_tester_client_secret_matches_canonical_value(self) -> None:
        assert self.tester_client.get("secret") == _CLIENT_SECRET, (
            f"fg-tester secret must be {_CLIENT_SECRET!r} (matches FG_KEYCLOAK_CLIENT_SECRET default)"
        )


# ---------------------------------------------------------------------------
# Part 2 — HTTP layer (TestClient + patched OIDC verification)
# ---------------------------------------------------------------------------


class TestCanonicalTesterHTTP:
    """HTTP-layer enforcement using canonical tester claims.

    External OIDC verification is patched — all session management, scope expansion,
    and tenant enforcement run for real via FastAPI TestClient.
    """

    def test_token_exchange_with_canonical_tester_claims_returns_200(
        self, oidc_client: TestClient
    ) -> None:
        claims = _canonical_claims()
        with _patch_verify(claims):
            resp = oidc_client.post(
                "/auth/token-exchange",
                headers={"Authorization": "Bearer canonical.tester.token"},
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert "session_id" in body
        assert body.get("user_id") == _TESTER_USER
        assert "fg_admin_session" in resp.cookies

    def test_canonical_tester_session_admin_me_returns_canonical_tenant(
        self, oidc_client: TestClient
    ) -> None:
        """Session from canonical tester token must show tenant-seed-primary in /admin/me,
        including current_tenant (requires tenant_id claim in token)."""
        claims = _canonical_claims()
        with _patch_verify(claims):
            exchange = oidc_client.post(
                "/auth/token-exchange",
                headers={"Authorization": "Bearer canonical.tester.token"},
            )
        assert exchange.status_code == 200, exchange.text

        me = oidc_client.get("/admin/me")
        assert me.status_code == 200, me.text
        body = me.json()
        assert _CANONICAL_TENANT in body.get("tenants", []), (
            f"/admin/me must include {_CANONICAL_TENANT!r} in tenants; got: {body.get('tenants')}"
        )
        assert body.get("current_tenant") == _CANONICAL_TENANT, (
            f"/admin/me current_tenant must be {_CANONICAL_TENANT!r}; "
            f"got: {body.get('current_tenant')!r} — "
            f"ensure fg-tester client emits tenant_id claim via protocol mapper"
        )

    def test_canonical_tester_session_does_not_fall_back_to_default_tenant(
        self, oidc_client: TestClient
    ) -> None:
        """Token without any tenant claims must not grant access to tenant-seed-primary."""
        # Strip ALL tenant claims — neither tenant_id nor allowed_tenants
        claims = _canonical_claims()
        del claims["tenant_id"]
        del claims["allowed_tenants"]
        with _patch_verify(claims):
            exchange = oidc_client.post(
                "/auth/token-exchange",
                headers={"Authorization": "Bearer no.tenant.token"},
            )
        assert exchange.status_code == 200, exchange.text

        # No tenant claims → get_allowed_tenants returns {"default"} fallback
        # Requesting tenant-seed-primary must be denied (not in allowed set)
        resp = oidc_client.get(
            f"/admin/audit/search?tenant_id={_CANONICAL_TENANT}&page_size=5"
        )
        assert resp.status_code == 403, (
            f"Session without tenant claims must not access {_CANONICAL_TENANT!r}; "
            f"got HTTP {resp.status_code}"
        )

    def test_canonical_tester_audit_search_succeeds_for_canonical_tenant(
        self, oidc_client: TestClient
    ) -> None:
        """Canonical tester session must succeed on /admin/audit/search for tenant-seed-primary."""
        claims = _canonical_claims()
        with _patch_verify(claims):
            oidc_client.post(
                "/auth/token-exchange",
                headers={"Authorization": "Bearer canonical.tester.token"},
            )

        resp = oidc_client.get(
            f"/admin/audit/search?tenant_id={_CANONICAL_TENANT}&page_size=5"
        )
        assert resp.status_code == 200, resp.text
        assert "items" in resp.json()

    def test_canonical_tester_audit_search_denied_for_wrong_tenant(
        self, oidc_client: TestClient
    ) -> None:
        """Canonical tester session must be denied access to a tenant outside allowed_tenants."""
        claims = _canonical_claims()
        with _patch_verify(claims):
            oidc_client.post(
                "/auth/token-exchange",
                headers={"Authorization": "Bearer canonical.tester.token"},
            )

        resp = oidc_client.get(
            f"/admin/audit/search?tenant_id={_WRONG_TENANT}&page_size=5"
        )
        assert resp.status_code == 403, (
            f"Access to {_WRONG_TENANT!r} must be denied (403); got HTTP {resp.status_code}"
        )

    def test_canonical_tester_requires_no_dev_bypass(
        self, oidc_client: TestClient
    ) -> None:
        """Canonical tester session works with OIDC; FG_DEV_AUTH_BYPASS must not be required."""
        # oidc_client fixture has FG_DEV_AUTH_BYPASS=false and OIDC configured.
        # Token exchange must succeed without bypass.
        claims = _canonical_claims()
        with _patch_verify(claims):
            resp = oidc_client.post(
                "/auth/token-exchange",
                headers={"Authorization": "Bearer canonical.tester.token"},
            )
        assert resp.status_code == 200, (
            f"Token exchange must succeed without FG_DEV_AUTH_BYPASS; got {resp.status_code}"
        )


# ---------------------------------------------------------------------------
# Part 3 — Gateway→core proxy auth contract
# ---------------------------------------------------------------------------


class TestGatewayCoreProxyContract:
    """Gateway→core proxy must use internal token, not forward user JWT.

    Verifies:
    - AG_CORE_INTERNAL_TOKEN activates is_internal=True proxy headers
    - AG_CORE_API_KEY fallback used only when AG_CORE_INTERNAL_TOKEN is absent
    - User upstream_access_token is stored in session but NOT forwarded to core
    - proxy headers include X-Admin-Gateway-Internal when internal token is used
    """

    def test_core_api_key_uses_internal_token_when_set(self, monkeypatch: Any) -> None:
        """AG_CORE_INTERNAL_TOKEN must return (token, True) in any env."""
        import sys

        mods = [m for m in sys.modules if m.startswith("admin_gateway")]
        for m in mods:
            del sys.modules[m]

        monkeypatch.setenv("FG_ENV", "dev")
        monkeypatch.setenv("AG_CORE_BASE_URL", "http://core.test")
        monkeypatch.setenv("AG_CORE_INTERNAL_TOKEN", "test-internal-token-dev")
        monkeypatch.delenv("AG_CORE_API_KEY", raising=False)

        from admin_gateway.routers.admin import _core_api_key

        token, is_internal = _core_api_key()
        assert token == "test-internal-token-dev"
        assert is_internal is True, (
            "_core_api_key must return is_internal=True when AG_CORE_INTERNAL_TOKEN is set"
        )

    def test_core_api_key_falls_back_to_api_key_in_dev(self, monkeypatch: Any) -> None:
        """When AG_CORE_INTERNAL_TOKEN is absent in dev, falls back to AG_CORE_API_KEY."""
        import sys

        mods = [m for m in sys.modules if m.startswith("admin_gateway")]
        for m in mods:
            del sys.modules[m]

        monkeypatch.setenv("FG_ENV", "dev")
        monkeypatch.setenv("AG_CORE_BASE_URL", "http://core.test")
        monkeypatch.delenv("AG_CORE_INTERNAL_TOKEN", raising=False)
        monkeypatch.setenv("AG_CORE_API_KEY", "test-api-key")

        from admin_gateway.routers.admin import _core_api_key

        token, is_internal = _core_api_key()
        assert token == "test-api-key"
        assert is_internal is False

    def test_proxy_headers_include_internal_markers_when_is_internal(
        self, monkeypatch: Any
    ) -> None:
        """When internal token is used, proxy headers must carry X-Admin-Gateway-Internal."""
        import sys
        from unittest.mock import MagicMock

        mods = [m for m in sys.modules if m.startswith("admin_gateway")]
        for m in mods:
            del sys.modules[m]

        monkeypatch.setenv("FG_ENV", "dev")
        monkeypatch.setenv("AG_CORE_BASE_URL", "http://core.test")
        monkeypatch.setenv("AG_CORE_INTERNAL_TOKEN", "test-internal-token")

        from admin_gateway.routers.admin import _core_proxy_headers

        fake_request = MagicMock()
        fake_request.state.request_id = "req-abc"

        headers = _core_proxy_headers(fake_request, tenant_id="tenant-seed-primary")

        assert headers.get("X-Admin-Gateway-Internal") == "true", (
            "Internal token path must send X-Admin-Gateway-Internal: true"
        )
        assert headers.get("X-FG-Internal-Token") == "test-internal-token"
        assert headers.get("X-API-Key") == "test-internal-token"
        assert headers.get("X-Tenant-Id") == "tenant-seed-primary"

    def test_proxy_headers_do_not_forward_user_jwt(self, monkeypatch: Any) -> None:
        """User OIDC bearer token must NOT appear in gateway→core proxy headers."""
        import sys
        from unittest.mock import MagicMock

        mods = [m for m in sys.modules if m.startswith("admin_gateway")]
        for m in mods:
            del sys.modules[m]

        monkeypatch.setenv("FG_ENV", "dev")
        monkeypatch.setenv("AG_CORE_BASE_URL", "http://core.test")
        monkeypatch.setenv("AG_CORE_INTERNAL_TOKEN", "test-internal-token")

        from admin_gateway.auth.session import Session
        from admin_gateway.routers.admin import _core_proxy_headers

        fake_request = MagicMock()
        fake_request.state.request_id = "req-xyz"

        session = Session(
            user_id="fg-tester-admin",
            tenant_id="tenant-seed-primary",
            upstream_access_token="user-oidc-bearer-token-must-not-be-forwarded",
        )

        headers = _core_proxy_headers(
            fake_request, session=session, tenant_id="tenant-seed-primary"
        )

        for _header_name, header_value in headers.items():
            assert "user-oidc-bearer-token-must-not-be-forwarded" not in str(
                header_value
            ), "User OIDC token must not appear in any proxy header"

        assert "Authorization" not in headers, (
            "Proxy headers must not include Authorization (no user JWT passthrough)"
        )
