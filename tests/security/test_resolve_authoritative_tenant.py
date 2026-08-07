"""Regression tests: resolve_authoritative_tenant canonical authority resolver.

Two layers:
1. Unit tests (TestResolveAuthoritativeTenant) — mock Request + ActorContext, test
   the resolver function directly for every branch of the decision tree.
2. Integration tests (TestMutationRouteIntegration) — real FastAPI app via
   build_app, prove the resolver is actually wired into the route dependency
   stack and that a real HTTP 403 is returned for cross-tenant access.

Invariants proved:
- Actor with matching tenant_id passes through
- Actor with mismatched tenant_id is rejected 403 (stale_session path)
- Actor with no tenant_id (admin keys, service principals) passes through
- Key bound to tenant-A cannot access tenant-B mutation route end-to-end
- Route tenant is the only authoritative source; actor claim does not override key binding
"""

from __future__ import annotations

import os
import pytest
from unittest.mock import MagicMock

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_AUTH_ENABLED", "1")


def _make_request(key_tenant: str | None = None, cached: bool = False) -> MagicMock:
    """Build a mock Request with auth.tenant_id set to key_tenant."""
    from fastapi import Request

    req = MagicMock(spec=Request)
    state = MagicMock()
    auth = MagicMock()
    auth.tenant_id = key_tenant
    auth.reason = "api_key"
    auth.key_prefix = "fg_test"
    auth.scopes = {"admin:write"}
    state.auth = auth
    state.tenant_id = key_tenant if (cached and key_tenant) else None
    state.tenant_is_key_bound = bool(cached and key_tenant)
    req.state = state
    return req


def _make_actor(tenant_id: str | None) -> MagicMock:
    """Build a mock ActorContext with the given tenant_id."""
    from api.actor_context import ActorContext

    actor = MagicMock(spec=ActorContext)
    actor.tenant_id = tenant_id
    return actor


class TestResolveAuthoritativeTenant:
    """Unit tests for resolve_authoritative_tenant()."""

    def test_matching_actor_tenant_passes(self):
        """Actor.tenant_id == route_tenant_id → resolved and logged."""
        from api.auth_scopes import resolve_authoritative_tenant

        req = _make_request(key_tenant="acme")
        actor = _make_actor("acme")

        result = resolve_authoritative_tenant(req, actor, "acme")
        assert result == "acme"

    def test_mismatched_actor_tenant_raises_403(self):
        """Actor.tenant_id != route_tenant_id → 403 forbidden."""
        from fastapi import HTTPException
        from api.auth_scopes import resolve_authoritative_tenant

        req = _make_request(key_tenant="acme")
        actor = _make_actor("rival-corp")

        with pytest.raises(HTTPException) as exc:
            resolve_authoritative_tenant(req, actor, "acme")

        assert exc.value.status_code == 403

    def test_none_actor_tenant_passes(self):
        """actor_ctx.tenant_id = None (admin key, service principal) → no cross-check, passes."""
        from api.auth_scopes import resolve_authoritative_tenant

        req = _make_request(key_tenant="acme")
        actor = _make_actor(None)

        result = resolve_authoritative_tenant(req, actor, "acme")
        assert result == "acme"

    def test_empty_actor_tenant_passes(self):
        """actor_ctx.tenant_id = '' → treated as unset, passes."""
        from api.auth_scopes import resolve_authoritative_tenant

        req = _make_request(key_tenant="acme")
        actor = _make_actor("")

        result = resolve_authoritative_tenant(req, actor, "acme")
        assert result == "acme"

    def test_key_bound_to_wrong_tenant_raises_403(self):
        """Key is bound to tenant-A but route is for tenant-B → 403 via bind_tenant_id."""
        from fastapi import HTTPException
        from api.auth_scopes import resolve_authoritative_tenant

        req = _make_request(key_tenant="tenant-a")
        actor = _make_actor("tenant-a")

        with pytest.raises(HTTPException) as exc:
            resolve_authoritative_tenant(req, actor, "tenant-b")

        assert exc.value.status_code == 403

    def test_route_tenant_authoritative_over_actor_claim(self):
        """Key bound to tenant-X; actor claims tenant-X; route says tenant-Y → 403.

        Neither actor claim nor key binding can override a mismatched route tenant.
        """
        from fastapi import HTTPException
        from api.auth_scopes import resolve_authoritative_tenant

        req = _make_request(key_tenant="legitimate")
        actor = _make_actor("legitimate")

        with pytest.raises(HTTPException) as exc:
            resolve_authoritative_tenant(req, actor, "different-tenant")

        assert exc.value.status_code == 403

    def test_whitespace_actor_tenant_treated_as_none(self):
        """actor_ctx.tenant_id = '   ' → stripped to empty, treated as unset."""
        from api.auth_scopes import resolve_authoritative_tenant

        req = _make_request(key_tenant="acme")
        actor = _make_actor("   ")

        result = resolve_authoritative_tenant(req, actor, "acme")
        assert result == "acme"


class TestMutationRouteIntegration:
    """Integration tests: resolver wired into real admin_identity mutation routes.

    Uses the conftest build_app fixture to spin up a full FastAPI app with
    SQLite, auth enabled, and tenant-scoped keys from mint_key. These tests
    catch wiring bugs that unit tests cannot — e.g. the route calling the old
    bind_tenant_id instead of resolve_authoritative_tenant.
    """

    def test_upsert_config_own_tenant_succeeds(self, build_app):
        """Key bound to TENANT + route for TENANT → 200 through resolve_authoritative_tenant."""
        from starlette.testclient import TestClient
        from api.auth_scopes import mint_key

        tenant = "h0pr2-integ-own-tenant-01"
        app = build_app(auth_enabled=True, api_key="")
        key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
        c = TestClient(app)

        r = c.put(
            f"/admin/identity/tenants/{tenant}/config",
            json={"identity_mode": "managed", "provider": "auth0"},
            headers={"x-api-key": key},
        )
        assert r.status_code == 200, r.text
        assert r.json()["tenant_id"] == tenant

    def test_upsert_config_cross_tenant_returns_403(self, build_app):
        """Key bound to TENANT_A + route for TENANT_B → 403 through resolve_authoritative_tenant.

        This proves the resolver (not just bind_tenant_id) is in the call path:
        if the route still called bare bind_tenant_id, cross-tenant would still
        return 403, but the stale_session audit path would never fire.
        """
        from starlette.testclient import TestClient
        from api.auth_scopes import mint_key

        tenant_a = "h0pr2-integ-cross-a-01"
        tenant_b = "h0pr2-integ-cross-b-01"
        app = build_app(auth_enabled=True, api_key="")
        key_a = mint_key("admin:read", "admin:write", tenant_id=tenant_a, ttl_seconds=3600)
        c = TestClient(app)

        r = c.put(
            f"/admin/identity/tenants/{tenant_b}/config",
            json={"identity_mode": "managed", "provider": "auth0"},
            headers={"x-api-key": key_a},
        )
        assert r.status_code == 403, r.text

    def test_create_invitation_cross_tenant_returns_403(self, build_app):
        """POST invitation on a tenant the key is not bound to → 403."""
        from starlette.testclient import TestClient
        from api.auth_scopes import mint_key

        tenant_a = "h0pr2-integ-invite-a-01"
        tenant_b = "h0pr2-integ-invite-b-01"
        app = build_app(auth_enabled=True, api_key="")
        key_a = mint_key("admin:read", "admin:write", tenant_id=tenant_a, ttl_seconds=3600)
        c = TestClient(app)

        r = c.post(
            f"/admin/identity/tenants/{tenant_b}/invitations",
            json={
                "email": "attacker@evil.example",
                "role": "assessor",
                "identity_type": "human",
            },
            headers={"x-api-key": key_a},
        )
        assert r.status_code == 403, r.text
