"""Regression tests: GET /admin/identity/tenants/{tenant_id}/engagements.

Invariants proved:
- Own-tenant admin key returns owned engagements (200)
- Cross-tenant admin key → 403 (resolve_authoritative_tenant rejects)
- Empty tenant returns [] not 404
- Server-side isolation: tenant B's engagements never appear in tenant A's list
- Missing admin:read scope → 403
"""

from __future__ import annotations

import os
import pytest

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_AUTH_ENABLED", "1")

_TENANT_A = "h0pr3-sel-a-01"
_TENANT_B = "h0pr3-sel-b-01"
_TENANT_EMPTY = "h0pr3-sel-empty-01"


def _create_engagement(client, key: str, tenant_id: str, client_name: str) -> str:
    r = client.post(
        "/field-assessment/engagements",
        json={
            "client_name": client_name,
            "client_domain": "example.com",
            "assessor_id": "assessor-1",
            "assessment_type": "soc2",
            "scheduled_date": None,
            "engagement_metadata": {},
        },
        headers={"x-api-key": key},
    )
    assert r.status_code == 201, f"seed engagement failed: {r.text}"
    return r.json()["id"]


class TestAdminEngagementSelector:
    def test_own_tenant_returns_engagements(self, build_app):
        """Admin key for tenant A lists tenant A's engagements → 200 with data."""
        from starlette.testclient import TestClient
        from api.auth_scopes import mint_key

        app = build_app(auth_enabled=True, api_key="")
        gov_key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_A, ttl_seconds=3600)
        admin_key = mint_key("admin:read", tenant_id=_TENANT_A, ttl_seconds=3600)
        c = TestClient(app)

        eid = _create_engagement(c, gov_key, _TENANT_A, "Acme Corp")

        r = c.get(
            f"/admin/identity/tenants/{_TENANT_A}/engagements",
            headers={"x-api-key": admin_key},
        )
        assert r.status_code == 200, r.text
        items = r.json()
        assert isinstance(items, list)
        assert any(item["id"] == eid for item in items)
        match = next(item for item in items if item["id"] == eid)
        assert match["client_name"] == "Acme Corp"
        assert "status" in match

    def test_cross_tenant_returns_403(self, build_app):
        """Admin key for tenant A cannot list tenant B's engagements → 403."""
        from starlette.testclient import TestClient
        from api.auth_scopes import mint_key

        app = build_app(auth_enabled=True, api_key="")
        key_a = mint_key("admin:read", tenant_id=_TENANT_A, ttl_seconds=3600)
        c = TestClient(app)

        r = c.get(
            f"/admin/identity/tenants/{_TENANT_B}/engagements",
            headers={"x-api-key": key_a},
        )
        assert r.status_code == 403, r.text

    def test_empty_tenant_returns_empty_list(self, build_app):
        """Tenant with no engagements returns [] not 404."""
        from starlette.testclient import TestClient
        from api.auth_scopes import mint_key

        app = build_app(auth_enabled=True, api_key="")
        admin_key = mint_key("admin:read", tenant_id=_TENANT_EMPTY, ttl_seconds=3600)
        c = TestClient(app)

        r = c.get(
            f"/admin/identity/tenants/{_TENANT_EMPTY}/engagements",
            headers={"x-api-key": admin_key},
        )
        assert r.status_code == 200, r.text
        assert r.json() == []

    def test_server_side_isolation_excludes_other_tenant(self, build_app):
        """Tenant B's engagement never appears in tenant A's list."""
        from starlette.testclient import TestClient
        from api.auth_scopes import mint_key

        app = build_app(auth_enabled=True, api_key="")
        gov_a = mint_key("governance:read", "governance:write", tenant_id=_TENANT_A, ttl_seconds=3600)
        gov_b = mint_key("governance:read", "governance:write", tenant_id=_TENANT_B, ttl_seconds=3600)
        admin_a = mint_key("admin:read", tenant_id=_TENANT_A, ttl_seconds=3600)
        c = TestClient(app)

        eid_a = _create_engagement(c, gov_a, _TENANT_A, "Alpha Client")
        eid_b = _create_engagement(c, gov_b, _TENANT_B, "Beta Client")

        r = c.get(
            f"/admin/identity/tenants/{_TENANT_A}/engagements",
            headers={"x-api-key": admin_a},
        )
        assert r.status_code == 200, r.text
        ids = [item["id"] for item in r.json()]
        assert eid_a in ids, "own engagement must appear"
        assert eid_b not in ids, "other tenant's engagement must be excluded"

    def test_missing_admin_scope_returns_403(self, build_app):
        """Key without admin:read scope → 403."""
        from starlette.testclient import TestClient
        from api.auth_scopes import mint_key

        app = build_app(auth_enabled=True, api_key="")
        gov_only_key = mint_key("governance:read", tenant_id=_TENANT_A, ttl_seconds=3600)
        c = TestClient(app)

        r = c.get(
            f"/admin/identity/tenants/{_TENANT_A}/engagements",
            headers={"x-api-key": gov_only_key},
        )
        assert r.status_code == 403, r.text
