"""Regression tests: GET /admin/identity/tenants/{tenant_id}/engagements.

Invariants proved:
- Own-tenant admin key returns owned engagements (200) with total_count
- Cross-tenant admin key → 403 (resolve_authoritative_tenant rejects)
- Empty tenant returns items=[], total_count=0, next_cursor=None
- Server-side isolation: tenant B's engagements never appear in tenant A's list
- Missing admin:read scope → 403
- Pagination: next_cursor present when result set is full page; absent on last page
- total_count reflects the full tenant set regardless of page size
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_AUTH_ENABLED", "1")

_TENANT_A = "h0pr3-sel-a-01"
_TENANT_B = "h0pr3-sel-b-01"
_TENANT_EMPTY = "h0pr3-sel-empty-01"
_TENANT_PAGE = "h0pr3-sel-page-01"


def _create_engagement(client, key: str, client_name: str) -> str:
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
        gov_key = mint_key(
            "governance:read", "governance:write", tenant_id=_TENANT_A, ttl_seconds=3600
        )
        admin_key = mint_key("admin:read", tenant_id=_TENANT_A, ttl_seconds=3600)
        c = TestClient(app)

        eid = _create_engagement(c, gov_key, "Acme Corp")

        r = c.get(
            f"/admin/identity/tenants/{_TENANT_A}/engagements",
            headers={"x-api-key": admin_key},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert isinstance(body["items"], list)
        assert body["total_count"] >= 1
        ids = [item["id"] for item in body["items"]]
        assert eid in ids
        match = next(item for item in body["items"] if item["id"] == eid)
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
        """Tenant with no engagements returns items=[], total_count=0, next_cursor=None."""
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
        body = r.json()
        assert body["items"] == []
        assert body["total_count"] == 0
        assert body["next_cursor"] is None

    def test_server_side_isolation_excludes_other_tenant(self, build_app):
        """Tenant B's engagement never appears in tenant A's list."""
        from starlette.testclient import TestClient
        from api.auth_scopes import mint_key

        app = build_app(auth_enabled=True, api_key="")
        gov_a = mint_key(
            "governance:read", "governance:write", tenant_id=_TENANT_A, ttl_seconds=3600
        )
        gov_b = mint_key(
            "governance:read", "governance:write", tenant_id=_TENANT_B, ttl_seconds=3600
        )
        admin_a = mint_key("admin:read", tenant_id=_TENANT_A, ttl_seconds=3600)
        c = TestClient(app)

        eid_a = _create_engagement(c, gov_a, "Alpha Client")
        eid_b = _create_engagement(c, gov_b, "Beta Client")

        r = c.get(
            f"/admin/identity/tenants/{_TENANT_A}/engagements",
            headers={"x-api-key": admin_a},
        )
        assert r.status_code == 200, r.text
        ids = [item["id"] for item in r.json()["items"]]
        assert eid_a in ids, "own engagement must appear"
        assert eid_b not in ids, "other tenant's engagement must be excluded"

    def test_missing_admin_scope_returns_403(self, build_app):
        """Key without admin:read scope → 403."""
        from starlette.testclient import TestClient
        from api.auth_scopes import mint_key

        app = build_app(auth_enabled=True, api_key="")
        gov_only_key = mint_key(
            "governance:read", tenant_id=_TENANT_A, ttl_seconds=3600
        )
        c = TestClient(app)

        r = c.get(
            f"/admin/identity/tenants/{_TENANT_A}/engagements",
            headers={"x-api-key": gov_only_key},
        )
        assert r.status_code == 403, r.text

    def test_pagination_cursor_and_total_count(self, build_app):
        """next_cursor present on full page; absent on last page; total_count consistent."""
        from starlette.testclient import TestClient
        from api.auth_scopes import mint_key

        app = build_app(auth_enabled=True, api_key="")
        gov_key = mint_key(
            "governance:read",
            "governance:write",
            tenant_id=_TENANT_PAGE,
            ttl_seconds=3600,
        )
        admin_key = mint_key("admin:read", tenant_id=_TENANT_PAGE, ttl_seconds=3600)
        c = TestClient(app)

        # Seed 3 engagements; request page size of 2 to force cursor pagination
        for name in ("Eng-1", "Eng-2", "Eng-3"):
            _create_engagement(c, gov_key, name)

        # First page: limit=2 → next_cursor set, total_count=3
        r1 = c.get(
            f"/admin/identity/tenants/{_TENANT_PAGE}/engagements?limit=2",
            headers={"x-api-key": admin_key},
        )
        assert r1.status_code == 200, r1.text
        body1 = r1.json()
        assert len(body1["items"]) == 2
        assert body1["total_count"] == 3
        assert body1["next_cursor"] is not None

        # Second page: limit=2, cursor from first page → 1 item, next_cursor=None
        r2 = c.get(
            f"/admin/identity/tenants/{_TENANT_PAGE}/engagements?limit=2&cursor={body1['next_cursor']}",
            headers={"x-api-key": admin_key},
        )
        assert r2.status_code == 200, r2.text
        body2 = r2.json()
        assert len(body2["items"]) == 1
        assert body2["total_count"] == 3
        assert body2["next_cursor"] is None

        # All IDs across both pages are distinct
        ids1 = {item["id"] for item in body1["items"]}
        ids2 = {item["id"] for item in body2["items"]}
        assert ids1.isdisjoint(ids2), "no engagement should appear on both pages"
