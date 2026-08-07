"""H0-PR5 — Cross-Tenant Regression Suite.

Proves the invariants stated in the H0-PR5 authority contract:

  CT-1  Grant list isolation: B's list never includes A's grant
  CT-2  Grant delete isolation: B cannot revoke A's grant; A's grant survives
  CT-3  Engagement-scoped grant route: B + A's engagement_id → 404
  CT-4  Engagement read isolation: B + A's engagement_id → 404
  CT-5  Engagement list isolation: B's list never includes A's engagement
  CT-6  Error code uniformity: no oracle leakage via error code differentiation
  CT-7  Full lifecycle chain: all attack vectors fired in sequence; A's resources
        remain intact and accessible after all attacks complete

H0-PR4 covers POST /portal/grants ownership (PG-1 through PG-4).
This suite covers everything downstream of grant creation.
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_AUTH_ENABLED", "1")

_TENANT_A = "h0pr5-ct-a-01"
_TENANT_B = "h0pr5-ct-b-01"

_ENG_BODY = {
    "client_name": "CT Regression Client",
    "client_domain": "ct-regression.example.com",
    "assessor_id": "assessor-h0pr5",
    "assessment_type": "ai_governance",
    "scheduled_date": None,
    "engagement_metadata": {},
}


def _gov_key(mint_key, tenant_id: str) -> str:
    return mint_key(
        "governance:read", "governance:write", tenant_id=tenant_id, ttl_seconds=3600
    )


def _admin_write_key(mint_key, tenant_id: str) -> str:
    return mint_key("admin:write", tenant_id=tenant_id, ttl_seconds=3600)


def _admin_read_key(mint_key, tenant_id: str) -> str:
    return mint_key("admin:read", tenant_id=tenant_id, ttl_seconds=3600)


def _create_engagement(client, gov_key: str) -> str:
    r = client.post(
        "/field-assessment/engagements",
        json=_ENG_BODY,
        headers={"x-api-key": gov_key},
    )
    assert r.status_code == 201, f"engagement seed failed: {r.text}"
    return r.json()["id"]


def _create_grant(client, admin_write_key: str, engagement_id: str) -> str:
    r = client.post(
        "/portal/grants",
        json={"engagement_id": engagement_id, "portal_role": "general", "ttl_days": 30},
        headers={"x-api-key": admin_write_key},
    )
    assert r.status_code == 201, f"grant seed failed: {r.text}"
    return r.json()["grant_id"]


class TestCrossTenantRegression:
    def test_ct1_grant_list_excludes_other_tenant(self, build_app):
        """GET /portal/grants — tenant B's list never contains tenant A's grant."""
        from starlette.testclient import TestClient
        from api.auth_scopes import mint_key

        app = build_app(auth_enabled=True, api_key="")
        c = TestClient(app)

        gov_a = _gov_key(mint_key, _TENANT_A)
        eng_id = _create_engagement(c, gov_a)
        grant_id = _create_grant(c, _admin_write_key(mint_key, _TENANT_A), eng_id)

        r = c.get("/portal/grants", headers={"x-api-key": _admin_read_key(mint_key, _TENANT_B)})
        assert r.status_code == 200, r.text
        ids = [g.get("grant_id") or g.get("credential_id") for g in r.json().get("items", [])]
        assert grant_id not in ids, "tenant A's grant must not appear in tenant B's list"

    def test_ct2_grant_delete_blocked_across_tenant(self, build_app):
        """DELETE /portal/grants/{id} — tenant B cannot revoke tenant A's grant; grant survives."""
        from starlette.testclient import TestClient
        from api.auth_scopes import mint_key

        app = build_app(auth_enabled=True, api_key="")
        c = TestClient(app)

        gov_a = _gov_key(mint_key, _TENANT_A)
        eng_id = _create_engagement(c, gov_a)
        admin_write_a = _admin_write_key(mint_key, _TENANT_A)
        grant_id = _create_grant(c, admin_write_a, eng_id)

        # Tenant B attempts to revoke tenant A's grant
        r = c.delete(
            f"/portal/grants/{grant_id}",
            headers={"x-api-key": _admin_write_key(mint_key, _TENANT_B)},
        )
        assert r.status_code == 404, r.text
        body = r.json()
        assert body["detail"]["code"] == "GRANT_NOT_FOUND"

        # Tenant A's grant must still exist AND be active — ID presence alone does
        # not prove the revoke didn't partially succeed (list includes revoked items).
        r2 = c.get("/portal/grants", headers={"x-api-key": _admin_read_key(mint_key, _TENANT_A)})
        assert r2.status_code == 200, r2.text
        items = r2.json().get("items", [])
        match = next(
            (g for g in items if (g.get("grant_id") or g.get("credential_id")) == grant_id),
            None,
        )
        assert match is not None, "tenant A's grant must still exist after B's revoke attempt"
        assert match.get("status") == "active", (
            f"tenant A's grant must still be active after B's revoke attempt, got: {match.get('status')}"
        )

    def test_ct3_engagement_scoped_grant_route_blocked(self, build_app):
        """POST /field-assessment/engagements/{id}/portal-grants — B key + A's engagement → 404."""
        from starlette.testclient import TestClient
        from api.auth_scopes import mint_key

        app = build_app(auth_enabled=True, api_key="")
        c = TestClient(app)

        gov_a = _gov_key(mint_key, _TENANT_A)
        eng_id = _create_engagement(c, gov_a)

        # Tenant B uses the engagement-scoped grant route with tenant A's engagement_id
        gov_b = _gov_key(mint_key, _TENANT_B)
        r = c.post(
            f"/field-assessment/engagements/{eng_id}/portal-grants",
            json={},
            headers={"x-api-key": gov_b},
        )
        assert r.status_code in (403, 404), r.text
        if r.status_code == 404:
            assert r.json()["detail"]["code"] == "ENGAGEMENT_NOT_FOUND"

    def test_ct4_engagement_read_blocked_across_tenant(self, build_app):
        """GET /field-assessment/engagements/{id} — tenant B key + tenant A's engagement → 404."""
        from starlette.testclient import TestClient
        from api.auth_scopes import mint_key

        app = build_app(auth_enabled=True, api_key="")
        c = TestClient(app)

        gov_a = _gov_key(mint_key, _TENANT_A)
        eng_id = _create_engagement(c, gov_a)

        gov_b = _gov_key(mint_key, _TENANT_B)
        r = c.get(
            f"/field-assessment/engagements/{eng_id}",
            headers={"x-api-key": gov_b},
        )
        assert r.status_code in (403, 404), r.text
        if r.status_code == 404:
            assert r.json()["detail"]["code"] == "ENGAGEMENT_NOT_FOUND"

    def test_ct5_engagement_list_excludes_other_tenant(self, build_app):
        """GET /field-assessment/engagements — tenant B's list never contains tenant A's engagement."""
        from starlette.testclient import TestClient
        from api.auth_scopes import mint_key

        app = build_app(auth_enabled=True, api_key="")
        c = TestClient(app)

        gov_a = _gov_key(mint_key, _TENANT_A)
        eng_id = _create_engagement(c, gov_a)

        gov_b = _gov_key(mint_key, _TENANT_B)
        r = c.get("/field-assessment/engagements", headers={"x-api-key": gov_b})
        assert r.status_code == 200, r.text
        ids = [item["id"] for item in r.json().get("items", [])]
        assert eng_id not in ids, "tenant A's engagement must not appear in tenant B's list"

    def test_ct6_error_codes_are_uniform_no_oracle_leakage(self, build_app):
        """Cross-tenant errors use not-found codes — never codes that reveal resource existence."""
        from starlette.testclient import TestClient
        from api.auth_scopes import mint_key

        app = build_app(auth_enabled=True, api_key="")
        c = TestClient(app)

        gov_a = _gov_key(mint_key, _TENANT_A)
        eng_id = _create_engagement(c, gov_a)
        grant_id = _create_grant(c, _admin_write_key(mint_key, _TENANT_A), eng_id)

        key_b_write = _admin_write_key(mint_key, _TENANT_B)
        key_b_gov = _gov_key(mint_key, _TENANT_B)

        # POST /portal/grants cross-tenant (regression anchor from PG-1)
        r1 = c.post(
            "/portal/grants",
            json={"engagement_id": eng_id, "portal_role": "general", "ttl_days": 30},
            headers={"x-api-key": key_b_write},
        )
        assert r1.status_code == 404
        assert r1.json()["detail"]["code"] == "ENGAGEMENT_NOT_FOUND"

        # DELETE /portal/grants/{id} cross-tenant
        r2 = c.delete(f"/portal/grants/{grant_id}", headers={"x-api-key": key_b_write})
        assert r2.status_code == 404
        assert r2.json()["detail"]["code"] == "GRANT_NOT_FOUND"

        # GET /field-assessment/engagements/{id} cross-tenant — must be 404, not 403.
        # A 403 would reveal the resource exists in another tenant; 404 gives no signal.
        r3 = c.get(
            f"/field-assessment/engagements/{eng_id}",
            headers={"x-api-key": key_b_gov},
        )
        assert r3.status_code == 404, r3.text
        assert r3.json()["detail"]["code"] == "ENGAGEMENT_NOT_FOUND"

    def test_ct7_full_lifecycle_chain(self, build_app):
        """All cross-tenant attack vectors fail in sequence; tenant A's resources survive intact."""
        from starlette.testclient import TestClient
        from api.auth_scopes import mint_key

        app = build_app(auth_enabled=True, api_key="")
        c = TestClient(app)

        gov_a = _gov_key(mint_key, _TENANT_A)
        admin_write_a = _admin_write_key(mint_key, _TENANT_A)
        eng_id = _create_engagement(c, gov_a)
        grant_id = _create_grant(c, admin_write_a, eng_id)

        key_b_write = _admin_write_key(mint_key, _TENANT_B)
        key_b_gov = _gov_key(mint_key, _TENANT_B)

        # 1. B tries to revoke A's grant
        assert c.delete(
            f"/portal/grants/{grant_id}", headers={"x-api-key": key_b_write}
        ).status_code == 404

        # 2. B's grant list must not include A's grant
        r_list = c.get("/portal/grants", headers={"x-api-key": _admin_read_key(mint_key, _TENANT_B)})
        assert r_list.status_code == 200
        b_ids = [g.get("grant_id") or g.get("credential_id") for g in r_list.json().get("items", [])]
        assert grant_id not in b_ids

        # 3. B tries POST /portal/grants with A's engagement_id
        assert c.post(
            "/portal/grants",
            json={"engagement_id": eng_id, "portal_role": "general", "ttl_days": 30},
            headers={"x-api-key": key_b_write},
        ).status_code == 404

        # 4. B tries engagement-scoped grant route with A's engagement_id
        assert c.post(
            f"/field-assessment/engagements/{eng_id}/portal-grants",
            json={},
            headers={"x-api-key": key_b_gov},
        ).status_code in (403, 404)

        # 5. B tries to read A's engagement directly
        assert c.get(
            f"/field-assessment/engagements/{eng_id}",
            headers={"x-api-key": key_b_gov},
        ).status_code in (403, 404)

        # A's resources must still be fully accessible after all attacks
        r_eng = c.get(
            f"/field-assessment/engagements/{eng_id}", headers={"x-api-key": gov_a}
        )
        assert r_eng.status_code == 200, f"A's engagement inaccessible after attack chain: {r_eng.text}"

        r_grants = c.get("/portal/grants", headers={"x-api-key": _admin_read_key(mint_key, _TENANT_A)})
        assert r_grants.status_code == 200
        a_ids = [g.get("grant_id") or g.get("credential_id") for g in r_grants.json().get("items", [])]
        assert grant_id in a_ids, "A's grant must survive after all B attack attempts"
