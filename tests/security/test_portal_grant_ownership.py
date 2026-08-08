"""H0-PR4 — Portal Grant Ownership Enforcement.

Proves the invariants stated in the H0-PR4 authority contract:

  PG-1  Forged engagement_id: tenant B key + tenant A engagement → 404
  PG-2  Body client_id field: schema forbids it → 422
  PG-3  client_id is server-derived from eng.client_name, never from request body
  PG-4  Valid grant creation returns portal_login_url (email delivery compatible)
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_AUTH_ENABLED", "1")

_TENANT_A = "h0pr4-own-a-01"
_TENANT_B = "h0pr4-own-b-01"

_ENG_BODY: dict[str, str | None | dict[str, object]] = {
    "client_name": "Acme Client Co",
    "client_domain": "acme.example.com",
    "assessor_id": "assessor-h0pr4",
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


def _create_engagement(client, gov_key: str) -> str:
    r = client.post(
        "/field-assessment/engagements", json=_ENG_BODY, headers={"x-api-key": gov_key}
    )
    assert r.status_code == 201, f"engagement seed failed: {r.text}"
    return r.json()["id"]


class TestPortalGrantOwnership:
    def test_pg1_forged_engagement_id_returns_404(self, build_app):
        """Tenant B key cannot create a grant for tenant A's engagement → 404 ENGAGEMENT_NOT_FOUND."""
        from starlette.testclient import TestClient
        from api.auth_scopes import mint_key

        app = build_app(auth_enabled=True, api_key="")
        c = TestClient(app)

        gov_a = _gov_key(mint_key, _TENANT_A)
        eng_id = _create_engagement(c, gov_a)

        # Tenant B attempts to issue a portal grant for tenant A's engagement
        key_b = _admin_write_key(mint_key, _TENANT_B)
        r = c.post(
            "/portal/grants",
            json={"engagement_id": eng_id, "portal_role": "general", "ttl_days": 30},
            headers={"x-api-key": key_b},
        )
        assert r.status_code == 404, r.text
        body = r.json()
        assert body["detail"]["code"] == "ENGAGEMENT_NOT_FOUND"

    def test_pg2_body_client_id_field_rejected(self, build_app):
        """Sending client_id in the body is rejected by schema → 422 (extra='forbid')."""
        from starlette.testclient import TestClient
        from api.auth_scopes import mint_key

        app = build_app(auth_enabled=True, api_key="")
        c = TestClient(app)

        gov_a = _gov_key(mint_key, _TENANT_A)
        eng_id = _create_engagement(c, gov_a)
        key_a = _admin_write_key(mint_key, _TENANT_A)

        r = c.post(
            "/portal/grants",
            # client_id is a forbidden extra field
            json={
                "client_id": "attacker-supplied",
                "engagement_id": eng_id,
                "portal_role": "general",
                "ttl_days": 30,
            },
            headers={"x-api-key": key_a},
        )
        assert r.status_code == 422, r.text

    def test_pg3_client_id_derived_from_engagement_record(self, build_app):
        """Grant client_id equals eng.client_name — never any caller-supplied value."""
        from starlette.testclient import TestClient
        from api.auth_scopes import mint_key

        app = build_app(auth_enabled=True, api_key="")
        c = TestClient(app)

        gov_a = _gov_key(mint_key, _TENANT_A)
        eng_id = _create_engagement(c, gov_a)
        key_a = _admin_write_key(mint_key, _TENANT_A)

        r = c.post(
            "/portal/grants",
            json={"engagement_id": eng_id, "portal_role": "general", "ttl_days": 30},
            headers={"x-api-key": key_a},
        )
        assert r.status_code == 201, r.text
        body = r.json()
        # client_id must match the engagement's client_name, not any attacker-supplied value
        assert body["client_id"] == _ENG_BODY["client_name"]
        assert body["engagement_id"] == eng_id

    def test_pg4_valid_grant_has_portal_login_url(self, build_app):
        """Successful grant creation returns portal_login_url — email delivery path intact."""
        from starlette.testclient import TestClient
        from api.auth_scopes import mint_key

        app = build_app(auth_enabled=True, api_key="")
        c = TestClient(app)

        gov_a = _gov_key(mint_key, _TENANT_A)
        eng_id = _create_engagement(c, gov_a)
        key_a = _admin_write_key(mint_key, _TENANT_A)

        r = c.post(
            "/portal/grants",
            json={"engagement_id": eng_id, "portal_role": "executive", "ttl_days": 14},
            headers={"x-api-key": key_a},
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert "raw_secret" in body
        assert "portal_login_url" in body
        assert body["portal_login_url"].startswith("/login")
        assert body["portal_role"] == "executive"
        assert "expires_at" in body
