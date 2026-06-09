"""Tests for admin identity governance routes (PR4).

These tests exercise all 13 routes using a fresh SQLite database via the
standard conftest `build_app` fixture. Auth is enabled; all requests use
tenant-scoped keys minted after DB init (via mint_key). Wrong-tenant tests
verify 403 for cross-tenant access.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from api.auth_scopes import mint_key

TENANT = "test-tenant-identity-001"


@pytest.fixture
def client(build_app):
    # Disable the global bypass key so mint_key tenant binding is enforced
    app = build_app(auth_enabled=True, api_key="")
    rw_key = mint_key("admin:read", "admin:write", tenant_id=TENANT, ttl_seconds=3600)
    return TestClient(app), {"x-api-key": rw_key}


# ── Config routes ─────────────────────────────────────────────────────────────


def test_get_config_not_configured_returns_200(client) -> None:
    c, headers = client
    r = c.get(f"/admin/identity/tenants/{TENANT}/config", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["tenant_id"] == TENANT
    assert body["configured"] is False


def test_upsert_config_creates_new(build_app) -> None:
    tenant = "tenant-upsert-create-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    payload = {
        "identity_mode": "managed",
        "provider": "auth0",
        "sso_enforced": False,
    }
    r = c.put(f"/admin/identity/tenants/{tenant}/config", json=payload, headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["identity_mode"] == "managed"
    assert body["provider"] == "auth0"
    assert body["tenant_id"] == tenant


def test_upsert_config_updates_existing(build_app) -> None:
    tenant = "tenant-upsert-update-02"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers=headers,
    )
    payload2 = {"identity_mode": "sso", "provider": "auth0", "sso_enforced": True}
    r = c.put(
        f"/admin/identity/tenants/{tenant}/config", json=payload2, headers=headers
    )
    assert r.status_code == 200
    body = r.json()
    assert body["identity_mode"] == "sso"
    assert body["sso_enforced"] is True


def test_upsert_config_syncs_providers_on_update(build_app) -> None:
    """BLOCKER 2: provider records must be replaced on update, not left stale."""
    tenant = "tenant-blocker2-sync"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={
            "identity_mode": "managed",
            "provider": "auth0",
            "auth0_organization_id": "org-old",
        },
        headers=headers,
    )
    r = c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={
            "identity_mode": "managed",
            "provider": "auth0",
            "auth0_organization_id": "org-new",
        },
        headers=headers,
    )
    assert r.status_code == 200
    full = c.get(f"/admin/identity/tenants/{tenant}/config", headers=headers).json()
    assert len(full["providers"]) == 1
    assert full["providers"][0]["organization_id"] == "org-new"


def test_upsert_config_invalid_mode_422(build_app) -> None:
    tenant = "tenant-invalid-mode-03"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    r = c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "bogus_mode"},
        headers={"x-api-key": key},
    )
    assert r.status_code == 422


def test_get_config_after_create_includes_providers(build_app) -> None:
    tenant = "tenant-config-read-04"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers=headers,
    )
    r = c.get(f"/admin/identity/tenants/{tenant}/config", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["configured"] is True
    assert isinstance(body["providers"], list)
    assert len(body["providers"]) >= 1


# ── Readiness route ────────────────────────────────────────────────────────────


def test_readiness_no_config_returns_not_ready(build_app) -> None:
    tenant = f"{TENANT}-readiness"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    r = c.get(f"/admin/identity/tenants/{tenant}/readiness", headers={"x-api-key": key})
    assert r.status_code == 200
    body = r.json()
    assert body["ready"] is False
    assert body["status"] == "not_configured"
    assert isinstance(body["checks"], list)
    assert isinstance(body["evidence"], list)


def test_readiness_with_config_has_evidence(build_app) -> None:
    tenant = "tenant-readiness-05"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers=headers,
    )
    r = c.get(f"/admin/identity/tenants/{tenant}/readiness", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert "evidence" in body
    assert len(body["evidence"]) > 0
    assert all("label" in ev for ev in body["evidence"])


# ── Invitation routes ──────────────────────────────────────────────────────────


def test_list_invitations_empty(build_app) -> None:
    tenant = f"{TENANT}-inv"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    r = c.get(
        f"/admin/identity/tenants/{tenant}/invitations", headers={"x-api-key": key}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["invitations"] == []


def test_create_invitation_requires_config(build_app) -> None:
    tenant = "tenant-no-config-inv-06"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    r = c.post(
        f"/admin/identity/tenants/{tenant}/invitations",
        json={"email": "user@example.com", "role": "user"},
        headers={"x-api-key": key},
    )
    assert r.status_code == 404


def test_create_and_list_invitation(build_app) -> None:
    tenant = "tenant-create-inv-07"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers=headers,
    )
    r = c.post(
        f"/admin/identity/tenants/{tenant}/invitations",
        json={"email": "alice@example.com", "role": "user", "identity_type": "human"},
        headers=headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["email"] == "alice@example.com"
    assert body["status"] == "pending"
    assert body["identity_type"] == "human"
    inv_id = body["id"]

    r2 = c.get(f"/admin/identity/tenants/{tenant}/invitations", headers=headers)
    assert r2.status_code == 200
    ids = [i["id"] for i in r2.json()["invitations"]]
    assert inv_id in ids


def test_invitation_identity_type_persisted(build_app) -> None:
    """FIX 3: identity_type must survive the round-trip to DB."""
    tenant = "tenant-itype-persist"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers=headers,
    )
    for itype in ("service", "agent", "workload"):
        r = c.post(
            f"/admin/identity/tenants/{tenant}/invitations",
            json={"email": f"{itype}@example.com", "identity_type": itype},
            headers=headers,
        )
        assert r.status_code == 200, r.text
        assert r.json()["identity_type"] == itype

    # Verify list also returns identity_type
    listed = c.get(
        f"/admin/identity/tenants/{tenant}/invitations", headers=headers
    ).json()
    found_types = {i["identity_type"] for i in listed["invitations"]}
    assert {"service", "agent", "workload"}.issubset(found_types)


def test_create_invitation_invalid_identity_type_422(build_app) -> None:
    tenant = "tenant-inv-itype-08"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers=headers,
    )
    r = c.post(
        f"/admin/identity/tenants/{tenant}/invitations",
        json={"email": "x@y.com", "identity_type": "robot"},
        headers=headers,
    )
    assert r.status_code == 422


def test_revoke_invitation(build_app) -> None:
    tenant = "tenant-revoke-09"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers=headers,
    )
    inv_r = c.post(
        f"/admin/identity/tenants/{tenant}/invitations",
        json={"email": "bob@example.com", "role": "user"},
        headers=headers,
    )
    inv_id = inv_r.json()["id"]
    r = c.post(f"/admin/identity/invitations/{inv_id}/revoke", headers=headers)
    assert r.status_code == 200
    assert r.json()["status"] == "revoked"


def test_revoke_nonexistent_invitation_404(build_app) -> None:
    tenant = f"{TENANT}-revoke-404"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    r = c.post(
        "/admin/identity/invitations/does-not-exist/revoke",
        headers={"x-api-key": key},
    )
    assert r.status_code == 404


def test_resend_invitation_from_pending(build_app) -> None:
    tenant = "tenant-resend-10"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers=headers,
    )
    inv_r = c.post(
        f"/admin/identity/tenants/{tenant}/invitations",
        json={"email": "carol@example.com", "role": "user"},
        headers=headers,
    )
    inv_id = inv_r.json()["id"]
    r = c.post(f"/admin/identity/invitations/{inv_id}/resend", headers=headers)
    assert r.status_code == 200
    assert r.json()["status"] == "pending"


def test_resend_refreshes_expires_at(build_app) -> None:
    """FIX 4: resend must update expires_at so the invitation is not dead on arrival."""
    import datetime as dt

    tenant = "tenant-resend-expiry"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers=headers,
    )
    inv_r = c.post(
        f"/admin/identity/tenants/{tenant}/invitations",
        json={"email": "fix4@example.com", "role": "user"},
        headers=headers,
    )
    original_expires = inv_r.json()["expires_at"]
    inv_id = inv_r.json()["id"]

    r = c.post(f"/admin/identity/invitations/{inv_id}/resend", headers=headers)
    assert r.status_code == 200

    # Fetch invitation list to verify expires_at was updated
    listed = c.get(
        f"/admin/identity/tenants/{tenant}/invitations", headers=headers
    ).json()
    inv_data = next(i for i in listed["invitations"] if i["id"] == inv_id)
    # expires_at should be non-null (refreshed)
    assert inv_data["expires_at"] is not None
    # It should be at least as recent as original (resend sets new future expiry)
    orig_dt = dt.datetime.fromisoformat(original_expires.replace("Z", "+00:00"))
    new_dt = dt.datetime.fromisoformat(inv_data["expires_at"].replace("Z", "+00:00"))
    assert new_dt >= orig_dt


# ── Governance routes ─────────────────────────────────────────────────────────


def test_governance_score_no_config(build_app) -> None:
    tenant = f"{TENANT}-score"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-score", headers={"x-api-key": key}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["score"] == 0
    assert body["grade"] == "F"


def test_governance_score_with_config(build_app) -> None:
    tenant = "tenant-score-11"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers=headers,
    )
    r = c.get(f"/admin/identity/tenants/{tenant}/governance-score", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert "score" in body
    assert "dimensions" in body
    assert "percent" in body
    assert isinstance(body["dimensions"], dict)


def test_drift_no_config(build_app) -> None:
    tenant = f"{TENANT}-drift"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    r = c.get(f"/admin/identity/tenants/{tenant}/drift", headers={"x-api-key": key})
    assert r.status_code == 200
    body = r.json()
    assert body["drift_detected"] is True
    assert any(i["type"] == "missing_config" for i in body["items"])


def test_drift_clean_config(build_app) -> None:
    tenant = "tenant-drift-clean-12"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers=headers,
    )
    r = c.get(f"/admin/identity/tenants/{tenant}/drift", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body["items"], list)


def test_audit_summary_empty(build_app) -> None:
    tenant = f"{TENANT}-audit"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    r = c.get(
        f"/admin/identity/tenants/{tenant}/audit-summary", headers={"x-api-key": key}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["total_events"] == 0
    assert body["recent"] == []


def test_audit_summary_after_config_create(build_app) -> None:
    tenant = "tenant-audit-13"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers=headers,
    )
    r = c.get(f"/admin/identity/tenants/{tenant}/audit-summary", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["total_events"] >= 1
    assert "tenant.identity_config.created" in body["by_type"]


def test_timeline_empty(build_app) -> None:
    tenant = f"{TENANT}-tl"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    r = c.get(f"/admin/identity/tenants/{tenant}/timeline", headers={"x-api-key": key})
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 0
    assert body["events"] == []


def test_timeline_limit_validation(build_app) -> None:
    tenant = f"{TENANT}-tl-lim"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    r = c.get(
        f"/admin/identity/tenants/{tenant}/timeline?limit=0",
        headers={"x-api-key": key},
    )
    assert r.status_code == 422


def test_readiness_history_empty(build_app) -> None:
    tenant = f"{TENANT}-rh"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    r = c.get(
        f"/admin/identity/tenants/{tenant}/readiness-history",
        headers={"x-api-key": key},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["transitions"] == []


def test_readiness_history_after_config(build_app) -> None:
    tenant = "tenant-rh-14"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers=headers,
    )
    r = c.get(f"/admin/identity/tenants/{tenant}/readiness-history", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert len(body["transitions"]) >= 1
    assert body["transitions"][0]["event_type"] == "tenant.identity_config.created"


def test_risk_no_config(build_app) -> None:
    tenant = f"{TENANT}-risk"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    r = c.get(f"/admin/identity/tenants/{tenant}/risk", headers={"x-api-key": key})
    assert r.status_code == 200
    body = r.json()
    assert body["risk_score"] > 0
    assert any(f["factor"] == "no_identity_config" for f in body["factors"])


def test_risk_with_config(build_app) -> None:
    tenant = "tenant-risk-15"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0", "sso_enforced": False},
        headers=headers,
    )
    r = c.get(f"/admin/identity/tenants/{tenant}/risk", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert "risk_score" in body
    assert body["risk_band"] in {"low", "medium", "high", "critical"}


def test_routes_require_auth(build_app) -> None:
    app = build_app(auth_enabled=True)
    c = TestClient(app)
    r = c.get(f"/admin/identity/tenants/{TENANT}/config")
    assert r.status_code in {401, 403}


# ── Tenant isolation (BLOCKER 1) ───────────────────────────────────────────────


def test_tenant_a_cannot_read_tenant_b_config(build_app) -> None:
    """Key bound to tenant-A must not access tenant-B paths."""
    app = build_app(auth_enabled=True, api_key="")
    key_a = mint_key(
        "admin:read", "admin:write", tenant_id="iso-tenant-a", ttl_seconds=3600
    )
    key_b = mint_key(
        "admin:read", "admin:write", tenant_id="iso-tenant-b", ttl_seconds=3600
    )
    c = TestClient(app)

    # Set up tenant-B with config
    c.put(
        "/admin/identity/tenants/iso-tenant-b/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key_b},
    )

    # Tenant-A key tries to read tenant-B's config → must be rejected
    r = c.get(
        "/admin/identity/tenants/iso-tenant-b/config", headers={"x-api-key": key_a}
    )
    assert r.status_code in {400, 403}


def test_tenant_a_cannot_write_tenant_b_config(build_app) -> None:
    app = build_app(auth_enabled=True, api_key="")
    key_a = mint_key("admin:read", "admin:write", tenant_id="iso-w-a", ttl_seconds=3600)
    c = TestClient(app)
    r = c.put(
        "/admin/identity/tenants/iso-w-b/config",
        json={"identity_mode": "managed"},
        headers={"x-api-key": key_a},
    )
    assert r.status_code in {400, 403}


def test_tenant_a_cannot_list_tenant_b_invitations(build_app) -> None:
    app = build_app(auth_enabled=True, api_key="")
    key_a = mint_key("admin:read", tenant_id="iso-inv-a", ttl_seconds=3600)
    c = TestClient(app)
    r = c.get(
        "/admin/identity/tenants/iso-inv-b/invitations", headers={"x-api-key": key_a}
    )
    assert r.status_code in {400, 403}


def test_tenant_a_cannot_create_invitation_for_tenant_b(build_app) -> None:
    app = build_app(auth_enabled=True, api_key="")
    key_a = mint_key("admin:write", tenant_id="iso-cinv-a", ttl_seconds=3600)
    c = TestClient(app)
    r = c.post(
        "/admin/identity/tenants/iso-cinv-b/invitations",
        json={"email": "x@example.com"},
        headers={"x-api-key": key_a},
    )
    assert r.status_code in {400, 403}


def test_tenant_a_cannot_revoke_tenant_b_invitation(build_app) -> None:
    """BLOCKER 1: after lookup, bind_tenant_id enforces caller matches invitation tenant."""
    app = build_app(auth_enabled=True, api_key="")
    key_b = mint_key(
        "admin:read", "admin:write", tenant_id="iso-rev-b", ttl_seconds=3600
    )
    key_a = mint_key("admin:write", tenant_id="iso-rev-a", ttl_seconds=3600)
    c = TestClient(app)

    # Create invitation owned by tenant-B
    c.put(
        "/admin/identity/tenants/iso-rev-b/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key_b},
    )
    inv_r = c.post(
        "/admin/identity/tenants/iso-rev-b/invitations",
        json={"email": "victim@example.com"},
        headers={"x-api-key": key_b},
    )
    inv_id = inv_r.json()["id"]

    # Tenant-A key tries to revoke tenant-B's invitation → must be rejected
    r = c.post(
        f"/admin/identity/invitations/{inv_id}/revoke", headers={"x-api-key": key_a}
    )
    assert r.status_code in {400, 403}


def test_tenant_a_cannot_resend_tenant_b_invitation(build_app) -> None:
    app = build_app(auth_enabled=True, api_key="")
    key_b = mint_key(
        "admin:read", "admin:write", tenant_id="iso-res-b", ttl_seconds=3600
    )
    key_a = mint_key("admin:write", tenant_id="iso-res-a", ttl_seconds=3600)
    c = TestClient(app)

    c.put(
        "/admin/identity/tenants/iso-res-b/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key_b},
    )
    inv_r = c.post(
        "/admin/identity/tenants/iso-res-b/invitations",
        json={"email": "victim2@example.com"},
        headers={"x-api-key": key_b},
    )
    inv_id = inv_r.json()["id"]

    r = c.post(
        f"/admin/identity/invitations/{inv_id}/resend", headers={"x-api-key": key_a}
    )
    assert r.status_code in {400, 403}


def test_tenant_a_cannot_read_tenant_b_timeline(build_app) -> None:
    app = build_app(auth_enabled=True, api_key="")
    key_a = mint_key("admin:read", tenant_id="iso-tl-a", ttl_seconds=3600)
    c = TestClient(app)
    r = c.get("/admin/identity/tenants/iso-tl-b/timeline", headers={"x-api-key": key_a})
    assert r.status_code in {400, 403}


def test_tenant_a_cannot_read_tenant_b_risk(build_app) -> None:
    app = build_app(auth_enabled=True, api_key="")
    key_a = mint_key("admin:read", tenant_id="iso-risk-a", ttl_seconds=3600)
    c = TestClient(app)
    r = c.get("/admin/identity/tenants/iso-risk-b/risk", headers={"x-api-key": key_a})
    assert r.status_code in {400, 403}
