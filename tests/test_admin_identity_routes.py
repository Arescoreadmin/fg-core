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


# ── Helpers for new-route tests ───────────────────────────────────────────────


def _setup_tenant(c, tenant, key):
    """Provision config and return a pending invitation id."""
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={
            "identity_mode": "managed",
            "provider": "auth0",
            "capability_flags": {"require_approval_non_human": True},
        },
        headers={"x-api-key": key},
    )
    r = c.post(
        f"/admin/identity/tenants/{tenant}/invitations",
        json={"email": "agent@example.com", "role": "user", "identity_type": "agent"},
        headers={"x-api-key": key},
    )
    assert r.status_code in {200, 201}
    return r.json()["id"]


# ── Wrong-tenant isolation for 8 new routes ───────────────────────────────────


def test_tenant_a_cannot_read_tenant_b_policy_violations(build_app) -> None:
    app = build_app(auth_enabled=True, api_key="")
    key_a = mint_key("admin:read", tenant_id="iso-pv-a", ttl_seconds=3600)
    c = TestClient(app)
    r = c.get(
        "/admin/identity/tenants/iso-pv-b/policy-violations",
        headers={"x-api-key": key_a},
    )
    assert r.status_code in {400, 403}


def test_tenant_a_cannot_read_tenant_b_approval_queue(build_app) -> None:
    app = build_app(auth_enabled=True, api_key="")
    key_a = mint_key("admin:read", tenant_id="iso-aq-a", ttl_seconds=3600)
    c = TestClient(app)
    r = c.get(
        "/admin/identity/tenants/iso-aq-b/approval-queue", headers={"x-api-key": key_a}
    )
    assert r.status_code in {400, 403}


def test_tenant_a_cannot_read_tenant_b_snapshots(build_app) -> None:
    app = build_app(auth_enabled=True, api_key="")
    key_a = mint_key("admin:read", tenant_id="iso-snap-a", ttl_seconds=3600)
    c = TestClient(app)
    r = c.get(
        "/admin/identity/tenants/iso-snap-b/governance-snapshots",
        headers={"x-api-key": key_a},
    )
    assert r.status_code in {400, 403}


def test_tenant_a_cannot_write_tenant_b_snapshot(build_app) -> None:
    app = build_app(auth_enabled=True, api_key="")
    key_a = mint_key(
        "admin:read", "admin:write", tenant_id="iso-wsnap-a", ttl_seconds=3600
    )
    c = TestClient(app)
    r = c.post(
        "/admin/identity/tenants/iso-wsnap-b/governance-snapshots",
        headers={"x-api-key": key_a},
    )
    assert r.status_code in {400, 403}


def test_tenant_a_cannot_read_tenant_b_recommendations(build_app) -> None:
    app = build_app(auth_enabled=True, api_key="")
    key_a = mint_key("admin:read", tenant_id="iso-rec-a", ttl_seconds=3600)
    c = TestClient(app)
    r = c.get(
        "/admin/identity/tenants/iso-rec-b/recommendations",
        headers={"x-api-key": key_a},
    )
    assert r.status_code in {400, 403}


def test_tenant_a_cannot_approve_tenant_b_invitation(build_app) -> None:
    app = build_app(auth_enabled=True, api_key="")
    key_b = mint_key(
        "admin:read", "admin:write", tenant_id="iso-app-b", ttl_seconds=3600
    )
    key_a = mint_key("admin:write", tenant_id="iso-app-a", ttl_seconds=3600)
    c = TestClient(app)
    inv_id = _setup_tenant(c, "iso-app-b", key_b)
    # request-approval first so state == pending
    c.post(
        f"/admin/identity/invitations/{inv_id}/request-approval",
        json={},
        headers={"x-api-key": key_b},
    )
    r = c.post(
        f"/admin/identity/invitations/{inv_id}/approve",
        json={},
        headers={"x-api-key": key_a},
    )
    assert r.status_code in {400, 403}


def test_tenant_a_cannot_reject_tenant_b_invitation(build_app) -> None:
    app = build_app(auth_enabled=True, api_key="")
    key_b = mint_key(
        "admin:read", "admin:write", tenant_id="iso-rej-b", ttl_seconds=3600
    )
    key_a = mint_key("admin:write", tenant_id="iso-rej-a", ttl_seconds=3600)
    c = TestClient(app)
    inv_id = _setup_tenant(c, "iso-rej-b", key_b)
    c.post(
        f"/admin/identity/invitations/{inv_id}/request-approval",
        json={},
        headers={"x-api-key": key_b},
    )
    r = c.post(
        f"/admin/identity/invitations/{inv_id}/reject-approval",
        json={},
        headers={"x-api-key": key_a},
    )
    assert r.status_code in {400, 403}


def test_tenant_a_cannot_request_approval_for_tenant_b(build_app) -> None:
    app = build_app(auth_enabled=True, api_key="")
    key_b = mint_key(
        "admin:read", "admin:write", tenant_id="iso-req-b", ttl_seconds=3600
    )
    key_a = mint_key("admin:write", tenant_id="iso-req-a", ttl_seconds=3600)
    c = TestClient(app)
    inv_id = _setup_tenant(c, "iso-req-b", key_b)
    r = c.post(
        f"/admin/identity/invitations/{inv_id}/request-approval",
        json={},
        headers={"x-api-key": key_a},
    )
    assert r.status_code in {400, 403}


# ── Approval state machine ────────────────────────────────────────────────────


def test_approval_flow_request_then_approve(build_app) -> None:
    tenant = "sm-approve-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    inv_id = _setup_tenant(c, tenant, key)

    # request approval
    r = c.post(
        f"/admin/identity/invitations/{inv_id}/request-approval",
        json={"reason": "needs review"},
        headers={"x-api-key": key},
    )
    assert r.status_code == 200
    assert r.json()["approval_state"] == "pending"

    # approve
    r = c.post(
        f"/admin/identity/invitations/{inv_id}/approve",
        json={"approver_user_id": "admin-1"},
        headers={"x-api-key": key},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["approval_state"] == "approved"
    assert body["approved_by_user_id"] == "admin-1"
    assert body["approved_at"] is not None

    # invitation list reflects state
    r = c.get(
        f"/admin/identity/tenants/{tenant}/invitations", headers={"x-api-key": key}
    )
    inv = next(i for i in r.json()["invitations"] if i["id"] == inv_id)
    assert inv["approval_state"] == "approved"


def test_approval_flow_request_then_reject(build_app) -> None:
    tenant = "sm-reject-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    inv_id = _setup_tenant(c, tenant, key)

    c.post(
        f"/admin/identity/invitations/{inv_id}/request-approval",
        json={},
        headers={"x-api-key": key},
    )
    r = c.post(
        f"/admin/identity/invitations/{inv_id}/reject-approval",
        json={"reason": "policy violation"},
        headers={"x-api-key": key},
    )
    assert r.status_code == 200
    assert r.json()["approval_state"] == "rejected"
    assert r.json()["reason"] == "policy violation"


def test_approve_twice_is_409(build_app) -> None:
    tenant = "sm-dbl-approve-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    inv_id = _setup_tenant(c, tenant, key)

    c.post(
        f"/admin/identity/invitations/{inv_id}/request-approval",
        json={},
        headers={"x-api-key": key},
    )
    c.post(
        f"/admin/identity/invitations/{inv_id}/approve",
        json={},
        headers={"x-api-key": key},
    )
    r = c.post(
        f"/admin/identity/invitations/{inv_id}/approve",
        json={},
        headers={"x-api-key": key},
    )
    assert r.status_code == 409


def test_approve_after_reject_is_409(build_app) -> None:
    tenant = "sm-app-after-rej-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    inv_id = _setup_tenant(c, tenant, key)

    c.post(
        f"/admin/identity/invitations/{inv_id}/request-approval",
        json={},
        headers={"x-api-key": key},
    )
    c.post(
        f"/admin/identity/invitations/{inv_id}/reject-approval",
        json={},
        headers={"x-api-key": key},
    )
    r = c.post(
        f"/admin/identity/invitations/{inv_id}/approve",
        json={},
        headers={"x-api-key": key},
    )
    assert r.status_code == 409


def test_reject_twice_is_409(build_app) -> None:
    tenant = "sm-dbl-rej-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    inv_id = _setup_tenant(c, tenant, key)

    c.post(
        f"/admin/identity/invitations/{inv_id}/request-approval",
        json={},
        headers={"x-api-key": key},
    )
    c.post(
        f"/admin/identity/invitations/{inv_id}/reject-approval",
        json={},
        headers={"x-api-key": key},
    )
    r = c.post(
        f"/admin/identity/invitations/{inv_id}/reject-approval",
        json={},
        headers={"x-api-key": key},
    )
    assert r.status_code == 409


def test_cannot_approve_revoked_invitation(build_app) -> None:
    tenant = "sm-rev-no-approve-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    inv_id = _setup_tenant(c, tenant, key)

    c.post(
        f"/admin/identity/invitations/{inv_id}/request-approval",
        json={},
        headers={"x-api-key": key},
    )
    c.post(f"/admin/identity/invitations/{inv_id}/revoke", headers={"x-api-key": key})
    r = c.post(
        f"/admin/identity/invitations/{inv_id}/approve",
        json={},
        headers={"x-api-key": key},
    )
    assert r.status_code == 409


# ── Approval queue ────────────────────────────────────────────────────────────


def test_approval_queue_returns_pending_only(build_app) -> None:
    tenant = "aq-queue-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)

    inv_id = _setup_tenant(c, tenant, key)
    c.post(
        f"/admin/identity/invitations/{inv_id}/request-approval",
        json={},
        headers={"x-api-key": key},
    )

    # Create a second invitation and approve it — should NOT appear in queue
    r2 = c.post(
        f"/admin/identity/tenants/{tenant}/invitations",
        json={"email": "svc@example.com", "role": "user", "identity_type": "service"},
        headers={"x-api-key": key},
    )
    inv_id2 = r2.json()["id"]
    c.post(
        f"/admin/identity/invitations/{inv_id2}/request-approval",
        json={},
        headers={"x-api-key": key},
    )
    c.post(
        f"/admin/identity/invitations/{inv_id2}/approve",
        json={},
        headers={"x-api-key": key},
    )

    r = c.get(
        f"/admin/identity/tenants/{tenant}/approval-queue", headers={"x-api-key": key}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["pending_count"] == 1
    ids = {i["id"] for i in body["items"]}
    assert inv_id in ids
    assert inv_id2 not in ids


# ── Governance snapshots ──────────────────────────────────────────────────────


def test_governance_snapshot_creates_row(build_app) -> None:
    tenant = "snap-create-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key},
    )

    r = c.post(
        f"/admin/identity/tenants/{tenant}/governance-snapshots",
        headers={"x-api-key": key},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["snapshot_id"] is not None
    assert body["tenant_id"] == tenant
    assert isinstance(body["score"], int)
    assert body["grade"] in {"A", "B", "C", "D", "F"}


def test_governance_snapshot_immutability(build_app) -> None:
    """Each POST creates a new snapshot row; old rows are never overwritten."""
    tenant = "snap-immut-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key},
    )

    r1 = c.post(
        f"/admin/identity/tenants/{tenant}/governance-snapshots",
        headers={"x-api-key": key},
    )
    r2 = c.post(
        f"/admin/identity/tenants/{tenant}/governance-snapshots",
        headers={"x-api-key": key},
    )
    assert r1.json()["snapshot_id"] != r2.json()["snapshot_id"]

    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-snapshots",
        headers={"x-api-key": key},
    )
    assert r.status_code == 200
    assert r.json()["snapshot_count"] == 2


def test_governance_snapshot_score_preserved(build_app) -> None:
    """Score written into a snapshot is returned unchanged on reads."""
    tenant = "snap-score-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key},
    )

    snap = c.post(
        f"/admin/identity/tenants/{tenant}/governance-snapshots",
        headers={"x-api-key": key},
    ).json()
    snap_id = snap["snapshot_id"]
    written_score = snap["score"]

    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-snapshots",
        headers={"x-api-key": key},
    )
    found = next(s for s in r.json()["snapshots"] if s["snapshot_id"] == snap_id)
    assert found["score"] == written_score
    assert found["percent"] == snap["percent"]
    assert found["grade"] == snap["grade"]


def test_governance_snapshots_empty_before_any_capture(build_app) -> None:
    tenant = "snap-empty-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key},
    )
    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-snapshots",
        headers={"x-api-key": key},
    )
    assert r.status_code == 200
    assert r.json()["snapshot_count"] == 0


# ── Recommendations ───────────────────────────────────────────────────────────


def test_recommendations_returns_valid_shape(build_app) -> None:
    tenant = "rec-shape-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key},
    )

    r = c.get(
        f"/admin/identity/tenants/{tenant}/recommendations", headers={"x-api-key": key}
    )
    assert r.status_code == 200
    body = r.json()
    assert "current_score" in body
    assert "recommendations" in body
    assert isinstance(body["recommendations"], list)


def test_recommendations_score_gain_matches_weight(build_app) -> None:
    """expected_score_gain for each recommendation must equal the dimension weight."""
    from api.admin_identity import _SCORE_WEIGHTS

    tenant = "rec-weight-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key},
    )

    r = c.get(
        f"/admin/identity/tenants/{tenant}/recommendations", headers={"x-api-key": key}
    )
    for rec in r.json()["recommendations"]:
        dim = rec["dimension"]
        assert rec["expected_score_gain"] == _SCORE_WEIGHTS[dim], (
            f"Recommendation for '{dim}' expected_score_gain={rec['expected_score_gain']} "
            f"but _SCORE_WEIGHTS['{dim}']={_SCORE_WEIGHTS[dim]}"
        )


def test_recommendations_only_for_failing_dimensions(build_app) -> None:
    """Passing dimensions must not produce recommendations."""
    tenant = "rec-only-fail-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key},
    )

    score_r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-score", headers={"x-api-key": key}
    )
    passing_dims = {k for k, v in score_r.json()["dimensions"].items() if v["pass"]}

    rec_r = c.get(
        f"/admin/identity/tenants/{tenant}/recommendations", headers={"x-api-key": key}
    )
    rec_dims = {r["dimension"] for r in rec_r.json()["recommendations"]}
    assert passing_dims.isdisjoint(rec_dims), (
        f"Recommendations produced for passing dimensions: {passing_dims & rec_dims}"
    )


def test_recommendations_projected_percent_is_plausible(build_app) -> None:
    tenant = "rec-proj-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key},
    )

    r = c.get(
        f"/admin/identity/tenants/{tenant}/recommendations", headers={"x-api-key": key}
    )
    body = r.json()
    assert body["projected_percent_if_all_applied"] >= body["current_percent"]
    assert body["projected_percent_if_all_applied"] <= 100.0


# ── Policy violations ─────────────────────────────────────────────────────────


def test_policy_violations_no_violations_on_clean_tenant(build_app) -> None:
    tenant = "pv-clean-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key},
    )
    c.post(
        f"/admin/identity/tenants/{tenant}/invitations",
        json={"email": "user@example.com", "role": "user", "identity_type": "human"},
        headers={"x-api-key": key},
    )

    r = c.get(
        f"/admin/identity/tenants/{tenant}/policy-violations",
        headers={"x-api-key": key},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["violation_count"] == 0
    assert body["violations"] == []


def test_policy_violations_detects_non_human_admin(build_app) -> None:
    tenant = "pv-nonhuman-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key},
    )
    c.post(
        f"/admin/identity/tenants/{tenant}/invitations",
        json={"email": "bot@example.com", "role": "admin", "identity_type": "agent"},
        headers={"x-api-key": key},
    )

    r = c.get(
        f"/admin/identity/tenants/{tenant}/policy-violations",
        headers={"x-api-key": key},
    )
    assert r.status_code == 200
    rules = [v["rule_id"] for v in r.json()["violations"]]
    assert "non_human_admin_role" in rules


def test_policy_violations_detects_unauthorized_domain(build_app) -> None:
    tenant = "pv-domain-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={
            "identity_mode": "managed",
            "provider": "auth0",
            "allowed_email_domains": ["corp.com"],
        },
        headers={"x-api-key": key},
    )
    c.post(
        f"/admin/identity/tenants/{tenant}/invitations",
        json={"email": "user@other.com", "role": "user", "identity_type": "human"},
        headers={"x-api-key": key},
    )

    r = c.get(
        f"/admin/identity/tenants/{tenant}/policy-violations",
        headers={"x-api-key": key},
    )
    rules = [v["rule_id"] for v in r.json()["violations"]]
    assert "unauthorized_domain" in rules


# ── Audit events for approval actions ─────────────────────────────────────────


def test_audit_events_emitted_for_approval_lifecycle(build_app) -> None:
    tenant = "aud-approval-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    inv_id = _setup_tenant(c, tenant, key)

    c.post(
        f"/admin/identity/invitations/{inv_id}/request-approval",
        json={},
        headers={"x-api-key": key},
    )
    c.post(
        f"/admin/identity/invitations/{inv_id}/approve",
        json={"approver_user_id": "u-1"},
        headers={"x-api-key": key},
    )

    r = c.get(
        f"/admin/identity/tenants/{tenant}/audit-summary", headers={"x-api-key": key}
    )
    events = set(r.json()["by_type"].keys())
    assert "tenant.invite.approval_requested" in events
    assert "tenant.invite.approved" in events


def test_audit_events_emitted_for_rejection(build_app) -> None:
    tenant = "aud-reject-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    inv_id = _setup_tenant(c, tenant, key)

    c.post(
        f"/admin/identity/invitations/{inv_id}/request-approval",
        json={},
        headers={"x-api-key": key},
    )
    c.post(
        f"/admin/identity/invitations/{inv_id}/reject-approval",
        json={"reason": "denied"},
        headers={"x-api-key": key},
    )

    r = c.get(
        f"/admin/identity/tenants/{tenant}/audit-summary", headers={"x-api-key": key}
    )
    events = set(r.json()["by_type"].keys())
    assert "tenant.invite.approval_rejected" in events


# ── Gap A: Governance Trend ───────────────────────────────────────────────────


def test_governance_trend_no_snapshots(build_app) -> None:
    tenant = "trend-empty-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key},
    )
    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-trend", headers={"x-api-key": key}
    )
    assert r.status_code == 200
    assert r.json()["has_trend"] is False


def test_governance_trend_with_two_snapshots(build_app) -> None:
    tenant = "trend-two-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key},
    )
    c.post(
        f"/admin/identity/tenants/{tenant}/governance-snapshots",
        headers={"x-api-key": key},
    )
    c.post(
        f"/admin/identity/tenants/{tenant}/governance-snapshots",
        headers={"x-api-key": key},
    )

    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-trend", headers={"x-api-key": key}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["has_trend"] is True
    assert body["grade_from"] is not None
    assert body["grade_to"] is not None
    assert isinstance(body["narrative"], list)
    assert isinstance(body["degraded"], list)
    assert isinstance(body["improved"], list)
    assert isinstance(body["stable_failing"], list)


def test_governance_trend_wrong_tenant(build_app) -> None:
    app = build_app(auth_enabled=True, api_key="")
    key_a = mint_key("admin:read", tenant_id="iso-trend-a", ttl_seconds=3600)
    c = TestClient(app)
    r = c.get(
        "/admin/identity/tenants/iso-trend-b/governance-trend",
        headers={"x-api-key": key_a},
    )
    assert r.status_code in {400, 403}


# ── Gap B: Governance Forecast ────────────────────────────────────────────────


def test_governance_forecast_no_snapshots(build_app) -> None:
    tenant = "fc-empty-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key},
    )
    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-forecast",
        headers={"x-api-key": key},
    )
    assert r.status_code == 200
    assert r.json()["has_forecast"] is False


def test_governance_forecast_with_snapshots(build_app) -> None:
    tenant = "fc-two-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key},
    )
    c.post(
        f"/admin/identity/tenants/{tenant}/governance-snapshots",
        headers={"x-api-key": key},
    )
    c.post(
        f"/admin/identity/tenants/{tenant}/governance-snapshots",
        headers={"x-api-key": key},
    )

    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-forecast",
        headers={"x-api-key": key},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["has_forecast"] is True
    assert body["projected_percent"] is not None
    assert 0.0 <= body["projected_percent"] <= 100.0
    assert body["projected_grade"] in {"A", "B", "C", "D", "F"}
    assert body["trend_direction"] in {"stable", "improving", "declining"}


def test_governance_forecast_wrong_tenant(build_app) -> None:
    app = build_app(auth_enabled=True, api_key="")
    key_a = mint_key("admin:read", tenant_id="iso-fc-a", ttl_seconds=3600)
    c = TestClient(app)
    r = c.get(
        "/admin/identity/tenants/iso-fc-b/governance-forecast",
        headers={"x-api-key": key_a},
    )
    assert r.status_code in {400, 403}


# ── Gap C: Governance SLA ─────────────────────────────────────────────────────


def test_governance_sla_clean_tenant(build_app) -> None:
    tenant = "sla-clean-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key},
    )
    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-sla", headers={"x-api-key": key}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["total_open_items"] == 0
    assert body["items"] == []


def test_governance_sla_pending_approval_appears(build_app) -> None:
    tenant = "sla-pending-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    _setup_tenant(c, tenant, key)
    # invitation was created with approval_required=True → approval_state='pending'
    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-sla", headers={"x-api-key": key}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["total_open_items"] >= 1
    item_types = [i["type"] for i in body["items"]]
    assert "pending_approval" in item_types


def test_governance_sla_item_has_sla_fields(build_app) -> None:
    tenant = "sla-fields-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    _setup_tenant(c, tenant, key)
    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-sla", headers={"x-api-key": key}
    )
    for item in r.json()["items"]:
        assert "sla_days" in item
        assert "sla_status" in item
        assert item["sla_status"] in {"on_track", "at_risk", "breached", "unknown"}


def test_governance_sla_policy_violation_surfaced(build_app) -> None:
    tenant = "sla-pv-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={
            "identity_mode": "managed",
            "provider": "auth0",
            "allowed_email_domains": ["corp.com"],
        },
        headers={"x-api-key": key},
    )
    c.post(
        f"/admin/identity/tenants/{tenant}/invitations",
        json={"email": "x@other.com", "role": "user", "identity_type": "human"},
        headers={"x-api-key": key},
    )
    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-sla", headers={"x-api-key": key}
    )
    types = [i["type"] for i in r.json()["items"]]
    assert "policy_violation" in types


def test_governance_sla_wrong_tenant(build_app) -> None:
    app = build_app(auth_enabled=True, api_key="")
    key_a = mint_key("admin:read", tenant_id="iso-sla-a", ttl_seconds=3600)
    c = TestClient(app)
    r = c.get(
        "/admin/identity/tenants/iso-sla-b/governance-sla", headers={"x-api-key": key_a}
    )
    assert r.status_code in {400, 403}


# ── Gap D: Cross-Tenant Benchmark ────────────────────────────────────────────


def test_governance_benchmark_no_snapshots(build_app) -> None:
    tenant = "bm-empty-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key},
    )
    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-benchmark",
        headers={"x-api-key": key},
    )
    assert r.status_code == 200


def test_governance_benchmark_with_snapshot(build_app) -> None:
    tenant = "bm-snap-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key},
    )
    c.post(
        f"/admin/identity/tenants/{tenant}/governance-snapshots",
        headers={"x-api-key": key},
    )
    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-benchmark",
        headers={"x-api-key": key},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["has_benchmark"] is True
    assert body["participating_tenants"] >= 1
    assert body["own_score"]["percent"] is not None
    bm = body["benchmark"]
    assert bm["p25"] <= bm["median"] <= bm["p75"] <= bm["p90"]


def test_governance_benchmark_no_other_tenant_data_exposed(build_app) -> None:
    """Benchmark response must not include any tenant_id other than the caller's."""
    tenant = "bm-privacy-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key},
    )
    c.post(
        f"/admin/identity/tenants/{tenant}/governance-snapshots",
        headers={"x-api-key": key},
    )
    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-benchmark",
        headers={"x-api-key": key},
    )
    body_str = r.text
    # Ensure no other tenant IDs leak into the response
    import json as _json

    body = _json.loads(body_str)
    assert body["tenant_id"] == tenant
    # benchmark sub-object has no tenant_ids
    bm = body.get("benchmark", {})
    assert "tenant_id" not in bm


def test_governance_benchmark_wrong_tenant(build_app) -> None:
    app = build_app(auth_enabled=True, api_key="")
    key_a = mint_key("admin:read", tenant_id="iso-bm-a", ttl_seconds=3600)
    c = TestClient(app)
    r = c.get(
        "/admin/identity/tenants/iso-bm-b/governance-benchmark",
        headers={"x-api-key": key_a},
    )
    assert r.status_code in {400, 403}


# ── Gap E: Governance Findings ────────────────────────────────────────────────


def test_governance_findings_clean_tenant(build_app) -> None:
    tenant = "gf-clean-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={
            "identity_mode": "managed",
            "provider": "auth0",
            "sso_enforced": True,
            "maturity_level": "level_1",
        },
        headers={"x-api-key": key},
    )
    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-findings",
        headers={"x-api-key": key},
    )
    assert r.status_code == 200
    body = r.json()
    assert "finding_count" in body
    assert "findings" in body
    assert isinstance(body["findings"], list)


def test_governance_findings_violation_aggregated(build_app) -> None:
    tenant = "gf-viol-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key},
    )
    c.post(
        f"/admin/identity/tenants/{tenant}/invitations",
        json={"email": "bot@corp.com", "role": "admin", "identity_type": "agent"},
        headers={"x-api-key": key},
    )
    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-findings",
        headers={"x-api-key": key},
    )
    finding_types = {f["type"] for f in r.json()["findings"]}
    assert "policy_violation" in finding_types


def test_governance_findings_drift_aggregated(build_app) -> None:
    """Failing score dimensions must appear as drift findings."""
    tenant = "gf-drift-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    # Minimal config → many dimensions will fail
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key},
    )
    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-findings",
        headers={"x-api-key": key},
    )
    finding_types = {f["type"] for f in r.json()["findings"]}
    assert "drift" in finding_types


def test_governance_findings_no_duplicate_ids(build_app) -> None:
    tenant = "gf-dedup-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key},
    )
    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-findings",
        headers={"x-api-key": key},
    )
    ids = [f["finding_id"] for f in r.json()["findings"]]
    assert len(ids) == len(set(ids)), "Duplicate finding_ids detected"


def test_governance_findings_each_has_evidence_key(build_app) -> None:
    tenant = "gf-ev-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key},
    )
    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-findings",
        headers={"x-api-key": key},
    )
    for f in r.json()["findings"]:
        assert "evidence" in f
        assert isinstance(f["evidence"], dict)
        assert "sources" in f
        assert isinstance(f["sources"], list)
        assert len(f["sources"]) >= 1


def test_governance_findings_sorted_critical_first(build_app) -> None:
    tenant = "gf-sort-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        json={"identity_mode": "managed", "provider": "auth0"},
        headers={"x-api-key": key},
    )
    c.post(
        f"/admin/identity/tenants/{tenant}/invitations",
        json={"email": "bot@corp.com", "role": "admin", "identity_type": "agent"},
        headers={"x-api-key": key},
    )
    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-findings",
        headers={"x-api-key": key},
    )
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sevs = [sev_order.get(f["severity"], 9) for f in r.json()["findings"]]
    assert sevs == sorted(sevs), "Findings not sorted critical-first"


def test_governance_findings_wrong_tenant(build_app) -> None:
    app = build_app(auth_enabled=True, api_key="")
    key_a = mint_key("admin:read", tenant_id="iso-gf-a", ttl_seconds=3600)
    c = TestClient(app)
    r = c.get(
        "/admin/identity/tenants/iso-gf-b/governance-findings",
        headers={"x-api-key": key_a},
    )
    assert r.status_code in {400, 403}


# ── Governance Actions Ledger ─────────────────────────────────────────────────


def test_governance_action_record_accepted(build_app) -> None:
    tenant = "gal-accepted-01"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    r = c.post(
        f"/admin/identity/tenants/{tenant}/governance-actions",
        json={
            "dimension": "sso_enforced",
            "action_state": "accepted",
            "actor_email": "ops@example.com",
            "actor_role": "operator",
            "reason": "Scheduled for Q3",
        },
        headers={"x-api-key": key},
    )
    assert r.status_code == 201
    body = r.json()
    assert body["dimension"] == "sso_enforced"
    assert body["action_state"] == "accepted"
    assert body["actor_email"] == "ops@example.com"
    assert body["reason"] == "Scheduled for Q3"
    assert "action_id" in body
    assert "recommendation_action" in body


def test_governance_action_full_lifecycle(build_app) -> None:
    """accepted → implemented is valid; second implemented → 409 (terminal)."""
    tenant = "gal-lifecycle-02"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    headers = {"x-api-key": key}

    r1 = c.post(
        f"/admin/identity/tenants/{tenant}/governance-actions",
        json={"dimension": "domains_verified", "action_state": "accepted"},
        headers=headers,
    )
    assert r1.status_code == 201

    r2 = c.post(
        f"/admin/identity/tenants/{tenant}/governance-actions",
        json={
            "dimension": "domains_verified",
            "action_state": "implemented",
            "outcome": "DNS TXT records added and verified",
        },
        headers=headers,
    )
    assert r2.status_code == 201
    assert r2.json()["action_state"] == "implemented"

    # terminal — cannot record again
    r3 = c.post(
        f"/admin/identity/tenants/{tenant}/governance-actions",
        json={"dimension": "domains_verified", "action_state": "accepted"},
        headers=headers,
    )
    assert r3.status_code == 409
    assert "terminal" in r3.json()["detail"]["code"].lower()


def test_governance_action_deferred_lifecycle(build_app) -> None:
    """deferred → accepted → implemented chain."""
    tenant = "gal-deferred-03"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    headers = {"x-api-key": key}

    c.post(
        f"/admin/identity/tenants/{tenant}/governance-actions",
        json={
            "dimension": "multi_provider",
            "action_state": "deferred",
            "deferred_until": "2026-09-01",
        },
        headers=headers,
    )
    c.post(
        f"/admin/identity/tenants/{tenant}/governance-actions",
        json={"dimension": "multi_provider", "action_state": "accepted"},
        headers=headers,
    )
    r = c.post(
        f"/admin/identity/tenants/{tenant}/governance-actions",
        json={
            "dimension": "multi_provider",
            "action_state": "implemented",
            "outcome": "Secondary IdP configured",
        },
        headers=headers,
    )
    assert r.status_code == 201


def test_governance_action_invalid_transition_409(build_app) -> None:
    """accepted → rejected is not a valid transition."""
    tenant = "gal-bad-transition-04"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    headers = {"x-api-key": key}

    c.post(
        f"/admin/identity/tenants/{tenant}/governance-actions",
        json={"dimension": "config_ready", "action_state": "accepted"},
        headers=headers,
    )
    r = c.post(
        f"/admin/identity/tenants/{tenant}/governance-actions",
        json={"dimension": "config_ready", "action_state": "rejected"},
        headers=headers,
    )
    assert r.status_code == 409
    assert "INVALID_TRANSITION" in r.json()["detail"]["code"]


def test_governance_action_unknown_dimension_422(build_app) -> None:
    tenant = "gal-bad-dim-05"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    r = c.post(
        f"/admin/identity/tenants/{tenant}/governance-actions",
        json={"dimension": "nonexistent_dimension", "action_state": "accepted"},
        headers={"x-api-key": key},
    )
    assert r.status_code == 422
    assert "UNKNOWN_DIMENSION" in r.json()["detail"]["code"]


def test_governance_action_invalid_state_422(build_app) -> None:
    tenant = "gal-bad-state-06"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    r = c.post(
        f"/admin/identity/tenants/{tenant}/governance-actions",
        json={"dimension": "sso_enforced", "action_state": "bogus_state"},
        headers={"x-api-key": key},
    )
    assert r.status_code == 422
    assert "INVALID_ACTION_STATE" in r.json()["detail"]["code"]


def test_list_governance_actions_empty(build_app) -> None:
    tenant = "gal-list-empty-07"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-actions",
        headers={"x-api-key": key},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 0
    assert body["actions"] == []


def test_list_governance_actions_returns_entries(build_app) -> None:
    tenant = "gal-list-08"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    headers = {"x-api-key": key}

    c.post(
        f"/admin/identity/tenants/{tenant}/governance-actions",
        json={
            "dimension": "sso_enforced",
            "action_state": "accepted",
            "actor_email": "a@b.com",
        },
        headers=headers,
    )
    c.post(
        f"/admin/identity/tenants/{tenant}/governance-actions",
        json={
            "dimension": "config_ready",
            "action_state": "rejected",
            "reason": "Out of scope",
        },
        headers=headers,
    )

    r = c.get(f"/admin/identity/tenants/{tenant}/governance-actions", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 2
    dims = {a["dimension"] for a in body["actions"]}
    assert "sso_enforced" in dims
    assert "config_ready" in dims


def test_list_governance_actions_filter_by_dimension(build_app) -> None:
    tenant = "gal-filter-dim-09"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    headers = {"x-api-key": key}

    for dim in ("sso_enforced", "multi_provider"):
        c.post(
            f"/admin/identity/tenants/{tenant}/governance-actions",
            json={"dimension": dim, "action_state": "deferred"},
            headers=headers,
        )

    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-actions?dimension=sso_enforced",
        headers=headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    assert body["actions"][0]["dimension"] == "sso_enforced"


def test_governance_action_summary_unaddressed(build_app) -> None:
    tenant = "gal-summary-unaddr-10"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-action-summary",
        headers={"x-api-key": key},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["unaddressed"] == body["total_dimensions"]
    assert body["implemented"] == 0
    for d in body["dimensions"]:
        assert d["current_state"] == "unaddressed"
        assert d["is_terminal"] is False


def test_governance_action_summary_reflects_decisions(build_app) -> None:
    tenant = "gal-summary-decided-11"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    headers = {"x-api-key": key}

    ra = c.post(
        f"/admin/identity/tenants/{tenant}/governance-actions",
        json={
            "dimension": "sso_enforced",
            "action_state": "accepted",
            "actor_email": "ops@example.com",
            "reason": "Q3 plan",
        },
        headers=headers,
    )
    assert ra.status_code == 201, ra.json()
    rb = c.post(
        f"/admin/identity/tenants/{tenant}/governance-actions",
        json={
            "dimension": "audit_chain_intact",
            "action_state": "implemented",
            "outcome": "Audit events wired",
        },
        headers=headers,
    )
    assert rb.status_code == 201, rb.json()

    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-action-summary",
        headers=headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["accepted"] == 1
    assert body["implemented"] == 1
    assert body["unaddressed"] == body["total_dimensions"] - 2

    dims_by_key = {d["dimension"]: d for d in body["dimensions"]}
    assert dims_by_key["sso_enforced"]["current_state"] == "accepted"
    assert dims_by_key["sso_enforced"]["actor_email"] == "ops@example.com"
    assert dims_by_key["audit_chain_intact"]["current_state"] == "implemented"
    assert dims_by_key["audit_chain_intact"]["is_terminal"] is True


def test_governance_action_wrong_tenant(build_app) -> None:
    app = build_app(auth_enabled=True, api_key="")
    key_a = mint_key(
        "admin:read", "admin:write", tenant_id="gal-wrong-a", ttl_seconds=3600
    )
    c = TestClient(app)
    r = c.post(
        "/admin/identity/tenants/gal-wrong-b/governance-actions",
        json={"dimension": "sso_enforced", "action_state": "accepted"},
        headers={"x-api-key": key_a},
    )
    assert r.status_code in {400, 403}


def test_governance_action_summary_wrong_tenant(build_app) -> None:
    app = build_app(auth_enabled=True, api_key="")
    key_a = mint_key("admin:read", tenant_id="gal-sum-wrong-a", ttl_seconds=3600)
    c = TestClient(app)
    r = c.get(
        "/admin/identity/tenants/gal-sum-wrong-b/governance-action-summary",
        headers={"x-api-key": key_a},
    )
    assert r.status_code in {400, 403}


def test_governance_action_ledger_ordered_desc(build_app) -> None:
    """Ledger must return most-recent action first."""
    tenant = "gal-order-12"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    c = TestClient(app)
    headers = {"x-api-key": key}

    c.post(
        f"/admin/identity/tenants/{tenant}/governance-actions",
        json={"dimension": "domains_verified", "action_state": "deferred"},
        headers=headers,
    )
    c.post(
        f"/admin/identity/tenants/{tenant}/governance-actions",
        json={"dimension": "domains_verified", "action_state": "accepted"},
        headers=headers,
    )

    r = c.get(
        f"/admin/identity/tenants/{tenant}/governance-actions?dimension=domains_verified",
        headers=headers,
    )
    actions = r.json()["actions"]
    assert actions[0]["action_state"] == "accepted"
    assert actions[1]["action_state"] == "deferred"
    # previous_action_id on the later row points to the earlier one
    assert actions[0]["previous_action_id"] == actions[1]["action_id"]
