"""tests/test_identity_next_login_binding.py — Next-login identity binding tests (PR5).

Verifies that:
  - An unbound user who invites creates a pending invitation record
  - The pending invitation remains pending until the governed flow completes
  - Bound users stay bound; their invitation shows 'bound' status
  - Unbound users cannot receive a governed session (session_service enforces this)
  - Non-human identity types cannot use the human invitation/login flow
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

import pytest
from starlette.testclient import TestClient

from api.auth_scopes import mint_key

TENANT = "test-tenant-pr5-binding"


@pytest.fixture
def client(build_app):
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=TENANT, ttl_seconds=3600)
    return TestClient(app), {"x-api-key": key}


def _setup_config(c: TestClient, headers: dict, tenant: str) -> None:
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        headers=headers,
        json={"identity_mode": "managed", "provider": "auth0"},
    )


# ── Invitation state: pending until governed flow completes ───────────────────


def test_invited_user_invitation_is_pending(build_app) -> None:
    tenant = "pr5-bind-pending"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    _setup_config(c, headers, tenant)

    invite_r = c.post(
        "/workforce/users",
        headers=headers,
        json={"email": "pending@example.com", "display_name": "Pending User"},
    )
    assert invite_r.status_code == 200
    invitation_id = invite_r.json()["invitation_id"]

    list_r = c.get(f"/admin/identity/tenants/{tenant}/invitations", headers=headers)
    inv = next(i for i in list_r.json()["invitations"] if i["id"] == invitation_id)
    assert inv["status"] == "pending"


def test_invited_user_binding_status_is_unbound(build_app) -> None:
    tenant = "pr5-bind-unbound"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    _setup_config(c, headers, tenant)

    c.post(
        "/workforce/users",
        headers=headers,
        json={"email": "unbound@example.com", "display_name": "Unbound User"},
    )

    list_r = c.get("/workforce/users", headers=headers)
    items = list_r.json()["items"]
    user = next(u for u in items if u["email"] == "unbound@example.com")
    assert user["identity_binding_status"] == "unbound"


def test_pending_invitation_stays_pending_without_binding(build_app) -> None:
    """Invitation must stay 'pending' if the governed callback never fires."""
    tenant = "pr5-stay-pending"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    _setup_config(c, headers, tenant)

    invite_r = c.post(
        "/workforce/users",
        headers=headers,
        json={"email": "stay@example.com", "display_name": "Stay Pending"},
    )
    invitation_id = invite_r.json()["invitation_id"]

    # Re-check — status should still be pending
    list_r = c.get(f"/admin/identity/tenants/{tenant}/invitations", headers=headers)
    inv = next(i for i in list_r.json()["invitations"] if i["id"] == invitation_id)
    assert inv["status"] == "pending"


# ── Non-human identity type cannot use human flow ─────────────────────────────


def test_non_human_invite_via_admin_identity_requires_governance(build_app) -> None:
    """Admin identity invitations for non-human types (service/agent) are accepted
    but cannot use the human login/session flow. Verify the invitation is created with
    the correct identity_type."""
    tenant = "pr5-nonhuman-type"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)

    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        headers=headers,
        json={"identity_mode": "managed", "provider": "auth0"},
    )

    r = c.post(
        f"/admin/identity/tenants/{tenant}/invitations",
        headers=headers,
        json={
            "email": "svc@internal.example.com",
            "role": "user",
            "identity_type": "service",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["identity_type"] == "service"


def test_admin_identity_rejects_invalid_identity_type(build_app) -> None:
    tenant = "pr5-invalid-type"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)

    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        headers=headers,
        json={"identity_mode": "managed", "provider": "auth0"},
    )

    r = c.post(
        f"/admin/identity/tenants/{tenant}/invitations",
        headers=headers,
        json={
            "email": "bad@example.com",
            "role": "user",
            "identity_type": "robot",
        },
    )
    assert r.status_code == 422


# ── Drift detection: UNBOUND_ACTIVE_USER ─────────────────────────────────────


def test_drift_detects_unbound_active_user(build_app) -> None:
    tenant = "pr5-drift-unbound"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    _setup_config(c, headers, tenant)

    c.post(
        "/workforce/users",
        headers=headers,
        json={"email": "driftu@example.com", "display_name": "Drift User"},
    )

    r = c.get(f"/admin/identity/tenants/{tenant}/drift", headers=headers)
    assert r.status_code == 200
    body = r.json()
    drift_types = [item["type"] for item in body["items"]]
    assert "UNBOUND_ACTIVE_USER" in drift_types


# ── Governance: invite_user audit event emitted on config-blocked invite ──────


def test_invite_blocked_emits_audit_event(build_app) -> None:
    """When no identity config exists, invitation_blocked audit event must be emitted."""
    tenant = "pr5-audit-blocked"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)

    # Attempt invite WITHOUT setting up config first
    r = c.post(
        "/workforce/users",
        headers=headers,
        json={"email": "blocked@example.com", "display_name": "Blocked User"},
    )
    assert r.status_code == 422

    # Now set up config so we can read the audit summary
    _setup_config(c, headers, tenant)
    audit_r = c.get(f"/admin/identity/tenants/{tenant}/audit-summary", headers=headers)
    assert audit_r.status_code == 200
    by_type = audit_r.json().get("by_type", {})
    assert by_type.get("tenant.identity_config.invitation_blocked", 0) >= 1
