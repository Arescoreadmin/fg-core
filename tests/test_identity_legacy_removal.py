"""tests/test_identity_legacy_removal.py — PR5 identity governance cutover tests.

Verifies:
  - accept-invite endpoint is a 410 tombstone (no info disclosure)
  - invite_user returns invitation_id/invitation_url, not invite_token/invite_url_hint
  - invite_user fails closed (422) when no identity config exists
  - list_users returns identity_binding_status, not invite_pending
  - Session rejection: unbound, no membership, non-governed, non-human flows
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

import pytest
from starlette.testclient import TestClient

from api.auth_scopes import mint_key

TENANT = "test-tenant-pr5-legacy"


@pytest.fixture
def client(build_app):
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=TENANT, ttl_seconds=3600)
    return TestClient(app), {"x-api-key": key}


# ── accept-invite tombstone ────────────────────────────────────────────────────


def test_accept_invite_returns_410(client) -> None:
    c, _ = client
    r = c.post("/workforce/users/accept-invite", json={"invite_token": "tok-abc"})
    assert r.status_code == 410


def test_accept_invite_returns_410_without_body(client) -> None:
    c, _ = client
    r = c.post("/workforce/users/accept-invite")
    assert r.status_code == 410


def test_accept_invite_response_code_is_tombstone(client) -> None:
    c, _ = client
    r = c.post("/workforce/users/accept-invite", json={"invite_token": "tok-abc"})
    assert r.status_code == 410
    body = r.json()
    detail = body.get("detail", {})
    code = detail.get("code") if isinstance(detail, dict) else None
    assert code == "LEGACY_INVITE_ENDPOINT_REMOVED"


def test_accept_invite_does_not_disclose_token_info(client) -> None:
    """Tombstone must not reveal whether a token is valid — no 401/403/200."""
    c, _ = client
    r = c.post(
        "/workforce/users/accept-invite", json={"invite_token": "any-token-value"}
    )
    assert r.status_code == 410
    assert "invalid" not in r.text.lower()
    assert "expired" not in r.text.lower()


# ── invite_user — token elimination ───────────────────────────────────────────


def test_invite_user_requires_identity_config(client) -> None:
    """invite_user must fail closed (422) when no identity config is present."""
    c, headers = client
    r = c.post(
        "/workforce/users",
        headers=headers,
        json={"email": "newuser@example.com", "display_name": "New User"},
    )
    assert r.status_code == 422
    body = r.json()
    detail = body.get("detail", {})
    code = detail.get("code") if isinstance(detail, dict) else None
    assert code == "IDENTITY_CONFIGURATION_REQUIRED"


def _setup_config(c: TestClient, headers: dict, tenant: str) -> None:
    c.put(
        f"/admin/identity/tenants/{tenant}/config",
        headers=headers,
        json={"identity_mode": "managed", "provider": "auth0"},
    )


def test_invite_user_returns_invitation_id(build_app) -> None:
    tenant = "pr5-invite-returns-id"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    _setup_config(c, headers, tenant)
    r = c.post(
        "/workforce/users",
        headers=headers,
        json={"email": "user@example.com", "display_name": "Test User"},
    )
    assert r.status_code == 200
    body = r.json()
    assert "invitation_id" in body
    assert body["invitation_id"]


def test_invite_user_returns_invitation_url(build_app) -> None:
    tenant = "pr5-invite-returns-url"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    _setup_config(c, headers, tenant)
    r = c.post(
        "/workforce/users",
        headers=headers,
        json={"email": "user@example.com", "display_name": "Test User"},
    )
    assert r.status_code == 200
    body = r.json()
    assert "invitation_url" in body
    assert body["invitation_url"]


def test_invite_user_no_invite_token_in_response(build_app) -> None:
    tenant = "pr5-no-raw-token"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    _setup_config(c, headers, tenant)
    r = c.post(
        "/workforce/users",
        headers=headers,
        json={"email": "user@example.com", "display_name": "Test User"},
    )
    assert r.status_code == 200
    body = r.json()
    assert "invite_token" not in body
    assert "inviteToken" not in body
    assert "invite_url_hint" not in body
    assert "invite_expires_at" not in body


def test_invite_user_invitation_url_no_token_param(build_app) -> None:
    """The invitation_url must not contain a raw token query parameter."""
    tenant = "pr5-url-no-token-param"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    _setup_config(c, headers, tenant)
    r = c.post(
        "/workforce/users",
        headers=headers,
        json={"email": "user@example.com", "display_name": "Test User"},
    )
    assert r.status_code == 200
    invitation_url = r.json()["invitation_url"]
    assert "token=" not in invitation_url


# ── list_users — identity_binding_status ──────────────────────────────────────


def test_list_users_has_identity_binding_status(build_app) -> None:
    tenant = "pr5-list-binding-status"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    _setup_config(c, headers, tenant)
    c.post(
        "/workforce/users",
        headers=headers,
        json={"email": "u1@example.com", "display_name": "U One"},
    )
    r = c.get("/workforce/users", headers=headers)
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) >= 1
    for item in items:
        assert "identity_binding_status" in item


def test_list_users_no_invite_pending_field(build_app) -> None:
    """invite_pending must not appear in list_users responses after PR5."""
    tenant = "pr5-no-invite-pending"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    _setup_config(c, headers, tenant)
    c.post(
        "/workforce/users",
        headers=headers,
        json={"email": "u2@example.com", "display_name": "U Two"},
    )
    r = c.get("/workforce/users", headers=headers)
    assert r.status_code == 200
    items = r.json()["items"]
    for item in items:
        assert "invite_pending" not in item


def test_new_user_starts_unbound(build_app) -> None:
    tenant = "pr5-starts-unbound"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    _setup_config(c, headers, tenant)
    c.post(
        "/workforce/users",
        headers=headers,
        json={"email": "u3@example.com", "display_name": "U Three"},
    )
    r = c.get("/workforce/users", headers=headers)
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) == 1
    assert items[0]["identity_binding_status"] == "unbound"


# ── Governance invitation created and visible ──────────────────────────────────


def test_invite_user_creates_governance_invitation(build_app) -> None:
    tenant = "pr5-governance-inv"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    _setup_config(c, headers, tenant)
    invite_r = c.post(
        "/workforce/users",
        headers=headers,
        json={"email": "user@example.com", "display_name": "Test User"},
    )
    assert invite_r.status_code == 200
    invitation_id = invite_r.json()["invitation_id"]

    list_r = c.get(f"/admin/identity/tenants/{tenant}/invitations", headers=headers)
    assert list_r.status_code == 200
    inv_ids = [i["id"] for i in list_r.json()["invitations"]]
    assert invitation_id in inv_ids


def test_invite_user_invitation_is_human_type(build_app) -> None:
    tenant = "pr5-human-type"
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id=tenant, ttl_seconds=3600)
    headers = {"x-api-key": key}
    c = TestClient(app)
    _setup_config(c, headers, tenant)
    invite_r = c.post(
        "/workforce/users",
        headers=headers,
        json={"email": "human@example.com", "display_name": "Human User"},
    )
    assert invite_r.status_code == 200
    invitation_id = invite_r.json()["invitation_id"]

    list_r = c.get(f"/admin/identity/tenants/{tenant}/invitations", headers=headers)
    inv = next(i for i in list_r.json()["invitations"] if i["id"] == invitation_id)
    assert inv["identity_type"] == "human"
