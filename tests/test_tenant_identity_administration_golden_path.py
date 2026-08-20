"""Tenant identity administration golden-path release invariant.

This exercises the canonical Core contract for Customer N+1:
no pre-seeded identity policy, setup through the admin identity route, invitation
through the workforce route, and fail-closed security negatives.
"""

from __future__ import annotations

from fastapi.testclient import TestClient


def _configure_app(tmp_path, monkeypatch) -> TestClient:
    db_path = tmp_path / "tenant_identity_admin_golden.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AUTH_ENABLED", "1")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", "test-admin-gateway-token")
    monkeypatch.setenv("FG_ENTITLEMENT_ENFORCEMENT", "true")
    monkeypatch.setenv("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

    import api.entitlements as entitlements
    from api.db import init_db, reset_engine_cache
    from api.main import build_app

    monkeypatch.setattr(entitlements, "ENFORCEMENT_STRICT", True)
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    return TestClient(build_app(auth_enabled=True), raise_server_exceptions=False)


def _seed_tenant(tenant_id: str, *, lifecycle_state: str = "active") -> None:
    """Seed an active tenant row so PR-CORE-002 tenant verification succeeds.

    Every admin-gateway call for X-Tenant-ID must correspond to an existing
    active tenant row (verified by bind_tenant_id -> _verify_admin_gateway_tenant).
    Tests exercising the admin-gateway path must seed the tenant explicitly;
    Core does not auto-create tenants on first admin-gateway contact.
    """
    from sqlalchemy import text

    from api.db import get_engine

    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO tenants (tenant_id, display_name, lifecycle_state)"
                " VALUES (:tid, :name, :state)"
            ),
            {"tid": tenant_id, "name": tenant_id, "state": lifecycle_state},
        )


def _admin_gateway_headers(
    tenant_id: str, token: str = "test-admin-gateway-token"
) -> dict[str, str]:
    return {
        "X-API-Key": token,
        "X-FG-Internal-Token": token,
        "X-Admin-Gateway-Internal": "true",
        "X-Tenant-ID": tenant_id,
        "X-Request-ID": f"golden-{tenant_id}",
    }


def _tenant_key_headers(tenant_id: str) -> dict[str, str]:
    from api.auth_scopes import mint_key

    key = mint_key("admin:read", "admin:write", tenant_id=tenant_id, ttl_seconds=3600)
    return {"X-API-Key": key, "X-Tenant-ID": tenant_id}


def _detail_code(response) -> str | None:
    body = response.json()
    detail = body.get("detail") if isinstance(body, dict) else None
    if isinstance(detail, dict):
        return detail.get("code")
    return None


def test_customer_n_plus_one_identity_admin_golden_path(tmp_path, monkeypatch) -> None:
    client = _configure_app(tmp_path, monkeypatch)
    tenant = "tenant-golden-n-plus-one"
    other_tenant = "tenant-golden-other"
    _seed_tenant(tenant)
    _seed_tenant(other_tenant)
    headers = _admin_gateway_headers(tenant)

    initial_config = client.get(
        f"/admin/identity/tenants/{tenant}/config", headers=headers
    )
    assert initial_config.status_code == 200, initial_config.text
    assert initial_config.json()["configured"] is False

    blocked_invite = client.post(
        "/workforce/users",
        headers=headers,
        json={
            "email": "new.admin@example.com",
            "display_name": "New Admin",
            "role": "admin",
        },
    )
    assert blocked_invite.status_code == 422, blocked_invite.text
    assert _detail_code(blocked_invite) == "IDENTITY_CONFIGURATION_REQUIRED"

    audit_after_block = client.get(
        f"/admin/identity/tenants/{tenant}/audit-summary", headers=headers
    )
    assert audit_after_block.status_code == 200, audit_after_block.text
    assert (
        audit_after_block.json()["by_type"].get(
            "tenant.identity_config.invitation_blocked"
        )
        == 1
    )

    configured = client.put(
        f"/admin/identity/tenants/{tenant}/config",
        headers=headers,
        json={
            "identity_mode": "managed",
            "provider": "auth0",
            "provisioning_status": "ready",
            "maturity_level": "level_1",
            "capability_flags": {"managed_identities": True},
        },
    )
    assert configured.status_code == 200, configured.text
    assert configured.json()["provisioning_status"] == "ready"

    readiness = client.get(
        f"/admin/identity/tenants/{tenant}/readiness", headers=headers
    )
    assert readiness.status_code == 200, readiness.text
    assert readiness.json()["status"] == "ready"

    invite = client.post(
        "/workforce/users",
        headers=headers,
        json={
            "email": "new.admin@example.com",
            "display_name": "New Admin",
            "role": "admin",
        },
    )
    assert invite.status_code == 200, invite.text
    invitation_id = invite.json()["invitation_id"]

    invitations = client.get(
        f"/admin/identity/tenants/{tenant}/invitations", headers=headers
    )
    assert invitations.status_code == 200, invitations.text
    assert invitation_id in {item["id"] for item in invitations.json()["invitations"]}

    audit = client.get(
        f"/admin/identity/tenants/{tenant}/audit-summary", headers=headers
    )
    assert audit.status_code == 200, audit.text
    by_type = audit.json()["by_type"]
    assert by_type.get("tenant.identity_config.created") == 1
    assert by_type.get("tenant.identity_config.provisioning_ready") == 1
    assert by_type.get("tenant.invite.created") == 1

    cross_tenant = client.put(
        f"/admin/identity/tenants/{other_tenant}/config",
        headers=_tenant_key_headers(tenant),
        json={
            "identity_mode": "managed",
            "provider": "auth0",
            "provisioning_status": "ready",
        },
    )
    assert cross_tenant.status_code == 403, cross_tenant.text

    stale_auth = client.post(
        "/workforce/users",
        headers=_admin_gateway_headers(tenant, token="stale-admin-gateway-token"),
        json={"email": "stale@example.com", "display_name": "Stale", "role": "admin"},
    )
    assert stale_auth.status_code == 401, stale_auth.text

    no_auth = client.post(
        "/workforce/users",
        json={
            "email": "missing@example.com",
            "display_name": "Missing",
            "role": "admin",
        },
    )
    assert no_auth.status_code == 401, no_auth.text

    tenant_key_invite = client.post(
        "/workforce/users",
        headers=_tenant_key_headers(tenant),
        json={
            "email": "tenant-key@example.com",
            "display_name": "Tenant Key",
            "role": "admin",
        },
    )
    assert tenant_key_invite.status_code == 403, tenant_key_invite.text
    assert _detail_code(tenant_key_invite) == "CAPABILITY_DENIED"


def test_existing_customer_identity_states_gate_invites(tmp_path, monkeypatch) -> None:
    client = _configure_app(tmp_path, monkeypatch)
    no_config = "tenant-existing-no-config"
    not_configured = "tenant-existing-not-configured"
    ready = "tenant-existing-ready"
    _seed_tenant(no_config)
    _seed_tenant(not_configured)
    _seed_tenant(ready)

    blocked_missing = client.post(
        "/workforce/users",
        headers=_admin_gateway_headers(no_config),
        json={
            "email": "missing@example.com",
            "display_name": "Missing",
            "role": "admin",
        },
    )
    assert blocked_missing.status_code == 422, blocked_missing.text
    assert _detail_code(blocked_missing) == "IDENTITY_CONFIGURATION_REQUIRED"

    not_ready_headers = _admin_gateway_headers(not_configured)
    config = client.put(
        f"/admin/identity/tenants/{not_configured}/config",
        headers=not_ready_headers,
        json={"identity_mode": "managed", "provider": "auth0"},
    )
    assert config.status_code == 200, config.text
    blocked_not_ready = client.post(
        "/workforce/users",
        headers=not_ready_headers,
        json={
            "email": "not-ready@example.com",
            "display_name": "Not Ready",
            "role": "admin",
        },
    )
    assert blocked_not_ready.status_code == 422, blocked_not_ready.text
    assert _detail_code(blocked_not_ready) == "IDENTITY_CONFIGURATION_NOT_READY"

    ready_headers = _admin_gateway_headers(ready)
    ready_config = client.put(
        f"/admin/identity/tenants/{ready}/config",
        headers=ready_headers,
        json={
            "identity_mode": "managed",
            "provider": "auth0",
            "provisioning_status": "ready",
        },
    )
    assert ready_config.status_code == 200, ready_config.text
    allowed = client.post(
        "/workforce/users",
        headers=ready_headers,
        json={"email": "ready@example.com", "display_name": "Ready", "role": "admin"},
    )
    assert allowed.status_code == 200, allowed.text
