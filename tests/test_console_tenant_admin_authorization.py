"""Console tenant-admin BFF -> Core authorization regressions.

These tests cover the production failure where Console Users mutations reached
Core with valid admin-gateway authentication but were denied by tenant commercial
capability checks before the tenant-admin route logic ran.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.admin_gateway_delegation import (
    configure_delegation_env,
    delegation_headers,
)


def _configure_app(tmp_path, monkeypatch):
    db_path = tmp_path / "console_tenant_admin_authz.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AUTH_ENABLED", "1")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", "test-admin-gateway-token")
    monkeypatch.setenv("FG_ENTITLEMENT_ENFORCEMENT", "true")
    monkeypatch.setenv("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")
    # PR-CORE-002: admin-gateway requests must present a delegation proof.
    # Pin the secret so this test and Core agree regardless of ambient env.
    configure_delegation_env(monkeypatch)

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
        "X-Request-ID": f"test-{tenant_id}",
    }


def _tenant_key_headers(tenant_id: str) -> dict[str, str]:
    from api.auth_scopes import mint_key

    key = mint_key("admin:read", "admin:write", tenant_id=tenant_id)
    return {"X-API-Key": key, "X-Tenant-ID": tenant_id}


def _capability_code(response) -> str | None:
    body = response.json()
    detail = body.get("detail") if isinstance(body, dict) else None
    if isinstance(detail, dict):
        return detail.get("code")
    return None


def _delegated_admin_gateway_headers(
    tenant_id: str, *, method: str, path: str
) -> dict[str, str]:
    base = _admin_gateway_headers(tenant_id)
    proof = delegation_headers(
        tenant_id=tenant_id,
        method=method,
        path=path,
        request_id=base["X-Request-ID"],
    )
    return {**base, **proof}


def test_admin_gateway_users_invite_reaches_business_validation_without_identity_entitlement(
    tmp_path, monkeypatch
):
    client = _configure_app(tmp_path, monkeypatch)
    tenant_id = "tenant-console-users-invite"
    _seed_tenant(tenant_id)

    response = client.post(
        "/workforce/users",
        headers=_delegated_admin_gateway_headers(
            tenant_id, method="POST", path="/workforce/users"
        ),
        json={"email": "probe@example.com", "display_name": "Probe", "role": "admin"},
    )

    assert response.status_code == 422, response.text
    assert _capability_code(response) == "IDENTITY_CONFIGURATION_REQUIRED"
    assert "CAPABILITY_DENIED" not in response.text


def test_admin_gateway_users_update_reaches_resource_gate_without_identity_entitlement(
    tmp_path, monkeypatch
):
    client = _configure_app(tmp_path, monkeypatch)
    tenant_id = "tenant-console-users-update"
    _seed_tenant(tenant_id)

    response = client.patch(
        "/workforce/users/missing-user",
        headers=_delegated_admin_gateway_headers(
            tenant_id, method="PATCH", path="/workforce/users/missing-user"
        ),
        json={"active": False},
    )

    assert response.status_code == 404, response.text
    assert _capability_code(response) == "USER_NOT_FOUND"
    assert "CAPABILITY_DENIED" not in response.text


def test_admin_gateway_identity_routes_reach_tenant_admin_logic_without_sso_entitlement(
    tmp_path, monkeypatch
):
    client = _configure_app(tmp_path, monkeypatch)
    tenant_id = "tenant-console-identity"
    _seed_tenant(tenant_id)

    config_path = f"/admin/identity/tenants/{tenant_id}/config"
    readiness_path = f"/admin/identity/tenants/{tenant_id}/readiness"

    config = client.get(
        config_path,
        headers=_delegated_admin_gateway_headers(
            tenant_id, method="GET", path=config_path
        ),
    )
    readiness = client.get(
        readiness_path,
        headers=_delegated_admin_gateway_headers(
            tenant_id, method="GET", path=readiness_path
        ),
    )
    upsert = client.put(
        config_path,
        headers=_delegated_admin_gateway_headers(
            tenant_id, method="PUT", path=config_path
        ),
        json={"identity_mode": "managed", "provider": "auth0"},
    )

    assert config.status_code == 200, config.text
    assert readiness.status_code == 200, readiness.text
    assert upsert.status_code == 200, upsert.text
    assert "CAPABILITY_DENIED" not in config.text + readiness.text + upsert.text


def test_tenant_api_key_still_requires_identity_scim_entitlement(tmp_path, monkeypatch):
    client = _configure_app(tmp_path, monkeypatch)
    tenant_id = "tenant-console-users-tenant-key-denied"
    _seed_tenant(tenant_id)

    response = client.post(
        "/workforce/users",
        headers=_tenant_key_headers(tenant_id),
        json={"email": "probe@example.com", "display_name": "Probe", "role": "admin"},
    )

    assert response.status_code == 403, response.text
    assert _capability_code(response) == "CAPABILITY_DENIED"
    assert response.json()["detail"]["capability"] == "identity.scim"


def test_stale_admin_gateway_token_fails_closed_before_capability_check(
    tmp_path, monkeypatch
):
    client = _configure_app(tmp_path, monkeypatch)
    tenant_id = "tenant-console-users-stale-token"

    response = client.post(
        "/workforce/users",
        headers=_admin_gateway_headers(tenant_id, token="stale-admin-gateway-token"),
        json={"email": "probe@example.com", "display_name": "Probe", "role": "admin"},
    )

    assert response.status_code == 401, response.text
    assert response.json()["detail"] == "Invalid or missing API key"
