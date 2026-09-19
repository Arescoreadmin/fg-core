"""TENANT-ISOLATION-E2E-001: real Core delegated-human authority proof."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import text

from tests.admin_gateway_delegation import (
    configure_delegation_env,
    delegation_headers,
)


TENANT_A = "high-table-financial"
TENANT_B = "continental-holdings"
MISSING_TENANT = "nonexistent-706"
SUBJECT_A = "auth0|high-table-admin"
SUBJECT_B = "auth0|continental-admin"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _configure_app(tmp_path, monkeypatch) -> TestClient:
    db_path = tmp_path / "tenant-isolation-e2e.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AUTH_ENABLED", "1")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", "test-admin-gateway-token")
    monkeypatch.setenv("FG_ENTITLEMENT_ENFORCEMENT", "true")
    monkeypatch.setenv("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")
    configure_delegation_env(monkeypatch)

    import api.entitlements as entitlements
    from api.db import init_db, reset_engine_cache
    from api.main import build_app

    monkeypatch.setattr(entitlements, "ENFORCEMENT_STRICT", True)
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    return TestClient(build_app(auth_enabled=True), raise_server_exceptions=False)


def _seed_actor(
    tenant_id: str,
    subject: str,
    *,
    role: str = "tenant_admin",
    active: bool = True,
    binding: str = "bound",
    principal_lifecycle: str = "active",
) -> None:
    from api.db import get_engine

    principal_id = f"principal-{tenant_id}"
    membership_id = f"membership-{tenant_id}"
    now = _now()
    with get_engine().begin() as conn:
        conn.execute(
            text(
                """
                INSERT OR IGNORE INTO tenants
                    (tenant_id, display_name, lifecycle_state, tenant_kind)
                VALUES (:tid, :name, 'active', 'customer')
                """
            ),
            {"tid": tenant_id, "name": tenant_id},
        )
        conn.execute(
            text(
                """
                INSERT OR IGNORE INTO fg_principals
                    (id, principal_type, lifecycle_state, mfa_verified,
                     authority_version, created_at, updated_at)
                VALUES (:pid, 'human', :lifecycle, 0, 1, :now, :now)
                """
            ),
            {"pid": principal_id, "lifecycle": principal_lifecycle, "now": now},
        )
        conn.execute(
            text(
                """
                INSERT OR IGNORE INTO tenant_users
                    (id, tenant_id, email, display_name, role, active,
                     identity_subject, identity_provider, identity_issuer,
                     identity_binding_status, principal_id,
                     created_at, updated_at)
                VALUES
                    (:mid, :tid, :email, :email, :role, :active,
                     :subject, 'auth0', 'https://example.auth0.com/',
                     :binding, :pid, :now, :now)
                """
            ),
            {
                "mid": membership_id,
                "tid": tenant_id,
                "email": f"admin@{tenant_id}.example",
                "role": role,
                "active": active,
                "subject": subject,
                "binding": binding,
                "pid": principal_id if binding == "bound" else None,
                "now": now,
            },
        )


def _headers(
    tenant_id: str,
    path: str,
    subject: str,
    authority: str = "tenant_human",
    *,
    method: str = "GET",
) -> dict[str, str]:
    request_id = f"706-{tenant_id}-{method.lower()}"
    return {
        "X-API-Key": "test-admin-gateway-token",
        "X-FG-Internal-Token": "test-admin-gateway-token",
        "X-Admin-Gateway-Internal": "true",
        "X-Tenant-ID": tenant_id,
        "X-Request-ID": request_id,
        **delegation_headers(
            tenant_id=tenant_id,
            method=method,
            path=path,
            request_id=request_id,
            actor_subject=subject,
            actor_authority=authority,
        ),
    }


def _config_path(tenant_id: str) -> str:
    return f"/admin/identity/tenants/{tenant_id}/config"


def test_tenant_human_v3_requires_canonical_active_membership(
    tmp_path, monkeypatch
) -> None:
    client = _configure_app(tmp_path, monkeypatch)
    _seed_actor(TENANT_A, SUBJECT_A)
    _seed_actor(TENANT_B, SUBJECT_B)

    own_path = _config_path(TENANT_A)
    own = client.get(own_path, headers=_headers(TENANT_A, own_path, SUBJECT_A))
    assert own.status_code == 200, own.text
    assert own.json() == {"tenant_id": TENANT_A, "configured": False}

    foreign_path = _config_path(TENANT_B)
    foreign = client.get(
        foreign_path, headers=_headers(TENANT_B, foreign_path, SUBJECT_A)
    )
    nonexistent_path = _config_path(MISSING_TENANT)
    nonexistent = client.get(
        nonexistent_path,
        headers=_headers(MISSING_TENANT, nonexistent_path, SUBJECT_A),
    )
    missing_actor = client.get(
        own_path, headers=_headers(TENANT_A, own_path, "auth0|missing-706")
    )

    assert (
        foreign.status_code
        == nonexistent.status_code
        == missing_actor.status_code
        == 403
    )
    assert foreign.json() == nonexistent.json() == missing_actor.json()
    assert TENANT_B not in foreign.text
    assert MISSING_TENANT not in nonexistent.text


def test_inactive_unbound_wrong_role_and_inactive_principal_fail_closed(
    tmp_path, monkeypatch
) -> None:
    client = _configure_app(tmp_path, monkeypatch)
    path = _config_path(TENANT_A)

    from api.db import get_engine

    for subject, role, active, binding, principal_lifecycle in (
        ("auth0|inactive", "tenant_admin", False, "bound", "active"),
        ("auth0|unbound", "tenant_admin", True, "unbound", "active"),
        ("auth0|wrong-role", "client_read_only", True, "bound", "active"),
        ("auth0|principal-inactive", "tenant_admin", True, "bound", "suspended"),
    ):
        with get_engine().begin() as conn:
            conn.execute(
                text("DELETE FROM tenant_users WHERE tenant_id = :tid"),
                {"tid": TENANT_A},
            )
            conn.execute(
                text("DELETE FROM fg_principals WHERE id = :pid"),
                {"pid": f"principal-{TENANT_A}"},
            )
        _seed_actor(
            TENANT_A,
            subject,
            role=role,
            active=active,
            binding=binding,
            principal_lifecycle=principal_lifecycle,
        )
        response = client.get(path, headers=_headers(TENANT_A, path, subject))
        assert response.status_code == 403, (subject, response.text)


def test_signed_internal_console_authority_preserves_cross_tenant_policy(
    tmp_path, monkeypatch
) -> None:
    client = _configure_app(tmp_path, monkeypatch)
    _seed_actor(TENANT_B, SUBJECT_B)
    path = _config_path(TENANT_B)

    response = client.get(
        path,
        headers=_headers(TENANT_B, path, "auth0|platform-admin", "internal_console"),
    )
    assert response.status_code == 200, response.text
    assert response.json()["tenant_id"] == TENANT_B


def test_actor_and_authority_tampering_invalidates_proof(tmp_path, monkeypatch) -> None:
    client = _configure_app(tmp_path, monkeypatch)
    _seed_actor(TENANT_A, SUBJECT_A)
    path = _config_path(TENANT_A)

    actor_headers = _headers(TENANT_A, path, SUBJECT_A)
    actor_headers["X-FG-Named-User-Sub"] = SUBJECT_B
    actor_tamper = client.get(path, headers=actor_headers)

    authority_headers = _headers(TENANT_A, path, SUBJECT_A)
    authority_headers["X-FG-Actor-Authority"] = "internal_console"
    authority_tamper = client.get(path, headers=authority_headers)

    unknown_authority = client.get(
        path,
        headers=_headers(TENANT_A, path, SUBJECT_A, "future_authority_706"),
    )

    assert actor_tamper.status_code == 403
    assert authority_tamper.status_code == 403
    assert unknown_authority.status_code == 403


def test_denied_foreign_mutation_leaves_persistence_unchanged(
    tmp_path, monkeypatch
) -> None:
    client = _configure_app(tmp_path, monkeypatch)
    _seed_actor(TENANT_A, SUBJECT_A)
    _seed_actor(TENANT_B, SUBJECT_B)
    path = _config_path(TENANT_B)

    denied = client.put(
        path,
        headers=_headers(TENANT_B, path, SUBJECT_A, method="PUT"),
        json={"identity_mode": "managed", "provider": "auth0"},
    )
    assert denied.status_code == 403, denied.text

    read_back = client.get(
        path,
        headers=_headers(TENANT_B, path, "auth0|platform-admin", "internal_console"),
    )
    assert read_back.status_code == 200, read_back.text
    assert read_back.json() == {"tenant_id": TENANT_B, "configured": False}
