from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from api.auth_scopes import mint_key
from api.db import get_sessionmaker
from services.connectors.oauth_store import load_active_secret, upsert_credential
from tests.test_auth import build_app


SENSITIVE_STATUS_KEYS = {
    "token",
    "refresh_token",
    "scope",
    "scopes",
    "provider_scope",
    "external_id",
    "oauth_error",
    "error_message",
    "client_id",
}


def _client() -> TestClient:
    app = build_app(auth_enabled=True)
    return TestClient(app)




def _set_default_policy_for_tenant(tenant_id: str) -> None:
    SessionLocal = get_sessionmaker()
    with SessionLocal() as db:
        db.execute(
            text(
                """
                INSERT INTO connectors_tenant_state (tenant_id, connector_id, enabled, config_hash, updated_by)
                VALUES (:tenant_id, '__policy__', 1, 'default', 'test')
                ON CONFLICT(tenant_id, connector_id)
                DO UPDATE SET config_hash='default', enabled=1, updated_by='test'
                """
            ),
            {"tenant_id": tenant_id},
        )
        db.commit()

def _contains_sensitive_keys(obj: object) -> bool:
    if isinstance(obj, dict):
        for key, value in obj.items():
            if str(key).lower() in SENSITIVE_STATUS_KEYS:
                return True
            if _contains_sensitive_keys(value):
                return True
    if isinstance(obj, list):
        for item in obj:
            if _contains_sensitive_keys(item):
                return True
    return False


def test_ingest_rejects_tenant_id_override_input() -> None:
    with _client() as client:
        key = mint_key("admin:write", ttl_seconds=3600, tenant_id="tenant-a")
        resp = client.post(
            "/internal/connectors/slack/ingest",
            headers={"x-api-key": key},
            json={"tenant_id": "tenant-b", "collection_id": "rag-default", "payload": {}},
        )
    assert resp.status_code == 422


def test_policy_missing_fail_closed() -> None:
    SessionLocal = get_sessionmaker()
    with SessionLocal() as db:
        db.execute(
            text(
                """
                INSERT INTO connectors_tenant_state (tenant_id, connector_id, enabled, config_hash, updated_by)
                VALUES ('tenant-a', '__policy__', 1, 'missing', 'test')
                """
            )
        )
        db.commit()

    with _client() as client:
        key = mint_key("admin:write", ttl_seconds=3600, tenant_id="tenant-a")
        resp = client.get("/admin/connectors/policy", headers={"x-api-key": key})
    assert resp.status_code == 403


def test_connector_cred_aad_binds_tenant_and_connector(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FG_CONNECTOR_KEK_CURRENT_VERSION", "v1")
    monkeypatch.setenv(
        "FG_CONNECTOR_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    )
    SessionLocal = get_sessionmaker()
    with SessionLocal() as db:
        upsert_credential(
            db,
            tenant_id="tenant-a",
            connector_id="slack",
            principal_id="user-1",
            auth_mode="oauth2",
            secret_payload={"token_hash": "abc"},
            credential_id="primary",
        )
        db.commit()

    with SessionLocal() as db:
        with pytest.raises(Exception):
            load_active_secret(
                db,
                tenant_id="tenant-b",
                connector_id="slack",
                principal_id="user-1",
                credential_id="primary",
            )


def test_status_contract_is_non_leaky() -> None:
    with _client() as client:
        key = mint_key("admin:write", ttl_seconds=3600, tenant_id="tenant-a")
        resp = client.get("/admin/connectors/status", headers={"x-api-key": key})
    assert resp.status_code == 200
    data = resp.json()
    assert not _contains_sensitive_keys(data)

    for connector in data["connectors"]:
        assert set(connector.keys()) == {
            "connector_id",
            "connected",
            "enabled",
            "last_success_at",
            "last_error_code",
            "health",
        }


def test_audit_ledger_emits_policy_set_and_revoke() -> None:
    _set_default_policy_for_tenant("tenant-a")
    with _client() as client:
        key = mint_key("admin:write", ttl_seconds=3600, tenant_id="tenant-a")
        set_resp = client.post(
            "/admin/connectors/policy",
            headers={"x-api-key": key, "Idempotency-Key": "idem-policy-1"},
            json={"version": "default"},
        )
        assert set_resp.status_code == 200

        revoke_resp = client.post(
            "/admin/connectors/slack/revoke",
            headers={"x-api-key": key, "Idempotency-Key": "idem-revoke-1"},
        )
        assert revoke_resp.status_code == 200

    SessionLocal = get_sessionmaker()
    with SessionLocal() as db:
        actions = db.execute(
            text(
                """
                SELECT action
                FROM connectors_audit_ledger
                WHERE tenant_id='tenant-a' AND action IN ('policy_set','credential_revoke')
                ORDER BY id
                """
            )
        ).fetchall()
    assert {row[0] for row in actions} == {"policy_set", "credential_revoke"}


def test_dispatch_deny_decision_has_deterministic_error_code() -> None:
    _set_default_policy_for_tenant("tenant-a")
    with _client() as client:
        key = mint_key("admin:write", ttl_seconds=3600, tenant_id="tenant-a")
        resp = client.post(
            "/internal/connectors/google_drive/ingest",
            headers={"x-api-key": key},
            json={"collection_id": "rag-default", "payload": {}},
        )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "CONNECTOR_DISABLED"


def test_creds_encrypted_and_kek_missing_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FG_CONNECTOR_KEK_CURRENT_VERSION", "v1")
    monkeypatch.setenv(
        "FG_CONNECTOR_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    )
    SessionLocal = get_sessionmaker()
    with SessionLocal() as db:
        upsert_credential(
            db,
            tenant_id="tenant-a",
            connector_id="slack",
            principal_id="user-2",
            auth_mode="oauth2",
            secret_payload={"token_hash": "abc"},
        )
        db.commit()

    monkeypatch.delenv("FG_CONNECTOR_KEK_V1", raising=False)
    with SessionLocal() as db:
        with pytest.raises(RuntimeError, match="connector KEK missing|missing KEK version"):
            load_active_secret(
                db,
                tenant_id="tenant-a",
                connector_id="slack",
                principal_id="user-2",
            )


def test_rls_expectations_present() -> None:
    sql = Path("migrations/postgres/0026_connectors_control_plane.sql").read_text(
        encoding="utf-8"
    )
    assert "ENABLE ROW LEVEL SECURITY" in sql
    assert "connectors_credentials_tenant_isolation" in sql
    assert "connectors_audit_ledger_tenant_isolation" in sql



def test_connector_routes_not_public_paths() -> None:
    from api.security.public_paths import PUBLIC_PATHS_EXACT, PUBLIC_PATHS_PREFIX

    all_public = set(PUBLIC_PATHS_EXACT) | set(PUBLIC_PATHS_PREFIX)
    assert not any(p.startswith("/admin/connectors") for p in all_public)
    assert not any(p.startswith("/internal/connectors") for p in all_public)
