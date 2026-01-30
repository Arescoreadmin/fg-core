"""Tests for admin audit endpoint tenant binding security."""

import json

import pytest
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key
from api.db import init_db, reset_engine_cache
from api.db_models import SecurityAuditLog


@pytest.fixture
def audit_tenant_client(tmp_path, monkeypatch):
    """Set up test client with audit data for multiple tenants."""
    db_path = tmp_path / "audit_tenant.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_API_KEY", "")
    monkeypatch.setenv("FG_AUDIT_REDACT", "true")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))

    from api.main import app

    client = TestClient(app)

    # Insert audit records for multiple tenants
    from api.db import get_engine
    from sqlalchemy.orm import Session

    engine = get_engine()
    with Session(engine) as session:
        session.add_all(
            [
                SecurityAuditLog(
                    event_type="auth_success",
                    event_category="security",
                    severity="info",
                    tenant_id="tenant-a",
                    success=True,
                    client_ip="10.0.0.1",
                    user_agent="agent-a",
                ),
                SecurityAuditLog(
                    event_type="auth_failure",
                    event_category="security",
                    severity="warning",
                    tenant_id="tenant-b",
                    success=False,
                    client_ip="10.0.0.2",
                    user_agent="agent-b",
                ),
                SecurityAuditLog(
                    event_type="key_created",
                    event_category="admin",
                    severity="info",
                    tenant_id="tenant-a",
                    success=True,
                ),
            ]
        )
        session.commit()

    return client


def test_scoped_key_cannot_search_other_tenant(audit_tenant_client):
    """Tenant-scoped key searching another tenant's audit logs returns 403."""
    client = audit_tenant_client
    key_a = mint_key("audit:read", ttl_seconds=3600, tenant_id="tenant-a")

    # Try to search tenant-b's audit logs with tenant-a's key
    response = client.get(
        "/admin/audit/search",
        headers={"X-API-Key": key_a},
        params={"tenant_id": "tenant-b"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Tenant mismatch"


def test_scoped_key_cannot_export_other_tenant(audit_tenant_client):
    """Tenant-scoped key exporting another tenant's audit logs returns 403."""
    client = audit_tenant_client
    key_a = mint_key("audit:read", ttl_seconds=3600, tenant_id="tenant-a")

    # Try to export tenant-b's audit logs with tenant-a's key
    response = client.post(
        "/admin/audit/export",
        headers={"X-API-Key": key_a},
        json={"tenant_id": "tenant-b", "format": "json"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Tenant mismatch"


def test_scoped_key_search_uses_auth_tenant_when_omitted(audit_tenant_client):
    """When tenant_id is omitted, scoped key uses its bound tenant."""
    client = audit_tenant_client
    key_a = mint_key("audit:read", ttl_seconds=3600, tenant_id="tenant-a")

    # Search without tenant_id - should use tenant-a from auth context
    response = client.get(
        "/admin/audit/search",
        headers={"X-API-Key": key_a},
    )

    assert response.status_code == 200
    payload = response.json()
    # All returned items should be for tenant-a only (not tenant-b)
    assert len(payload["items"]) > 0
    assert all(item["tenant_id"] == "tenant-a" for item in payload["items"])


def test_scoped_key_export_uses_auth_tenant_when_omitted(audit_tenant_client):
    """When tenant_id is omitted in export, scoped key uses its bound tenant."""
    client = audit_tenant_client
    key_a = mint_key("audit:read", ttl_seconds=3600, tenant_id="tenant-a")

    # Export without tenant_id - should use tenant-a from auth context
    response = client.post(
        "/admin/audit/export",
        headers={"X-API-Key": key_a},
        json={"format": "json"},
    )

    assert response.status_code == 200
    lines = [line for line in response.text.splitlines() if line]
    # Should have items only for tenant-a (not tenant-b)
    assert len(lines) > 0
    for line in lines:
        event = json.loads(line)
        assert event["tenant_id"] == "tenant-a"


def test_scoped_key_can_search_own_tenant_explicitly(audit_tenant_client):
    """Tenant-scoped key can explicitly request its own tenant."""
    client = audit_tenant_client
    key_a = mint_key("audit:read", ttl_seconds=3600, tenant_id="tenant-a")

    # Search with explicit tenant_id matching auth tenant
    response = client.get(
        "/admin/audit/search",
        headers={"X-API-Key": key_a},
        params={"tenant_id": "tenant-a"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert all(item["tenant_id"] == "tenant-a" for item in payload["items"])


def test_unscoped_key_can_search_any_tenant(audit_tenant_client):
    """Unscoped key (global admin) can search any tenant."""
    client = audit_tenant_client
    key_global = mint_key("audit:read", ttl_seconds=3600)  # No tenant_id

    # Search tenant-b's audit logs
    response = client.get(
        "/admin/audit/search",
        headers={"X-API-Key": key_global},
        params={"tenant_id": "tenant-b"},
    )

    assert response.status_code == 200
    payload = response.json()
    # All items should be for tenant-b only
    assert len(payload["items"]) > 0
    assert all(item["tenant_id"] == "tenant-b" for item in payload["items"])


def test_unscoped_key_defaults_to_unknown_tenant(audit_tenant_client):
    """Unscoped key without tenant_id defaults to 'unknown' tenant."""
    client = audit_tenant_client
    key_global = mint_key("audit:read", ttl_seconds=3600)  # No tenant_id

    # Search without tenant_id - should default to 'unknown'
    response = client.get(
        "/admin/audit/search",
        headers={"X-API-Key": key_global},
    )

    # Should return 200 (searching for 'unknown' tenant, which may have no records)
    assert response.status_code == 200
    payload = response.json()
    # No records for 'unknown' tenant in our test data
    assert len(payload["items"]) == 0


def test_audit_search_redacts_ip_and_user_agent(audit_tenant_client):
    """Audit search redacts IP and user agent when FG_AUDIT_REDACT is set."""
    client = audit_tenant_client
    key_a = mint_key("audit:read", ttl_seconds=3600, tenant_id="tenant-a")

    response = client.get(
        "/admin/audit/search",
        headers={"X-API-Key": key_a},
        params={"tenant_id": "tenant-a"},
    )

    assert response.status_code == 200
    payload = response.json()
    for item in payload["items"]:
        # IP and user_agent should be redacted (null)
        assert item["ip"] is None
        assert item["user_agent"] is None


def test_audit_export_redacts_ip_and_user_agent(audit_tenant_client):
    """Audit export redacts IP and user agent when FG_AUDIT_REDACT is set."""
    client = audit_tenant_client
    key_a = mint_key("audit:read", ttl_seconds=3600, tenant_id="tenant-a")

    response = client.post(
        "/admin/audit/export",
        headers={"X-API-Key": key_a},
        json={"tenant_id": "tenant-a", "format": "json"},
    )

    assert response.status_code == 200
    lines = [line for line in response.text.splitlines() if line]
    for line in lines:
        event = json.loads(line)
        assert event["ip"] is None
        assert event["user_agent"] is None


def test_missing_api_key_returns_401(audit_tenant_client):
    """Missing API key returns 401 Unauthorized."""
    client = audit_tenant_client

    response = client.get(
        "/admin/audit/search",
        params={"tenant_id": "tenant-a"},
    )

    assert response.status_code == 401


def test_invalid_api_key_returns_401(audit_tenant_client):
    """Invalid API key returns 401 Unauthorized."""
    client = audit_tenant_client

    response = client.get(
        "/admin/audit/search",
        headers={"X-API-Key": "invalid-key"},
        params={"tenant_id": "tenant-a"},
    )

    assert response.status_code == 401


def test_key_without_audit_scope_returns_403(audit_tenant_client):
    """Valid key without audit:read scope returns 403 Forbidden."""
    client = audit_tenant_client
    # Key with a different scope
    key_no_audit = mint_key("admin:read", ttl_seconds=3600, tenant_id="tenant-a")

    response = client.get(
        "/admin/audit/search",
        headers={"X-API-Key": key_no_audit},
        params={"tenant_id": "tenant-a"},
    )

    assert response.status_code == 403
