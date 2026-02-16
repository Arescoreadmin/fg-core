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
    assert response.json()["detail"].lower() in {"tenant mismatch", "forbidden"}


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
    assert response.json()["detail"].lower() in {"tenant mismatch", "forbidden"}


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


def test_unscoped_key_cannot_search_any_tenant(audit_tenant_client):
    """Unscoped key is denied even with explicit tenant_id."""
    client = audit_tenant_client
    key_global = mint_key("audit:read", ttl_seconds=3600)  # No tenant_id

    # Search tenant-b's audit logs
    response = client.get(
        "/admin/audit/search",
        headers={"X-API-Key": key_global},
        params={"tenant_id": "tenant-b"},
    )

    assert response.status_code == 400


def test_unscoped_key_requires_tenant_id_for_search(audit_tenant_client):
    """Unscoped key without tenant_id returns 400 for search."""
    client = audit_tenant_client
    key_global = mint_key("audit:read", ttl_seconds=3600)  # No tenant_id

    # Search without tenant_id - should require explicit tenant_id
    response = client.get(
        "/admin/audit/search",
        headers={"X-API-Key": key_global},
    )

    # Should return 400 because unscoped keys must provide tenant_id
    assert response.status_code == 400
    assert response.json()["detail"] == "tenant_id required for unscoped keys"


def test_unscoped_key_requires_tenant_id_for_export(audit_tenant_client):
    """Unscoped key without tenant_id returns 400 for export."""
    client = audit_tenant_client
    key_global = mint_key("audit:read", ttl_seconds=3600)  # No tenant_id

    # Export without tenant_id - should require explicit tenant_id
    response = client.post(
        "/admin/audit/export",
        headers={"X-API-Key": key_global},
        json={"format": "json"},
    )

    # Should return 400 because unscoped keys must provide tenant_id
    assert response.status_code == 400
    assert response.json()["detail"] == "tenant_id required for unscoped keys"


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


# =============================================================================
# Export Header Tests
# =============================================================================


def test_export_csv_headers(audit_tenant_client):
    """CSV export has correct Content-Type and Content-Disposition headers."""
    client = audit_tenant_client
    key_a = mint_key("audit:read", ttl_seconds=3600, tenant_id="tenant-a")

    response = client.post(
        "/admin/audit/export",
        headers={"X-API-Key": key_a},
        json={"format": "csv", "tenant_id": "tenant-a"},
    )

    assert response.status_code == 200
    # Content-Type for CSV
    assert response.headers["content-type"] == "text/csv; charset=utf-8"
    # Content-Disposition includes filename with tenant and timestamp
    content_disp = response.headers["content-disposition"]
    assert content_disp.startswith('attachment; filename="audit-tenant-a-')
    assert content_disp.endswith('.csv"')


def test_export_ndjson_headers(audit_tenant_client):
    """NDJSON export has correct Content-Type and Content-Disposition headers."""
    client = audit_tenant_client
    key_a = mint_key("audit:read", ttl_seconds=3600, tenant_id="tenant-a")

    response = client.post(
        "/admin/audit/export",
        headers={"X-API-Key": key_a},
        json={"format": "json", "tenant_id": "tenant-a"},
    )

    assert response.status_code == 200
    # Content-Type for NDJSON
    assert response.headers["content-type"] == "application/x-ndjson"
    # Content-Disposition includes filename with tenant and timestamp
    content_disp = response.headers["content-disposition"]
    assert content_disp.startswith('attachment; filename="audit-tenant-a-')
    assert content_disp.endswith('.json"')


def test_export_filename_includes_tenant_and_timestamp(audit_tenant_client):
    """Export filename contains tenant_id and ISO timestamp pattern."""
    import re

    client = audit_tenant_client
    key_a = mint_key("audit:read", ttl_seconds=3600, tenant_id="tenant-a")

    response = client.post(
        "/admin/audit/export",
        headers={"X-API-Key": key_a},
        json={"format": "json", "tenant_id": "tenant-a"},
    )

    assert response.status_code == 200
    content_disp = response.headers["content-disposition"]
    # Pattern: audit-{tenant_id}-{YYYYMMDDTHHMMSSZ}.json
    pattern = r'attachment; filename="audit-tenant-a-\d{8}T\d{6}Z\.json"'
    assert re.match(pattern, content_disp), (
        f"Unexpected Content-Disposition: {content_disp}"
    )


def test_unscoped_key_export_with_explicit_tenant_denied(audit_tenant_client):
    """Unscoped key export is denied even when tenant_id is supplied."""
    client = audit_tenant_client
    key_global = mint_key("audit:read", ttl_seconds=3600)  # No tenant_id

    # Export with explicit tenant_id should still be denied
    response = client.post(
        "/admin/audit/export",
        headers={"X-API-Key": key_global},
        json={"format": "json", "tenant_id": "tenant-b"},
    )

    assert response.status_code == 400


def test_invalid_tenant_id_format_returns_400(audit_tenant_client):
    """Invalid tenant_id format returns 400."""
    client = audit_tenant_client
    key_global = mint_key("audit:read", ttl_seconds=3600)  # No tenant_id

    # Search with invalid tenant_id format
    response = client.get(
        "/admin/audit/search",
        headers={"X-API-Key": key_global},
        params={"tenant_id": "tenant@invalid!"},
    )

    assert response.status_code == 400
    assert "invalid" in response.json()["detail"].lower()
