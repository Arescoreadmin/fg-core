import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key
from api.db import init_db, reset_engine_cache
from api.db_models import SecurityAuditLog


@pytest.fixture
def audit_client(tmp_path, monkeypatch):
    db_path = tmp_path / "audit.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_API_KEY", "")
    monkeypatch.setenv("FG_AUDIT_REDACT", "true")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))

    from api.main import app

    client = TestClient(app)
    api_key = mint_key("audit:read", ttl_seconds=3600, tenant_id="tenant-a")
    return client, api_key


def test_unscoped_key_denied_for_audit_search(audit_client):
    """Unscoped key is denied for tenant-scoped audit search."""
    client, _ = audit_client
    api_key = mint_key("audit:read", ttl_seconds=3600)
    response = client.get(
        "/admin/audit/search",
        headers={"X-API-Key": api_key},
        params={"tenant_id": "tenant-a"},
    )
    assert response.status_code == 400
    assert "tenant_id required" in response.json()["detail"]


def test_audit_filters_by_tenant(audit_client):
    client, api_key = audit_client

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
                ),
                SecurityAuditLog(
                    event_type="auth_failure",
                    event_category="security",
                    severity="warning",
                    tenant_id="tenant-a",
                    success=False,
                ),
            ]
        )
        session.commit()

    response = client.get(
        "/admin/audit/search",
        headers={"X-API-Key": api_key},
        params={"tenant_id": "tenant-a"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert all(item["tenant_id"] == "tenant-a" for item in payload["items"])


def test_audit_redacts_sensitive_details_and_ip(audit_client):
    client, api_key = audit_client

    from api.db import get_engine
    from sqlalchemy.orm import Session

    engine = get_engine()
    with Session(engine) as session:
        session.add(
            SecurityAuditLog(
                event_type="auth_success",
                event_category="security",
                severity="info",
                tenant_id="tenant-a",
                success=True,
                client_ip="192.168.1.10",
                user_agent="agent",
                details_json={
                    "authorization": "Bearer secret",
                    "nested": {"token": "secret-token"},
                    "safe": "ok",
                },
            )
        )
        session.commit()

    response = client.get(
        "/admin/audit/search",
        headers={"X-API-Key": api_key},
        params={"tenant_id": "tenant-a"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["items"]
    event = payload["items"][0]
    details = event["meta"]["details"]
    assert details["authorization"] == "[REDACTED]"
    assert details["nested"]["token"] == "[REDACTED]"
    assert details["safe"] == "ok"
    assert event["ip"] is None
    assert event["user_agent"] is None


def test_audit_pagination_is_stable(audit_client):
    client, api_key = audit_client

    from api.db import get_engine
    from sqlalchemy.orm import Session

    base_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    engine = get_engine()
    with Session(engine) as session:
        session.add_all(
            [
                SecurityAuditLog(
                    event_type="event_a",
                    event_category="security",
                    severity="info",
                    tenant_id="tenant-a",
                    success=True,
                    created_at=base_time + timedelta(seconds=1),
                ),
                SecurityAuditLog(
                    event_type="event_b",
                    event_category="security",
                    severity="info",
                    tenant_id="tenant-a",
                    success=True,
                    created_at=base_time + timedelta(seconds=2),
                ),
                SecurityAuditLog(
                    event_type="event_c",
                    event_category="security",
                    severity="info",
                    tenant_id="tenant-a",
                    success=True,
                    created_at=base_time + timedelta(seconds=3),
                ),
            ]
        )
        session.commit()

    first = client.get(
        "/admin/audit/search",
        headers={"X-API-Key": api_key},
        params={"page_size": 1},
    )
    assert first.status_code == 200
    first_payload = first.json()
    assert first_payload["items"][0]["action"] == "event_c"
    cursor = first_payload["next_cursor"]

    second = client.get(
        "/admin/audit/search",
        headers={"X-API-Key": api_key},
        params={"page_size": 1, "cursor": cursor},
    )
    assert second.status_code == 200
    second_payload = second.json()
    assert second_payload["items"][0]["action"] == "event_b"


def test_audit_contract_endpoints_present():
    from pathlib import Path

    spec = json.loads(Path("contracts/admin/openapi.json").read_text())
    assert "/admin/audit/search" in spec["paths"]
    assert "/admin/audit/export" in spec["paths"]

    export = spec["paths"]["/admin/audit/export"]["post"]["responses"]["200"]
    content = export["content"]
    assert "text/csv" in content
    assert "application/x-ndjson" in content
    headers = export["headers"]
    assert "Content-Disposition" in headers
    assert "Content-Type" in headers


def test_audit_export_csv(audit_client):
    client, api_key = audit_client

    from api.db import get_engine
    from sqlalchemy.orm import Session

    engine = get_engine()
    with Session(engine) as session:
        session.add(
            SecurityAuditLog(
                event_type="auth_success",
                event_category="security",
                severity="info",
                tenant_id="tenant-a",
                success=True,
                details_json=json.dumps({"note": "ok"}),
            )
        )
        session.commit()

    response = client.post(
        "/admin/audit/export",
        headers={"X-API-Key": api_key},
        json={"format": "csv"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "action" in response.text


def test_audit_export_redacts_ip_user_agent(audit_client):
    client, api_key = audit_client

    from api.db import get_engine
    from sqlalchemy.orm import Session

    engine = get_engine()
    with Session(engine) as session:
        session.add(
            SecurityAuditLog(
                event_type="auth_failure",
                event_category="security",
                severity="warning",
                tenant_id="tenant-a",
                success=False,
                client_ip="10.0.0.1",
                user_agent="test-agent",
            )
        )
        session.commit()

    response = client.post(
        "/admin/audit/export",
        headers={"X-API-Key": api_key},
        json={"format": "json"},
    )
    assert response.status_code == 200
    lines = [line for line in response.text.splitlines() if line]
    payload = json.loads(lines[0])
    assert payload["ip"] is None
    assert payload["user_agent"] is None
