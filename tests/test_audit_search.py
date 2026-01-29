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
    api_key = mint_key("audit:read", ttl_seconds=3600)
    return client, api_key


def test_audit_requires_tenant_filter(audit_client):
    client, api_key = audit_client
    response = client.get("/admin/audit", headers={"X-API-Key": api_key})
    assert response.status_code == 400
    assert response.json()["detail"] == "tenant_id or tenant_ids is required"


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
                    tenant_id="tenant-b",
                    success=False,
                ),
            ]
        )
        session.commit()

    response = client.get(
        "/admin/audit",
        headers={"X-API-Key": api_key},
        params={"tenant_id": "tenant-a"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert all(event["tenant_id"] == "tenant-a" for event in payload["events"])


def test_audit_redacts_sensitive_details(audit_client):
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
                tenant_id="tenant-1",
                success=True,
                details_json={
                    "authorization": "Bearer secret",
                    "nested": {"token": "secret-token"},
                    "safe": "ok",
                },
            )
        )
        session.commit()

    response = client.get(
        "/admin/audit",
        headers={"X-API-Key": api_key},
        params={"tenant_id": "tenant-1"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["events"]
    details = payload["events"][0]["details"]
    assert details["authorization"] == "[REDACTED]"
    assert details["nested"]["token"] == "[REDACTED]"
    assert details["safe"] == "ok"


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
                    tenant_id="tenant-3",
                    success=True,
                    created_at=base_time + timedelta(seconds=1),
                ),
                SecurityAuditLog(
                    event_type="event_b",
                    event_category="security",
                    severity="info",
                    tenant_id="tenant-3",
                    success=True,
                    created_at=base_time + timedelta(seconds=2),
                ),
                SecurityAuditLog(
                    event_type="event_c",
                    event_category="security",
                    severity="info",
                    tenant_id="tenant-3",
                    success=True,
                    created_at=base_time + timedelta(seconds=3),
                ),
            ]
        )
        session.commit()

    response = client.get(
        "/admin/audit",
        headers={"X-API-Key": api_key},
        params={"tenant_id": "tenant-3", "limit": 1, "offset": 1},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["events"][0]["event_type"] == "event_b"


def test_audit_contract_endpoints_present():
    from pathlib import Path

    spec = json.loads(Path("contracts/admin/openapi.json").read_text())
    assert "/admin/audit" in spec["paths"]
    assert "/admin/audit/export" in spec["paths"]


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
                tenant_id="tenant-2",
                success=True,
                details_json=json.dumps({"note": "ok"}),
            )
        )
        session.commit()

    response = client.get(
        "/admin/audit/export",
        headers={"X-API-Key": api_key},
        params={"tenant_id": "tenant-2", "format": "csv"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "event_type" in response.text
