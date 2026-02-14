from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.db import get_engine
from api.db_models import SecurityAuditLog
from api.security_audit import AuditPersistenceError, audit_admin_action


def test_admin_audit_records_required_fields(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("admin:write", tenant_id="tenant-a")

    resp = client.put(
        "/admin/tenants/tenant-a/quota",
        headers={"X-API-Key": key},
        json={"quota": 1200},
    )
    assert resp.status_code == 200

    engine = get_engine()
    with Session(engine) as session:
        row = session.execute(
            select(SecurityAuditLog)
            .where(SecurityAuditLog.event_type == "admin_action")
            .where(SecurityAuditLog.reason == "tenant_quota_updated")
            .order_by(SecurityAuditLog.id.desc())
        ).scalar_one()

    details = row.details_json or {}
    assert details.get("actor_id")
    assert details.get("scope")
    assert details.get("action") == "tenant_quota_updated"
    assert details.get("correlation_id")
    assert details.get("timestamp")


def test_admin_audit_missing_required_fields_raises():
    try:
        audit_admin_action(action="test-action", request=None, tenant_id="tenant-a")
    except AuditPersistenceError as exc:
        assert exc.code == "FG-AUDIT-ADMIN-001"
    else:
        raise AssertionError(
            "expected AuditPersistenceError for missing required fields"
        )
