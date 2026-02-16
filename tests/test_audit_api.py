from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.db import get_engine
from api.db_models import AuditExportJob
from services.audit_engine.engine import append_audit_record


def _auth_headers(key: str, extra: dict[str, str] | None = None):
    headers = {"X-API-Key": key}
    if extra:
        headers.update(extra)
    return headers


def test_audit_scope_enforcement(build_app):
    app = build_app()
    client = TestClient(app)

    read_key = mint_key("audit:read", tenant_id="tenant-a")
    export_key = mint_key("audit:export", tenant_id="tenant-a")

    res = client.get("/audit/sessions?tenant_id=tenant-a", headers=_auth_headers(read_key))
    assert res.status_code == 200

    now = datetime.now(tz=UTC)
    start = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    end = now.isoformat().replace("+00:00", "Z")
    denied = client.get(
        f"/audit/export?tenant_id=tenant-a&start={start}&end={end}",
        headers=_auth_headers(read_key),
    )
    assert denied.status_code == 403
    allowed = client.get(
        f"/audit/export?tenant_id=tenant-a&start={start}&end={end}",
        headers=_auth_headers(export_key),
    )
    assert allowed.status_code == 200


def test_bypass_requires_reason_ticket_and_ttl(build_app, monkeypatch):
    monkeypatch.setenv("FG_AUDIT_RATE_LIMIT_RPS", "0.0001")
    monkeypatch.setenv("FG_AUDIT_RATE_LIMIT_BURST", "1")
    app = build_app()
    client = TestClient(app)

    key = mint_key("audit:export", "audit:auditor", tenant_id="tenant-a")
    engine = get_engine()
    with Session(engine) as db:
        append_audit_record(db, tenant_id="tenant-a", invariant_id="soc-invariants", decision="pass", config_hash="a" * 64, policy_hash="b" * 64)
        db.commit()

    now = datetime.now(tz=UTC)
    start = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    end = now.isoformat().replace("+00:00", "Z")
    missing = client.get(
        f"/audit/export?tenant_id=tenant-a&start={start}&end={end}",
        headers=_auth_headers(key),
    )
    assert missing.status_code == 400

    ok = client.get(
        f"/audit/export?tenant_id=tenant-a&start={start}&end={end}",
        headers=_auth_headers(
            key,
            {
                "X-Audit-Bypass-Reason": "incident",
                "X-Audit-Bypass-Ticket": "INC-1",
                "X-Audit-Bypass-TTL-Seconds": "60",
            },
        ),
    )
    assert ok.status_code == 200


def test_retention_dry_run_and_apply_confirmation(build_app):
    app = build_app()
    client = TestClient(app)

    export_key = mint_key("audit:export", tenant_id="tenant-a")
    engine = get_engine()
    with Session(engine) as db:
        append_audit_record(db, tenant_id="tenant-a", invariant_id="soc-invariants", decision="pass", config_hash="a" * 64, policy_hash="b" * 64)
        db.commit()

    dry = client.post(
        "/audit/retention/apply?tenant_id=tenant-a",
        headers=_auth_headers(export_key),
        json={"retention_days": 0, "dry_run": True, "reason_code": "policy", "ticket_id": "RET-1"},
    )
    assert dry.status_code == 200
    token = dry.json()["confirmation_token"]

    bad = client.post(
        "/audit/retention/apply?tenant_id=tenant-a",
        headers=_auth_headers(export_key),
        json={"retention_days": 0, "dry_run": False, "reason_code": "policy", "ticket_id": "RET-1", "confirmation_token": "bad"},
    )
    assert bad.status_code == 409

    good = client.post(
        "/audit/retention/apply?tenant_id=tenant-a",
        headers=_auth_headers(export_key),
        json={"retention_days": 0, "dry_run": False, "reason_code": "policy", "ticket_id": "RET-1", "confirmation_token": token},
    )
    assert good.status_code == 200


def test_ui_audit_endpoints_scoped(build_app):
    app = build_app()
    client = TestClient(app)
    key = mint_key("audit:read", tenant_id="tenant-a")

    resp = client.get("/ui/audit/overview?tenant_id=tenant-a", headers=_auth_headers(key))
    assert resp.status_code == 200
    cross = client.get("/ui/audit/overview?tenant_id=tenant-b", headers=_auth_headers(key))
    assert cross.status_code == 403


def test_export_job_cancel_endpoint(build_app):
    app = build_app()
    client = TestClient(app)

    export_key = mint_key("audit:export", tenant_id="tenant-a")
    now = datetime.now(tz=UTC)
    start = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    end = now.isoformat().replace("+00:00", "Z")

    create = client.post(
        "/audit/export-jobs?tenant_id=tenant-a",
        headers=_auth_headers(export_key),
        json={"start": start, "end": end, "purpose": "audit", "retention_class": "regulated"},
    )
    assert create.status_code == 200
    job_id = create.json()["job_id"]

    cancel = client.post(
        f"/audit/export-jobs/{job_id}/cancel?tenant_id=tenant-a",
        headers=_auth_headers(export_key),
        json={"reason": "OPERATOR_ERROR", "ticket_id": "OPS-123", "notes": "manual stop"},
    )
    assert cancel.status_code == 200
    assert cancel.json() == {"job_id": job_id, "status": "cancelled", "error_code": None}

    run = client.post(f"/audit/export-jobs/{job_id}/run?tenant_id=tenant-a", headers=_auth_headers(export_key))
    assert run.status_code == 409
    assert run.json()["detail"] == {"job_id": job_id, "status": "cancelled", "error_code": "AUDIT_EXPORT_JOB_CANCELLED"}



def test_export_job_cancel_scope_and_tenant_isolation(build_app):
    app = build_app()
    client = TestClient(app)

    export_key_a = mint_key("audit:export", tenant_id="tenant-a")
    export_key_b = mint_key("audit:export", tenant_id="tenant-b")
    read_key_a = mint_key("audit:read", tenant_id="tenant-a")

    now = datetime.now(tz=UTC)
    start = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    end = now.isoformat().replace("+00:00", "Z")

    create = client.post(
        "/audit/export-jobs?tenant_id=tenant-a",
        headers=_auth_headers(export_key_a),
        json={"start": start, "end": end, "purpose": "audit", "retention_class": "regulated"},
    )
    assert create.status_code == 200
    job_id = create.json()["job_id"]

    forbidden_scope = client.post(
        f"/audit/export-jobs/{job_id}/cancel?tenant_id=tenant-a",
        headers=_auth_headers(read_key_a),
        json={"reason": "OPERATOR_ERROR", "ticket_id": "OPS-403"},
    )
    assert forbidden_scope.status_code == 403

    cross_tenant = client.post(
        f"/audit/export-jobs/{job_id}/cancel?tenant_id=tenant-a",
        headers=_auth_headers(export_key_b),
        json={"reason": "OPERATOR_ERROR", "ticket_id": "OPS-404"},
    )
    assert cross_tenant.status_code == 403



def test_export_job_cancel_requires_owner_or_admin_or_bypass(build_app):
    app = build_app()
    client = TestClient(app)

    owner_key = mint_key("audit:export", tenant_id="tenant-a")
    other_key = mint_key("audit:export", tenant_id="tenant-a")
    admin_key = mint_key("audit:export", "audit:admin", tenant_id="tenant-a")
    bypass_key = mint_key("audit:export", "audit:auditor_bypass", tenant_id="tenant-a")

    now = datetime.now(tz=UTC)
    start = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    end = now.isoformat().replace("+00:00", "Z")

    create = client.post(
        "/audit/export-jobs?tenant_id=tenant-a",
        headers=_auth_headers(owner_key),
        json={"start": start, "end": end, "purpose": "audit", "retention_class": "regulated"},
    )
    assert create.status_code == 200
    job_id = create.json()["job_id"]

    engine = get_engine()
    with Session(engine) as db:
        row = db.query(AuditExportJob).filter(AuditExportJob.job_id == job_id).one()
        row.triggered_by = "known-owner"
        db.commit()

    denied = client.post(
        f"/audit/export-jobs/{job_id}/cancel?tenant_id=tenant-a",
        headers=_auth_headers(other_key),
        json={"reason": "OPERATOR_ERROR", "ticket_id": "OPS-900"},
    )
    assert denied.status_code == 403

    admin_ok = client.post(
        f"/audit/export-jobs/{job_id}/cancel?tenant_id=tenant-a",
        headers=_auth_headers(admin_key),
        json={"reason": "OPERATOR_ERROR", "ticket_id": "OPS-901"},
    )
    assert admin_ok.status_code == 200

    create2 = client.post(
        "/audit/export-jobs?tenant_id=tenant-a",
        headers=_auth_headers(owner_key),
        json={"start": start, "end": end, "purpose": "audit", "retention_class": "regulated", "force": True},
    )
    assert create2.status_code == 200
    job2 = create2.json()["job_id"]
    bypass_ok = client.post(
        f"/audit/export-jobs/{job2}/cancel?tenant_id=tenant-a",
        headers=_auth_headers(bypass_key),
        json={"reason": "SECURITY_INCIDENT", "ticket_id": "OPS-902"},
    )
    assert bypass_ok.status_code == 200


def test_export_job_cancel_ticket_required_in_prod(build_app, monkeypatch):
    monkeypatch.setenv("FG_AUDIT_CANCEL_REQUIRE_TICKET_NONPROD", "1")
    app = build_app()
    client = TestClient(app)

    export_key = mint_key("audit:export", tenant_id="tenant-a")
    now = datetime.now(tz=UTC)
    start = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    end = now.isoformat().replace("+00:00", "Z")

    create = client.post(
        "/audit/export-jobs?tenant_id=tenant-a",
        headers=_auth_headers(export_key),
        json={"start": start, "end": end, "purpose": "audit", "retention_class": "regulated", "force": True},
    )
    assert create.status_code == 200
    job_id = create.json()["job_id"]

    missing = client.post(
        f"/audit/export-jobs/{job_id}/cancel?tenant_id=tenant-a",
        headers=_auth_headers(export_key),
        json={"reason": "OPERATOR_ERROR"},
    )
    assert missing.status_code == 400
    assert missing.json()["detail"]["error_code"] == "AUDIT_EXPORT_JOB_TICKET_REQUIRED"



def test_export_job_cancel_reason_enum_validation(build_app):
    app = build_app()
    client = TestClient(app)
    key = mint_key("audit:export", tenant_id="tenant-a")
    now = datetime.now(tz=UTC)
    start = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    end = now.isoformat().replace("+00:00", "Z")
    create = client.post(
        "/audit/export-jobs?tenant_id=tenant-a",
        headers=_auth_headers(key),
        json={"start": start, "end": end, "purpose": "audit", "retention_class": "regulated", "force": True},
    )
    assert create.status_code == 200
    job_id = create.json()["job_id"]

    bad = client.post(
        f"/audit/export-jobs/{job_id}/cancel?tenant_id=tenant-a",
        headers=_auth_headers(key),
        json={"reason": "freeform", "ticket_id": "OPS-1"},
    )
    assert bad.status_code == 400
    assert bad.json()["detail"]["error_code"] == "AUDIT_EXPORT_JOB_BAD_REQUEST"

    other_without_notes = client.post(
        f"/audit/export-jobs/{job_id}/cancel?tenant_id=tenant-a",
        headers=_auth_headers(key),
        json={"reason": "OTHER", "ticket_id": "OPS-2", "notes": ""},
    )
    assert other_without_notes.status_code == 400


def test_export_job_cancel_normal_rate_limit(build_app, monkeypatch):
    monkeypatch.setenv("FG_AUDIT_CANCEL_RATE_LIMIT_RPS", "0.0001")
    monkeypatch.setenv("FG_AUDIT_CANCEL_RATE_LIMIT_BURST", "1")
    app = build_app()
    client = TestClient(app)
    key = mint_key("audit:export", tenant_id="tenant-a")
    now = datetime.now(tz=UTC)
    start = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    end = now.isoformat().replace("+00:00", "Z")

    create = client.post("/audit/export-jobs?tenant_id=tenant-a", headers=_auth_headers(key), json={"start": start, "end": end, "purpose": "audit", "retention_class": "regulated", "force": True})
    assert create.status_code == 200
    job1 = create.json()["job_id"]
    one = client.post(f"/audit/export-jobs/{job1}/cancel?tenant_id=tenant-a", headers=_auth_headers(key), json={"reason": "OPERATOR_ERROR", "ticket_id": "OPS-11"})
    assert one.status_code == 200

    create2 = client.post("/audit/export-jobs?tenant_id=tenant-a", headers=_auth_headers(key), json={"start": start, "end": end, "purpose": "audit", "retention_class": "regulated", "force": False})
    assert create2.status_code == 200
    job2 = create2.json()["job_id"]
    two = client.post(f"/audit/export-jobs/{job2}/cancel?tenant_id=tenant-a", headers=_auth_headers(key), json={"reason": "OPERATOR_ERROR", "ticket_id": "OPS-12"})
    assert two.status_code == 429
    assert two.json()["detail"]["error_code"] == "AUDIT_EXPORT_JOB_RATE_LIMIT"

