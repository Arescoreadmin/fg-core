from __future__ import annotations

from datetime import datetime, timezone
import json

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.db import get_engine
from api.db_models import DecisionRecord, SecurityAuditLog


def test_ui_cross_tenant_returns_404_and_logs_forensics(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", tenant_id="tenant-a")

    engine = get_engine()
    with Session(engine) as session:
        row = DecisionRecord(
            tenant_id="tenant-b",
            source="unit-test",
            event_id="evt-cross-tenant",
            event_type="auth.bruteforce",
            threat_level="low",
            anomaly_score=0.1,
            ai_adversarial_score=0.0,
            pq_fallback=False,
            rules_triggered_json=["rule-1"],
            decision_diff_json={"summary": "allow"},
            request_json={"request_id": "req-1"},
            response_json={"policy_version": "v1"},
            created_at=datetime.now(timezone.utc),
        )
        session.add(row)
        session.commit()
        decision_id = int(row.id)

    resp = client.get(f"/ui/decision/{decision_id}", headers={"X-API-Key": key})
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Decision not found"

    with Session(engine) as session:
        record = session.execute(
            select(SecurityAuditLog)
            .where(SecurityAuditLog.event_type == "admin_action")
            .where(SecurityAuditLog.reason == "cross_tenant_access_denied")
            .order_by(SecurityAuditLog.id.desc())
        ).scalar_one()

    details = record.details_json or {}
    assert details["deny_bucket"] == "tenant_not_found"
    assert details["action"] == "ui_decision_detail"
    assert details["target_tenant_id"] == "tenant-b"


def test_admin_config_change_snapshot_and_revert(build_app, monkeypatch, tmp_path):
    monkeypatch.setenv("FG_CONFIG_CHANGE_DIR", str(tmp_path / "config_changes"))

    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("admin:write", tenant_id="tenant-a")

    update_resp = client.put(
        "/admin/tenants/tenant-a/quota",
        headers={"X-API-Key": key},
        json={"quota": 777},
    )
    assert update_resp.status_code == 200
    change_id = update_resp.json()["config_change_id"]

    artifact = tmp_path / "config_changes" / f"{change_id}.json"
    assert artifact.exists()
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["tenant_id"] == "tenant-a"
    assert payload["field"] == "custom_quota"
    assert payload["after"] == 777
    assert payload["revert_supported"] is True

    revert_resp = client.post(
        f"/admin/config/changes/{change_id}/revert",
        headers={"X-API-Key": key},
    )
    assert revert_resp.status_code == 200
    body = revert_resp.json()
    assert body["success"] is True
    assert body["change_id"] == change_id
    assert body["tenant_id"] == "tenant-a"


def test_ui_decision_not_found_bucket_consistency(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", tenant_id="tenant-a")

    engine = get_engine()
    with Session(engine) as session:
        row = DecisionRecord(
            tenant_id="tenant-b",
            source="unit-test",
            event_id="evt-consistency",
            event_type="auth.bruteforce",
            threat_level="low",
            anomaly_score=0.1,
            ai_adversarial_score=0.0,
            pq_fallback=False,
            rules_triggered_json=["rule-1"],
            decision_diff_json={"summary": "allow"},
            request_json={"request_id": "req-1"},
            response_json={"policy_version": "v1"},
            created_at=datetime.now(timezone.utc),
        )
        session.add(row)
        session.commit()
        existing_id = int(row.id)

    wrong_tenant = client.get(f"/ui/decision/{existing_id}", headers={"X-API-Key": key})
    not_found = client.get("/ui/decision/999999", headers={"X-API-Key": key})

    assert wrong_tenant.status_code == 404
    assert not_found.status_code == 404
    assert wrong_tenant.json()["detail"] == not_found.json()["detail"] == "Decision not found"
    assert "request_id" in wrong_tenant.json()
    assert "request_id" in not_found.json()


def test_admin_config_snapshot_tamper_detected(build_app, monkeypatch, tmp_path):
    monkeypatch.setenv("FG_CONFIG_CHANGE_DIR", str(tmp_path / "config_changes"))

    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("admin:write", tenant_id="tenant-a")

    update_resp = client.put(
        "/admin/tenants/tenant-a/quota",
        headers={"X-API-Key": key},
        json={"quota": 1001},
    )
    assert update_resp.status_code == 200
    change_id = update_resp.json()["config_change_id"]

    artifact = tmp_path / "config_changes" / f"{change_id}.json"
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    payload["after"] = 9999
    artifact.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    revert_resp = client.post(
        f"/admin/config/changes/{change_id}/revert",
        headers={"X-API-Key": key},
    )
    assert revert_resp.status_code == 409
    assert "integrity" in revert_resp.json()["detail"].lower()


def test_admin_config_revert_rejects_stale_state(build_app, monkeypatch, tmp_path):
    monkeypatch.setenv("FG_CONFIG_CHANGE_DIR", str(tmp_path / "config_changes"))

    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("admin:write", tenant_id="tenant-a")

    first = client.put(
        "/admin/tenants/tenant-a/quota",
        headers={"X-API-Key": key},
        json={"quota": 500},
    )
    assert first.status_code == 200
    first_id = first.json()["config_change_id"]

    second = client.put(
        "/admin/tenants/tenant-a/quota",
        headers={"X-API-Key": key},
        json={"quota": 700},
    )
    assert second.status_code == 200

    stale_revert = client.post(
        f"/admin/config/changes/{first_id}/revert",
        headers={"X-API-Key": key},
    )
    assert stale_revert.status_code == 409


def test_admin_config_revert_is_idempotent(build_app, monkeypatch, tmp_path):
    monkeypatch.setenv("FG_CONFIG_CHANGE_DIR", str(tmp_path / "config_changes"))

    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("admin:write", tenant_id="tenant-a")

    update_resp = client.put(
        "/admin/tenants/tenant-a/quota",
        headers={"X-API-Key": key},
        json={"quota": 333},
    )
    change_id = update_resp.json()["config_change_id"]

    first_revert = client.post(
        f"/admin/config/changes/{change_id}/revert",
        headers={"X-API-Key": key},
    )
    assert first_revert.status_code == 200
    assert first_revert.json()["already_reverted"] is False

    second_revert = client.post(
        f"/admin/config/changes/{change_id}/revert",
        headers={"X-API-Key": key},
    )
    assert second_revert.status_code == 200
    assert second_revert.json()["already_reverted"] is True


def test_admin_write_config_fallback_disabled_in_prod(build_app, monkeypatch, tmp_path):
    monkeypatch.setenv("FG_CONFIG_CHANGE_DIR", str(tmp_path / "config_changes"))
    monkeypatch.setenv("FG_ENV", "prod")
    monkeypatch.setenv("FG_ADMIN_WRITE_CONFIG_FALLBACK", "0")

    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("admin:write", tenant_id="tenant-a")

    resp = client.put(
        "/admin/tenants/tenant-a/quota",
        headers={"X-API-Key": key},
        json={"quota": 777},
    )
    assert resp.status_code == 403


def test_ui_audit_packet_not_found_bucket_consistency(build_app, monkeypatch, tmp_path):
    audit_dir = tmp_path / "audit_packets"
    monkeypatch.setenv("FG_AUDIT_PACKET_DIR", str(audit_dir))

    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("audit:read", tenant_id="tenant-a")

    packet_dir = audit_dir / "packet-tenant-b-20260101000000"
    packet_dir.mkdir(parents=True, exist_ok=True)
    (packet_dir / "token.txt").write_text("known-token", encoding="utf-8")
    (packet_dir / "metadata.json").write_text(
        json.dumps({"tenant_id": "tenant-b", "packet_id": packet_dir.name}),
        encoding="utf-8",
    )

    wrong_tenant = client.get(
        f"/ui/audit/packet/{packet_dir.name}/download?token=known-token",
        headers={"X-API-Key": key},
    )
    not_found = client.get(
        "/ui/audit/packet/packet-does-not-exist/download?token=known-token",
        headers={"X-API-Key": key},
    )

    assert wrong_tenant.status_code == 404
    assert not_found.status_code == 404
    assert wrong_tenant.json()["detail"] == not_found.json()["detail"] == "Packet not found"
    assert "request_id" in wrong_tenant.json()
    assert "request_id" in not_found.json()
