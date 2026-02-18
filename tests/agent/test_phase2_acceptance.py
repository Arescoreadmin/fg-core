from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.db import get_engine
from api.db_models import AgentDeviceIdentity
from tests.agent.helpers import admin_headers, enroll_device, signed_headers


def _sig(enrolled: dict[str, str], path: str, body: dict) -> dict[str, str]:
    return signed_headers(path, body, enrolled["device_key_prefix"], enrolled["device_key"])


def test_revoked_device_denied_codes_for_phase2_control(build_app):
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)
    assert (
        client.post(
            f"/admin/agent/devices/{enrolled['device_id']}/revoke",
            headers=admin_headers(),
        ).status_code
        == 200
    )

    res = client.post(
        "/agent/commands/poll",
        headers=_sig(enrolled, "/agent/commands/poll", {"controller_id": "ctrl-1", "lease_seconds": 60}),
        json={"controller_id": "ctrl-1", "lease_seconds": 60},
    )
    assert res.status_code == 403
    assert res.json()["detail"]["code"] == "DEVICE_REVOKED"


def test_quarantined_device_denied_policy_fetch_with_stable_code(build_app):
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    assert (
        client.post(
            f"/admin/agent/quarantine/{enrolled['device_id']}",
            headers=admin_headers(),
            json={"reason": "test"},
        ).status_code
        == 200
    )

    res = client.post(
        "/agent/commands/poll",
        headers=_sig(enrolled, "/agent/commands/poll", {"controller_id": "ctrl-1", "lease_seconds": 60}),
        json={"controller_id": "ctrl-1", "lease_seconds": 60},
    )
    assert res.status_code == 403
    assert res.json()["detail"]["code"] == "DEVICE_QUARANTINED"


def test_expired_cert_has_stable_error_code(build_app):
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    with Session(get_engine()) as session:
        session.add(
            AgentDeviceIdentity(
                device_id=enrolled["device_id"],
                tenant_id="tenant-a",
                cert_fingerprint="ef" * 32,
                cert_pem="pem",
                cert_chain_pem="chain",
                cert_not_after=datetime.now(UTC) - timedelta(minutes=1),
                status="active",
            )
        )
        session.commit()

    res = client.post(
        "/agent/commands/poll",
        headers=_sig(enrolled, "/agent/commands/poll", {"controller_id": "ctrl-1", "lease_seconds": 60}),
        json={"controller_id": "ctrl-1", "lease_seconds": 60},
    )
    assert res.status_code == 403
    assert res.json()["detail"]["code"] == "CERT_EXPIRED"


def test_audit_params_hash_present_for_policy_publish(build_app, monkeypatch):
    app = build_app()
    client = TestClient(app)

    captured: dict = {}

    def _fake_audit(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr("api.agent_phase2.audit_admin_action", _fake_audit)

    payload = {"version": "v1", "policy_json": {"a": 1}, "signature": "sig"}
    res = client.post(
        "/admin/agent/policy/publish",
        headers=admin_headers(),
        json=payload,
    )
    assert res.status_code == 200
    details = captured.get("details") or {}
    assert details.get("params_hash")
