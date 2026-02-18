from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.db import get_engine
from api.db_models import AgentDeviceRegistry
from tests.agent.helpers import admin_headers, enroll_device, signed_headers


def _tamper_body() -> dict:
    return {
        "ts": "2026-01-01T00:00:00Z",
        "agent_version": "1.0.0",
        "os": "linux",
        "hostname": "h",
        "signals": {"tamper": True, "debugged": False},
    }


def test_suspicious_then_quarantined_transition(build_app):
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    body = _tamper_body()
    first_headers = signed_headers("/agent/heartbeat", body, enrolled["device_key_prefix"], enrolled["device_key"], nonce="n1")
    first = client.post("/agent/heartbeat", headers=first_headers, json=body)
    assert first.status_code == 200

    second_headers = signed_headers("/agent/heartbeat", body, enrolled["device_key_prefix"], enrolled["device_key"], nonce="n2")
    second = client.post("/agent/heartbeat", headers=second_headers, json=body)
    assert second.status_code == 200

    with Session(get_engine()) as session:
        row = session.query(AgentDeviceRegistry).filter(AgentDeviceRegistry.device_id == enrolled["device_id"]).first()
        assert row is not None
        assert row.status == "quarantined"


def test_revoked_terminal_and_rotation_denied(build_app):
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    revoke = client.post(f"/admin/agent/devices/{enrolled['device_id']}/revoke", headers=admin_headers())
    assert revoke.status_code == 200

    body = {}
    rotate_headers = signed_headers("/agent/key/rotate", body, enrolled["device_key_prefix"], enrolled["device_key"])
    rotate = client.post("/agent/key/rotate", headers=rotate_headers, json=body)
    assert rotate.status_code == 403

    hb_body = {
        "ts": "2026-01-01T00:00:00Z",
        "agent_version": "1.0.0",
        "os": "linux",
        "hostname": "h",
    }
    hb_headers = signed_headers("/agent/heartbeat", hb_body, enrolled["device_key_prefix"], enrolled["device_key"])
    hb = client.post("/agent/heartbeat", headers=hb_headers, json=hb_body)
    assert hb.status_code == 403


def test_rotation_denied_when_quarantined(build_app):
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    body = _tamper_body()
    h1 = signed_headers("/agent/heartbeat", body, enrolled["device_key_prefix"], enrolled["device_key"], nonce="q1")
    h2 = signed_headers("/agent/heartbeat", body, enrolled["device_key_prefix"], enrolled["device_key"], nonce="q2")
    assert client.post("/agent/heartbeat", headers=h1, json=body).status_code == 200
    assert client.post("/agent/heartbeat", headers=h2, json=body).status_code == 200

    rotate = client.post(
        "/agent/key/rotate",
        headers=signed_headers("/agent/key/rotate", {}, enrolled["device_key_prefix"], enrolled["device_key"]),
        json={},
    )
    assert rotate.status_code == 403
