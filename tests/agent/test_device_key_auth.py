from __future__ import annotations

from fastapi.testclient import TestClient

from tests.agent.helpers import admin_headers, enroll_device, signed_headers


def _heartbeat_body() -> dict:
    return {
        "ts": "2026-01-01T00:00:00Z",
        "agent_version": "1.0.0",
        "os": "linux",
        "hostname": "h",
    }


def test_heartbeat_valid_signature(build_app):
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)
    body = _heartbeat_body()
    headers = signed_headers(
        "/agent/heartbeat", body, enrolled["device_key_prefix"], enrolled["device_key"]
    )
    res = client.post("/agent/heartbeat", headers=headers, json=body)
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


def test_revoked_device_key_fails(build_app):
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    revoke = client.post(
        f"/admin/agent/devices/{enrolled['device_id']}/revoke", headers=admin_headers()
    )
    assert revoke.status_code == 200

    body = _heartbeat_body()
    headers = signed_headers(
        "/agent/heartbeat", body, enrolled["device_key_prefix"], enrolled["device_key"]
    )
    denied = client.post("/agent/heartbeat", headers=headers, json=body)
    assert denied.status_code == 403


def test_replay_nonce_rejected(build_app):
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)
    body = _heartbeat_body()
    headers = signed_headers(
        "/agent/heartbeat",
        body,
        enrolled["device_key_prefix"],
        enrolled["device_key"],
        nonce="same-nonce-0001",
    )
    first = client.post("/agent/heartbeat", headers=headers, json=body)
    assert first.status_code == 200
    second = client.post("/agent/heartbeat", headers=headers, json=body)
    assert second.status_code == 403


def test_signature_edge_cases(build_app):
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)
    body = _heartbeat_body()

    missing = client.post(
        "/agent/heartbeat",
        json=body,
        headers={"X-FG-DEVICE-KEY": enrolled["device_key_prefix"]},
    )
    assert missing.status_code == 401

    future_headers = signed_headers(
        "/agent/heartbeat",
        body,
        enrolled["device_key_prefix"],
        enrolled["device_key"],
        ts=4_102_444_800,
    )
    future = client.post("/agent/heartbeat", headers=future_headers, json=body)
    assert future.status_code == 401

    old_headers = signed_headers(
        "/agent/heartbeat",
        body,
        enrolled["device_key_prefix"],
        enrolled["device_key"],
        ts=1,
    )
    old = client.post("/agent/heartbeat", headers=old_headers, json=body)
    assert old.status_code == 401

    bad_sig_headers = signed_headers(
        "/agent/heartbeat",
        body,
        enrolled["device_key_prefix"],
        enrolled["device_key"],
    )
    bad_sig_headers["X-FG-SIG"] = "0" * 64
    bad = client.post("/agent/heartbeat", headers=bad_sig_headers, json=body)
    assert bad.status_code == 403
