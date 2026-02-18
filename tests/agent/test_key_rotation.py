from __future__ import annotations

from fastapi.testclient import TestClient

from tests.agent.helpers import enroll_device, signed_headers


def test_key_rotation_revokes_old_key(build_app):
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    rotate_body = {}
    rotate_headers = signed_headers(
        "/agent/key/rotate",
        rotate_body,
        enrolled["device_key_prefix"],
        enrolled["device_key"],
    )
    rotate = client.post("/agent/key/rotate", headers=rotate_headers, json=rotate_body)
    assert rotate.status_code == 200
    rotated = rotate.json()

    body = {
        "ts": "2026-01-01T00:00:00Z",
        "agent_version": "1.0.0",
        "os": "linux",
        "hostname": "h",
    }
    old_headers = signed_headers(
        "/agent/heartbeat", body, enrolled["device_key_prefix"], enrolled["device_key"]
    )
    old_res = client.post("/agent/heartbeat", headers=old_headers, json=body)
    assert old_res.status_code == 403

    new_headers = signed_headers(
        "/agent/heartbeat", body, rotated["device_key_prefix"], rotated["device_key"]
    )
    new_res = client.post("/agent/heartbeat", headers=new_headers, json=body)
    assert new_res.status_code == 200
