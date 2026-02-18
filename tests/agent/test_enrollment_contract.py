from __future__ import annotations

from fastapi.testclient import TestClient

from tests.agent.helpers import admin_headers


def test_enrollment_token_issue_then_enroll(build_app):
    app = build_app()
    client = TestClient(app)

    issue = client.post(
        "/admin/agent/enrollment-tokens",
        json={
            "ttl_minutes": 15,
            "max_uses": 1,
            "reason": "new install",
            "ticket": "INC-1",
        },
        headers=admin_headers(),
    )
    assert issue.status_code == 200
    token = issue.json()["token"]

    enroll = client.post(
        "/agent/enroll",
        json={
            "enrollment_token": token,
            "device_fingerprint": "fp-12345678",
            "device_name": "host-a",
            "os": "linux",
            "agent_version": "1.0.0",
        },
    )
    assert enroll.status_code == 200
    body = enroll.json()
    assert body["device_id"].startswith("dev_")
    assert body["device_key_prefix"].startswith("fgd_")
    assert len(body["device_key"]) >= 24

    replay = client.post(
        "/agent/enroll",
        json={"enrollment_token": token, "device_fingerprint": "fp-12345678"},
    )
    assert replay.status_code == 401


def test_enrollment_requires_reason_ticket(build_app):
    app = build_app()
    client = TestClient(app)
    res = client.post(
        "/admin/agent/enrollment-tokens", json={}, headers=admin_headers()
    )
    assert res.status_code == 422
