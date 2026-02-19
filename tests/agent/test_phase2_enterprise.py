from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.db import get_engine
from api.db_models import AgentDeviceIdentity
from tests.agent.helpers import admin_headers, enroll_device, signed_headers


def _sig(enrolled: dict[str, str], path: str, body: dict) -> dict[str, str]:
    return signed_headers(
        path, body, enrolled["device_key_prefix"], enrolled["device_key"]
    )


def test_command_replay_prevented(build_app):
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    issue = client.post(
        "/admin/agent/commands/issue",
        headers=admin_headers(),
        json={
            "device_id": enrolled["device_id"],
            "command_type": "collect_diagnostics",
            "payload": {},
        },
    )
    assert issue.status_code == 200
    command_id = issue.json()["command_id"]

    ack_body = {"command_id": command_id, "status": "ok", "result": {"done": True}}
    first = client.post(
        "/agent/commands/ack",
        headers=_sig(enrolled, "/agent/commands/ack", ack_body),
        json=ack_body,
    )
    assert first.status_code == 200
    second = client.post(
        "/agent/commands/ack",
        headers=_sig(enrolled, "/agent/commands/ack", ack_body),
        json=ack_body,
    )
    assert second.status_code == 403


def test_cross_tenant_command_isolation(build_app):
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    headers = admin_headers()
    headers["X-Tenant-Id"] = "tenant-b"
    issue = client.post(
        "/admin/agent/commands/issue",
        headers=headers,
        json={
            "device_id": enrolled["device_id"],
            "command_type": "collect_diagnostics",
            "payload": {},
        },
    )
    assert issue.status_code == 403


def test_expired_cert_cannot_send_commands(build_app):
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    with Session(get_engine()) as session:
        session.add(
            AgentDeviceIdentity(
                device_id=enrolled["device_id"],
                tenant_id="tenant-a",
                cert_fingerprint="ab" * 32,
                cert_pem="pem",
                cert_chain_pem="chain",
                cert_not_after=datetime.now(UTC) - timedelta(minutes=1),
                status="active",
            )
        )
        session.commit()

    body = {"controller_id": "ctrl-1", "lease_seconds": 60}
    res = client.post(
        "/agent/commands/poll",
        headers=_sig(enrolled, "/agent/commands/poll", body),
        json=body,
    )
    assert res.status_code == 403


def test_revoked_device_cannot_heartbeat(build_app):
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    revoke = client.post(
        f"/admin/agent/devices/{enrolled['device_id']}/revoke", headers=admin_headers()
    )
    assert revoke.status_code == 200

    hb_body = {
        "ts": "2026-01-01T00:00:00Z",
        "agent_version": "1.0.0",
        "os": "linux",
        "hostname": "h",
    }
    hb = client.post(
        "/agent/heartbeat",
        headers=_sig(enrolled, "/agent/heartbeat", hb_body),
        json=hb_body,
    )
    assert hb.status_code == 403


def test_quarantine_restricts_commands(build_app):
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    assert (
        client.post(
            f"/admin/agent/quarantine/{enrolled['device_id']}",
            headers=admin_headers(),
            json={"reason": "incident"},
        ).status_code
        == 200
    )

    denied_issue = client.post(
        "/admin/agent/commands/issue",
        headers=admin_headers(),
        json={
            "device_id": enrolled["device_id"],
            "command_type": "collect_diagnostics",
            "payload": {},
        },
    )
    assert denied_issue.status_code == 403
    assert denied_issue.json()["detail"]["code"] == "DEVICE_QUARANTINED"

    body = {"controller_id": "ctrl-1", "lease_seconds": 60}
    poll = client.post(
        "/agent/commands/poll",
        headers=_sig(enrolled, "/agent/commands/poll", body),
        json=body,
    )
    assert poll.status_code == 403
    assert poll.json()["detail"]["code"] == "DEVICE_QUARANTINED"
