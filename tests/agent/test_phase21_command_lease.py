from __future__ import annotations

from fastapi.testclient import TestClient

from sqlalchemy.orm import Session

from api.db import get_engine
from api.db_models import AgentCommand
from tests.agent.helpers import admin_headers, enroll_device, signed_headers


def _sig(enrolled: dict[str, str], path: str, body: dict) -> dict[str, str]:
    return signed_headers(path, body, enrolled["device_key_prefix"], enrolled["device_key"])


def _issue(client: TestClient, device_id: str, idem: str | None = None):
    body = {
        "device_id": device_id,
        "command_type": "collect_diagnostics",
        "payload": {"include_processes": True, "include_network": True},
    }
    if idem:
        body["idempotency_key"] = idem
    return client.post("/admin/agent/commands/issue", headers=admin_headers(), json=body)


def test_idempotency_key_reuses_command(build_app):
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    first = _issue(client, enrolled["device_id"], idem="idem-12345678")
    assert first.status_code == 200
    second = _issue(client, enrolled["device_id"], idem="idem-12345678")
    assert second.status_code == 200
    assert first.json()["command_id"] == second.json()["command_id"]
    assert second.json().get("idempotent_replay") is True


def test_two_controllers_cannot_lease_same_command(build_app):
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)
    issue = _issue(client, enrolled["device_id"])
    assert issue.status_code == 200

    poll_a_body = {"controller_id": "ctrl-a", "lease_seconds": 120}
    poll_a = client.post(
        "/agent/commands/poll",
        headers=_sig(enrolled, "/agent/commands/poll", poll_a_body),
        json=poll_a_body,
    )
    assert poll_a.status_code == 200
    assert len(poll_a.json()["commands"]) == 1

    poll_b_body = {"controller_id": "ctrl-b", "lease_seconds": 120}
    poll_b = client.post(
        "/agent/commands/poll",
        headers=_sig(enrolled, "/agent/commands/poll", poll_b_body),
        json=poll_b_body,
    )
    assert poll_b.status_code == 200
    assert poll_b.json()["commands"] == []


def test_ack_after_lease_expiry_denied(build_app):
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)
    issue = _issue(client, enrolled["device_id"])
    assert issue.status_code == 200
    command_id = issue.json()["command_id"]

    poll_body = {"controller_id": "ctrl-a", "lease_seconds": 10}
    poll = client.post(
        "/agent/commands/poll",
        headers=_sig(enrolled, "/agent/commands/poll", poll_body),
        json=poll_body,
    )
    assert poll.status_code == 200
    with Session(get_engine()) as session:
        row = session.query(AgentCommand).filter(AgentCommand.command_id == command_id).first()
        row.lease_expires_at = row.issued_at
        session.commit()

    ack_body = {"command_id": command_id, "status": "ok", "result": {"ok": True}}
    ack = client.post(
        "/agent/commands/ack",
        headers=_sig(enrolled, "/agent/commands/ack", ack_body),
        json=ack_body,
    )
    assert ack.status_code == 403
    assert ack.json()["detail"]["code"] == "LEASE_EXPIRED"
