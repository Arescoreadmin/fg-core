from __future__ import annotations

from fastapi.testclient import TestClient

from tests.agent.helpers import admin_headers, enroll_device


def test_unknown_command_type_rejected(build_app):
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    res = client.post(
        "/admin/agent/commands/issue",
        headers=admin_headers(),
        json={
            "device_id": enrolled["device_id"],
            "command_type": "unknown_type",
            "payload": {},
        },
    )
    assert res.status_code == 422


def test_command_params_extra_forbidden(build_app):
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    res = client.post(
        "/admin/agent/commands/issue",
        headers=admin_headers(),
        json={
            "device_id": enrolled["device_id"],
            "command_type": "collect_diagnostics",
            "payload": {"include_processes": True, "evil": "x"},
        },
    )
    assert res.status_code == 403
    assert res.json()["detail"]["code"] == "COMMAND_PARAMS_INVALID"
