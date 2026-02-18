from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.db import get_engine
from api.db_models import AgentDeviceRegistry
from tests.agent.helpers import admin_headers, enroll_device, signed_headers


def _sig(enrolled: dict[str, str], path: str, body: dict) -> dict[str, str]:
    return signed_headers(path, body, enrolled["device_key_prefix"], enrolled["device_key"])


def _set_ring(device_id: str, ring: str) -> None:
    with Session(get_engine()) as session:
        row = session.query(AgentDeviceRegistry).filter(AgentDeviceRegistry.device_id == device_id).first()
        row.ring = ring
        session.commit()


def test_canary_receives_before_broad_when_error_budget_blocks_broad(build_app):
    app = build_app()
    client = TestClient(app)
    canary = enroll_device(client)
    broad = enroll_device(client)
    _set_ring(canary["device_id"], "canary")
    _set_ring(broad["device_id"], "broad")

    assert client.post(
        "/admin/agent/update/rollout",
        headers=admin_headers(),
        json={
            "canary_percent_per_hour": 10,
            "pilot_percent_per_hour": 10,
            "broad_percent_per_hour": 100,
            "canary_error_budget": 1,
            "paused": False,
            "kill_switch": False,
        },
    ).status_code == 200

    c0 = client.post("/agent/update/manifest", headers=_sig(canary, "/agent/update/manifest", {}), json={})
    assert c0.status_code == 200

    fail = {"version": "2.0.0", "status": "failed", "detail": "bad"}
    assert client.post(
        "/agent/update/report", headers=_sig(canary, "/agent/update/report", fail), json=fail
    ).status_code == 200
    assert client.post(
        "/agent/update/report", headers=_sig(canary, "/agent/update/report", fail), json=fail
    ).status_code == 200

    b = client.post("/agent/update/manifest", headers=_sig(broad, "/agent/update/manifest", {}), json={})
    assert b.status_code == 403


def test_kill_switch_blocks_all_rings(build_app):
    app = build_app()
    client = TestClient(app)
    canary = enroll_device(client)
    broad = enroll_device(client)
    _set_ring(canary["device_id"], "canary")
    _set_ring(broad["device_id"], "broad")

    assert client.post(
        "/admin/agent/update/rollout",
        headers=admin_headers(),
        json={
            "canary_percent_per_hour": 10,
            "pilot_percent_per_hour": 10,
            "broad_percent_per_hour": 100,
            "canary_error_budget": 5,
            "paused": False,
            "kill_switch": True,
        },
    ).status_code == 200

    c = client.post("/agent/update/manifest", headers=_sig(canary, "/agent/update/manifest", {}), json={})
    b = client.post("/agent/update/manifest", headers=_sig(broad, "/agent/update/manifest", {}), json={})
    assert c.status_code == 403
    assert b.status_code == 403
    c_detail = c.json().get("detail")
    b_detail = b.json().get("detail")
    if isinstance(c_detail, dict):
        assert c_detail.get("code") == "UPDATE_KILL_SWITCH"
    if isinstance(b_detail, dict):
        assert b_detail.get("code") == "UPDATE_KILL_SWITCH"
