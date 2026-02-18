from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.db import get_engine
from api.db_models import AgentDeviceRegistry
from tests.agent.helpers import enroll_device, signed_headers


def test_tamper_signal_transitions_to_suspicious(build_app):
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    body = {
        "ts": "2026-01-01T00:00:00Z",
        "agent_version": "1.0.0",
        "os": "linux",
        "hostname": "h",
        "signals": {"tamper": True, "debugged": False},
    }
    headers = signed_headers("/agent/heartbeat", body, enrolled["device_key_prefix"], enrolled["device_key"])
    res = client.post("/agent/heartbeat", headers=headers, json=body)
    assert res.status_code == 200

    with Session(get_engine()) as session:
        row = session.query(AgentDeviceRegistry).filter(AgentDeviceRegistry.device_id == enrolled["device_id"]).first()
        assert row is not None
        assert row.status == "suspicious"
        assert row.suspicious is True
