import os
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key


def test_governance_not_mounted_when_disabled(build_app, monkeypatch):
    monkeypatch.delenv("FG_MISSION_ENVELOPE_ENABLED", raising=False)
    monkeypatch.delenv("FG_RING_ROUTER_ENABLED", raising=False)
    monkeypatch.delenv("FG_ROE_ENGINE_ENABLED", raising=False)
    monkeypatch.delenv("FG_FORENSICS_ENABLED", raising=False)
    monkeypatch.delenv("FG_GOVERNANCE_ENABLED", raising=False)
    app = build_app()
    client = TestClient(app)

    r = client.get(
        "/governance/changes", headers={"X-API-Key": os.environ["FG_API_KEY"]}
    )
    assert r.status_code == 404


def test_governance_approval_flow(build_app, monkeypatch):
    monkeypatch.setenv("FG_GOVERNANCE_ENABLED", "1")
    app = build_app()

    client = TestClient(app)
    headers = {"X-API-Key": mint_key("governance:write", tenant_id="tenant-test")}

    create = client.post(
        "/governance/changes",
        headers=headers,
        json={
            "change_type": "add_rule",
            "proposed_by": "tester",
            "justification": "unit-test",
        },
    )
    assert create.status_code == 200, create.text
    change = create.json()
    change_id = change["change_id"]

    first = client.post(
        f"/governance/changes/{change_id}/approve",
        headers=headers,
        json={"approver": "security-lead"},
    )
    assert first.status_code == 200, first.text
    assert first.json()["status"] == "pending"

    second = client.post(
        f"/governance/changes/{change_id}/approve",
        headers=headers,
        json={"approver": "ciso"},
    )
    assert second.status_code == 200, second.text
    assert second.json()["status"] == "deployed"
