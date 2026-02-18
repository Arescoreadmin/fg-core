from __future__ import annotations

from fastapi.testclient import TestClient

from tests.agent.helpers import admin_headers, enroll_device, signed_headers


def _sig(enrolled: dict[str, str], path: str, body: dict) -> dict[str, str]:
    return signed_headers(path, body, enrolled["device_key_prefix"], enrolled["device_key"])


def test_policy_publish_rate_limit_code(build_app, monkeypatch):
    monkeypatch.setenv("FG_AGENT_POLICY_PUBLISH_PER_DAY", "1")
    app = build_app()
    client = TestClient(app)

    payload = {"version": "v1", "policy_json": {"x": 1}, "signature": "sig"}
    assert client.post("/admin/agent/policy/publish", headers=admin_headers(), json=payload).status_code == 200
    second = client.post("/admin/agent/policy/publish", headers=admin_headers(), json=payload)
    assert second.status_code == 429
    assert second.json()["detail"]["code"] == "RATE_LIMIT_POLICY_PUBLISH"


def test_update_check_rate_limit_code(build_app, monkeypatch):
    monkeypatch.setenv("FG_AGENT_UPDATE_CHECKS_PER_MIN", "1")
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    first = client.post("/agent/update/manifest", headers=_sig(enrolled, "/agent/update/manifest", {}), json={})
    assert first.status_code == 200
    second = client.post("/agent/update/manifest", headers=_sig(enrolled, "/agent/update/manifest", {}), json={})
    assert second.status_code == 429
    assert second.json()["detail"]["code"] == "RATE_LIMIT_UPDATE_CHECK"
