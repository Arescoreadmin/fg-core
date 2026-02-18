from __future__ import annotations

from fastapi.testclient import TestClient

from api.auth_scopes import mint_key


def _client(build_app):
    return TestClient(build_app(auth_enabled=True))


def _headers(*scopes: str, tenant_id: str) -> dict[str, str]:
    return {"X-API-Key": mint_key(*scopes, tenant_id=tenant_id)}


def _enable(client: TestClient, headers: dict[str, str], device_id: str) -> None:
    resp = client.post(
        "/ui/ai/device/enable", headers=headers, json={"device_id": device_id}
    )
    assert resp.status_code == 200


def test_tenant_mismatch_denied(build_app):
    client = _client(build_app)
    hdrs = _headers("ui:read", "ai:chat", tenant_id="tenant-dev")

    exp = client.get("/ui/ai/experience", headers=hdrs)
    assert exp.status_code == 200

    mismatch = client.get("/ui/ai/experience?tenant_id=tenant-other", headers=hdrs)
    assert mismatch.status_code == 403


def test_device_enable_disable_gate(build_app):
    client = _client(build_app)
    user_hdrs = _headers("ui:read", "ai:chat", tenant_id="tenant-dev")
    admin_hdrs = _headers("ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev")

    exp = client.get("/ui/ai/experience", headers=user_hdrs)
    assert exp.status_code == 200
    device_id = exp.json()["device"]["device_id"]

    deny_enable = client.post(
        "/ui/ai/device/enable", headers=user_hdrs, json={"device_id": device_id}
    )
    assert deny_enable.status_code == 403

    ok_enable = client.post(
        "/ui/ai/device/enable", headers=admin_hdrs, json={"device_id": device_id}
    )
    assert ok_enable.status_code == 200

    ok_disable = client.post(
        "/ui/ai/device/disable", headers=admin_hdrs, json={"device_id": device_id}
    )
    assert ok_disable.status_code == 200


def test_unknown_device_denied(build_app):
    client = _client(build_app)
    hdrs = _headers("ui:read", "ai:chat", tenant_id="tenant-dev")
    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": "hello", "device_id": "unknown-device"},
    )
    assert resp.status_code == 403


def test_usage_data_isolation_between_tenants(build_app):
    client = _client(build_app)
    hdrs_a = _headers("ui:read", "ai:chat", "admin:write", tenant_id="tenant-a")
    hdrs_b = _headers("ui:read", "ai:chat", "admin:write", tenant_id="tenant-b")

    exp_a = client.get("/ui/ai/experience", headers=hdrs_a).json()
    exp_b = client.get("/ui/ai/experience", headers=hdrs_b).json()

    _enable(client, hdrs_a, exp_a["device"]["device_id"])
    _enable(client, hdrs_b, exp_b["device"]["device_id"])

    chat_a = client.post(
        "/ui/ai/chat",
        headers=hdrs_a,
        json={
            "message": "hello from tenant a",
            "device_id": exp_a["device"]["device_id"],
        },
    )
    assert chat_a.status_code == 200

    now_a = client.get("/ui/ai/experience", headers=hdrs_a).json()
    now_b = client.get("/ui/ai/experience", headers=hdrs_b).json()
    assert now_a["usage"]["tokens_used"] > now_b["usage"]["tokens_used"]


def test_provider_denied_by_server_config(build_app, monkeypatch):
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")

    client = _client(build_app)
    hdrs = _headers("ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev")
    exp = client.get("/ui/ai/experience", headers=hdrs).json()
    device_id = exp["device"]["device_id"]
    _enable(client, hdrs, device_id)

    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": "hello", "device_id": device_id, "provider": "simulated"},
    )
    assert resp.status_code == 403


def test_request_token_cap_exceeded(build_app, monkeypatch):
    monkeypatch.setenv("FG_AI_REQUEST_TOKEN_CAP", "8")

    client = _client(build_app)
    hdrs = _headers("ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev")

    exp = client.get("/ui/ai/experience", headers=hdrs).json()
    device_id = exp["device"]["device_id"]
    _enable(client, hdrs, device_id)

    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": "x" * 500, "device_id": device_id},
    )
    assert resp.status_code == 400


def test_legacy_device_routes_still_available(build_app):
    client = _client(build_app)
    hdrs = _headers("ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev")

    exp = client.get("/ui/ai/experience", headers=hdrs).json()
    device_id = exp["device"]["device_id"]

    admin_list = client.get("/admin/devices", headers=hdrs)
    assert admin_list.status_code == 200

    en = client.post(f"/admin/devices/{device_id}/enable", headers=hdrs)
    assert en.status_code == 200

    dis = client.post(f"/ui/devices/{device_id}/disable", headers=hdrs)
    assert dis.status_code == 200
