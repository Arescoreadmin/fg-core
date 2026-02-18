from __future__ import annotations

from fastapi.testclient import TestClient

from api.auth_scopes import mint_key
import api.ui_ai_console as ai_console


def _client(build_app) -> TestClient:
    app = build_app()
    return TestClient(app)


def _headers(*scopes: str, tenant_id: str = "tenant-dev") -> dict[str, str]:
    return {"X-API-Key": mint_key(*scopes, tenant_id=tenant_id)}


def _enable(client: TestClient, headers: dict[str, str], device_id: str) -> None:
    resp = client.post(
        f"/ui/devices/{device_id}/enable",
        headers=headers,
        json={"reason": "allow test device", "ticket": "SEC-1"},
    )
    assert resp.status_code == 200


def test_tenant_mismatch_denied(build_app):
    client = _client(build_app)
    hdrs = _headers("ui:read", "ai:chat", tenant_id="tenant-dev")

    exp = client.get("/ui/ai/experience", headers=hdrs)
    assert exp.status_code == 200
    device_id = exp.json()["device"]["device_id"]

    deny = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={
            "message": "hello",
            "device_id": device_id,
            "requested_tenant_id": "tenant-other",
        },
    )
    assert deny.status_code == 403


def test_device_enable_disable_gate(build_app):
    client = _client(build_app)
    hdrs = _headers("ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev")

    exp = client.get("/ui/ai/experience", headers=hdrs)
    assert exp.status_code == 200
    device_id = exp.json()["device"]["device_id"]

    denied = client.post(
        "/ui/ai/chat", headers=hdrs, json={"message": "hello", "device_id": device_id}
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AI_DEVICE_DISABLED"

    _enable(client, hdrs, device_id)

    allowed = client.post(
        "/ui/ai/chat", headers=hdrs, json={"message": "hello", "device_id": device_id}
    )
    assert allowed.status_code == 200
    body = allowed.json()
    assert body["session_id"]
    assert body["usage"]["usage_record_id"]

    disabled = client.post(
        f"/ui/devices/{device_id}/disable",
        headers=hdrs,
        json={"reason": "revoke", "ticket": "SEC-2"},
    )
    assert disabled.status_code == 200

    denied_again = client.post(
        "/ui/ai/chat", headers=hdrs, json={"message": "hello", "device_id": device_id}
    )
    assert denied_again.status_code == 403


def test_token_usage_and_quota_enforcement(build_app, monkeypatch):
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "simulated")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")

    client = _client(build_app)
    hdrs = _headers("ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev")

    exp = client.get("/ui/ai/experience", headers=hdrs)
    device_id = exp.json()["device"]["device_id"]
    _enable(client, hdrs, device_id)

    ok = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": "small prompt", "device_id": device_id},
    )
    assert ok.status_code == 200
    usage = ok.json()["usage"]
    assert usage["total_tokens"] >= usage["prompt_tokens"]
    assert usage["metering_mode"] == "estimated"


def test_unknown_device_denied(build_app):
    client = _client(build_app)
    hdrs = _headers("ui:read", "ai:chat", tenant_id="tenant-dev")
    resp = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": "hello", "device_id": "unknown-device"},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]["error_code"] == "AI_DEVICE_DISABLED"


def test_usage_data_isolation_between_tenants(build_app):
    client = _client(build_app)
    hdrs_a = _headers("ui:read", "ai:chat", "admin:write", tenant_id="tenant-a")
    hdrs_b = _headers("ui:read", "ai:chat", "admin:write", tenant_id="tenant-b")

    exp_a = client.get("/ui/ai/experience", headers=hdrs_a).json()
    exp_b = client.get("/ui/ai/experience", headers=hdrs_b).json()
    _enable(client, hdrs_a, exp_a["device"]["device_id"])
    _enable(client, hdrs_b, exp_b["device"]["device_id"])

    assert (
        client.post(
            "/ui/ai/chat",
            headers=hdrs_a,
            json={
                "message": "tenant a data",
                "device_id": exp_a["device"]["device_id"],
            },
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/ui/ai/chat",
            headers=hdrs_b,
            json={
                "message": "tenant b data",
                "device_id": exp_b["device"]["device_id"],
            },
        ).status_code
        == 200
    )

    usage_a = client.get("/ui/ai/usage", headers=hdrs_a)
    assert usage_a.status_code == 200
    items = usage_a.json()["items"]
    assert items
    assert all(item["tenant_id"] == "tenant-a" for item in items)

    devices_a = client.get("/admin/devices?tenant=tenant-a", headers=hdrs_a)
    assert devices_a.status_code == 200
    device_items = devices_a.json()["items"]
    assert device_items
    assert all(item["tenant_id"] == "tenant-a" for item in device_items)


def test_provider_denied_by_server_config(build_app, monkeypatch):
    monkeypatch.setenv("FG_AI_ALLOWED_PROVIDERS", "")
    monkeypatch.setenv("FG_AI_ENABLE_SIMULATED", "1")

    client = _client(build_app)
    hdrs = _headers("ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev")
    exp = client.get("/ui/ai/experience", headers=hdrs).json()
    device_id = exp["device"]["device_id"]
    _enable(client, hdrs, device_id)

    denied = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": "hello", "device_id": device_id},
    )
    assert denied.status_code == 400
    assert denied.json()["detail"]["error_code"] == "AI_PROVIDER_DENIED_BY_SERVER"


def test_request_token_cap_exceeded(build_app):
    client = _client(build_app)
    hdrs = _headers("ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev")

    exp = client.get("/ui/ai/experience", headers=hdrs).json()
    device_id = exp["device"]["device_id"]
    _enable(client, hdrs, device_id)

    large_prompt = "a " * 5000
    denied = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": large_prompt, "device_id": device_id},
    )
    assert denied.status_code == 400
    assert denied.json()["detail"]["error_code"] == "AI_REQUEST_TOKEN_CAP_EXCEEDED"


def test_quota_rollover_uses_request_start_day(build_app, monkeypatch):
    client = _client(build_app)
    hdrs = _headers("ui:read", "ai:chat", "admin:write", tenant_id="tenant-dev")

    exp = client.get("/ui/ai/experience", headers=hdrs).json()
    device_id = exp["device"]["device_id"]
    _enable(client, hdrs, device_id)

    days = iter(["2026-01-01", "2026-01-02", "2026-01-02"])
    monkeypatch.setattr(ai_console, "_day_bucket", lambda: next(days))

    ok = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": "rollover request", "device_id": device_id},
    )
    assert ok.status_code == 200

    usage = client.get("/ui/ai/usage", headers=hdrs).json()["items"][0]
    assert usage["usage_day"] == "2026-01-01"
