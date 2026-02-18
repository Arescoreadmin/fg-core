from __future__ import annotations

from fastapi.testclient import TestClient

from api.auth_scopes import mint_key


def _headers(*scopes: str, tenant_id: str = "tenant-dev") -> dict[str, str]:
    return {"X-API-Key": mint_key(*scopes, tenant_id=tenant_id)}


def test_signature_hook_requires_headers_when_enabled(build_app, monkeypatch):
    monkeypatch.setenv("FG_AI_DEVICE_SIGNATURE_ENABLED", "1")
    monkeypatch.setenv("FG_AI_DEVICE_SIG_SECRET", "test-secret")

    app = build_app()
    client = TestClient(app)
    hdrs = _headers("ui:read", "ai:chat", "admin:write")

    exp = client.get("/ui/ai/experience", headers=hdrs).json()
    device_id = exp["device"]["device_id"]
    client.post(
        f"/ui/devices/{device_id}/enable",
        headers=hdrs,
        json={"reason": "allow", "ticket": "SEC-77"},
    )

    denied = client.post(
        "/ui/ai/chat",
        headers=hdrs,
        json={"message": "hello", "device_id": device_id},
    )
    assert denied.status_code == 401
    assert denied.json()["detail"]["error_code"] == "AI_DEVICE_SIG_REQUIRED"
