from __future__ import annotations

from fastapi import HTTPException


def test_admin_auth_required(client_no_bypass):
    response = client_no_bypass.get("/admin/keys")
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"


def test_admin_list_keys_happy_path(client):
    response = client.get("/admin/keys?tenant_id=tenant-dev")
    assert response.status_code == 200
    assert response.json()["tenant_id"] == "tenant-dev"


def test_admin_list_keys_upstream_error(client, monkeypatch):
    from admin_gateway.routers import admin as admin_router

    async def _fail_proxy(*_args, **_kwargs):
        raise HTTPException(status_code=502, detail="upstream failure")

    monkeypatch.setattr(admin_router, "_proxy_to_core", _fail_proxy)

    response = client.get("/admin/keys?tenant_id=tenant-dev")
    assert response.status_code == 502
    assert response.json()["detail"] == "upstream failure"


def test_admin_create_key_validation(client, csrf_headers):
    headers = csrf_headers(client)
    response = client.post(
        "/admin/keys",
        json={"tenant_id": "tenant-dev", "ttl_seconds": 1},
        headers=headers,
    )
    assert response.status_code == 422
