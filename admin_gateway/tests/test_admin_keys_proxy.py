"""Tests for admin key proxy endpoints."""

import pytest
from fastapi.testclient import TestClient

from admin_gateway.auth.session import Session


def test_admin_keys_list_proxies(client, monkeypatch):
    """List keys endpoint should proxy to core."""
    from admin_gateway.routers import admin as admin_router

    calls = {}

    async def _mock_proxy(request, method, path, params=None, json_body=None):
        calls["method"] = method
        calls["path"] = path
        calls["params"] = params
        return {"keys": [{"prefix": "fgk"}], "total": 1}

    monkeypatch.setattr(admin_router, "_proxy_to_core", _mock_proxy)

    response = client.get("/admin/keys", params={"tenant_id": "tenant-dev"})
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert calls["method"] == "GET"
    assert calls["path"] == "/admin/keys"
    assert calls["params"] == {"tenant_id": "tenant-dev"}


def test_admin_keys_scope_enforced(app, monkeypatch):
    """Missing scope should be rejected."""
    from admin_gateway.auth.dependencies import get_current_session
    from admin_gateway.routers import admin as admin_router

    async def _mock_proxy(request, method, path, params=None, json_body=None):
        return {"keys": [], "total": 0}

    def _override_session():
        return Session(
            user_id="tester",
            scopes={"product:read"},
            tenant_id="tenant-dev",
            claims={"allowed_tenants": ["tenant-dev"]},
        )

    app.dependency_overrides[get_current_session] = _override_session
    monkeypatch.setattr(admin_router, "_proxy_to_core", _mock_proxy)

    with TestClient(app) as test_client:
        response = test_client.get("/admin/keys", params={"tenant_id": "tenant-dev"})
    assert response.status_code == 403


def test_core_api_key_prod_requires_internal_token(monkeypatch):
    """Production must not fall back to AG_CORE_API_KEY."""
    from admin_gateway.routers import admin as admin_router
    from fastapi import HTTPException

    monkeypatch.setenv("FG_ENV", "production")
    monkeypatch.delenv("AG_CORE_INTERNAL_TOKEN", raising=False)
    monkeypatch.setenv("AG_CORE_API_KEY", "legacy-shared-key")

    with pytest.raises(HTTPException) as exc:
        admin_router._core_api_key()
    assert exc.value.status_code == 503
    assert "AG_CORE_INTERNAL_TOKEN not configured" in str(exc.value.detail)


def test_core_api_key_non_prod_falls_back_to_legacy(monkeypatch):
    """Non-production may use AG_CORE_API_KEY compatibility fallback."""
    from admin_gateway.routers import admin as admin_router

    monkeypatch.setenv("FG_ENV", "dev")
    monkeypatch.delenv("AG_CORE_INTERNAL_TOKEN", raising=False)
    monkeypatch.setenv("AG_CORE_API_KEY", "legacy-shared-key")

    assert admin_router._core_api_key() == "legacy-shared-key"
