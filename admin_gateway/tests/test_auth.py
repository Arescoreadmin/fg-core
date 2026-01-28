"""Tests for authentication and authorization."""

import pytest
from fastapi.testclient import TestClient

from admin_gateway.auth import AuthUser, get_current_user
from admin_gateway.main import build_app


def test_admin_me_requires_auth(client):
    response = client.get("/admin/me")
    assert response.status_code == 401


def test_dev_bypass_allows_access(monkeypatch):
    monkeypatch.setenv("FG_ENV", "dev")
    monkeypatch.setenv("FG_DEV_AUTH_BYPASS", "true")
    monkeypatch.setenv("FG_SESSION_SECRET", "test-session-secret")
    app = build_app()
    with TestClient(app) as client:
        response = client.get("/admin/me")
    assert response.status_code == 200


def test_dev_bypass_refused_in_prod(monkeypatch):
    monkeypatch.setenv("FG_ENV", "prod")
    monkeypatch.setenv("FG_DEV_AUTH_BYPASS", "true")
    monkeypatch.setenv("FG_SESSION_SECRET", "test-session-secret")
    monkeypatch.setenv("FG_OIDC_ISSUER", "https://issuer.example.com")
    monkeypatch.setenv("FG_OIDC_CLIENT_ID", "client")
    monkeypatch.setenv("FG_OIDC_CLIENT_SECRET", "secret")
    monkeypatch.setenv(
        "FG_OIDC_REDIRECT_URL",
        "https://console.example.com/auth/callback",
    )
    with pytest.raises(RuntimeError):
        build_app()


def test_csrf_protects_state_changes(app):
    user = AuthUser(
        sub="tester",
        email="tester@example.com",
        scopes=["product:write"],
        tenants=["tenant-a"],
        exp=None,
    )

    def override_user():
        return user

    app.dependency_overrides[get_current_user] = override_user
    with TestClient(app) as client:
        response = client.post("/api/v1/products", json={"tenant_id": "tenant-a"})
        assert response.status_code == 403
        token = client.get("/auth/csrf").json()["csrf_token"]
        response = client.post(
            "/api/v1/products",
            json={"tenant_id": "tenant-a"},
            headers={"X-CSRF-Token": token},
        )
    assert response.status_code == 200


def test_rbac_enforced(app):
    user = AuthUser(
        sub="tester",
        email="tester@example.com",
        scopes=["product:read"],
        tenants=["tenant-a"],
        exp=None,
    )

    def override_user():
        return user

    app.dependency_overrides[get_current_user] = override_user
    with TestClient(app) as client:
        token = client.get("/auth/csrf").json()["csrf_token"]
        response = client.post(
            "/api/v1/products",
            json={"tenant_id": "tenant-a"},
            headers={"X-CSRF-Token": token},
        )
    assert response.status_code == 403


def test_tenant_scope_enforced(app):
    user = AuthUser(
        sub="tester",
        email="tester@example.com",
        scopes=["product:write"],
        tenants=["tenant-a"],
        exp=None,
    )

    def override_user():
        return user

    app.dependency_overrides[get_current_user] = override_user
    with TestClient(app) as client:
        token = client.get("/auth/csrf").json()["csrf_token"]
        response = client.post(
            "/api/v1/products",
            json={"tenant_id": "tenant-b"},
            headers={"X-CSRF-Token": token},
        )
    assert response.status_code == 403


def test_audit_event_emitted(app):
    events = []

    class StubAuditLogger:
        async def log_event(self, event):
            events.append(event)

    app.state.audit_logger = StubAuditLogger()

    def override_user():
        return AuthUser(
            sub="tester",
            email="tester@example.com",
            scopes=["console:admin"],
            tenants=["tenant-a"],
            exp=None,
        )

    app.dependency_overrides[get_current_user] = override_user
    with TestClient(app) as client:
        client.get("/admin/me")
    assert events
