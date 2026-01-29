"""Tests for authentication and authorization."""

import pytest
from fastapi.testclient import TestClient


def test_admin_me_requires_auth(client_no_bypass):
    """Test that /admin/me requires authentication when bypass is disabled."""
    response = client_no_bypass.get("/admin/me")
    assert response.status_code == 401


def test_dev_bypass_allows_access(monkeypatch):
    monkeypatch.setenv("FG_ENV", "dev")
    monkeypatch.setenv("FG_DEV_AUTH_BYPASS", "true")
    monkeypatch.setenv("FG_SESSION_SECRET", "test-session-secret")
    from admin_gateway.auth.config import reset_auth_config
    from admin_gateway.main import build_app

    reset_auth_config()
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
    import importlib
    import sys

    from admin_gateway.auth.config import reset_auth_config

    reset_auth_config()
    sys.modules.pop("admin_gateway.main", None)
    with pytest.raises(RuntimeError):
        importlib.import_module("admin_gateway.main")


def test_csrf_protects_state_changes(app_no_bypass, csrf_headers, session_cookie):
    """Test CSRF protection when bypass is disabled."""
    from admin_gateway.auth.session import Session

    user = Session(
        user_id="tester",
        email="tester@example.com",
        scopes={"product:write"},
        claims={"allowed_tenants": ["tenant-a"]},
        tenant_id="tenant-a",
    )

    with TestClient(app_no_bypass) as client:
        cookie_name, cookie_value = session_cookie(user)
        client.cookies.set(cookie_name, cookie_value)
        response = client.post("/api/v1/products", json={"tenant_id": "tenant-a"})
        assert response.status_code == 403
        response = client.post(
            "/api/v1/products",
            json={"tenant_id": "tenant-a"},
            headers=csrf_headers(client),
        )
    assert response.status_code == 200


def test_rbac_enforced(app_no_bypass, csrf_headers, session_cookie):
    """Test RBAC scope enforcement when bypass is disabled."""
    from admin_gateway.auth.session import Session

    user = Session(
        user_id="tester",
        email="tester@example.com",
        scopes={"product:read"},
        claims={"allowed_tenants": ["tenant-a"]},
        tenant_id="tenant-a",
    )

    with TestClient(app_no_bypass) as client:
        cookie_name, cookie_value = session_cookie(user)
        client.cookies.set(cookie_name, cookie_value)
        response = client.post(
            "/api/v1/products",
            json={"tenant_id": "tenant-a"},
            headers=csrf_headers(client),
        )
    assert response.status_code == 403


def test_tenant_scope_enforced(app_no_bypass, csrf_headers, session_cookie):
    """Test tenant scope enforcement when bypass is disabled."""
    from admin_gateway.auth.session import Session

    user = Session(
        user_id="tester",
        email="tester@example.com",
        scopes={"product:write"},
        claims={"allowed_tenants": ["tenant-a"]},
        tenant_id="tenant-a",
    )

    with TestClient(app_no_bypass) as client:
        cookie_name, cookie_value = session_cookie(user)
        client.cookies.set(cookie_name, cookie_value)
        response = client.post(
            "/api/v1/products",
            json={"tenant_id": "tenant-b"},
            headers=csrf_headers(client),
        )
    assert response.status_code == 403


def test_audit_event_emitted(app):
    """Test audit events are emitted."""
    # Import after module cache is cleared by fixture
    from admin_gateway.auth.dependencies import get_current_session
    from admin_gateway.auth.session import Session

    events = []

    class StubAuditLogger:
        async def log_event(self, event):
            events.append(event)

    app.state.audit_logger = StubAuditLogger()

    def override_user():
        return Session(
            user_id="tester",
            email="tester@example.com",
            scopes={"console:admin"},
            claims={"allowed_tenants": ["tenant-a"]},
            tenant_id="tenant-a",
        )

    app.dependency_overrides[get_current_session] = override_user
    with TestClient(app) as client:
        client.get("/admin/me")
    assert events
