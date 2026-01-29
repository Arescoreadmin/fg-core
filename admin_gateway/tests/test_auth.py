"""Tests for authentication and authorization."""

import pytest
from fastapi.testclient import TestClient

from admin_gateway.main import build_app


def test_admin_me_requires_auth(client_no_bypass):
    """Test that /admin/me requires authentication when bypass is disabled."""
    response = client_no_bypass.get("/admin/me")
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


def test_csrf_protects_state_changes(app_no_bypass):
    """Test CSRF protection when bypass is disabled."""
    # Import after module cache is cleared by fixture
    from admin_gateway.auth.dependencies import get_current_session
    from admin_gateway.auth.session import Session

    user = Session(
        user_id="tester",
        email="tester@example.com",
        scopes={"product:write"},
        claims={"allowed_tenants": ["tenant-a"]},
        tenant_id="tenant-a",
    )

    def override_user():
        return user

    app_no_bypass.dependency_overrides[get_current_session] = override_user
    with TestClient(app_no_bypass) as client:
        response = client.post("/api/v1/products", json={"tenant_id": "tenant-a"})
        assert response.status_code == 403
        csrf = client.get("/admin/csrf-token").json()
        token = csrf["csrf_token"]
        header = csrf["header_name"]
        response = client.post(
            "/api/v1/products",
            json={"tenant_id": "tenant-a"},
            headers={header: token},
        )
    assert response.status_code == 200


def test_rbac_enforced(app_no_bypass):
    """Test RBAC scope enforcement when bypass is disabled."""
    # Import after module cache is cleared by fixture
    from admin_gateway.auth.dependencies import get_current_session
    from admin_gateway.auth.session import Session

    user = Session(
        user_id="tester",
        email="tester@example.com",
        scopes={"product:read"},
        claims={"allowed_tenants": ["tenant-a"]},
        tenant_id="tenant-a",
    )

    def override_user():
        return user

    app_no_bypass.dependency_overrides[get_current_session] = override_user
    with TestClient(app_no_bypass) as client:
        csrf = client.get("/admin/csrf-token").json()
        token = csrf["csrf_token"]
        header = csrf["header_name"]
        response = client.post(
            "/api/v1/products",
            json={"tenant_id": "tenant-a"},
            headers={header: token},
        )
    assert response.status_code == 403


def test_tenant_scope_enforced(app_no_bypass):
    """Test tenant scope enforcement when bypass is disabled."""
    # Import after module cache is cleared by fixture
    from admin_gateway.auth.dependencies import get_current_session
    from admin_gateway.auth.session import Session

    user = Session(
        user_id="tester",
        email="tester@example.com",
        scopes={"product:write"},
        claims={"allowed_tenants": ["tenant-a"]},
        tenant_id="tenant-a",
    )

    def override_user():
        return user

    app_no_bypass.dependency_overrides[get_current_session] = override_user
    with TestClient(app_no_bypass) as client:
        csrf = client.get("/admin/csrf-token").json()
        token = csrf["csrf_token"]
        header = csrf["header_name"]
        response = client.post(
            "/api/v1/products",
            json={"tenant_id": "tenant-b"},
            headers={header: token},
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
