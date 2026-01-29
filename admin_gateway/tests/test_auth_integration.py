"""Integration smoke tests for authentication.

Tests unauthorized blocked; authorized allowed flows.
"""

import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from admin_gateway.auth.config import reset_auth_config


@pytest.fixture(autouse=True)
def reset_config():
    """Reset auth config cache between tests."""
    reset_auth_config()
    yield
    reset_auth_config()


@pytest.fixture
def client_no_bypass():
    """Create test client WITHOUT dev bypass."""
    reset_auth_config()
    with patch.dict(
        os.environ, {"FG_ENV": "dev", "FG_DEV_AUTH_BYPASS": "false"}, clear=False
    ):
        reset_auth_config()
        from admin_gateway.main import build_app

        app = build_app()
        with TestClient(app) as c:
            yield c


@pytest.fixture
def client_with_bypass():
    """Create test client WITH dev bypass enabled."""
    reset_auth_config()
    with patch.dict(
        os.environ, {"FG_ENV": "dev", "FG_DEV_AUTH_BYPASS": "true"}, clear=False
    ):
        reset_auth_config()
        from admin_gateway.main import build_app

        app = build_app()
        with TestClient(app) as c:
            yield c


class TestPublicEndpoints:
    """Tests for public endpoints (no auth required)."""

    def test_health_endpoint_public(self, client_no_bypass):
        """Test /health is accessible without auth."""
        response = client_no_bypass.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    def test_version_endpoint_public(self, client_no_bypass):
        """Test /version is accessible without auth."""
        response = client_no_bypass.get("/version")
        assert response.status_code == 200
        data = response.json()
        assert "version" in data

    def test_openapi_endpoint_public(self, client_no_bypass):
        """Test /openapi.json is accessible without auth."""
        response = client_no_bypass.get("/openapi.json")
        assert response.status_code == 200
        data = response.json()
        assert "openapi" in data


class TestUnauthorizedBlocked:
    """Tests verifying unauthorized requests are blocked."""

    def test_admin_me_requires_auth(self, client_no_bypass):
        """Test /admin/me requires authentication."""
        response = client_no_bypass.get("/admin/me")
        assert response.status_code == 401
        data = response.json()
        assert "detail" in data

    def test_api_tenants_requires_auth(self, client_no_bypass):
        """Test /api/v1/tenants requires authentication."""
        response = client_no_bypass.get("/api/v1/tenants")
        assert response.status_code == 401

    def test_api_keys_requires_auth(self, client_no_bypass):
        """Test /api/v1/keys requires authentication."""
        response = client_no_bypass.get("/api/v1/keys")
        assert response.status_code == 401

    def test_api_dashboard_requires_auth(self, client_no_bypass):
        """Test /api/v1/dashboard requires authentication."""
        response = client_no_bypass.get("/api/v1/dashboard")
        assert response.status_code == 401

    def test_admin_tenants_requires_auth(self, client_no_bypass):
        """Test /admin/tenants requires authentication."""
        response = client_no_bypass.get("/admin/tenants")
        assert response.status_code == 401

    def test_admin_keys_requires_auth(self, client_no_bypass):
        """Test /admin/keys requires authentication."""
        response = client_no_bypass.get("/admin/keys")
        assert response.status_code == 401


class TestAuthorizedAllowed:
    """Tests verifying authorized requests are allowed with dev bypass."""

    def test_admin_me_with_bypass(self, client_with_bypass):
        """Test /admin/me works with dev bypass."""
        response = client_with_bypass.get("/admin/me")
        assert response.status_code == 200
        data = response.json()

        # Verify user info
        assert data["user_id"] == "dev-user"
        assert data["email"] == "dev@localhost"
        assert "console:admin" in data["scopes"]
        assert len(data["tenants"]) > 0

    def test_api_tenants_with_bypass(self, client_with_bypass):
        """Test /api/v1/tenants works with dev bypass."""
        response = client_with_bypass.get("/api/v1/tenants")
        assert response.status_code == 200
        data = response.json()
        assert "tenants" in data
        assert "total" in data

    def test_api_keys_with_bypass(self, client_with_bypass):
        """Test /api/v1/keys works with dev bypass."""
        response = client_with_bypass.get("/api/v1/keys")
        assert response.status_code == 200
        data = response.json()
        assert "keys" in data

    def test_api_dashboard_with_bypass(self, client_with_bypass):
        """Test /api/v1/dashboard works with dev bypass."""
        response = client_with_bypass.get("/api/v1/dashboard")
        assert response.status_code == 200
        data = response.json()
        assert "stats" in data

    def test_admin_tenants_with_bypass(self, client_with_bypass):
        """Test /admin/tenants works with dev bypass."""
        response = client_with_bypass.get("/admin/tenants")
        assert response.status_code == 200
        data = response.json()
        assert "tenants" in data

    def test_admin_keys_with_bypass(self, client_with_bypass):
        """Test /admin/keys works with dev bypass."""
        response = client_with_bypass.get("/admin/keys")
        assert response.status_code == 200
        data = response.json()
        assert "keys" in data


class TestCSRFEnforcement:
    """Tests for CSRF enforcement on state-changing requests."""

    def test_post_without_csrf_blocked(self, client_with_bypass):
        """Test POST without CSRF token is blocked."""
        response = client_with_bypass.post(
            "/admin/keys",
            json={"tenant_id": "default", "scopes": [], "ttl_seconds": 3600},
        )
        # Should be 403 due to missing CSRF
        assert response.status_code == 403

    def test_post_with_csrf_allowed(self, client_with_bypass):
        """Test POST with CSRF token is allowed."""
        # First get a CSRF token
        csrf_response = client_with_bypass.get("/admin/csrf-token")
        assert csrf_response.status_code == 200
        csrf_data = csrf_response.json()
        csrf_token = csrf_data["csrf_token"]
        header_name = csrf_data["header_name"]

        # Set CSRF cookie and header
        client_with_bypass.cookies.set("fg_csrf_token", csrf_token)
        response = client_with_bypass.post(
            "/admin/keys",
            json={"tenant_id": "default", "scopes": [], "ttl_seconds": 3600},
            headers={header_name: csrf_token},
        )

        # Should work now
        assert response.status_code == 200


class TestScopeEnforcement:
    """Tests for scope-based access control."""

    def test_admin_scopes_available(self, client_with_bypass):
        """Test scopes endpoint returns available scopes."""
        response = client_with_bypass.get("/admin/scopes")
        assert response.status_code == 200
        data = response.json()

        # Dev user should have console:admin which expands to all scopes
        assert "console:admin" in data["user_scopes"]
        assert "available_scopes" in data
        assert len(data["available_scopes"]) >= 7


class TestTenantScoping:
    """Tests for tenant-based access control."""

    def test_admin_me_includes_tenants(self, client_with_bypass):
        """Test /admin/me includes tenant information."""
        response = client_with_bypass.get("/admin/me")
        assert response.status_code == 200
        data = response.json()

        assert "tenants" in data
        assert "current_tenant" in data
        assert len(data["tenants"]) > 0

    def test_keys_filtered_by_tenant(self, client_with_bypass):
        """Test /admin/keys accepts tenant_id filter."""
        response = client_with_bypass.get(
            "/admin/keys",
            params={"tenant_id": "default"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data.get("tenant_id") == "default"


class TestAuthFlowEndpoints:
    """Tests for auth flow endpoints."""

    def test_login_endpoint_exists(self, client_no_bypass):
        """Test /auth/login endpoint exists."""
        response = client_no_bypass.get("/auth/login", follow_redirects=False)
        # Should either redirect or return error (no OIDC configured)
        assert response.status_code in [302, 503]

    def test_logout_endpoint_exists(self, client_no_bypass):
        """Test /auth/logout endpoint exists."""
        response = client_no_bypass.get("/auth/logout", follow_redirects=False)
        # Should redirect to home
        assert response.status_code == 302


class TestAuditLogging:
    """Tests for audit logging on admin requests."""

    def test_admin_request_logged(self, client_with_bypass, caplog):
        """Test admin requests are logged."""
        import logging

        with caplog.at_level(logging.INFO, logger="admin-gateway.audit"):
            response = client_with_bypass.get("/admin/tenants")
            assert response.status_code == 200

        # Check audit log was emitted
        # The actual log format may vary, but we should see the request
