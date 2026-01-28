"""Integration tests for Products Registry API.

Tests the full CRUD lifecycle and security controls.
"""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient


class TestProductsCRUD:
    """Test complete CRUD lifecycle: create -> list -> read -> patch -> test connection."""

    def test_create_product(self, client):
        """Test creating a new product."""
        response = client.post(
            "/admin/products",
            json={
                "slug": "test-product",
                "name": "Test Product",
                "env": "test",
                "owner": "test-team@example.com",
                "enabled": True,
                "endpoints": [
                    {
                        "kind": "rest",
                        "url": "https://api.example.com",
                    }
                ],
            },
            headers={"X-Tenant-ID": "test-tenant"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["slug"] == "test-product"
        assert data["name"] == "Test Product"
        assert data["env"] == "test"
        assert data["tenant_id"] == "test-tenant"
        assert data["enabled"] is True
        assert len(data["endpoints"]) == 1
        assert data["endpoints"][0]["kind"] == "rest"
        assert data["endpoints"][0]["url"] == "https://api.example.com"

    def test_list_products(self, client):
        """Test listing products after creation."""
        # Create two products
        client.post(
            "/admin/products",
            json={"slug": "product-a", "name": "Product A"},
            headers={"X-Tenant-ID": "test-tenant"},
        )
        client.post(
            "/admin/products",
            json={"slug": "product-b", "name": "Product B"},
            headers={"X-Tenant-ID": "test-tenant"},
        )

        # List products
        response = client.get(
            "/admin/products",
            headers={"X-Tenant-ID": "test-tenant"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        assert len(data["products"]) == 2
        slugs = [p["slug"] for p in data["products"]]
        assert "product-a" in slugs
        assert "product-b" in slugs

    def test_get_product(self, client):
        """Test getting a single product by ID."""
        # Create product
        create_resp = client.post(
            "/admin/products",
            json={"slug": "my-product", "name": "My Product"},
            headers={"X-Tenant-ID": "test-tenant"},
        )
        product_id = create_resp.json()["id"]

        # Get product
        response = client.get(
            f"/admin/products/{product_id}",
            headers={"X-Tenant-ID": "test-tenant"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == product_id
        assert data["slug"] == "my-product"
        assert data["name"] == "My Product"

    def test_patch_product(self, client):
        """Test updating a product."""
        # Create product
        create_resp = client.post(
            "/admin/products",
            json={
                "slug": "update-me",
                "name": "Original Name",
                "env": "development",
            },
            headers={"X-Tenant-ID": "test-tenant"},
        )
        product_id = create_resp.json()["id"]

        # Update product
        response = client.patch(
            f"/admin/products/{product_id}",
            json={
                "name": "Updated Name",
                "env": "production",
                "enabled": False,
            },
            headers={"X-Tenant-ID": "test-tenant"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated Name"
        assert data["env"] == "production"
        assert data["enabled"] is False
        assert data["slug"] == "update-me"  # Slug unchanged

    def test_patch_product_endpoints(self, client):
        """Test updating product endpoints."""
        # Create product with REST endpoint
        create_resp = client.post(
            "/admin/products",
            json={
                "slug": "endpoints-test",
                "name": "Endpoints Test",
                "endpoints": [{"kind": "rest", "url": "https://old.example.com"}],
            },
            headers={"X-Tenant-ID": "test-tenant"},
        )
        product_id = create_resp.json()["id"]

        # Update endpoints
        response = client.patch(
            f"/admin/products/{product_id}",
            json={
                "endpoints": [
                    {"kind": "rest", "url": "https://new.example.com"},
                    {"kind": "grpc", "url": "grpc.example.com:443"},
                ],
            },
            headers={"X-Tenant-ID": "test-tenant"},
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data["endpoints"]) == 2
        kinds = [ep["kind"] for ep in data["endpoints"]]
        assert "rest" in kinds
        assert "grpc" in kinds

    def test_test_connection_success(self, client):
        """Test connection endpoint with mocked successful response."""
        # Create product with endpoint
        create_resp = client.post(
            "/admin/products",
            json={
                "slug": "conntest",
                "name": "Connection Test",
                "endpoints": [{"kind": "rest", "url": "https://api.example.com"}],
            },
            headers={"X-Tenant-ID": "test-tenant"},
        )
        product_id = create_resp.json()["id"]

        # Mock httpx.AsyncClient
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            response = client.post(
                f"/admin/products/{product_id}/test-connection",
                headers={"X-Tenant-ID": "test-tenant"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["status_code"] == 200
        assert data["endpoint_url"] == "https://api.example.com/health"

    def test_test_connection_failure(self, client):
        """Test connection endpoint with mocked failure response."""
        # Create product
        create_resp = client.post(
            "/admin/products",
            json={
                "slug": "connfail",
                "name": "Connection Fail",
                "endpoints": [{"kind": "rest", "url": "https://api.example.com"}],
            },
            headers={"X-Tenant-ID": "test-tenant"},
        )
        product_id = create_resp.json()["id"]

        # Mock httpx.AsyncClient with connection error
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            response = client.post(
                f"/admin/products/{product_id}/test-connection",
                headers={"X-Tenant-ID": "test-tenant"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "Connection failed" in data["error"]

    def test_test_connection_no_endpoint(self, client):
        """Test connection endpoint when no endpoint configured."""
        # Create product without endpoints
        create_resp = client.post(
            "/admin/products",
            json={"slug": "no-endpoint", "name": "No Endpoint"},
            headers={"X-Tenant-ID": "test-tenant"},
        )
        product_id = create_resp.json()["id"]

        response = client.post(
            f"/admin/products/{product_id}/test-connection",
            headers={"X-Tenant-ID": "test-tenant"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "No REST endpoint" in data["error"]


class TestProductsValidation:
    """Test input validation."""

    def test_create_duplicate_slug(self, client):
        """Test creating product with duplicate slug returns 409."""
        # Create first product
        client.post(
            "/admin/products",
            json={"slug": "duplicate", "name": "First"},
            headers={"X-Tenant-ID": "test-tenant"},
        )

        # Try to create second with same slug
        response = client.post(
            "/admin/products",
            json={"slug": "duplicate", "name": "Second"},
            headers={"X-Tenant-ID": "test-tenant"},
        )
        assert response.status_code == 409
        assert "already exists" in response.json()["detail"]

    def test_create_invalid_slug(self, client):
        """Test creating product with invalid slug."""
        response = client.post(
            "/admin/products",
            json={"slug": "Invalid Slug!", "name": "Test"},
            headers={"X-Tenant-ID": "test-tenant"},
        )
        assert response.status_code == 422  # Validation error

    def test_get_nonexistent_product(self, client):
        """Test getting product that doesn't exist."""
        response = client.get(
            "/admin/products/99999",
            headers={"X-Tenant-ID": "test-tenant"},
        )
        assert response.status_code == 404

    def test_patch_nonexistent_product(self, client):
        """Test patching product that doesn't exist."""
        response = client.patch(
            "/admin/products/99999",
            json={"name": "New Name"},
            headers={"X-Tenant-ID": "test-tenant"},
        )
        assert response.status_code == 404


class TestTenantIsolation:
    """Test tenant scoping and cross-tenant access blocking."""

    def test_list_products_tenant_scoped(self, client):
        """Test that products are scoped to tenant."""
        # Create product for tenant A
        client.post(
            "/admin/products",
            json={"slug": "tenant-a-product", "name": "Tenant A Product"},
            headers={"X-Tenant-ID": "tenant-a"},
        )

        # Create product for tenant B
        client.post(
            "/admin/products",
            json={"slug": "tenant-b-product", "name": "Tenant B Product"},
            headers={"X-Tenant-ID": "tenant-b"},
        )

        # List products for tenant A
        response_a = client.get(
            "/admin/products",
            headers={"X-Tenant-ID": "tenant-a"},
        )
        assert response_a.status_code == 200
        data_a = response_a.json()
        assert data_a["total"] == 1
        assert data_a["products"][0]["slug"] == "tenant-a-product"

        # List products for tenant B
        response_b = client.get(
            "/admin/products",
            headers={"X-Tenant-ID": "tenant-b"},
        )
        assert response_b.status_code == 200
        data_b = response_b.json()
        assert data_b["total"] == 1
        assert data_b["products"][0]["slug"] == "tenant-b-product"

    def test_cross_tenant_get_blocked(self, client):
        """Test that tenant A cannot access tenant B's product."""
        # Create product for tenant A
        create_resp = client.post(
            "/admin/products",
            json={"slug": "private-product", "name": "Private"},
            headers={"X-Tenant-ID": "tenant-a"},
        )
        product_id = create_resp.json()["id"]

        # Try to access from tenant B - should get 404 (not found within tenant scope)
        response = client.get(
            f"/admin/products/{product_id}",
            headers={"X-Tenant-ID": "tenant-b"},
        )
        assert response.status_code == 404

    def test_cross_tenant_patch_blocked(self, client):
        """Test that tenant A cannot modify tenant B's product."""
        # Create product for tenant A
        create_resp = client.post(
            "/admin/products",
            json={"slug": "secure-product", "name": "Secure"},
            headers={"X-Tenant-ID": "tenant-a"},
        )
        product_id = create_resp.json()["id"]

        # Try to update from tenant B - should get 404
        response = client.patch(
            f"/admin/products/{product_id}",
            json={"name": "Hacked!"},
            headers={"X-Tenant-ID": "tenant-b"},
        )
        assert response.status_code == 404

    def test_same_slug_different_tenants(self, client):
        """Test that same slug can exist in different tenants."""
        # Create product in tenant A
        resp_a = client.post(
            "/admin/products",
            json={"slug": "shared-slug", "name": "Tenant A Version"},
            headers={"X-Tenant-ID": "tenant-a"},
        )
        assert resp_a.status_code == 201

        # Create product with same slug in tenant B
        resp_b = client.post(
            "/admin/products",
            json={"slug": "shared-slug", "name": "Tenant B Version"},
            headers={"X-Tenant-ID": "tenant-b"},
        )
        assert resp_b.status_code == 201

        # Both should have different IDs
        assert resp_a.json()["id"] != resp_b.json()["id"]


class TestRBACScopes:
    """Test RBAC scope enforcement."""

    @pytest.fixture
    def auth_client(self, tmp_path):
        """Create test client with auth enabled."""
        db_path = tmp_path / "auth_test.db"
        os.environ["AG_SQLITE_PATH"] = str(db_path)
        os.environ["AG_AUTH_ENABLED"] = "1"
        os.environ["AG_API_KEY"] = "test-api-key-12345"
        os.environ["AG_ENV"] = "test"

        # Clear module cache
        import sys

        mods_to_remove = [k for k in sys.modules if k.startswith("admin_gateway")]
        for mod in mods_to_remove:
            del sys.modules[mod]

        from admin_gateway.main import build_app

        app = build_app()

        with TestClient(app) as c:
            yield c

        # Cleanup
        os.environ.pop("AG_SQLITE_PATH", None)
        os.environ.pop("AG_AUTH_ENABLED", None)
        os.environ.pop("AG_API_KEY", None)
        os.environ.pop("AG_ENV", None)

    def test_missing_auth_returns_401(self, auth_client):
        """Test that missing API key returns 401."""
        response = auth_client.get(
            "/admin/products",
            headers={"X-Tenant-ID": "test-tenant"},
        )
        assert response.status_code == 401

    def test_invalid_auth_returns_401(self, auth_client):
        """Test that invalid API key returns 401."""
        response = auth_client.get(
            "/admin/products",
            headers={
                "X-Tenant-ID": "test-tenant",
                "X-API-Key": "invalid-key",
            },
        )
        assert response.status_code == 401

    def test_valid_auth_allows_access(self, auth_client):
        """Test that valid API key grants access."""
        response = auth_client.get(
            "/admin/products",
            headers={
                "X-Tenant-ID": "test-tenant",
                "X-API-Key": "test-api-key-12345",
            },
        )
        assert response.status_code == 200

    def test_valid_auth_allows_write(self, auth_client):
        """Test that valid API key allows write operations."""
        response = auth_client.post(
            "/admin/products",
            json={"slug": "auth-test", "name": "Auth Test"},
            headers={
                "X-Tenant-ID": "test-tenant",
                "X-API-Key": "test-api-key-12345",
            },
        )
        assert response.status_code == 201
