"""Integration tests for Products Registry API.

Tests the full CRUD lifecycle and security controls.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from fastapi.testclient import TestClient


class TestProductsCRUD:
    """Test complete CRUD lifecycle: create -> list -> read -> patch -> test connection."""

    def test_create_product(self, client, csrf_headers):
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
            headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["slug"] == "test-product"
        assert data["name"] == "Test Product"
        assert data["env"] == "test"
        assert data["tenant_id"] == "tenant-dev"
        assert data["enabled"] is True
        assert len(data["endpoints"]) == 1
        assert data["endpoints"][0]["kind"] == "rest"
        assert data["endpoints"][0]["url"] == "https://api.example.com"

    def test_list_products(self, client, csrf_headers):
        """Test listing products after creation."""
        # Create two products
        client.post(
            "/admin/products",
            json={"slug": "product-a", "name": "Product A"},
            headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
        )
        client.post(
            "/admin/products",
            json={"slug": "product-b", "name": "Product B"},
            headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
        )

        # List products
        response = client.get(
            "/admin/products",
            headers={"X-Tenant-ID": "tenant-dev"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        assert len(data["products"]) == 2
        slugs = [p["slug"] for p in data["products"]]
        assert "product-a" in slugs
        assert "product-b" in slugs

    def test_get_product(self, client, csrf_headers):
        """Test getting a single product by ID."""
        # Create product
        create_resp = client.post(
            "/admin/products",
            json={"slug": "my-product", "name": "My Product"},
            headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
        )
        product_id = create_resp.json()["id"]

        # Get product
        response = client.get(
            f"/admin/products/{product_id}",
            headers={"X-Tenant-ID": "tenant-dev"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == product_id
        assert data["slug"] == "my-product"
        assert data["name"] == "My Product"

    def test_patch_product(self, client, csrf_headers):
        """Test updating a product."""
        # Create product
        create_resp = client.post(
            "/admin/products",
            json={
                "slug": "update-me",
                "name": "Original Name",
                "env": "development",
            },
            headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
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
            headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated Name"
        assert data["env"] == "production"
        assert data["enabled"] is False
        assert data["slug"] == "update-me"  # Slug unchanged

    def test_patch_product_endpoints(self, client, csrf_headers):
        """Test updating product endpoints."""
        # Create product with REST endpoint
        create_resp = client.post(
            "/admin/products",
            json={
                "slug": "endpoints-test",
                "name": "Endpoints Test",
                "endpoints": [{"kind": "rest", "url": "https://old.example.com"}],
            },
            headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
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
            headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data["endpoints"]) == 2
        kinds = [ep["kind"] for ep in data["endpoints"]]
        assert "rest" in kinds
        assert "grpc" in kinds

    def test_test_connection_success(self, client, csrf_headers):
        """Test connection endpoint with mocked successful response."""
        # Create product with endpoint
        create_resp = client.post(
            "/admin/products",
            json={
                "slug": "conntest",
                "name": "Connection Test",
                "endpoints": [{"kind": "rest", "url": "https://api.example.com"}],
            },
            headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
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

            with patch("socket.getaddrinfo") as mock_getaddrinfo:
                mock_getaddrinfo.return_value = [
                    (None, None, None, None, ("93.184.216.34", 0))
                ]
                response = client.post(
                    f"/admin/products/{product_id}/test-connection",
                    headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
                )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["status_code"] == 200
        assert data["endpoint_url"] == "https://api.example.com/health"

    def test_test_connection_failure(self, client, csrf_headers):
        """Test connection endpoint with mocked failure response."""
        # Create product
        create_resp = client.post(
            "/admin/products",
            json={
                "slug": "connfail",
                "name": "Connection Fail",
                "endpoints": [{"kind": "rest", "url": "https://api.example.com"}],
            },
            headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
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

            with patch("socket.getaddrinfo") as mock_getaddrinfo:
                mock_getaddrinfo.return_value = [
                    (None, None, None, None, ("93.184.216.34", 0))
                ]
                response = client.post(
                    f"/admin/products/{product_id}/test-connection",
                    headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
                )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "Connection failed" in data["error"]

    def test_test_connection_no_endpoint(self, client, csrf_headers):
        """Test connection endpoint when no endpoint configured."""
        # Create product without endpoints
        create_resp = client.post(
            "/admin/products",
            json={"slug": "no-endpoint", "name": "No Endpoint"},
            headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
        )
        product_id = create_resp.json()["id"]

        response = client.post(
            f"/admin/products/{product_id}/test-connection",
            headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "No REST endpoint" in data["error"]


class TestProductsSSRF:
    """Test SSRF protections for test-connection."""

    def _create_product(self, client, csrf_headers, url: str) -> int:
        response = client.post(
            "/admin/products",
            json={
                "slug": "ssrf-test",
                "name": "SSRF Test",
                "endpoints": [{"kind": "rest", "url": url}],
            },
            headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
        )
        return response.json()["id"]

    def test_blocks_localhost(self, client, csrf_headers):
        product_id = self._create_product(client, csrf_headers, "http://localhost:8080")
        response = client.post(
            f"/admin/products/{product_id}/test-connection",
            headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "Blocked endpoint host"

    def test_blocks_loopback_ip(self, client, csrf_headers):
        product_id = self._create_product(client, csrf_headers, "http://127.0.0.1:8080")
        response = client.post(
            f"/admin/products/{product_id}/test-connection",
            headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "Blocked endpoint host"

    def test_blocks_link_local(self, client, csrf_headers):
        product_id = self._create_product(
            client, csrf_headers, "http://169.254.169.254"
        )
        response = client.post(
            f"/admin/products/{product_id}/test-connection",
            headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "Blocked endpoint host"

    def test_blocks_internal_dns(self, client, csrf_headers):
        product_id = self._create_product(
            client, csrf_headers, "http://internal.example.test"
        )
        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [(None, None, None, None, ("10.0.0.5", 0))]
            response = client.post(
                f"/admin/products/{product_id}/test-connection",
                headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
            )
        assert response.status_code == 400
        assert response.json()["detail"] == "Blocked endpoint host"

    def test_blocks_redirects(self, client, csrf_headers):
        product_id = self._create_product(
            client, csrf_headers, "https://api.example.com"
        )
        mock_response = MagicMock()
        mock_response.status_code = 302
        mock_response.headers = {"location": "http://127.0.0.1"}

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            with patch("socket.getaddrinfo") as mock_getaddrinfo:
                mock_getaddrinfo.return_value = [
                    (None, None, None, None, ("93.184.216.34", 0))
                ]
                response = client.post(
                    f"/admin/products/{product_id}/test-connection",
                    headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
                )

        assert response.status_code == 400
        assert response.json()["detail"] == "Redirects are not allowed"

    def test_allows_public_https(self, client, csrf_headers):
        product_id = self._create_product(
            client, csrf_headers, "https://api.example.com"
        )
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            with patch("socket.getaddrinfo") as mock_getaddrinfo:
                mock_getaddrinfo.return_value = [
                    (None, None, None, None, ("93.184.216.34", 0))
                ]
                response = client.post(
                    f"/admin/products/{product_id}/test-connection",
                    headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
                )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True


class TestProductsValidation:
    """Test input validation."""

    def test_create_duplicate_slug(self, client, csrf_headers):
        """Test creating product with duplicate slug returns 409."""
        # Create first product
        client.post(
            "/admin/products",
            json={"slug": "duplicate", "name": "First"},
            headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
        )

        # Try to create second with same slug
        response = client.post(
            "/admin/products",
            json={"slug": "duplicate", "name": "Second"},
            headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
        )
        assert response.status_code == 409
        assert "already exists" in response.json()["detail"]

    def test_create_invalid_slug(self, client, csrf_headers):
        """Test creating product with invalid slug."""
        response = client.post(
            "/admin/products",
            json={"slug": "Invalid Slug!", "name": "Test"},
            headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
        )
        assert response.status_code == 422  # Validation error

    def test_get_nonexistent_product(self, client):
        """Test getting product that doesn't exist."""
        response = client.get(
            "/admin/products/99999",
            headers={"X-Tenant-ID": "tenant-dev"},
        )
        assert response.status_code == 404

    def test_patch_nonexistent_product(self, client, csrf_headers):
        """Test patching product that doesn't exist."""
        response = client.patch(
            "/admin/products/99999",
            json={"name": "New Name"},
            headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
        )
        assert response.status_code == 404


class TestTenantIsolation:
    """Test tenant scoping and access control."""

    def test_unauthorized_tenant_returns_403(self, client):
        """Test that accessing unauthorized tenant returns 403."""
        # Try to access a tenant not in the user's tenants list
        response = client.get(
            "/admin/products",
            headers={"X-Tenant-ID": "unauthorized-tenant"},
        )
        assert response.status_code == 403
        assert "Tenant access denied" in response.json()["detail"]

    def test_missing_tenant_rejected_for_write(self, client, csrf_headers):
        """Test that missing tenant header is rejected for writes."""
        response = client.post(
            "/admin/products",
            json={"slug": "default-tenant-product", "name": "Default Tenant"},
            headers=csrf_headers(client),
        )
        assert response.status_code == 400

    def test_tenant_scoped_queries(self, client, csrf_headers):
        """Test that products are scoped to tenant."""
        # Create product
        create_resp = client.post(
            "/admin/products",
            json={"slug": "scoped-product", "name": "Scoped Product"},
            headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
        )
        assert create_resp.status_code == 201
        product_id = create_resp.json()["id"]

        # Should be visible within same tenant
        get_resp = client.get(
            f"/admin/products/{product_id}",
            headers={"X-Tenant-ID": "tenant-dev"},
        )
        assert get_resp.status_code == 200

        # Verify it's in the list
        list_resp = client.get(
            "/admin/products",
            headers={"X-Tenant-ID": "tenant-dev"},
        )
        assert list_resp.status_code == 200
        slugs = [p["slug"] for p in list_resp.json()["products"]]
        assert "scoped-product" in slugs


class TestProductsRBAC:
    """Test RBAC enforcement for products endpoints."""

    def test_list_requires_product_read(self, app_no_bypass, session_cookie):
        from admin_gateway.auth.session import Session

        def _no_product_scope():
            return Session(
                user_id="rbac-user",
                scopes={"keys:read"},
                tenant_id="tenant-dev",
                claims={"allowed_tenants": ["tenant-dev"]},
            )

        with TestClient(app_no_bypass) as client:
            session = _no_product_scope()
            cookie_name, cookie_value = session_cookie(session)
            client.cookies.set(cookie_name, cookie_value)
            response = client.get(
                "/admin/products",
                headers={"X-Tenant-ID": "tenant-dev"},
            )
        assert response.status_code == 403

    def test_create_requires_product_write(
        self, app_no_bypass, csrf_headers, session_cookie
    ):
        from admin_gateway.auth.session import Session

        def _read_only():
            return Session(
                user_id="rbac-user",
                scopes={"product:read"},
                tenant_id="tenant-dev",
                claims={"allowed_tenants": ["tenant-dev"]},
            )

        with TestClient(app_no_bypass) as client:
            session = _read_only()
            cookie_name, cookie_value = session_cookie(session)
            client.cookies.set(cookie_name, cookie_value)
            response = client.post(
                "/admin/products",
                json={"slug": "rbac-create", "name": "RBAC Create"},
                headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
            )
        assert response.status_code == 403

    def test_patch_requires_product_write(
        self, app_no_bypass, csrf_headers, session_cookie
    ):
        from admin_gateway.auth.session import Session

        def _writer():
            return Session(
                user_id="rbac-user",
                scopes={"product:write"},
                tenant_id="tenant-dev",
                claims={"allowed_tenants": ["tenant-dev"]},
            )

        def _reader():
            return Session(
                user_id="rbac-user",
                scopes={"product:read"},
                tenant_id="tenant-dev",
                claims={"allowed_tenants": ["tenant-dev"]},
            )

        with TestClient(app_no_bypass) as client:
            writer_session = _writer()
            cookie_name, cookie_value = session_cookie(writer_session)
            client.cookies.set(cookie_name, cookie_value)
            create_resp = client.post(
                "/admin/products",
                json={"slug": "rbac-update", "name": "RBAC Update"},
                headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
            )
            product_id = create_resp.json()["id"]

            reader_session = _reader()
            cookie_name, cookie_value = session_cookie(reader_session)
            client.cookies.set(cookie_name, cookie_value)
            response = client.patch(
                f"/admin/products/{product_id}",
                json={"name": "Blocked"},
                headers={**csrf_headers(client), "X-Tenant-ID": "tenant-dev"},
            )
        assert response.status_code == 403
