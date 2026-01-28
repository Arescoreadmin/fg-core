"""Tests for admin-gateway health endpoints."""


def test_health_returns_ok(client):
    """Test health endpoint returns ok status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "admin-gateway"
    assert "version" in data
    assert "timestamp" in data


def test_health_includes_request_id(client):
    """Test health endpoint includes request ID."""
    response = client.get("/health")
    assert response.status_code == 200
    assert "X-Request-Id" in response.headers
    data = response.json()
    assert data["request_id"] == response.headers["X-Request-Id"]


def test_health_propagates_request_id(client):
    """Test request ID is propagated from header."""
    custom_id = "test-request-123"
    response = client.get("/health", headers={"X-Request-Id": custom_id})
    assert response.status_code == 200
    assert response.headers["X-Request-Id"] == custom_id
    data = response.json()
    assert data["request_id"] == custom_id


def test_version_endpoint(client):
    """Test version endpoint returns service info."""
    response = client.get("/version")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "admin-gateway"
    assert "version" in data
    assert "api_version" in data


def test_openapi_json(client):
    """Test OpenAPI schema is available."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    data = response.json()
    assert "openapi" in data
    assert "info" in data
    assert data["info"]["title"] == "FrostGate Admin Gateway"
