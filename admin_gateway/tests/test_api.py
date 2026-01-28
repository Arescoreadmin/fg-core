"""Tests for admin-gateway API endpoints."""


def test_list_tenants_returns_empty(client):
    """Test list tenants endpoint (placeholder)."""
    response = client.get("/api/v1/tenants")
    assert response.status_code == 200
    data = response.json()
    assert "tenants" in data
    assert "total" in data
    assert data["total"] == 0


def test_list_keys_returns_empty(client):
    """Test list keys endpoint (placeholder)."""
    response = client.get("/api/v1/keys")
    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    assert "total" in data
    assert data["total"] == 0


def test_dashboard_returns_stats(client):
    """Test dashboard endpoint returns stats."""
    response = client.get("/api/v1/dashboard")
    assert response.status_code == 200
    data = response.json()
    assert "stats" in data
    assert "recent_events" in data
    stats = data["stats"]
    assert "total_requests" in stats
    assert "blocked_requests" in stats
