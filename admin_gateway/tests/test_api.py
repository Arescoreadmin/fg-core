"""Tests for admin-gateway API endpoints."""

from fastapi.testclient import TestClient


def test_list_tenants_returns_allowed(app_no_bypass):
    """Test list tenants endpoint (placeholder)."""
    # Import after module cache is cleared by fixture
    from admin_gateway.auth import AuthUser, get_current_user

    def _override_user():
        return AuthUser(
            sub="tester",
            email="tester@example.com",
            scopes=["console:admin", "keys:read"],
            tenants=["tenant-a"],
            exp=None,
        )

    app_no_bypass.dependency_overrides[get_current_user] = _override_user
    with TestClient(app_no_bypass) as client:
        response = client.get("/api/v1/tenants")
    assert response.status_code == 200
    data = response.json()
    assert data["tenants"] == ["tenant-a"]
    assert data["total"] == 1


def test_list_keys_returns_empty(app_no_bypass):
    """Test list keys endpoint (placeholder)."""
    # Import after module cache is cleared by fixture
    from admin_gateway.auth import AuthUser, get_current_user

    def _override_user():
        return AuthUser(
            sub="tester",
            email="tester@example.com",
            scopes=["console:admin", "keys:read"],
            tenants=["tenant-a"],
            exp=None,
        )

    app_no_bypass.dependency_overrides[get_current_user] = _override_user
    with TestClient(app_no_bypass) as client:
        response = client.get("/api/v1/keys")
    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    assert "total" in data
    assert data["total"] == 0


def test_dashboard_returns_stats(app_no_bypass):
    """Test dashboard endpoint returns stats."""
    # Import after module cache is cleared by fixture
    from admin_gateway.auth import AuthUser, get_current_user

    def _override_user():
        return AuthUser(
            sub="tester",
            email="tester@example.com",
            scopes=["console:admin", "keys:read"],
            tenants=["tenant-a"],
            exp=None,
        )

    app_no_bypass.dependency_overrides[get_current_user] = _override_user
    with TestClient(app_no_bypass) as client:
        response = client.get("/api/v1/dashboard")
    assert response.status_code == 200
    data = response.json()
    assert "stats" in data
    assert "recent_events" in data
    stats = data["stats"]
    assert "total_requests" in stats
    assert "blocked_requests" in stats
