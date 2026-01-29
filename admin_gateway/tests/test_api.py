"""Tests for admin-gateway API endpoints."""

from fastapi.testclient import TestClient


def test_list_tenants_returns_allowed(app_no_bypass, session_cookie):
    """Test list tenants endpoint (placeholder)."""
    from admin_gateway.auth.session import Session

    session = Session(
        user_id="tester",
        email="tester@example.com",
        scopes={"console:admin", "keys:read"},
        claims={"allowed_tenants": ["tenant-a"]},
        tenant_id="tenant-a",
    )
    cookie_name, cookie_value = session_cookie(session)
    with TestClient(app_no_bypass) as client:
        client.cookies.set(cookie_name, cookie_value)
        response = client.get("/api/v1/tenants")
    assert response.status_code == 200
    data = response.json()
    assert data["tenants"] == ["tenant-a"]
    assert data["total"] == 1


def test_list_keys_returns_empty(app_no_bypass, session_cookie):
    """Test list keys endpoint (placeholder)."""
    from admin_gateway.auth.session import Session

    session = Session(
        user_id="tester",
        email="tester@example.com",
        scopes={"console:admin", "keys:read"},
        claims={"allowed_tenants": ["tenant-a"]},
        tenant_id="tenant-a",
    )
    cookie_name, cookie_value = session_cookie(session)
    with TestClient(app_no_bypass) as client:
        client.cookies.set(cookie_name, cookie_value)
        response = client.get("/api/v1/keys")
    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    assert "total" in data
    assert data["total"] == 0


def test_dashboard_returns_stats(app_no_bypass, session_cookie):
    """Test dashboard endpoint returns stats."""
    from admin_gateway.auth.session import Session

    session = Session(
        user_id="tester",
        email="tester@example.com",
        scopes={"console:admin", "keys:read"},
        claims={"allowed_tenants": ["tenant-a"]},
        tenant_id="tenant-a",
    )
    cookie_name, cookie_value = session_cookie(session)
    with TestClient(app_no_bypass) as client:
        client.cookies.set(cookie_name, cookie_value)
        response = client.get("/api/v1/dashboard")
    assert response.status_code == 200
    data = response.json()
    assert "stats" in data
    assert "recent_events" in data
    stats = data["stats"]
    assert "total_requests" in stats
    assert "blocked_requests" in stats
