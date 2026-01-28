"""Tests for admin-gateway API endpoints."""

import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from admin_gateway.auth.config import reset_auth_config


@pytest.fixture
def auth_client():
    """Create authenticated test client with dev bypass."""
    reset_auth_config()
    with patch.dict(
        os.environ,
        {"FG_ENV": "dev", "FG_DEV_AUTH_BYPASS": "true"},
        clear=False,
    ):
        reset_auth_config()
        from admin_gateway.main import build_app

        app = build_app()
        with TestClient(app) as c:
            yield c


def test_list_tenants_returns_empty(auth_client):
    """Test list tenants endpoint (placeholder)."""
    response = auth_client.get("/api/v1/tenants")
    assert response.status_code == 200
    data = response.json()
    assert "tenants" in data
    assert "total" in data
    assert data["total"] == 0


def test_list_keys_returns_empty(auth_client):
    """Test list keys endpoint (placeholder)."""
    response = auth_client.get("/api/v1/keys")
    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    assert "total" in data
    assert data["total"] == 0


def test_dashboard_returns_stats(auth_client):
    """Test dashboard endpoint returns stats."""
    response = auth_client.get("/api/v1/dashboard")
    assert response.status_code == 200
    data = response.json()
    assert "stats" in data
    assert "recent_events" in data
    stats = data["stats"]
    assert "total_requests" in stats
    assert "blocked_requests" in stats
