"""Test fixtures for admin-gateway."""

import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def app(monkeypatch):
    """Create FastAPI app with test environment."""
    monkeypatch.setenv("FG_ENV", "dev")
    monkeypatch.setenv("FG_SESSION_SECRET", "test-session-secret")
    monkeypatch.delenv("FG_DEV_AUTH_BYPASS", raising=False)
    for key in (
        "FG_OIDC_ISSUER",
        "FG_OIDC_CLIENT_ID",
        "FG_OIDC_CLIENT_SECRET",
        "FG_OIDC_REDIRECT_URL",
    ):
        os.environ.pop(key, None)
    from admin_gateway.main import build_app

    return build_app()


@pytest.fixture
def client(app):
    """Create test client for admin-gateway."""
    with TestClient(app) as c:
        yield c
