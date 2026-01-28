"""Test fixtures for admin-gateway."""

import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Create test client for admin-gateway (unauthenticated)."""
    from admin_gateway.auth.config import reset_auth_config

    reset_auth_config()
    with patch.dict(
        os.environ,
        {"FG_ENV": "dev", "FG_DEV_AUTH_BYPASS": "false"},
        clear=False,
    ):
        reset_auth_config()
        from admin_gateway.main import build_app

        app = build_app()
        with TestClient(app) as c:
            yield c


@pytest.fixture
def auth_client():
    """Create authenticated test client with dev bypass."""
    from admin_gateway.auth.config import reset_auth_config

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
