"""Test fixtures for admin-gateway."""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Create test client for admin-gateway."""
    from admin_gateway.main import build_app

    app = build_app()
    with TestClient(app) as c:
        yield c
