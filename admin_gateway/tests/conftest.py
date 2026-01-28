"""Test fixtures for admin-gateway."""

import os
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path):
    """Set up test environment with SQLite and disabled auth."""
    db_path = tmp_path / "test.db"
    os.environ["AG_SQLITE_PATH"] = str(db_path)
    os.environ["AG_AUTH_ENABLED"] = "0"
    os.environ["AG_ENV"] = "test"

    # Clear module cache to pick up new env vars
    mods_to_remove = [k for k in sys.modules if k.startswith("admin_gateway")]
    for mod in mods_to_remove:
        del sys.modules[mod]

    yield

    # Cleanup
    os.environ.pop("AG_SQLITE_PATH", None)
    os.environ.pop("AG_AUTH_ENABLED", None)
    os.environ.pop("AG_ENV", None)


@pytest.fixture
def client(setup_test_env):
    """Create test client for admin-gateway."""
    from admin_gateway.main import build_app

    app = build_app()
    with TestClient(app) as c:
        yield c
