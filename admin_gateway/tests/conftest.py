"""Test fixtures for admin-gateway."""

import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path, monkeypatch):
    """Set up test environment with SQLite and dev auth bypass."""
    db_path = tmp_path / "test.db"

    # Set environment variables for database
    monkeypatch.setenv("AG_SQLITE_PATH", str(db_path))

    # Set environment variables for auth bypass in dev mode
    monkeypatch.setenv("FG_ENV", "dev")
    monkeypatch.setenv("FG_SESSION_SECRET", "test-session-secret")
    monkeypatch.setenv("FG_DEV_AUTH_BYPASS", "1")

    # Clear OIDC env vars to ensure dev mode
    for key in (
        "FG_OIDC_ISSUER",
        "FG_OIDC_CLIENT_ID",
        "FG_OIDC_CLIENT_SECRET",
        "FG_OIDC_REDIRECT_URL",
    ):
        monkeypatch.delenv(key, raising=False)

    # Clear module cache to pick up new env vars
    mods_to_remove = [k for k in sys.modules if k.startswith("admin_gateway")]
    for mod in mods_to_remove:
        del sys.modules[mod]

    yield


@pytest.fixture
def app(setup_test_env):
    """Create FastAPI app with test environment (dev bypass enabled)."""
    from admin_gateway.main import build_app

    return build_app()


@pytest.fixture
def app_no_bypass(tmp_path, monkeypatch):
    """Create FastAPI app without dev auth bypass (for testing auth behavior)."""
    db_path = tmp_path / "auth_test.db"

    # Set environment variables for database
    monkeypatch.setenv("AG_SQLITE_PATH", str(db_path))

    # Set environment WITHOUT dev bypass
    monkeypatch.setenv("FG_ENV", "dev")
    monkeypatch.setenv("FG_SESSION_SECRET", "test-session-secret")
    monkeypatch.delenv("FG_DEV_AUTH_BYPASS", raising=False)

    # Clear OIDC env vars
    for key in (
        "FG_OIDC_ISSUER",
        "FG_OIDC_CLIENT_ID",
        "FG_OIDC_CLIENT_SECRET",
        "FG_OIDC_REDIRECT_URL",
    ):
        monkeypatch.delenv(key, raising=False)

    # Clear module cache
    mods_to_remove = [k for k in sys.modules if k.startswith("admin_gateway")]
    for mod in mods_to_remove:
        del sys.modules[mod]

    from admin_gateway.main import build_app

    return build_app()


@pytest.fixture
def client(app):
    """Create test client for admin-gateway (with dev bypass)."""
    with TestClient(app) as c:
        yield c


@pytest.fixture
def client_no_bypass(app_no_bypass):
    """Create test client without dev bypass (for testing auth behavior)."""
    with TestClient(app_no_bypass) as c:
        yield c
