"""Test fixtures for admin-gateway."""

import sys

import pytest
from fastapi.testclient import TestClient

DEFAULT_TENANTS = ["tenant-dev", "tenant-2"]
DEFAULT_SCOPES = [
    "console:admin",
    "product:read",
    "product:write",
    "keys:read",
    "keys:write",
]


async def _mock_proxy_to_core(request, method, path, params=None, json_body=None):
    if path == "/admin/keys" and method == "GET":
        return {
            "keys": [],
            "total": 0,
            "tenant_id": (params or {}).get("tenant_id"),
        }
    if path == "/admin/keys" and method == "POST":
        tenant_id = (json_body or {}).get("tenant_id")
        return {
            "key": "fgk.mock.token",
            "prefix": "fgk",
            "scopes": (json_body or {}).get("scopes", []),
            "tenant_id": tenant_id,
            "ttl_seconds": (json_body or {}).get("ttl_seconds", 86400),
            "expires_at": 0,
        }
    if path.endswith("/revoke") and method == "POST":
        prefix = path.split("/")[-2]
        return {
            "revoked": True,
            "prefix": prefix,
            "message": "Key successfully revoked",
        }
    if path.endswith("/rotate") and method == "POST":
        prefix = path.split("/")[-2]
        return {
            "new_key": "fgk.rotated.token",
            "new_prefix": "fgk",
            "old_prefix": prefix,
            "scopes": ["read"],
            "tenant_id": (params or {}).get("tenant_id"),
            "expires_at": 0,
            "old_key_revoked": True,
        }
    return {}


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
    monkeypatch.setenv("FG_DEV_AUTH_USER_ID", "test-user")
    monkeypatch.setenv("FG_DEV_AUTH_EMAIL", "test-user@example.com")
    monkeypatch.setenv("FG_DEV_AUTH_NAME", "Test User")
    monkeypatch.setenv("FG_DEV_AUTH_TENANTS", ",".join(DEFAULT_TENANTS))
    monkeypatch.setenv("FG_DEV_AUTH_SCOPES", ",".join(DEFAULT_SCOPES))
    monkeypatch.setenv("AG_CORE_BASE_URL", "http://core.local")
    monkeypatch.setenv("AG_CORE_API_KEY", "test-core-key")

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


@pytest.fixture(autouse=True)
def mock_core_proxy(monkeypatch, setup_test_env):
    """Mock core proxy calls for admin key endpoints."""
    from admin_gateway.routers import admin as admin_router

    monkeypatch.setattr(admin_router, "_proxy_to_core", _mock_proxy_to_core)


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
    monkeypatch.setenv("AG_CORE_BASE_URL", "http://core.local")
    monkeypatch.setenv("AG_CORE_API_KEY", "test-core-key")

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
    from admin_gateway.routers import admin as admin_router

    app_instance = build_app()
    monkeypatch.setattr(admin_router, "_proxy_to_core", _mock_proxy_to_core)
    return app_instance


@pytest.fixture
def csrf_headers():
    """Return a function that generates CSRF headers for a client."""

    def _factory(client):
        response = client.get("/admin/csrf-token")
        assert response.status_code == 200
        data = response.json()
        return {data["header_name"]: data["csrf_token"]}

    return _factory


@pytest.fixture
def session_cookie():
    """Return a function that creates a session cookie value for a session."""

    def _factory(session):
        from admin_gateway.auth.config import get_auth_config
        from admin_gateway.auth.session import SessionManager

        config = get_auth_config()
        manager = SessionManager(config)
        return config.session_cookie_name, manager.encode_session(session)

    return _factory


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
