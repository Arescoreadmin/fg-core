from __future__ import annotations

import os

from fastapi.testclient import TestClient

from api.main import build_app
from api.security.public_paths import PUBLIC_PATHS_PREFIX


def test_build_app_mounts_required_router_paths() -> None:
    app = build_app()
    paths = {getattr(route, "path", "") for route in app.routes}
    required = {
        "/defend",
        "/ingest",
        "/feed/live",
        "/decisions",
        "/stats",
        "/config/versions",
        "/billing/invoices",
        "/audit/exams",
        "/admin/connectors/status",
        "/planes",
        "/evidence/runs",
    }
    missing = sorted(p for p in required if p not in paths)
    assert not missing, f"missing mounted routes: {missing}"


def test_debug_not_in_public_paths_prefix() -> None:
    """/_debug must not appear in PUBLIC_PATHS_PREFIX — P0 security fix."""
    for prefix in PUBLIC_PATHS_PREFIX:
        assert not prefix.startswith("/_debug"), (
            f"/_debug found in PUBLIC_PATHS_PREFIX as {prefix!r}; "
            "this bypasses auth middleware for the debug route"
        )


def test_debug_routes_unauthenticated_is_401(build_app) -> None:
    """Unauthenticated GET /_debug/routes must be rejected with 401."""
    app = build_app(auth_enabled=True)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/_debug/routes")
    assert resp.status_code == 401, (
        f"Expected 401 for unauthenticated /_debug/routes, got {resp.status_code}"
    )


def test_debug_routes_authenticated_is_200(build_app) -> None:
    """Authenticated GET /_debug/routes must succeed."""
    api_key = os.environ.get(
        "FG_API_KEY", "ci-test-key-00000000000000000000000000000000"
    )
    app = build_app(auth_enabled=True)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/_debug/routes", headers={"X-API-Key": api_key})
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("ok") is True


def test_debug_routes_bad_key_is_401(build_app) -> None:
    """Wrong API key must be rejected with 401 — not silently allowed."""
    app = build_app(auth_enabled=True)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/_debug/routes", headers={"X-API-Key": "not-a-valid-key"})
    assert resp.status_code == 401, (
        f"Expected 401 for bad API key on /_debug/routes, got {resp.status_code}"
    )


def test_debug_routes_auth_disabled_is_200(build_app) -> None:
    """When auth is disabled (dev/test env), /_debug/routes is accessible."""
    app = build_app(auth_enabled=False)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/_debug/routes")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# /metrics — P0-3: removed from PUBLIC_PATHS_EXACT, now auth-gated
# ---------------------------------------------------------------------------


def test_metrics_not_in_public_paths_exact() -> None:
    """/metrics must not appear in PUBLIC_PATHS_EXACT after P0-3 hardening."""
    from api.security.public_paths import PUBLIC_PATHS_EXACT

    assert "/metrics" not in PUBLIC_PATHS_EXACT, (
        "/metrics found in PUBLIC_PATHS_EXACT; it should require auth in production"
    )


def test_metrics_unauthenticated_is_401(build_app) -> None:
    """Unauthenticated GET /metrics must be rejected with 401 when auth is enabled."""
    app = build_app(auth_enabled=True)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/metrics")
    assert resp.status_code == 401, (
        f"Expected 401 for unauthenticated /metrics, got {resp.status_code}"
    )


def test_metrics_bad_key_is_401(build_app) -> None:
    """Wrong API key must be rejected for /metrics."""
    app = build_app(auth_enabled=True)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/metrics", headers={"X-API-Key": "not-a-valid-key"})
    assert resp.status_code == 401, (
        f"Expected 401 for bad API key on /metrics, got {resp.status_code}"
    )


def test_metrics_authenticated_is_200(build_app) -> None:
    """Authenticated GET /metrics must return Prometheus text format."""
    import os

    api_key = os.environ.get(
        "FG_API_KEY", "ci-test-key-00000000000000000000000000000000"
    )
    app = build_app(auth_enabled=True)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/metrics", headers={"X-API-Key": api_key})
    assert resp.status_code == 200, (
        f"Expected 200 for authenticated /metrics, got {resp.status_code}"
    )


def test_metrics_auth_disabled_is_200(build_app) -> None:
    """When auth is disabled (dev/test env), /metrics is accessible without credentials."""
    app = build_app(auth_enabled=False)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/metrics")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# /ui/* — P0-3: confirm route-level scope protection survives middleware bypass
# ---------------------------------------------------------------------------


def test_ui_unauthenticated_is_401(build_app) -> None:
    """/ui/* routes must reject unauthenticated requests even though auth_gate
    middleware bypasses the /ui prefix (route-level require_scopes enforces auth)."""
    app = build_app(auth_enabled=True)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/ui/ai")
    assert resp.status_code in (401, 403), (
        f"Expected 401/403 for unauthenticated /ui/ai, got {resp.status_code}"
    )
