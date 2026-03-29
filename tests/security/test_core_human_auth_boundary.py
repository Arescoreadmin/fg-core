from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key
from api.main import build_app


def _seed_hosted_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, env: str) -> None:
    mission_path = tmp_path / f"mission_envelope_{env}.json"
    mission_path.write_text("[]", encoding="utf-8")
    ring_state = tmp_path / f"ring_state_{env}"
    ring_model = tmp_path / f"ring_model_{env}"
    ring_state.mkdir()
    ring_model.mkdir()

    seeded = {
        "FG_ENV": env,
        "FG_ENFORCEMENT_MODE": "enforce",
        "FG_API_KEY": "a" * 32,
        "FG_AUTH_ENABLED": "1",
        "FG_DB_BACKEND": "postgres",
        "FG_DB_URL": "postgresql://user:pass@localhost:5432/frostgate",
        "FG_TENANT_CONTEXT_MODE": "db_session",
        "FG_CORS_ORIGINS": "https://example.com",
        "FG_AUDIT_PERSIST_DB": "1",
        "FG_ENCRYPTION_KEY": "b" * 32,
        "FG_JWT_SECRET": "c" * 32,
        "FG_WEBHOOK_SECRET": "d" * 32,
        "FG_QUOTA_ENFORCEMENT_ENABLED": "1",
        "FG_DOS_GUARD_ENABLED": "1",
        "FG_RL_ENABLED": "1",
        "FG_REQUEST_TIMEOUT_SEC": "15",
        "FG_MAX_BODY_BYTES": "1048576",
        "FG_MAX_QUERY_BYTES": "8192",
        "FG_MAX_PATH_BYTES": "2048",
        "FG_MAX_HEADERS_COUNT": "100",
        "FG_MAX_HEADERS_BYTES": "16384",
        "FG_MAX_HEADER_LINE_BYTES": "8192",
        "FG_MULTIPART_MAX_BYTES": "5242880",
        "FG_MULTIPART_MAX_PARTS": "50",
        "FG_MAX_CONCURRENT_REQUESTS": "100",
        "FG_KEEPALIVE_TIMEOUT_SEC": "5",
        "FG_GOVERNANCE_ENABLED": "1",
        "FG_ROE_ENGINE_ENABLED": "1",
        "FG_RING_ROUTER_ENABLED": "1",
        "FG_MISSION_ENVELOPE_ENABLED": "1",
        "FG_MISSION_ENVELOPE_PATH": str(mission_path),
        "FG_RING_STATE_DIR": str(ring_state),
        "FG_RING_MODEL_DIR": str(ring_model),
    }
    for key, value in seeded.items():
        monkeypatch.setenv(key, value)


def _build_hosted_core(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, env: str
) -> TestClient:
    _seed_hosted_env(monkeypatch, tmp_path, env)
    monkeypatch.setattr("api.main.init_db", lambda: None)
    return TestClient(build_app(auth_enabled=True))


def test_hosted_profiles_do_not_mount_ui_routes(monkeypatch, tmp_path: Path) -> None:
    for env in ("staging", "prod"):
        with _build_hosted_core(monkeypatch, tmp_path, env) as client:
            for path in (
                "/ui",
                "/ui/token",
                "/ui/csrf",
                "/ui/ai",
                "/ui/ai/experience",
                "/ui/dash/testing-control-tower",
            ):
                resp = client.get(path)
                assert resp.status_code == 404, (env, path, resp.status_code, resp.text)


def test_hosted_runtime_route_inventory_has_no_ui_surface(
    monkeypatch, tmp_path: Path
) -> None:
    with _build_hosted_core(monkeypatch, tmp_path, "staging") as client:
        route_paths = sorted(
            {
                getattr(route, "path", "")
                for route in client.app.router.routes
                if getattr(route, "path", "")
            }
        )
    assert not [path for path in route_paths if path.startswith("/ui")]


def test_hosted_profiles_reject_cookie_only_auth(monkeypatch, tmp_path: Path) -> None:
    for env in ("staging", "prod"):
        with _build_hosted_core(monkeypatch, tmp_path, env) as client:
            key = mint_key("stats:read", tenant_id="tenant-a")
            cookie_name = "fg_api_key"
            client.cookies.set(cookie_name, key)
            resp = client.get("/stats")
            assert resp.status_code == 401, (env, resp.status_code, resp.text)
