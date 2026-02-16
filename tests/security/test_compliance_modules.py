from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.main import build_app


def _seed_prod_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    mission_path = tmp_path / "mission_envelope.json"
    mission_path.write_text("[]", encoding="utf-8")
    ring_state = tmp_path / "ring_state"
    ring_model = tmp_path / "ring_models"
    ring_state.mkdir()
    ring_model.mkdir()

    env = {
        "FG_ENV": "prod",
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
    for key, value in env.items():
        monkeypatch.setenv(key, value)


def _assert_startup_fails_before_routes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, disabled_flag: str
) -> None:
    _seed_prod_env(monkeypatch, tmp_path)
    monkeypatch.setenv(disabled_flag, "0")

    called = {"init_db": False}

    def _fake_init_db() -> None:
        called["init_db"] = True

    monkeypatch.setattr("api.main.init_db", _fake_init_db)

    with pytest.raises(RuntimeError):
        with TestClient(build_app()) as client:
            client.get("/health")

    assert called["init_db"] is False


def test_governance_disabled_in_prod_fails_startup(monkeypatch, tmp_path):
    _assert_startup_fails_before_routes(monkeypatch, tmp_path, "FG_GOVERNANCE_ENABLED")


def test_roe_engine_disabled_in_prod_fails_startup(monkeypatch, tmp_path):
    _assert_startup_fails_before_routes(monkeypatch, tmp_path, "FG_ROE_ENGINE_ENABLED")


def test_ring_router_disabled_in_prod_fails_startup(monkeypatch, tmp_path):
    _assert_startup_fails_before_routes(monkeypatch, tmp_path, "FG_RING_ROUTER_ENABLED")


def test_mission_envelope_disabled_in_prod_fails_startup(monkeypatch, tmp_path):
    _assert_startup_fails_before_routes(
        monkeypatch, tmp_path, "FG_MISSION_ENVELOPE_ENABLED"
    )


def test_ui_disabled_by_default_in_prod_returns_404(monkeypatch, tmp_path):
    _seed_prod_env(monkeypatch, tmp_path)
    monkeypatch.delenv("FG_UI_ENABLED", raising=False)

    monkeypatch.setattr("api.main.init_db", lambda: None)

    with TestClient(build_app()) as client:
        resp = client.get("/ui")
        assert resp.status_code == 404
