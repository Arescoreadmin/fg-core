from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from api.auth_scopes import mint_key
from api.db import init_db, reset_engine_cache
from api.main import build_app


def _client(tmp_path: Path, *, degraded: bool, backpressure: bool) -> tuple[TestClient, str]:
    import os

    db_path = tmp_path / "resilience.db"
    os.environ["FG_ENV"] = "test"
    os.environ["FG_SQLITE_PATH"] = str(db_path)
    os.environ["FG_AUTH_ENABLED"] = "1"
    os.environ["FG_API_KEY"] = ""
    os.environ["FG_DEGRADED_MODE"] = "1" if degraded else "0"
    os.environ["FG_BACKPRESSURE_ENABLED"] = "1" if backpressure else "0"
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    key = mint_key("admin:write", "compliance:read", tenant_id="tenant-a")
    return TestClient(build_app(auth_enabled=True)), key


def test_degraded_blocks_write_noncritical(tmp_path: Path) -> None:
    client, key = _client(tmp_path, degraded=True, backpressure=False)
    resp = client.post("/ai/infer", json={"query": "hello"}, headers={"X-API-Key": key})
    assert resp.status_code == 503
    assert resp.json()["detail"]["error_code"] == "SERVICE_DEGRADED_READONLY"


def test_backpressure_sheds_noncritical(tmp_path: Path) -> None:
    client, key = _client(tmp_path, degraded=False, backpressure=True)
    resp = client.post("/ai/infer", json={"query": "hello"}, headers={"X-API-Key": key})
    assert resp.status_code == 503
    assert resp.json()["detail"]["error_code"] == "SERVICE_OVERLOADED_SHED"
