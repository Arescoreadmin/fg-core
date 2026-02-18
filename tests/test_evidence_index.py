from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from api.auth_scopes import mint_key
from api.db import init_db, reset_engine_cache
from api.main import build_app


def _setup(tmp_path: Path) -> tuple[TestClient, str, str]:
    import os

    db_path = tmp_path / "evidence-index.db"
    os.environ["FG_ENV"] = "test"
    os.environ["FG_SQLITE_PATH"] = str(db_path)
    os.environ["FG_AUTH_ENABLED"] = "1"
    os.environ["FG_API_KEY"] = ""
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    key_a = mint_key("admin:write", "compliance:read", tenant_id="tenant-a")
    key_b = mint_key("admin:write", "compliance:read", tenant_id="tenant-b")
    return TestClient(build_app(auth_enabled=True)), key_a, key_b


def test_evidence_index_register_and_tenant_isolation(tmp_path: Path) -> None:
    client, key_a, key_b = _setup(tmp_path)
    p = tmp_path / "artifact.json"
    p.write_text('{"ok":true}', encoding="utf-8")
    created = client.post(
        "/evidence/runs/register",
        json={
            "plane_id": "ai_plane",
            "artifact_type": "ai_plane_evidence",
            "artifact_path": str(p),
            "schema_version": "v1",
            "git_sha": "abc",
            "status": "PASS",
            "summary_json": {"ok": True},
        },
        headers={"X-API-Key": key_a},
    )
    assert created.status_code == 200
    list_a = client.get("/evidence/runs", headers={"X-API-Key": key_a})
    list_b = client.get("/evidence/runs", headers={"X-API-Key": key_b})
    assert list_a.status_code == 200
    assert list_b.status_code == 200
    assert len(list_a.json()["runs"]) >= 1
    assert list_b.json()["runs"] == []
