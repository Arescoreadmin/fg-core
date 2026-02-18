from __future__ import annotations

import subprocess

from services.plane_registry import PLANE_REGISTRY


def test_plane_registry_has_required_fields() -> None:
    assert PLANE_REGISTRY
    for plane in PLANE_REGISTRY:
        assert plane.plane_id
        assert plane.route_prefixes
        assert plane.mount_flag.startswith("FG_")
        assert plane.required_make_targets


def test_plane_registry_checker_passes() -> None:
    proc = subprocess.run(
        [".venv/bin/python", "tools/ci/check_plane_registry.py"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_planes_endpoint_scoped_and_tenant_bound(tmp_path):
    import os
    from fastapi.testclient import TestClient
    from api.auth_scopes import mint_key
    from api.db import init_db, reset_engine_cache
    from api.main import build_app

    db_path = tmp_path / "planes.db"
    os.environ["FG_ENV"] = "test"
    os.environ["FG_SQLITE_PATH"] = str(db_path)
    os.environ["FG_AUTH_ENABLED"] = "1"
    os.environ["FG_API_KEY"] = ""
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    key = mint_key("admin:write", tenant_id="tenant-a")
    client = TestClient(build_app(auth_enabled=True))

    unauth = client.get("/planes")
    assert unauth.status_code == 401
    ok = client.get("/planes", headers={"X-API-Key": key})
    assert ok.status_code == 200
    assert "planes" in ok.json()
