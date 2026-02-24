import os
from fastapi.testclient import TestClient
from api.main import build_app


def test_planes_requires_tenant_for_unscoped_key():
    os.environ["FG_AUTH_ENABLED"] = "true"
    os.environ["FG_API_KEY"] = "dev-root-key-change-me"

    app = build_app()
    c = TestClient(app)

    r = c.get("/planes", headers={"X-API-Key": "dev-root-key-change-me"})
    assert r.status_code == 400
    assert "tenant_id required" in r.text


def test_planes_accepts_tenant_header_for_unscoped_key():
    os.environ["FG_AUTH_ENABLED"] = "true"
    os.environ["FG_API_KEY"] = "dev-root-key-change-me"

    app = build_app()
    c = TestClient(app)

    r = c.get(
        "/planes",
        headers={
            "X-API-Key": "dev-root-key-change-me",
            "X-Tenant-Id": "tenant-a-test",
        },
    )
    assert r.status_code == 200
    assert "planes" in r.json()
