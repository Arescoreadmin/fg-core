from __future__ import annotations

from fastapi.testclient import TestClient

from api.auth_scopes import mint_key


def test_scope_enforcement(build_app):
    app = build_app()
    client = TestClient(app)

    tenant_id = "tenant-a"
    key_no_scope = mint_key(ttl_seconds=3600, tenant_id=tenant_id)
    key_with_scope = mint_key("stats:read", ttl_seconds=3600, tenant_id=tenant_id)

    resp = client.get(
        "/stats/summary",
        headers={"X-API-Key": key_no_scope},
        params={"tenant_id": tenant_id},
    )
    assert resp.status_code == 403

    ok_resp = client.get(
        "/stats/summary",
        headers={"X-API-Key": key_with_scope},
        params={"tenant_id": tenant_id},
    )
    assert ok_resp.status_code == 200
