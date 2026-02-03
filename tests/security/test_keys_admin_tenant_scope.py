from __future__ import annotations

from fastapi.testclient import TestClient

from api.auth_scopes import mint_key


def test_keys_admin_tenant_scope(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)

    tenant_a_admin = mint_key("keys:admin", tenant_id="tenant-a")
    tenant_b_key = mint_key("defend:write", tenant_id="tenant-b")
    mint_key("defend:write", tenant_id="tenant-a")

    list_resp = client.get(
        "/keys",
        headers={"X-API-Key": tenant_a_admin},
    )
    assert list_resp.status_code == 200
    keys = list_resp.json()["keys"]
    assert keys
    assert all(k["tenant_id"] == "tenant-a" for k in keys)

    tenant_b_prefix = tenant_b_key.split(".")[0]
    revoke_resp = client.post(
        "/keys/revoke?tenant_id=tenant-b",
        headers={"X-API-Key": tenant_a_admin},
        json={"prefix": tenant_b_prefix},
    )
    assert revoke_resp.status_code == 403
