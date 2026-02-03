from __future__ import annotations

from fastapi.testclient import TestClient

from api.auth_scopes import mint_key


def test_admin_tenant_scope_enforced(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)

    tenant_a_admin = mint_key("admin:write", tenant_id="tenant-a")

    resp = client.put(
        "/admin/tenants/tenant-b/quota",
        headers={"X-API-Key": tenant_a_admin},
        json={"quota": 100},
    )
    assert resp.status_code == 403
