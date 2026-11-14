"""MSP-001 route security contract.

Every /admin/msp/* route rejects unauthenticated callers, callers without the
required scope, and callers whose tenant header disagrees with the key-bound
tenant. The public core OpenAPI contract publishes the request bodies but not
the control-plane-only /admin/msp paths. Synthetic tenants only.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from api.auth_scopes import mint_key

_RID = "00000000-0000-0000-0000-000000000000"

ROUTES = [
    ("PUT", "/admin/msp/organizations/tenant-a", {"status": "active"}, "admin:write"),
    ("GET", "/admin/msp/relationships", None, "admin:read"),
    (
        "POST",
        "/admin/msp/relationships",
        {"customer_tenant_id": "tenant-b", "requested_capabilities": ["evidence.read"]},
        "admin:write",
    ),
    (
        "POST",
        f"/admin/msp/relationships/{_RID}/approve",
        {"authorized_capabilities": ["evidence.read"]},
        "admin:write",
    ),
    ("POST", f"/admin/msp/relationships/{_RID}/suspend", None, "admin:write"),
    ("POST", f"/admin/msp/relationships/{_RID}/resume", None, "admin:write"),
    ("POST", f"/admin/msp/relationships/{_RID}/revoke", None, "admin:write"),
    ("GET", "/admin/msp/customers", None, "admin:read"),
    ("POST", "/admin/msp/customers/tenant-b/context", None, "admin:read"),
]


def test_every_msp_route_is_mounted(build_app) -> None:
    app = build_app(auth_enabled=True)
    mounted = {
        (m, getattr(r, "path", ""))
        for r in app.routes
        for m in (getattr(r, "methods", None) or ())
    }
    templates = {
        ("PUT", "/admin/msp/organizations/{tenant_id}"),
        ("GET", "/admin/msp/relationships"),
        ("POST", "/admin/msp/relationships"),
        ("POST", "/admin/msp/relationships/{relationship_id}/approve"),
        ("POST", "/admin/msp/relationships/{relationship_id}/suspend"),
        ("POST", "/admin/msp/relationships/{relationship_id}/resume"),
        ("POST", "/admin/msp/relationships/{relationship_id}/revoke"),
        ("GET", "/admin/msp/customers"),
        ("POST", "/admin/msp/customers/{customer_tenant_id}/context"),
    }
    assert templates <= mounted, sorted(templates - mounted)


def test_msp_routes_require_auth_scope_and_bound_tenant(build_app) -> None:
    client = TestClient(build_app(auth_enabled=True))

    for method, path, body, scope in ROUTES:
        no_auth = client.request(method, path, json=body)
        assert no_auth.status_code in {401, 403}, (method, path)

        wrong = mint_key("stats:read", tenant_id="tenant-a")
        resp = client.request(method, path, json=body, headers={"X-API-Key": wrong})
        assert resp.status_code == 403, (method, path, resp.status_code)

        scoped = mint_key(scope, tenant_id="tenant-a")
        mismatch = client.request(
            method,
            path,
            json=body,
            headers={"X-API-Key": scoped, "X-Tenant-Id": "tenant-b"},
        )
        assert mismatch.status_code in {400, 401, 403, 404, 409}, (
            method,
            path,
            mismatch.status_code,
        )
        assert mismatch.status_code != 200


def test_core_contract_publishes_bodies_but_not_admin_msp_paths() -> None:
    spec = json.loads(Path("contracts/core/openapi.json").read_text(encoding="utf-8"))
    assert not [p for p in spec.get("paths", {}) if p.startswith("/admin/msp")]
    schemas = spec["components"]["schemas"]
    for name in (
        "OrganizationStatusBody",
        "ProposeRelationshipBody",
        "ApproveRelationshipBody",
    ):
        assert schemas[name]["additionalProperties"] is False, name
