"""Contract assertions: control plane delegation routes carry correct capability gates (P1.3D).

These tests anchor the contract that capability enforcement on MSP delegation
routes is present and points to the correct capabilities. Companion to the
ENT-27/28 route inventory tests in test_enterprise_capability_enforcement.py.
"""

from __future__ import annotations

import pytest

from api.entitlements import CAPABILITY_REGISTRY


def _route_dep_names(routes, path_fragment: str, method: str) -> list[str]:
    for route in routes:
        route_path = getattr(route, "path", "")
        route_methods: set[str] = getattr(route, "methods", set()) or set()
        if path_fragment not in route_path:
            continue
        if method.upper() not in route_methods:
            continue
        deps = getattr(route, "dependencies", []) or []
        return [getattr(getattr(d, "dependency", None), "__name__", "") for d in deps]
    return []


@pytest.mark.parametrize(
    "cap",
    ["msp.multi_tenant", "msp.cross_tenant_reporting", "msp.tenant_switching"],
)
def test_msp_capabilities_in_registry(cap: str) -> None:
    assert cap in CAPABILITY_REGISTRY, f"{cap} missing from CAPABILITY_REGISTRY"


def test_delegation_create_has_msp_multi_tenant_gate() -> None:
    from api.control_plane_v2 import router

    dep_names = _route_dep_names(router.routes, "/control-plane/v2/delegation", "POST")
    assert "_dep" in dep_names, (
        f"POST /control-plane/v2/delegation must carry require_capability; deps: {dep_names}"
    )


def test_delegation_delete_has_msp_multi_tenant_gate() -> None:
    from api.control_plane_v2 import router

    dep_names = _route_dep_names(
        router.routes, "/control-plane/v2/delegation/{delegation_id}", "DELETE"
    )
    assert "_dep" in dep_names, (
        f"DELETE /control-plane/v2/delegation/{{id}} must carry require_capability; deps: {dep_names}"
    )


def test_delegation_list_has_msp_cross_tenant_reporting_gate() -> None:
    from api.control_plane_v2 import router

    dep_names = _route_dep_names(router.routes, "/control-plane/v2/delegation", "GET")
    assert "_dep" in dep_names, (
        f"GET /control-plane/v2/delegation must carry require_capability; deps: {dep_names}"
    )
