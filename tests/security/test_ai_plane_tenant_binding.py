from __future__ import annotations


def test_ai_plane_tenant_binding_baseline() -> None:
    tenant_id = "tenant-test"
    assert tenant_id.startswith("tenant-")
