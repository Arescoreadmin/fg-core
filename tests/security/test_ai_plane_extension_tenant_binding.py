def test_ai_plane_extension_tenant_binding_placeholder() -> None:
    tenant_id = "tenant_a"
    payload = {"tenant_id": tenant_id, "rules": []}

    assert "tenant_id" in payload
    assert payload["tenant_id"] == tenant_id
    assert payload["tenant_id"] != "tenant_b"
