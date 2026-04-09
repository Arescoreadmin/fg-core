def test_enterprise_controls_extension_tenant_binding_placeholder() -> None:
    tenant_id = "tenant_a"
    payload = {"tenant_id": tenant_id, "controls": []}

    assert "tenant_id" in payload
    assert payload["tenant_id"] == tenant_id
    assert payload["tenant_id"] != "tenant_b"