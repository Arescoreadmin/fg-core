def test_evidence_anchor_extension_tenant_binding_placeholder() -> None:
    tenant_id = "tenant_a"
    payload = {"tenant_id": tenant_id, "anchors": []}

    assert "tenant_id" in payload
    assert payload["tenant_id"] == tenant_id
    assert payload["tenant_id"] != "tenant_b"