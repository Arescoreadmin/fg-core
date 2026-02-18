from __future__ import annotations

from fastapi.testclient import TestClient

from api.auth_scopes import mint_key


def test_breakglass_required_fields_and_optional_metadata_safe(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("governance:write", tenant_id="tenant-a")

    bad = client.post(
        "/breakglass/sessions",
        headers={"X-API-Key": key, "X-Tenant-Id": "tenant-a"},
        json={"reason": "incident"},
    )
    assert bad.status_code == 422

    good = client.post(
        "/breakglass/sessions",
        headers={"X-API-Key": key, "X-Tenant-Id": "tenant-a"},
        json={"reason": "incident", "expires_at_utc": "2099-01-01T00:00:00Z"},
    )
    assert good.status_code == 200
    body = good.json()
    assert body["scope"] == "global"
    assert body["risk_tier"] == "medium"
    assert body["status"] == "active"


def test_exception_audit_emission_deterministic(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("governance:write", tenant_id="tenant-a")

    created = client.post(
        "/exceptions/requests",
        headers={"X-API-Key": key, "X-Tenant-Id": "tenant-a"},
        json={
            "subject_type": "control",
            "subject_id": "CTRL-001",
            "justification": "needed",
            "expires_at_utc": "2099-01-01T00:00:00Z",
        },
    )
    assert created.status_code == 200
    body = created.json()
    assert body["status"] == "pending"
    assert body["scope"] == "global"
    assert body["risk_tier"] == "medium"
