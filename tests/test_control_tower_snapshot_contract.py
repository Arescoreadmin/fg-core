from __future__ import annotations

import json
import pytest

pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient

from api.auth_scopes import mint_key


def test_control_tower_snapshot_contract_and_determinism(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("admin:read", tenant_id="tenant-a")

    response = client.get(
        "/control-tower/snapshot", headers={"X-API-Key": key, "X-Request-ID": "rid-1"}
    )
    assert response.status_code == 200
    assert response.headers.get("x-request-id") == "rid-1"
    payload = response.json()
    assert payload["version"] == "ControlTowerSnapshotV1"
    assert payload["tenant"]["tenant_id"] == "tenant-a"
    for field in (
        "planes",
        "last_replay",
        "chain_integrity",
        "key_lifecycle",
        "connectors",
        "agents",
        "lockers",
        "audit_incidents",
        "links",
    ):
        assert field in payload

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    assert response.text == canonical

    response_2 = client.get(
        "/control-tower/snapshot", headers={"X-API-Key": key, "X-Request-ID": "rid-1"}
    )
    assert response_2.status_code == 200
    assert response_2.text == response.text


def test_control_tower_tenant_clamp_and_override_policy(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("admin:read", tenant_id="tenant-a")

    response = client.get(
        "/control-tower/snapshot?requested_tenant_id=tenant-b",
        headers={"X-API-Key": key},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["tenant"]["tenant_id"] == "tenant-a"
    assert payload["tenant"]["clamp"]["clamped"] is True
    assert payload["tenant"]["clamp"]["requested_tenant_id"] == "tenant-b"
    assert payload["tenant"]["clamp"]["effective_tenant_id"] == "tenant-a"
