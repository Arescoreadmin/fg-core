from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from api.auth_scopes import mint_key
from api.db import get_sessionmaker
from services.evidence_index.storage import list_runs


def test_evidence_runs_tenant_isolation(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)

    admin_a = mint_key("admin:write", tenant_id="tenant-a")
    read_a = mint_key("compliance:read", tenant_id="tenant-a")
    read_b = mint_key("compliance:read", tenant_id="tenant-b")

    reg = client.post(
        "/evidence/runs/register",
        headers={"X-API-Key": admin_a, "X-Tenant-Id": "tenant-a"},
        json={
            "plane_id": "ai_plane",
            "artifact_type": "ai_plane_evidence",
            "artifact_path": "artifacts/ai_plane_evidence.json",
            "schema_version": "v1",
            "git_sha": "abc123",
            "status": "PASS",
            "summary_json": {},
        },
    )
    assert reg.status_code == 200
    run_id = reg.json()["id"]

    own = client.get(
        "/evidence/runs", headers={"X-API-Key": read_a, "X-Tenant-Id": "tenant-a"}
    )
    assert own.status_code == 200
    assert any(r["id"] == run_id for r in own.json()["runs"])

    other = client.get(
        "/evidence/runs", headers={"X-API-Key": read_b, "X-Tenant-Id": "tenant-b"}
    )
    assert other.status_code == 200
    assert all(r["id"] != run_id for r in other.json()["runs"])

    SessionLocal = get_sessionmaker()
    with SessionLocal() as db:
        with pytest.raises(ValueError, match="EVIDENCE_TENANT_REQUIRED"):
            list_runs(db, "")
