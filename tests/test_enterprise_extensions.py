from __future__ import annotations

import base64
import json
from pathlib import Path

from fastapi.testclient import TestClient

from api.auth_scopes import mint_key
from api.db import init_db, reset_engine_cache
from api.main import build_app


def _setup_client(tmp_path: Path) -> tuple[TestClient, str, str]:
    db_path = tmp_path / "enterprise-ext.db"
    import os

    os.environ["FG_ENV"] = "test"
    os.environ["FG_SQLITE_PATH"] = str(db_path)
    os.environ["FG_AUTH_ENABLED"] = "1"
    os.environ["FG_API_KEY"] = ""
    os.environ["FG_COMPLIANCE_HMAC_KEY_CURRENT"] = "0123456789abcdef0123456789abcdef"
    os.environ["FG_COMPLIANCE_HMAC_KEY_ID_CURRENT"] = "v1"
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    key_a = mint_key(
        "admin:write", "compliance:read", "governance:write", tenant_id="tenant-a"
    )
    key_b = mint_key(
        "admin:write", "compliance:read", "governance:write", tenant_id="tenant-b"
    )
    client = TestClient(build_app(auth_enabled=True))
    return client, key_a, key_b


def test_compliance_cp_authz_401(tmp_path: Path) -> None:
    client, _, _ = _setup_client(tmp_path)
    resp = client.get("/compliance-cp/summary")
    assert resp.status_code == 401


def test_compliance_cp_happy_and_tenant_isolation(tmp_path: Path) -> None:
    client, key_a, key_b = _setup_client(tmp_path)
    r1 = client.get("/compliance-cp/summary", headers={"X-API-Key": key_a})
    assert r1.status_code == 200
    r2 = client.get("/compliance-cp/summary", headers={"X-API-Key": key_b})
    assert r2.status_code == 200
    assert r2.json()["tenant_id"] == "tenant-b"


def test_enterprise_controls_happy_and_forbidden_tenant_mismatch(
    tmp_path: Path,
) -> None:
    client, key_a, _ = _setup_client(tmp_path)
    ok = client.get("/enterprise-controls/frameworks", headers={"X-API-Key": key_a})
    assert ok.status_code == 200
    forbidden = client.get(
        "/enterprise-controls/frameworks?tenant_id=tenant-z",
        headers={"X-API-Key": key_a},
    )
    assert forbidden.status_code == 403


def test_breakglass_happy(tmp_path: Path) -> None:
    client, key_a, _ = _setup_client(tmp_path)
    resp = client.post(
        "/breakglass/sessions",
        json={"reason": "incident", "expires_at_utc": "2026-01-02T00:00:00Z"},
        headers={"X-API-Key": key_a},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "active"


def test_governance_risk_hook_sod_violation_when_enabled(monkeypatch) -> None:
    from services.governance_risk_extension import GovernanceRiskExtension

    monkeypatch.setenv("FG_GOVERNANCE_RISK_EXTENSION_ENABLED", "1")
    ext = GovernanceRiskExtension()
    result = ext.evaluate(
        proposed_by="alice",
        approver="alice",
        required_roles=["security-lead", "ciso"],
    )
    assert result["enabled"] is True
    assert result["sod_ok"] is False
    assert result["quorum_required"] == 2


def test_evidence_anchor_happy_tenant_isolation_and_error_code(tmp_path: Path) -> None:
    client, key_a, key_b = _setup_client(tmp_path)
    artifact = tmp_path / "artifact.json"
    artifact.write_text('{"ok":true}', encoding="utf-8")
    created = client.post(
        "/evidence/anchors",
        json={"artifact_path": str(artifact), "immutable_retention": True},
        headers={"X-API-Key": key_a},
    )
    assert created.status_code == 200
    list_b = client.get("/evidence/anchors", headers={"X-API-Key": key_b})
    assert list_b.status_code == 200
    assert list_b.json()["anchors"] == []
    missing = client.post(
        "/evidence/anchors",
        json={
            "artifact_path": str(tmp_path / "missing.json"),
            "immutable_retention": True,
        },
        headers={"X-API-Key": key_a},
    )
    assert missing.status_code == 404
    body = missing.json()
    assert body["detail"]["error_code"] == "evidence_anchor_artifact_not_found"


def test_federation_error_and_happy(tmp_path: Path) -> None:
    client, key_a, _ = _setup_client(tmp_path)
    no_bearer = client.post("/auth/federation/validate", headers={"X-API-Key": key_a})
    assert no_bearer.status_code == 401

    payload = {
        "iss": "https://issuer.example",
        "sub": "user-1",
        "tenant_id": "tenant-a",
        "groups": ["ops"],
    }
    p = (
        base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8"))
        .decode("utf-8")
        .rstrip("=")
    )
    token = f"x.{p}.y"
    resp = client.post(
        "/auth/federation/validate",
        headers={"X-API-Key": key_a, "Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["tenant_id"] == "tenant-a"
