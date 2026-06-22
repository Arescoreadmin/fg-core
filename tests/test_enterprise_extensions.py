from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from unittest.mock import Mock

import uuid

from api.auth_scopes import mint_key
from api.db import get_sessionmaker, init_db, reset_engine_cache
from api.db_models import (
    Capability,
    PolicyBundle,
    PolicyBundleCapability,
    TenantBundleAssignment,
)
from api.main import build_app
from services.capability_bundles.resolver import invalidate_cache
from services.enterprise_controls_extension.service import EnterpriseControlsService


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

    # Grant identity.sso to both tenants so enterprise routes (e.g. federation)
    # pass capability enforcement introduced in P1.3D.
    db = get_sessionmaker(sqlite_path=str(db_path))()
    cap = Capability(
        id=str(uuid.uuid4()),
        capability_key="identity.sso",
        capability_name="identity.sso",
        capability_category="identity",
        active=True,
    )
    db.add(cap)
    db.flush()
    bundle = PolicyBundle(
        id=str(uuid.uuid4()),
        bundle_key="ent_ext_bundle",
        bundle_name="ent_ext_bundle",
        active=True,
    )
    db.add(bundle)
    db.flush()
    db.add(PolicyBundleCapability(bundle_id=bundle.id, capability_id=cap.id))
    for tid in ["tenant-a", "tenant-b"]:
        db.add(
            TenantBundleAssignment(
                id=str(uuid.uuid4()), tenant_id=tid, bundle_id=bundle.id
            )
        )
    db.commit()
    db.close()
    invalidate_cache("tenant-a")
    invalidate_cache("tenant-b")

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


def test_federation_error_and_happy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import time

    import jwt as _jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jwt.algorithms import RSAAlgorithm

    client, key_a, _ = _setup_client(tmp_path)

    # No bearer → 401 before any token inspection
    no_bearer = client.post("/auth/federation/validate", headers={"X-API-Key": key_a})
    assert no_bearer.status_code == 401

    # Build an RS256 key pair and matching JWKS
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    jwk_dict = json.loads(RSAAlgorithm.to_jwk(public_key))
    jwk_dict["kid"] = "test-key-1"
    jwk_dict["use"] = "sig"
    jwks = {"keys": [jwk_dict]}

    # Configure required env vars (cleaned up by monkeypatch after the test)
    monkeypatch.setenv(
        "FG_FEDERATION_JWKS_URL", "https://idp.example.com/.well-known/jwks.json"
    )
    monkeypatch.setenv("FG_FEDERATION_ISSUER", "https://idp.example.com/")
    monkeypatch.setenv("FG_FEDERATION_AUDIENCE", "https://api.frostgate.ai")

    # Pre-seed the module-level service's JWKS cache to avoid network calls
    import api.auth_federation as _fed_mod

    monkeypatch.setattr(_fed_mod.service.cache, "_doc", jwks)
    monkeypatch.setattr(_fed_mod.service.cache, "_exp", time.time() + 3600)

    now = int(time.time())
    token = _jwt.encode(
        {
            "sub": "user-1",
            "iss": "https://idp.example.com/",
            "aud": "https://api.frostgate.ai",
            "tenant_id": "tenant-a",
            "groups": ["ops"],
            "exp": now + 300,
            "iat": now,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key-1"},
    )
    resp = client.post(
        "/auth/federation/validate",
        headers={"X-API-Key": key_a, "Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["tenant_id"] == "tenant-a"


def test_enterprise_seed_rejects_non_list_sections() -> None:
    class _BadListSeedService(EnterpriseControlsService):
        def _seed_payload(self) -> dict[str, object]:
            return {"frameworks": "bad", "controls": [], "crosswalk": []}

    service = _BadListSeedService()
    db = Mock(spec=Session)
    with pytest.raises(ValueError, match="ENTERPRISE_SEED_FRAMEWORKS_MUST_BE_LIST"):
        service.seed_minimal(db)


def test_enterprise_seed_rejects_non_object_items() -> None:
    class _BadItemSeedService(EnterpriseControlsService):
        def _seed_payload(self) -> dict[str, object]:
            return {"frameworks": ["bad-item"], "controls": [], "crosswalk": []}

    service = _BadItemSeedService()
    db = Mock(spec=Session)
    with pytest.raises(
        ValueError, match="ENTERPRISE_SEED_FRAMEWORKS_ITEM_MUST_BE_OBJECT"
    ):
        service.seed_minimal(db)
