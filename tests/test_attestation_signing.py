from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from api.db import get_engine, get_sessionmaker
from api.db_models import ApprovalLog
from api.main import build_app
from api.signed_artifacts import canonical_hash

TEST_PRIVATE_KEY = bytes(range(1, 33))


def _set_signing_env(monkeypatch: pytest.MonkeyPatch) -> None:
    priv = Ed25519PrivateKey.from_private_bytes(TEST_PRIVATE_KEY)
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    monkeypatch.setenv(
        "FG_EVIDENCE_SIGNING_KEY_B64", base64.b64encode(TEST_PRIVATE_KEY).decode()
    )
    monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_ID", "test-key-1")
    monkeypatch.setenv(
        "FG_EVIDENCE_PUBLIC_KEYS_B64",
        '{"test-key-1":"' + base64.b64encode(pub).decode() + '"}',
    )


@pytest.fixture
def client(tmp_path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    db_path = tmp_path / "attestation.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_API_KEY", "test-api-key")
    monkeypatch.setenv("FG_AUTH_ENABLED", "0")
    _set_signing_env(monkeypatch)
    app = build_app(auth_enabled=False)
    return TestClient(app)


def test_bundle_sign_and_verify_ok(client: TestClient):
    payload = {
        "tenant_id": "t1",
        "subject_type": "decision",
        "subject_id": "d-1",
        "payload": {"risk": "high"},
    }
    create_resp = client.post("/evidence/bundles", json=payload)
    assert create_resp.status_code == 200
    body = create_resp.json()

    bundle_resp = client.get(f"/evidence/bundles/{body['bundle_id']}")
    verify_resp = client.post(
        "/evidence/verify",
        json={
            "bundle": bundle_resp.json()["bundle"],
            "bundle_hash": body["bundle_hash"],
            "signature": body["signature"],
            "key_id": body["key_id"],
        },
    )
    assert verify_resp.status_code == 200
    assert verify_resp.json()["verified"] is True


def test_bundle_verify_fails_if_payload_tampered(client: TestClient):
    create_resp = client.post(
        "/evidence/bundles",
        json={
            "tenant_id": "t1",
            "subject_type": "decision",
            "subject_id": "d-2",
            "payload": {"risk": "low"},
        },
    )
    body = create_resp.json()
    bundle_resp = client.get(f"/evidence/bundles/{body['bundle_id']}").json()
    bundle_resp["bundle"]["payload"]["risk"] = "critical"

    verify_resp = client.post(
        "/evidence/verify",
        json={
            "bundle": bundle_resp["bundle"],
            "bundle_hash": body["bundle_hash"],
            "signature": body["signature"],
            "key_id": body["key_id"],
        },
    )
    assert verify_resp.json()["verified"] is False
    assert verify_resp.json()["reason"] == "bundle_hash_mismatch"


def test_bundle_verify_fails_if_signature_tampered(client: TestClient):
    create_resp = client.post(
        "/evidence/bundles",
        json={
            "tenant_id": "t1",
            "subject_type": "decision",
            "subject_id": "d-3",
            "payload": {"risk": "medium"},
        },
    )
    body = create_resp.json()
    bundle_resp = client.get(f"/evidence/bundles/{body['bundle_id']}").json()
    sig = body["signature"]
    tampered_sig = ("A" if sig[0] != "A" else "B") + sig[1:]
    verify_resp = client.post(
        "/evidence/verify",
        json={
            "bundle": bundle_resp["bundle"],
            "bundle_hash": body["bundle_hash"],
            "signature": tampered_sig,
            "key_id": body["key_id"],
        },
    )
    assert verify_resp.json()["verified"] is False


def test_bundle_verify_fails_if_key_id_tampered(client: TestClient):
    create_resp = client.post(
        "/evidence/bundles",
        json={
            "tenant_id": "t1",
            "subject_type": "decision",
            "subject_id": "d-4",
            "payload": {"risk": "medium"},
        },
    )
    body = create_resp.json()
    bundle_resp = client.get(f"/evidence/bundles/{body['bundle_id']}").json()

    verify_resp = client.post(
        "/evidence/verify",
        json={
            "bundle": bundle_resp["bundle"],
            "bundle_hash": body["bundle_hash"],
            "signature": body["signature"],
            "key_id": "tampered-key-id",
        },
    )
    assert verify_resp.json()["verified"] is False


def test_approval_verify_detects_tenant_id_tamper(client: TestClient):
    client.post(
        "/approvals",
        json={
            "tenant_id": "t1",
            "subject_type": "change",
            "subject_id": "sub-tenant",
            "action": "approve",
            "approver": "eve",
            "reason": "ok",
        },
    )

    with get_engine().begin() as conn:
        conn.execute(
            text(
                "UPDATE approval_logs SET entry_json = :entry WHERE subject_id = :subject_id AND seq = 1"
            ),
            {
                "entry": '{"tenant_id":"tampered","subject_type":"change","subject_id":"sub-tenant","seq":1,"action":"approve","approver":"eve","reason":"ok","bundle_id":null}',
                "subject_id": "sub-tenant",
            },
        )

    verify_resp = client.post(
        "/approvals/verify",
        json={"tenant_id": "t1", "subject_type": "change", "subject_id": "sub-tenant"},
    )
    assert verify_resp.json()["verified"] is False
    assert verify_resp.json()["reason"] == "entry_hash_mismatch"


def test_module_enforcement_detects_tenant_id_tamper(client: TestClient):
    client.post(
        "/modules/register",
        json={
            "tenant_id": "t1",
            "module_id": "mod.tenant",
            "version": "1.0.1",
            "capabilities": ["read"],
            "required_scopes": ["modules:use"],
            "git_sha": "abc1234",
            "build_id": "build-tenant",
        },
    )

    with get_engine().begin() as conn:
        conn.execute(
            text(
                "UPDATE module_registry SET record_json = json_set(record_json, '$.tenant_id', 'tampered') WHERE module_id = :module_id AND version = :version"
            ),
            {"module_id": "mod.tenant", "version": "1.0.1"},
        )

    resp = client.get(
        "/modules/enforce/mod.tenant",
        params={"version": "1.0.1"},
        headers={"X-Tenant-Id": "t1"},
    )
    assert resp.status_code == 403


def test_bundle_deterministic_hash_same_payload_same_hash():
    payload = {"a": 1, "b": [2, 3], "c": {"x": "y"}}
    assert canonical_hash(payload) == canonical_hash(payload)


def test_approval_chain_verifies(client: TestClient):
    for idx in range(1, 4):
        resp = client.post(
            "/approvals",
            json={
                "tenant_id": "t1",
                "subject_type": "change",
                "subject_id": "sub-1",
                "action": "approve",
                "approver": "alice",
                "reason": f"r{idx}",
            },
        )
        assert resp.status_code == 200

    verify_resp = client.post(
        "/approvals/verify",
        json={"tenant_id": "t1", "subject_type": "change", "subject_id": "sub-1"},
    )
    assert verify_resp.json()["verified"] is True


def test_chain_break_detected_on_middle_entry_edit(client: TestClient):
    for _ in range(3):
        client.post(
            "/approvals",
            json={
                "tenant_id": "t1",
                "subject_type": "change",
                "subject_id": "sub-2",
                "action": "approve",
                "approver": "bob",
                "reason": "ok",
            },
        )

    with get_engine().begin() as conn:
        conn.execute(
            text(
                "UPDATE approval_logs SET entry_json = :entry WHERE subject_id = :subject_id AND seq = 2"
            ),
            {
                "entry": '{"tenant_id":"t1","subject_type":"change","subject_id":"sub-2","seq":2,"action":"approve","approver":"bob","reason":"tampered","bundle_id":null}',
                "subject_id": "sub-2",
            },
        )

    verify_resp = client.post(
        "/approvals/verify",
        json={"tenant_id": "t1", "subject_type": "change", "subject_id": "sub-2"},
    )
    assert verify_resp.json()["verified"] is False


def test_reordering_detected(client: TestClient):
    for _ in range(2):
        client.post(
            "/approvals",
            json={
                "tenant_id": "t1",
                "subject_type": "change",
                "subject_id": "sub-3",
                "action": "approve",
                "approver": "carol",
                "reason": "ok",
            },
        )
    with get_engine().begin() as conn:
        conn.execute(
            text(
                "UPDATE approval_logs SET seq = 5 WHERE subject_id = :subject_id AND seq = 2"
            ),
            {"subject_id": "sub-3"},
        )

    verify_resp = client.post(
        "/approvals/verify",
        json={"tenant_id": "t1", "subject_type": "change", "subject_id": "sub-3"},
    )
    assert verify_resp.json()["verified"] is False
    assert verify_resp.json()["reason"] == "seq_not_monotonic"


def test_seq_monotonic_enforced(client: TestClient):
    client.post(
        "/approvals",
        json={
            "tenant_id": "t1",
            "subject_type": "change",
            "subject_id": "sub-4",
            "action": "approve",
            "approver": "dana",
            "reason": "ok",
        },
    )

    session = get_sessionmaker()()
    with pytest.raises(IntegrityError):
        try:
            session.add(
                ApprovalLog(
                    tenant_id="t1",
                    subject_type="change",
                    subject_id="sub-4",
                    seq=1,
                    entry_json={"x": 1},
                    entry_hash="0" * 64,
                    prev_chain_hash="0" * 64,
                    chain_hash="1" * 64,
                    signature="sig",
                    key_id="k",
                )
            )
            session.commit()
        finally:
            session.rollback()
            session.close()


def test_module_registration_signature_verifies(client: TestClient):
    resp = client.post(
        "/modules/register",
        json={
            "tenant_id": "t1",
            "module_id": "mod.alpha",
            "version": "1.2.3",
            "capabilities": ["read"],
            "required_scopes": ["modules:use"],
            "git_sha": "abc1234",
            "build_id": "build-1",
        },
    )
    assert resp.status_code == 200
    enforce = client.get(
        "/modules/enforce/mod.alpha",
        params={"version": "1.2.3"},
        headers={"X-Tenant-Id": "t1"},
    )
    assert enforce.status_code == 200
    assert enforce.json()["allowed"] is True


def test_module_registration_rejects_missing_required_fields(client: TestClient):
    resp = client.post(
        "/modules/register",
        json={
            "tenant_id": "t1",
            "module_id": "mod.bad",
            "capabilities": ["read"],
            "required_scopes": [],
            "git_sha": "abc1234",
            "build_id": "build-2",
        },
    )
    assert resp.status_code == 422


def test_module_usage_denied_if_unregistered(client: TestClient):
    resp = client.get(
        "/modules/enforce/mod.unknown",
        params={"version": "0.1.0"},
        headers={"X-Tenant-Id": "t1"},
    )
    assert resp.status_code == 403


def test_module_usage_denied_if_signature_invalid(client: TestClient):
    client.post(
        "/modules/register",
        json={
            "tenant_id": "t1",
            "module_id": "mod.sig",
            "version": "1.0.0",
            "capabilities": ["read"],
            "required_scopes": ["modules:use"],
            "git_sha": "abc1234",
            "build_id": "build-3",
        },
    )

    with get_engine().begin() as conn:
        conn.execute(
            text(
                "UPDATE module_registry SET signature = :signature WHERE module_id = :module_id AND version = :version"
            ),
            {"signature": "tampered", "module_id": "mod.sig", "version": "1.0.0"},
        )

    resp = client.get(
        "/modules/enforce/mod.sig",
        params={"version": "1.0.0"},
        headers={"X-Tenant-Id": "t1"},
    )
    assert resp.status_code == 403
