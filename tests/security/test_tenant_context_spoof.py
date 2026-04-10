"""
Regression tests: tenant context integrity enforcement on protected paths.

Invariants proved:
- Forged tenant_id in header/body is rejected on scoped paths
- Auth-derived tenant binding overrides or rejects conflicting request-supplied values
- Unscoped keys with forged tenant assertions fail closed (400/403)
- No cross-tenant data side effect from spoof attempts
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key
from api.db import get_engine, reset_engine_cache
from api.db_models import ApprovalLog
from sqlalchemy.orm import Session


def _suffix() -> str:
    return uuid.uuid4().hex[:8]


@pytest.fixture
def spoof_client(tmp_path, monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from api.main import build_app

    db_path = tmp_path / "spoof-test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_AUTH_ENABLED", "1")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")

    priv = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    monkeypatch.setenv(
        "FG_EVIDENCE_SIGNING_KEY_B64", base64.b64encode(bytes(range(1, 33))).decode()
    )
    monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_ID", "spoof-key-1")
    monkeypatch.setenv(
        "FG_EVIDENCE_PUBLIC_KEYS_B64",
        '{"spoof-key-1":"' + base64.b64encode(pub).decode() + '"}',
    )

    reset_engine_cache()
    app = build_app(auth_enabled=True)
    return app


def _seed_approval(session: Session, *, tenant_id: str, subject_id: str) -> None:
    from api.signed_artifacts import GENESIS_CHAIN_HASH, canonical_hash, chain_hash

    entry = {
        "tenant_id": tenant_id,
        "subject_type": "change",
        "subject_id": subject_id,
        "seq": 1,
        "action": "approve",
        "approver": "system",
        "reason": "seeded",
        "bundle_id": None,
    }
    entry_hash = canonical_hash(entry)
    c_hash = chain_hash(GENESIS_CHAIN_HASH, entry_hash)
    session.add(
        ApprovalLog(
            tenant_id=tenant_id,
            subject_type="change",
            subject_id=subject_id,
            seq=1,
            entry_json=entry,
            entry_hash=entry_hash,
            prev_chain_hash=GENESIS_CHAIN_HASH,
            chain_hash=c_hash,
            signature="test-sig",
            key_id="spoof-key-1",
        )
    )


# ---------------------------------------------------------------------------
# A) Header spoof: forged X-Tenant-Id header on scoped path
# ---------------------------------------------------------------------------


def test_header_spoof_tenant_rejected_on_list_approvals(spoof_client, monkeypatch):
    """Scoped key bound to tenant-a; forged X-Tenant-Id: tenant-b must be rejected."""
    s = _suffix()
    tenant_a = f"spoof-hdr-a-{s}"
    tenant_b = f"spoof-hdr-b-{s}"
    key_a = mint_key("attestation:admin", tenant_id=tenant_a)
    client = TestClient(spoof_client)

    resp = client.get(
        f"/approvals/change/sub-{s}",
        headers={"X-API-Key": key_a, "X-Tenant-Id": tenant_b},
    )
    assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text}"


def test_header_spoof_tenant_auth_binding_wins_on_list_approvals(spoof_client):
    """Auth-derived tenant wins; matching header is accepted; foreign data not leaked."""
    s = _suffix()
    tenant_a = f"spoof-win-a-{s}"
    tenant_b = f"spoof-win-b-{s}"
    subject_id = f"sub-{s}"
    key_a = mint_key("attestation:admin", tenant_id=tenant_a)

    engine = get_engine()
    with Session(engine) as session:
        _seed_approval(session, tenant_id=tenant_a, subject_id=subject_id)
        _seed_approval(session, tenant_id=tenant_b, subject_id=subject_id)
        session.commit()

    client = TestClient(spoof_client)
    resp = client.get(
        f"/approvals/change/{subject_id}",
        headers={"X-API-Key": key_a, "X-Tenant-Id": tenant_a},
    )
    assert resp.status_code == 200
    rows = resp.json()
    assert all(r["entry"]["tenant_id"] == tenant_a for r in rows), (
        "cross-tenant data leaked"
    )
    assert len(rows) == 1


# ---------------------------------------------------------------------------
# B) Body spoof: forged tenant_id in request body on scoped path
# ---------------------------------------------------------------------------


def test_body_spoof_tenant_rejected_on_create_approval(spoof_client):
    """Scoped key bound to tenant-a; body with tenant_id=tenant-b must be rejected."""
    s = _suffix()
    tenant_a = f"spoof-body-a-{s}"
    tenant_b = f"spoof-body-b-{s}"
    key_a = mint_key("attestation:admin", tenant_id=tenant_a)
    client = TestClient(spoof_client)

    resp = client.post(
        "/approvals",
        headers={"X-API-Key": key_a},
        json={
            "tenant_id": tenant_b,
            "subject_type": "change",
            "subject_id": f"sub-{s}",
            "action": "approve",
            "approver": "attacker",
            "reason": "spoof attempt",
        },
    )
    assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text}"


def test_body_spoof_tenant_rejected_on_verify_approvals(spoof_client):
    """Scoped key bound to tenant-a; verify body with tenant_id=tenant-b must be rejected."""
    s = _suffix()
    tenant_a = f"spoof-verify-a-{s}"
    tenant_b = f"spoof-verify-b-{s}"
    key_a = mint_key("attestation:admin", tenant_id=tenant_a)
    client = TestClient(spoof_client)

    resp = client.post(
        "/approvals/verify",
        headers={"X-API-Key": key_a},
        json={
            "tenant_id": tenant_b,
            "subject_type": "change",
            "subject_id": f"sub-{s}",
        },
    )
    assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text}"


# ---------------------------------------------------------------------------
# C) Unscoped key with forged tenant header — fail closed
# ---------------------------------------------------------------------------


def test_unscoped_key_spoof_tenant_header_rejected(spoof_client):
    """Unscoped attestation:admin key (no tenant binding) + forged header must fail closed."""
    s = _suffix()
    tenant_x = f"spoof-unscoped-x-{s}"
    unscoped_key = mint_key("attestation:admin")
    client = TestClient(spoof_client)

    resp = client.get(
        f"/approvals/change/sub-{s}",
        headers={"X-API-Key": unscoped_key, "X-Tenant-Id": tenant_x},
    )
    assert resp.status_code in {400, 403}, (
        f"Expected 400/403, got {resp.status_code}: {resp.text}"
    )


def test_unscoped_key_spoof_body_tenant_rejected(spoof_client):
    """Unscoped attestation:admin key (no tenant binding) + forged body tenant must fail closed."""
    s = _suffix()
    tenant_x = f"spoof-unscoped-body-{s}"
    unscoped_key = mint_key("attestation:admin")
    client = TestClient(spoof_client)

    resp = client.post(
        "/approvals",
        headers={"X-API-Key": unscoped_key},
        json={
            "tenant_id": tenant_x,
            "subject_type": "change",
            "subject_id": f"sub-{s}",
            "action": "approve",
            "approver": "attacker",
            "reason": "spoof attempt",
        },
    )
    assert resp.status_code in {400, 403}, (
        f"Expected 400/403, got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# D) Mixed-input conflict: body and header disagree — verified binding wins
# ---------------------------------------------------------------------------


def test_mixed_input_spoof_tenant_conflict_rejected(spoof_client):
    """Key bound to tenant-a; body says tenant-a but header says tenant-b — header conflict rejected."""
    s = _suffix()
    tenant_a = f"spoof-mix-a-{s}"
    tenant_b = f"spoof-mix-b-{s}"
    key_a = mint_key("attestation:admin", tenant_id=tenant_a)
    client = TestClient(spoof_client)

    resp = client.post(
        "/approvals",
        headers={"X-API-Key": key_a, "X-Tenant-Id": tenant_b},
        json={
            "tenant_id": tenant_a,
            "subject_type": "change",
            "subject_id": f"sub-{s}",
            "action": "approve",
            "approver": "user",
            "reason": "mixed conflict test",
        },
    )
    # Auth gate middleware rejects X-Tenant-Id conflict before the handler fires
    assert resp.status_code == 403, (
        f"Expected 403 on mixed conflict, got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# E) No cross-tenant side effect from spoof attempt
# ---------------------------------------------------------------------------


def test_spoof_tenant_body_does_not_write_to_foreign_tenant(spoof_client):
    """Spoof attempt (body tenant-b) with key bound to tenant-a must not create tenant-b records."""
    s = _suffix()
    tenant_a = f"spoof-nowrite-a-{s}"
    tenant_b = f"spoof-nowrite-b-{s}"
    key_a = mint_key("attestation:admin", tenant_id=tenant_a)
    client = TestClient(spoof_client)

    client.post(
        "/approvals",
        headers={"X-API-Key": key_a},
        json={
            "tenant_id": tenant_b,
            "subject_type": "change",
            "subject_id": f"sub-{s}",
            "action": "approve",
            "approver": "attacker",
            "reason": "spoof attempt",
        },
    )

    engine = get_engine()
    with Session(engine) as session:
        count = (
            session.query(ApprovalLog).filter(ApprovalLog.tenant_id == tenant_b).count()
        )
    assert count == 0, (
        f"Spoof attempt wrote {count} record(s) to foreign tenant {tenant_b}"
    )


# ---------------------------------------------------------------------------
# F) Scoped path, no forged value, correct tenant — succeeds (baseline)
# ---------------------------------------------------------------------------


def test_scoped_tenant_spoof_baseline_success(spoof_client):
    """Scoped key with correct matching tenant succeeds — verifies tests would fail if protection removed."""
    s = _suffix()
    tenant_a = f"spoof-base-a-{s}"
    subject_id = f"sub-{s}"
    key_a = mint_key("attestation:admin", tenant_id=tenant_a)
    client = TestClient(spoof_client)

    resp = client.post(
        "/approvals",
        headers={"X-API-Key": key_a},
        json={
            "tenant_id": tenant_a,
            "subject_type": "change",
            "subject_id": subject_id,
            "action": "approve",
            "approver": "legitimate-user",
            "reason": "valid request",
        },
    )
    assert resp.status_code == 200, (
        f"Expected 200 for valid scoped request, got {resp.status_code}: {resp.text}"
    )
