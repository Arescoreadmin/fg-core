"""Tests for deterministic finding ID derivation."""

from __future__ import annotations

import hashlib


from services.connectors.msgraph.findings.derivation import (
    derive_finding_id,
    hash_tenant_id,
)


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def test_derive_finding_id_is_deterministic():
    fid1 = derive_finding_id(tenant_id="t1", control_id="CTRL-001", evidence_key="key1")
    fid2 = derive_finding_id(tenant_id="t1", control_id="CTRL-001", evidence_key="key1")
    assert fid1 == fid2


def test_derive_finding_id_differs_on_tenant():
    fid1 = derive_finding_id(tenant_id="t1", control_id="CTRL-001", evidence_key="key")
    fid2 = derive_finding_id(tenant_id="t2", control_id="CTRL-001", evidence_key="key")
    assert fid1 != fid2


def test_derive_finding_id_differs_on_control():
    fid1 = derive_finding_id(tenant_id="t1", control_id="CTRL-001", evidence_key="key")
    fid2 = derive_finding_id(tenant_id="t1", control_id="CTRL-002", evidence_key="key")
    assert fid1 != fid2


def test_derive_finding_id_differs_on_evidence_key():
    fid1 = derive_finding_id(tenant_id="t1", control_id="CTRL-001", evidence_key="key1")
    fid2 = derive_finding_id(tenant_id="t1", control_id="CTRL-001", evidence_key="key2")
    assert fid1 != fid2


def test_derive_finding_id_does_not_contain_tenant_plaintext():
    tenant_id = "my-secret-tenant-id"
    fid = derive_finding_id(
        tenant_id=tenant_id, control_id="CTRL-001", evidence_key="k"
    )
    assert tenant_id not in fid


def test_hash_tenant_id_is_sha256():
    tid = "abc-123"
    result = hash_tenant_id(tid)
    assert result == hashlib.sha256(tid.encode()).hexdigest()
    assert len(result) == 64
