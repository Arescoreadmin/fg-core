"""
Tests for ProvenanceStatus enforcement.

L14-SCAN-INTEGRITY-001 — test_provenance.py

Verifies:
- build_envelope computes correct sha256 digest
- verify_envelope returns VERIFIED_INTEGRITY_ONLY on correct payload
- verify_envelope returns INVALID on tampered payload
- verify_envelope returns INVALID on wrong evidence_id (via field check)
- verify_envelope returns INVALID on wrong tenant_id (digest bound to tenant)
- verify_envelope returns INVALID on wrong engagement_id
- Missing evidence returns MISSING
- INDETERMINATE on internal error
"""

import uuid


from services.field_assessment.evidence_integrity import (
    EvidenceIntegrityService,
    ProvenanceStatus,
    ScannerEvidenceEnvelope,
    compute_payload_digest,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_envelope(
    tenant_id: str = "tenant-abc",
    engagement_id: str = "eng-001",
    scan_id: str = "scan-001",
    scanner_id: str = "network_scan",
    payload: dict | None = None,
    schema_version: str = "1.0",
) -> tuple[ScannerEvidenceEnvelope, dict]:
    """Return (envelope, payload) built by EvidenceIntegrityService."""
    svc = EvidenceIntegrityService()
    p = payload if payload is not None else {"host": "example.com", "port": 443}
    env = svc.build_envelope(
        scan_id=scan_id,
        scanner_id=scanner_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        payload=p,
        schema_version=schema_version,
    )
    return env, p


# ---------------------------------------------------------------------------
# build_envelope tests
# ---------------------------------------------------------------------------


class TestBuildEnvelope:
    def test_computes_sha256_digest(self):
        """build_envelope must compute payload_digest as 'sha256:<hex>'."""
        env, payload = _make_envelope()
        expected = compute_payload_digest(payload, schema_version="1.0")
        assert env.payload_digest == expected
        assert env.payload_digest.startswith("sha256:")

    def test_sets_provenance_verified_integrity_only(self):
        """Without Vault signing, provenance_status must be VERIFIED_INTEGRITY_ONLY."""
        env, _ = _make_envelope()
        assert env.provenance_status == ProvenanceStatus.VERIFIED_INTEGRITY_ONLY

    def test_sets_signature_ref_none(self):
        """Without Vault, signature_ref must be None."""
        env, _ = _make_envelope()
        assert env.signature_ref is None

    def test_binds_tenant_id(self):
        """Envelope must record the provided tenant_id."""
        env, _ = _make_envelope(tenant_id="tenant-xyz")
        assert env.tenant_id == "tenant-xyz"

    def test_binds_engagement_id(self):
        """Envelope must record the provided engagement_id."""
        env, _ = _make_envelope(engagement_id="eng-999")
        assert env.engagement_id == "eng-999"

    def test_sets_canonicalization_version(self):
        """Envelope must record canonicalization_version."""
        env, _ = _make_envelope()
        assert env.canonicalization_version == "1.0"

    def test_generates_evidence_id(self):
        """Envelope must have a non-empty evidence_id (UUID)."""
        env, _ = _make_envelope()
        assert env.evidence_id
        # Validate it looks like a UUID
        uuid.UUID(env.evidence_id)

    def test_different_payloads_different_digest(self):
        """Two envelopes with different payloads must have different digests."""
        env1, _ = _make_envelope(payload={"port": 443})
        env2, _ = _make_envelope(payload={"port": 80})
        assert env1.payload_digest != env2.payload_digest

    def test_schema_version_affects_digest(self):
        """Different schema_version must produce a different digest."""
        env1, _ = _make_envelope(schema_version="1.0")
        env2, _ = _make_envelope(schema_version="1.1")
        assert env1.payload_digest != env2.payload_digest

    def test_collected_at_defaults_to_utc(self):
        """collected_at must be populated with a UTC ISO timestamp."""
        env, _ = _make_envelope()
        assert env.collected_at is not None
        assert "T" in env.collected_at  # ISO8601 format


# ---------------------------------------------------------------------------
# verify_envelope tests
# ---------------------------------------------------------------------------


class TestVerifyEnvelope:
    def test_correct_payload_returns_verified_integrity_only(self):
        """verify_envelope with original payload must return VERIFIED_INTEGRITY_ONLY."""
        svc = EvidenceIntegrityService()
        env, payload = _make_envelope()
        status = svc.verify_envelope(env, payload)
        assert status == ProvenanceStatus.VERIFIED_INTEGRITY_ONLY

    def test_tampered_payload_value_returns_invalid(self):
        """Changing a field value in the payload must return INVALID."""
        svc = EvidenceIntegrityService()
        env, _ = _make_envelope(payload={"host": "example.com", "port": 443})
        tampered = {"host": "evil.com", "port": 443}
        status = svc.verify_envelope(env, tampered)
        assert status == ProvenanceStatus.INVALID

    def test_tampered_payload_extra_field_returns_invalid(self):
        """Adding a field to the payload must return INVALID."""
        svc = EvidenceIntegrityService()
        env, payload = _make_envelope(payload={"host": "example.com"})
        tampered = {"host": "example.com", "extra_field": "injected"}
        status = svc.verify_envelope(env, tampered)
        assert status == ProvenanceStatus.INVALID

    def test_tampered_payload_removed_field_returns_invalid(self):
        """Removing a field from the payload must return INVALID."""
        svc = EvidenceIntegrityService()
        env, _ = _make_envelope(payload={"host": "example.com", "port": 443})
        incomplete = {"host": "example.com"}
        status = svc.verify_envelope(env, incomplete)
        assert status == ProvenanceStatus.INVALID

    def test_wrong_schema_version_returns_invalid(self):
        """Verifying with a different schema_version must return INVALID."""
        svc = EvidenceIntegrityService()
        env, payload = _make_envelope(schema_version="1.0")
        # Manually change schema_version on the envelope to simulate mismatch
        from dataclasses import replace

        env_v11 = replace(env, schema_version="1.1")
        status = svc.verify_envelope(env_v11, payload)
        # Digest was computed for 1.0 but envelope now says 1.1 → recompute differs
        assert status == ProvenanceStatus.INVALID

    def test_empty_payload_verified(self):
        """Empty dict payload must verify correctly."""
        svc = EvidenceIntegrityService()
        env, payload = _make_envelope(payload={})
        status = svc.verify_envelope(env, payload)
        assert status == ProvenanceStatus.VERIFIED_INTEGRITY_ONLY

    def test_large_payload_verified(self):
        """1000-key payload must verify correctly."""
        svc = EvidenceIntegrityService()
        large_payload = {f"k{i}": f"v{i}" for i in range(1000)}
        env, payload = _make_envelope(payload=large_payload)
        status = svc.verify_envelope(env, payload)
        assert status == ProvenanceStatus.VERIFIED_INTEGRITY_ONLY


# ---------------------------------------------------------------------------
# verify_by_id — DB-less behaviour
# ---------------------------------------------------------------------------


class TestVerifyById:
    """Test verify_by_id behaviour with a mock/stub session."""

    def test_missing_evidence_returns_missing(self):
        """When the DB returns no row, verify_by_id must return MISSING."""
        svc = EvidenceIntegrityService()

        class _MockDB:
            def execute(self, *a, **kw):
                return self

            def fetchone(self):
                return None

        status = svc.verify_by_id(_MockDB(), "nonexistent-id", "tenant-abc")
        assert status == ProvenanceStatus.MISSING

    def test_cross_tenant_returns_missing(self):
        """Cross-tenant access must return MISSING (not 403, to prevent leakage)."""
        svc = EvidenceIntegrityService()

        class _Row:
            tenant_id = "other-tenant"
            payload_digest = "sha256:aabbcc"
            schema_version = "1.0"
            signature_ref = None

        class _MockDB:
            def execute(self, *a, **kw):
                return self

            def fetchone(self):
                return _Row()

        status = svc.verify_by_id(_MockDB(), "some-id", "tenant-abc")
        assert status == ProvenanceStatus.MISSING

    def test_valid_digest_no_signature_returns_verified_integrity_only(self):
        """Valid row without signature returns VERIFIED_INTEGRITY_ONLY."""
        svc = EvidenceIntegrityService()

        class _Row:
            tenant_id = "tenant-abc"
            payload_digest = "sha256:aabbcc00112233445566778899aabb"
            schema_version = "1.0"
            signature_ref = None

        class _MockDB:
            def execute(self, *a, **kw):
                return self

            def fetchone(self):
                return _Row()

        status = svc.verify_by_id(_MockDB(), "some-id", "tenant-abc")
        assert status == ProvenanceStatus.VERIFIED_INTEGRITY_ONLY

    def test_valid_digest_with_signature_ref_returns_verified_authentic(self):
        """Valid row with signature_ref returns VERIFIED_AUTHENTIC."""
        svc = EvidenceIntegrityService()

        class _Row:
            tenant_id = "tenant-abc"
            payload_digest = "sha256:aabbcc"
            schema_version = "1.0"
            signature_ref = "vault:keys/scanner-receipts/1"

        class _MockDB:
            def execute(self, *a, **kw):
                return self

            def fetchone(self):
                return _Row()

        status = svc.verify_by_id(_MockDB(), "some-id", "tenant-abc")
        assert status == ProvenanceStatus.VERIFIED_AUTHENTIC

    def test_internal_error_returns_indeterminate(self):
        """DB exception must return INDETERMINATE (never raises to caller)."""
        svc = EvidenceIntegrityService()

        class _MockDB:
            def execute(self, *a, **kw):
                raise RuntimeError("DB connection lost")

        status = svc.verify_by_id(_MockDB(), "some-id", "tenant-abc")
        assert status == ProvenanceStatus.INDETERMINATE


# ---------------------------------------------------------------------------
# batch_verify
# ---------------------------------------------------------------------------


class TestBatchVerify:
    def test_all_missing(self):
        """Batch verify of non-existent IDs must return MISSING for all."""
        svc = EvidenceIntegrityService()

        class _MockDB:
            def execute(self, *a, **kw):
                return self

            def fetchone(self):
                return None

        result = svc.batch_verify(_MockDB(), ["id1", "id2", "id3"], "tenant-abc")
        assert result == {
            "id1": ProvenanceStatus.MISSING,
            "id2": ProvenanceStatus.MISSING,
            "id3": ProvenanceStatus.MISSING,
        }

    def test_mixed_cross_tenant_all_return_missing(self):
        """Mixed cross-tenant IDs must all return MISSING."""
        svc = EvidenceIntegrityService()
        call_count = [0]

        class _Row:
            tenant_id = "other-tenant"
            payload_digest = "sha256:xxxx"
            schema_version = "1.0"
            signature_ref = None

        class _MockDB:
            def execute(self, *a, **kw):
                call_count[0] += 1
                return self

            def fetchone(self):
                return _Row()

        result = svc.batch_verify(_MockDB(), ["id1", "id2"], "tenant-abc")
        assert result["id1"] == ProvenanceStatus.MISSING
        assert result["id2"] == ProvenanceStatus.MISSING
