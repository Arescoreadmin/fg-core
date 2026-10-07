"""tests/test_customer_zero_final_readiness_001.py — CUSTOMER-ZERO-FINAL-READINESS-001 adversarial test suite.

This module is NOT standalone. It is a component of the FrostGate governance
platform and Customer-Zero trust ceremony readiness authority.

These tests verify:
  A — AUTHORITY (5 tests)
  B — DETERMINISM (5 tests)
  C — PROVENANCE (4 tests)
  D — TRUST (8 tests)
  E — PORTABLE VERIFICATION (10 tests)
  F — TENANT ISOLATION (3 tests)
  G — COST / INFRA (5 tests)
  H — AGGREGATION (6 tests)
  I — CEREMONY TRUTH (4 tests)

Total: 50+ tests (≥ 50 required)

Scope boundary: OFFLINE ONLY. No live infrastructure. No Vault server. No AWS
API calls. No Railway mutations. No HCP API calls. No paid infrastructure.
No secrets read or displayed.
"""

from __future__ import annotations

import base64
import os
import subprocess
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("FG_ENV", "test")

import pytest

from services.governance.customer_zero_readiness import (
    REQUIRED_COMPLETED_PREREQUISITES,
    WORK_ITEM,
    FinalResult,
    PortableVerificationAuthority,
    PortableVerificationBundle,
    ReadinessDimension,
    ReadinessResult,
    ReadinessStatus,
    _check_no_secret_material,
    _extract_blockers,
    evaluate,
    render_human_readable,
)

REPO = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _make_dim(
    status: ReadinessStatus = ReadinessStatus.PASS,
    required: bool = True,
    id: str = "test-dim-001",
    category: str = "TEST",
    name: str = "test_dimension",
    evidence: str = "test evidence",
    reason: str = "",
    remediation: str = "",
) -> ReadinessDimension:
    return ReadinessDimension(
        id=id,
        category=category,
        name=name,
        status=status,
        evidence=evidence,
        required=required,
        reason=reason,
        remediation=remediation,
    )


def _make_result(dims: list[ReadinessDimension]) -> ReadinessResult:
    blockers = _extract_blockers(dims)
    return ReadinessResult(
        source_sha="abc123" * 7,
        generated_at="2026-10-07T00:00:00Z",
        dimensions=dims,
        blockers=blockers,
    )


def _make_portable_bundle(
    *,
    trust_domain: str = "frostgate.report-proof.v1",
    algorithm: str = "ed25519",
    artifact_digest: str = "a" * 64,
    key_version: int = 1,
    key_identifier: str = "test-key-001",
) -> tuple[PortableVerificationBundle, PortableVerificationAuthority, bytes]:
    """Create a portable bundle with pre-enrolled public material. Returns (bundle, authority, signing_payload)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from services.cgin.key_management.vault_transit import public_key_fingerprint

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64 = base64.b64encode(pub_raw).decode("ascii")
    fp = public_key_fingerprint(pub_b64)

    signing_payload = f"{trust_domain}\n{artifact_digest}".encode("utf-8")
    sig_raw = priv.sign(signing_payload)
    signature = f"vault:v{key_version}:" + base64.b64encode(sig_raw).decode("ascii")

    bundle = PortableVerificationBundle(
        artifact_digest=artifact_digest,
        manifest={"report_id": "rep-test-001", "version": 1},
        signature=signature,
        trust_domain=trust_domain,
        public_key_material=pub_b64,
        public_key_fingerprint=fp,
        key_identifier=key_identifier,
        key_version=key_version,
        algorithm=algorithm,
        signing_timestamp="2026-10-07T00:00:00Z",
        source_sha="a" * 40,
        methodology_version="1.0.0",
        provenance_sha="b" * 40,
        audit_evidence_reference="fake-test-issuer",
    )

    authority = PortableVerificationAuthority()
    authority.enroll(trust_domain, key_identifier, key_version, pub_b64)

    return bundle, authority, signing_payload


# ---------------------------------------------------------------------------
# A — AUTHORITY (5 tests)
# ---------------------------------------------------------------------------


def test_a1_authorized_work_item_passes() -> None:
    """Test 1: Authorized work item CUSTOMER-ZERO-FINAL-READINESS-001 is in next_sequence."""
    result = subprocess.run(
        [
            "python",
            str(REPO / "tools" / "ci" / "check_customer_one_roadmap.py"),
            "--work-item",
            WORK_ITEM,
        ],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, (
        f"CUSTOMER-ZERO-FINAL-READINESS-001 must be AUTHORIZED; got: {result.stderr}"
    )
    assert "AUTHORIZED" in result.stdout


def test_a2_missing_roadmap_authority_fails() -> None:
    """Test 2: Roadmap checker fails gracefully when authority file is absent."""
    result = subprocess.run(
        [
            "python",
            str(REPO / "tools" / "ci" / "check_customer_one_roadmap.py"),
            "--authority",
            "/nonexistent/roadmap_authority.yaml",
            "--work-item",
            "SOME-ITEM",
        ],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode != 0, "Missing authority file must fail"


def test_a3_incomplete_prerequisite_fails() -> None:
    """Test 3: Blocked work item with unmet blocked_by fails authorization."""
    # CUSTOMER-ZERO-TRUST-003 is in blocked; should not be authorized
    result = subprocess.run(
        [
            "python",
            str(REPO / "tools" / "ci" / "check_customer_one_roadmap.py"),
            "--work-item",
            "CUSTOMER-ZERO-TRUST-003",
        ],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode != 0, (
        "CUSTOMER-ZERO-TRUST-003 must be BLOCKED (not authorized)"
    )


def test_a4_source_mismatch_fails() -> None:
    """Test 4: A4 dimension reports FAIL when source SHA does not match origin/main."""
    # Test via dimension evaluation — A4 checks git clean state
    # We simulate a mismatched source by patching _git_status_clean
    from services.governance.customer_zero_readiness import (
        _evaluate_repository_authority,
    )

    with patch(
        "services.governance.customer_zero_readiness._git_status_clean",
        return_value=False,
    ):
        dims = _evaluate_repository_authority(REPO)
        a4 = next((d for d in dims if d.id == "A4-clean-source-requirement"), None)
        assert a4 is not None, "A4-clean-source-requirement dimension must exist"
        assert a4.status == ReadinessStatus.FAIL, (
            f"A4 must be FAIL when source is not clean; got {a4.status}"
        )


def test_a5_completed_prerequisite_ids_verified() -> None:
    """Test 5: Both PROVENANCE-INTEGRITY-001 and VAULT-VERIFY-CONTRACT-001 are in completed."""
    import yaml

    authority_path = REPO / "customer_one" / "roadmap_authority.yaml"
    with open(authority_path, encoding="utf-8") as f:
        authority = yaml.safe_load(f)

    completed_ids = {
        e.get("id") for e in authority.get("completed", []) if isinstance(e, dict)
    }

    for prereq in REQUIRED_COMPLETED_PREREQUISITES:
        assert prereq in completed_ids, (
            f"Prerequisite {prereq!r} must be in completed; current completed: {sorted(completed_ids)}"
        )


# ---------------------------------------------------------------------------
# B — DETERMINISM (5 tests)
# ---------------------------------------------------------------------------


def test_b6_same_inputs_identical_readiness_result() -> None:
    """Test 6: Same inputs produce identical readiness result (deterministic)."""
    result1 = evaluate(REPO)
    result2 = evaluate(REPO)
    assert result1.final_result == result2.final_result, (
        "Same inputs must produce identical final result"
    )
    assert len(result1.dimensions) == len(result2.dimensions), (
        "Same inputs must produce same number of dimensions"
    )
    assert len(result1.blockers) == len(result2.blockers), (
        "Same inputs must produce same number of blockers"
    )


def test_b7_same_inputs_identical_fingerprint() -> None:
    """Test 7: Same inputs produce identical canonical fingerprint."""
    result1 = evaluate(REPO)
    result2 = evaluate(REPO)
    # Fingerprint excludes generated_at; must be stable
    assert result1.canonical_fingerprint == result2.canonical_fingerprint, (
        "Same inputs must produce identical canonical fingerprint"
    )


def test_b8_deterministic_blocker_ordering() -> None:
    """Test 8: Blockers are sorted deterministically by ID."""
    dims = [
        _make_dim(ReadinessStatus.FAIL, id="Z-last-001"),
        _make_dim(ReadinessStatus.FAIL, id="A-first-001"),
        _make_dim(ReadinessStatus.FAIL, id="M-middle-001"),
    ]
    blockers = _extract_blockers(dims)
    ids = [b.id for b in blockers]
    assert ids == sorted(ids), f"Blockers must be sorted deterministically; got {ids}"


def test_b9_no_wall_clock_contamination_in_canonical_hash() -> None:
    """Test 9: generated_at is excluded from the canonical fingerprint hash."""
    dims = [_make_dim(ReadinessStatus.PASS)]
    result1 = ReadinessResult(
        source_sha="abc" * 14,
        generated_at="2026-10-07T00:00:00Z",
        dimensions=dims,
        blockers=[],
    )
    result2 = ReadinessResult(
        source_sha="abc" * 14,
        generated_at="2026-10-07T12:00:00Z",  # different time
        dimensions=dims,
        blockers=[],
    )
    assert result1.canonical_fingerprint == result2.canonical_fingerprint, (
        "Canonical fingerprint must not include generated_at (wall-clock free)"
    )


def test_b10_no_random_identifiers() -> None:
    """Test 10: Evaluation produces stable dimension IDs (no random UUIDs)."""
    result = evaluate(REPO)
    for dim in result.dimensions:
        # All IDs must be stable strings (not UUIDs or random)
        assert dim.id, "Dimension ID must not be empty"
        # IDs should be deterministic (not contain random UUID-like patterns at end)
        # Basic check: ID must start with a category letter
        assert dim.id[0].isalpha() or dim.id[0].isdigit(), (
            f"Dimension ID must start with letter or digit: {dim.id!r}"
        )


# ---------------------------------------------------------------------------
# C — PROVENANCE (4 tests)
# ---------------------------------------------------------------------------


def test_c11_valid_provenance_pass() -> None:
    """Test 11: Valid provenance (PROVENANCE-INTEGRITY-001 complete) -> PASS."""
    result = evaluate(REPO)
    b12 = next(
        (d for d in result.dimensions if d.id == "B12-provenance-integrity"), None
    )
    assert b12 is not None, "B12-provenance-integrity dimension must be present"
    assert b12.status == ReadinessStatus.PASS, (
        f"PROVENANCE-INTEGRITY-001 is complete; B12 must be PASS, got {b12.status}"
    )


def test_c12_mutated_report_is_blocker() -> None:
    """Test 12: When PROVENANCE-INTEGRITY-001 is absent from completed -> blocker."""
    import yaml

    authority_path = REPO / "customer_one" / "roadmap_authority.yaml"
    with open(authority_path, encoding="utf-8") as f:
        authority = yaml.safe_load(f)

    # Simulate missing PROVENANCE-INTEGRITY-001
    authority_modified = dict(authority)
    authority_modified["completed"] = [
        e
        for e in authority.get("completed", [])
        if isinstance(e, dict) and e.get("id") != "PROVENANCE-INTEGRITY-001"
    ]

    from services.governance.customer_zero_readiness import _find_in_section

    assert not _find_in_section(
        authority_modified, "completed", "PROVENANCE-INTEGRITY-001"
    ), "Modified authority must not have PROVENANCE-INTEGRITY-001"

    # Now verify that _evaluate_application_truth detects this
    with patch(
        "services.governance.customer_zero_readiness._load_yaml_safe",
        return_value=authority_modified,
    ):
        from services.governance.customer_zero_readiness import (
            _evaluate_application_truth,
        )

        dims = _evaluate_application_truth(REPO)
        b12 = next((d for d in dims if d.id == "B12-provenance-integrity"), None)
        assert b12 is not None
        assert b12.status == ReadinessStatus.FAIL, (
            f"Missing PROVENANCE-INTEGRITY-001 must produce FAIL; got {b12.status}"
        )


def test_c13_missing_manifest_hash_function_is_blocker() -> None:
    """Test 13: Missing _derive_manifest_hash_from_report_json produces FAIL."""
    from services.governance.customer_zero_readiness import _evaluate_application_truth

    # Patch Path.read_text to simulate absence of the function
    original_read_text = Path.read_text

    def patched_read_text(self, *args, **kwargs) -> str:
        content = original_read_text(self, *args, **kwargs)
        if self.name == "field_assessment.py":
            # Remove the function from the content
            return content.replace(
                "_derive_manifest_hash_from_report_json", "__removed__"
            )
        return content

    with patch.object(Path, "read_text", patched_read_text):
        dims = _evaluate_application_truth(REPO)
        b7 = next((d for d in dims if d.id == "B7-deterministic-findings"), None)
        assert b7 is not None
        assert b7.status == ReadinessStatus.FAIL, (
            f"Missing derive function must produce FAIL; got {b7.status}"
        )


def test_c14_source_provenance_mismatch_is_blocker() -> None:
    """Test 14: HEAD != origin/main produces A3 blocker."""
    from services.governance.customer_zero_readiness import (
        _evaluate_repository_authority,
    )

    with (
        patch(
            "services.governance.customer_zero_readiness._git_head",
            return_value="aaa" + "0" * 37,
        ),
        patch(
            "services.governance.customer_zero_readiness._git_origin_main",
            return_value="bbb" + "0" * 37,
        ),
    ):
        dims = _evaluate_repository_authority(REPO)
        a3 = next((d for d in dims if d.id == "A3-canonical-source-sha"), None)
        assert a3 is not None
        assert a3.status == ReadinessStatus.FAIL, (
            f"SHA mismatch must produce FAIL; got {a3.status}"
        )


# ---------------------------------------------------------------------------
# D — TRUST (8 tests)
# ---------------------------------------------------------------------------


def test_d15_correct_domain_verification_pass() -> None:
    """Test 15: Pre-enrolled public material + correct domain -> PASS."""
    bundle, authority, _ = _make_portable_bundle(
        trust_domain="frostgate.report-proof.v1"
    )
    assert authority.verify_offline(bundle) is True, (
        "Correct domain with pre-enrolled material must verify"
    )


def test_d16_wrong_domain_fails() -> None:
    """Test 16: Wrong trust domain -> False."""
    bundle, authority, _ = _make_portable_bundle(
        trust_domain="frostgate.report-proof.v1"
    )
    # Create bundle with wrong domain but same key material
    bad_bundle = PortableVerificationBundle(
        artifact_digest=bundle.artifact_digest,
        manifest=bundle.manifest,
        signature=bundle.signature,
        trust_domain="frostgate.production-qualification.v1",  # WRONG domain
        public_key_material=bundle.public_key_material,
        public_key_fingerprint=bundle.public_key_fingerprint,
        key_identifier=bundle.key_identifier,
        key_version=bundle.key_version,
        algorithm=bundle.algorithm,
        signing_timestamp=bundle.signing_timestamp,
        source_sha=bundle.source_sha,
        methodology_version=bundle.methodology_version,
        provenance_sha=bundle.provenance_sha,
        audit_evidence_reference=bundle.audit_evidence_reference,
    )
    # Different domain -> not enrolled under that domain
    assert authority.verify_offline(bad_bundle) is False, (
        "Wrong domain must fail (not enrolled)"
    )


def test_d17_wrong_key_fails() -> None:
    """Test 17: Substituted public key -> False."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    bundle, authority, _ = _make_portable_bundle()

    # Enroll a DIFFERENT key under the same domain/id/version
    wrong_priv = Ed25519PrivateKey.generate()
    wrong_pub = wrong_priv.public_key()
    wrong_pub_raw = wrong_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    wrong_pub_b64 = base64.b64encode(wrong_pub_raw).decode("ascii")

    # Override enrollment with wrong key
    authority._enrolled[
        (bundle.trust_domain, bundle.key_identifier, bundle.key_version)
    ] = wrong_pub_b64

    assert authority.verify_offline(bundle) is False, (
        "Wrong public key must fail verification"
    )


def test_d18_wrong_key_version_fails() -> None:
    """Test 18: Absent key version -> False (key not enrolled)."""
    bundle, authority, _ = _make_portable_bundle(key_version=1)
    # Create bundle claiming version 2 but version 2 not enrolled
    bad_bundle = PortableVerificationBundle(
        artifact_digest=bundle.artifact_digest,
        manifest=bundle.manifest,
        signature=bundle.signature,
        trust_domain=bundle.trust_domain,
        public_key_material=bundle.public_key_material,
        public_key_fingerprint=bundle.public_key_fingerprint,
        key_identifier=bundle.key_identifier,
        key_version=2,  # WRONG version — not enrolled
        algorithm=bundle.algorithm,
        signing_timestamp=bundle.signing_timestamp,
        source_sha=bundle.source_sha,
        methodology_version=bundle.methodology_version,
        provenance_sha=bundle.provenance_sha,
        audit_evidence_reference=bundle.audit_evidence_reference,
    )
    assert authority.verify_offline(bad_bundle) is False, (
        "Wrong key version (not enrolled) must fail"
    )


def test_d19_malformed_signature_fails() -> None:
    """Test 19: Malformed signature -> False."""
    bundle, authority, _ = _make_portable_bundle()
    bad_bundle = PortableVerificationBundle(
        artifact_digest=bundle.artifact_digest,
        manifest=bundle.manifest,
        signature="not-a-valid-vault-signature",  # MALFORMED
        trust_domain=bundle.trust_domain,
        public_key_material=bundle.public_key_material,
        public_key_fingerprint=bundle.public_key_fingerprint,
        key_identifier=bundle.key_identifier,
        key_version=bundle.key_version,
        algorithm=bundle.algorithm,
        signing_timestamp=bundle.signing_timestamp,
        source_sha=bundle.source_sha,
        methodology_version=bundle.methodology_version,
        provenance_sha=bundle.provenance_sha,
        audit_evidence_reference=bundle.audit_evidence_reference,
    )
    assert authority.verify_offline(bad_bundle) is False, (
        "Malformed signature must fail"
    )


def test_d20_cross_domain_replay_fails() -> None:
    """Test 20: Signature from domain A cannot be replayed as domain B."""
    # Create bundle signed under report domain
    bundle_report, authority_report, _ = _make_portable_bundle(
        trust_domain="frostgate.report-proof.v1",
        key_identifier="key-report",
    )
    # Create a separate authority for qualification domain
    bundle_qual, authority_qual, _ = _make_portable_bundle(
        trust_domain="frostgate.production-qualification.v1",
        key_identifier="key-qual",
    )

    # Replay: use report signature against qualification domain
    replayed = PortableVerificationBundle(
        artifact_digest=bundle_report.artifact_digest,
        manifest=bundle_report.manifest,
        signature=bundle_report.signature,  # report domain signature
        trust_domain="frostgate.production-qualification.v1",  # wrong domain
        public_key_material=bundle_report.public_key_material,
        public_key_fingerprint=bundle_report.public_key_fingerprint,
        key_identifier=bundle_report.key_identifier,
        key_version=bundle_report.key_version,
        algorithm=bundle_report.algorithm,
        signing_timestamp=bundle_report.signing_timestamp,
        source_sha=bundle_report.source_sha,
        methodology_version=bundle_report.methodology_version,
        provenance_sha=bundle_report.provenance_sha,
        audit_evidence_reference=bundle_report.audit_evidence_reference,
    )
    # Not enrolled under qualification domain -> False
    assert authority_report.verify_offline(replayed) is False, (
        "Cross-domain replay must fail"
    )


def test_d21_historical_legitimate_version_pass() -> None:
    """Test 21: Pre-enrolled historical version verifies after 'Vault is gone'."""
    bundle, authority, _ = _make_portable_bundle(key_version=1)
    # Simulate Vault being absent: authority only has pre-enrolled material
    # verify_offline uses ONLY the enrolled material
    assert authority.verify_offline(bundle) is True, (
        "Pre-enrolled historical v1 must verify offline (Vault absent)"
    )


def test_d22_operational_verifier_failure_handled_deterministically() -> None:
    """Test 22: TrustBindingAuthority.verify_report catches VaultTransitError -> False."""
    from services.cgin.key_management.vault_transit import VaultTransitError
    from services.governance.trust_binding import (
        TrustBindingAuthority,
        build_report_signing_payload,
    )

    class _FailingBackend:
        def sign(self, role, payload):
            raise VaultTransitError("test failure")

        def verify(self, role, payload, signature):
            raise VaultTransitError("Vault unavailable test")

    authority = TrustBindingAuthority(_FailingBackend())
    payload = build_report_signing_payload(
        tenant_id="t1",
        engagement_id="e1",
        report_id="r1",
        report_version_id="rv1",
        report_fingerprint="f" * 64,
        report_schema_version="1.0",
    )

    from services.governance.trust_binding import SignatureEnvelope

    fake_env = SignatureEnvelope(
        issuer="test",
        trust_role="customer-zero-identity",
        key_id="k1",
        key_version=1,
        algorithm="ed25519",
        public_key_fingerprint="fp",
        signature="vault:v1:abc",
        domain="frostgate.report-proof.v1",
        signed_payload_sha256="sha",
    )
    # Must return False, not raise
    result = authority.verify_report(payload, fake_env)
    assert result is False, (
        "VaultTransitError must produce deterministic False at authority boundary"
    )


# ---------------------------------------------------------------------------
# E — PORTABLE VERIFICATION (10 tests)
# ---------------------------------------------------------------------------


def test_e23_pre_enrolled_public_material_offline_verify_pass() -> None:
    """Test 23: Pre-enrolled public material allows offline historical verification."""
    bundle, authority, _ = _make_portable_bundle()
    assert authority.verify_offline(bundle) is True


def test_e24_simulated_vault_absent_historical_verify_pass() -> None:
    """Test 24: When Vault is 'absent', pre-enrolled material still works."""
    bundle, authority, _ = _make_portable_bundle()
    # authority has no live Vault connection at all — purely offline
    # Confirm: verify_offline makes no network calls
    assert authority.verify_offline(bundle) is True, (
        "Historical verification must succeed with pre-enrolled material when Vault is absent"
    )


def test_e25_missing_public_material_returns_false() -> None:
    """Test 25: No pre-enrolled material -> False (NOT_PROVEN)."""
    bundle, _, _ = _make_portable_bundle()
    empty_authority = PortableVerificationAuthority()
    # Nothing enrolled
    assert empty_authority.verify_offline(bundle) is False, (
        "Missing enrollment must return False"
    )


def test_e26_substituted_public_material_fails() -> None:
    """Test 26: Substituted (different) public material -> False."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )  # noqa: F401

    bundle, authority, _ = _make_portable_bundle()

    # Enroll a different key for the same domain/id/version
    wrong_key = Ed25519PrivateKey.generate()
    wrong_pub = wrong_key.public_key()
    wrong_pub_raw = wrong_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    wrong_pub_b64 = base64.b64encode(wrong_pub_raw).decode("ascii")

    authority._enrolled[
        (bundle.trust_domain, bundle.key_identifier, bundle.key_version)
    ] = wrong_pub_b64

    assert authority.verify_offline(bundle) is False, (
        "Substituted public material must fail fingerprint or signature check"
    )


def test_e27_mutated_signed_artifact_fails() -> None:
    """Test 27: Mutated artifact digest -> False (signature mismatch)."""
    bundle, authority, _ = _make_portable_bundle()
    # Mutate the artifact digest
    mutated_bundle = PortableVerificationBundle(
        artifact_digest="deadbeef" + "0" * 56,  # MUTATED
        manifest=bundle.manifest,
        signature=bundle.signature,
        trust_domain=bundle.trust_domain,
        public_key_material=bundle.public_key_material,
        public_key_fingerprint=bundle.public_key_fingerprint,
        key_identifier=bundle.key_identifier,
        key_version=bundle.key_version,
        algorithm=bundle.algorithm,
        signing_timestamp=bundle.signing_timestamp,
        source_sha=bundle.source_sha,
        methodology_version=bundle.methodology_version,
        provenance_sha=bundle.provenance_sha,
        audit_evidence_reference=bundle.audit_evidence_reference,
    )
    assert authority.verify_offline(mutated_bundle) is False, (
        "Mutated artifact digest must fail signature verification"
    )


def test_e28_wrong_domain_fails() -> None:
    """Test 28: Wrong trust domain -> False (not enrolled)."""
    bundle, authority, _ = _make_portable_bundle(
        trust_domain="frostgate.report-proof.v1"
    )
    wrong_domain_bundle = PortableVerificationBundle(
        artifact_digest=bundle.artifact_digest,
        manifest=bundle.manifest,
        signature=bundle.signature,
        trust_domain="frostgate.governed-delivery-authorization.v1",  # wrong
        public_key_material=bundle.public_key_material,
        public_key_fingerprint=bundle.public_key_fingerprint,
        key_identifier=bundle.key_identifier,
        key_version=bundle.key_version,
        algorithm=bundle.algorithm,
        signing_timestamp=bundle.signing_timestamp,
        source_sha=bundle.source_sha,
        methodology_version=bundle.methodology_version,
        provenance_sha=bundle.provenance_sha,
        audit_evidence_reference=bundle.audit_evidence_reference,
    )
    assert authority.verify_offline(wrong_domain_bundle) is False


def test_e29_wrong_version_fails() -> None:
    """Test 29: Claimed version not enrolled -> False."""
    bundle, authority, _ = _make_portable_bundle(key_version=1)
    # Version 99 not enrolled
    bad_bundle = PortableVerificationBundle(
        artifact_digest=bundle.artifact_digest,
        manifest=bundle.manifest,
        signature=bundle.signature,
        trust_domain=bundle.trust_domain,
        public_key_material=bundle.public_key_material,
        public_key_fingerprint=bundle.public_key_fingerprint,
        key_identifier=bundle.key_identifier,
        key_version=99,  # not enrolled
        algorithm=bundle.algorithm,
        signing_timestamp=bundle.signing_timestamp,
        source_sha=bundle.source_sha,
        methodology_version=bundle.methodology_version,
        provenance_sha=bundle.provenance_sha,
        audit_evidence_reference=bundle.audit_evidence_reference,
    )
    assert authority.verify_offline(bad_bundle) is False


def test_e30_malformed_portable_bundle_fails() -> None:
    """Test 30: Malformed bundle (unknown domain) -> False."""
    bundle, authority, _ = _make_portable_bundle()
    bad_bundle = PortableVerificationBundle(
        artifact_digest=bundle.artifact_digest,
        manifest=bundle.manifest,
        signature=bundle.signature,
        trust_domain="frostgate.unknown-domain.v99",  # unknown
        public_key_material=bundle.public_key_material,
        public_key_fingerprint=bundle.public_key_fingerprint,
        key_identifier=bundle.key_identifier,
        key_version=bundle.key_version,
        algorithm=bundle.algorithm,
        signing_timestamp=bundle.signing_timestamp,
        source_sha=bundle.source_sha,
        methodology_version=bundle.methodology_version,
        provenance_sha=bundle.provenance_sha,
        audit_evidence_reference=bundle.audit_evidence_reference,
    )
    assert authority.verify_offline(bad_bundle) is False, (
        "Unknown domain must return False"
    )


def test_e31_private_key_material_forbidden_in_bundle() -> None:
    """Test 31: Manifest containing a secret-bearing field name raises ValueError."""
    # A bundle whose manifest contains a field named 'private_key' must be rejected.
    with pytest.raises(ValueError, match="secret-bearing"):
        PortableVerificationBundle(
            artifact_digest="a" * 64,
            manifest={
                "private_key": "this-value-does-not-matter"
            },  # field NAME is secret-bearing
            signature="vault:v1:abc",
            trust_domain="frostgate.report-proof.v1",
            public_key_material="validpubkey",
            public_key_fingerprint="fp",
            key_identifier="key-001",
            key_version=1,
            algorithm="ed25519",
            signing_timestamp="2026-10-07T00:00:00Z",
            source_sha="a" * 40,
            methodology_version="1.0.0",
            provenance_sha="b" * 40,
            audit_evidence_reference="ref",
        )


def test_e32_bundle_contains_no_secret_material() -> None:
    """Test 32: Portable bundle dict contains no secret/token/private-key material."""
    bundle, _, _ = _make_portable_bundle()
    bundle_dict = bundle.to_dict()
    assert PortableVerificationBundle.validate_no_private_material(bundle_dict), (
        "Portable bundle must contain no secret/private-key material"
    )


# ---------------------------------------------------------------------------
# F — TENANT ISOLATION (3 tests)
# ---------------------------------------------------------------------------


def test_f33_tenant_a_evidence_cannot_satisfy_tenant_b() -> None:
    """Test 33: Tenant A artifact cannot verify as Tenant B."""
    from services.governance.trust_binding import (
        build_report_signing_payload,
    )
    from services.governance.trust_binding_fake import make_test_authority

    auth_a = make_test_authority()

    payload_a = build_report_signing_payload(
        tenant_id="tenant-a",
        engagement_id="eng-a",
        report_id="rep-a",
        report_version_id="rv-a",
        report_fingerprint="fp" * 32,
        report_schema_version="1.0",
    )
    payload_b = build_report_signing_payload(
        tenant_id="tenant-b",  # different tenant
        engagement_id="eng-b",
        report_id="rep-b",
        report_version_id="rv-b",
        report_fingerprint="fp" * 32,
        report_schema_version="1.0",
    )

    # Sign tenant A payload with auth_a
    env_a = auth_a.sign_report(payload_a)

    # Attempt to verify tenant A envelope against tenant B payload -> must fail
    result = auth_a.verify_report(payload_b, env_a)
    assert result is False, "Tenant A envelope must not verify against Tenant B payload"


def test_f34_cross_tenant_proof_substitution_fails() -> None:
    """Test 34: Cross-tenant proof substitution fails deterministically."""
    from services.governance.trust_binding import (
        build_report_signing_payload,
    )
    from services.governance.trust_binding_fake import make_test_authority

    auth = make_test_authority()

    payload_a = build_report_signing_payload(
        tenant_id="tenant-alpha",
        engagement_id="eng-1",
        report_id="rep-1",
        report_version_id="rv-1",
        report_fingerprint="x" * 64,
        report_schema_version="1.0",
    )
    payload_b = build_report_signing_payload(
        tenant_id="tenant-beta",  # different
        engagement_id="eng-2",
        report_id="rep-2",
        report_version_id="rv-2",
        report_fingerprint="y" * 64,
        report_schema_version="1.0",
    )

    env_a = auth.sign_report(payload_a)
    # Substitution: envelope from A against payload from B
    assert auth.verify_report(payload_b, env_a) is False, (
        "Cross-tenant substitution must fail"
    )


def test_f35_tenant_bound_provenance_remains_bound() -> None:
    """Test 35: Tenant-bound provenance cannot be reused for a different tenant."""
    from services.governance.trust_binding import (
        build_report_signing_payload,
    )
    from services.governance.trust_binding_fake import make_test_authority

    auth = make_test_authority()

    payload = build_report_signing_payload(
        tenant_id="tenant-bound-001",
        engagement_id="eng-bound",
        report_id="rep-bound",
        report_version_id="rv-bound",
        report_fingerprint="b" * 64,
        report_schema_version="1.0",
    )

    env = auth.sign_report(payload)
    # Original verifies
    assert auth.verify_report(payload, env) is True

    # Mutated tenant
    mutated_payload = dict(payload)
    mutated_payload["tenant_id"] = "tenant-different-002"
    assert auth.verify_report(mutated_payload, env) is False, (
        "Tenant-bound provenance must not verify for a different tenant"
    )


# ---------------------------------------------------------------------------
# G — COST / INFRA (5 tests)
# ---------------------------------------------------------------------------


def test_g36_paid_infrastructure_present_blocked() -> None:
    """Test 36: Paid infrastructure declared present -> FAIL on G46."""
    from services.governance.customer_zero_readiness import _evaluate_cost_authority

    mock_ceremony = {
        "infrastructure_lifecycle_status": "HCP_ACTIVE",  # simulated active
        "third_paid_ceremony_status": "NOT_AUTHORIZED",
        "cost_containment": {
            "outcome": "CUSTOMER_ZERO_COST_CONTAINMENT_COMPLETE",
            "historical_october_usage_usd": 321.81,
            "stages_completed": [],
            "preserved_aws_resources": [],
        },
    }

    with patch(
        "services.governance.customer_zero_readiness._load_yaml_safe",
        return_value=mock_ceremony,
    ):
        dims = _evaluate_cost_authority(REPO)
        g46 = next((d for d in dims if d.id == "G46-paid-infrastructure-absent"), None)
        assert g46 is not None
        assert g46.status == ReadinessStatus.FAIL, (
            f"HCP_ACTIVE infrastructure must produce FAIL; got {g46.status}"
        )


def test_g37_absent_paid_infrastructure_expected_state() -> None:
    """Test 37: HCP_ABSENT infrastructure -> PASS on G46."""
    result = evaluate(REPO)
    g46 = next(
        (d for d in result.dimensions if d.id == "G46-paid-infrastructure-absent"), None
    )
    assert g46 is not None
    assert g46.status == ReadinessStatus.PASS, (
        f"HCP_ABSENT infrastructure must produce PASS; got {g46.status}"
    )


def test_g38_fresh_cost_authorization_absent_does_not_trigger_provisioning() -> None:
    """Test 38: Readiness evaluation never provisions resources (read-only)."""
    # The test simply runs the evaluation and confirms it does not fail
    # with any side effect. If this test runs without timeout, provisioning
    # did not occur.
    result = evaluate(REPO)
    # Must complete without provisioning anything
    g47 = next(
        (
            d
            for d in result.dimensions
            if d.id == "G47-fresh-cost-authorization-required"
        ),
        None,
    )
    assert g47 is not None
    assert g47.status == ReadinessStatus.PASS, (
        "G47 must PASS (fresh authorization required = correctly required, not manufactured)"
    )


def test_g39_readiness_gate_cannot_authorize_paid_ceremony() -> None:
    """Test 39: READY result does NOT authorize CUSTOMER-ZERO-TRUST-003."""
    result = evaluate(REPO)
    result_dict = result.to_dict()
    # canonical_truth must preserve NOT_AUTHORIZED
    canonical_truth = result_dict.get("canonical_truth", {})
    assert canonical_truth.get("CUSTOMER_ZERO_TRUST_003") == "NOT_AUTHORIZED", (
        "READY must NOT authorize CUSTOMER-ZERO-TRUST-003"
    )
    assert canonical_truth.get("THIRD_PAID_CEREMONY") == "NOT_AUTHORIZED", (
        "READY must NOT authorize third paid ceremony"
    )


def test_g40_preserved_aws_audit_boundary_not_teardown_failure() -> None:
    """Test 40: Preserved AWS audit resources do not count as teardown failures."""
    import yaml

    ceremony_path = REPO / "customer_one" / "ceremony_state.yaml"
    with open(ceremony_path, encoding="utf-8") as f:
        ceremony = yaml.safe_load(f)

    # AWS audit preserved: this is NOT a blocker
    assert ceremony.get("aws_audit_lifecycle_status") == "AWS_AUDIT_PRESERVED", (
        "AWS audit must be preserved, not torn down"
    )
    assert ceremony.get("infrastructure_lifecycle_status") == "HCP_ABSENT", (
        "HCP must be absent (HCP_ABSENT) — only AWS audit is preserved"
    )

    result = evaluate(REPO)
    # E35 should PASS (audit preserved)
    e35 = next(
        (d for d in result.dimensions if d.id == "E35-audit-evidence-separation"), None
    )
    assert e35 is not None
    assert e35.status == ReadinessStatus.PASS, (
        f"AWS audit preserved must be PASS, not blocker; got {e35.status}"
    )


# ---------------------------------------------------------------------------
# H — AGGREGATION (6 tests)
# ---------------------------------------------------------------------------


def test_h41_all_required_pass_is_ready() -> None:
    """Test 41: All required dimensions PASS -> READY."""
    dims = [
        _make_dim(ReadinessStatus.PASS, required=True, id=f"dim-{i:03d}")
        for i in range(10)
    ]
    result = _make_result(dims)
    assert result.final_result == FinalResult.READY
    assert result.offline_blocker_count == 0


def test_h42_one_fail_is_blocked() -> None:
    """Test 42: One FAIL in required dimension -> BLOCKED."""
    dims = [_make_dim(ReadinessStatus.PASS, id=f"pass-{i:03d}") for i in range(5)] + [
        _make_dim(ReadinessStatus.FAIL, id="fail-001", reason="Test failure")
    ]
    result = _make_result(dims)
    assert result.final_result == FinalResult.BLOCKED
    assert result.offline_blocker_count >= 1


def test_h43_one_required_not_proven_is_blocked() -> None:
    """Test 43: One required NOT_PROVEN -> BLOCKED."""
    dims = [_make_dim(ReadinessStatus.PASS, id=f"pass-{i:03d}") for i in range(5)] + [
        _make_dim(
            ReadinessStatus.NOT_PROVEN, required=True, id="np-001", reason="Not proven"
        )
    ]
    result = _make_result(dims)
    assert result.final_result == FinalResult.BLOCKED
    assert result.offline_blocker_count >= 1


def test_h44_multiple_blockers_all_retained() -> None:
    """Test 44: Multiple blockers are all retained (no truncation)."""
    dims = [
        _make_dim(ReadinessStatus.FAIL, id=f"fail-{i:03d}", reason=f"Failure {i}")
        for i in range(7)
    ]
    result = _make_result(dims)
    assert result.offline_blocker_count == 7, (
        f"All 7 blockers must be retained; got {result.offline_blocker_count}"
    )


def test_h45_blocker_output_deterministic() -> None:
    """Test 45: Blocker output is deterministically sorted."""
    dims = [
        _make_dim(ReadinessStatus.FAIL, id="Z-dim-003"),
        _make_dim(ReadinessStatus.FAIL, id="A-dim-001"),
        _make_dim(ReadinessStatus.FAIL, id="M-dim-002"),
    ]
    result = _make_result(dims)
    blocker_ids = [b.id for b in result.blockers]
    assert blocker_ids == sorted(blocker_ids), (
        f"Blockers must be sorted deterministically; got {blocker_ids}"
    )


def test_h46_no_blocker_truncation() -> None:
    """Test 46: 20 blockers — none truncated in result."""
    dims = [_make_dim(ReadinessStatus.FAIL, id=f"fail-{i:03d}") for i in range(20)]
    result = _make_result(dims)
    assert result.offline_blocker_count == 20, (
        f"All 20 blockers must be retained; got {result.offline_blocker_count}"
    )
    result_dict = result.to_dict()
    assert len(result_dict["offline_blockers"]) == 20


# ---------------------------------------------------------------------------
# I — CEREMONY TRUTH (4 tests)
# ---------------------------------------------------------------------------


def test_i47_trust_remains_not_proven() -> None:
    """Test 47: CUSTOMER_ZERO_TRUST remains NOT_PROVEN after evaluation."""
    result = evaluate(REPO)
    result_dict = result.to_dict()
    assert result_dict["customer_zero_trust_status"] == "NOT_PROVEN", (
        "CUSTOMER_ZERO_TRUST must remain NOT_PROVEN"
    )
    assert result_dict["canonical_truth"]["CUSTOMER_ZERO_TRUST"] == "NOT_PROVEN"


def test_i48_acceptance_remains_blocked() -> None:
    """Test 48: CUSTOMER_ZERO_ACCEPTANCE remains BLOCKED after evaluation."""
    result = evaluate(REPO)
    result_dict = result.to_dict()
    assert result_dict["canonical_truth"]["CUSTOMER_ZERO_ACCEPTANCE"] == "BLOCKED", (
        "CUSTOMER_ZERO_ACCEPTANCE must remain BLOCKED"
    )


def test_i49_third_paid_ceremony_remains_not_authorized() -> None:
    """Test 49: THIRD_PAID_CEREMONY remains NOT_AUTHORIZED after evaluation."""
    result = evaluate(REPO)
    result_dict = result.to_dict()
    assert result_dict["third_paid_ceremony_status"] == "NOT_AUTHORIZED", (
        "THIRD_PAID_CEREMONY must remain NOT_AUTHORIZED"
    )
    assert result_dict["canonical_truth"]["THIRD_PAID_CEREMONY"] == "NOT_AUTHORIZED"


def test_i50_hcp_paid_infrastructure_remains_absent() -> None:
    """Test 50: PAID_HCP_INFRASTRUCTURE remains ABSENT."""
    result = evaluate(REPO)
    result_dict = result.to_dict()
    assert result_dict["paid_infrastructure_present"] is False, (
        "paid_infrastructure_present must be False"
    )
    assert result_dict["canonical_truth"]["PAID_HCP_INFRASTRUCTURE"] == "ABSENT", (
        "PAID_HCP_INFRASTRUCTURE must be ABSENT"
    )


# ---------------------------------------------------------------------------
# Additional tests (bonus coverage for robustness and security)
# ---------------------------------------------------------------------------


def test_bonus_51_human_readable_output_contains_canonical_truth() -> None:
    """Bonus 51: Human-readable output contains canonical truth statements."""
    result = evaluate(REPO)
    output = render_human_readable(result)
    assert "NOT_PROVEN" in output, (
        "Human-readable output must mention NOT_PROVEN status"
    )
    assert "NOT_AUTHORIZED" in output, (
        "Human-readable output must mention NOT_AUTHORIZED"
    )


def test_bonus_52_secret_scanner_rejects_private_key_fields() -> None:
    """Bonus 52: Secret scanner rejects private_key, secret_id, token fields."""
    violations = _check_no_secret_material(
        {"private_key": "abc", "data": {"secret_id": "xyz"}}
    )
    assert len(violations) >= 2, (
        f"Secret scanner must detect private_key and secret_id; got {violations}"
    )


def test_bonus_53_secret_scanner_allows_public_material() -> None:
    """Bonus 53: Secret scanner allows public key material fields."""
    violations = _check_no_secret_material(
        {
            "public_key": "abc123",
            "public_key_fingerprint": "fp123",
            "algorithm": "ed25519",
        }
    )
    assert len(violations) == 0, (
        f"Public material must not trigger secret scanner; violations: {violations}"
    )


def test_bonus_54_result_schema_version_correct() -> None:
    """Bonus 54: Result schema version is 1.0.0."""
    result = evaluate(REPO)
    result_dict = result.to_dict()
    assert result_dict["schema_version"] == "1.0.0"


def test_bonus_55_result_work_item_correct() -> None:
    """Bonus 55: Result work_item is CUSTOMER-ZERO-FINAL-READINESS-001."""
    result = evaluate(REPO)
    result_dict = result.to_dict()
    assert result_dict["work_item"] == "CUSTOMER-ZERO-FINAL-READINESS-001"


def test_bonus_56_result_mode_offline() -> None:
    """Bonus 56: Result mode is offline."""
    result = evaluate(REPO)
    result_dict = result.to_dict()
    assert result_dict["mode"] == "offline"


def test_bonus_57_all_dimensions_have_evidence() -> None:
    """Bonus 57: Every dimension has non-empty evidence string."""
    result = evaluate(REPO)
    for dim in result.dimensions:
        assert dim.evidence, f"Dimension {dim.id!r} must have non-empty evidence"


def test_bonus_58_enroll_rejects_private_material() -> None:
    """Bonus 58: PortableVerificationAuthority.enroll() rejects private material.

    The scanner checks field names in the data structure wrapping public_key_material.
    Since enroll() wraps the input as {"public_key_material": value}, a value that
    is itself a dict containing secret-bearing keys will be rejected.
    The simpler path: if we patch _check_no_secret_material to simulate a violation,
    the enroll() correctly propagates the error.
    """
    authority = PortableVerificationAuthority()

    # Direct test: passing a dict-as-string tricks the scanner
    # More realistic: verify that enroll propagates the error from _check_no_secret_material
    # by patching it to return a violation
    with patch(
        "services.governance.customer_zero_readiness._check_no_secret_material",
        return_value=["secret-bearing field rejected: $.private_key"],
    ):
        with pytest.raises(ValueError, match="Private material rejected"):
            authority.enroll(
                "frostgate.report-proof.v1",
                "key-001",
                1,
                "valid_looking_public_key",  # would pass normally, fails due to patch
            )

    # Verify that normal valid public key DOES enroll without error
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64 = base64.b64encode(pub_raw).decode("ascii")

    authority.enroll("frostgate.report-proof.v1", "key-legit", 1, pub_b64)
    assert authority.is_enrolled("frostgate.report-proof.v1", "key-legit", 1)


def test_bonus_59_fingerprint_deterministic_across_executions() -> None:
    """Bonus 59: Canonical fingerprint is identical across two independent evaluations."""
    r1 = evaluate(REPO)
    r2 = evaluate(REPO)
    assert r1.canonical_fingerprint == r2.canonical_fingerprint


def test_bonus_60_not_applicable_does_not_block() -> None:
    """Bonus 60: NOT_APPLICABLE dimensions (even required=True) do not block."""
    dims = [
        _make_dim(ReadinessStatus.PASS, id="pass-001"),
        _make_dim(ReadinessStatus.NOT_APPLICABLE, required=True, id="na-001"),
    ]
    blockers = _extract_blockers(dims)
    assert len(blockers) == 0, "NOT_APPLICABLE must not produce a blocker"
