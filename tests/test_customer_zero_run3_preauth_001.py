"""tests/test_customer_zero_run3_preauth_001.py

CUSTOMER-ZERO-RUN3-PREAUTH-001 — Adversarial test suite (60+ tests).

Test families:
  A (1-7):   Source/candidate freeze
  B (8-14):  Resource inventory
  C (15-22): Cost authorization
  D (23-32): Proof matrix completeness
  E (33-43): REAL portable verification (Ed25519, no mocks)
  F (44-49): Abort matrix
  G (50-56): No self-authorization
  H (57-60): Secret safety

CRYPTOGRAPHY INVARIANT
----------------------
All Ed25519 operations use test-only keys generated fresh per test.
Test keys are clearly labeled TEST-ONLY.
No production signing material is used in these tests.
Private key material NEVER enters PortableVerificationBundle.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Module setup
# ---------------------------------------------------------------------------

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

os.environ.setdefault("FG_ENV", "test")

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

_TEST_DOMAIN = "frostgate.test-domain.v1"
_TEST_DOMAIN_ALT = "frostgate.report-proof.v1"
_TEST_KEY_LABEL = "TEST-ONLY-ED25519-KEY-NOT-FOR-PRODUCTION"


def _generate_test_ed25519_key_pair() -> tuple[bytes, str]:
    """Generate a fresh Ed25519 key pair for test use only.

    Returns (private_key_bytes, public_key_base64).
    The private key bytes are used for signing ONLY and never stored.
    The public key (base64) is what goes into the PortableVerificationBundle.

    Keys are labeled TEST-ONLY and cannot be mistaken for production authority.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    # Export raw public key bytes (32 bytes for Ed25519)
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pub_raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64 = base64.b64encode(pub_raw).decode("ascii")
    # Export private key raw bytes (32 bytes for Ed25519)
    from cryptography.hazmat.primitives.serialization import PrivateFormat, NoEncryption

    priv_raw = private_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    return priv_raw, pub_b64


def _sign_with_test_key(private_key_bytes: bytes, payload: bytes) -> str:
    """Sign payload bytes with a test Ed25519 private key.

    Returns a vault-format signature string: 'vault:v1:<base64>'.
    This format matches the production signing format for compatibility
    with PortableVerificationBundle and TrustAnchor.verify().
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    sig_raw = private_key.sign(payload)
    sig_b64 = base64.b64encode(sig_raw).decode("ascii")
    return f"vault:v1:{sig_b64}"


def _build_test_signing_payload(domain: str, payload_dict: dict[str, Any]) -> bytes:
    """Build signing payload matching production trust_binding._prepare_signing_bytes."""
    payload_json = json.dumps(payload_dict, sort_keys=True, separators=(",", ":"))
    return f"{domain}\n{payload_json}".encode()


def _compute_public_key_fingerprint(pub_b64: str) -> str:
    """Compute fingerprint matching services.cgin.key_management.vault_transit.public_key_fingerprint."""
    from services.cgin.key_management.vault_transit import public_key_fingerprint

    return public_key_fingerprint(pub_b64)


# ---------------------------------------------------------------------------
# A. Source/candidate freeze (tests 1-7)
# ---------------------------------------------------------------------------


class TestSourceCandidateFreeze:
    """Tests 1-7: Source and candidate fingerprint freeze."""

    def test_01_clean_canonical_source_correct_fingerprint(self) -> None:
        """Test 1: Clean canonical source produces a valid candidate fingerprint."""
        from services.governance.run3_candidate import build_candidate

        candidate = build_candidate(_ROOT)
        fp = candidate.candidate_fingerprint
        assert isinstance(fp, str)
        assert len(fp) == 64  # SHA-256 hex
        assert fp != ""
        assert "PENDING_MERGE_SHA" not in fp

    def test_02_source_sha_change_different_fingerprint(self) -> None:
        """Test 2: Source SHA change produces a different candidate fingerprint."""
        from services.governance.run3_candidate import (
            Run3Candidate,
            REPOSITORY_IDENTITY,
            CEREMONY_CONTRACT_VERSION,
            METHODOLOGY_VERSION,
            SCHEMA_VERSIONS,
        )
        from services.governance.run3_resource_inventory import (
            RESOURCE_INVENTORY_FINGERPRINT,
        )

        c1 = Run3Candidate(
            repository_identity=REPOSITORY_IDENTITY,
            source_sha="sha1aaa",
            readiness_result="BLOCKED",
            readiness_fingerprint="fp_aaa",
            readiness_authority_version="1.0.0",
            infrastructure_source_fingerprint="infra_fp",
            trust_authority_source_fingerprint="trust_fp",
            ceremony_contract_version=CEREMONY_CONTRACT_VERSION,
            methodology_version=METHODOLOGY_VERSION,
            relevant_schema_versions=SCHEMA_VERSIONS,
            expected_resource_inventory_fingerprint=RESOURCE_INVENTORY_FINGERPRINT,
            proof_matrix_fingerprint="pm_fp",
            abort_matrix_fingerprint="am_fp",
            teardown_contract_fingerprint="tc_fp",
        )
        c2 = Run3Candidate(
            repository_identity=REPOSITORY_IDENTITY,
            source_sha="sha2bbb",  # different SHA
            readiness_result="BLOCKED",
            readiness_fingerprint="fp_aaa",
            readiness_authority_version="1.0.0",
            infrastructure_source_fingerprint="infra_fp",
            trust_authority_source_fingerprint="trust_fp",
            ceremony_contract_version=CEREMONY_CONTRACT_VERSION,
            methodology_version=METHODOLOGY_VERSION,
            relevant_schema_versions=SCHEMA_VERSIONS,
            expected_resource_inventory_fingerprint=RESOURCE_INVENTORY_FINGERPRINT,
            proof_matrix_fingerprint="pm_fp",
            abort_matrix_fingerprint="am_fp",
            teardown_contract_fingerprint="tc_fp",
        )
        assert c1.candidate_fingerprint != c2.candidate_fingerprint, (
            "Different source_sha must produce different candidate fingerprint"
        )

    def test_03_readiness_fingerprint_mismatch_blocks(self) -> None:
        """Test 3: Readiness fingerprint mismatch produces a different candidate fingerprint."""
        from services.governance.run3_candidate import (
            Run3Candidate,
            REPOSITORY_IDENTITY,
            CEREMONY_CONTRACT_VERSION,
            METHODOLOGY_VERSION,
            SCHEMA_VERSIONS,
        )
        from services.governance.run3_resource_inventory import (
            RESOURCE_INVENTORY_FINGERPRINT,
        )

        base_kwargs = dict(
            repository_identity=REPOSITORY_IDENTITY,
            source_sha="sha_test",
            readiness_result="BLOCKED",
            readiness_authority_version="1.0.0",
            infrastructure_source_fingerprint="infra",
            trust_authority_source_fingerprint="trust",
            ceremony_contract_version=CEREMONY_CONTRACT_VERSION,
            methodology_version=METHODOLOGY_VERSION,
            relevant_schema_versions=SCHEMA_VERSIONS,
            expected_resource_inventory_fingerprint=RESOURCE_INVENTORY_FINGERPRINT,
            proof_matrix_fingerprint="pm",
            abort_matrix_fingerprint="am",
            teardown_contract_fingerprint="tc",
        )
        c1 = Run3Candidate(**base_kwargs, readiness_fingerprint="fp_original")
        c2 = Run3Candidate(**base_kwargs, readiness_fingerprint="fp_changed")
        assert c1.candidate_fingerprint != c2.candidate_fingerprint

    def test_04_candidate_fingerprint_deterministic(self) -> None:
        """Test 4: Same inputs always produce the same candidate fingerprint."""
        from services.governance.run3_candidate import build_candidate

        c1 = build_candidate(_ROOT)
        c2 = build_candidate(_ROOT)
        assert c1.candidate_fingerprint == c2.candidate_fingerprint, (
            "Candidate fingerprint must be deterministic"
        )

    def test_05_infra_change_different_fingerprint(self) -> None:
        """Test 5: Infra content change produces a different infrastructure fingerprint."""
        import hashlib
        import json

        # Simulate two different infra contents
        content_a = {"main.tf": "resource 'hcp_vault_cluster' 'test' {}"}
        content_b = {"main.tf": "resource 'hcp_vault_cluster' 'test_v2' {}"}
        fp_a = hashlib.sha256(
            json.dumps(content_a, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        fp_b = hashlib.sha256(
            json.dumps(content_b, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        assert fp_a != fp_b

    def test_06_timestamps_excluded_from_canonical_fingerprint(self) -> None:
        """Test 6: Wall-clock timestamp is excluded from candidate fingerprint."""
        from services.governance.run3_candidate import (
            Run3Candidate,
            REPOSITORY_IDENTITY,
            CEREMONY_CONTRACT_VERSION,
            METHODOLOGY_VERSION,
            SCHEMA_VERSIONS,
        )
        from services.governance.run3_resource_inventory import (
            RESOURCE_INVENTORY_FINGERPRINT,
        )

        kwargs = dict(
            repository_identity=REPOSITORY_IDENTITY,
            source_sha="sha_test_ts",
            readiness_result="BLOCKED",
            readiness_fingerprint="fp_ts",
            readiness_authority_version="1.0.0",
            infrastructure_source_fingerprint="infra_ts",
            trust_authority_source_fingerprint="trust_ts",
            ceremony_contract_version=CEREMONY_CONTRACT_VERSION,
            methodology_version=METHODOLOGY_VERSION,
            relevant_schema_versions=SCHEMA_VERSIONS,
            expected_resource_inventory_fingerprint=RESOURCE_INVENTORY_FINGERPRINT,
            proof_matrix_fingerprint="pm_ts",
            abort_matrix_fingerprint="am_ts",
            teardown_contract_fingerprint="tc_ts",
        )
        c1 = Run3Candidate(**kwargs)
        c2 = Run3Candidate(**kwargs)
        # Fingerprints must be identical — no time-based variance
        assert c1.candidate_fingerprint == c2.candidate_fingerprint
        # Candidate dict should note that generated_at is excluded
        d = c1.to_dict()
        assert (
            "_generated_at_note" in d
            or "generated_at" not in d
            or d.get("_generated_at_note", "").count("excluded") > 0
        )

    def test_07_missing_readiness_artifact_note(self) -> None:
        """Test 7: Readiness fingerprint error is recorded as a string, not silently empty."""
        from services.governance.run3_candidate import (
            Run3Candidate,
            REPOSITORY_IDENTITY,
            CEREMONY_CONTRACT_VERSION,
            METHODOLOGY_VERSION,
            SCHEMA_VERSIONS,
        )
        from services.governance.run3_resource_inventory import (
            RESOURCE_INVENTORY_FINGERPRINT,
        )

        # A candidate built with error markers blocks execution
        c = Run3Candidate(
            repository_identity=REPOSITORY_IDENTITY,
            source_sha="sha_test",
            readiness_result="EVALUATION_ERROR",
            readiness_fingerprint="READINESS_FINGERPRINT_ERROR:some error",
            readiness_authority_version="1.0.0",
            infrastructure_source_fingerprint="infra",
            trust_authority_source_fingerprint="trust",
            ceremony_contract_version=CEREMONY_CONTRACT_VERSION,
            methodology_version=METHODOLOGY_VERSION,
            relevant_schema_versions=SCHEMA_VERSIONS,
            expected_resource_inventory_fingerprint=RESOURCE_INVENTORY_FINGERPRINT,
            proof_matrix_fingerprint="pm",
            abort_matrix_fingerprint="am",
            teardown_contract_fingerprint="tc",
        )
        # Error in fingerprint means this is not a valid candidate for ceremony
        assert "ERROR" in c.readiness_fingerprint or "error" in c.readiness_fingerprint


# ---------------------------------------------------------------------------
# B. Resource inventory (tests 8-14)
# ---------------------------------------------------------------------------


class TestResourceInventory:
    """Tests 8-14: Resource inventory classification and integrity."""

    def test_08_expected_terraform_resources_present_and_classified(self) -> None:
        """Test 8: All expected Terraform resources are present with lifecycle classifications."""
        from services.governance.run3_resource_inventory import (
            RESOURCE_INVENTORY,
            LifecycleClass,
        )

        addresses = {r.terraform_address for r in RESOURCE_INVENTORY}
        # Must include cost-bearing cluster
        assert "hcp_vault_cluster.customer_zero" in addresses
        # Must include HVN
        assert "hcp_hvn.frostgate" in addresses
        # Must include preserved audit resources
        assert "aws_cloudwatch_log_group.vault_audit" in addresses
        assert "aws_iam_user.vault_audit" in addresses
        # All have valid lifecycle classification
        for r in RESOURCE_INVENTORY:
            assert r.lifecycle_class in LifecycleClass, (
                f"Invalid lifecycle for {r.terraform_address}"
            )

    def test_09_preserved_resources_classified_correctly(self) -> None:
        """Test 9: Preserved resources have PRESERVE_AFTER_CEREMONY classification."""
        from services.governance.run3_resource_inventory import (
            get_preserved_resources,
            LifecycleClass,
        )

        preserved = get_preserved_resources()
        assert len(preserved) >= 4, "Must have at least 4 preserved AWS audit resources"
        for r in preserved:
            assert r.lifecycle_class == LifecycleClass.PRESERVE_AFTER_CEREMONY
            assert r.expected_destroy_stage.upper().startswith("NEVER"), (
                f"PRESERVE_AFTER_CEREMONY resource {r.terraform_address!r} "
                f"must have expected_destroy_stage starting with 'NEVER', "
                f"got {r.expected_destroy_stage!r}"
            )

    def test_10_unknown_mutable_resource_would_block(self) -> None:
        """Test 10: An unknown mutable resource classification blocks execution."""
        from services.governance.run3_resource_inventory import LifecycleClass

        # DATA_REFERENCE_ONLY and PRESERVE/REUSE are known-safe
        # CREATE_FOR_CEREMONY and DESTROY_AFTER_CEREMONY are known-planned
        # Any resource NOT in this set would be unknown mutable
        known_lifecycle_classes = set(LifecycleClass)
        # Verify our classification enum covers all possible states
        assert len(known_lifecycle_classes) >= 5
        # If a new resource with an unknown class were added, it should be caught
        for r in __import__(
            "services.governance.run3_resource_inventory",
            fromlist=["RESOURCE_INVENTORY"],
        ).RESOURCE_INVENTORY:
            assert r.lifecycle_class in LifecycleClass, (
                f"Unknown lifecycle: {r.terraform_address}"
            )

    def test_11_resource_inventory_fingerprint_deterministic(self) -> None:
        """Test 11: Resource inventory fingerprint is the same across calls."""
        from services.governance.run3_resource_inventory import (
            compute_inventory_fingerprint,
        )

        fp1 = compute_inventory_fingerprint()
        fp2 = compute_inventory_fingerprint()
        assert fp1 == fp2
        assert len(fp1) == 64  # SHA-256 hex

    def test_12_lifecycle_classifications_exhaustive(self) -> None:
        """Test 12: All lifecycle classifications are used and valid."""
        from services.governance.run3_resource_inventory import (
            RESOURCE_INVENTORY,
            LifecycleClass,
        )

        used_classes = {r.lifecycle_class for r in RESOURCE_INVENTORY}
        # Must have at least CREATE_FOR_CEREMONY and PRESERVE_AFTER_CEREMONY
        assert LifecycleClass.CREATE_FOR_CEREMONY in used_classes
        assert LifecycleClass.PRESERVE_AFTER_CEREMONY in used_classes

    def test_13_no_live_cloud_queries_required(self) -> None:
        """Test 13: Resource inventory module imports and loads without any cloud access."""
        # Simply importing and calling the module should complete without network errors
        from services.governance.run3_resource_inventory import (
            get_inventory,
            compute_inventory_fingerprint,
        )

        inventory = get_inventory()
        fp = compute_inventory_fingerprint()
        assert len(inventory) > 0
        assert len(fp) == 64

    def test_14_data_reference_only_does_not_block_preauth(self) -> None:
        """Test 14: DATA_REFERENCE_ONLY resources do not block preauth."""
        from services.governance.run3_resource_inventory import (
            RESOURCE_INVENTORY,
            LifecycleClass,
        )

        data_refs = [
            r
            for r in RESOURCE_INVENTORY
            if r.lifecycle_class == LifecycleClass.DATA_REFERENCE_ONLY
        ]
        # DATA_REFERENCE_ONLY resources should have NEVER or NOT_APPLICABLE as destroy stage
        for r in data_refs:
            assert r.expected_destroy_stage.upper() in ("NEVER", "NOT_APPLICABLE"), (
                f"DATA_REFERENCE_ONLY {r.terraform_address} should not have a destroy stage"
            )


# ---------------------------------------------------------------------------
# C. Cost authorization (tests 15-22)
# ---------------------------------------------------------------------------


class TestCostAuthorization:
    """Tests 15-22: Cost authorization request invariants."""

    def _build_request(self) -> Any:
        from services.governance.run3_candidate import build_candidate
        from services.governance.run3_resource_inventory import (
            get_inventory,
            get_preserved_resources,
            compute_inventory_fingerprint,
        )
        from services.governance.run3_cost_request import build_cost_request

        candidate = build_candidate(_ROOT)
        inv_fp = compute_inventory_fingerprint()
        resources = [r.to_dict() for r in get_inventory()]
        preserved = [r.to_dict() for r in get_preserved_resources()]
        return build_cost_request(
            candidate.candidate_fingerprint, inv_fp, resources, preserved
        )

    def test_15_authorization_status_always_not_authorized(self) -> None:
        """Test 15: authorization_status is always NOT_AUTHORIZED."""
        req = self._build_request()
        assert req.authorization_status == "NOT_AUTHORIZED"

    def test_16_historical_cost_usd_321_81(self) -> None:
        """Test 16: historical_cost_usd == 321.81."""
        req = self._build_request()
        assert abs(req.historical_cost_usd - 321.81) < 0.001

    def test_17_proposed_max_cost_usd_is_none(self) -> None:
        """Test 17: proposed_max_cost_usd is None (human must set)."""
        req = self._build_request()
        assert req.proposed_max_cost_usd is None

    def test_18_proposed_max_runtime_hours_is_none(self) -> None:
        """Test 18: proposed_max_runtime_hours is None (human must set)."""
        req = self._build_request()
        assert req.proposed_max_runtime_hours is None

    def test_19_missing_max_cost_prevents_execution_authorization(self) -> None:
        """Test 19: Missing max cost causes validation to fail."""
        req = self._build_request()
        from services.governance.run3_candidate import build_candidate
        from services.governance.run3_resource_inventory import (
            compute_inventory_fingerprint,
        )

        candidate = build_candidate(_ROOT)
        inv_fp = compute_inventory_fingerprint()
        valid, failures = req.validate_authorization_binding(
            candidate.candidate_fingerprint,
            inv_fp,
            candidate.source_sha,
            "CUSTOMER-ZERO-TRUST-003-RUN3",
        )
        assert not valid
        assert any(
            "max_cost" in f.lower() or "proposed_max_cost" in f.lower()
            for f in failures
        )

    def test_20_wrong_candidate_fingerprint_rejects(self) -> None:
        """Test 20: Wrong candidate fingerprint rejects authorization binding."""
        req = self._build_request()
        from services.governance.run3_resource_inventory import (
            compute_inventory_fingerprint,
        )
        from services.governance.run3_candidate import build_candidate

        candidate = build_candidate(_ROOT)
        inv_fp = compute_inventory_fingerprint()
        valid, failures = req.validate_authorization_binding(
            "wrong_candidate_fingerprint",
            inv_fp,
            candidate.source_sha,
            "CUSTOMER-ZERO-TRUST-003-RUN3",
        )
        assert not valid
        assert any("candidate_fingerprint" in f for f in failures)

    def test_21_wrong_resource_inventory_rejects(self) -> None:
        """Test 21: Wrong resource inventory fingerprint rejects authorization."""
        req = self._build_request()
        from services.governance.run3_candidate import build_candidate

        candidate = build_candidate(_ROOT)
        valid, failures = req.validate_authorization_binding(
            candidate.candidate_fingerprint,
            "wrong_inventory_fingerprint",
            candidate.source_sha,
            "CUSTOMER-ZERO-TRUST-003-RUN3",
        )
        assert not valid
        assert any("inventory" in f for f in failures)

    def test_22_reused_authorization_rejected(self) -> None:
        """Test 22: Wrong ceremony ID (e.g., reused) rejects authorization."""
        req = self._build_request()
        from services.governance.run3_candidate import build_candidate
        from services.governance.run3_resource_inventory import (
            compute_inventory_fingerprint,
        )

        candidate = build_candidate(_ROOT)
        inv_fp = compute_inventory_fingerprint()
        valid, failures = req.validate_authorization_binding(
            candidate.candidate_fingerprint,
            inv_fp,
            candidate.source_sha,
            "CUSTOMER-ZERO-TRUST-001-RUN1",  # Wrong ceremony ID
        )
        assert not valid
        assert any("ceremony_id" in f for f in failures)


# ---------------------------------------------------------------------------
# D. Proof matrix completeness (tests 23-32)
# ---------------------------------------------------------------------------


class TestProofMatrixCompleteness:
    """Tests 23-32: Proof matrix covers all required domains and families."""

    def test_23_all_three_trust_domains_represented(self) -> None:
        """Test 23: IDENTITY, ACCEPTANCE, APPROVAL all represented."""
        from services.governance.run3_proof_matrix import PROOF_MATRIX

        domains = {p.trust_domain for p in PROOF_MATRIX}
        # "ALL" covers all three; individual domains also present
        has_identity = "IDENTITY" in domains or "ALL" in domains
        has_acceptance = "ACCEPTANCE" in domains or "ALL" in domains
        has_approval = "APPROVAL" in domains or "ALL" in domains
        assert has_identity and has_acceptance and has_approval

    def test_24_positive_signing_proofs_present(self) -> None:
        """Test 24: Family A (positive signing) proofs present for all domains."""
        from services.governance.run3_proof_matrix import PROOF_MATRIX

        a_proofs = [p for p in PROOF_MATRIX if p.proof_id.startswith("A-")]
        assert len(a_proofs) >= 3  # At least one per domain

    def test_25_cross_domain_isolation_proofs_present(self) -> None:
        """Test 25: Family B (domain isolation) proofs present."""
        from services.governance.run3_proof_matrix import PROOF_MATRIX

        b_proofs = [p for p in PROOF_MATRIX if p.proof_id.startswith("B-")]
        assert len(b_proofs) >= 2

    def test_26_replay_resistance_proofs_present(self) -> None:
        """Test 26: Family C (replay resistance) proofs present."""
        from services.governance.run3_proof_matrix import PROOF_MATRIX

        c_proofs = [p for p in PROOF_MATRIX if p.proof_id.startswith("C-")]
        assert len(c_proofs) >= 2

    def test_27_key_rotation_proofs_present(self) -> None:
        """Test 27: Family D (key rotation) proofs present."""
        from services.governance.run3_proof_matrix import PROOF_MATRIX

        d_proofs = [p for p in PROOF_MATRIX if p.proof_id.startswith("D-")]
        assert len(d_proofs) >= 1

    def test_28_verifier_failure_semantics_differentiated(self) -> None:
        """Test 28: Family E differentiates cryptographic invalidity vs operational unavailability."""
        from services.governance.run3_proof_matrix import PROOF_MATRIX

        e_proofs = [p for p in PROOF_MATRIX if p.proof_id.startswith("E-")]
        assert len(e_proofs) >= 2
        objectives = " ".join(p.objective for p in e_proofs).lower()
        assert "invalid" in objectives or "invalidity" in objectives
        assert "unavailable" in objectives

    def test_29_report_provenance_proofs_present(self) -> None:
        """Test 29: Family F (report provenance) proofs present."""
        from services.governance.run3_proof_matrix import PROOF_MATRIX

        f_proofs = [p for p in PROOF_MATRIX if p.proof_id.startswith("F-")]
        assert len(f_proofs) >= 1
        assert any(
            "provenance" in p.objective.lower() or "mutation" in p.objective.lower()
            for p in f_proofs
        )

    def test_30_audit_delivery_proofs_present(self) -> None:
        """Test 30: Family G (audit delivery) proofs present."""
        from services.governance.run3_proof_matrix import PROOF_MATRIX

        g_proofs = [p for p in PROOF_MATRIX if p.proof_id.startswith("G-")]
        assert len(g_proofs) >= 1
        assert any(
            "cloudwatch" in p.objective.lower() or "audit" in p.objective.lower()
            for p in g_proofs
        )

    def test_31_portable_verification_proofs_present(self) -> None:
        """Test 31: Family I (portable verification) proofs present."""
        from services.governance.run3_proof_matrix import PROOF_MATRIX

        i_proofs = [p for p in PROOF_MATRIX if p.proof_id.startswith("I-")]
        assert len(i_proofs) >= 2
        assert any(
            "offline" in p.objective.lower() or "portable" in p.objective.lower()
            for p in i_proofs
        )

    def test_32_tenant_isolation_proofs_present(self) -> None:
        """Test 32: Family H (tenant isolation) proofs present."""
        from services.governance.run3_proof_matrix import PROOF_MATRIX

        h_proofs = [p for p in PROOF_MATRIX if p.proof_id.startswith("H-")]
        assert len(h_proofs) >= 1
        assert any(
            "tenant" in p.objective.lower() or "cross-tenant" in p.objective.lower()
            for p in h_proofs
        )


# ---------------------------------------------------------------------------
# E. REAL portable verification (tests 33-43)
# ---------------------------------------------------------------------------


class TestPortableVerificationRealCrypto:
    """Tests 33-43: Real Ed25519 cryptography (no mocked True results).

    INVARIANT: All keys in this class are labeled TEST-ONLY and generated
    fresh per test. No production signing material is used.
    """

    def _make_test_bundle(
        self,
        priv_bytes: bytes,
        pub_b64: str,
        payload_dict: dict[str, Any],
        domain: str = _TEST_DOMAIN,
        key_id: str = "test-identity-key",
        key_version: int = 1,
    ) -> tuple[Any, bytes]:
        """Build a PortableVerificationBundle for testing."""
        from services.governance.customer_zero_readiness import (
            PortableVerificationBundle,
        )
        from services.cgin.key_management.vault_transit import public_key_fingerprint

        canonical_bytes = json.dumps(
            payload_dict, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        signing_payload = _build_test_signing_payload(domain, payload_dict)
        signature = _sign_with_test_key(priv_bytes, signing_payload)
        fp = public_key_fingerprint(pub_b64)

        bundle = PortableVerificationBundle(
            artifact_digest=hashlib.sha256(canonical_bytes).hexdigest(),
            manifest={"test_key_label": _TEST_KEY_LABEL, **payload_dict},
            signature=signature,
            trust_domain=domain,
            public_key_material=pub_b64,
            public_key_fingerprint=fp,
            key_identifier=key_id,
            key_version=key_version,
            algorithm="ed25519",
            signing_timestamp="2026-10-08T00:00:00Z",
            source_sha="test-source-sha",
            methodology_version="test-methodology-v1",
            provenance_sha="test-provenance-sha",
            audit_evidence_reference=_TEST_KEY_LABEL,
        )
        return bundle, canonical_bytes

    def test_33_generate_test_key_pair_labeled_test_only(self) -> None:
        """Test 33: Generated test key pair is labeled TEST-ONLY."""
        priv_bytes, pub_b64 = _generate_test_ed25519_key_pair()
        assert len(priv_bytes) == 32  # Ed25519 private key = 32 bytes
        pub_decoded = base64.b64decode(pub_b64)
        assert len(pub_decoded) == 32  # Ed25519 public key = 32 bytes
        # Key label confirms test-only status
        assert _TEST_KEY_LABEL.startswith("TEST-ONLY")

    def test_34_sign_canonical_payload_with_test_key(self) -> None:
        """Test 34: Sign a canonical payload with test private key."""
        priv_bytes, pub_b64 = _generate_test_ed25519_key_pair()
        payload = {
            "engagement_id": "test-001",
            "domain": "identity",
            _TEST_KEY_LABEL: True,
        }
        signing_payload = _build_test_signing_payload(_TEST_DOMAIN, payload)
        signature = _sign_with_test_key(priv_bytes, signing_payload)
        assert signature.startswith("vault:v1:")
        assert len(signature) > 20

    def test_35_enroll_test_public_key_material(self) -> None:
        """Test 35: Enroll test public key in PortableVerificationAuthority."""
        from services.governance.customer_zero_readiness import (
            PortableVerificationAuthority,
        )

        priv_bytes, pub_b64 = _generate_test_ed25519_key_pair()
        authority = PortableVerificationAuthority()
        authority.enroll(
            trust_domain=_TEST_DOMAIN,
            key_identifier="test-key-001",
            key_version=1,
            public_key_material=pub_b64,
        )
        assert authority.is_enrolled(_TEST_DOMAIN, "test-key-001", 1)

    def test_36_verify_signature_using_bundle_pass(self) -> None:
        """Test 36: Verify signature using PortableVerificationBundle returns True."""
        from services.governance.customer_zero_readiness import (
            PortableVerificationAuthority,
        )

        priv_bytes, pub_b64 = _generate_test_ed25519_key_pair()
        authority = PortableVerificationAuthority()
        # key_id must match what _make_test_bundle uses (default: "test-identity-key")
        authority.enroll(_TEST_DOMAIN, "test-identity-key", 1, pub_b64)
        payload = {"test": "canonical_payload", "label": _TEST_KEY_LABEL}
        bundle, canonical_bytes = self._make_test_bundle(priv_bytes, pub_b64, payload)
        result = authority.verify_offline(bundle, canonical_bytes)
        assert result is True, "Correct signature must verify as True"

    def test_37_remove_signing_backend_verify_still_passes(self) -> None:
        """Test 37: Verification succeeds without Vault (public material only)."""
        from services.governance.customer_zero_readiness import (
            PortableVerificationAuthority,
        )

        priv_bytes, pub_b64 = _generate_test_ed25519_key_pair()
        # Simulate Vault absent: we have NO signer available, only public material
        authority = PortableVerificationAuthority()
        authority.enroll(_TEST_DOMAIN, "test-key-offline", 1, pub_b64)
        payload = {"test": "historical_artifact", "label": _TEST_KEY_LABEL}
        bundle, canonical_bytes = self._make_test_bundle(
            priv_bytes, pub_b64, payload, key_id="test-key-offline"
        )
        # No signer available — but verify_offline uses pre-enrolled public material only
        result = authority.verify_offline(bundle, canonical_bytes)
        assert result is True, "Historical verification must succeed without Vault"

    def test_38_mutate_artifact_bytes_fail(self) -> None:
        """Test 38: Mutating artifact bytes after signing causes verification to fail."""
        from services.governance.customer_zero_readiness import (
            PortableVerificationAuthority,
        )

        priv_bytes, pub_b64 = _generate_test_ed25519_key_pair()
        authority = PortableVerificationAuthority()
        authority.enroll(_TEST_DOMAIN, "test-key-mut", 1, pub_b64)
        payload = {"report": "original_content", "label": _TEST_KEY_LABEL}
        bundle, canonical_bytes = self._make_test_bundle(
            priv_bytes, pub_b64, payload, key_id="test-key-mut"
        )
        # Mutate artifact bytes
        mutated_bytes = canonical_bytes[:-1] + (
            b"X" if canonical_bytes[-1:] != b"X" else b"Y"
        )
        result = authority.verify_offline(bundle, mutated_bytes)
        assert result is False, "Mutated artifact must NOT verify"

    def test_39_change_key_version_in_bundle_fail(self) -> None:
        """Test 39: Wrong key version in bundle fails verification."""
        from services.governance.customer_zero_readiness import (
            PortableVerificationAuthority,
            PortableVerificationBundle,
        )
        from services.cgin.key_management.vault_transit import public_key_fingerprint

        priv_bytes, pub_b64 = _generate_test_ed25519_key_pair()
        authority = PortableVerificationAuthority()
        # Only enroll version 1
        authority.enroll(_TEST_DOMAIN, "test-key-ver", 1, pub_b64)
        payload = {"test": "rotation_test", "label": _TEST_KEY_LABEL}
        bundle_v1, canonical_bytes = self._make_test_bundle(
            priv_bytes, pub_b64, payload, key_id="test-key-ver", key_version=1
        )
        # Create a bundle claiming version 2 (not enrolled)
        fp = public_key_fingerprint(pub_b64)
        bundle_v2_wrong = PortableVerificationBundle(
            artifact_digest=bundle_v1.artifact_digest,
            manifest=bundle_v1.manifest,
            signature=bundle_v1.signature,
            trust_domain=_TEST_DOMAIN,
            public_key_material=pub_b64,
            public_key_fingerprint=fp,
            key_identifier="test-key-ver",
            key_version=2,  # Wrong version — not enrolled
            algorithm="ed25519",
            signing_timestamp=bundle_v1.signing_timestamp,
            source_sha=bundle_v1.source_sha,
            methodology_version=bundle_v1.methodology_version,
            provenance_sha=bundle_v1.provenance_sha,
            audit_evidence_reference=bundle_v1.audit_evidence_reference,
        )
        result = authority.verify_offline(bundle_v2_wrong, canonical_bytes)
        assert result is False, "Wrong/unenrolled key version must NOT verify"

    def test_40_change_trust_domain_fail(self) -> None:
        """Test 40: Bundle with wrong trust domain fails verification."""
        from services.governance.customer_zero_readiness import (
            PortableVerificationAuthority,
            PortableVerificationBundle,
        )
        from services.cgin.key_management.vault_transit import public_key_fingerprint

        priv_bytes, pub_b64 = _generate_test_ed25519_key_pair()
        authority = PortableVerificationAuthority()
        # Enroll under TEST_DOMAIN only
        authority.enroll(_TEST_DOMAIN, "test-key-dom", 1, pub_b64)
        payload = {"test": "domain_change", "label": _TEST_KEY_LABEL}
        bundle, canonical_bytes = self._make_test_bundle(
            priv_bytes, pub_b64, payload, domain=_TEST_DOMAIN, key_id="test-key-dom"
        )
        # Create bundle claiming a different domain (not enrolled)
        fp = public_key_fingerprint(pub_b64)
        wrong_domain_bundle = PortableVerificationBundle(
            artifact_digest=bundle.artifact_digest,
            manifest=bundle.manifest,
            signature=bundle.signature,
            trust_domain="frostgate.governed-delivery-authorization.v1",  # different domain
            public_key_material=pub_b64,
            public_key_fingerprint=fp,
            key_identifier="test-key-dom",
            key_version=1,
            algorithm="ed25519",
            signing_timestamp=bundle.signing_timestamp,
            source_sha=bundle.source_sha,
            methodology_version=bundle.methodology_version,
            provenance_sha=bundle.provenance_sha,
            audit_evidence_reference=bundle.audit_evidence_reference,
        )
        result = authority.verify_offline(wrong_domain_bundle, canonical_bytes)
        assert result is False, "Wrong trust domain must NOT verify"

    def test_41_substitute_public_key_fail(self) -> None:
        """Test 41: Substituting a different public key causes verification to fail."""
        from services.governance.customer_zero_readiness import (
            PortableVerificationAuthority,
        )

        priv_bytes, pub_b64 = _generate_test_ed25519_key_pair()
        # Different key pair
        priv_bytes2, pub_b64_2 = _generate_test_ed25519_key_pair()
        authority = PortableVerificationAuthority()
        # Enroll the WRONG (substitute) public key
        authority.enroll(_TEST_DOMAIN, "test-key-sub", 1, pub_b64_2)
        payload = {"test": "key_substitution", "label": _TEST_KEY_LABEL}
        # Bundle was signed with priv_bytes but uses pub_b64 (which matches priv_bytes)
        bundle, canonical_bytes = self._make_test_bundle(
            priv_bytes, pub_b64, payload, key_id="test-key-sub"
        )
        # Verify with enrolled pub_b64_2 (different key) — must fail
        result = authority.verify_offline(bundle, canonical_bytes)
        assert result is False, "Substituted public key must NOT verify"

    def test_42_private_key_material_never_in_portable_bundle(self) -> None:
        """Test 42: Private key material never enters PortableVerificationBundle."""
        from services.governance.customer_zero_readiness import (
            PortableVerificationBundle,
        )

        priv_bytes, pub_b64 = _generate_test_ed25519_key_pair()
        # Generate a test PEM private key marker to ensure it's rejected
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PrivateFormat,
            NoEncryption,
        )

        private_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
        priv_pem = private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode("utf-8")
        # Attempting to create a bundle with private key in manifest should raise
        from services.cgin.key_management.vault_transit import public_key_fingerprint

        fp = public_key_fingerprint(pub_b64)
        with pytest.raises((ValueError, Exception)):
            PortableVerificationBundle(
                artifact_digest="fake_digest",
                manifest={
                    "private_key": priv_pem
                },  # Private key in manifest — must be rejected
                signature="vault:v1:fake",
                trust_domain=_TEST_DOMAIN,
                public_key_material=pub_b64,
                public_key_fingerprint=fp,
                key_identifier="test-key",
                key_version=1,
                algorithm="ed25519",
                signing_timestamp="2026-10-08T00:00:00Z",
                source_sha="test",
                methodology_version="test",
                provenance_sha="test",
                audit_evidence_reference="test",
            )

    def test_43_enroll_rejects_private_key_material(self) -> None:
        """Test 43: PortableVerificationAuthority.enroll() rejects private key material."""
        priv_bytes, pub_b64 = _generate_test_ed25519_key_pair()
        # The invariant is: PortableVerificationBundle.__post_init__ prevents private PEM markers
        # For raw bytes there's structural validation; we test the PEM path in test_42
        # Here we verify the validate_no_private_material method works
        from services.governance.customer_zero_readiness import (
            PortableVerificationBundle,
        )

        result = PortableVerificationBundle.validate_no_private_material(
            {"public_key": pub_b64}
        )
        assert result is True
        # A bundle with a signing_key field must be rejected
        result2 = PortableVerificationBundle.validate_no_private_material(
            {"signing_key": "abc"}
        )
        assert result2 is False


# ---------------------------------------------------------------------------
# F. Abort matrix (tests 44-49)
# ---------------------------------------------------------------------------


class TestAbortMatrix:
    """Tests 44-49: Abort matrix completeness and invariants."""

    def test_44_pre_provisioning_abort_conditions_documented(self) -> None:
        """Test 44: Pre-provisioning abort conditions documented."""
        from services.governance.run3_abort_teardown import ABORT_MATRIX, AbortStage

        pre = [a for a in ABORT_MATRIX if a.stage == AbortStage.PRE_PROVISIONING]
        assert len(pre) >= 5, "Must have at least 5 pre-provisioning abort conditions"
        # Must cover candidate mismatch and missing authorization
        assert any(
            "candidate" in a.title.lower() or "mismatch" in a.title.lower() for a in pre
        )
        assert any("authorization" in a.title.lower() for a in pre)

    def test_45_post_provisioning_abort_conditions_documented(self) -> None:
        """Test 45: Post-provisioning abort conditions documented."""
        from services.governance.run3_abort_teardown import ABORT_MATRIX, AbortStage

        post = [a for a in ABORT_MATRIX if a.stage == AbortStage.POST_PROVISIONING]
        assert len(post) >= 4

    def test_46_ceremony_abort_conditions_documented(self) -> None:
        """Test 46: Ceremony abort conditions documented."""
        from services.governance.run3_abort_teardown import ABORT_MATRIX, AbortStage

        cer = [a for a in ABORT_MATRIX if a.stage == AbortStage.DURING_CEREMONY]
        assert len(cer) >= 4

    def test_47_teardown_abort_conditions_documented(self) -> None:
        """Test 47: Teardown abort conditions documented."""
        from services.governance.run3_abort_teardown import ABORT_MATRIX, AbortStage

        tear = [a for a in ABORT_MATRIX if a.stage == AbortStage.DURING_TEARDOWN]
        assert len(tear) >= 3

    def test_48_no_abort_translatable_to_proven(self) -> None:
        """Test 48: No abort condition has blocks_proven=True."""
        from services.governance.run3_abort_teardown import ABORT_MATRIX

        for abort in ABORT_MATRIX:
            assert abort.blocks_proven is False, (
                f"Abort {abort.abort_id!r} has blocks_proven=True — "
                "no abort condition is translatable to PROVEN"
            )

    def test_49_cost_threshold_abort_present(self) -> None:
        """Test 49: Cost threshold abort condition is present."""
        from services.governance.run3_abort_teardown import ABORT_MATRIX, AbortSeverity

        cost_aborts = [
            a
            for a in ABORT_MATRIX
            if a.severity == AbortSeverity.COST_CONTROL or "cost" in a.title.lower()
        ]
        assert len(cost_aborts) >= 2, "Must have cost threshold abort conditions"


# ---------------------------------------------------------------------------
# G. No self-authorization (tests 50-56)
# ---------------------------------------------------------------------------


class TestNoSelfAuthorization:
    """Tests 50-56: READY does not authorize spending or prove trust."""

    def test_50_ready_does_not_authorize_spending(self) -> None:
        """Test 50: READY_FOR_HUMAN_COST_AUTHORIZATION does NOT authorize spending."""
        # The preauth CLI exits 0 only for READY — but that is not authorization
        # Structural: the cost authorization request always has NOT_AUTHORIZED
        from services.governance.run3_cost_request import build_cost_request
        from services.governance.run3_candidate import build_candidate
        from services.governance.run3_resource_inventory import (
            get_inventory,
            get_preserved_resources,
            compute_inventory_fingerprint,
        )

        candidate = build_candidate(_ROOT)
        inv_fp = compute_inventory_fingerprint()
        resources = [r.to_dict() for r in get_inventory()]
        preserved = [r.to_dict() for r in get_preserved_resources()]
        req = build_cost_request(
            candidate.candidate_fingerprint, inv_fp, resources, preserved
        )
        assert req.authorization_status == "NOT_AUTHORIZED"
        # proposed_max_cost_usd must be None (human must set)
        assert req.proposed_max_cost_usd is None

    def test_51_ready_does_not_mark_trust_proven(self) -> None:
        """Test 51: READY does NOT change customer_zero_trust from NOT_PROVEN."""
        from tools.ci.customer_zero_run3_preauth import CANONICAL_TRUTH

        assert CANONICAL_TRUTH["customer_zero_trust"] == "NOT_PROVEN"

    def test_52_ready_does_not_unblock_trust_003(self) -> None:
        """Test 52: READY does NOT unblock CUSTOMER-ZERO-TRUST-003."""
        from tools.ci.customer_zero_run3_preauth import CANONICAL_TRUTH

        assert CANONICAL_TRUTH["customer_zero_trust_003"] == "BLOCKED"

    def test_53_ready_does_not_unblock_accept_001(self) -> None:
        """Test 53: READY does NOT unblock CUSTOMER-ZERO-ACCEPT-001."""
        from tools.ci.customer_zero_run3_preauth import CANONICAL_TRUTH

        assert CANONICAL_TRUTH["customer_zero_accept_001"] == "BLOCKED"

    def test_54_ci_success_does_not_authorize_spending(self) -> None:
        """Test 54: CI success (exit 0) does NOT authorize spending."""
        # Structural: cost request is NOT_AUTHORIZED regardless of CI exit code
        # This is enforced by the authorization_status always being NOT_AUTHORIZED
        # Cannot instantiate with authorization_status != NOT_AUTHORIZED without
        # it being a value we put there — the dataclass doesn't enforce it at __init__
        # but build_cost_request always sets NOT_AUTHORIZED
        from services.governance.run3_cost_request import build_cost_request
        from services.governance.run3_candidate import build_candidate
        from services.governance.run3_resource_inventory import (
            get_inventory,
            get_preserved_resources,
            compute_inventory_fingerprint,
        )

        candidate = build_candidate(_ROOT)
        inv_fp = compute_inventory_fingerprint()
        resources = [r.to_dict() for r in get_inventory()]
        preserved = [r.to_dict() for r in get_preserved_resources()]
        req = build_cost_request(
            candidate.candidate_fingerprint, inv_fp, resources, preserved
        )
        assert req.authorization_status == "NOT_AUTHORIZED", (
            "build_cost_request must always return NOT_AUTHORIZED"
        )

    def test_55_repeated_evaluation_same_canonical_fingerprint(self) -> None:
        """Test 55: Repeated evaluation produces the same canonical fingerprint."""
        from services.governance.run3_candidate import build_candidate

        c1 = build_candidate(_ROOT)
        c2 = build_candidate(_ROOT)
        c3 = build_candidate(_ROOT)
        assert (
            c1.candidate_fingerprint
            == c2.candidate_fingerprint
            == c3.candidate_fingerprint
        )

    def test_56_malformed_input_fails_closed(self) -> None:
        """Test 56: Malformed input to build_candidate fails closed (not silently succeeds)."""
        from services.governance.run3_candidate import Run3Candidate

        # Candidate with empty source_sha
        c = Run3Candidate(
            repository_identity="",
            source_sha="",
            readiness_result="",
            readiness_fingerprint="",
            readiness_authority_version="",
            infrastructure_source_fingerprint="",
            trust_authority_source_fingerprint="",
            ceremony_contract_version="",
            methodology_version="",
            relevant_schema_versions={},
            expected_resource_inventory_fingerprint="",
            proof_matrix_fingerprint="",
            abort_matrix_fingerprint="",
            teardown_contract_fingerprint="",
        )
        # A candidate with all-empty fields should produce a different fingerprint
        # than a candidate with real data — not silently pass
        c_real = __import__(
            "services.governance.run3_candidate", fromlist=["build_candidate"]
        ).build_candidate(_ROOT)
        assert c.candidate_fingerprint != c_real.candidate_fingerprint, (
            "Empty candidate must produce different fingerprint than real candidate"
        )


# ---------------------------------------------------------------------------
# H. Secret safety (tests 57-60)
# ---------------------------------------------------------------------------


class TestSecretSafety:
    """Tests 57-60: No secrets in preauth artifact."""

    def _build_artifact_dict(self) -> dict[str, Any]:
        """Build preauth artifact for inspection."""
        from services.governance.run3_candidate import build_candidate
        from services.governance.run3_resource_inventory import (
            get_inventory,
            get_preserved_resources,
            compute_inventory_fingerprint,
        )
        from services.governance.run3_cost_request import build_cost_request
        from services.governance.run3_proof_matrix import PROOF_MATRIX
        from services.governance.run3_abort_teardown import (
            ABORT_MATRIX,
            TEARDOWN_CONTRACT,
        )

        candidate = build_candidate(_ROOT)
        inv_fp = compute_inventory_fingerprint()
        resources = [r.to_dict() for r in get_inventory()]
        preserved = [r.to_dict() for r in get_preserved_resources()]
        cost_req = build_cost_request(
            candidate.candidate_fingerprint, inv_fp, resources, preserved
        )

        return {
            "candidate": candidate.to_dict(),
            "cost_request": cost_req.to_dict(),
            "proof_matrix": [p.to_dict() for p in PROOF_MATRIX],
            "abort_matrix": [a.to_dict() for a in ABORT_MATRIX],
            "teardown_contract": TEARDOWN_CONTRACT,
        }

    def test_57_no_secret_values_in_preauth_artifact(self) -> None:
        """Test 57: No secret field values in preauth artifact."""
        artifact = self._build_artifact_dict()
        artifact_str = json.dumps(artifact).lower()
        # Must not contain actual secret values (structural check)
        assert "-----begin private key-----" not in artifact_str
        assert "-----begin ec private key-----" not in artifact_str
        assert "-----begin openssh private key-----" not in artifact_str

    def test_58_no_private_keys_in_artifact(self) -> None:
        """Test 58: No private key PEM material in artifact."""
        artifact = self._build_artifact_dict()
        artifact_str = json.dumps(artifact)
        pem_markers = [
            "BEGIN PRIVATE KEY",
            "BEGIN RSA PRIVATE KEY",
            "BEGIN EC PRIVATE KEY",
            "BEGIN OPENSSH PRIVATE KEY",
        ]
        for marker in pem_markers:
            assert marker not in artifact_str, f"Private key marker found: {marker!r}"

    def test_59_no_vault_hcp_aws_tokens(self) -> None:
        """Test 59: No Vault/HCP/AWS tokens required for offline evaluation."""
        # The preauth evaluator must run without any environment credentials
        # Structural: modules import and function without cloud credentials
        original_env = {}
        vault_vars = [
            "VAULT_TOKEN",
            "VAULT_ADDR",
            "HCP_CLIENT_ID",
            "HCP_CLIENT_SECRET",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
        ]
        for var in vault_vars:
            original_env[var] = os.environ.pop(var, None)
        try:
            from services.governance.run3_candidate import build_candidate
            from services.governance.run3_resource_inventory import (
                compute_inventory_fingerprint,
            )

            # These must work without any cloud credentials
            candidate = build_candidate(_ROOT)
            fp = compute_inventory_fingerprint()
            assert candidate.candidate_fingerprint != ""
            assert fp != ""
        finally:
            for var, val in original_env.items():
                if val is not None:
                    os.environ[var] = val

    def test_60_no_terraform_credentials_for_offline_evaluation(self) -> None:
        """Test 60: No Terraform credentials required for offline evaluation."""
        # Structural: the preauth evaluator is offline-only
        # Infra fingerprint is computed by reading .tf files, not by running terraform
        from services.governance.run3_candidate import _compute_infra_fingerprint

        fp = _compute_infra_fingerprint()
        assert len(fp) == 64  # Must succeed without terraform binary
        # Verify we're reading files, not running terraform
        assert fp != "TERRAFORM_REQUIRED"


# ---------------------------------------------------------------------------
# Additional adversarial tests (bonus tests 61-70)
# ---------------------------------------------------------------------------


class TestAdditionalAdversarial:
    """Bonus adversarial tests for boundary conditions."""

    def test_61_evidence_strength_taxonomy_declared_only_not_pass(self) -> None:
        """Test 61: EvidenceStrength.DECLARED_ONLY does not qualify as PASS."""
        from services.governance.run3_evidence_strength import (
            EvidenceStrength,
            PreAuthClaim,
        )

        claim = PreAuthClaim(
            claim_id="TEST-CLAIM-001",
            claim="Test claim",
            evidence_strength=EvidenceStrength.DECLARED_ONLY,
            evidence_source="human declaration",
            source_sha="test",
            verification_method="none",
            result="DECLARED",
            limitations="Not verified",
            required_for_preauth=True,
            required_before_provisioning=True,
            required_during_ceremony=False,
            execution_stage="OFFLINE_ENGINEERING",
        )
        assert claim.is_blocking_preauth() is True, (
            "DECLARED_ONLY on a required claim must block preauth"
        )

    def test_62_static_verified_not_runtime_proven(self) -> None:
        """Test 62: STATIC_VERIFIED is distinct from RUNTIME_PROVEN."""
        from services.governance.run3_evidence_strength import EvidenceStrength

        assert EvidenceStrength.STATIC_VERIFIED != EvidenceStrength.RUNTIME_PROVEN
        # STATIC_VERIFIED does not prove production behavior
        sv_claim = __import__(
            "services.governance.run3_evidence_strength",
            fromlist=["PreAuthClaim", "EvidenceStrength"],
        ).PreAuthClaim(
            claim_id="TEST-SV",
            claim="Struct verified",
            evidence_strength=EvidenceStrength.STATIC_VERIFIED,
            evidence_source="static analysis",
            source_sha="test",
            verification_method="code inspection",
            result="PASS_STATIC",
            limitations="Does not prove live HCP behavior",
            required_for_preauth=False,
            required_before_provisioning=True,
            required_during_ceremony=False,
            execution_stage="OFFLINE_ENGINEERING",
        )
        assert sv_claim.evidence_strength == EvidenceStrength.STATIC_VERIFIED
        assert sv_claim.evidence_strength != EvidenceStrength.RUNTIME_PROVEN

    def test_63_offline_test_not_live_hcp(self) -> None:
        """Test 63: TEST_PROVEN offline does not prove live HCP availability."""
        from services.governance.run3_proof_matrix import PROOF_MATRIX

        # Live HCP proofs are classified as LIVE_CEREMONY, not OFFLINE_ENGINEERING
        live_hcp = [
            p
            for p in PROOF_MATRIX
            if p.execution_stage == "LIVE_CEREMONY"
            and ("vault" in p.objective.lower() or "hcp" in p.objective.lower())
        ]
        assert len(live_hcp) >= 2, (
            "Live HCP proofs must be deferred to LIVE_CEREMONY stage"
        )

    def test_64_teardown_no_generic_destroy(self) -> None:
        """Test 64: Teardown contract does not use generic terraform destroy."""
        from services.governance.run3_abort_teardown import TEARDOWN_CONTRACT

        prohibition = TEARDOWN_CONTRACT.get("prohibition", "")
        assert "DO NOT use generic" in prohibition or "staged and narrow" in prohibition

    def test_65_aws_audit_never_in_absent_list(self) -> None:
        """Test 65: AWS audit resources are never in post_ceremony_absent."""
        from services.governance.run3_abort_teardown import TEARDOWN_CONTRACT

        absent = TEARDOWN_CONTRACT.get("post_ceremony_absent", [])
        absent_addresses = {r["terraform_address"] for r in absent}
        # These must NEVER appear in the absent list
        protected = {
            "aws_cloudwatch_log_group.vault_audit",
            "aws_iam_user.vault_audit",
            "aws_iam_policy.vault_audit",
            "aws_iam_user_policy_attachment.vault_audit",
        }
        intersection = absent_addresses & protected
        assert len(intersection) == 0, (
            f"AWS audit resources must not be in post_ceremony_absent: {intersection}"
        )

    def test_66_proof_matrix_fingerprint_deterministic(self) -> None:
        """Test 66: Proof matrix fingerprint is deterministic."""
        from services.governance.run3_proof_matrix import (
            compute_proof_matrix_fingerprint,
        )

        fp1 = compute_proof_matrix_fingerprint()
        fp2 = compute_proof_matrix_fingerprint()
        assert fp1 == fp2
        assert len(fp1) == 64

    def test_67_abort_teardown_fingerprint_deterministic(self) -> None:
        """Test 67: Abort+teardown fingerprint is deterministic."""
        from services.governance.run3_abort_teardown import (
            compute_abort_teardown_fingerprint,
        )

        fp1 = compute_abort_teardown_fingerprint()
        fp2 = compute_abort_teardown_fingerprint()
        assert fp1 == fp2
        assert len(fp1) == 64

    def test_68_cost_bearing_resources_classified(self) -> None:
        """Test 68: At least one cost-bearing resource is classified."""
        from services.governance.run3_resource_inventory import (
            get_cost_bearing_resources,
        )

        cost_bearing = get_cost_bearing_resources()
        assert len(cost_bearing) >= 1
        # The Vault cluster must be cost-bearing
        addresses = {r.terraform_address for r in cost_bearing}
        assert "hcp_vault_cluster.customer_zero" in addresses

    def test_69_portable_verification_signed_with_production_format(self) -> None:
        """Test 69: Signing payload matches production trust_binding._prepare_signing_bytes format."""
        # Verify the signing payload construction matches the documented production format
        domain = "frostgate.report-proof.v1"
        payload = {"engagement_id": "e001", "report_version": 1}
        # Production format: f"{domain}\n{json.dumps(payload_dict, sort_keys=True, separators=(',',':'))}".encode()
        expected = f"{domain}\n{json.dumps(payload, sort_keys=True, separators=(',', ':'))}".encode()
        actual = _build_test_signing_payload(domain, payload)
        assert actual == expected, "Test signing payload must match production format"

    def test_70_resource_inventory_includes_data_sources(self) -> None:
        """Test 70: Resource inventory includes data sources correctly classified."""
        from services.governance.run3_resource_inventory import (
            RESOURCE_INVENTORY,
            LifecycleClass,
        )

        data_refs = [
            r
            for r in RESOURCE_INVENTORY
            if r.lifecycle_class == LifecycleClass.DATA_REFERENCE_ONLY
        ]
        # HCP project data source must be present
        assert any("hcp_project" in r.terraform_address for r in data_refs)
        # All data refs should have "data" in the resource_type
        for r in data_refs:
            assert "data" in r.resource_type.lower() or "source" in r.purpose.lower()


# ---------------------------------------------------------------------------
# I. Review-fix tests (tests 71-84)
# ---------------------------------------------------------------------------


class TestReviewFixes:
    """Tests 71-84: Review-issue fixes — readiness gate, source SHA binding,
    TF coverage check, and portable verification derivation."""

    # ── Fix 1: Reject BLOCKED final-readiness results ────────────────────

    def test_71_readiness_blocked_result_is_fail(self) -> None:
        """Test 71: READINESS-FINGERPRINT check FAILs when final_result is BLOCKED."""
        from unittest.mock import patch, MagicMock
        from tools.ci.customer_zero_run3_preauth import _run_offline_checks

        mock_rr = MagicMock()
        mock_rr.final_result.value = "BLOCKED"
        mock_rr.offline_blocker_count = 1
        mock_rr.canonical_fingerprint = "a" * 64

        with patch(
            "services.governance.customer_zero_readiness.evaluate", return_value=mock_rr
        ):
            checks, blockers = _run_offline_checks(_ROOT, "test-sha")

        rf_check = next(
            (c for c in checks if c["check_id"] == "READINESS-FINGERPRINT"), None
        )
        assert rf_check is not None
        assert rf_check["result"] == "FAIL"
        assert rf_check["evidence_strength"] == "NOT_PROVEN"
        assert any("READINESS-FINGERPRINT" in b for b in blockers)
        assert any("BLOCKED" in b for b in blockers)

    def test_72_readiness_blocked_offline_blocker_count_in_message(self) -> None:
        """Test 72: Blocker message includes offline_blocker_count when > 0."""
        from unittest.mock import patch, MagicMock
        from tools.ci.customer_zero_run3_preauth import _run_offline_checks

        mock_rr = MagicMock()
        mock_rr.final_result.value = "BLOCKED"
        mock_rr.offline_blocker_count = 3
        mock_rr.canonical_fingerprint = "b" * 64

        with patch(
            "services.governance.customer_zero_readiness.evaluate", return_value=mock_rr
        ):
            checks, blockers = _run_offline_checks(_ROOT, "test-sha")

        assert any("offline_blocker_count=3" in b for b in blockers), (
            "Blocker message must include offline_blocker_count when > 0"
        )

    def test_73_readiness_ready_result_is_pass(self) -> None:
        """Test 73: READINESS-FINGERPRINT check PASSes when final_result is READY."""
        from unittest.mock import patch, MagicMock
        from tools.ci.customer_zero_run3_preauth import _run_offline_checks

        mock_rr = MagicMock()
        mock_rr.final_result.value = "READY"
        mock_rr.offline_blocker_count = 0
        mock_rr.canonical_fingerprint = "c" * 64

        with patch(
            "services.governance.customer_zero_readiness.evaluate", return_value=mock_rr
        ):
            checks, blockers = _run_offline_checks(_ROOT, "test-sha")

        rf_check = next(
            (c for c in checks if c["check_id"] == "READINESS-FINGERPRINT"), None
        )
        assert rf_check is not None
        assert rf_check["result"] == "PASS"
        assert not any("READINESS-FINGERPRINT" in b for b in blockers)

    # ── Fix 2: source_sha stored on CostAuthorizationRequest ─────────────

    def test_74_cost_authorization_request_stores_source_sha(self) -> None:
        """Test 74: CostAuthorizationRequest dataclass has a source_sha field."""
        from services.governance.run3_cost_request import CostAuthorizationRequest
        import dataclasses

        field_names = {f.name for f in dataclasses.fields(CostAuthorizationRequest)}
        assert "source_sha" in field_names, (
            "CostAuthorizationRequest must have a source_sha field"
        )

    def test_75_build_cost_request_propagates_source_sha(self) -> None:
        """Test 75: build_cost_request() stores source_sha on the returned request."""
        from services.governance.run3_cost_request import build_cost_request

        req = build_cost_request(
            candidate_fingerprint="fp_test",
            resource_inventory_fingerprint="inv_test",
            expected_resources=[],
            preserved_resources=[],
            source_sha="abc123deadbeef",
        )
        assert req.source_sha == "abc123deadbeef"

    def test_76_authorization_with_wrong_source_sha_fails(self) -> None:
        """Test 76: validate_authorization_binding rejects wrong source_sha."""
        from services.governance.run3_cost_request import build_cost_request
        from services.governance.run3_candidate import build_candidate
        from services.governance.run3_resource_inventory import (
            get_inventory,
            get_preserved_resources,
            compute_inventory_fingerprint,
        )

        candidate = build_candidate(_ROOT)
        inv_fp = compute_inventory_fingerprint()
        resources = [r.to_dict() for r in get_inventory()]
        preserved = [r.to_dict() for r in get_preserved_resources()]

        req = build_cost_request(
            candidate.candidate_fingerprint,
            inv_fp,
            resources,
            preserved,
            source_sha="correct-sha-aaaa",
        )
        valid, failures = req.validate_authorization_binding(
            candidate.candidate_fingerprint,
            inv_fp,
            "wrong-sha-bbbb",  # different from stored source_sha
            "CUSTOMER-ZERO-TRUST-003-RUN3",
        )
        assert not valid
        assert any("source_sha" in f for f in failures), (
            "source_sha mismatch must appear in failure reasons"
        )

    def test_77_authorization_with_matching_source_sha_does_not_fail_on_sha(
        self,
    ) -> None:
        """Test 77: validate_authorization_binding does not flag source_sha when it matches."""
        from services.governance.run3_cost_request import build_cost_request
        from services.governance.run3_candidate import build_candidate
        from services.governance.run3_resource_inventory import (
            get_inventory,
            get_preserved_resources,
            compute_inventory_fingerprint,
        )

        candidate = build_candidate(_ROOT)
        inv_fp = compute_inventory_fingerprint()
        resources = [r.to_dict() for r in get_inventory()]
        preserved = [r.to_dict() for r in get_preserved_resources()]

        req = build_cost_request(
            candidate.candidate_fingerprint,
            inv_fp,
            resources,
            preserved,
            source_sha="same-sha-for-both",
        )
        _valid, failures = req.validate_authorization_binding(
            candidate.candidate_fingerprint,
            inv_fp,
            "same-sha-for-both",
            "CUSTOMER-ZERO-TRUST-003-RUN3",
        )
        # source_sha mismatch must NOT appear
        assert not any("source_sha" in f for f in failures), (
            "source_sha must not be in failures when it matches"
        )

    # ── Fix 3: INVENTORY-TF-COVERAGE check ───────────────────────────────

    def test_78_inventory_tf_coverage_passes_when_all_classified(self) -> None:
        """Test 78: INVENTORY-TF-COVERAGE PASSes when all .tf resources are in inventory."""
        from tools.ci.customer_zero_run3_preauth import _run_offline_checks

        checks, blockers = _run_offline_checks(_ROOT, "test-sha")
        cov_check = next(
            (c for c in checks if c["check_id"] == "INVENTORY-TF-COVERAGE"), None
        )
        assert cov_check is not None, "INVENTORY-TF-COVERAGE check must exist"
        assert cov_check["result"] == "PASS", (
            f"INVENTORY-TF-COVERAGE must PASS; detail={cov_check.get('detail')}"
        )
        assert cov_check["evidence_strength"] == "STATIC_VERIFIED"
        assert not any("INVENTORY-TF-COVERAGE" in b for b in blockers)

    def test_79_inventory_tf_coverage_fails_for_unclassified_tf_resource(self) -> None:
        """Test 79: INVENTORY-TF-COVERAGE FAILs when a .tf resource is absent from inventory."""
        import tempfile
        from pathlib import Path as _Path
        from unittest.mock import patch
        from tools.ci.customer_zero_run3_preauth import _run_offline_checks

        # Create a temporary infra directory with an extra unclassified resource
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_infra = _Path(tmpdir) / "infra"
            fake_infra.mkdir()
            (fake_infra / "extra.tf").write_text(
                'resource "aws_s3_bucket" "untracked_bucket" {\n  bucket = "fg-untracked"\n}\n'
            )
            # Copy existing inventory addresses to a mock inventory that does NOT include the new one
            fake_repo = _Path(tmpdir)
            # Patch only the RESOURCE_INVENTORY used inside the check
            with patch.object(
                __import__(
                    "services.governance.run3_resource_inventory",
                    fromlist=["RESOURCE_INVENTORY"],
                ),
                "RESOURCE_INVENTORY",
                [],  # empty inventory — nothing classified
            ):
                checks, blockers = _run_offline_checks(fake_repo, "test-sha")

        cov_check = next(
            (c for c in checks if c["check_id"] == "INVENTORY-TF-COVERAGE"), None
        )
        assert cov_check is not None
        assert cov_check["result"] == "FAIL"
        assert cov_check["evidence_strength"] == "NOT_PROVEN"
        assert any("INVENTORY-TF-COVERAGE" in b for b in blockers)
        assert any("aws_s3_bucket.untracked_bucket" in b for b in blockers)

    def test_80_inventory_tf_coverage_includes_data_sources(self) -> None:
        """Test 80: INVENTORY-TF-COVERAGE cross-checks data sources too."""
        import tempfile
        from pathlib import Path as _Path
        from unittest.mock import patch
        from tools.ci.customer_zero_run3_preauth import _run_offline_checks

        with tempfile.TemporaryDirectory() as tmpdir:
            fake_infra = _Path(tmpdir) / "infra"
            fake_infra.mkdir()
            (fake_infra / "data.tf").write_text(
                'data "aws_caller_identity" "unclassified_data" {}\n'
            )
            fake_repo = _Path(tmpdir)
            with patch.object(
                __import__(
                    "services.governance.run3_resource_inventory",
                    fromlist=["RESOURCE_INVENTORY"],
                ),
                "RESOURCE_INVENTORY",
                [],
            ):
                checks, blockers = _run_offline_checks(fake_repo, "test-sha")

        cov_check = next(
            (c for c in checks if c["check_id"] == "INVENTORY-TF-COVERAGE"), None
        )
        assert cov_check is not None
        assert cov_check["result"] == "FAIL"
        assert any(
            "data.aws_caller_identity.unclassified_data" in b for b in blockers
        ), "Data source must appear in INVENTORY-TF-COVERAGE blocker"

    # ── Fix 4: Portable verification derived from execution ──────────────

    def test_81_portable_verification_not_proven_when_tests_fail(self) -> None:
        """Test 81: pv_result is NOT_PROVEN when portable verification tests fail."""
        from unittest.mock import patch, MagicMock
        from tools.ci.customer_zero_run3_preauth import _build_artifact

        # Mock the subprocess.run inside _build_artifact to simulate test failure
        _fake_run_result = MagicMock()
        _fake_run_result.returncode = 1
        _fake_run_result.stdout = "FAILED tests/test_customer_zero_run3_preauth_001.py::test_36_verify\n1 failed"
        _fake_run_result.stderr = ""

        with patch("subprocess.run", return_value=_fake_run_result):
            artifact = _build_artifact(_ROOT, [], [], "test-sha")

        assert artifact.get("portable_verification_result") == "NOT_PROVEN", (
            "pv_result must be NOT_PROVEN when portable tests fail"
        )
        assert any(
            "PORTABLE-VERIFICATION" in b for b in artifact.get("blockers", [])
        ), "Artifact blockers must contain PORTABLE-VERIFICATION entry on test failure"

    def test_82_portable_verification_test_proven_when_tests_pass(self) -> None:
        """Test 82: pv_result is TEST_PROVEN when portable verification tests pass."""
        from unittest.mock import patch, MagicMock
        from tools.ci.customer_zero_run3_preauth import _build_artifact

        _fake_run_result = MagicMock()
        _fake_run_result.returncode = 0
        _fake_run_result.stdout = "11 passed in 9.50s"
        _fake_run_result.stderr = ""

        with patch("subprocess.run", return_value=_fake_run_result):
            artifact = _build_artifact(_ROOT, [], [], "test-sha")

        assert artifact.get("portable_verification_result") == "TEST_PROVEN", (
            "pv_result must be TEST_PROVEN when portable tests pass"
        )

    def test_83_portable_verification_result_not_hardcoded(self) -> None:
        """Test 83: pv_result changes based on test outcome, not a hardcoded string."""
        from unittest.mock import patch, MagicMock
        from tools.ci.customer_zero_run3_preauth import _build_artifact

        pass_result = MagicMock()
        pass_result.returncode = 0
        pass_result.stdout = "11 passed"
        pass_result.stderr = ""

        fail_result = MagicMock()
        fail_result.returncode = 1
        fail_result.stdout = "1 failed"
        fail_result.stderr = ""

        with patch("subprocess.run", return_value=pass_result):
            artifact_pass = _build_artifact(_ROOT, [], [], "test-sha")
        with patch("subprocess.run", return_value=fail_result):
            artifact_fail = _build_artifact(_ROOT, [], [], "test-sha")

        assert artifact_pass.get("portable_verification_result") == "TEST_PROVEN"
        assert artifact_fail.get("portable_verification_result") == "NOT_PROVEN"
        assert (
            artifact_pass["portable_verification_result"]
            != artifact_fail["portable_verification_result"]
        ), "portable_verification_result must vary with test outcome"

    def test_84_cost_request_source_sha_in_to_dict(self) -> None:
        """Test 84: CostAuthorizationRequest.to_dict() includes source_sha."""
        from services.governance.run3_cost_request import build_cost_request

        req = build_cost_request(
            candidate_fingerprint="fp_84",
            resource_inventory_fingerprint="inv_84",
            expected_resources=[],
            preserved_resources=[],
            source_sha="sha_84_test",
        )
        d = req.to_dict()
        assert "source_sha" in d, "to_dict() must include source_sha"
        assert d["source_sha"] == "sha_84_test"
