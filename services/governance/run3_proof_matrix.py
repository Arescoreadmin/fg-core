"""CUSTOMER-ZERO-RUN3-PREAUTH-001 — Deterministic machine-readable proof matrix.

Covers three trust domains: IDENTITY, ACCEPTANCE, APPROVAL
Proof families A through K as defined in the PREAUTH-001 spec.

Each proof requirement includes:
  - proof_id
  - trust_domain
  - objective
  - preconditions
  - execution_stage (OFFLINE_ENGINEERING | PRE_PROVISIONING | LIVE_CEREMONY)
  - verification_method
  - expected_result
  - evidence_artifact
  - failure_classification
  - mandatory
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal


ExecutionStage = Literal["OFFLINE_ENGINEERING", "PRE_PROVISIONING", "LIVE_CEREMONY"]
TrustDomain = Literal["IDENTITY", "ACCEPTANCE", "APPROVAL", "ALL"]


@dataclass(frozen=True)
class ProofRequirement:
    """A single proof requirement in the Run-3 proof matrix."""

    proof_id: str
    trust_domain: TrustDomain
    objective: str
    preconditions: list[str]
    execution_stage: ExecutionStage
    verification_method: str
    expected_result: str
    evidence_artifact: str
    failure_classification: str
    mandatory: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "proof_id": self.proof_id,
            "trust_domain": self.trust_domain,
            "objective": self.objective,
            "preconditions": self.preconditions,
            "execution_stage": self.execution_stage,
            "verification_method": self.verification_method,
            "expected_result": self.expected_result,
            "evidence_artifact": self.evidence_artifact,
            "failure_classification": self.failure_classification,
            "mandatory": self.mandatory,
        }


def _p(
    proof_id: str,
    trust_domain: TrustDomain,
    objective: str,
    preconditions: list[str],
    execution_stage: ExecutionStage,
    verification_method: str,
    expected_result: str,
    evidence_artifact: str,
    failure_classification: str,
    mandatory: bool = True,
) -> ProofRequirement:
    return ProofRequirement(
        proof_id=proof_id,
        trust_domain=trust_domain,
        objective=objective,
        preconditions=preconditions,
        execution_stage=execution_stage,
        verification_method=verification_method,
        expected_result=expected_result,
        evidence_artifact=evidence_artifact,
        failure_classification=failure_classification,
        mandatory=mandatory,
    )


# ---------------------------------------------------------------------------
# Proof matrix — families A through K
# ---------------------------------------------------------------------------

PROOF_MATRIX: list[ProofRequirement] = [
    # ── A. Positive signing ───────────────────────────────────────────────
    _p(
        "A-IDENTITY-SIGN",
        "IDENTITY",
        "IDENTITY trust role signs an authorized canonical report payload and verifier returns True",
        ["Vault Transit IDENTITY key provisioned", "AppRole IDENTITY authenticated"],
        "LIVE_CEREMONY",
        "TrustBindingAuthority.sign_report() + verify_report() with live Vault",
        "verify_report() returns True",
        "ceremony_audit_log/identity_signing_positive",
        "CEREMONY_FAILURE",
    ),
    _p(
        "A-ACCEPTANCE-SIGN",
        "ACCEPTANCE",
        "ACCEPTANCE trust role signs an authorized canonical delivery authorization and verifier returns True",
        ["Vault Transit ACCEPTANCE key provisioned", "AppRole ACCEPTANCE authenticated"],
        "LIVE_CEREMONY",
        "TrustBindingAuthority.sign_delivery_authorization() + verify_delivery_authorization()",
        "verify_delivery_authorization() returns True",
        "ceremony_audit_log/acceptance_signing_positive",
        "CEREMONY_FAILURE",
    ),
    _p(
        "A-APPROVAL-SIGN",
        "APPROVAL",
        "APPROVAL trust role signs an authorized canonical qualification decision and verifier returns True",
        ["Vault Transit APPROVAL key provisioned", "AppRole APPROVAL authenticated"],
        "LIVE_CEREMONY",
        "TrustBindingAuthority.sign_qualification() + verify_qualification()",
        "verify_qualification() returns True",
        "ceremony_audit_log/approval_signing_positive",
        "CEREMONY_FAILURE",
    ),
    # ── B. Domain isolation ───────────────────────────────────────────────
    _p(
        "B-CROSS-IDENTITY-ACCEPTANCE",
        "IDENTITY",
        "IDENTITY signature CANNOT verify as ACCEPTANCE — cross-domain substitution fails closed",
        ["Positive signing proofs A-IDENTITY-SIGN and A-ACCEPTANCE-SIGN complete"],
        "LIVE_CEREMONY",
        "verify_delivery_authorization() with IDENTITY-signed envelope → must return False",
        "False (cross-domain replay rejected)",
        "ceremony_audit_log/domain_isolation_3x3",
        "P0_SECURITY_FAILURE",
    ),
    _p(
        "B-CROSS-ACCEPTANCE-APPROVAL",
        "ACCEPTANCE",
        "ACCEPTANCE signature CANNOT verify as APPROVAL — cross-domain substitution fails closed",
        ["Positive signing proofs complete"],
        "LIVE_CEREMONY",
        "verify_qualification() with ACCEPTANCE-signed envelope → must return False",
        "False",
        "ceremony_audit_log/domain_isolation_3x3",
        "P0_SECURITY_FAILURE",
    ),
    _p(
        "B-CROSS-APPROVAL-IDENTITY",
        "APPROVAL",
        "APPROVAL signature CANNOT verify as IDENTITY — cross-domain substitution fails closed",
        ["Positive signing proofs complete"],
        "LIVE_CEREMONY",
        "verify_report() with APPROVAL-signed envelope → must return False",
        "False",
        "ceremony_audit_log/domain_isolation_3x3",
        "P0_SECURITY_FAILURE",
    ),
    _p(
        "B-DOMAIN-ISOLATION-OFFLINE",
        "ALL",
        "Cross-domain isolation is TEST_PROVEN offline with real Ed25519 test keys",
        ["TrustBindingFake or PortableVerificationAuthority available"],
        "OFFLINE_ENGINEERING",
        "tests/test_customer_zero_run3_preauth_001.py::test_cross_domain_isolation_*",
        "All cross-domain tests return False",
        "pytest test output",
        "OFFLINE_TEST_FAILURE",
    ),
    # ── C. Replay resistance ───────────────────────────────────────────────
    _p(
        "C-WRONG-PAYLOAD-REPLAY",
        "ALL",
        "Modified payload bytes cause signature verification to return False",
        ["Positive signing complete"],
        "LIVE_CEREMONY",
        "Mutate payload bytes → verify → must return False",
        "False (payload tamper detected)",
        "ceremony_audit_log/replay_resistance",
        "P0_SECURITY_FAILURE",
    ),
    _p(
        "C-WRONG-DOMAIN-REPLAY",
        "ALL",
        "Correct signature replayed against wrong domain returns False",
        ["Positive signing complete"],
        "LIVE_CEREMONY",
        "Replace domain in envelope → verify → must return False",
        "False",
        "ceremony_audit_log/replay_resistance",
        "P0_SECURITY_FAILURE",
    ),
    _p(
        "C-WRONG-KEY-VERSION-REPLAY",
        "ALL",
        "Signature from key version N cannot be verified against key version N+1",
        ["Key rotation (family D) complete"],
        "LIVE_CEREMONY",
        "Verify old-version envelope after rotation → must return False or valid per version",
        "False for wrong-version replay; True for correct-version historical",
        "ceremony_audit_log/rotation_replay",
        "P0_SECURITY_FAILURE",
    ),
    _p(
        "C-REPLAY-RESISTANCE-OFFLINE",
        "ALL",
        "Replay resistance TEST_PROVEN offline with real Ed25519 test keys",
        ["Offline test key pair available"],
        "OFFLINE_ENGINEERING",
        "tests/test_customer_zero_run3_preauth_001.py::test_replay_resistance_*",
        "All replay tests return False on mutation/wrong-domain",
        "pytest test output",
        "OFFLINE_TEST_FAILURE",
    ),
    # ── D. Key rotation ───────────────────────────────────────────────────
    _p(
        "D-IDENTITY-ROTATION",
        "IDENTITY",
        "After IDENTITY key rotation, historical v1 artifacts remain verifiable; new v2 signs correctly",
        ["IDENTITY positive signing complete (v1)"],
        "LIVE_CEREMONY",
        "Rotate IDENTITY key; verify v1 historical signature; sign new artifact with v2; verify v2",
        "Historical v1 True; v2 positive True; v1 payload with v2 key = False",
        "ceremony_audit_log/rotation_identity",
        "CEREMONY_FAILURE",
    ),
    _p(
        "D-ROTATION-HISTORICAL-OFFLINE",
        "ALL",
        "Historical verification after rotation is TEST_PROVEN offline",
        ["Offline test key pair available"],
        "OFFLINE_ENGINEERING",
        "tests/test_customer_zero_run3_preauth_001.py::test_key_rotation_*",
        "Historical key version verifies correctly; wrong version fails",
        "pytest test output",
        "OFFLINE_TEST_FAILURE",
    ),
    # ── E. Verifier failure semantics ──────────────────────────────────────
    _p(
        "E-CRYPTOGRAPHIC-INVALIDITY-FALSE",
        "ALL",
        "Cryptographically invalid proof (bad signature bytes) returns deterministic False — NEVER raises",
        ["Vault Transit provisioned"],
        "LIVE_CEREMONY",
        "Submit corrupted signature bytes; verify_* must return False, not raise",
        "False (deterministic)",
        "ceremony_audit_log/verifier_contract",
        "P0_SECURITY_FAILURE",
    ),
    _p(
        "E-VAULT-UNAVAILABLE-FALSE",
        "ALL",
        "Vault operationally unavailable during verify returns False — does NOT raise VaultTransitError to caller",
        ["VaultVerifierUnavailableError path tested (VAULT-VERIFY-CONTRACT-001 repair proven)"],
        "LIVE_CEREMONY",
        "Simulate Vault network failure during verify_*; must return False",
        "False (fail-closed)",
        "ceremony_audit_log/verifier_contract",
        "P0_SECURITY_FAILURE",
    ),
    _p(
        "E-VERIFIER-SEMANTICS-OFFLINE",
        "ALL",
        "Verifier failure semantics TEST_PROVEN offline — invalid signature returns False, not exception",
        ["TrustBindingFake or real Ed25519 offline test"],
        "OFFLINE_ENGINEERING",
        "tests/test_customer_zero_run3_preauth_001.py::test_verifier_failure_semantics_*",
        "Invalid signature returns False; no exception propagation",
        "pytest test output",
        "OFFLINE_TEST_FAILURE",
    ),
    # ── F. Report provenance ───────────────────────────────────────────────
    _p(
        "F-REPORT-MUTATION-FAILS",
        "IDENTITY",
        "Mutating report_json content after signing causes verify_report() to return False",
        ["IDENTITY positive signing complete", "PROVENANCE-INTEGRITY-001 repair proven"],
        "LIVE_CEREMONY",
        "Sign report; mutate report_json bytes; verify → must return False",
        "False (provenance tamper detected)",
        "ceremony_audit_log/provenance_integrity",
        "P0_SECURITY_FAILURE",
    ),
    _p(
        "F-PROVENANCE-OFFLINE",
        "IDENTITY",
        "Report provenance mutation attack is TEST_PROVEN offline",
        ["Offline test key pair available"],
        "OFFLINE_ENGINEERING",
        "tests/test_customer_zero_run3_preauth_001.py::test_report_provenance_*",
        "Mutated artifact fails offline verification",
        "pytest test output",
        "OFFLINE_TEST_FAILURE",
    ),
    # ── G. Audit delivery ──────────────────────────────────────────────────
    _p(
        "G-VAULT-AUDIT-CLOUDWATCH",
        "ALL",
        "Vault audit events reach CloudWatch log group; independently readable by FrostGateVaultAuditReader",
        ["HCP Vault cluster provisioned", "CloudWatch audit log group present", "HCP UI audit config complete"],
        "LIVE_CEREMONY",
        "Perform signing operation; verify CloudWatch log group contains audit event (FilterLogEvents)",
        "At least one audit event visible in aws_cloudwatch_log_group.vault_audit",
        "ceremony_audit_log/cloudwatch_audit_evidence",
        "CEREMONY_FAILURE",
    ),
    _p(
        "G-AUDIT-DELIVERY-CHECKPOINT",
        "ALL",
        "Audit delivery verified EARLY in ceremony before full proof matrix execution",
        ["CloudWatch log group present", "HCP UI audit logging configured"],
        "LIVE_CEREMONY",
        "Checkpoint Q: audit event visible before proceeding to signing proofs",
        "PASS — audit delivery confirmed early",
        "ceremony_audit_log/checkpoint_q_audit",
        "CEREMONY_FAILURE",
    ),
    # ── H. Tenant isolation ────────────────────────────────────────────────
    _p(
        "H-CROSS-TENANT-SIGN-FAILS",
        "ALL",
        "Signing with one tenant's AppRole cannot produce a valid signature for another tenant's artifacts",
        ["Three trust AppRoles provisioned"],
        "LIVE_CEREMONY",
        "Cross-tenant signing attempt fails at AppRole policy level — wrong policy denies access",
        "Vault returns permission denied; no cross-tenant signature possible",
        "ceremony_audit_log/tenant_isolation",
        "P0_SECURITY_FAILURE",
    ),
    _p(
        "H-TENANT-ISOLATION-OFFLINE",
        "ALL",
        "Cross-tenant signing/verification fails closed — TEST_PROVEN offline",
        ["Offline test key pairs for two test tenants"],
        "OFFLINE_ENGINEERING",
        "tests/test_customer_zero_run3_preauth_001.py::test_tenant_isolation_*",
        "Cross-tenant proof substitution returns False",
        "pytest test output",
        "OFFLINE_TEST_FAILURE",
    ),
    # ── I. Portable verification ────────────────────────────────────────────
    _p(
        "I-OFFLINE-AFTER-VAULT-ABSENT",
        "ALL",
        "Historical artifact is verifiable offline using PortableVerificationAuthority after Vault teardown",
        ["PortableVerificationAuthority implemented (CUSTOMER-ZERO-FINAL-READINESS-001)"],
        "OFFLINE_ENGINEERING",
        "tests/test_customer_zero_run3_preauth_001.py::test_portable_verification_*",
        "verify_offline() returns True with enrolled public key; True without Vault",
        "pytest test output",
        "OFFLINE_TEST_FAILURE",
    ),
    _p(
        "I-PORTABLE-MUTATION-FAILS",
        "ALL",
        "Mutating artifact bytes after Vault teardown causes offline verification to return False",
        ["PortableVerificationAuthority.verify_offline() implemented"],
        "OFFLINE_ENGINEERING",
        "tests/test_customer_zero_run3_preauth_001.py::test_portable_mutation_*",
        "verify_offline() returns False on mutated bytes",
        "pytest test output",
        "OFFLINE_TEST_FAILURE",
    ),
    _p(
        "I-PRIVATE-KEY-NOT-IN-BUNDLE",
        "ALL",
        "Private signing material NEVER enters PortableVerificationBundle",
        ["PortableVerificationBundle.__post_init__ enforces no-private-material"],
        "OFFLINE_ENGINEERING",
        "tests/test_customer_zero_run3_preauth_001.py::test_private_key_not_in_bundle",
        "No PEM private-key markers in bundle dict",
        "pytest test output",
        "P0_SECURITY_FAILURE",
    ),
    # ── J. Source and release provenance ─────────────────────────────────
    _p(
        "J-SOURCE-SHA-BINDING",
        "ALL",
        "Signed artifact binds to approved source SHA; wrong SHA changes candidate fingerprint",
        ["Candidate freeze implemented"],
        "OFFLINE_ENGINEERING",
        "tests/test_customer_zero_run3_preauth_001.py::test_source_sha_binding",
        "Different source SHA produces different candidate fingerprint",
        "pytest test output",
        "OFFLINE_TEST_FAILURE",
    ),
    _p(
        "J-METHODOLOGY-BINDING",
        "ALL",
        "Artifact binds to approved methodology version; methodology change changes fingerprint",
        ["Candidate freeze implemented"],
        "OFFLINE_ENGINEERING",
        "tests/test_customer_zero_run3_preauth_001.py::test_methodology_binding",
        "Different methodology produces different fingerprint",
        "pytest test output",
        "OFFLINE_TEST_FAILURE",
    ),
    # ── K. Complete evidence ──────────────────────────────────────────────
    _p(
        "K-SIGNATURE-DOES-NOT-CONCEAL-INCOMPLETE-EVIDENCE",
        "ALL",
        "A valid signature does NOT automatically constitute complete evidence — DECLARED_ONLY != PASS",
        ["Evidence-strength taxonomy implemented"],
        "OFFLINE_ENGINEERING",
        "tests/test_customer_zero_run3_preauth_001.py::test_declared_only_not_pass",
        "Claims with DECLARED_ONLY strength do not qualify as PASS",
        "pytest test output",
        "OFFLINE_TEST_FAILURE",
    ),
    _p(
        "K-STATIC-VERIFIED-NOT-LIVE-PROOF",
        "ALL",
        "STATIC_VERIFIED does NOT prove production behavior — explicit test",
        ["Evidence-strength taxonomy implemented"],
        "OFFLINE_ENGINEERING",
        "tests/test_customer_zero_run3_preauth_001.py::test_static_verified_not_live",
        "STATIC_VERIFIED != RUNTIME_PROVEN; boundary explicit",
        "pytest test output",
        "OFFLINE_TEST_FAILURE",
    ),
    _p(
        "K-OFFLINE-TEST-NOT-LIVE-HCP",
        "ALL",
        "TEST_PROVEN offline does NOT prove live HCP Vault availability — boundary explicit",
        ["Evidence-strength taxonomy implemented"],
        "OFFLINE_ENGINEERING",
        "tests/test_customer_zero_run3_preauth_001.py::test_offline_not_live_hcp",
        "TEST_PROVEN != RUNTIME_PROVEN; HCP availability is a LIVE_CEREMONY proof only",
        "pytest test output",
        "OFFLINE_TEST_FAILURE",
    ),
]


# ---------------------------------------------------------------------------
# Proof matrix helper functions
# ---------------------------------------------------------------------------


def get_proof_matrix() -> list[ProofRequirement]:
    """Return the canonical proof matrix."""
    return list(PROOF_MATRIX)


def get_offline_proofs() -> list[ProofRequirement]:
    """Return proofs that must pass in this PR."""
    return [p for p in PROOF_MATRIX if p.execution_stage == "OFFLINE_ENGINEERING"]


def get_deferred_live_proofs() -> list[ProofRequirement]:
    """Return proofs deferred to live ceremony."""
    return [p for p in PROOF_MATRIX if p.execution_stage in ("PRE_PROVISIONING", "LIVE_CEREMONY")]


def get_proofs_by_domain(domain: TrustDomain) -> list[ProofRequirement]:
    """Return proofs for a specific trust domain."""
    return [p for p in PROOF_MATRIX if p.trust_domain in (domain, "ALL")]


def compute_proof_matrix_fingerprint() -> str:
    """Deterministic fingerprint of the proof matrix."""
    canonical = sorted(
        [p.to_dict() for p in PROOF_MATRIX],
        key=lambda x: x["proof_id"],
    )
    return hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


PROOF_MATRIX_FINGERPRINT = compute_proof_matrix_fingerprint()
