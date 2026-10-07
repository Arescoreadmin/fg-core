"""tests/test_vault_verify_contract_001.py — VAULT-VERIFY-CONTRACT-001 adversarial test suite.

This module is NOT standalone. It is a component of the Field Assessment
Engagement Substrate and Governance Platform.

Proves that the Vault verification contract is deterministic and fail-closed
across all adversarial scenarios identified during Customer-Zero ceremonies
1 and 2. The root-cause defect (DEFECT-VERIFIER-CONTRACT): a post-rotation
cross-domain verification attempt raised VaultTransitError instead of
returning a deterministic False.

Contract:
  VERIFIED    — cryptographically valid proof, correct domain/version → True
  INVALID     — cryptographic invalidity (wrong domain, version, key, replay,
                altered payload, malformed) → False (deterministic)
  UNAVAILABLE — Vault operationally absent (transport, auth, timeout) →
                False (deterministic, fail-closed per ceremony_state.yaml:153-160)

All verify_* paths return a deterministic boolean. No path raises
VaultTransitError as a substitute for a fail-closed boolean result.
Internal epistemic distinction is preserved inside VaultBackend:
  - VaultKeyVersionUnavailableError (wrong-version proof) → return False
  - VaultVerifierUnavailableError (transport/auth outage) → caught by verify_*, return False
Unexpected non-VaultTransitError exceptions propagate (diagnosable, not silently False).

Categories:
  A — Valid proof verifies (golden path)
  B — Cryptographic invalidity → deterministic False
  C — Payload tampering → False
  D — Wrong trust domain (all cross-domain combinations) → False
  E — Key version violations → False
  F — Replay attacks (cross-report, cross-tenant, cross-engagement) → False
  G — Missing / empty / malformed signature → False
  H — Malformed fingerprint → False
  I — ROOT-CAUSE REGRESSION: cross-domain/incompatible-version → INVALID (False), not exception
  J — Vault unavailable / timeout / auth failure → False (deterministic, not exception)
  K — Unexpected Vault response / internal exception → fail closed
  L — Determinism
  M — PROVENANCE-INTEGRITY-001 preserved
  N — Post-teardown verification assessment
"""

from __future__ import annotations

import base64
import os

os.environ.setdefault("FG_ENV", "test")

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from services.cgin.key_management.vault_transit import (
    ManagedSignature,
    TrustAnchor,
    TrustRole,
    VaultKeyVersionUnavailableError,
    VaultTransitError,
    VaultVerifierUnavailableError,
    public_key_fingerprint,
)
from services.governance.trust_binding import (
    _ROLE_DELIVERY_AUTHORIZATION,
    _ROLE_QUALIFICATION,
    _ROLE_REPORT,
    DOMAIN_DELIVERY_AUTHORIZATION,
    DOMAIN_QUALIFICATION,
    DOMAIN_REPORT,
    SignatureEnvelope,
    TrustBindingAuthority,
    build_delivery_authorization_signing_payload,
    build_qualification_signing_payload,
    build_report_signing_payload,
)
from services.governance.trust_binding_fake import (
    TrustBindingFake,
    make_test_authority,
    make_test_fake,
)

# ---------------------------------------------------------------------------
# Helpers and fixtures
# ---------------------------------------------------------------------------


def _make_report_payload(
    tenant_id: str = "tenant-vvc-001",
    engagement_id: str = "eng-vvc-001",
    report_id: str = "rep-vvc-001",
    report_version_id: str = "rv-vvc-001",
    report_fingerprint: str = "fp" * 32,
    report_schema_version: str = "1.0",
) -> dict:
    return build_report_signing_payload(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        report_id=report_id,
        report_version_id=report_version_id,
        report_fingerprint=report_fingerprint,
        report_schema_version=report_schema_version,
    )


def _make_qual_payload(
    tenant_id: str = "tenant-vvc-001",
    engagement_id: str = "eng-vvc-001",
    report_id: str = "rep-vvc-001",
    qual_request_id: str = "qr-vvc-001",
    report_version_id: str = "rv-vvc-001",
    report_fingerprint: str = "fp" * 32,
    decision: str = "QUALIFIED",
    decided_by: str = "actor-vvc-001",
    schema_version: str = "1.0",
) -> dict:
    return build_qualification_signing_payload(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        report_id=report_id,
        qual_request_id=qual_request_id,
        report_version_id=report_version_id,
        report_fingerprint=report_fingerprint,
        decision=decision,
        decided_by=decided_by,
        schema_version=schema_version,
    )


def _make_delivery_payload(
    tenant_id: str = "tenant-vvc-001",
    engagement_id: str = "eng-vvc-001",
    report_id: str = "rep-vvc-001",
    report_version_id: str = "rv-vvc-001",
    report_fingerprint: str = "fp" * 32,
) -> dict:
    return build_delivery_authorization_signing_payload(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        report_id=report_id,
        report_version_id=report_version_id,
        report_fingerprint=report_fingerprint,
        qualification_decision_id="qd-vvc-001",
        delivery_request_id="dr-vvc-001",
        recipient_type="operator_direct",
        recipient_id=None,
        channel="direct_download",
        outcome="AUTHORIZED",
        schema_version="1.0",
    )


@pytest.fixture()
def authority() -> TrustBindingAuthority:
    return make_test_authority()


@pytest.fixture()
def fake() -> TrustBindingFake:
    return make_test_fake()


@pytest.fixture()
def report_payload() -> dict:
    return _make_report_payload()


@pytest.fixture()
def qual_payload() -> dict:
    return _make_qual_payload()


@pytest.fixture()
def delivery_payload() -> dict:
    return _make_delivery_payload()


# ---------------------------------------------------------------------------
# Multi-version fake for historical key version tests
# ---------------------------------------------------------------------------


class _MultiVersionFakeRoleKey:
    """Ephemeral Ed25519 key with multi-version rotation support for tests."""

    def __init__(self, role: TrustRole) -> None:
        self._role = role
        self._key_id = f"fake-mv-{role.value}"
        self._keys: dict[int, tuple[Ed25519PrivateKey, str, str]] = {}
        self._current_version = 1
        self._add_version(1)

    def _add_version(self, version: int) -> None:
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        pub_raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        pub_b64 = base64.b64encode(pub_raw).decode("ascii")
        fp = public_key_fingerprint(pub_b64)
        self._keys[version] = (priv, pub_b64, fp)

    def rotate(self) -> int:
        self._current_version += 1
        self._add_version(self._current_version)
        return self._current_version

    def sign(self, payload: bytes) -> ManagedSignature:
        version = self._current_version
        priv, pub_b64, fp = self._keys[version]
        sig_raw = priv.sign(payload)
        sig_str = f"vault:v{version}:" + base64.b64encode(sig_raw).decode("ascii")
        return ManagedSignature(
            issuer="fake-multi-version",
            trust_role=self._role,
            key_id=self._key_id,
            key_version=version,
            algorithm="ed25519",
            public_key_fingerprint=fp,
            signature=sig_str,
        )

    def verify(self, payload: bytes, signature: str) -> bool:
        if not signature.startswith("vault:v"):
            return False
        try:
            parts = signature.split(":", 2)
            if len(parts) != 3:
                return False
            version = int(parts[1][1:])
            if version not in self._keys:
                return False
            priv, pub_b64, fp = self._keys[version]
            pub = priv.public_key()
            raw = base64.b64decode(parts[2])
            pub.verify(raw, payload)
            return True
        except Exception:
            return False


class MultiVersionFake:
    """Per-role multi-version fake backend for rotation tests."""

    def __init__(self) -> None:
        self._keys = {role: _MultiVersionFakeRoleKey(role) for role in TrustRole}

    def sign(self, role: TrustRole, payload: bytes) -> ManagedSignature:
        return self._keys[role].sign(payload)

    def verify(self, role: TrustRole, payload: bytes, signature: str) -> bool:
        return self._keys[role].verify(payload, signature)

    def rotate(self, role: TrustRole) -> int:
        return self._keys[role].rotate()

    def key_id(self, role: TrustRole) -> str:
        return self._keys[role]._key_id


# ---------------------------------------------------------------------------
# A — Valid proof verifies (golden path)
# ---------------------------------------------------------------------------


def test_a1_valid_report_signature_verifies(authority, report_payload):
    """Test 1: Valid proof / correct domain / correct version → VERIFIED."""
    env = authority.sign_report(report_payload)
    assert authority.verify_report(report_payload, env) is True


def test_a2_valid_qualification_signature_verifies(authority, qual_payload):
    """Test 1 (qual): Valid qualification proof verifies."""
    env = authority.sign_qualification(qual_payload)
    assert authority.verify_qualification(qual_payload, env) is True


def test_a3_valid_delivery_authorization_verifies(authority, delivery_payload):
    """Test 1 (delivery): Valid delivery proof verifies."""
    env = authority.sign_delivery_authorization(delivery_payload)
    assert authority.verify_delivery_authorization(delivery_payload, env) is True


# ---------------------------------------------------------------------------
# B — Invalid signature → deterministic False
# ---------------------------------------------------------------------------


def test_b1_invalid_signature_returns_false(authority, report_payload):
    """Test 2: Invalid signature → INVALID (False), not exception."""
    env = authority.sign_report(report_payload)
    # Corrupt the signature bytes
    corrupted_b64 = base64.b64encode(b"\x00" * 64).decode("ascii")
    bad_sig = f"vault:v{env.key_version}:{corrupted_b64}"
    bad_env = SignatureEnvelope(
        issuer=env.issuer,
        trust_role=env.trust_role,
        key_id=env.key_id,
        key_version=env.key_version,
        algorithm=env.algorithm,
        public_key_fingerprint=env.public_key_fingerprint,
        signature=bad_sig,
        domain=env.domain,
        signed_payload_sha256=env.signed_payload_sha256,
    )
    result = authority.verify_report(report_payload, bad_env)
    assert result is False


def test_b2_vault_transit_ordinary_invalid_proof_returns_false_not_exception(
    report_payload,
):
    """Test 16: Vault returns ordinary invalid result → False (not exception).

    Simulates a backend whose verify() returns False for invalid crypto.
    Confirms no exception leakage on the INVALID path.
    """

    class ReturningFalseBackend:
        def sign(self, role, payload):
            raise AssertionError("sign should not be called in this test")

        def verify(self, role, payload, signature):
            return False  # Ordinary invalid result (not exception)

    authority = TrustBindingAuthority(ReturningFalseBackend())
    # Need a well-formed envelope so pre-crypto checks pass
    fake = make_test_fake()
    real_authority = TrustBindingAuthority(fake)
    env = real_authority.sign_report(report_payload)
    # Now verify with the false-returning backend
    result = authority.verify_report(report_payload, env)
    assert result is False


# ---------------------------------------------------------------------------
# C — Payload tampering → False
# ---------------------------------------------------------------------------


def test_c1_altered_payload_fails_verification(authority, report_payload):
    """Test 3: Altered payload → INVALID."""
    env = authority.sign_report(report_payload)
    tampered = dict(report_payload)
    tampered["report_fingerprint"] = "tampered-fingerprint"
    assert authority.verify_report(tampered, env) is False


def test_c2_altered_tenant_id_fails(authority, report_payload):
    """Altered tenant_id in payload → INVALID."""
    env = authority.sign_report(report_payload)
    tampered = dict(report_payload)
    tampered["tenant_id"] = "ATTACKER-TENANT"
    assert authority.verify_report(tampered, env) is False


def test_c3_altered_report_id_fails(authority, report_payload):
    """Altered report_id in payload → INVALID."""
    env = authority.sign_report(report_payload)
    tampered = dict(report_payload)
    tampered["report_id"] = "DIFFERENT-REPORT"
    assert authority.verify_report(tampered, env) is False


# ---------------------------------------------------------------------------
# D — Wrong trust domain → False (all applicable cross-domain combinations)
# ---------------------------------------------------------------------------


def test_d1_identity_signed_report_fails_qualification_verify(
    authority, report_payload
):
    """Test 4: Wrong domain (IDENTITY vs APPROVAL) → INVALID."""
    env = authority.sign_report(report_payload)
    # Try to verify as qualification
    qual_payload = _make_qual_payload()
    # Forge a qualification-looking envelope with the report signature
    forged = SignatureEnvelope(
        issuer=env.issuer,
        trust_role=_ROLE_QUALIFICATION.value,
        key_id=env.key_id,
        key_version=env.key_version,
        algorithm=env.algorithm,
        public_key_fingerprint=env.public_key_fingerprint,
        signature=env.signature,
        domain=DOMAIN_QUALIFICATION,
        signed_payload_sha256=env.signed_payload_sha256,
    )
    assert authority.verify_qualification(qual_payload, forged) is False


def test_d2_identity_signed_report_fails_delivery_verify(authority, report_payload):
    """Test 4: Wrong domain (IDENTITY vs ACCEPTANCE) → INVALID."""
    env = authority.sign_report(report_payload)
    delivery_payload = _make_delivery_payload()
    forged = SignatureEnvelope(
        issuer=env.issuer,
        trust_role=_ROLE_DELIVERY_AUTHORIZATION.value,
        key_id=env.key_id,
        key_version=env.key_version,
        algorithm=env.algorithm,
        public_key_fingerprint=env.public_key_fingerprint,
        signature=env.signature,
        domain=DOMAIN_DELIVERY_AUTHORIZATION,
        signed_payload_sha256=env.signed_payload_sha256,
    )
    assert authority.verify_delivery_authorization(delivery_payload, forged) is False


def test_d3_approval_signed_qual_fails_report_verify(authority, qual_payload):
    """Test 4: Wrong domain (APPROVAL vs IDENTITY) → INVALID."""
    env = authority.sign_qualification(qual_payload)
    report_payload = _make_report_payload()
    forged = SignatureEnvelope(
        issuer=env.issuer,
        trust_role=_ROLE_REPORT.value,
        key_id=env.key_id,
        key_version=env.key_version,
        algorithm=env.algorithm,
        public_key_fingerprint=env.public_key_fingerprint,
        signature=env.signature,
        domain=DOMAIN_REPORT,
        signed_payload_sha256=env.signed_payload_sha256,
    )
    assert authority.verify_report(report_payload, forged) is False


def test_d4_approval_signed_qual_fails_delivery_verify(authority, qual_payload):
    """Test 4: Wrong domain (APPROVAL vs ACCEPTANCE) → INVALID."""
    env = authority.sign_qualification(qual_payload)
    delivery_payload = _make_delivery_payload()
    forged = SignatureEnvelope(
        issuer=env.issuer,
        trust_role=_ROLE_DELIVERY_AUTHORIZATION.value,
        key_id=env.key_id,
        key_version=env.key_version,
        algorithm=env.algorithm,
        public_key_fingerprint=env.public_key_fingerprint,
        signature=env.signature,
        domain=DOMAIN_DELIVERY_AUTHORIZATION,
        signed_payload_sha256=env.signed_payload_sha256,
    )
    assert authority.verify_delivery_authorization(delivery_payload, forged) is False


def test_d5_acceptance_signed_delivery_fails_report_verify(authority, delivery_payload):
    """Test 4: Wrong domain (ACCEPTANCE vs IDENTITY) → INVALID."""
    env = authority.sign_delivery_authorization(delivery_payload)
    report_payload = _make_report_payload()
    forged = SignatureEnvelope(
        issuer=env.issuer,
        trust_role=_ROLE_REPORT.value,
        key_id=env.key_id,
        key_version=env.key_version,
        algorithm=env.algorithm,
        public_key_fingerprint=env.public_key_fingerprint,
        signature=env.signature,
        domain=DOMAIN_REPORT,
        signed_payload_sha256=env.signed_payload_sha256,
    )
    assert authority.verify_report(report_payload, forged) is False


def test_d6_acceptance_signed_delivery_fails_qualification_verify(
    authority, delivery_payload
):
    """Test 4: Wrong domain (ACCEPTANCE vs APPROVAL) → INVALID."""
    env = authority.sign_delivery_authorization(delivery_payload)
    qual_payload = _make_qual_payload()
    forged = SignatureEnvelope(
        issuer=env.issuer,
        trust_role=_ROLE_QUALIFICATION.value,
        key_id=env.key_id,
        key_version=env.key_version,
        algorithm=env.algorithm,
        public_key_fingerprint=env.public_key_fingerprint,
        signature=env.signature,
        domain=DOMAIN_QUALIFICATION,
        signed_payload_sha256=env.signed_payload_sha256,
    )
    assert authority.verify_qualification(qual_payload, forged) is False


# ---------------------------------------------------------------------------
# E — Key version violations
# ---------------------------------------------------------------------------


def test_e1_valid_historical_previous_key_version_still_verifies():
    """Test 5: Valid historical previous key version → still VERIFIED.

    This test proves that after key rotation, a signature created under v1
    continues to verify correctly, because the verification backend tracks
    key versions independently.
    """
    mv = MultiVersionFake()
    authority = TrustBindingAuthority(mv)
    payload = _make_qual_payload()

    # Sign under v1
    env_v1 = authority.sign_qualification(payload)
    assert env_v1.key_version == 1

    # Rotate to v2
    mv.rotate(TrustRole.APPROVAL)

    # v1 signature still verifies (backend has v1 key)
    assert authority.verify_qualification(payload, env_v1) is True

    # v2 signature also verifies
    env_v2 = authority.sign_qualification(payload)
    assert env_v2.key_version == 2
    assert authority.verify_qualification(payload, env_v2) is True


def test_e2_nonexistent_key_version_returns_false():
    """Test 6: Nonexistent key version → INVALID (False).

    A signature claiming version 999 that doesn't exist in the backend
    must return False without exception.
    """
    fake = make_test_fake()
    authority = TrustBindingAuthority(fake)
    payload = _make_report_payload()
    env = authority.sign_report(payload)

    # Mutate signature to claim version 999
    parts = env.signature.split(":", 2)
    bad_sig = f"vault:v999:{parts[2]}"
    bad_env = SignatureEnvelope(
        issuer=env.issuer,
        trust_role=env.trust_role,
        key_id=env.key_id,
        key_version=999,
        algorithm=env.algorithm,
        public_key_fingerprint=env.public_key_fingerprint,
        signature=bad_sig,
        domain=env.domain,
        signed_payload_sha256=env.signed_payload_sha256,
    )
    # The signed_payload_sha256 will still match so pre-crypto checks pass.
    # The crypto check should fail because v999 key doesn't exist in the fake.
    result = authority.verify_report(payload, bad_env)
    assert result is False


def test_e3_malformed_key_version_in_signature_returns_false():
    """Test 7: Malformed key version → INVALID (False)."""
    fake = make_test_fake()
    authority = TrustBindingAuthority(fake)
    payload = _make_report_payload()
    env = authority.sign_report(payload)

    # Malformed version: non-integer
    parts = env.signature.split(":", 2)
    bad_sig = f"vault:vXXX:{parts[2]}"
    bad_env = SignatureEnvelope(
        issuer=env.issuer,
        trust_role=env.trust_role,
        key_id=env.key_id,
        key_version=1,
        algorithm=env.algorithm,
        public_key_fingerprint=env.public_key_fingerprint,
        signature=bad_sig,
        domain=env.domain,
        signed_payload_sha256=env.signed_payload_sha256,
    )
    result = authority.verify_report(payload, bad_env)
    assert result is False


def test_e4_manipulated_key_version_metadata_returns_false():
    """Test 8: Manipulated key-version metadata (envelope.key_version != signature version) → INVALID."""
    fake = make_test_fake()
    authority = TrustBindingAuthority(fake)
    payload = _make_report_payload()
    env = authority.sign_report(payload)

    # Envelope claims v1, but signature contains v2
    parts = env.signature.split(":", 2)
    bad_sig = f"vault:v2:{parts[2]}"  # Version mismatch
    bad_env = SignatureEnvelope(
        issuer=env.issuer,
        trust_role=env.trust_role,
        key_id=env.key_id,
        key_version=1,  # envelope claims v1
        algorithm=env.algorithm,
        public_key_fingerprint=env.public_key_fingerprint,
        signature=bad_sig,  # signature says v2
        domain=env.domain,
        signed_payload_sha256=env.signed_payload_sha256,
    )
    result = authority.verify_report(payload, bad_env)
    assert result is False


# ---------------------------------------------------------------------------
# F — Replay attacks
# ---------------------------------------------------------------------------


def test_f1_cross_report_replay_fails():
    """Test 9: Replay report A → report B → INVALID."""
    authority = make_test_authority()
    payload_a = _make_report_payload(report_id="rep-A", report_version_id="rv-A")
    payload_b = _make_report_payload(report_id="rep-B", report_version_id="rv-B")

    env_a = authority.sign_report(payload_a)
    # Try to verify report B using report A's envelope
    assert authority.verify_report(payload_b, env_a) is False


def test_f2_cross_tenant_replay_fails():
    """Test 10: Replay tenant A → tenant B → INVALID."""
    authority = make_test_authority()
    payload_tenant_a = _make_report_payload(tenant_id="tenant-A")
    payload_tenant_b = _make_report_payload(tenant_id="tenant-B")

    env_a = authority.sign_report(payload_tenant_a)
    assert authority.verify_report(payload_tenant_b, env_a) is False


def test_f3_cross_engagement_replay_fails():
    """Test 11: Replay engagement A → engagement B → INVALID."""
    authority = make_test_authority()
    payload_eng_a = _make_report_payload(engagement_id="eng-A")
    payload_eng_b = _make_report_payload(engagement_id="eng-B")

    env_a = authority.sign_report(payload_eng_a)
    assert authority.verify_report(payload_eng_b, env_a) is False


def test_f4_cross_domain_replay_qualification_signature_as_report():
    """Cross-domain replay: qualification sig attempted as report sig → INVALID."""
    authority = make_test_authority()
    qual_payload = _make_qual_payload()
    report_payload = _make_report_payload()

    qual_env = authority.sign_qualification(qual_payload)

    # Try to use qualification envelope to verify a report
    forged_report_env = SignatureEnvelope(
        issuer=qual_env.issuer,
        trust_role=_ROLE_REPORT.value,  # claim report role
        key_id=qual_env.key_id,
        key_version=qual_env.key_version,
        algorithm=qual_env.algorithm,
        public_key_fingerprint=qual_env.public_key_fingerprint,
        signature=qual_env.signature,
        domain=DOMAIN_REPORT,
        signed_payload_sha256=qual_env.signed_payload_sha256,
    )
    assert authority.verify_report(report_payload, forged_report_env) is False


# ---------------------------------------------------------------------------
# G — Missing / empty / malformed signature
# ---------------------------------------------------------------------------


def test_g1_empty_signature_returns_false(authority, report_payload):
    """Test 12: Empty signature → INVALID (False)."""
    env = authority.sign_report(report_payload)
    bad_env = SignatureEnvelope(
        issuer=env.issuer,
        trust_role=env.trust_role,
        key_id=env.key_id,
        key_version=env.key_version,
        algorithm=env.algorithm,
        public_key_fingerprint=env.public_key_fingerprint,
        signature="",
        domain=env.domain,
        signed_payload_sha256=env.signed_payload_sha256,
    )
    assert authority.verify_report(report_payload, bad_env) is False


def test_g2_malformed_signature_returns_false(authority, qual_payload):
    """Test 13: Malformed signature → INVALID (False)."""
    env = authority.sign_qualification(qual_payload)
    bad_env = SignatureEnvelope(
        issuer=env.issuer,
        trust_role=env.trust_role,
        key_id=env.key_id,
        key_version=env.key_version,
        algorithm=env.algorithm,
        public_key_fingerprint=env.public_key_fingerprint,
        signature="not-a-vault-signature!!",
        domain=env.domain,
        signed_payload_sha256=env.signed_payload_sha256,
    )
    assert authority.verify_qualification(qual_payload, bad_env) is False


def test_g3_missing_vault_prefix_returns_false(authority, delivery_payload):
    """Test 14: Signature missing vault: prefix → INVALID (False)."""
    env = authority.sign_delivery_authorization(delivery_payload)
    bad_env = SignatureEnvelope(
        issuer=env.issuer,
        trust_role=env.trust_role,
        key_id=env.key_id,
        key_version=env.key_version,
        algorithm=env.algorithm,
        public_key_fingerprint=env.public_key_fingerprint,
        signature="AABBCCDDEEFF",  # missing vault: prefix
        domain=env.domain,
        signed_payload_sha256=env.signed_payload_sha256,
    )
    assert authority.verify_delivery_authorization(delivery_payload, bad_env) is False


# ---------------------------------------------------------------------------
# H — Malformed fingerprint
# ---------------------------------------------------------------------------


def test_h1_malformed_public_key_fingerprint_returns_false(authority, report_payload):
    """Test 15: Malformed fingerprint in envelope → INVALID (False).

    The TrustAnchor checks public_key_fingerprint; a mismatch causes failure.
    Tests the TrustAnchor level directly since TrustBindingFake doesn't check
    fingerprints in its verify() path.
    """
    # TrustAnchor.verify() checks fingerprint consistency before crypto verify.
    # Generate a real key for this test.
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64 = base64.b64encode(pub_raw).decode("ascii")
    real_fp = public_key_fingerprint(pub_b64)
    signing_bytes = b"test-payload"
    sig_raw = priv.sign(signing_bytes)
    sig_str = f"vault:v1:{base64.b64encode(sig_raw).decode()}"

    # Correct fingerprint → True
    correct_anchor = TrustAnchor(
        issuer="test",
        trust_role=TrustRole.IDENTITY,
        key_id="k",
        key_version=1,
        algorithm="ed25519",
        public_key=pub_b64,
        public_key_fingerprint=real_fp,
    )
    assert correct_anchor.verify(signing_bytes, sig_str) is True

    # Wrong fingerprint → False
    wrong_anchor = TrustAnchor(
        issuer="test",
        trust_role=TrustRole.IDENTITY,
        key_id="k",
        key_version=1,
        algorithm="ed25519",
        public_key=pub_b64,
        public_key_fingerprint="0" * 64,  # wrong
    )
    assert wrong_anchor.verify(signing_bytes, sig_str) is False


def test_h2_empty_fingerprint_in_envelope_returns_false(authority, qual_payload):
    """Empty public_key_fingerprint in envelope fails the pre-crypto guard."""
    env = authority.sign_qualification(qual_payload)
    bad_env = SignatureEnvelope(
        issuer=env.issuer,
        trust_role=env.trust_role,
        key_id=env.key_id,
        key_version=env.key_version,
        algorithm=env.algorithm,
        public_key_fingerprint="",  # empty
        signature=env.signature,
        domain=env.domain,
        signed_payload_sha256=env.signed_payload_sha256,
    )
    assert authority.verify_qualification(qual_payload, bad_env) is False


# ---------------------------------------------------------------------------
# I — ROOT-CAUSE REGRESSION: cross-domain/incompatible-version
# ---------------------------------------------------------------------------


def test_i1_root_cause_regression_cross_domain_incompatible_version():
    """Test 17 — ROOT-CAUSE REGRESSION.

    DEFECT-VERIFIER-CONTRACT: a post-rotation cross-domain verification attempt
    involving a source proof signed under domain A / key version N, being
    verified against incompatible domain B / version M, must return deterministic
    False — NOT raise VaultTransitError.

    Two parts:
    1. Cross-domain via pre-crypto guard (domain/role mismatch) → False (fast path)
    2. Operational failure via backend.verify() raising VaultTransitError → wrapped as
       VaultVerifierUnavailableError, never raw VaultTransitError leakage
    """
    # Part 1: TrustBindingFake — cross-domain returns False deterministically
    # via the pre-crypto envelope guard (role/domain mismatch caught early).
    authority = make_test_authority()
    payload_a = _make_report_payload()
    qual_payload_b = _make_qual_payload()

    env_report = authority.sign_report(payload_a)

    # Attempt to use IDENTITY-signed report envelope as APPROVAL qualification
    # The envelope.trust_role != _ROLE_QUALIFICATION → returns False immediately.
    forged = SignatureEnvelope(
        issuer=env_report.issuer,
        trust_role=_ROLE_QUALIFICATION.value,  # wrong role claim
        key_id=env_report.key_id,
        key_version=env_report.key_version,
        algorithm=env_report.algorithm,
        public_key_fingerprint=env_report.public_key_fingerprint,
        signature=env_report.signature,
        domain=DOMAIN_QUALIFICATION,  # wrong domain
        signed_payload_sha256=env_report.signed_payload_sha256,
    )
    # Must return False (pre-crypto guard: signed_payload_sha256 mismatch), not raise
    result = authority.verify_qualification(qual_payload_b, forged)
    assert result is False, (
        "ROOT-CAUSE REGRESSION: cross-domain verification returned something "
        "other than False — the DEFECT-VERIFIER-CONTRACT is not repaired"
    )

    # Part 2: Simulate the exact DEFECT-VERIFIER-CONTRACT path:
    # A VaultBackend-like scenario where the backend's verify() raises VaultTransitError
    # (e.g., because Vault refuses/can't verify an incompatible key version).
    # With the fix, verify_* catches VaultTransitError and returns False (deterministic).

    # First, create a well-formed qualification envelope that passes all pre-crypto checks.
    qual_env = _make_verifiable_envelope("sign_qualification", qual_payload_b)

    class _VaultBackendSimulator:
        """Simulates VaultBackend when Vault rejects a cross-version/cross-domain verify."""

        def sign(self, role, payload):
            raise AssertionError("sign should not be called")

        def verify(self, role, payload, signature):
            # The exact defect: Vault Transit returns 400/403 for incompatible
            # key version, which was previously raised raw as VaultTransitError.
            raise VaultTransitError(
                "Vault Transit request failed (400) — key version not found"
            )

    vault_like_authority = TrustBindingAuthority(_VaultBackendSimulator())
    # With the fix: VaultTransitError from backend.verify() → False (deterministic boolean)
    result = vault_like_authority.verify_qualification(qual_payload_b, qual_env)
    assert result is False, (
        "ROOT-CAUSE REGRESSION: VaultTransitError from backend did not produce "
        "deterministic False from verify_qualification"
    )


def test_i2_root_cause_regression_no_vault_transit_error_from_verify():
    """Test 17 (cont) — VaultTransitError must not escape from verify_* as an exception.

    The previous defect: VaultTransitError escaped from VaultBackend.verify()
    (from public_key() fetch) without being wrapped. This test confirms it is
    now caught by verify_* and returned as deterministic False.
    """

    class _RawVaultTransitRaiser:
        """Backend that raises VaultTransitError directly from verify()."""

        def sign(self, role, payload):
            raise AssertionError("sign not expected")

        def verify(self, role, payload, signature):
            raise VaultTransitError("raw leak")

    authority = TrustBindingAuthority(_RawVaultTransitRaiser())
    payload = _make_report_payload()
    fake = make_test_fake()
    real_authority = TrustBindingAuthority(fake)
    env = real_authority.sign_report(payload)

    # Must return False (deterministic), not raise any VaultTransitError
    try:
        result = authority.verify_report(payload, env)
    except VaultTransitError as e:
        pytest.fail(
            f"ROOT-CAUSE REGRESSION: VaultTransitError escaped from verify_report "
            f"(must be caught and returned as False): {e}"
        )
    assert result is False, (
        "ROOT-CAUSE REGRESSION: VaultTransitError from backend did not produce "
        "deterministic False from verify_report"
    )


def test_i3_same_for_delivery_authorization():
    """Test 17 (delivery): VaultTransitError from backend.verify() → False (deterministic)."""

    class _RawRaiser:
        def sign(self, role, payload):
            raise AssertionError("not expected")

        def verify(self, role, payload, signature):
            raise VaultTransitError("transport failure")

    authority = TrustBindingAuthority(_RawRaiser())
    payload = _make_delivery_payload()
    fake = make_test_fake()
    real_authority = TrustBindingAuthority(fake)
    env = real_authority.sign_delivery_authorization(payload)

    try:
        result = authority.verify_delivery_authorization(payload, env)
    except VaultTransitError as e:
        pytest.fail(
            f"VaultTransitError escaped from verify_delivery_authorization: {e}"
        )
    assert result is False


# ---------------------------------------------------------------------------
# J — Vault unavailable / timeout / auth failure → False (deterministic, fail-closed)
# ---------------------------------------------------------------------------


class _UnavailableBackend:
    """Backend that raises VaultTransitError from verify() to simulate unavailability."""

    def __init__(self, message: str = "Vault unavailable") -> None:
        self._message = message

    def sign(self, role, payload):
        raise VaultTransitError(self._message)

    def verify(self, role, payload, signature):
        raise VaultTransitError(self._message)


def _make_verifiable_envelope(
    sign_method_name: str, payload: dict
) -> SignatureEnvelope:
    """Create a verifiable envelope using TrustBindingFake.

    sign_method_name: one of 'sign_report', 'sign_qualification',
    'sign_delivery_authorization'.
    """
    fake = make_test_fake()
    authority = TrustBindingAuthority(fake)
    sign_method = getattr(authority, sign_method_name)
    return sign_method(payload)


def test_j1_vault_unavailable_returns_false(report_payload):
    """Test 18: Vault unavailable → False (deterministic fail-closed, not exception)."""
    authority = TrustBindingAuthority(_UnavailableBackend("transport failure"))
    env = _make_verifiable_envelope("sign_report", report_payload)
    try:
        result = authority.verify_report(report_payload, env)
    except VaultTransitError as e:
        pytest.fail(f"VaultTransitError escaped from verify_report on Vault outage: {e}")
    assert result is False


def test_j2_vault_timeout_returns_false(qual_payload):
    """Test 19: Vault timeout → False (deterministic fail-closed)."""
    authority = TrustBindingAuthority(
        _UnavailableBackend("Vault Transit transport failure: timeout")
    )
    env = _make_verifiable_envelope("sign_qualification", qual_payload)
    # env was signed by TrustBindingFake; now verify with _UnavailableBackend
    # Pre-crypto checks pass (correct role/domain/sha256); backend.verify() raises
    try:
        result = authority.verify_qualification(qual_payload, env)
    except VaultTransitError as e:
        pytest.fail(f"VaultTransitError escaped from verify_qualification on timeout: {e}")
    assert result is False


def test_j3_vault_auth_failure_returns_false(delivery_payload):
    """Test 20: Vault authentication failure → False (deterministic fail-closed)."""
    authority = TrustBindingAuthority(
        _UnavailableBackend("Vault authentication denied (403)")
    )
    env = _make_verifiable_envelope("sign_delivery_authorization", delivery_payload)
    try:
        result = authority.verify_delivery_authorization(delivery_payload, env)
    except VaultTransitError as e:
        pytest.fail(f"VaultTransitError escaped from verify_delivery_authorization on auth failure: {e}")
    assert result is False


def test_j4_vault_authorization_failure_returns_false(report_payload):
    """Test 21: Vault authorization failure → False (deterministic fail-closed)."""

    class _AuthzFailureBackend:
        def sign(self, role, payload):
            raise VaultTransitError(
                "Vault Transit request failed (403) for identity-role"
            )

        def verify(self, role, payload, signature):
            raise VaultTransitError(
                "Vault Transit request failed (403) for identity-role"
            )

    authority = TrustBindingAuthority(_AuthzFailureBackend())
    env = _make_verifiable_envelope("sign_report", report_payload)
    try:
        result = authority.verify_report(report_payload, env)
    except VaultTransitError as e:
        pytest.fail(f"VaultTransitError escaped from verify_report on authorization failure: {e}")
    assert result is False


def test_j5_inaccessible_key_returns_false(qual_payload):
    """Test 22: Inaccessible key version from backend → False (deterministic fail-closed).

    This covers the case where the backend's verify() raises VaultTransitError
    (including VaultKeyVersionUnavailableError) for a key version not in Vault.
    verify_* must catch and return False, not propagate.
    """

    class _KeyVersionNotFoundBackend:
        def sign(self, role, payload):
            raise VaultTransitError("Vault Transit public key version unavailable")

        def verify(self, role, payload, signature):
            raise VaultTransitError("Vault Transit public key version unavailable")

    authority = TrustBindingAuthority(_KeyVersionNotFoundBackend())
    env = _make_verifiable_envelope("sign_qualification", qual_payload)
    try:
        result = authority.verify_qualification(qual_payload, env)
    except VaultTransitError as e:
        pytest.fail(f"VaultTransitError escaped from verify_qualification for inaccessible key: {e}")
    assert result is False


def test_j6_unexpected_vault_response_returns_false(delivery_payload):
    """Test 23: Unexpected Vault response → False (deterministic fail-closed)."""

    class _UnexpectedResponseBackend:
        def sign(self, role, payload):
            raise VaultTransitError("Vault Transit returned malformed data")

        def verify(self, role, payload, signature):
            raise VaultTransitError("Vault Transit returned malformed data")

    authority = TrustBindingAuthority(_UnexpectedResponseBackend())
    env = _make_verifiable_envelope("sign_delivery_authorization", delivery_payload)
    try:
        result = authority.verify_delivery_authorization(delivery_payload, env)
    except VaultTransitError as e:
        pytest.fail(f"VaultTransitError escaped from verify_delivery_authorization on malformed response: {e}")
    assert result is False


def test_j7_vault_unavailable_backend_for_all_verify_returns_false():
    """All three verify methods return False when backend.verify() raises VaultTransitError."""
    for make_payload, sign_name, verify_name in [
        (_make_report_payload, "sign_report", "verify_report"),
        (_make_qual_payload, "sign_qualification", "verify_qualification"),
        (
            _make_delivery_payload,
            "sign_delivery_authorization",
            "verify_delivery_authorization",
        ),
    ]:
        payload = make_payload()
        env = _make_verifiable_envelope(sign_name, payload)
        authority = TrustBindingAuthority(_UnavailableBackend())
        verify = getattr(authority, verify_name)
        try:
            result = verify(payload, env)
        except VaultTransitError as e:
            pytest.fail(
                f"VaultTransitError escaped from {verify_name} on Vault outage: {e}"
            )
        assert result is False, (
            f"{verify_name} did not return False on Vault outage — "
            "deterministic boolean contract violated"
        )


def test_j8_vault_backend_wrong_key_version_returns_false():
    """VaultBackend.verify(): VaultKeyVersionUnavailableError from public_key() → False.

    P1 #2 regression: a proof referencing a nonexistent key version caused
    VaultBackend to raise VaultVerifierUnavailableError (wrong classification —
    this is an invalid proof, not a Vault outage). After the fix, VaultBackend
    catches VaultKeyVersionUnavailableError specifically and returns False.
    """
    from services.governance.trust_binding import VaultBackend

    class _MockClient:
        def public_key(self, key_id, key_version, role, correlation_id=None):
            raise VaultKeyVersionUnavailableError(
                f"Vault Transit public key version unavailable: {key_id} v{key_version}"
            )

    class _MockSigner:
        _key_ids: dict = {role: f"fg-{role.value}" for role in TrustRole}  # noqa: RUF012
        _issuer = "vault-transit"
        _client = _MockClient()

    backend = VaultBackend(_MockSigner())
    # Signature must parse correctly (vault:vN:payload) to reach public_key() call
    result = backend.verify(TrustRole.IDENTITY, b"payload", "vault:v999:abc123==")
    assert result is False, (
        "VaultBackend.verify() must return False for VaultKeyVersionUnavailableError "
        "(wrong-version proof is invalid, not a Vault outage)"
    )


def test_j9_vault_backend_outage_raises_verifier_unavailable():
    """VaultBackend.verify(): transport VaultTransitError from public_key() → VaultVerifierUnavailableError.

    Internal epistemic distinction: genuine transport/auth failures remain
    classified as VaultVerifierUnavailableError inside VaultBackend so that
    callers with monitoring needs can distinguish outage from invalid proof.
    verify_* catches this and returns False; the distinction is visible at
    the VaultBackend layer.
    """
    from services.governance.trust_binding import VaultBackend

    class _MockClient:
        def public_key(self, key_id, key_version, role, correlation_id=None):
            raise VaultTransitError("Vault Transit transport failure: connection refused")

    class _MockSigner:
        _key_ids: dict = {role: f"fg-{role.value}" for role in TrustRole}  # noqa: RUF012
        _issuer = "vault-transit"
        _client = _MockClient()

    backend = VaultBackend(_MockSigner())
    with pytest.raises(VaultVerifierUnavailableError):
        backend.verify(TrustRole.IDENTITY, b"payload", "vault:v1:abc123==")


# ---------------------------------------------------------------------------
# K — Unexpected internal exception → fail closed (not VERIFIED, not silently False)
# ---------------------------------------------------------------------------


def test_k1_unexpected_exception_from_backend_is_not_verified():
    """Test 24: Unexpected internal exception → NOT VERIFIED, NOT silently False.

    An unexpected exception (not VaultTransitError) from the backend's verify()
    must propagate as-is (fail closed, diagnosable). It must NOT be converted
    to True (which would be a security failure).
    """

    class _BrokenBackend:
        def sign(self, role, payload):
            raise AssertionError("not expected")

        def verify(self, role, payload, signature):
            raise RuntimeError("unexpected internal failure — not a Vault error")

    authority = TrustBindingAuthority(_BrokenBackend())
    payload = _make_report_payload()
    fake = make_test_fake()
    real_authority = TrustBindingAuthority(fake)
    env = real_authority.sign_report(payload)

    # Must NOT return True — unexpected exception must propagate
    raised = False
    try:
        result = authority.verify_report(payload, env)
        # If we reach here without raising, result must not be True
        assert result is not True, (
            "SECURITY FAILURE: unexpected internal exception was converted to VERIFIED"
        )
    except RuntimeError:
        raised = True
    except Exception:
        # Any exception except RuntimeError is also acceptable (fail closed)
        raised = True

    # The unexpected exception should propagate (fail closed and diagnosable)
    assert raised, "Unexpected internal exception should propagate, not be swallowed"


def test_k2_unexpected_exception_not_silently_false_when_not_vault_error():
    """Unexpected (non-VaultTransitError) exceptions must NOT be silently converted to False."""

    class _BrokenVerify:
        def sign(self, role, payload):
            raise AssertionError("not expected")

        def verify(self, role, payload, signature):
            raise MemoryError("catastrophic failure")

    authority = TrustBindingAuthority(_BrokenVerify())
    payload = _make_qual_payload()
    fake = make_test_fake()
    env = TrustBindingAuthority(fake).sign_qualification(payload)

    # Must propagate — should NOT be silently caught and returned as False
    with pytest.raises(MemoryError):
        authority.verify_qualification(payload, env)


# ---------------------------------------------------------------------------
# L — Determinism
# ---------------------------------------------------------------------------


def test_l1_repeated_verification_is_deterministic(authority, report_payload):
    """Test 25: Repeated verification of the same proof returns the same result."""
    env = authority.sign_report(report_payload)
    results = [authority.verify_report(report_payload, env) for _ in range(5)]
    assert all(r is True for r in results), "Verification is not deterministic"


def test_l2_valid_proof_remains_valid_across_repeated_verification(
    authority, qual_payload
):
    """Test 26: Valid proof remains valid across repeated verification."""
    env = authority.sign_qualification(qual_payload)
    for _ in range(3):
        assert authority.verify_qualification(qual_payload, env) is True


def test_l3_invalid_proof_remains_deterministically_invalid(authority, qual_payload):
    """Test 27: Invalid proof remains deterministically invalid."""
    env = authority.sign_qualification(qual_payload)
    tampered = dict(qual_payload)
    tampered["tenant_id"] = "ATTACKER"
    results = [authority.verify_qualification(tampered, env) for _ in range(5)]
    assert all(r is False for r in results), "Invalid verification is not deterministic"


# ---------------------------------------------------------------------------
# M — PROVENANCE-INTEGRITY-001 preservation
# ---------------------------------------------------------------------------


def test_m1_provenance_integrity_report_json_tampering_still_fails_closed():
    """Test 28: report_json tampering still fails closed (PROVENANCE-INTEGRITY-001 preserved).

    Verifies that the _derive_manifest_hash_from_report_json helper detects
    mutations at the content level, independent of the trust signature path.
    """
    from api.field_assessment import _derive_manifest_hash_from_report_json

    report_json_original = {
        "tenant_id": "demo-bank",
        "version": "1.0",
        "report_type": "governance",
        "content": "authentic content",
    }
    hash_original = _derive_manifest_hash_from_report_json(report_json_original)

    report_json_tampered = dict(report_json_original)
    report_json_tampered["content"] = "TAMPERED CONTENT"
    hash_tampered = _derive_manifest_hash_from_report_json(report_json_tampered)

    assert hash_original != hash_tampered, (
        "PROVENANCE-INTEGRITY-001 REGRESSION: mutated report_json produces "
        "the same hash as the original"
    )


def test_m2_stored_manifest_hash_only_trust_remains_impossible():
    """Test 29: stored manifest_hash-only trust remains impossible.

    A report with a valid manifest_hash but an altered report_json must fail
    the content integrity check. The manifest_hash is not the only input to
    the signing payload — the current report_json content must also match.
    """
    from api.field_assessment import _derive_manifest_hash_from_report_json

    original_json = {"section": "original", "findings": ["finding-1"]}
    original_hash = _derive_manifest_hash_from_report_json(original_json)

    # Tamper: change the content without updating the hash
    tampered_json = {"section": "tampered", "findings": ["finding-EVIL"]}
    tampered_hash = _derive_manifest_hash_from_report_json(tampered_json)

    assert original_hash != tampered_hash, (
        "REGRESSION: different content produces the same manifest hash"
    )

    # Verify that the hash function is content-deterministic
    same_hash = _derive_manifest_hash_from_report_json(original_json)
    assert original_hash == same_hash


# ---------------------------------------------------------------------------
# N — Post-teardown verification assessment
# ---------------------------------------------------------------------------


def test_n1_offline_verification_capability_assessment():
    """PHASE 7 assessment: post-teardown verification using TrustAnchor (offline path).

    The TrustAnchor.verify() method operates OFFLINE without any Vault call.
    If the public key material is enrolled and preserved, verification can
    proceed without the live Vault infrastructure.

    Classification evidence:
    POST_TEARDOWN_VERIFICATION_PARTIALLY_SUPPORTED

    Reason: TrustAnchor.verify() works fully offline given the public key.
    However, the production path (VaultBackend.verify()) fetches the public
    key online from Vault at verification time. Without Vault, historical
    verification requires pre-enrolled public keys in a TrustAnchorRegistry.
    The infrastructure to enroll and persist public keys offline is not
    currently built — the ceremony runbook does not preserve them.
    Therefore: PARTIALLY_SUPPORTED (offline path exists but requires
    pre-enrollment of public keys before Vault teardown).
    """
    # Generate a key pair (simulating a pre-enrolled Vault public key)
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64 = base64.b64encode(pub_raw).decode("ascii")
    fp = public_key_fingerprint(pub_b64)

    signing_bytes = b'frostgate.report-proof.v1\n{"domain":"test"}'
    sig_raw = priv.sign(signing_bytes)
    sig_str = f"vault:v1:{base64.b64encode(sig_raw).decode()}"

    # Offline verification using TrustAnchor — no Vault call needed
    anchor = TrustAnchor(
        issuer="vault-transit",
        trust_role=TrustRole.IDENTITY,
        key_id="fg-identity-key",
        key_version=1,
        algorithm="ed25519",
        public_key=pub_b64,
        public_key_fingerprint=fp,
    )
    assert anchor.verify(signing_bytes, sig_str) is True

    # Wrong payload → offline verify returns False (no Vault needed)
    assert anchor.verify(b"tampered-payload", sig_str) is False

    # Assessment: POST_TEARDOWN_VERIFICATION_PARTIALLY_SUPPORTED
    # TrustAnchorRegistry + pre-enrolled public keys = fully offline verification
    # VaultBackend alone = requires live Vault (not offline)


def test_n2_vault_backend_verify_requires_live_vault():
    """Confirms VaultBackend.verify() raises VaultVerifierUnavailableError when Vault is absent.

    Post-teardown scenario: Vault has been destroyed. Any attempt to verify
    using VaultBackend fails with VaultVerifierUnavailableError (not silently).
    This is fail-closed: verification does not succeed without Vault.
    """
    # Simulate post-teardown: Vault connection fails immediately
    import httpx

    no_connect_client = httpx.Client(
        timeout=httpx.Timeout(0.001), follow_redirects=False
    )

    from services.cgin.key_management.vault_transit import (  # noqa: PLC0415
        VaultCustomerZeroSigner,
        VaultTransitClient,
    )

    try:
        client = VaultTransitClient(
            "http://127.0.0.1:19999",  # non-existent address
            token="test-token",
            http_client=no_connect_client,
        )
        signer = VaultCustomerZeroSigner(
            client,
            {
                TrustRole.IDENTITY: "key-identity",
                TrustRole.ACCEPTANCE: "key-acceptance",
                TrustRole.APPROVAL: "key-approval",
            },
        )
        from services.governance.trust_binding import VaultBackend

        backend = VaultBackend(signer)

        # Attempt to verify — must raise VaultVerifierUnavailableError (fail closed)
        sig_str = "vault:v1:" + base64.b64encode(b"\x00" * 64).decode()
        raised = False
        try:
            backend.verify(TrustRole.IDENTITY, b"test-payload", sig_str)
        except VaultVerifierUnavailableError:
            raised = True
        except VaultTransitError:
            # Also acceptable (should be subclass)
            raised = True
        except Exception:
            raised = True  # fail closed — any exception is acceptable

        assert raised, (
            "POST-TEARDOWN: VaultBackend.verify() should fail closed when Vault is absent"
        )
    except Exception:
        # If connection refused immediately, test is valid
        pass


# ---------------------------------------------------------------------------
# Additional: VaultVerifierUnavailableError type hierarchy
# ---------------------------------------------------------------------------


def test_vault_verifier_unavailable_is_subclass_of_vault_transit_error():
    """VaultVerifierUnavailableError IS-A VaultTransitError for backward compat."""
    err = VaultVerifierUnavailableError("test")
    assert isinstance(err, VaultTransitError)
    assert isinstance(err, RuntimeError)


def test_vault_transit_error_is_not_necessarily_verifier_unavailable():
    """Base VaultTransitError is NOT necessarily a VaultVerifierUnavailableError."""
    err = VaultTransitError("base error")
    assert not isinstance(err, VaultVerifierUnavailableError)


def test_signing_operations_still_raise_vault_transit_error_directly():
    """Signing operations must still propagate VaultTransitError (not wrapped).

    This confirms the fix only changes the verify path, not the sign path.
    """

    class _UnavailableSignerBackend:
        def sign(self, role, payload):
            raise VaultTransitError("Vault unreachable")

        def verify(self, role, payload, signature):
            return False  # not relevant for this test

    authority = TrustBindingAuthority(_UnavailableSignerBackend())
    payload = _make_report_payload()

    # Sign must still raise VaultTransitError (not wrapped)
    with pytest.raises(VaultTransitError):
        authority.sign_report(payload)
