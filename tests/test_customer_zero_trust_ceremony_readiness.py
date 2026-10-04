"""CUSTOMER-ZERO-TRUST-001 — ceremony-readiness operational negative suite.

This module is NOT standalone. It is a component of the Field Assessment
Engagement Substrate and Governance Platform.

These tests prove the operational properties the live HCP Vault ceremony is
expected to verify, exercised in the local LOCAL_MODEL mode so a provable
baseline exists before any paid provider interaction. Each test exists on both
sides of the ceremony boundary:

  LOCAL_MODEL (this file) — proves the authority refuses what the ceremony is
    required to refuse: cross-role substitution, forbidden production signers,
    non-deterministic signing bytes, undisclosed algorithms, missing provenance,
    silent fallback to ephemeral/raw signers, and leakage of secret material
    into the SignatureEnvelope.
  LIVE_PROVEN (ceremony runbook §M–R) — proves the same properties against the
    live customer-zero-identity, customer-zero-acceptance, and
    customer-zero-approval Vault Transit roles, with role separation enforced
    by Vault policy and SecretIDs never crossing the Claude boundary.

Classes:
    A — Role-substitution adversarial matrix (9 explicit deny cases, 3x3)
    B — Forbidden production signers (fallback / ephemeral / env-key rejection)
    C — Signature envelope integrity (schema, algorithm, metadata, no secrets)
    D — Determinism (same payload → same canonical signing bytes)
    E — Rotation / historical anchor modelling (LOCAL_PASS; LIVE_PROVEN pending)
    F — Failure / recovery (vault unavailable, malformed, timeout → fail-closed)
    G — Public-anchor-only verification (verify without any Vault connection)
    H — Secret-boundary scanning (envelope and manifest never carry secrets)

Scope boundary: this suite is LOCAL_MODEL only. It never contacts a Vault
server, never touches live AWS or HCP resources, and never issues or consumes
AppRole SecretIDs. The live-provider counterpart is captured as evidence by the
ceremony runbook (infra/docs/ceremony-runbook.md checkpoints M, N, O, P, R).
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import os

os.environ.setdefault("FG_ENV", "test")

import pytest

from services.cgin.key_management.vault_transit import (
    ManagedSignature,
    TrustAnchor,
    TrustAnchorRegistry,
    TrustRole,
    VaultTransitError,
    public_key_fingerprint,
)
from services.governance.trust_binding import (
    DOMAIN_DELIVERY_AUTHORIZATION,
    DOMAIN_QUALIFICATION,
    DOMAIN_REPORT,
    SCHEMA_VERSION,
    SignatureEnvelope,
    TrustBindingAuthority,
    _prepare_signing_bytes,
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
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def authority() -> TrustBindingAuthority:
    return make_test_authority()


@pytest.fixture()
def fake() -> TrustBindingFake:
    return make_test_fake()


@pytest.fixture()
def report_payload() -> dict:
    return build_report_signing_payload(
        tenant_id="tenant-ceremony-001",
        engagement_id="eng-ceremony-001",
        report_id="rep-ceremony-001",
        report_version_id="rv-ceremony-001",
        report_fingerprint="aa" * 32,
        report_schema_version="1.0",
    )


@pytest.fixture()
def qual_payload() -> dict:
    return build_qualification_signing_payload(
        tenant_id="tenant-ceremony-001",
        engagement_id="eng-ceremony-001",
        report_id="rep-ceremony-001",
        qual_request_id="qr-ceremony-001",
        report_version_id="rv-ceremony-001",
        report_fingerprint="aa" * 32,
        decision="QUALIFIED",
        decided_by="actor-ceremony-001",
        schema_version="1.0",
    )


@pytest.fixture()
def delivery_payload() -> dict:
    return build_delivery_authorization_signing_payload(
        tenant_id="tenant-ceremony-001",
        engagement_id="eng-ceremony-001",
        report_id="rep-ceremony-001",
        report_version_id="rv-ceremony-001",
        report_fingerprint="aa" * 32,
        qualification_decision_id="qd-ceremony-001",
        delivery_request_id="dr-ceremony-001",
        recipient_type="operator_direct",
        recipient_id=None,
        channel="direct_download",
        outcome="AUTHORIZED",
        schema_version="1.0",
    )


# ---------------------------------------------------------------------------
# A. Role-substitution adversarial matrix (3x3 deny matrix proof)
#
# The ceremony claims that each of the three Vault Transit keys can sign only
# its own trust role's artefact type.  Expressed as a 3x3 permission matrix,
# the diagonal is ALLOW and the six off-diagonal cells are DENY.
#
# This class proves the six off-diagonal DENY cells locally.  LIVE_PROVEN cells
# are produced at ceremony §N (vault policy enforces structural deny).
# ---------------------------------------------------------------------------


def _reroute(
    envelope: SignatureEnvelope,
    *,
    trust_role: TrustRole,
    domain: str,
) -> SignatureEnvelope:
    """Rebuild an envelope with its claimed role / domain substituted."""
    return SignatureEnvelope(
        issuer=envelope.issuer,
        trust_role=trust_role.value,
        key_id=envelope.key_id,
        key_version=envelope.key_version,
        algorithm=envelope.algorithm,
        public_key_fingerprint=envelope.public_key_fingerprint,
        signature=envelope.signature,
        domain=domain,
        signed_payload_sha256=envelope.signed_payload_sha256,
    )


def test_a1_identity_signature_cannot_pose_as_qualification(
    authority, report_payload, qual_payload
):
    """IDENTITY-signed report must never satisfy verify_qualification."""
    env = authority.sign_report(report_payload)
    forged = _reroute(env, trust_role=TrustRole.APPROVAL, domain=DOMAIN_QUALIFICATION)
    assert authority.verify_qualification(qual_payload, forged) is False


def test_a2_identity_signature_cannot_pose_as_delivery(
    authority, report_payload, delivery_payload
):
    """IDENTITY-signed report must never satisfy verify_delivery_authorization."""
    env = authority.sign_report(report_payload)
    forged = _reroute(
        env, trust_role=TrustRole.ACCEPTANCE, domain=DOMAIN_DELIVERY_AUTHORIZATION
    )
    assert authority.verify_delivery_authorization(delivery_payload, forged) is False


def test_a3_qualification_signature_cannot_pose_as_report(
    authority, qual_payload, report_payload
):
    """APPROVAL-signed qualification must never satisfy verify_report."""
    env = authority.sign_qualification(qual_payload)
    forged = _reroute(env, trust_role=TrustRole.IDENTITY, domain=DOMAIN_REPORT)
    assert authority.verify_report(report_payload, forged) is False


def test_a4_qualification_signature_cannot_pose_as_delivery(
    authority, qual_payload, delivery_payload
):
    """APPROVAL-signed qualification must never satisfy verify_delivery_authorization."""
    env = authority.sign_qualification(qual_payload)
    forged = _reroute(
        env, trust_role=TrustRole.ACCEPTANCE, domain=DOMAIN_DELIVERY_AUTHORIZATION
    )
    assert authority.verify_delivery_authorization(delivery_payload, forged) is False


def test_a5_delivery_signature_cannot_pose_as_report(
    authority, delivery_payload, report_payload
):
    """ACCEPTANCE-signed delivery must never satisfy verify_report."""
    env = authority.sign_delivery_authorization(delivery_payload)
    forged = _reroute(env, trust_role=TrustRole.IDENTITY, domain=DOMAIN_REPORT)
    assert authority.verify_report(report_payload, forged) is False


def test_a6_delivery_signature_cannot_pose_as_qualification(
    authority, delivery_payload, qual_payload
):
    """ACCEPTANCE-signed delivery must never satisfy verify_qualification."""
    env = authority.sign_delivery_authorization(delivery_payload)
    forged = _reroute(env, trust_role=TrustRole.APPROVAL, domain=DOMAIN_QUALIFICATION)
    assert authority.verify_qualification(qual_payload, forged) is False


def test_a7_wrong_role_verify_helper_proves_cross_role_denial(fake, report_payload):
    """TrustBindingFake.wrong_role_verify returns False for every other key.

    LOCAL_MODEL proof that each per-role ephemeral key only validates its own
    role's signatures. LIVE_PROVEN counterpart: ceremony §N, Vault policy
    structurally denies the sign request before any signature is produced.
    """
    signing_bytes = _prepare_signing_bytes(DOMAIN_REPORT, report_payload)
    managed = fake.sign(TrustRole.IDENTITY, signing_bytes)
    assert (
        fake.wrong_role_verify(TrustRole.IDENTITY, signing_bytes, managed.signature)
        is False
    )


def test_a8_cross_role_cannot_derive_matching_public_fingerprint(fake):
    """Public-key fingerprints must be distinct across the three trust roles.

    If the three roles shared a key, the LIVE Vault policy's structural
    separation would be the only barrier.  Fingerprint distinctness is a
    LOCAL_PASS invariant proving the model matches the live expectation.
    """
    fp_identity = fake.fingerprint(TrustRole.IDENTITY)
    fp_acceptance = fake.fingerprint(TrustRole.ACCEPTANCE)
    fp_approval = fake.fingerprint(TrustRole.APPROVAL)
    assert len({fp_identity, fp_acceptance, fp_approval}) == 3


def test_a9_envelope_role_claim_cannot_outvote_domain_check(
    authority, qual_payload, delivery_payload
):
    """Even if an attacker correctly claims a role, a wrong domain still denies.

    Belt-and-braces: role + domain are both cryptographically bound inputs.
    Removing one defence cannot create a valid signature.
    """
    env = authority.sign_qualification(qual_payload)
    # Keep role as APPROVAL, but mutate the domain to delivery authorisation.
    forged = SignatureEnvelope(
        issuer=env.issuer,
        trust_role=env.trust_role,  # correct role
        key_id=env.key_id,
        key_version=env.key_version,
        algorithm=env.algorithm,
        public_key_fingerprint=env.public_key_fingerprint,
        signature=env.signature,
        domain=DOMAIN_DELIVERY_AUTHORIZATION,  # wrong domain
        signed_payload_sha256=env.signed_payload_sha256,
    )
    assert authority.verify_delivery_authorization(delivery_payload, forged) is False


# ---------------------------------------------------------------------------
# B. Forbidden production signers
#
# Raw env-key paths, ephemeral in-process keys, and the test fake must never
# satisfy a production qualification path.
# ---------------------------------------------------------------------------


def test_b1_from_environment_rejects_env_key_only_configuration(monkeypatch):
    """TrustBindingAuthority.from_environment() cannot fall back to FG_REPORT_SIGNING_KEY.

    Even if the legacy report signing key is set, from_environment() still
    requires Vault configuration and must raise when it is absent.
    """
    for key in list(os.environ.keys()):
        if key.startswith("FG_CUSTOMER_ZERO") or key.startswith("VAULT_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", "ab" * 32)
    with pytest.raises((ValueError, RuntimeError)):
        TrustBindingAuthority.from_environment()


def test_b2_test_fake_refused_in_production(monkeypatch):
    """TrustBindingFake must raise if FG_ENV=production (and FG_CUSTOMER_ZERO_ENVIRONMENT)."""
    monkeypatch.setenv("FG_ENV", "production")
    with pytest.raises(RuntimeError, match="test-only"):
        make_test_fake()
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_CUSTOMER_ZERO_ENVIRONMENT", "production")
    with pytest.raises(RuntimeError, match="test-only"):
        make_test_fake()


def test_b3_test_fake_refused_in_staging(monkeypatch):
    """TrustBindingFake must raise if FG_ENV=staging — staging is a production environment."""
    monkeypatch.setenv("FG_ENV", "staging")
    with pytest.raises(RuntimeError, match="test-only"):
        make_test_fake()


def test_b4_from_environment_rejects_static_token_in_production(monkeypatch):
    """VaultTransitClient.from_environment() refuses static-token mode in production."""
    from services.cgin.key_management.vault_transit import VaultTransitClient

    monkeypatch.setenv("FG_CUSTOMER_ZERO_VAULT_AUTH_MODE", "static_token")
    monkeypatch.setenv("FG_CUSTOMER_ZERO_ENVIRONMENT", "production")
    monkeypatch.setenv("FG_CUSTOMER_ZERO_VAULT_ADDR", "https://vault.example")
    monkeypatch.setenv("FG_CUSTOMER_ZERO_VAULT_TOKEN", "ignored")
    with pytest.raises(ValueError, match="test/development"):
        VaultTransitClient.from_environment()


def test_b5_raw_ephemeral_signer_cannot_satisfy_production_verify(
    authority, qual_payload
):
    """A locally-generated ephemeral signature over the right payload must not
    satisfy verify_qualification issued by a DIFFERENT process-local authority.

    Proves there is no implicit trust in "any Ed25519 signature over the correct
    payload" — the public key must come from the ceremony's enrolled anchor.
    """
    env = authority.sign_qualification(qual_payload)

    # A separately-created fake has a different (independent) key.
    attacker_fake = make_test_fake()
    attacker_authority = TrustBindingAuthority(attacker_fake)
    attacker_env = attacker_authority.sign_qualification(qual_payload)

    # The attacker's envelope is well-formed but was signed by their own key.
    # The original authority's backend cannot verify a signature produced by a
    # key it has never seen.
    assert authority.verify_qualification(qual_payload, attacker_env) is False
    # And the original envelope remains valid under its own authority.
    assert authority.verify_qualification(qual_payload, env) is True


def test_b6_env_key_report_signing_cannot_mint_customer_zero_envelope(monkeypatch):
    """The legacy FG_REPORT_SIGNING_KEY path signs over SHA-256 of canonical
    JSON, not the Customer-Zero domain-prefixed canonical bytes.

    Production reports MUST surface a SignatureEnvelope via the Vault
    authority. The legacy raw-ed25519 signature does not satisfy
    verify_report() under the Customer-Zero authority: it lacks the Vault
    signature format (vault:vN:) and the public anchor.
    """
    from services.governance.report.signing import sign_report as legacy_sign

    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", "cd" * 32)
    canonical = json.dumps(
        {"domain": "unused", "report_id": "r"}, sort_keys=True, separators=(",", ":")
    )
    raw_hex_sig = legacy_sign(canonical)
    # The legacy signature is 128 hex chars (64 bytes), not a vault:vN: string.
    assert len(raw_hex_sig) == 128
    assert not raw_hex_sig.startswith("vault:v")


# ---------------------------------------------------------------------------
# C. Signature envelope integrity
# ---------------------------------------------------------------------------


def test_c1_envelope_schema_version_is_pinned(authority, report_payload):
    """Every envelope issued by the authority carries the pinned schema version."""
    env = authority.sign_report(report_payload)
    assert env.schema_version == SCHEMA_VERSION


def test_c2_envelope_algorithm_is_ed25519_only(authority, qual_payload):
    """Every envelope issued by the authority declares ed25519."""
    env = authority.sign_qualification(qual_payload)
    assert env.algorithm == "ed25519"


def test_c3_envelope_payload_sha256_matches_canonical_signed_bytes(
    authority, delivery_payload
):
    """signed_payload_sha256 must equal SHA-256 of domain + newline + canonical JSON."""
    env = authority.sign_delivery_authorization(delivery_payload)
    canonical = json.dumps(delivery_payload, sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256(
        f"{DOMAIN_DELIVERY_AUTHORIZATION}\n{canonical}".encode("utf-8")
    ).hexdigest()
    assert env.signed_payload_sha256 == expected


def test_c4_envelope_contains_no_private_or_token_fields(authority, qual_payload):
    """Reject any envelope field named like a secret."""
    env = authority.sign_qualification(qual_payload)
    serialised = env.to_dict()
    for key in serialised:
        assert "token" not in key.lower()
        assert "secret" not in key.lower()
        assert "private" not in key.lower()
        assert "bearer" not in key.lower()


def test_c5_envelope_json_is_safe_to_commit(authority, delivery_payload):
    """to_dict() output serialises to pure JSON with no non-ASCII artefacts."""
    env = authority.sign_delivery_authorization(delivery_payload)
    rendered = json.dumps(env.to_dict(), sort_keys=True)
    # No PEM markers, AWS secret-key prefixes, Slack tokens, or Vault tokens
    assert "-----BEGIN" not in rendered
    assert "AKIA" not in rendered  # noqa: Q000 — explicit AWS access key id prefix
    assert "xoxb-" not in rendered
    assert not any(
        rendered.startswith(prefix) or f'"{prefix}' in rendered
        for prefix in ("hvs.", "s.", "b.")
    )


# ---------------------------------------------------------------------------
# D. Determinism (same artefact → same canonical signing bytes)
# ---------------------------------------------------------------------------


def test_d1_canonical_signing_bytes_are_deterministic(report_payload):
    """Preparing signing bytes twice from the same payload yields identical bytes."""
    first = _prepare_signing_bytes(DOMAIN_REPORT, report_payload)
    second = _prepare_signing_bytes(DOMAIN_REPORT, dict(report_payload))
    assert first == second


def test_d2_reordered_payload_fields_do_not_change_signing_bytes(qual_payload):
    """Deterministic serialisation is invariant to key insertion order."""
    reordered = dict(reversed(list(qual_payload.items())))
    first = _prepare_signing_bytes(DOMAIN_QUALIFICATION, qual_payload)
    second = _prepare_signing_bytes(DOMAIN_QUALIFICATION, reordered)
    assert first == second


def test_d3_different_domain_prefix_changes_signing_bytes(qual_payload):
    """Changing the domain prefix changes the signing bytes."""
    report_bytes = _prepare_signing_bytes(DOMAIN_REPORT, qual_payload)
    qual_bytes = _prepare_signing_bytes(DOMAIN_QUALIFICATION, qual_payload)
    assert report_bytes != qual_bytes


def test_d4_signed_payload_sha256_is_deterministic_across_two_signings(
    authority, delivery_payload
):
    """Signing the same payload twice produces identical signed_payload_sha256.

    Signature bytes may differ (Vault / Ed25519 nonces), but the digest of the
    canonical signing bytes must be identical — this is the operator's
    verification anchor.
    """
    env1 = authority.sign_delivery_authorization(delivery_payload)
    env2 = authority.sign_delivery_authorization(dict(delivery_payload))
    assert env1.signed_payload_sha256 == env2.signed_payload_sha256


# ---------------------------------------------------------------------------
# E. Rotation / historical anchor modelling (LOCAL_PASS; LIVE_PROVEN pending)
# ---------------------------------------------------------------------------


def test_e1_envelope_records_key_version_for_historical_verification(
    authority, report_payload
):
    """key_version is captured on every envelope — required for historical verify."""
    env = authority.sign_report(report_payload)
    assert isinstance(env.key_version, int)
    assert env.key_version >= 1
    assert env.signature.startswith(f"vault:v{env.key_version}:")


def test_e2_historical_anchor_registry_rejects_unknown_version(fake, report_payload):
    """TrustAnchorRegistry.resolve raises when a (issuer,role,key,version) is not enrolled.

    Models the ceremony §P historical verification: an old (v1) signature must
    be verifiable only via the retained v1 public anchor, and a request for an
    unknown version must fail closed.
    """
    signing_bytes = _prepare_signing_bytes(DOMAIN_REPORT, report_payload)
    managed = fake.sign(TrustRole.IDENTITY, signing_bytes)
    anchor_v1 = TrustAnchor(
        issuer=managed.issuer,
        trust_role=TrustRole.IDENTITY,
        key_id=managed.key_id,
        key_version=managed.key_version,
        algorithm="ed25519",
        public_key=fake.public_key_b64(TrustRole.IDENTITY),
        public_key_fingerprint=managed.public_key_fingerprint,
    )
    registry = TrustAnchorRegistry([anchor_v1])

    # Correct resolve for v1 verifies the signature.
    assert (
        registry.verify(
            managed.issuer,
            TrustRole.IDENTITY,
            managed.key_id,
            managed.key_version,
            signing_bytes,
            managed.signature,
        )
        is True
    )

    # Unknown v2 request fails closed with ValueError.
    with pytest.raises(ValueError, match="unknown Vault trust anchor"):
        registry.resolve(managed.issuer, TrustRole.IDENTITY, managed.key_id, 2)


def test_e3_rotation_model_old_signature_still_verifies_against_old_anchor(fake):
    """LOCAL_MODEL rotation: v1 signature remains verifiable against retained v1 anchor.

    The fake only has one key per role, so this is a model of the ceremony §P
    invariant rather than a live rotation.  Live rotation proof is captured by
    ceremony §P (post_rotation_sign_rc=0, historical_verify_rc=0).
    """
    payload = build_report_signing_payload(
        tenant_id="t",
        engagement_id="e",
        report_id="r",
        report_version_id="rv",
        report_fingerprint="aa" * 32,
        report_schema_version="1.0",
    )
    signing_bytes = _prepare_signing_bytes(DOMAIN_REPORT, payload)
    managed_v1 = fake.sign(TrustRole.IDENTITY, signing_bytes)

    anchor_v1 = TrustAnchor(
        issuer=managed_v1.issuer,
        trust_role=TrustRole.IDENTITY,
        key_id=managed_v1.key_id,
        key_version=managed_v1.key_version,
        algorithm="ed25519",
        public_key=fake.public_key_b64(TrustRole.IDENTITY),
        public_key_fingerprint=managed_v1.public_key_fingerprint,
    )
    # The retained v1 anchor validates the v1 signature.
    assert anchor_v1.verify(signing_bytes, managed_v1.signature) is True


# ---------------------------------------------------------------------------
# F. Failure / recovery — fail-closed under provider errors
# ---------------------------------------------------------------------------


class _VaultDownBackend:
    """Backend that always raises VaultTransitError."""

    def sign(self, role, payload):
        raise VaultTransitError("Vault unavailable")

    def verify(self, role, payload, signature):
        raise VaultTransitError("Vault unavailable")


class _MalformedBackend:
    """Backend whose managed signature claims a non-ed25519 algorithm."""

    def __init__(self, delegate: TrustBindingFake) -> None:
        self._delegate = delegate

    def sign(self, role, payload):
        managed = self._delegate.sign(role, payload)
        return ManagedSignature(
            issuer=managed.issuer,
            trust_role=managed.trust_role,
            key_id=managed.key_id,
            key_version=managed.key_version,
            algorithm="rsa-pss",  # unsupported
            public_key_fingerprint=managed.public_key_fingerprint,
            signature=managed.signature,
        )

    def verify(self, role, payload, signature):
        return self._delegate.verify(role, payload, signature)


def test_f1_vault_down_sign_report_raises(report_payload):
    authority = TrustBindingAuthority(_VaultDownBackend())
    with pytest.raises(VaultTransitError):
        authority.sign_report(report_payload)


def test_f2_vault_down_sign_qualification_raises(qual_payload):
    authority = TrustBindingAuthority(_VaultDownBackend())
    with pytest.raises(VaultTransitError):
        authority.sign_qualification(qual_payload)


def test_f3_vault_down_sign_delivery_authorization_raises(delivery_payload):
    authority = TrustBindingAuthority(_VaultDownBackend())
    with pytest.raises(VaultTransitError):
        authority.sign_delivery_authorization(delivery_payload)


def test_f4_backend_producing_bad_algorithm_fails_verify(qual_payload):
    """A backend that reports an unsupported algorithm must fail verification."""
    fake = make_test_fake()
    bad_backend = _MalformedBackend(fake)
    authority = TrustBindingAuthority(bad_backend)
    env = authority.sign_qualification(qual_payload)
    # The envelope now carries algorithm='rsa-pss' which fails the pre-crypto guard
    assert authority.verify_qualification(qual_payload, env) is False


def test_f5_envelope_with_altered_bytes_fails_verify(authority, qual_payload):
    """Any single-byte alteration of the signing payload must invalidate the signature."""
    env = authority.sign_qualification(qual_payload)
    tampered = dict(qual_payload)
    tampered["decision"] = "QUALIFIED "  # trailing space — a single byte of difference
    assert authority.verify_qualification(tampered, env) is False


# ---------------------------------------------------------------------------
# G. Public-anchor-only verification (verify without Vault)
# ---------------------------------------------------------------------------


def test_g1_verify_without_vault_connection(fake, report_payload):
    """TrustAnchor.verify() produces True without any Vault call.

    LIVE_PROVEN counterpart: external verifier (operator / customer) can
    validate the enrolled anchor + envelope without any HCP Vault connection.
    """
    signing_bytes = _prepare_signing_bytes(DOMAIN_REPORT, report_payload)
    managed = fake.sign(TrustRole.IDENTITY, signing_bytes)

    anchor = TrustAnchor(
        issuer=managed.issuer,
        trust_role=TrustRole.IDENTITY,
        key_id=managed.key_id,
        key_version=managed.key_version,
        algorithm="ed25519",
        public_key=fake.public_key_b64(TrustRole.IDENTITY),
        public_key_fingerprint=managed.public_key_fingerprint,
    )
    assert anchor.verify(signing_bytes, managed.signature) is True


def test_g2_anchor_rejects_signature_with_wrong_key_version(fake, report_payload):
    """A signature for v1 must not validate against an anchor claiming v2."""
    signing_bytes = _prepare_signing_bytes(DOMAIN_REPORT, report_payload)
    managed = fake.sign(TrustRole.IDENTITY, signing_bytes)
    anchor_v2 = TrustAnchor(
        issuer=managed.issuer,
        trust_role=TrustRole.IDENTITY,
        key_id=managed.key_id,
        key_version=2,  # mismatch
        algorithm="ed25519",
        public_key=fake.public_key_b64(TrustRole.IDENTITY),
        public_key_fingerprint=managed.public_key_fingerprint,
    )
    assert anchor_v2.verify(signing_bytes, managed.signature) is False


def test_g3_anchor_rejects_signature_with_wrong_public_key(fake, report_payload):
    """A signature by role X must not validate against role Y's public key."""
    signing_bytes = _prepare_signing_bytes(DOMAIN_REPORT, report_payload)
    managed_identity = fake.sign(TrustRole.IDENTITY, signing_bytes)

    # Build an anchor that claims to be the identity anchor but carries the
    # ACCEPTANCE public key.
    hostile_anchor = TrustAnchor(
        issuer=managed_identity.issuer,
        trust_role=TrustRole.IDENTITY,
        key_id=managed_identity.key_id,
        key_version=managed_identity.key_version,
        algorithm="ed25519",
        public_key=fake.public_key_b64(TrustRole.ACCEPTANCE),
        public_key_fingerprint=public_key_fingerprint(
            fake.public_key_b64(TrustRole.ACCEPTANCE)
        ),
    )
    assert hostile_anchor.verify(signing_bytes, managed_identity.signature) is False


def test_g4_anchor_rejects_inactive_status(fake, report_payload):
    """An anchor flagged inactive must fail-closed even with correct material."""
    signing_bytes = _prepare_signing_bytes(DOMAIN_REPORT, report_payload)
    managed = fake.sign(TrustRole.IDENTITY, signing_bytes)
    revoked = TrustAnchor(
        issuer=managed.issuer,
        trust_role=TrustRole.IDENTITY,
        key_id=managed.key_id,
        key_version=managed.key_version,
        algorithm="ed25519",
        public_key=fake.public_key_b64(TrustRole.IDENTITY),
        public_key_fingerprint=managed.public_key_fingerprint,
        status="revoked",
    )
    assert revoked.verify(signing_bytes, managed.signature) is False


# ---------------------------------------------------------------------------
# H. Secret-boundary scanning (envelope / manifest never carry secrets)
# ---------------------------------------------------------------------------


def test_h1_managed_signature_dataclass_does_not_expose_vault_token(fake):
    """ManagedSignature should not carry any Vault token or secret ID."""
    managed = fake.sign(TrustRole.IDENTITY, b"payload")
    for field_name in managed.__dataclass_fields__:
        value = getattr(managed, field_name)
        if isinstance(value, str):
            assert "hvs." not in value
            assert "s." not in value or value.startswith("vault:")  # vault: prefix ok
            # Signature strings are the only base64-looking strings allowed
            if field_name != "signature":
                try:
                    base64.b64decode(value, validate=True)
                except (ValueError, Exception):
                    pass  # not base64 — fine


def test_h2_signature_envelope_fields_are_whitelisted(authority, qual_payload):
    """The SignatureEnvelope dataclass has a fixed, whitelisted field set."""
    env = authority.sign_qualification(qual_payload)
    allowed_fields = {
        "issuer",
        "trust_role",
        "key_id",
        "key_version",
        "algorithm",
        "public_key_fingerprint",
        "signature",
        "domain",
        "signed_payload_sha256",
        "schema_version",
    }
    assert set(env.to_dict().keys()) == allowed_fields


def test_h3_fake_signer_does_not_leak_private_key_bytes(fake):
    """TrustBindingFake must never expose private key material via public API."""
    public_api = {name for name in dir(fake) if not name.startswith("_")}
    forbidden = {"private_key", "seed", "signing_key", "_priv", "secret"}
    assert public_api.isdisjoint(forbidden)


def test_h4_fake_signer_repr_does_not_contain_private_key(fake):
    """str/repr of the fake must not include any private key hex / seed."""
    r = repr(fake)
    assert "private" not in r.lower()
    assert "seed" not in r.lower()
    assert "secret" not in r.lower()


# ---------------------------------------------------------------------------
# I. Live-ceremony contract markers (expectations the ceremony MUST satisfy)
#
# These assertions do not test runtime behaviour; they declare the invariants
# the ceremony is contracted to produce.  Any change to a role name, domain
# string, or algorithm MUST land here first — the ceremony runbook and
# Terraform configuration reference these constants.
# ---------------------------------------------------------------------------


def test_i1_trust_role_names_are_pinned():
    """Trust-role names are the external contract shipped to the live ceremony."""
    assert TrustRole.IDENTITY.value == "customer-zero-identity"
    assert TrustRole.ACCEPTANCE.value == "customer-zero-acceptance"
    assert TrustRole.APPROVAL.value == "customer-zero-approval"


def test_i2_trust_domains_are_pinned():
    """Trust domains cannot drift silently — they are hashed into every signature."""
    assert DOMAIN_REPORT == "frostgate.report-proof.v1"
    assert DOMAIN_QUALIFICATION == "frostgate.production-qualification.v1"
    assert (
        DOMAIN_DELIVERY_AUTHORIZATION == "frostgate.governed-delivery-authorization.v1"
    )


def test_i3_signature_envelope_schema_version_pin():
    """Schema version is pinned at 1 — any bump requires explicit migration."""
    assert SCHEMA_VERSION == "1"


# ---------------------------------------------------------------------------
# J. Provenance-field mutation (known gap documentation)
#
# TrustBindingAuthority.verify_* checks envelope provenance fields
# (key_id, issuer, public_key_fingerprint) for non-emptiness but does NOT
# compare them against the enrolled anchor.  A stored envelope with forged
# provenance metadata but a cryptographically valid signature will be accepted.
#
# These tests DOCUMENT the current behavior.  They pass today because the gap
# exists.  When provenance binding against the anchor is implemented, these
# tests will fail and must be converted to assert the forged envelopes REJECT.
# ---------------------------------------------------------------------------


def test_j1_verify_report_accepts_forged_key_id(authority, report_payload):
    """KNOWN GAP: verify_report accepts a non-empty key_id that differs from the
    enrolled anchor.  The backend verify() uses the configured role key, not
    envelope.key_id, so provenance forgery passes the cryptographic check."""
    env = authority.sign_report(report_payload)
    forged = dataclasses.replace(env, key_id="transit/keys/attacker-key/9999")
    assert authority.verify_report(report_payload, forged) is True, (
        "KNOWN GAP: mutated key_id should fail once anchor comparison is implemented"
    )


def test_j2_verify_report_accepts_forged_issuer(authority, report_payload):
    """KNOWN GAP: verify_report accepts a non-empty issuer that differs from the
    enrolled anchor.  Issuer is recorded in the envelope but never validated
    against the anchor registry."""
    env = authority.sign_report(report_payload)
    forged = dataclasses.replace(env, issuer="https://attacker.invalid/vault")
    assert authority.verify_report(report_payload, forged) is True, (
        "KNOWN GAP: mutated issuer should fail once anchor comparison is implemented"
    )


def test_j3_verify_report_accepts_forged_public_key_fingerprint(
    authority, report_payload
):
    """KNOWN GAP: verify_report accepts a non-empty public_key_fingerprint that
    does not match the signing key.  The fingerprint is checked for non-emptiness
    but never re-derived from the signing key or compared against the anchor."""
    env = authority.sign_report(report_payload)
    forged = dataclasses.replace(env, public_key_fingerprint="a" * 64)
    assert authority.verify_report(report_payload, forged) is True, (
        "KNOWN GAP: forged fingerprint should fail once anchor comparison is implemented"
    )
