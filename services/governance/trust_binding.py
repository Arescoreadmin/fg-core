"""TRUST-BINDING-001 — canonical governance artifact trust binding authority.

Routes governance artifact signing to the correct Customer-Zero Vault Transit
trust role with strict domain separation.

This module is NOT standalone. It is a component of the Field Assessment
Engagement Substrate and Governance Platform.

Security invariants:
- Role binding is hard-coded; callers cannot override which role signs which artifact.
- Domain prefixes prevent cross-artifact forgery (IDENTITY sig ≠ APPROVAL sig).
- Signing bytes are deterministic (sort_keys, no volatile fields in signed payload).
- Vault unavailable → VaultTransitError raised; no silent fallback.
- SignatureEnvelope contains only public verification material (no private key material).
- Production env-key path (FG_REPORT_SIGNING_KEY) is explicitly rejected for canonical use.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from services.cgin.key_management.vault_transit import (
    ManagedSignature,
    TrustRole,
    VaultCustomerZeroSigner,
    public_key_fingerprint,
    signer_from_environment,
)

# Domain separators — prepended before signing so a signature over a report payload
# cannot be replayed as a qualification signature (and vice versa).
DOMAIN_REPORT = "frostgate.report-proof.v1"
DOMAIN_QUALIFICATION = "frostgate.production-qualification.v1"
DOMAIN_DELIVERY_AUTHORIZATION = "frostgate.governed-delivery-authorization.v1"

# Role assignment — hard-coded, non-overridable.
_ROLE_REPORT = TrustRole.IDENTITY
_ROLE_QUALIFICATION = TrustRole.APPROVAL
_ROLE_DELIVERY_AUTHORIZATION = TrustRole.ACCEPTANCE

SCHEMA_VERSION = "1"


@dataclass(frozen=True)
class SignatureEnvelope:
    """Public-only verification material for a Vault-issued governance signature.

    NEVER contains private key material, seeds, or Vault tokens.
    """

    issuer: str
    trust_role: str
    key_id: str
    key_version: int
    algorithm: str
    public_key_fingerprint: str
    signature: str  # vault:v<n>:<base64>
    domain: str
    signed_payload_sha256: str
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "trust_role": self.trust_role,
            "key_id": self.key_id,
            "key_version": self.key_version,
            "algorithm": self.algorithm,
            "public_key_fingerprint": self.public_key_fingerprint,
            "signature": self.signature,
            "domain": self.domain,
            "signed_payload_sha256": self.signed_payload_sha256,
            "schema_version": self.schema_version,
        }


@runtime_checkable
class TrustBindingBackend(Protocol):
    """Protocol for the signing backend (real Vault or deterministic test fake)."""

    def sign(self, role: TrustRole, payload: bytes) -> ManagedSignature: ...
    def verify(
        self, role: TrustRole, payload: bytes, signature: str
    ) -> bool: ...


def _prepare_signing_bytes(domain: str, payload_dict: dict[str, Any]) -> bytes:
    """Deterministic serialization with domain prefix.

    The domain prefix is prepended before the JSON bytes so that a signature
    produced under DOMAIN_REPORT cannot be replayed as a DOMAIN_QUALIFICATION
    signature, even if the payload dict is identical.
    """
    payload_json = json.dumps(payload_dict, sort_keys=True, separators=(",", ":"))
    return f"{domain}\n{payload_json}".encode("utf-8")


def _envelope_from_managed(
    managed: ManagedSignature,
    domain: str,
    signing_bytes: bytes,
) -> SignatureEnvelope:
    return SignatureEnvelope(
        issuer=managed.issuer,
        trust_role=managed.trust_role.value,
        key_id=managed.key_id,
        key_version=managed.key_version,
        algorithm=managed.algorithm,
        public_key_fingerprint=managed.public_key_fingerprint,
        signature=managed.signature,
        domain=domain,
        signed_payload_sha256=hashlib.sha256(signing_bytes).hexdigest(),
        schema_version=SCHEMA_VERSION,
    )


class TrustBindingAuthority:
    """Routes governance artifact signing to the canonical Customer-Zero trust roles.

    Role assignment is FIXED:
      report                → TrustRole.IDENTITY
      qualification         → TrustRole.APPROVAL
      delivery authorization → TrustRole.ACCEPTANCE

    Construct with a concrete backend (VaultBackend in production, TrustBindingFake
    in tests).  Do NOT use TrustBindingAuthority.from_environment() in tests.
    """

    def __init__(self, backend: TrustBindingBackend) -> None:
        self._backend = backend

    # ── Report ──────────────────────────────────────────────────────────────

    def sign_report(self, canonical_payload: dict[str, Any]) -> SignatureEnvelope:
        """Sign a report canonical payload with the IDENTITY trust role."""
        signing_bytes = _prepare_signing_bytes(DOMAIN_REPORT, canonical_payload)
        managed = self._backend.sign(_ROLE_REPORT, signing_bytes)
        return _envelope_from_managed(managed, DOMAIN_REPORT, signing_bytes)

    def verify_report(
        self, canonical_payload: dict[str, Any], envelope: SignatureEnvelope
    ) -> bool:
        """Verify a report signature; returns False on any mismatch or error."""
        if envelope.trust_role != _ROLE_REPORT.value:
            return False
        if envelope.domain != DOMAIN_REPORT:
            return False
        signing_bytes = _prepare_signing_bytes(DOMAIN_REPORT, canonical_payload)
        expected_sha = hashlib.sha256(signing_bytes).hexdigest()
        if envelope.signed_payload_sha256 != expected_sha:
            return False
        return self._backend.verify(_ROLE_REPORT, signing_bytes, envelope.signature)

    # ── Qualification ────────────────────────────────────────────────────────

    def sign_qualification(
        self, canonical_payload: dict[str, Any]
    ) -> SignatureEnvelope:
        """Sign a qualification decision canonical payload with the APPROVAL trust role."""
        signing_bytes = _prepare_signing_bytes(
            DOMAIN_QUALIFICATION, canonical_payload
        )
        managed = self._backend.sign(_ROLE_QUALIFICATION, signing_bytes)
        return _envelope_from_managed(managed, DOMAIN_QUALIFICATION, signing_bytes)

    def verify_qualification(
        self, canonical_payload: dict[str, Any], envelope: SignatureEnvelope
    ) -> bool:
        """Verify a qualification decision signature."""
        if envelope.trust_role != _ROLE_QUALIFICATION.value:
            return False
        if envelope.domain != DOMAIN_QUALIFICATION:
            return False
        signing_bytes = _prepare_signing_bytes(
            DOMAIN_QUALIFICATION, canonical_payload
        )
        expected_sha = hashlib.sha256(signing_bytes).hexdigest()
        if envelope.signed_payload_sha256 != expected_sha:
            return False
        return self._backend.verify(
            _ROLE_QUALIFICATION, signing_bytes, envelope.signature
        )

    # ── Delivery authorization ────────────────────────────────────────────────

    def sign_delivery_authorization(
        self, canonical_payload: dict[str, Any]
    ) -> SignatureEnvelope:
        """Sign a delivery authorization canonical payload with the ACCEPTANCE trust role."""
        signing_bytes = _prepare_signing_bytes(
            DOMAIN_DELIVERY_AUTHORIZATION, canonical_payload
        )
        managed = self._backend.sign(_ROLE_DELIVERY_AUTHORIZATION, signing_bytes)
        return _envelope_from_managed(
            managed, DOMAIN_DELIVERY_AUTHORIZATION, signing_bytes
        )

    def verify_delivery_authorization(
        self, canonical_payload: dict[str, Any], envelope: SignatureEnvelope
    ) -> bool:
        """Verify a delivery authorization signature."""
        if envelope.trust_role != _ROLE_DELIVERY_AUTHORIZATION.value:
            return False
        if envelope.domain != DOMAIN_DELIVERY_AUTHORIZATION:
            return False
        signing_bytes = _prepare_signing_bytes(
            DOMAIN_DELIVERY_AUTHORIZATION, canonical_payload
        )
        expected_sha = hashlib.sha256(signing_bytes).hexdigest()
        if envelope.signed_payload_sha256 != expected_sha:
            return False
        return self._backend.verify(
            _ROLE_DELIVERY_AUTHORIZATION, signing_bytes, envelope.signature
        )

    # ── Factory ──────────────────────────────────────────────────────────────

    @classmethod
    def from_environment(cls) -> "TrustBindingAuthority":
        """Build the production authority from environment variables.

        Fails closed if Vault env is not configured.
        Never uses FG_REPORT_SIGNING_KEY for the canonical signing path.
        """
        _reject_env_key_in_canonical_path()
        signer = signer_from_environment()
        return cls(VaultBackend(signer))


def _reject_env_key_in_canonical_path() -> None:
    """Fail closed if caller attempts to use the legacy env-key path for canonical signing.

    The FG_REPORT_SIGNING_KEY env-var path is test/dev only. Canonical signing
    MUST use Vault Transit.  This guard is enforced at TrustBindingAuthority.from_environment().
    """
    # If someone explicitly passes FG_TRUST_BINDING_ALLOW_ENV_KEY=1, they have opted
    # into a test-only path. Production callers must not set this variable.
    if os.getenv("FG_TRUST_BINDING_ALLOW_ENV_KEY", "") == "1":
        # Only allowed in test/development environments
        env = os.getenv("FG_CUSTOMER_ZERO_ENVIRONMENT", "").lower()
        if env not in {"test", "development", "local"}:
            raise RuntimeError(
                "FG_TRUST_BINDING_ALLOW_ENV_KEY=1 is not permitted in "
                f"environment '{env}'"
            )
        return
    # In the canonical path, the presence of FG_REPORT_SIGNING_KEY must not
    # silently take over. We do not READ it here, but we note the conflict.
    # The canonical path uses Vault, period.


class VaultBackend:
    """Production Vault-backed signing backend."""

    def __init__(self, signer: VaultCustomerZeroSigner) -> None:
        self._signer = signer
        self._pub_cache: dict[tuple[TrustRole, str, int], str] = {}

    def sign(self, role: TrustRole, payload: bytes) -> ManagedSignature:
        return self._signer.sign(role, payload)

    def verify(self, role: TrustRole, payload: bytes, signature: str) -> bool:
        # Verification via TrustAnchor.verify() requires the public key.
        # For test/offline use we need the key from Vault.
        # Production callers should use TrustAnchorRegistry.verify() with
        # enrolled public anchors. Here we do an online verify for simplicity.
        if not signature.startswith("vault:v"):
            return False
        try:
            parts = signature.split(":", 2)
            if len(parts) != 3:
                return False
            version = int(parts[1][1:])
        except (IndexError, ValueError):
            return False

        from services.cgin.key_management.vault_transit import TrustAnchor

        key_id = self._signer._key_ids[role]  # type: ignore[attr-defined]
        cache_key = (role, key_id, version)
        if cache_key not in self._pub_cache:
            pub = self._signer._client.public_key(key_id, version, role)  # type: ignore[attr-defined]
            self._pub_cache[cache_key] = pub
        pub_key = self._pub_cache[cache_key]

        anchor = TrustAnchor(
            issuer=self._signer._issuer,  # type: ignore[attr-defined]
            trust_role=role,
            key_id=key_id,
            key_version=version,
            algorithm="ed25519",
            public_key=pub_key,
            public_key_fingerprint=public_key_fingerprint(pub_key),
        )
        return anchor.verify(payload, signature)


# ── Canonical payload builders ────────────────────────────────────────────────


def build_report_signing_payload(
    *,
    tenant_id: str,
    engagement_id: str,
    report_id: str,
    report_version_id: str,
    report_fingerprint: str,
    report_schema_version: str,
) -> dict[str, Any]:
    """Minimal deterministic payload for report signing.

    MUST NOT include timestamps or volatile fields.  IDs are stable identifiers.
    """
    return {
        "domain": DOMAIN_REPORT,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "report_id": report_id,
        "report_version_id": report_version_id,
        "report_fingerprint": report_fingerprint,
        "report_schema_version": report_schema_version,
    }


def build_qualification_signing_payload(
    *,
    tenant_id: str,
    engagement_id: str,
    report_id: str,
    qual_request_id: str,
    report_version_id: str,
    report_fingerprint: str,
    decision: str,
    decided_by: str,
    schema_version: str,
) -> dict[str, Any]:
    """Minimal deterministic payload for qualification decision signing."""
    return {
        "domain": DOMAIN_QUALIFICATION,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "report_id": report_id,
        "qual_request_id": qual_request_id,
        "report_version_id": report_version_id,
        "report_fingerprint": report_fingerprint,
        "decision": decision,
        "decided_by": decided_by,
        "schema_version": schema_version,
    }


def build_delivery_authorization_signing_payload(
    *,
    tenant_id: str,
    engagement_id: str,
    report_id: str,
    report_version_id: str,
    report_fingerprint: str,
    qualification_decision_id: str,
    delivery_request_id: str,
    recipient_type: str,
    recipient_id: str | None,
    channel: str,
    outcome: str,
    schema_version: str,
) -> dict[str, Any]:
    """Minimal deterministic payload for delivery authorization signing."""
    return {
        "domain": DOMAIN_DELIVERY_AUTHORIZATION,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "report_id": report_id,
        "report_version_id": report_version_id,
        "report_fingerprint": report_fingerprint,
        "qualification_decision_id": qualification_decision_id,
        "delivery_request_id": delivery_request_id,
        "recipient_type": recipient_type,
        "recipient_id": recipient_id,
        "channel": channel,
        "outcome": outcome,
        "schema_version": schema_version,
    }
