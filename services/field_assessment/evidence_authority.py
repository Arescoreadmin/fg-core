"""Evidence Authority — Ed25519 signing and verification for provenance events.

This module is a trust infrastructure primitive.

Every provenance event becomes a signed authority event.  A verifier with only
the public key and a provenance record can independently confirm:
  - what evidence existed (via event_hash covering the full payload)
  - that the payload was not modified after signing
  - which authority signed it (authority_version)
  - which key signed it (signing_key_id = SHA256(pub_bytes)[:16])

Reuse potential:
  build_canonical_provenance_event() returns a generic authority event dict.
  The signing primitive (_sign_canonical_bytes) is chain-type-agnostic.
  Future: Report Authority, Identity Authority, RBAC Authority reuse the same
  pattern — different canonical event shape, same Ed25519 + SHA-256 algorithm.

PR 1.3 design constraints:
  - No private key persistence (key never enters DB, logs, responses, metrics)
  - No external PKI / CA / revocation in this PR
  - Rotation: key_id stored per record; future rotation re-signs new records only
  - Fail closed in prod: missing key raises; dev/test: caller catches and skips
"""

from __future__ import annotations

import base64
import hashlib
import os
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from api.db_models_field_assessment import FaEvidenceProvenance
from services.canonical import canonical_json_bytes, utc_iso8601_z_now

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

AUTHORITY_VERSION: str = "evidence-authority-v1"
SIGNATURE_VERSION: str = "evidence-signature-v1"


class EvidenceAuthorityError(RuntimeError):
    """Raised when signing key material is missing or invalid."""


# ---------------------------------------------------------------------------
# Key management (private — key material must never leave this module)
# ---------------------------------------------------------------------------


def _load_private_key_seed() -> bytes:
    """Load 32-byte Ed25519 seed from FG_EVIDENCE_SIGNING_KEY_B64.

    Raises EvidenceAuthorityError if missing or invalid.
    """
    raw = (os.getenv("FG_EVIDENCE_SIGNING_KEY_B64") or "").strip()
    if not raw:
        raise EvidenceAuthorityError(
            "FG_EVIDENCE_SIGNING_KEY_B64 is required for evidence authority signing"
        )
    try:
        seed = base64.b64decode(raw)
    except Exception as exc:
        raise EvidenceAuthorityError(
            "FG_EVIDENCE_SIGNING_KEY_B64 must be valid base64"
        ) from exc
    if len(seed) != 32:
        raise EvidenceAuthorityError(
            f"FG_EVIDENCE_SIGNING_KEY_B64 must decode to 32 bytes (got {len(seed)})"
        )
    return seed


def _derive_public_key_bytes(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


def _derive_key_id(pub_bytes: bytes) -> str:
    """SHA256(public_key_bytes)[:16] — stable 16-char fingerprint for key rotation queries."""
    return hashlib.sha256(pub_bytes).hexdigest()[:16]


def _load_verification_public_key() -> bytes:
    """Load public key bytes for signature verification.

    Tries FG_EVIDENCE_SIGNING_KEY_B64 first (derives pub from priv).
    No separate public-key-only env var in this PR — rotation support is future work.
    """
    return _derive_public_key_bytes(_load_private_key_seed())


# ---------------------------------------------------------------------------
# Canonical authority event
# ---------------------------------------------------------------------------


def _build_canonical_event(
    *,
    event_hash: str,
    previous_hash: str | None,
    tenant_id: str,
    engagement_id: str,
    evidence_id: str | None,
    finding_id: str | None,
    source_type: str,
    collected_at: str,
) -> dict[str, Any]:
    """Build the deterministic dict that is signed.

    Only immutable provenance identity fields are included.
    Mutable review/status/report fields are excluded by design.
    """
    return {
        "event_hash": event_hash,
        "previous_hash": previous_hash,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "evidence_id": evidence_id,
        "finding_id": finding_id,
        "source_type": source_type,
        "collected_at": collected_at,
        "authority_version": AUTHORITY_VERSION,
        "signature_version": SIGNATURE_VERSION,
    }


def build_canonical_provenance_event(record: FaEvidenceProvenance) -> dict[str, Any]:
    """Build the canonical authority event dict from an existing provenance record.

    The returned dict is what is (or was) signed. A verifier recomputes this,
    hashes it, and verifies the Ed25519 signature over the digest.
    """
    return _build_canonical_event(
        event_hash=record.event_hash,
        previous_hash=record.previous_hash,
        tenant_id=record.tenant_id,
        engagement_id=record.engagement_id,
        evidence_id=record.evidence_id,
        finding_id=record.finding_id,
        source_type=record.source_type,
        collected_at=record.collected_at,
    )


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def _sign_canonical_bytes(canonical: dict[str, Any]) -> str:
    """Ed25519-sign SHA-256(canonical_json_bytes(canonical)). Returns hex signature."""
    seed = _load_private_key_seed()
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    digest = hashlib.sha256(canonical_json_bytes(canonical)).digest()
    return priv.sign(digest).hex()


def _make_authority_fields(*, signature: str, pub_bytes: bytes) -> dict[str, str]:
    return {
        "signature": signature,
        "signing_key_id": _derive_key_id(pub_bytes),
        "signed_at": utc_iso8601_z_now(),
        "signature_version": SIGNATURE_VERSION,
        "authority_version": AUTHORITY_VERSION,
    }


def sign_provenance_event(record: FaEvidenceProvenance) -> dict[str, str]:
    """Sign a provenance record and return the authority fields dict.

    Returns:
      signature        hex Ed25519 signature
      signing_key_id   SHA256(pub_bytes)[:16]
      signed_at        ISO8601-Z timestamp
      signature_version "evidence-signature-v1"
      authority_version "evidence-authority-v1"

    Raises EvidenceAuthorityError if FG_EVIDENCE_SIGNING_KEY_B64 is not configured.
    Caller assigns returned fields to the record before db.commit().
    """
    seed = _load_private_key_seed()
    pub_bytes = _derive_public_key_bytes(seed)
    canonical = build_canonical_provenance_event(record)
    sig = _sign_canonical_bytes(canonical)
    return _make_authority_fields(signature=sig, pub_bytes=pub_bytes)


def sign_new_provenance_event(
    *,
    event_hash: str,
    previous_hash: str | None,
    tenant_id: str,
    engagement_id: str,
    evidence_id: str | None,
    finding_id: str | None,
    source_type: str,
    collected_at: str,
) -> dict[str, str]:
    """Sign provenance fields before record creation.

    Use this when the ORM record does not exist yet (append-only tables cannot
    be updated after INSERT, so signatures must be computed before the first flush).

    Raises EvidenceAuthorityError if FG_EVIDENCE_SIGNING_KEY_B64 is not configured.
    """
    seed = _load_private_key_seed()
    pub_bytes = _derive_public_key_bytes(seed)
    canonical = _build_canonical_event(
        event_hash=event_hash,
        previous_hash=previous_hash,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        evidence_id=evidence_id,
        finding_id=finding_id,
        source_type=source_type,
        collected_at=collected_at,
    )
    sig = _sign_canonical_bytes(canonical)
    return _make_authority_fields(signature=sig, pub_bytes=pub_bytes)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def verify_provenance_signature(record: FaEvidenceProvenance) -> dict[str, Any]:
    """Verify the Ed25519 authority signature on a provenance record.

    Returns a result dict:
      valid             bool | None  (None = not applicable for legacy_unsigned)
      status            "verified" | "legacy_unsigned" | "invalid" | "key_unavailable" | "error"
      reason            str
      authority_version str | None
      signing_key_id    str | None

    Legacy unsigned records (signature=None) return status="legacy_unsigned",
    valid=None — this is a warning, not a failure.

    Signed records with an invalid signature return valid=False — hard failure.
    """
    if record.signature is None:
        return {
            "valid": None,
            "status": "legacy_unsigned",
            "reason": "no_signature",
            "authority_version": None,
            "signing_key_id": None,
        }

    try:
        pub_bytes = _load_verification_public_key()
    except EvidenceAuthorityError as exc:
        return {
            "valid": False,
            "status": "key_unavailable",
            "reason": f"signing_key_not_configured: {exc}",
            "authority_version": record.authority_version,
            "signing_key_id": record.signing_key_id,
        }

    # Warn on key_id mismatch (could be rotation), but still attempt verification
    current_key_id = _derive_key_id(pub_bytes)
    if record.signing_key_id and record.signing_key_id != current_key_id:
        # Key rotation not yet supported — treat as verification failure
        return {
            "valid": False,
            "status": "invalid",
            "reason": f"key_id_mismatch: stored={record.signing_key_id} current={current_key_id}",
            "authority_version": record.authority_version,
            "signing_key_id": record.signing_key_id,
        }

    canonical = build_canonical_provenance_event(record)
    digest = hashlib.sha256(canonical_json_bytes(canonical)).digest()

    try:
        sig_bytes = bytes.fromhex(record.signature)
    except ValueError:
        return {
            "valid": False,
            "status": "invalid",
            "reason": "signature_encoding_error",
            "authority_version": record.authority_version,
            "signing_key_id": record.signing_key_id,
        }

    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub.verify(sig_bytes, digest)
        return {
            "valid": True,
            "status": "verified",
            "reason": "ok",
            "authority_version": record.authority_version or AUTHORITY_VERSION,
            "signing_key_id": record.signing_key_id,
        }
    except InvalidSignature:
        return {
            "valid": False,
            "status": "invalid",
            "reason": "signature_mismatch",
            "authority_version": record.authority_version,
            "signing_key_id": record.signing_key_id,
        }
    except Exception as exc:
        return {
            "valid": False,
            "status": "error",
            "reason": f"verification_error: {type(exc).__name__}",
            "authority_version": record.authority_version,
            "signing_key_id": record.signing_key_id,
        }
