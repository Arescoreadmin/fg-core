"""Canonical CGIN trust and integrity helpers. Single source of truth for snapshot signing.

Cryptographic agility: all callers reference SigningAlgorithm and
ACTIVE_SIGNING_ALGORITHM — never hardcoded strings — so algorithm rotation
requires changes only in this file.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from services.cgin.privacy import (
    ACTIVE_FINGERPRINT_ALGORITHM,
    CGIN_SCHEMA_VERSION,
)

# ---------------------------------------------------------------------------
# Version constants
# ---------------------------------------------------------------------------

CGIN_TRUST_VERSION = "1.0"
CGIN_CANONICALIZATION_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Algorithm registry — cryptographic agility
# ---------------------------------------------------------------------------


class SigningAlgorithm(str, Enum):
    """Supported CGIN snapshot signing algorithms.

    Add new values here when rotating algorithms; callers never reference
    raw strings.
    """

    ED25519_V1 = "ed25519-v1"
    # Future slots (not yet active):
    # ED448_V1 = "ed448-v1"
    # DILITHIUM_V1 = "dilithium-v1"
    # SPHINCS_V1 = "sphincs-v1"


# The active algorithm used by sign_payload(). Changing this value here
# is the only action needed to rotate the algorithm platform-wide.
ACTIVE_SIGNING_ALGORITHM = SigningAlgorithm.ED25519_V1


# ---------------------------------------------------------------------------
# Canonicalization
# ---------------------------------------------------------------------------


def _canonical_value(obj: Any) -> Any:
    """Recursively prepare a value for canonical JSON serialization."""
    if isinstance(obj, dict):
        return {k: _canonical_value(v) for k, v in sorted(obj.items())}
    if isinstance(obj, (list, tuple)):
        return [_canonical_value(v) for v in obj]
    if isinstance(obj, float):
        # Use repr() to guarantee round-trip fidelity across Python 3.12+ runtimes.
        # json.dumps will handle the actual float-to-JSON conversion with repr precision.
        return obj
    return obj


def canonicalize_snapshot(payload: dict) -> bytes:
    """Return a deterministic, platform-independent byte representation of payload.

    Rules:
    - Recursively sort all dict keys (not Python insertion order)
    - Encode as UTF-8 JSON with no extra whitespace
    - float values: json.dumps uses repr-level precision
    - Arrays: preserve element order, sort only dict keys within elements
    - Output bytes are identical across all Python 3.12+ runtimes given identical inputs
    """
    canonical = _canonical_value(payload)
    return json.dumps(canonical, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


# ---------------------------------------------------------------------------
# Digest
# ---------------------------------------------------------------------------


def generate_digest(canonical_bytes: bytes) -> str:
    """Return SHA-256 of canonical_bytes as a lowercase 64-char hex string."""
    return hashlib.sha256(canonical_bytes).hexdigest()


# ---------------------------------------------------------------------------
# Signing and verification
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url decode with padding restoration."""
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def sign_payload(canonical_bytes: bytes, private_key: Any) -> str:
    """Sign canonical_bytes with private_key. Returns base64url-encoded signature (no padding).

    For ED25519_V1: private_key must be Ed25519PrivateKey.
    """
    if ACTIVE_SIGNING_ALGORITHM == SigningAlgorithm.ED25519_V1:
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("Expected Ed25519PrivateKey for ED25519_V1")
        sig_bytes = private_key.sign(canonical_bytes)
        return _b64url_encode(sig_bytes)

    raise NotImplementedError(
        f"Unsupported signing algorithm: {ACTIVE_SIGNING_ALGORITHM}"
    )


def verify_payload(
    canonical_bytes: bytes,
    signature_b64: str,
    public_key: Any,
    algorithm: SigningAlgorithm,
) -> bool:
    """Verify a signature. Returns True on valid, False on any failure. Never raises."""
    try:
        sig_bytes = _b64url_decode(signature_b64)
        if algorithm == SigningAlgorithm.ED25519_V1:
            if not isinstance(public_key, Ed25519PublicKey):
                return False
            public_key.verify(sig_bytes, canonical_bytes)
            return True
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# VerificationResult
# ---------------------------------------------------------------------------


@dataclass
class VerificationResult:
    valid: bool
    digest_match: bool
    signature_valid: bool
    algorithm_supported: bool
    canonicalization_valid: bool
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# verify_snapshot
# ---------------------------------------------------------------------------


def verify_snapshot(
    payload: dict,
    public_key: Any,
    expected_digest: str | None = None,
) -> VerificationResult:
    """Verify a CGIN snapshot. Never raises. Always returns VerificationResult."""
    errors: list[str] = []
    digest_match = False
    signature_valid = False
    algorithm_supported = False
    canonicalization_valid = False

    # 1. Extract trust block
    trust = payload.get("trust")
    if trust is None:
        errors.append("missing trust block")
        return VerificationResult(
            valid=False,
            digest_match=False,
            signature_valid=False,
            algorithm_supported=False,
            canonicalization_valid=False,
            errors=errors,
        )

    # 2. Extract fields from trust block
    signing_algorithm_raw = trust.get("signing_algorithm")
    stored_digest = trust.get("digest")
    stored_signature = trust.get("signature")

    if signing_algorithm_raw is None:
        errors.append("trust block missing signing_algorithm")
    if stored_digest is None:
        errors.append("trust block missing digest")
    if stored_signature is None:
        errors.append("trust block missing signature")

    if errors:
        return VerificationResult(
            valid=False,
            digest_match=False,
            signature_valid=False,
            algorithm_supported=False,
            canonicalization_valid=False,
            errors=errors,
        )

    # 3. Verify algorithm is known
    try:
        algorithm = SigningAlgorithm(signing_algorithm_raw)
        algorithm_supported = True
    except ValueError:
        errors.append(f"unsupported signing algorithm: {signing_algorithm_raw!r}")
        return VerificationResult(
            valid=False,
            digest_match=False,
            signature_valid=False,
            algorithm_supported=False,
            canonicalization_valid=False,
            errors=errors,
        )

    # 4. Re-canonicalize payload without the trust key
    try:
        payload_without_trust = {k: v for k, v in payload.items() if k != "trust"}
        canonical_bytes = canonicalize_snapshot(payload_without_trust)
        canonicalization_valid = True
    except Exception as exc:
        errors.append(f"canonicalization failed: {exc}")
        return VerificationResult(
            valid=False,
            digest_match=False,
            signature_valid=False,
            algorithm_supported=algorithm_supported,
            canonicalization_valid=False,
            errors=errors,
        )

    # 5. Recompute digest
    computed_digest = generate_digest(canonical_bytes)

    # 6. Compare digests
    if computed_digest == stored_digest:
        digest_match = True
    else:
        errors.append("digest mismatch")

    # 7. Verify signature
    signature_valid = verify_payload(
        canonical_bytes, stored_signature, public_key, algorithm
    )
    if not signature_valid:
        errors.append("signature verification failed")

    # 8. Compare against expected_digest if provided
    if expected_digest is not None and computed_digest != expected_digest:
        errors.append("digest does not match expected_digest")
        digest_match = False

    # 9. Compute overall validity
    valid = (
        digest_match
        and signature_valid
        and algorithm_supported
        and canonicalization_valid
    )

    return VerificationResult(
        valid=valid,
        digest_match=digest_match,
        signature_valid=signature_valid,
        algorithm_supported=algorithm_supported,
        canonicalization_valid=canonicalization_valid,
        errors=errors,
    )


# ---------------------------------------------------------------------------
# build_trust_metadata
# ---------------------------------------------------------------------------


def build_trust_metadata(
    *,
    payload_without_trust: dict,
    private_key: Any,
    authority_version: str = "1.0",
    trust_version: str = CGIN_TRUST_VERSION,
    canonicalization_version: str = CGIN_CANONICALIZATION_VERSION,
    algorithm: SigningAlgorithm = ACTIVE_SIGNING_ALGORITHM,
    previous_snapshot_digest: str | None = None,
) -> dict:
    """Build the trust block to embed in every snapshot.

    Returns a dict containing digest, signature, and metadata about the
    signing authority. The payload_without_trust is canonicalized, digested,
    and signed. The returned trust dict itself is NOT part of the signed payload.
    """
    canonical_bytes = canonicalize_snapshot(payload_without_trust)
    digest = generate_digest(canonical_bytes)
    signature = sign_payload(canonical_bytes, private_key)

    trust: dict[str, Any] = {
        "schema_version": CGIN_SCHEMA_VERSION,
        "digest": digest,
        "signature": signature,
        "signing_algorithm": algorithm.value,
        "fingerprint_algorithm": ACTIVE_FINGERPRINT_ALGORITHM.value,
        "created_at": datetime.now(tz=timezone.utc).isoformat(),
        "authority_version": authority_version,
        "trust_version": trust_version,
        "canonicalization_version": canonicalization_version,
    }

    if previous_snapshot_digest is not None:
        trust["previous_snapshot_digest"] = previous_snapshot_digest

    return trust
