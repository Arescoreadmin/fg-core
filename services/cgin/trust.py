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
from typing import Any

from services.cgin.key_management import as_provider
from services.cgin.key_management.provider import (
    SigningAlgorithm as _KMSigningAlgorithm,
)
from services.cgin.privacy import (
    ACTIVE_FINGERPRINT_ALGORITHM,
    CGIN_SCHEMA_VERSION,
)

# ---------------------------------------------------------------------------
# Algorithm registry re-exports — callers continue to import from this module.
# SigningAlgorithm is defined in key_management.provider (avoids circular
# imports), but re-exported here so all existing callers are unaffected.
# ---------------------------------------------------------------------------

SigningAlgorithm = _KMSigningAlgorithm
ACTIVE_SIGNING_ALGORITHM = SigningAlgorithm.ED25519_V1

# ---------------------------------------------------------------------------
# Version constants
# ---------------------------------------------------------------------------

CGIN_TRUST_VERSION = "1.0"
CGIN_CANONICALIZATION_VERSION = "1.0"


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

    Accepts a raw Ed25519PrivateKey or any KeyProvider. Raw keys are wrapped
    automatically in MemoryKeyProvider via as_provider().
    """
    return as_provider(private_key).sign(canonical_bytes, ACTIVE_SIGNING_ALGORITHM)


def verify_payload(
    canonical_bytes: bytes,
    signature_b64: str,
    public_key: Any,
    algorithm: SigningAlgorithm,
) -> bool:
    """Verify a signature. Returns True on valid, False on any failure. Never raises."""
    try:
        return as_provider(public_key).verify(canonical_bytes, signature_b64, algorithm)
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

    # 2. Guard non-dict trust block (e.g. {"trust": "x"})
    if not isinstance(trust, dict):
        errors.append("trust block must be a dict")
        return VerificationResult(
            valid=False,
            digest_match=False,
            signature_valid=False,
            algorithm_supported=False,
            canonicalization_valid=False,
            errors=errors,
        )

    # 3. Extract fields from trust block
    signing_algorithm_raw = trust.get("signing_algorithm")
    stored_digest = trust.get("digest")
    stored_signature = trust.get("signature")
    if not isinstance(stored_signature, str):
        errors.append("missing or invalid signature")
        return VerificationResult(
            valid=False,
            digest_match=digest_match,
            signature_valid=False,
            algorithm_supported=algorithm_supported,
            canonicalization_valid=canonicalization_valid,
            errors=errors,
        )

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

    # 4. Verify algorithm is known
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

    # 5. Re-canonicalize: payload minus trust, plus protected trust fields (minus self-refs)
    _SELF_REF = {"digest", "signature"}
    try:
        payload_without_trust = {k: v for k, v in payload.items() if k != "trust"}
        trust_protected = {k: v for k, v in trust.items() if k not in _SELF_REF}
        signing_payload = {**payload_without_trust, "trust": trust_protected}
        canonical_bytes = canonicalize_snapshot(signing_payload)
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

    # 6. Recompute digest
    computed_digest = generate_digest(canonical_bytes)

    # 7. Compare digests
    if computed_digest == stored_digest:
        digest_match = True
    else:
        errors.append("digest mismatch")

    # 8. Verify signature
    signature_valid = verify_payload(
        canonical_bytes, stored_signature, public_key, algorithm
    )
    if not signature_valid:
        errors.append("signature verification failed")

    # 9. Compare against expected_digest if provided
    if expected_digest is not None and computed_digest != expected_digest:
        errors.append("digest does not match expected_digest")
        digest_match = False

    # 10. Compute overall validity
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
    # Build protected trust metadata (everything except self-referential digest/signature)
    trust_meta: dict[str, Any] = {
        "schema_version": CGIN_SCHEMA_VERSION,
        "signing_algorithm": algorithm.value,
        "fingerprint_algorithm": ACTIVE_FINGERPRINT_ALGORITHM.value,
        "created_at": datetime.now(tz=timezone.utc).isoformat(),
        "authority_version": authority_version,
        "trust_version": trust_version,
        "canonicalization_version": canonicalization_version,
    }

    if previous_snapshot_digest is not None:
        trust_meta["previous_snapshot_digest"] = previous_snapshot_digest

    # Sign payload + protected trust metadata so those fields are tamper-evident
    signing_payload = {**payload_without_trust, "trust": trust_meta}
    canonical_bytes = canonicalize_snapshot(signing_payload)
    digest = generate_digest(canonical_bytes)
    signature = sign_payload(canonical_bytes, private_key)

    return {**trust_meta, "digest": digest, "signature": signature}
