"""Ed25519 report signing and verification for governance report artifacts.

Key material is loaded exclusively from the FG_REPORT_SIGNING_KEY environment
variable. Missing or malformed key material raises a specific exception — signing
never silently no-ops.

Signing target: canonical report JSON string produced by
services.governance.report.serialization.serialize_for_manifest().

Security invariants:
- Private key material is never logged or included in any response.
- Missing key raises ReportSigningKeyError (not a silent fallback).
- Invalid key material raises ReportSigningKeyError.
- Verification failure returns False (does not raise).
- Verification internal errors never leak key material.
"""

from __future__ import annotations

import hashlib
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_ENV_KEY = "FG_REPORT_SIGNING_KEY"


class ReportSigningKeyError(RuntimeError):
    """Raised when signing key material is missing or invalid."""


def _load_private_key_bytes() -> bytes:
    raw = (os.getenv(_ENV_KEY) or "").strip()
    if not raw:
        raise ReportSigningKeyError(
            f"{_ENV_KEY} is required for report signing but is not set"
        )
    try:
        key_bytes = bytes.fromhex(raw)
    except ValueError as exc:
        raise ReportSigningKeyError(
            f"{_ENV_KEY} must be a 64-character hex-encoded Ed25519 seed"
        ) from exc
    if len(key_bytes) != 32:
        raise ReportSigningKeyError(
            f"{_ENV_KEY} must decode to exactly 32 bytes (got {len(key_bytes)})"
        )
    return key_bytes


def _derive_public_key_bytes(private_bytes: bytes) -> bytes:
    priv = Ed25519PrivateKey.from_private_bytes(private_bytes)
    pub = priv.public_key()
    return pub.public_bytes_raw()


def sign_report(canonical_json: str) -> str:
    """Sign canonical report JSON with Ed25519; return hex-encoded signature.

    Raises ReportSigningKeyError if FG_REPORT_SIGNING_KEY is missing or invalid.
    The signing target is the SHA-256 digest of the canonical JSON bytes.
    """
    key_bytes = _load_private_key_bytes()
    priv = Ed25519PrivateKey.from_private_bytes(key_bytes)
    digest = hashlib.sha256(canonical_json.encode("utf-8")).digest()
    sig = priv.sign(digest)
    return sig.hex()


def verify_report(canonical_json: str, signature: str) -> bool:
    """Verify an Ed25519 hex signature over canonical report JSON.

    Returns True if the signature is valid, False otherwise.
    Raises ReportSigningKeyError if the signing key is missing or invalid
    (private-key-only verification limitation: public key is derived from private).
    """
    try:
        sig_bytes = bytes.fromhex(signature)
    except (ValueError, TypeError):
        return False

    priv_bytes = _load_private_key_bytes()
    pub_bytes = _derive_public_key_bytes(priv_bytes)

    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
    except ValueError:
        return False

    digest = hashlib.sha256(canonical_json.encode("utf-8")).digest()
    try:
        pub.verify(sig_bytes, digest)
        return True
    except InvalidSignature:
        return False
