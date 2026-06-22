"""Ed25519 report signing and verification for governance report artifacts.

Key material is loaded from environment variables:
  FG_REPORT_SIGNING_KEY       — 64-char hex Ed25519 private key seed (required for signing)
  FG_REPORT_SIGNING_PUBLIC_KEY — 64-char hex Ed25519 public key (sufficient for verification)

Verification-only deployments (e.g. external auditors, client portals) may set only
FG_REPORT_SIGNING_PUBLIC_KEY. They can verify signatures without ever possessing the
private key. The public key is retrievable from GET /signing/public-key.

Security invariants:
- Private key material is never logged or included in any response.
- Missing signing key raises ReportSigningKeyError (not a silent fallback).
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
_ENV_PUBLIC_KEY = "FG_REPORT_SIGNING_PUBLIC_KEY"


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


def get_public_key_hex() -> str:
    """Return the hex-encoded Ed25519 public key for this server.

    Checks FG_REPORT_SIGNING_PUBLIC_KEY first (verification-only deployments).
    Falls back to deriving the public key from FG_REPORT_SIGNING_KEY.
    Raises ReportSigningKeyError if neither variable is configured.
    """
    pub_raw = (os.getenv(_ENV_PUBLIC_KEY) or "").strip()
    if pub_raw:
        try:
            pub_bytes = bytes.fromhex(pub_raw)
        except ValueError as exc:
            raise ReportSigningKeyError(
                f"{_ENV_PUBLIC_KEY} must be a 64-character hex-encoded Ed25519 public key"
            ) from exc
        if len(pub_bytes) != 32:
            raise ReportSigningKeyError(
                f"{_ENV_PUBLIC_KEY} must decode to exactly 32 bytes (got {len(pub_bytes)})"
            )
        return pub_raw
    # Derive from private key
    priv_bytes = _load_private_key_bytes()
    return _derive_public_key_bytes(priv_bytes).hex()


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

    Prefers FG_REPORT_SIGNING_PUBLIC_KEY for verification so callers without
    the private key can still validate signatures independently.
    Returns True if the signature is valid, False otherwise.
    Raises ReportSigningKeyError if neither key variable is configured.
    """
    try:
        sig_bytes = bytes.fromhex(signature)
    except (ValueError, TypeError):
        return False

    pub_hex = get_public_key_hex()
    try:
        pub_bytes = bytes.fromhex(pub_hex)
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
    except (ValueError, TypeError):
        return False

    digest = hashlib.sha256(canonical_json.encode("utf-8")).digest()
    try:
        pub.verify(sig_bytes, digest)
        return True
    except InvalidSignature:
        return False
