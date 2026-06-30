"""services/report_authority/signature.py

Report signing utilities. Reuses platform key management patterns.
Produces deterministic signatures where the signing algorithm supports it.
"""

from __future__ import annotations

import hashlib
import hmac
import os

SIGNING_ALGORITHM = "HMAC-SHA256"


def sign_payload(payload_bytes: bytes, signing_key: bytes | None = None) -> str:
    """Sign payload bytes with HMAC-SHA256. Returns hex-encoded signature.

    If no key is provided the function derives one from the environment.
    In production this should delegate to the Key Management Authority.
    """
    key = signing_key or _get_default_key()
    h = hmac.new(key, payload_bytes, hashlib.sha256)
    return h.hexdigest()


def verify_signature(
    payload_bytes: bytes,
    signature: str,
    signing_key: bytes | None = None,
) -> bool:
    """Verify an HMAC-SHA256 signature. Returns True if the signature is valid.

    Uses hmac.compare_digest to prevent timing-side-channel attacks.
    """
    key = signing_key or _get_default_key()
    h = hmac.new(key, payload_bytes, hashlib.sha256)
    expected = h.hexdigest()
    return hmac.compare_digest(expected, signature)


def _get_default_key() -> bytes:
    """Derive a signing key from the environment.

    This is a development fallback only. Production deployments must set
    REPORT_SIGNING_KEY to a secret managed by the Key Management Authority.
    """
    raw = os.environ.get(
        "REPORT_SIGNING_KEY",
        "frostgate-report-authority-dev-key-v1",
    )
    return hashlib.sha256(raw.encode()).digest()
