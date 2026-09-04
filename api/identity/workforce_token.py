"""fgwi1.* workforce invitation acceptance token.

Mirrors the portal_user_authority token pattern: 256-bit entropy,
HMAC-SHA256 fingerprint with FG_KEY_PEPPER, plaintext never persisted.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets

_PREFIX = "fgwi1."


def generate() -> tuple[str, str]:
    """Return (raw_token, fingerprint). raw_token is single-use; only fingerprint is stored."""
    hex_ = secrets.token_hex(32)
    raw = _PREFIX + hex_
    fp = _fingerprint(hex_)
    return raw, fp


def fingerprint_for(raw_token: str) -> str | None:
    """Compute fingerprint from raw token. Returns None if prefix is wrong."""
    if not raw_token.startswith(_PREFIX):
        return None
    return _fingerprint(raw_token[len(_PREFIX):])


def _fingerprint(hex_: str) -> str:
    pepper = (os.getenv("FG_KEY_PEPPER") or "").encode()
    return hmac.new(pepper, hex_.encode(), hashlib.sha256).hexdigest()
