from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

GENESIS_CHAIN_HASH = "0" * 64


def canonical_json(obj: Any) -> bytes:
    def _normalize(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                str(k): _normalize(v)
                for k, v in sorted(value.items(), key=lambda x: str(x[0]))
            }
        if isinstance(value, list):
            return [_normalize(v) for v in value]
        if isinstance(value, tuple):
            return [_normalize(v) for v in value]
        if isinstance(value, datetime):
            ts = value if value.tzinfo else value.replace(tzinfo=UTC)
            return ts.astimezone(UTC).isoformat().replace("+00:00", "Z")
        if isinstance(value, Decimal):
            return float(value)
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        raise TypeError(f"Unsupported canonical json type: {type(value)!r}")

    normalized = _normalize(obj)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_hash(payload: Any) -> str:
    return sha256_hex(canonical_json(payload))


def _decode_b64_key(raw: str) -> bytes:
    try:
        return base64.b64decode(raw, validate=True)
    except Exception as exc:  # pragma: no cover - defensive guard
        raise ValueError("Invalid base64 signing key") from exc


def _private_key_bytes_from_env() -> bytes:
    raw = (os.getenv("FG_EVIDENCE_SIGNING_KEY_B64") or "").strip()
    if not raw:
        raise RuntimeError("FG_EVIDENCE_SIGNING_KEY_B64 is required")
    key = _decode_b64_key(raw)
    if len(key) != 32:
        raise RuntimeError(
            "FG_EVIDENCE_SIGNING_KEY_B64 must decode to 32-byte Ed25519 seed"
        )
    return key


def signing_key_id() -> str:
    key_id = (os.getenv("FG_EVIDENCE_SIGNING_KEY_ID") or "").strip()
    if not key_id:
        raise RuntimeError("FG_EVIDENCE_SIGNING_KEY_ID is required")
    return key_id


def _public_key_from_env(key_id: str) -> bytes:
    specific = os.getenv(f"FG_EVIDENCE_PUBLIC_KEY_B64_{key_id}")
    generic = os.getenv("FG_EVIDENCE_PUBLIC_KEYS_B64")
    if specific:
        key = _decode_b64_key(specific.strip())
        if len(key) != 32:
            raise RuntimeError("Public key must be 32 bytes")
        return key

    if not generic:
        raise RuntimeError("FG_EVIDENCE_PUBLIC_KEYS_B64 is required for verification")

    mapping = json.loads(generic)
    if key_id not in mapping:
        raise RuntimeError(f"No public key configured for key_id={key_id}")
    key = _decode_b64_key(str(mapping[key_id]).strip())
    if len(key) != 32:
        raise RuntimeError("Public key must be 32 bytes")
    return key


def sign_hash(hash_hex: str) -> str:
    digest = bytes.fromhex(hash_hex)
    priv = Ed25519PrivateKey.from_private_bytes(_private_key_bytes_from_env())
    sig = priv.sign(digest)
    return base64.b64encode(sig).decode("ascii")


def verify_hash_signature(
    hash_hex: str, signature_b64: str, key_id: str
) -> tuple[bool, str | None]:
    try:
        digest = bytes.fromhex(hash_hex)
        sig = _decode_b64_key(signature_b64)
        pub = Ed25519PublicKey.from_public_bytes(_public_key_from_env(key_id))
        pub.verify(sig, digest)
        return True, None
    except InvalidSignature:
        return False, "invalid_signature"
    except Exception as exc:
        return False, f"verification_error:{type(exc).__name__}"


def chain_hash(prev_chain_hash: str, entry_hash: str) -> str:
    prev = prev_chain_hash or GENESIS_CHAIN_HASH
    if len(prev) != 64:
        raise ValueError("prev_chain_hash must be 64 hex chars")
    return sha256_hex(bytes.fromhex(prev) + bytes.fromhex(entry_hash))
