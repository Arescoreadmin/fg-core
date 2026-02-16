from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class AuditSigningError(RuntimeError):
    pass


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def utc_rfc3339(ts: datetime | None = None) -> str:
    v = ts or datetime.now(tz=UTC)
    if v.tzinfo is None:
        v = v.replace(tzinfo=UTC)
    v = v.astimezone(UTC)
    return v.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _b64decode(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


def _load_json_env_or_file(env_name: str, file_env_name: str) -> dict[str, str]:
    raw = (os.getenv(env_name) or "").strip()
    if raw:
        return json.loads(raw)
    p = (os.getenv(file_env_name) or "").strip()
    if p:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    return {}


def _hmac_keys() -> list[str]:
    raw = (os.getenv("FG_AUDIT_HMAC_KEYS") or "").strip()
    if raw:
        return [x.strip() for x in raw.split(",") if x.strip()]
    return [(os.getenv("FG_API_KEY") or "dev-audit-key")]


def sign_hmac(payload: bytes) -> tuple[str, str]:
    kid = (os.getenv("FG_AUDIT_HMAC_ACTIVE_KID") or "hmac-active").strip()
    key = _hmac_keys()[0].encode("utf-8")
    return kid, hmac.new(key, payload, hashlib.sha256).hexdigest()


def verify_hmac(payload: bytes, signature: str) -> bool:
    for k in _hmac_keys():
        expected = hmac.new(k.encode("utf-8"), payload, hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, signature):
            return True
    return False


@dataclass(frozen=True)
class Ed25519Keyset:
    active_kid: str
    private_keys: dict[str, Ed25519PrivateKey]
    public_keys: dict[str, Ed25519PublicKey]


_def_empty_keyset = Ed25519Keyset(active_kid="", private_keys={}, public_keys={})


def load_ed25519_keyset() -> Ed25519Keyset:
    active_kid = (os.getenv("FG_AUDIT_ED25519_ACTIVE_KID") or "").strip()
    priv_map_raw = _load_json_env_or_file(
        "FG_AUDIT_ED25519_PRIVATE_KEYS_JSON", "FG_AUDIT_ED25519_PRIVATE_KEYS_FILE"
    )
    pub_map_raw = _load_json_env_or_file(
        "FG_AUDIT_ED25519_PUBLIC_KEYS_JSON", "FG_AUDIT_ED25519_PUBLIC_KEYS_FILE"
    )
    if not active_kid and priv_map_raw:
        active_kid = sorted(priv_map_raw.keys())[0]

    if not priv_map_raw and not pub_map_raw:
        return _def_empty_keyset

    priv_map: dict[str, Ed25519PrivateKey] = {}
    for kid, b64 in priv_map_raw.items():
        raw = _b64decode(str(b64))
        if len(raw) != 32:
            raise AuditSigningError("FG-AUDIT-SIGN-001:invalid_private_key_length")
        priv_map[str(kid)] = Ed25519PrivateKey.from_private_bytes(raw)

    pub_map: dict[str, Ed25519PublicKey] = {}
    for kid, b64 in pub_map_raw.items():
        raw = _b64decode(str(b64))
        if len(raw) != 32:
            raise AuditSigningError("FG-AUDIT-SIGN-002:invalid_public_key_length")
        pub_map[str(kid)] = Ed25519PublicKey.from_public_bytes(raw)

    for kid, priv in priv_map.items():
        if kid not in pub_map:
            pub_map[kid] = priv.public_key()

    if active_kid and active_kid not in priv_map:
        raise AuditSigningError("FG-AUDIT-SIGN-003:active_kid_missing_private_key")

    return Ed25519Keyset(active_kid=active_kid, private_keys=priv_map, public_keys=pub_map)


def verification_kids() -> set[str]:
    kids: set[str] = set()
    active = (os.getenv("FG_AUDIT_ED25519_ACTIVE_KID") or "").strip()
    if active:
        kids.add(active)
    prev = (os.getenv("FG_AUDIT_ED25519_PREV_KIDS") or "").strip()
    if prev:
        kids.update({k.strip() for k in prev.split(",") if k.strip()})
    return kids


def export_signing_mode() -> str:
    mode = (os.getenv("FG_AUDIT_EXPORT_SIGNING_MODE") or "hmac").strip().lower()
    if mode not in {"hmac", "ed25519"}:
        raise AuditSigningError("FG-AUDIT-SIGN-004:unsupported_signing_mode")
    return mode


def sign_manifest_payload(payload: dict[str, Any], *, signed_at: str | None = None) -> dict[str, str]:
    mode = export_signing_mode()
    payload_b = canonical_json_bytes(payload)
    signed_at = signed_at or utc_rfc3339()

    if mode == "ed25519":
        keyset = load_ed25519_keyset()
        if not keyset.active_kid:
            raise AuditSigningError("FG-AUDIT-SIGN-005:missing_active_kid")
        key = keyset.private_keys.get(keyset.active_kid)
        if key is None:
            raise AuditSigningError("FG-AUDIT-SIGN-006:private_key_not_found")
        sig = key.sign(payload_b)
        return {
            "signature_algo": "ed25519",
            "kid": keyset.active_kid,
            "signed_at": signed_at,
            "signature": base64.b64encode(sig).decode("utf-8"),
        }

    kid, sig = sign_hmac(payload_b)
    return {
        "signature_algo": "hmac-sha256",
        "kid": kid,
        "signed_at": signed_at,
        "signature": sig,
    }


def verify_manifest_signature(payload: dict[str, Any], *, signature_algo: str, kid: str, signature: str) -> bool:
    payload_b = canonical_json_bytes(payload)
    algo = signature_algo.strip().lower()
    if algo == "hmac-sha256":
        return verify_hmac(payload_b, signature)
    if algo == "ed25519":
        keyset = load_ed25519_keyset()
        allowed = verification_kids()
        if allowed and kid not in allowed:
            return False
        pub = keyset.public_keys.get(kid)
        if pub is None:
            return False
        try:
            pub.verify(base64.b64decode(signature.encode("utf-8")), payload_b)
            return True
        except Exception:
            return False
    return False
