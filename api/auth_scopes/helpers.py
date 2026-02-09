from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
from typing import Optional, Set

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from api.config.env import is_production_env

log = logging.getLogger("frostgate")


def _b64url(b: bytes) -> str:
    """Base64url encode bytes, no padding."""
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _b64url_json(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _get_key_pepper() -> str:
    pepper = (os.getenv("FG_KEY_PEPPER") or "").strip()
    if pepper:
        return pepper
    if is_production_env():
        raise RuntimeError("FG_KEY_PEPPER is required in production")
    log.warning("FG_KEY_PEPPER not set; using dev default pepper")
    return "dev-unsafe-pepper"


def _key_lookup_hash(secret: str, pepper: str) -> str:
    return hmac.new(
        pepper.encode("utf-8"), secret.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def _argon2_params() -> dict[str, int]:
    return {
        "time_cost": int(os.getenv("FG_KEY_HASH_TIME_COST", "2")),
        "memory_cost": int(os.getenv("FG_KEY_HASH_MEMORY_KIB", "65536")),
        "parallelism": int(os.getenv("FG_KEY_HASH_PARALLELISM", "1")),
        "hash_len": int(os.getenv("FG_KEY_HASH_HASH_LEN", "32")),
        "salt_len": int(os.getenv("FG_KEY_HASH_SALT_LEN", "16")),
    }


def _argon2_hasher(params: Optional[dict[str, int]] = None) -> PasswordHasher:
    p = params or _argon2_params()
    return PasswordHasher(
        time_cost=p["time_cost"],
        memory_cost=p["memory_cost"],
        parallelism=p["parallelism"],
        hash_len=p["hash_len"],
        salt_len=p["salt_len"],
    )


def hash_key(secret: str) -> tuple[str, str, dict[str, int], str]:
    pepper = _get_key_pepper()
    params = _argon2_params()
    hasher = _argon2_hasher(params)
    hashed = hasher.hash(f"{secret}:{pepper}")
    lookup = _key_lookup_hash(secret, pepper)
    return hashed, "argon2id", params, lookup


def verify_key(secret: str, stored_hash: str, hash_alg: Optional[str]) -> bool:
    if hash_alg == "argon2id":
        try:
            pepper = _get_key_pepper()
            hasher = _argon2_hasher()
            return hasher.verify(stored_hash, f"{secret}:{pepper}")
        except VerifyMismatchError:
            return False
        except Exception:
            log.exception("argon2 verify failed")
            return False
    return _constant_time_compare(_sha256_hex(secret), stored_hash)


def _constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _decode_token_payload(token: str) -> Optional[dict]:
    """Decode base64url-encoded token payload, return None on failure."""
    try:
        padding = 4 - (len(token) % 4)
        if padding != 4:
            token += "=" * padding
        raw = base64.urlsafe_b64decode(token)
        return json.loads(raw)
    except Exception:
        return None


def _parse_scopes_csv(val) -> Set[str]:
    if not val:
        return set()
    if isinstance(val, (list, tuple, set)):
        return {str(x).strip() for x in val if str(x).strip()}
    s = str(val).strip()
    if not s:
        return set()
    return {x.strip() for x in s.split(",") if x.strip()}
