from __future__ import annotations

import logging
import os
import re
import time
from typing import Optional, Tuple

from api.config.env import is_production_env

log = logging.getLogger("frostgate")


def _is_production_env() -> bool:
    return is_production_env()


def _env_bool_auth(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def _is_key_expired(payload: Optional[dict], now: Optional[int] = None) -> bool:
    """Check if key is expired based on token payload."""
    if payload is None:
        return False  # Legacy keys without payload are not expired by this check

    exp = payload.get("exp")
    if exp is None:
        return False  # No expiration set

    now_ts = now if now is not None else int(time.time())
    return now_ts > int(exp)


def _validate_tenant_id(tenant_id: str) -> Tuple[bool, str]:
    """
    Validate tenant_id format for security.
    Returns (is_valid, error_message).
    """
    if tenant_id is None:
        return True, ""

    tenant_id = str(tenant_id).strip()
    if not tenant_id:
        return True, ""

    if len(tenant_id) > 128:
        return False, "tenant_id exceeds maximum length"

    if not re.match(r"^[a-zA-Z0-9_-]+$", tenant_id):
        return False, "tenant_id contains invalid characters"

    return True, ""
