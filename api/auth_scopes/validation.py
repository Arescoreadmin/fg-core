from __future__ import annotations

import logging
import os
import re
import sqlite3
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


def _validate_tenant_id(tenant_id: Optional[str]) -> Tuple[bool, str]:
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


def _check_db_expiration(
    sqlite_path: str,
    prefix: str,
    identifier_col: str,
    identifier: Optional[str] = None,
) -> bool:
    """
    Check if key is expired based on DB expires_at column.
    Returns True if expired (deny), False if not expired or no expiration set (allow).

    P0: Fail-closed by default - DB errors return True (expired = deny).

    INV-003: Fail-open behavior:
      - In prod/staging: requires BOTH
          FG_AUTH_DB_FAIL_OPEN=true
          FG_AUTH_DB_FAIL_OPEN_ACKNOWLEDGED=true
        otherwise deny.
      - In dev/test: FG_AUTH_DB_FAIL_OPEN=true is sufficient (no ack required).
    """
    try:
        con = sqlite3.connect(sqlite_path)
        try:
            cols = con.execute("PRAGMA table_info(api_keys)").fetchall()
            col_names = {r[1] for r in cols}

            if "expires_at" not in col_names:
                return False

            if identifier is None:
                identifier = identifier_col
                identifier_col = "key_hash"

            if identifier_col not in col_names:
                return True

            row = con.execute(
                f"SELECT expires_at FROM api_keys WHERE prefix=? AND {identifier_col}=? LIMIT 1",
                (prefix, identifier),
            ).fetchone()

            if not row or row[0] is None:
                return False

            expires_at = row[0]
            now_ts = int(time.time())

            if isinstance(expires_at, (int, float)):
                return now_ts > int(expires_at)

            if isinstance(expires_at, str):
                try:
                    from datetime import datetime

                    dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                    return now_ts > int(dt.timestamp())
                except Exception:
                    log.warning(
                        "SECURITY: Failed to parse expires_at=%r for key prefix=%s, treating as expired",
                        expires_at,
                        prefix,
                    )
                    return True

            return False
        finally:
            con.close()

    except Exception as e:
        fail_open = _env_bool_auth("FG_AUTH_DB_FAIL_OPEN", False)
        ack = _env_bool_auth("FG_AUTH_DB_FAIL_OPEN_ACKNOWLEDGED", False)

        if fail_open:
            if _is_production_env() and not ack:
                log.critical(
                    "SECURITY: DB expiration check fail-open requested but NOT ACKNOWLEDGED - DENYING (fail-closed). "
                    "To allow fail-open in prod/staging, set FG_AUTH_DB_FAIL_OPEN_ACKNOWLEDGED=true. "
                    "Error: %s, Prefix: %s",
                    e,
                    prefix,
                )
                return True  # deny (treat as expired)

            # dev/test OR acknowledged prod
            log.error(
                "SECURITY: DB expiration check failed - FAIL-OPEN enabled, allowing request. "
                "Error: %s, Prefix: %s",
                e,
                prefix,
            )
            return False  # allow (treat as not expired)

        log.error(
            "SECURITY: DB expiration check failed - denying request (fail-closed). "
            "Error: %s, Prefix: %s",
            e,
            prefix,
        )
        return True  # deny (treat as expired)
