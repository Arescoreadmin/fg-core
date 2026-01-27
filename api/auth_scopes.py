from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from typing import Callable, Optional, Set, Tuple
from api.db import _resolve_sqlite_path

from fastapi import Depends, Header, HTTPException, Request
from api.db import init_db

import logging

log = logging.getLogger("frostgate")
_security_log = logging.getLogger("frostgate.security")


def _b64url(b: bytes) -> str:
    """Base64url encode bytes, no padding."""
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


ERR_INVALID = "Invalid or missing API key"
DEFAULT_TTL_SECONDS = 24 * 3600


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _decode_token_payload(token: str) -> Optional[dict]:
    """Decode base64url-encoded token payload, return None on failure."""
    try:
        # Add padding if needed
        padding = 4 - (len(token) % 4)
        if padding != 4:
            token += "=" * padding
        raw = base64.urlsafe_b64decode(token)
        return json.loads(raw)
    except Exception:
        return None


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

    # Max length check
    if len(tenant_id) > 128:
        return False, "tenant_id exceeds maximum length"

    # Alphanumeric, dash, underscore only (prevent injection)
    if not re.match(r"^[a-zA-Z0-9_-]+$", tenant_id):
        return False, "tenant_id contains invalid characters"

    return True, ""


def _log_auth_event(
    event_type: str,
    success: bool,
    key_prefix: Optional[str] = None,
    tenant_id: Optional[str] = None,
    reason: Optional[str] = None,
    request_path: Optional[str] = None,
    client_ip: Optional[str] = None,
) -> None:
    """Log security-relevant authentication events."""
    log_data = {
        "event": event_type,
        "success": success,
        "key_prefix": key_prefix[:8] if key_prefix else None,
        "tenant_id": tenant_id,
        "reason": reason,
        "path": request_path,
        "client_ip": client_ip,
        "timestamp": int(time.time()),
    }

    if success:
        _security_log.info("auth_event", extra=log_data)
    else:
        _security_log.warning("auth_event", extra=log_data)


def _b64url_json(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _parse_scopes_csv(val) -> Set[str]:
    if not val:
        return set()
    if isinstance(val, (list, tuple, set)):
        return {str(x).strip() for x in val if str(x).strip()}
    s = str(val).strip()
    if not s:
        return set()
    return {x.strip() for x in s.split(",") if x.strip()}


def _extract_key(request: Request, x_api_key: Optional[str]) -> Optional[str]:
    # Header first
    if x_api_key and str(x_api_key).strip():
        return str(x_api_key).strip()

    # Cookie (UI)
    cookie_name = (
        os.getenv("FG_UI_COOKIE_NAME") or "fg_api_key"
    ).strip() or "fg_api_key"
    ck = (request.cookies.get(cookie_name) or "").strip()
    if ck:
        return ck

    # Query (dev convenience)
    qp = request.query_params
    qk = (qp.get("api_key") or qp.get("key") or "").strip()
    if qk:
        return qk

    return None


def mint_key(
    *scopes: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    tenant_id: Optional[str] = None,
    now: Optional[int] = None,
    secret: Optional[str] = None,
) -> str:
    """
    Mint a key and persist it into sqlite table `api_keys`:
      api_keys(prefix, key_hash, scopes_csv, enabled)

    Returned key format (NEW):
      <prefix>.<token>.<secret>

    Where:
      key_hash stored = sha256(secret)
      token is base64url(json payload)
    """
    sqlite_path = (os.getenv("FG_SQLITE_PATH") or "").strip()
    if not sqlite_path:
        sqlite_path = str(_resolve_sqlite_path())

    # Ensure schema exists in the exact sqlite file (safe/idempotent).
    # This prevents "no such table: api_keys/decisions" when tests call mint_key early.
    try:
        init_db(sqlite_path=sqlite_path)
    except Exception:
        # Best effort: mint_key should still fail later if DB truly unusable,
        # but schema init errors shouldn't crash import-time.
        log.exception("init_db failed in mint_key (best effort)")

    now_i = int(now) if now is not None else int(time.time())
    exp_i = now_i + int(ttl_seconds)

    if secret is None:
        secret = secrets.token_urlsafe(32)

    prefix = "fgk"
    payload = {
        "scopes": list(scopes),
        "tenant_id": tenant_id,
        "iat": now_i,
        "exp": exp_i,
    }

    token = _b64url(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    key_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    scopes_csv = ",".join(scopes)

    # Persist key into sqlite (schema-aware)
    con = sqlite3.connect(sqlite_path)
    try:
        cols = con.execute("PRAGMA table_info(api_keys)").fetchall()
        # (cid, name, type, notnull, dflt_value, pk)
        names = [r[1] for r in cols]
        notnull = {r[1] for r in cols if int(r[3] or 0) == 1 and r[4] is None}

        values = {
            "prefix": prefix,
            "key_hash": key_hash,
            "scopes_csv": scopes_csv,
            "enabled": 1,
        }

        # Newer schema requires name (NOT NULL)
        if "name" in names:
            values["name"] = "minted:" + (scopes_csv or "none")

        # Optional schema evolution support
        if "tenant_id" in names:
            values["tenant_id"] = tenant_id
        if "created_at" in names and "created_at" in notnull:
            values["created_at"] = now_i

        # SaaS schema evolution - version and use_count (NOT NULL with defaults)
        if "version" in names:
            values["version"] = 1
        if "use_count" in names:
            values["use_count"] = 0

        ordered = [
            c
            for c in (
                "name",
                "prefix",
                "key_hash",
                "scopes_csv",
                "tenant_id",
                "created_at",
                "enabled",
                "version",
                "use_count",
            )
            if c in names and c in values
        ]
        if not ordered:
            raise RuntimeError("api_keys table has no usable columns for insert")

        qcols = ",".join(ordered)
        qmarks = ",".join(["?"] * len(ordered))
        params = tuple(values[c] for c in ordered)
        con.execute(f"INSERT INTO api_keys({qcols}) VALUES({qmarks})", params)
        con.commit()
    finally:
        con.close()

    return f"{prefix}.{token}.{secret}"


def verify_api_key_raw(
    raw: Optional[str] = None,
    required_scopes=None,
    raw_key: Optional[str] = None,
    db=None,
    check_expiration: bool = True,
    **_ignored,
) -> bool:
    """
    Verifies:
      1) Global FG_API_KEY matches exactly (constant-time comparison)
      2) DB-backed keys in sqlite `api_keys` table

    Supports TWO DB key formats:
      A) NEW: <prefix>.<token>.<secret>
         - prefix stored as `prefix`
         - key_hash stored = sha256(secret)
         - token contains expiration info
      B) LEGACY (tests): raw="TEST_<uuidhex>" (no dots)
         - prefix stored = raw[:16]
         - key_hash stored = api.db_models.hash_api_key(raw)

    Security features:
      - Constant-time comparison to prevent timing attacks
      - Token expiration checking
      - Audit logging for failed attempts
    """
    raw = (raw or raw_key or "").strip()

    # 1) global key bypass (constant-time comparison)
    global_key = (os.getenv("FG_API_KEY") or "").strip()
    if raw and global_key and _constant_time_compare(raw, global_key):
        _log_auth_event("global_key_auth", success=True)
        return True

    if not raw:
        _log_auth_event("auth_attempt", success=False, reason="no_key_provided")
        return False

    sqlite_path = (os.getenv("FG_SQLITE_PATH") or "").strip()
    if not sqlite_path:
        _log_auth_event("auth_attempt", success=False, reason="no_db_configured")
        return False

    def _row_for(prefix: str, key_hash: str):
        con = sqlite3.connect(sqlite_path)
        try:
            try:
                return con.execute(
                    "select scopes_csv, enabled from api_keys where prefix=? and key_hash=? limit 1",
                    (prefix, key_hash),
                ).fetchone()
            except sqlite3.OperationalError:
                return None
        finally:
            con.close()

    scopes_csv = None
    enabled = None
    token_payload = None
    key_prefix = None

    parts = raw.split(".")
    if len(parts) >= 3:
        # NEW: prefix.token.secret
        key_prefix = parts[0]
        token = parts[1] if len(parts) > 1 else ""
        secret_val = parts[-1]

        # Decode token to check expiration
        token_payload = _decode_token_payload(token)

        # Check expiration before DB lookup (fail fast)
        if check_expiration and _is_key_expired(token_payload):
            _log_auth_event(
                "auth_attempt",
                success=False,
                key_prefix=key_prefix,
                reason="key_expired",
            )
            return False

        row = _row_for(key_prefix, _sha256_hex(secret_val))
        if row:
            scopes_csv, enabled = row
    else:
        # LEGACY: raw key stored hashed by api.db_models.hash_api_key(raw), prefix=raw[:16]
        key_prefix = raw[:16]
        try:
            from api.db_models import (
                hash_api_key as _hash_api_key,
            )  # matches tests/_mk_test_key.py

            legacy_hash = _hash_api_key(raw)
        except Exception:
            # fallback to something deterministic; shouldn't be needed if api.db_models exists
            legacy_hash = _sha256_hex(raw)

        row = _row_for(key_prefix, legacy_hash)
        if row:
            scopes_csv, enabled = row

    if scopes_csv is None or enabled is None:
        _log_auth_event(
            "auth_attempt",
            success=False,
            key_prefix=key_prefix,
            reason="key_not_found",
        )
        return False

    if not int(enabled):
        _log_auth_event(
            "auth_attempt",
            success=False,
            key_prefix=key_prefix,
            reason="key_disabled",
        )
        return False

    # Scope enforcement (if requested)
    if required_scopes is None:
        _log_auth_event("auth_attempt", success=True, key_prefix=key_prefix)
        return True

    needed = (
        set(required_scopes)
        if isinstance(required_scopes, (set, list, tuple))
        else {str(required_scopes)}
    )
    needed = {s.strip() for s in needed if str(s).strip()}
    if not needed:
        _log_auth_event("auth_attempt", success=True, key_prefix=key_prefix)
        return True

    have = _parse_scopes_csv(scopes_csv)
    if "*" in have:
        _log_auth_event("auth_attempt", success=True, key_prefix=key_prefix)
        return True

    if needed.issubset(have):
        _log_auth_event("auth_attempt", success=True, key_prefix=key_prefix)
        return True

    _log_auth_event(
        "auth_attempt",
        success=False,
        key_prefix=key_prefix,
        reason=f"missing_scopes:{','.join(needed - have)}",
    )
    return False


def require_api_key_always(
    request: Request,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    required_scopes: Set[str] | None = None,
) -> str:
    got = _extract_key(request, x_api_key)
    if not got:
        raise HTTPException(status_code=401, detail=ERR_INVALID)

    if not verify_api_key_raw(got, required_scopes=required_scopes):
        raise HTTPException(status_code=401, detail=ERR_INVALID)

    return got


def verify_api_key(
    request: Request,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> str:
    # compatibility dep expected by modules
    return require_api_key_always(request, x_api_key, required_scopes=None)


def require_scopes(*scopes: str) -> Callable[..., None]:
    """
    Returns a dependency that enforces the provided scopes.

    IMPORTANT: No untyped lambda params.
    If you use `lambda request, ...` without type hints, FastAPI may treat `request`
    as a query param and you'll see: {"loc":["query","request"],"msg":"Field required"}.
    """
    needed: Set[str] = {str(s).strip() for s in scopes if str(s).strip()}

    if not needed:

        def _noop() -> None:
            return None

        return _noop

    def _scoped_key_dep(
        request: Request,
        x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    ) -> str:
        return require_api_key_always(request, x_api_key, required_scopes=needed)

    def _dep(_: str = Depends(_scoped_key_dep)) -> None:
        return None

    return _dep


def revoke_api_key(key_prefix: str, key_hash: Optional[str] = None) -> bool:
    """
    Revoke (disable) an API key by prefix and optionally key_hash.
    Returns True if key was found and disabled, False otherwise.
    """
    sqlite_path = (os.getenv("FG_SQLITE_PATH") or "").strip()
    if not sqlite_path:
        return False

    con = sqlite3.connect(sqlite_path)
    try:
        if key_hash:
            cur = con.execute(
                "UPDATE api_keys SET enabled=0 WHERE prefix=? AND key_hash=?",
                (key_prefix, key_hash),
            )
        else:
            cur = con.execute(
                "UPDATE api_keys SET enabled=0 WHERE prefix=?",
                (key_prefix,),
            )
        con.commit()
        revoked = cur.rowcount > 0
        if revoked:
            _log_auth_event(
                "key_revoked",
                success=True,
                key_prefix=key_prefix,
            )
        return revoked
    except Exception:
        log.exception("Failed to revoke API key")
        return False
    finally:
        con.close()


def list_api_keys(
    tenant_id: Optional[str] = None,
    include_disabled: bool = False,
) -> list[dict]:
    """
    List API keys (prefix, name, scopes, enabled, created_at).
    Never returns the actual key hash or secret.
    """
    sqlite_path = (os.getenv("FG_SQLITE_PATH") or "").strip()
    if not sqlite_path:
        return []

    con = sqlite3.connect(sqlite_path)
    try:
        # Check what columns exist
        cols = con.execute("PRAGMA table_info(api_keys)").fetchall()
        col_names = {r[1] for r in cols}

        select_cols = ["prefix", "scopes_csv", "enabled"]
        if "name" in col_names:
            select_cols.insert(1, "name")
        if "created_at" in col_names:
            select_cols.append("created_at")
        if "tenant_id" in col_names:
            select_cols.append("tenant_id")

        query = f"SELECT {','.join(select_cols)} FROM api_keys"
        conditions = []
        params = []

        if not include_disabled:
            conditions.append("enabled=1")

        if tenant_id and "tenant_id" in col_names:
            conditions.append("tenant_id=?")
            params.append(tenant_id)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        rows = con.execute(query, params).fetchall()

        result = []
        for row in rows:
            item = dict(zip(select_cols, row))
            # Parse scopes_csv to list
            scopes_csv = item.get("scopes_csv", "")
            item["scopes"] = [
                s.strip() for s in (scopes_csv or "").split(",") if s.strip()
            ]
            del item["scopes_csv"]
            result.append(item)

        return result
    except Exception:
        log.exception("Failed to list API keys")
        return []
    finally:
        con.close()


# Export validation functions for use in other modules
__all__ = [
    "mint_key",
    "verify_api_key_raw",
    "verify_api_key",
    "require_api_key_always",
    "require_scopes",
    "revoke_api_key",
    "list_api_keys",
    "_validate_tenant_id",
    "_log_auth_event",
    "_constant_time_compare",
    "ERR_INVALID",
    "DEFAULT_TTL_SECONDS",
]
