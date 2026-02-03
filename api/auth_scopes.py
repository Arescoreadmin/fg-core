from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import time
from typing import Callable, Optional, Set, Tuple

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from fastapi import Depends, Header, HTTPException, Request

from api.config.env import is_production_env
from api.db import _resolve_sqlite_path, init_db

log = logging.getLogger("frostgate")
_security_log = logging.getLogger("frostgate.security")


def _b64url(b: bytes) -> str:
    """Base64url encode bytes, no padding."""
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


ERR_INVALID = "Invalid or missing API key"
DEFAULT_TTL_SECONDS = 24 * 3600


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
    """
    Extract API key from request.

    Security: Keys are ONLY accepted from:
      1. X-API-Key header (preferred)
      2. Cookie (for UI sessions)

    Query parameters are NOT supported.
    """
    if x_api_key and str(x_api_key).strip():
        return str(x_api_key).strip()

    cookie_name = (
        os.getenv("FG_UI_COOKIE_NAME") or "fg_api_key"
    ).strip() or "fg_api_key"
    ck = (request.cookies.get(cookie_name) or "").strip()
    if ck:
        return ck

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
    """
    sqlite_path = (os.getenv("FG_SQLITE_PATH") or "").strip()
    if not sqlite_path:
        sqlite_path = str(_resolve_sqlite_path())

    try:
        init_db(sqlite_path=sqlite_path)
    except Exception:
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
    key_hash, hash_alg, hash_params, key_lookup = hash_key(secret)
    scopes_csv = ",".join(scopes)

    con = sqlite3.connect(sqlite_path)
    try:
        cols = con.execute("PRAGMA table_info(api_keys)").fetchall()
        names = [r[1] for r in cols]
        notnull = {r[1] for r in cols if int(r[3] or 0) == 1 and r[4] is None}

        if (
            "hash_alg" not in names
            or "hash_params" not in names
            or "key_lookup" not in names
        ):
            raise RuntimeError("api_keys schema missing hash columns; run migrations")

        values = {
            "prefix": prefix,
            "key_hash": key_hash,
            "key_lookup": key_lookup,
            "hash_alg": hash_alg,
            "hash_params": json.dumps(
                hash_params, separators=(",", ":"), sort_keys=True
            ),
            "scopes_csv": scopes_csv,
            "enabled": 1,
        }

        if "name" in names:
            values["name"] = "minted:" + (scopes_csv or "none")

        if "tenant_id" in names:
            values["tenant_id"] = tenant_id
        if "created_at" in names and "created_at" in notnull:
            values["created_at"] = now_i
        if "expires_at" in names:
            values["expires_at"] = exp_i

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
                "key_lookup",
                "hash_alg",
                "hash_params",
                "scopes_csv",
                "tenant_id",
                "created_at",
                "expires_at",
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


class AuthResult:
    """Result of API key verification with details for proper status codes."""

    __slots__ = ("valid", "reason", "key_prefix", "tenant_id", "scopes")

    def __init__(
        self,
        valid: bool,
        reason: str = "",
        key_prefix: Optional[str] = None,
        tenant_id: Optional[str] = None,
        scopes: Optional[Set[str]] = None,
    ):
        self.valid = valid
        self.reason = reason
        self.key_prefix = key_prefix
        self.tenant_id = tenant_id
        self.scopes = scopes or set()

    @property
    def is_missing_key(self) -> bool:
        return self.reason == "no_key_provided"

    @property
    def is_invalid_key(self) -> bool:
        return not self.valid and not self.is_missing_key


def _update_key_usage(
    sqlite_path: str, prefix: str, identifier_col: str, identifier: str
) -> None:
    """Atomically update last_used_at and use_count for a key (best effort)."""
    try:
        con = sqlite3.connect(sqlite_path, timeout=5.0)
        try:
            cols = con.execute("PRAGMA table_info(api_keys)").fetchall()
            col_names = {r[1] for r in cols}

            if (
                "last_used_at" in col_names
                and "use_count" in col_names
                and identifier_col in col_names
            ):
                now_ts = int(time.time())
                con.execute(
                    """UPDATE api_keys
                       SET last_used_at = ?, use_count = use_count + 1
                       WHERE prefix = ? AND {col} = ?""".format(col=identifier_col),
                    (now_ts, prefix, identifier),
                )
                con.commit()
        finally:
            con.close()
    except Exception:
        pass


def _env_bool_auth(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


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
            if is_production_env() and not ack:
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


def verify_api_key_raw(
    raw: Optional[str] = None,
    required_scopes=None,
    raw_key: Optional[str] = None,
    db=None,
    check_expiration: bool = True,
    request: Optional[Request] = None,
    **_ignored,
) -> bool:
    result = verify_api_key_detailed(
        raw=raw,
        required_scopes=required_scopes,
        raw_key=raw_key,
        db=db,
        check_expiration=check_expiration,
        request=request,
    )
    return result.valid


def verify_api_key_detailed(
    raw: Optional[str] = None,
    required_scopes=None,
    raw_key: Optional[str] = None,
    db=None,
    check_expiration: bool = True,
    request: Optional[Request] = None,
    **_ignored,
) -> AuthResult:
    request_path = None
    client_ip = None
    if request:
        request_path = str(request.url.path) if request.url else None
        for header in ("x-forwarded-for", "x-real-ip", "cf-connecting-ip"):
            value = request.headers.get(header) if hasattr(request, "headers") else None
            if value:
                client_ip = value.split(",")[0].strip()
                break
        if not client_ip and hasattr(request, "client") and request.client:
            client_ip = request.client.host

    raw = (raw or raw_key or "").strip()

    # 1) global key bypass (constant-time comparison)
    global_key = (os.getenv("FG_API_KEY") or "").strip()
    if raw and global_key and _constant_time_compare(raw, global_key):
        if is_production_env():
            log.warning(
                "FG_API_KEY env key rejected in production path",
                extra={"path": request_path},
            )
            _log_auth_event(
                "global_key_auth",
                success=False,
                reason="env_key_disabled_production",
                request_path=request_path,
                client_ip=client_ip,
            )
            return AuthResult(valid=False, reason="env_key_disabled_production")
        _log_auth_event(
            "global_key_auth",
            success=True,
            request_path=request_path,
            client_ip=client_ip,
        )
        return AuthResult(valid=True, reason="global_key")

    if not raw:
        _log_auth_event(
            "auth_attempt",
            success=False,
            reason="no_key_provided",
            request_path=request_path,
            client_ip=client_ip,
        )
        return AuthResult(valid=False, reason="no_key_provided")

    sqlite_path = (os.getenv("FG_SQLITE_PATH") or "").strip()
    if not sqlite_path:
        _log_auth_event(
            "auth_attempt",
            success=False,
            reason="no_db_configured",
            request_path=request_path,
            client_ip=client_ip,
        )
        return AuthResult(valid=False, reason="no_db_configured")

    def _row_for(prefix: str, lookup_hash: Optional[str], legacy_hash: Optional[str]):
        con = sqlite3.connect(sqlite_path)
        try:
            try:
                cols = con.execute("PRAGMA table_info(api_keys)").fetchall()
                col_names = {r[1] for r in cols}
                base_cols = ["id", "scopes_csv", "enabled", "tenant_id", "key_hash"]
                select_cols = [c for c in base_cols if c in col_names]
                if "hash_alg" in col_names:
                    select_cols.append("hash_alg")
                if "hash_params" in col_names:
                    select_cols.append("hash_params")
                if "key_lookup" in col_names:
                    select_cols.append("key_lookup")

                select_clause = ",".join(select_cols)

                if lookup_hash and "key_lookup" in col_names:
                    row = con.execute(
                        f"SELECT {select_clause} FROM api_keys WHERE prefix=? AND key_lookup=? LIMIT 1",
                        (prefix, lookup_hash),
                    ).fetchone()
                    if row:
                        return dict(zip(select_cols, row)), "key_lookup", col_names

                if legacy_hash:
                    row = con.execute(
                        f"SELECT {select_clause} FROM api_keys WHERE prefix=? AND key_hash=? LIMIT 1",
                        (prefix, legacy_hash),
                    ).fetchone()
                    if row:
                        return dict(zip(select_cols, row)), "key_hash", col_names

                return None, None, col_names
            except sqlite3.OperationalError:
                return None, None, set()
        finally:
            con.close()

    scopes_csv = None
    enabled = None
    tenant_id = None
    token_payload = None
    key_prefix = None
    key_hash = None
    key_lookup = None
    hash_alg = None
    identifier_col = None
    col_names: Set[str] = set()
    secret_for_verify: Optional[str] = None

    parts = raw.split(".")
    if len(parts) >= 3:
        key_prefix = parts[0]
        token = parts[1] if len(parts) > 1 else ""
        secret_val = parts[-1]
        secret_for_verify = secret_val
        try:
            key_lookup = _key_lookup_hash(secret_val, _get_key_pepper())
        except Exception:
            key_lookup = None
        key_hash = _sha256_hex(secret_val)

        try:
            from api.tripwires import check_canary_key

            if check_canary_key(key_prefix):
                _log_auth_event(
                    "canary_token_accessed",
                    success=False,
                    key_prefix=key_prefix,
                    reason="canary_token",
                    request_path=request_path,
                    client_ip=client_ip,
                )
                return AuthResult(
                    valid=False, reason="canary_token", key_prefix=key_prefix
                )
        except ImportError:
            pass

        token_payload = _decode_token_payload(token)

        if check_expiration and _is_key_expired(token_payload):
            _log_auth_event(
                "auth_attempt",
                success=False,
                key_prefix=key_prefix,
                reason="key_expired_token",
                request_path=request_path,
                client_ip=client_ip,
            )
            return AuthResult(
                valid=False, reason="key_expired_token", key_prefix=key_prefix
            )

        row, identifier_col, col_names = _row_for(key_prefix, key_lookup, key_hash)
        if row:
            scopes_csv = row.get("scopes_csv")
            enabled = row.get("enabled")
            tenant_id = row.get("tenant_id")
            key_hash = row.get("key_hash")
            hash_alg = row.get("hash_alg")
            key_lookup = row.get("key_lookup") or key_lookup
    else:
        key_prefix = raw[:16]

        try:
            from api.tripwires import check_canary_key

            if check_canary_key(key_prefix):
                _log_auth_event(
                    "canary_token_accessed",
                    success=False,
                    key_prefix=key_prefix,
                    reason="canary_token",
                    request_path=request_path,
                    client_ip=client_ip,
                )
                return AuthResult(
                    valid=False, reason="canary_token", key_prefix=key_prefix
                )
        except ImportError:
            pass

        secret_for_verify = raw
        try:
            from api.db_models import hash_api_key as _hash_api_key

            key_hash = _hash_api_key(raw)
        except Exception:
            key_hash = _sha256_hex(raw)

        try:
            key_lookup = _key_lookup_hash(raw, _get_key_pepper())
        except Exception:
            key_lookup = None

        row, identifier_col, col_names = _row_for(key_prefix, key_lookup, key_hash)
        if row:
            scopes_csv = row.get("scopes_csv")
            enabled = row.get("enabled")
            tenant_id = row.get("tenant_id")
            key_hash = row.get("key_hash")
            hash_alg = row.get("hash_alg")
            key_lookup = row.get("key_lookup") or key_lookup

    if scopes_csv is None or enabled is None:
        _log_auth_event(
            "auth_attempt",
            success=False,
            key_prefix=key_prefix,
            reason="key_not_found",
            request_path=request_path,
            client_ip=client_ip,
        )
        return AuthResult(valid=False, reason="key_not_found", key_prefix=key_prefix)

    if not int(enabled):
        _log_auth_event(
            "auth_attempt",
            success=False,
            key_prefix=key_prefix,
            reason="key_disabled",
            request_path=request_path,
            client_ip=client_ip,
        )
        return AuthResult(valid=False, reason="key_disabled", key_prefix=key_prefix)

    if (
        check_expiration
        and identifier_col
        and key_prefix
        and (key_lookup or key_hash)
        and _check_db_expiration(
            sqlite_path,
            key_prefix,
            identifier_col,
            key_lookup if identifier_col == "key_lookup" else key_hash,
        )
    ):
        _log_auth_event(
            "auth_attempt",
            success=False,
            key_prefix=key_prefix,
            reason="key_expired_db",
            request_path=request_path,
            client_ip=client_ip,
        )
        return AuthResult(valid=False, reason="key_expired_db", key_prefix=key_prefix)

    have = _parse_scopes_csv(scopes_csv)

    if key_hash and secret_for_verify:
        if not verify_key(secret_for_verify, key_hash, hash_alg):
            _log_auth_event(
                "auth_attempt",
                success=False,
                key_prefix=key_prefix,
                tenant_id=tenant_id,
                reason="key_hash_mismatch",
                request_path=request_path,
                client_ip=client_ip,
            )
            return AuthResult(
                valid=False,
                reason="key_hash_mismatch",
                key_prefix=key_prefix,
                tenant_id=tenant_id,
                scopes=have,
            )

        if hash_alg != "argon2id":
            if (
                "hash_alg" in col_names
                and "hash_params" in col_names
                and "key_lookup" in col_names
            ):
                try:
                    new_hash, new_alg, new_params, new_lookup = hash_key(
                        secret_for_verify
                    )
                    con = sqlite3.connect(sqlite_path)
                    try:
                        con.execute(
                            "UPDATE api_keys SET key_hash=?, hash_alg=?, hash_params=?, key_lookup=? WHERE id=?",
                            (
                                new_hash,
                                new_alg,
                                json.dumps(
                                    new_params, separators=(",", ":"), sort_keys=True
                                ),
                                new_lookup,
                                row.get("id"),
                            ),
                        )
                        con.commit()
                        key_hash = new_hash
                        key_lookup = new_lookup
                        identifier_col = "key_lookup"
                    finally:
                        con.close()
                except Exception:
                    log.exception("Failed to upgrade legacy key hash")

    if required_scopes is not None:
        needed = (
            set(required_scopes)
            if isinstance(required_scopes, (set, list, tuple))
            else {str(required_scopes)}
        )
        needed = {s.strip() for s in needed if str(s).strip()}

        if needed and "*" not in have and not needed.issubset(have):
            _log_auth_event(
                "auth_attempt",
                success=False,
                key_prefix=key_prefix,
                tenant_id=tenant_id,
                reason=f"missing_scopes:{','.join(needed - have)}",
                request_path=request_path,
                client_ip=client_ip,
            )
            return AuthResult(
                valid=False,
                reason=f"missing_scopes:{','.join(needed - have)}",
                key_prefix=key_prefix,
                tenant_id=tenant_id,
                scopes=have,
            )

    if identifier_col and (key_lookup or key_hash):
        _update_key_usage(
            sqlite_path,
            key_prefix,
            identifier_col,
            key_lookup if identifier_col == "key_lookup" else key_hash,
        )

    _log_auth_event(
        "auth_attempt",
        success=True,
        key_prefix=key_prefix,
        tenant_id=tenant_id,
        request_path=request_path,
        client_ip=client_ip,
    )
    return AuthResult(
        valid=True,
        reason="valid",
        key_prefix=key_prefix,
        tenant_id=tenant_id,
        scopes=have,
    )


def require_api_key_always(
    request: Request,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    required_scopes: Set[str] | None = None,
) -> str:
    got = _extract_key(request, x_api_key)
    if not got:
        raise HTTPException(status_code=401, detail=ERR_INVALID)

    result = verify_api_key_detailed(
        raw=got, required_scopes=required_scopes, request=request
    )

    if result.valid:
        request.state.auth = result
        return got

    if result.is_missing_key:
        raise HTTPException(status_code=401, detail=ERR_INVALID)
    if result.reason.startswith("missing_scopes:"):
        raise HTTPException(status_code=403, detail=ERR_INVALID)
    raise HTTPException(status_code=401, detail=ERR_INVALID)


def verify_api_key(
    request: Request,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> str:
    return require_api_key_always(request, x_api_key, required_scopes=None)


def bind_tenant_id(
    request: Request,
    requested_tenant: Optional[str],
    *,
    require_explicit_for_unscoped: bool = False,
    default_unscoped: str = "unknown",
) -> str:
    requested = (str(requested_tenant).strip() if requested_tenant else "") or None
    auth = getattr(getattr(request, "state", None), "auth", None)
    auth_tenant = getattr(auth, "tenant_id", None)
    auth_reason = getattr(auth, "reason", None)
    is_global_key = auth_reason == "global_key"

    if auth_tenant:
        if requested and requested != auth_tenant:
            raise HTTPException(status_code=403, detail="Tenant mismatch")
        request.state.tenant_id = auth_tenant
        return auth_tenant

    if requested:
        valid, error = _validate_tenant_id(requested)
        if not valid:
            raise HTTPException(status_code=400, detail=error)
        request.state.tenant_id = requested
        return requested

    if require_explicit_for_unscoped and not is_global_key:
        raise HTTPException(
            status_code=400, detail="tenant_id required for unscoped keys"
        )

    if is_global_key:
        request.state.tenant_id = default_unscoped
        return default_unscoped

    request.state.tenant_id = default_unscoped
    return default_unscoped


def _is_production_env() -> bool:
    return is_production_env()


def require_scopes(*scopes: str) -> Callable[..., None]:
    needed: Set[str] = {str(s).strip() for s in scopes if str(s).strip()}

    def _scoped_key_dep(
        request: Request,
        x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    ) -> str:
        return require_api_key_always(
            request, x_api_key, required_scopes=needed or None
        )

    def _dep(_: str = Depends(_scoped_key_dep)) -> None:
        return None

    return _dep


def revoke_api_key(
    key_prefix: str,
    key_hash: Optional[str] = None,
    *,
    tenant_id: Optional[str] = None,
) -> bool:
    sqlite_path = (os.getenv("FG_SQLITE_PATH") or "").strip()
    if not sqlite_path:
        return False

    con = sqlite3.connect(sqlite_path)
    try:
        cols = con.execute("PRAGMA table_info(api_keys)").fetchall()
        col_names = {r[1] for r in cols}
        if tenant_id and "tenant_id" not in col_names:
            return False
        if key_hash:
            query = "UPDATE api_keys SET enabled=0 WHERE prefix=? AND key_hash=?"
            params = [key_prefix, key_hash]
        else:
            query = "UPDATE api_keys SET enabled=0 WHERE prefix=?"
            params = [key_prefix]
        if tenant_id:
            query += " AND tenant_id=?"
            params.append(tenant_id)
        cur = con.execute(query, params)
        con.commit()
        revoked = cur.rowcount > 0
        if revoked:
            _log_auth_event("key_revoked", success=True, key_prefix=key_prefix)
        return revoked
    except Exception:
        log.exception("Failed to revoke API key")
        return False
    finally:
        con.close()


def rotate_api_key_by_prefix(
    key_prefix: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    tenant_id: Optional[str] = None,
    revoke_old: bool = True,
) -> dict:
    sqlite_path = (os.getenv("FG_SQLITE_PATH") or "").strip()
    if not sqlite_path:
        sqlite_path = str(_resolve_sqlite_path())

    con = sqlite3.connect(sqlite_path)
    try:
        row = con.execute(
            "SELECT id, scopes_csv, enabled, tenant_id, key_hash FROM api_keys WHERE prefix=? LIMIT 1",
            (key_prefix,),
        ).fetchone()

        if not row:
            raise ValueError("Key not found")

        key_id, scopes_csv, enabled, db_tenant_id, old_key_hash = row

        if tenant_id:
            if not db_tenant_id or tenant_id != db_tenant_id:
                raise ValueError("Key not found for tenant")

        if not int(enabled):
            raise ValueError("Key is disabled")

        scopes = list(_parse_scopes_csv(scopes_csv))
        new_key = mint_key(*scopes, ttl_seconds=ttl_seconds, tenant_id=db_tenant_id)
        parts = new_key.split(".")
        new_prefix = parts[0] if parts else "fgk"
        new_secret = parts[-1]
        try:
            new_lookup = _key_lookup_hash(new_secret, _get_key_pepper())
        except Exception:
            new_lookup = None

        cols = con.execute("PRAGMA table_info(api_keys)").fetchall()
        col_names = {r[1] for r in cols}

        if "rotated_from" in col_names and new_lookup and "key_lookup" in col_names:
            con.execute(
                "UPDATE api_keys SET rotated_from=? WHERE key_lookup=?",
                (old_key_hash, new_lookup),
            )

        old_key_revoked = False
        if revoke_old:
            con.execute("UPDATE api_keys SET enabled=0 WHERE id=?", (key_id,))
            old_key_revoked = True

        con.commit()

        now = int(time.time())
        expires_at = now + int(ttl_seconds)

        return {
            "new_key": new_key,
            "new_prefix": new_prefix,
            "old_prefix": key_prefix,
            "scopes": scopes,
            "tenant_id": db_tenant_id,
            "expires_at": expires_at,
            "old_key_revoked": old_key_revoked,
        }
    finally:
        con.close()


def list_api_keys(
    tenant_id: Optional[str] = None,
    include_disabled: bool = False,
) -> list[dict]:
    sqlite_path = (os.getenv("FG_SQLITE_PATH") or "").strip()
    if not sqlite_path:
        return []

    con = sqlite3.connect(sqlite_path)
    try:
        cols = con.execute("PRAGMA table_info(api_keys)").fetchall()
        col_names = {r[1] for r in cols}

        select_cols = ["prefix", "scopes_csv", "enabled"]
        if "name" in col_names:
            select_cols.insert(1, "name")
        if "created_at" in col_names:
            select_cols.append("created_at")
        if "tenant_id" in col_names:
            select_cols.append("tenant_id")
        if "expires_at" in col_names:
            select_cols.append("expires_at")
        if "last_used_at" in col_names:
            select_cols.append("last_used_at")
        if "use_count" in col_names:
            select_cols.append("use_count")

        query = f"SELECT {','.join(select_cols)} FROM api_keys"
        conditions = []
        params = []

        if not include_disabled:
            conditions.append("enabled=1")

        if tenant_id:
            if "tenant_id" not in col_names:
                return []
            conditions.append("tenant_id=?")
            params.append(tenant_id)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        rows = con.execute(query, params).fetchall()

        result = []
        for row in rows:
            item = dict(zip(select_cols, row))
            for ts_field in ("created_at", "expires_at", "last_used_at"):
                if ts_field in item and item[ts_field] is not None:
                    item[ts_field] = str(item[ts_field])
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


__all__ = [
    "AuthResult",
    "mint_key",
    "verify_api_key_raw",
    "verify_api_key_detailed",
    "verify_api_key",
    "require_api_key_always",
    "require_scopes",
    "bind_tenant_id",
    "revoke_api_key",
    "rotate_api_key_by_prefix",
    "list_api_keys",
    "_extract_key",
    "_validate_tenant_id",
    "_log_auth_event",
    "_constant_time_compare",
    "ERR_INVALID",
    "DEFAULT_TTL_SECONDS",
]
