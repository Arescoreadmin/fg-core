from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from typing import Callable, Optional, Set

from fastapi import Depends, Header, HTTPException, Request

from api.db import set_tenant_context

from .definitions import AuthResult, ERR_INVALID
from .helpers import (
    _constant_time_compare,
    _decode_token_payload,
    _get_key_pepper,
    _key_lookup_hash,
    _parse_scopes_csv,
    _sha256_hex,
    hash_key,
    verify_key,
)
from .mapping import _update_key_usage
from .validation import (
    _check_db_expiration,
    _is_key_expired,
    _is_production_env,
    _validate_tenant_id,
)

log = logging.getLogger("frostgate")
_security_log = logging.getLogger("frostgate.security")


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
        if _is_production_env():
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
        _apply_tenant_context(request, auth_tenant)
        return auth_tenant

    if requested:
        valid, error = _validate_tenant_id(requested)
        if not valid:
            raise HTTPException(status_code=400, detail=error)
        request.state.tenant_id = requested
        _apply_tenant_context(request, requested)
        return requested

    if require_explicit_for_unscoped and not is_global_key:
        raise HTTPException(
            status_code=400, detail="tenant_id required for unscoped keys"
        )

    if _is_production_env():
        raise HTTPException(status_code=400, detail="tenant_id required")

    if is_global_key:
        request.state.tenant_id = default_unscoped
        _apply_tenant_context(request, default_unscoped)
        return default_unscoped

    request.state.tenant_id = default_unscoped
    _apply_tenant_context(request, default_unscoped)
    return default_unscoped


def _apply_tenant_context(request: Request, tenant_id: Optional[str]) -> None:
    if not tenant_id:
        return
    mode = (os.getenv("FG_TENANT_CONTEXT_MODE") or "db_session").strip().lower()
    if mode != "db_session":
        return
    db_session = getattr(getattr(request, "state", None), "db_session", None)
    if db_session is None:
        return
    try:
        set_tenant_context(db_session, tenant_id)
    except Exception:
        if _is_production_env():
            raise


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

    setattr(_dep, "__fg_scope_dependency__", True)
    return _dep
