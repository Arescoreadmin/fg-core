from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import time
from contextlib import contextmanager
from typing import Callable, Optional, Set, Tuple, Dict, Any

from fastapi import Depends, Header, HTTPException, Request

from api.db import set_tenant_context

from .definitions import AuthResult
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


# -------------------------
# Error contract helpers
# -------------------------
def is_prod_like_env() -> bool:
    env = (os.getenv("FG_ENV") or "").strip().lower()
    return env in {"prod", "production", "staging"}


def redact_detail(detail: str, generic: str = "forbidden") -> str:
    # In prod-like, do not leak decision details to clients.
    return generic if is_prod_like_env() else detail


def http_error(
    status_code: int,
    *,
    error_code: str,
    message: str,
    generic: str = "forbidden",
) -> HTTPException:
    """
    Single source of truth for client-facing error payloads.
    Always returns: {"detail": {"error_code": "...", "message": "..."}}
    """
    msg = redact_detail(message, generic=generic)
    return HTTPException(
        status_code=status_code, detail={"error_code": error_code, "message": msg}
    )


def _request_id(request: Optional[Request]) -> Optional[str]:
    if request is None:
        return None
    rid = getattr(getattr(request, "state", None), "request_id", None)
    if rid:
        return str(rid)
    header_val = request.headers.get("x-request-id") if request.headers else None
    return str(header_val).strip() if header_val else None


def _normalize_field(value: Optional[str], *, max_len: int = 128) -> Optional[str]:
    if value is None:
        return None
    text = str(value)
    text = re.sub(r"[\x00-\x1f\x7f]", "", text).strip()
    if not text:
        return None
    return text[:max_len]


def _hash16(value: Optional[str]) -> Optional[str]:
    norm = _normalize_field(value, max_len=256)
    if not norm:
        return None
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16]


def _env_bool(name: str, default: bool = False) -> bool:
    raw = (os.getenv(name) or "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on", "y"}


def _trust_proxy_headers(request: Optional[Request]) -> bool:
    """
    Trust X-Forwarded-For style headers only when explicitly enabled.
    Default is fail-closed (socket client IP only) to reduce log poisoning.
    """
    if request is None:
        return False
    return _env_bool("FG_TRUST_PROXY_HEADERS", False)


def _remote_ip_value(request: Optional[Request]) -> Optional[str]:
    if request is None:
        return None

    if _trust_proxy_headers(request):
        for header in ("x-forwarded-for", "x-real-ip", "cf-connecting-ip"):
            raw_ip = request.headers.get(header) if request.headers else None
            if raw_ip:
                return _normalize_field(raw_ip.split(",")[0], max_len=64)

    if getattr(request, "client", None) is not None:
        return _normalize_field(request.client.host, max_len=64)
    return None


def _safe_remote_ip_for_logs(request: Optional[Request]) -> Optional[str]:
    ip = _remote_ip_value(request)
    if not ip:
        return None
    return _hash16(ip) if is_prod_like_env() else ip


# -------------------------
# SQLite helpers
# -------------------------
def _sqlite_timeout_s() -> float:
    # Keep it short. This is an auth check; we should fail closed, not hang.
    try:
        return float((os.getenv("FG_AUTH_SQLITE_TIMEOUT_S") or "1.0").strip())
    except Exception:
        return 1.0


def _sqlite_readonly() -> bool:
    # Optional: allow forcing read-only mode (except when upgrading hashes/usage)
    return _env_bool("FG_AUTH_SQLITE_READONLY", False)


@contextmanager
def _sqlite_connect(sqlite_path: str, *, writable: bool) -> sqlite3.Connection:
    """
    Opens SQLite with conservative defaults.
    If readonly is forced, writable=False even if caller requests writable.
    """
    timeout = _sqlite_timeout_s()

    readonly_forced = _sqlite_readonly()
    if readonly_forced:
        writable = False

    # If writable=False, try URI readonly mode to avoid accidental writes.
    if not writable:
        uri = f"file:{sqlite_path}?mode=ro"
        con = sqlite3.connect(uri, uri=True, timeout=timeout)
    else:
        con = sqlite3.connect(sqlite_path, timeout=timeout)

    try:
        con.row_factory = sqlite3.Row
        yield con
    finally:
        con.close()


# -------------------------
# Security Logging
# -------------------------
def log_tenant_denial_event(
    *,
    request: Optional[Request],
    reason: str,
    tenant_from_key: Optional[str],
    tenant_supplied: Optional[str],
    key_id: Optional[str],
) -> None:
    route = _normalize_field(str(request.url.path), max_len=256) if request else None
    method = _normalize_field(request.method, max_len=16) if request else None
    request_id = _normalize_field(_request_id(request), max_len=128)

    tenant_hash = _hash16(tenant_supplied or tenant_from_key)

    _security_log.warning(
        "tenant_denial",
        extra={
            "event": "tenant_denial",
            "reason": _normalize_field(reason, max_len=64) or "tenant_denied",
            "env": _normalize_field((os.getenv("FG_ENV") or "").lower(), max_len=24),
            "route": route,
            "method": method,
            "request_id": request_id,
            "remote_ip": _safe_remote_ip_for_logs(request),
            "tenant_id_hash": tenant_hash,
            "key_id": _normalize_field(key_id, max_len=32),
            "ts": int(time.time()),
        },
    )


def _tenant_denial_log(
    *,
    request: Optional[Request],
    event: str,
    reason: str,
    tenant_from_key: Optional[str],
    tenant_supplied: Optional[str],
    key_prefix: Optional[str],
    scopes: Optional[Set[str]],
) -> None:
    # Keep signature stable for call sites; event/scopes are intentionally not exposed.
    _ = event
    _ = scopes
    log_tenant_denial_event(
        request=request,
        reason=reason,
        tenant_from_key=tenant_from_key,
        tenant_supplied=tenant_supplied,
        key_id=key_prefix,
    )


def _log_auth_event(
    event_type: str,
    success: bool,
    key_prefix: Optional[str] = None,
    tenant_id: Optional[str] = None,
    reason: Optional[str] = None,
    request_path: Optional[str] = None,
    client_ip: Optional[str] = None,
) -> None:
    """
    Log security-relevant authentication events.
    In prod-like, avoid logging raw tenant_id/client_ip.
    """
    tenant_for_log = _hash16(tenant_id) if is_prod_like_env() else tenant_id
    ip_for_log = _hash16(client_ip) if (is_prod_like_env() and client_ip) else client_ip

    log_data = {
        "event": event_type,
        "success": bool(success),
        "key_prefix": (key_prefix[:8] if key_prefix else None),
        "tenant_id": tenant_for_log,
        "reason": reason,
        "path": request_path,
        "client_ip": ip_for_log,
        "ts": int(time.time()),
    }

    if success:
        _security_log.info("auth_event", extra=log_data)
    else:
        _security_log.warning("auth_event", extra=log_data)


# -------------------------
# Key Extraction
# -------------------------
def _extract_key(request: Request, x_api_key: Optional[str]) -> Optional[str]:
    """
    Extract API key from request.

    Keys are accepted ONLY from:
      1) X-API-Key header (preferred)
      2) Cookie (for UI sessions)

    Query params are not supported.
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


# -------------------------
# Verification (raw + detailed)
# -------------------------
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
    return bool(result.valid)


def verify_api_key_detailed(
    raw: Optional[str] = None,
    required_scopes=None,
    raw_key: Optional[str] = None,
    db=None,
    check_expiration: bool = True,
    request: Optional[Request] = None,
    **_ignored,
) -> AuthResult:
    request_path: Optional[str] = None
    client_ip: Optional[str] = None
    if request:
        request_path = str(request.url.path) if request.url else None
        client_ip = _remote_ip_value(request)

    raw = (raw or raw_key or "").strip()

    # 1) global key bypass (constant-time comparison)
    # NOTE: Valid auth result but with NO tenant binding. Must bind via bind_tenant_id().
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
        return AuthResult(valid=False, reason="no_key_provided", is_missing_key=True)

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

    def _row_for(
        prefix: str, lookup_hash: Optional[str], legacy_hash: Optional[str]
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str], Set[str]]:
        try:
            with _sqlite_connect(sqlite_path, writable=False) as con:
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
                        return dict(row), "key_lookup", col_names

                if legacy_hash:
                    row = con.execute(
                        f"SELECT {select_clause} FROM api_keys WHERE prefix=? AND key_hash=? LIMIT 1",
                        (prefix, legacy_hash),
                    ).fetchone()
                    if row:
                        return dict(row), "key_hash", col_names

                return None, None, col_names
        except sqlite3.OperationalError:
            return None, None, set()

    scopes_csv: Optional[str] = None
    enabled: Optional[int] = None
    tenant_id: Optional[str] = None
    token_payload = None
    key_prefix: Optional[str] = None
    key_hash: Optional[str] = None
    key_lookup: Optional[str] = None
    hash_alg: Optional[str] = None
    identifier_col: Optional[str] = None
    col_names: Set[str] = set()
    secret_for_verify: Optional[str] = None
    row: Optional[Dict[str, Any]] = None

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
        secret_for_verify = raw

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

    # Verify secret against stored hash
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

        # Upgrade legacy hash to argon2id if schema supports it and sqlite writable is allowed.
        if hash_alg != "argon2id":
            if (
                "hash_alg" in col_names
                and "hash_params" in col_names
                and "key_lookup" in col_names
                and row is not None
            ):
                try:
                    new_hash, new_alg, new_params, new_lookup = hash_key(
                        secret_for_verify
                    )
                    with _sqlite_connect(sqlite_path, writable=True) as con:
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
                except Exception:
                    log.exception("Failed to upgrade legacy key hash")

    # Scope enforcement
    if required_scopes is not None:
        needed = (
            set(required_scopes)
            if isinstance(required_scopes, (set, list, tuple))
            else {str(required_scopes)}
        )
        needed = {str(s).strip() for s in needed if str(s).strip()}

        if needed and "*" not in have and not needed.issubset(have):
            missing = needed - have
            _log_auth_event(
                "auth_attempt",
                success=False,
                key_prefix=key_prefix,
                tenant_id=tenant_id,
                reason=f"missing_scopes:{','.join(sorted(missing))}",
                request_path=request_path,
                client_ip=client_ip,
            )
            return AuthResult(
                valid=False,
                reason=f"missing_scopes:{','.join(sorted(missing))}",
                key_prefix=key_prefix,
                tenant_id=tenant_id,
                scopes=have,
            )

    # Usage accounting (best effort; do not break auth if this fails)
    if identifier_col and (key_lookup or key_hash):
        try:
            _update_key_usage(
                sqlite_path,
                key_prefix,
                identifier_col,
                key_lookup if identifier_col == "key_lookup" else key_hash,
            )
        except Exception:
            log.exception("Failed to update key usage")

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


# -------------------------
# FastAPI Dependencies
# -------------------------
def require_api_key_always(
    request: Request,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    required_scopes: Set[str] | None = None,
) -> str:
    got = _extract_key(request, x_api_key)
    if not got:
        # Contract: error_code required.
        raise http_error(
            401,
            error_code="auth_missing_key",
            message="missing api key",
            generic="unauthorized",
        )

    result = verify_api_key_detailed(
        raw=got, required_scopes=required_scopes, request=request
    )

    if result.valid:
        request.state.auth = result
        return got

    # Keep client contract stable (no internal reason leakage).
    if getattr(result, "is_missing_key", False):
        raise http_error(
            401,
            error_code="auth_missing_key",
            message="missing api key",
            generic="unauthorized",
        )

    if str(getattr(result, "reason", "")).startswith("missing_scopes:"):
        raise http_error(
            403,
            error_code="auth_missing_scopes",
            message="missing required scopes",
            generic="forbidden",
        )

    # Default invalid key.
    raise http_error(
        401,
        error_code="auth_invalid_key",
        message="invalid api key",
        generic="unauthorized",
    )


def verify_api_key(
    request: Request,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> str:
    return require_api_key_always(request, x_api_key, required_scopes=None)


# -------------------------
# Tenant Binding
# -------------------------
def _auth_tenant_from_request(request: Request) -> Optional[str]:
    auth = getattr(getattr(request, "state", None), "auth", None)
    tenant = getattr(auth, "tenant_id", None)
    if tenant is None:
        return None
    return str(tenant).strip() or None


def bind_tenant_id(
    request: Request,
    requested_tenant: Optional[str],
    *,
    require_explicit_for_unscoped: bool = False,
    default_unscoped: Optional[str] = None,
) -> str:
    """
    Bind tenant id for the request.

    Cases:
      - Key-bound tenant (scoped key): tenant comes from auth context, header must match if supplied.
      - Unscoped/global key (e.g., FG_API_KEY): tenant MUST be explicitly provided (if require_explicit_for_unscoped),
        or optionally defaulted (default_unscoped).

    This sets:
      request.state.tenant_id
      request.state.tenant_is_key_bound = True
    and applies tenant context to db_session if present + enabled.
    """
    requested = (str(requested_tenant).strip() if requested_tenant else "") or None

    cached_tenant_raw = getattr(getattr(request, "state", None), "tenant_id", None)
    cached_tenant = (
        cached_tenant_raw.strip() if isinstance(cached_tenant_raw, str) else None
    )
    cached_tenant = cached_tenant or None

    key_bound_flag = bool(
        getattr(getattr(request, "state", None), "tenant_is_key_bound", False)
    )
    if key_bound_flag and not cached_tenant:
        # Partial state is not trusted; force re-resolution.
        request.state.tenant_is_key_bound = False
        key_bound_flag = False

    # If already bound, ensure requested doesn't conflict.
    if cached_tenant and key_bound_flag:
        if requested and requested != cached_tenant:
            auth = getattr(getattr(request, "state", None), "auth", None)
            _tenant_denial_log(
                request=request,
                event="tenant_mismatch_denied",
                reason="cached_tenant_mismatch",
                tenant_from_key=cached_tenant,
                tenant_supplied=requested,
                key_prefix=getattr(auth, "key_prefix", None),
                scopes=getattr(auth, "scopes", set()),
            )
            raise http_error(
                403,
                error_code="tenant_mismatch",
                message="tenant mismatch",
                generic="forbidden",
            )
        return cached_tenant

    auth = getattr(getattr(request, "state", None), "auth", None)
    auth_tenant = _auth_tenant_from_request(request)
    key_prefix = getattr(auth, "key_prefix", None)
    scopes = getattr(auth, "scopes", set())

    # Key-bound tenant: enforce match if requested supplied.
    if auth_tenant:
        if requested and requested != auth_tenant:
            _tenant_denial_log(
                request=request,
                event="tenant_mismatch_denied",
                reason="requested_tenant_mismatch",
                tenant_from_key=auth_tenant,
                tenant_supplied=requested,
                key_prefix=key_prefix,
                scopes=scopes,
            )
            raise http_error(
                403,
                error_code="tenant_mismatch",
                message="tenant mismatch",
                generic="forbidden",
            )

        request.state.tenant_id = auth_tenant
        request.state.tenant_is_key_bound = True
        _apply_tenant_context(request, auth_tenant)
        return auth_tenant

    # Unscoped/global key path: validate requested tenant if present.
    if requested:
        valid, _error = _validate_tenant_id(requested)
        if not valid:
            raise http_error(
                400,
                error_code="tenant_invalid",
                message="invalid tenant_id",
                generic="invalid request",
            )

        # Explicit tenant binding for unscoped keys.
        if require_explicit_for_unscoped:
            request.state.tenant_id = requested
            request.state.tenant_is_key_bound = True
            _apply_tenant_context(request, requested)
            return requested

    # Optional default for unscoped keys (only if no explicit tenant supplied)
    if (not requested) and default_unscoped:
        valid, _error = _validate_tenant_id(default_unscoped)
        if valid:
            request.state.tenant_id = default_unscoped
            request.state.tenant_is_key_bound = True
            _apply_tenant_context(request, default_unscoped)
            return default_unscoped

    _tenant_denial_log(
        request=request,
        event="tenant_binding_missing_denied",
        reason="missing_key_bound_tenant",
        tenant_from_key=auth_tenant,
        tenant_supplied=requested,
        key_prefix=key_prefix,
        scopes=scopes,
    )
    raise http_error(
        400,
        error_code="tenant_required",
        message="tenant_id required for unscoped keys",
        generic="invalid request",
    )


def require_bound_tenant(request: Request) -> str:
    tenant_id = getattr(getattr(request, "state", None), "tenant_id", None)
    if tenant_id and bool(
        getattr(getattr(request, "state", None), "tenant_is_key_bound", False)
    ):
        return str(tenant_id)

    raise http_error(
        400,
        error_code="tenant_required",
        message="tenant_id required for unscoped keys",
        generic="invalid request",
    )


def _apply_tenant_context(request: Request, tenant_id: Optional[str]) -> None:
    """
    Apply tenant context to the DB session, if present and enabled.

    Mode:
      FG_TENANT_CONTEXT_MODE=db_session (default) -> set tenant context on session
      else -> do nothing
    """
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
        # Fail closed in production; degrade in dev.
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

    return _dep
