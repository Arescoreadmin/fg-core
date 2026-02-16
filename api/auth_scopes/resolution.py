from __future__ import annotations

import hashlib
import json
import logging
import os
import re
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


def is_prod_like_env() -> bool:
    env = (os.getenv("FG_ENV") or "").strip().lower()
    return env in {"prod", "production", "staging"}


def redact_detail(detail: str, generic: str = "forbidden") -> str:
    return generic if is_prod_like_env() else detail


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


def _tenant_hash(value: Optional[str]) -> Optional[str]:
    norm = _normalize_field(value, max_len=256)
    if not norm:
        return None
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16]


def _trust_proxy_headers(request: Optional[Request]) -> bool:
    """
    Trust X-Forwarded-For style headers only when explicitly enabled.
    Default is fail-closed (socket client IP only) to avoid log poisoning.
    """
    if request is None:
        return False
    return (os.getenv("FG_TRUST_PROXY_HEADERS") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
        "y",
    }


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
    remote_ip = _remote_ip_value(request)
    if not remote_ip:
        return None
    if is_prod_like_env():
        return _tenant_hash(remote_ip)
    return remote_ip


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
            "tenant_id_hash": _tenant_hash(tenant_supplied or tenant_from_key),
            "key_id": _normalize_field(key_id, max_len=32),
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
    requested = (str(requested_tenant).strip() if requested_tenant else "") or None

    cached_tenant_raw = getattr(getattr(request, "state", None), "tenant_id", None)
    cached_tenant = None
    if isinstance(cached_tenant_raw, str):
        cached_tenant = cached_tenant_raw.strip() or None

    key_bound_flag = bool(
        getattr(getattr(request, "state", None), "tenant_is_key_bound", False)
    )
    if key_bound_flag and not cached_tenant:
        # Partial state is not trusted; force re-resolution from auth context.
        request.state.tenant_is_key_bound = False

    if cached_tenant and key_bound_flag:
        cached = cached_tenant
        if requested and requested != cached:
            auth = getattr(getattr(request, "state", None), "auth", None)
            _tenant_denial_log(
                request=request,
                event="tenant_mismatch_denied",
                reason="cached_tenant_mismatch",
                tenant_from_key=cached,
                tenant_supplied=requested,
                key_prefix=getattr(auth, "key_prefix", None),
                scopes=getattr(auth, "scopes", set()),
            )
            raise HTTPException(
                status_code=403,
                detail=redact_detail("tenant mismatch", generic="forbidden"),
            )
        return cached

    auth = getattr(getattr(request, "state", None), "auth", None)
    auth_tenant = _auth_tenant_from_request(request)
    key_prefix = getattr(auth, "key_prefix", None)
    scopes = getattr(auth, "scopes", set())

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
            raise HTTPException(
                status_code=403,
                detail=redact_detail("tenant mismatch", generic="forbidden"),
            )
        request.state.tenant_id = auth_tenant
        request.state.tenant_is_key_bound = True
        _apply_tenant_context(request, auth_tenant)
        return auth_tenant

    if requested:
        valid, _error = _validate_tenant_id(requested)
        if not valid:
            raise HTTPException(
                status_code=400,
                detail=redact_detail("invalid tenant_id", generic="invalid request"),
            )

    _tenant_denial_log(
        request=request,
        event="tenant_binding_missing_denied",
        reason="missing_key_bound_tenant",
        tenant_from_key=auth_tenant,
        tenant_supplied=requested,
        key_prefix=key_prefix,
        scopes=scopes,
    )
    _ = require_explicit_for_unscoped
    _ = default_unscoped
    raise HTTPException(
        status_code=400,
        detail=redact_detail(
            "tenant_id required for unscoped keys", generic="invalid request"
        ),
    )


def require_bound_tenant(request: Request) -> str:
    tenant_id = getattr(getattr(request, "state", None), "tenant_id", None)
    if tenant_id and bool(
        getattr(getattr(request, "state", None), "tenant_is_key_bound", False)
    ):
        return str(tenant_id)
    raise HTTPException(
        status_code=400,
        detail=redact_detail(
            "tenant_id required for unscoped keys", generic="invalid request"
        ),
    )


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

    return _dep
