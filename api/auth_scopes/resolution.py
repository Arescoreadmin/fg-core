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


def tenant_denial(
    request: Request,
    *,
    reason: str,
    tenant_supplied: Optional[str] = None,
    tenant_from_key: Optional[str] = None,
) -> None:
    """
    Security log for tenant binding denials.

    Tests require:
      - logger name: frostgate.security
      - msg: "tenant_denial"
      - extra fields: event, reason, env, route, method, request_id, remote_ip, tenant_id_hash, key_id
    """
    import os

    log_sec = logging.getLogger("frostgate.security")
    env = os.getenv("FG_ENV", "dev")

    headers = getattr(request, "headers", None) or {}
    scope = getattr(request, "scope", None) or {}

    # route + method (works for real Request and mocks)
    route = None
    try:
        route = getattr(getattr(request, "url", None), "path", None) or scope.get(
            "path"
        )
    except Exception:
        route = scope.get("path")
    method = None
    try:
        method = getattr(request, "method", None) or scope.get("method")
    except Exception:
        method = scope.get("method")

    # request id
    request_id = None
    try:
        request_id = headers.get("X-Request-Id") or headers.get("X-Request-ID")
    except Exception:
        request_id = None
    if not request_id:
        request_id = getattr(getattr(request, "state", None), "request_id", None)

    # remote_ip (trust proxy only if explicitly enabled)
    trust_proxy = os.getenv("FG_TRUST_PROXY_HEADERS", "0").strip().lower() in (
        "1",
        "true",
        "yes",
    )
    remote_ip = None
    if trust_proxy:
        try:
            xff = headers.get("X-Forwarded-For")
            if xff:
                remote_ip = xff.split(",")[0].strip()
        except Exception:
            remote_ip = None
    if not remote_ip:
        try:
            client = getattr(request, "client", None)
            remote_ip = getattr(client, "host", None)
        except Exception:
            remote_ip = None

    # key_id best-effort
    st = getattr(request, "state", None)
    auth = getattr(st, "auth", None) if st is not None else None
    key_id = (
        getattr(auth, "key_id", None)
        or getattr(auth, "key_hash", None)
        or getattr(auth, "id", None)
    )

    log_sec.warning(
        "tenant_denial",
        extra={
            "event": "tenant_denial",
            "reason": reason,
            "env": env,
            "route": route,
            "method": method,
            "request_id": request_id,
            "remote_ip": remote_ip,
            "tenant_id_hash": _tenant_hash(tenant_supplied or tenant_from_key),
            "key_id": key_id,
        },
    )


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


def verify_api_key(
    request: Request,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> str:
    """
    Back-compat dependency used across the codebase and re-exported by api.auth_scopes.
    Verifies the key (no scope requirement) and seeds request.state auth context.
    """
    return require_api_key_always(request, x_api_key, required_scopes=None)


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
        # NOTE: env/global key is unscoped (no tenant, no scopes)
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
    row = None

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
                                row.get("id") if row else None,
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
                reason=f"missing_scopes:{','.join(sorted(needed - have))}",
                request_path=request_path,
                client_ip=client_ip,
            )
            return AuthResult(
                valid=False,
                reason=f"missing_scopes:{','.join(sorted(needed - have))}",
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

    # Verify now (dependency path). Middleware may also verify, but we do not rely on it.
    result = verify_api_key_detailed(
        raw=got, required_scopes=required_scopes, request=request
    )

    if result.valid:
        # Canonical state used across deps
        request.state.auth = result

        # Self-heal: some routes expect auth_context (older/middleware-driven code paths).
        st = getattr(request, "state", None)
        if st is not None and getattr(st, "auth_context", None) is None:
            scopes = set(getattr(result, "scopes", set()) or set())
            tenant_id = getattr(result, "tenant_id", None)
            tenant_is_key_bound = bool(
                tenant_id
            )  # DB keys may be tenant-bound; env/global is not.

            st.auth_context = {
                "api_key_present": True,
                "api_key_prefix": getattr(result, "key_prefix", None),
                "scopes": sorted(list(scopes)),
                "tenant_id": tenant_id,
                "tenant_is_key_bound": tenant_is_key_bound,
                "source": "api.auth_scopes.resolution.require_api_key_always",
            }
            if tenant_id:
                st.tenant_id = tenant_id
                st.tenant_is_key_bound = tenant_is_key_bound

        return got

    # Normalize errors
    if (
        getattr(result, "is_missing_key", False)
        or getattr(result, "reason", "") == "no_key_provided"
    ):
        raise HTTPException(status_code=401, detail=ERR_INVALID)

    reason = str(getattr(result, "reason", "") or "")
    if reason.startswith("missing_scopes:"):
        raise HTTPException(status_code=403, detail=ERR_INVALID)

    raise HTTPException(status_code=401, detail=ERR_INVALID)


def verify_api_key_header(
    request: Request,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> str:
    """
    Wrapper dependency for routes that just want a key validated.
    Named to avoid shadowing api.auth.verify_api_key (if present).
    """
    return require_api_key_always(request, x_api_key, required_scopes=None)


def _auth_tenant_from_request(request: Request) -> Optional[str]:
    auth = getattr(getattr(request, "state", None), "auth", None)
    tenant = getattr(auth, "tenant_id", None)
    if tenant is None:
        return None
    return str(tenant).strip() or None


def _fg__is_env_api_key(presented_key: str | None, settings_obj) -> bool:
    try:
        expected = getattr(settings_obj, "FG_API_KEY", None)
    except Exception:
        expected = None
    return bool(expected) and bool(presented_key) and presented_key == expected


def _fg__request_path(request) -> str:
    try:
        return request.url.path
    except Exception:
        return ""


def _fg__header_tenant(request) -> str | None:
    try:
        return request.headers.get("X-Tenant-Id")
    except Exception:
        return None


def bind_tenant_id(
    request: Request,
    requested_tenant: Optional[str],
    *,
    require_explicit_for_unscoped: bool = False,
    default_unscoped: Optional[str] = None,
) -> str:
    """
    Tenant binding contract:

    - If the API key is tenant-bound: effective tenant is ALWAYS the key's tenant.
      If the client supplies a different tenant (query/header/body/path), deny with 403.

    - If the API key is unscoped:
      - If any supplied tenant is invalid format -> 400 invalid tenant_id.
      - Only /ai/query may use FG_API_KEY (env) with X-Tenant-Id for dev convenience.
      - Otherwise: unscoped keys cannot act on ANY tenant, even if supplied -> 400.
    """
    import os

    def _norm_tid(v):
        # MagicMock-safe: only accept real strings.
        if not isinstance(v, str):
            return None
        v = v.strip()
        return v or None

    st = getattr(request, "state", None)
    if st is None:
        st = type("State", (), {})()
        setattr(request, "state", st)

    # Populate tenant cache once per request from the shared helper (monkeypatchable).
    if getattr(st, "tenant_id", None) is None:
        try:
            st.tenant_id = _norm_tid(_auth_tenant_from_request(request))
        except Exception:
            st.tenant_id = None

    # Source of truth: auth object (unit tests set st.auth directly; middleware sets st.tenant_id too).
    auth = getattr(st, "auth", None)
    auth_tenant = (
        _norm_tid(getattr(auth, "tenant_id", None)) if auth is not None else None
    )
    # Cache derived fields for the rest of the request, but never treat cache as authoritative.
    if getattr(st, "tenant_id", None) is None:
        st.tenant_id = auth_tenant
    if not hasattr(st, "tenant_is_key_bound"):
        st.tenant_is_key_bound = bool(auth_tenant)

    # Determine key binding (auth-first, then cached).
    key_tenant = auth_tenant or _norm_tid(getattr(st, "tenant_id", None))
    key_is_bound = bool(key_tenant)
    # Keep the cache consistent (middleware may have set these already).
    st.tenant_id = key_tenant
    st.tenant_is_key_bound = bool(key_tenant)

    # Gather supplied tenant (query preferred, then header)
    req_tenant = _norm_tid(requested_tenant)
    headers = getattr(request, "headers", None) or {}
    try:
        hdr_tenant = _norm_tid(headers.get("X-Tenant-Id"))
    except Exception:
        hdr_tenant = None
    supplied = req_tenant or hdr_tenant

    # Unscoped key: require explicit tenant when requested by caller.
    if (not key_is_bound) and require_explicit_for_unscoped and not supplied:
        raise HTTPException(
            status_code=400,
            detail=redact_detail(
                "tenant_id required for unscoped keys", generic="invalid request"
            ),
        )

    # Key-bound: clamp, mismatch -> 403
    if key_is_bound and key_tenant:
        if supplied and supplied != key_tenant:
            tenant_denial(
                request,
                reason="tenant_mismatch",
                tenant_supplied=supplied,
                tenant_from_key=key_tenant,
            )
            raise HTTPException(
                status_code=403,
                detail=redact_detail("tenant mismatch", generic="forbidden"),
            )
        st.tenant_id = key_tenant
        st.tenant_is_key_bound = True
        return str(key_tenant)

    # Unscoped: validate supplied format if present
    if supplied:
        valid, _err = _validate_tenant_id(supplied)
        if not valid:
            raise HTTPException(
                status_code=400,
                detail=redact_detail("invalid tenant_id", generic="invalid request"),
            )

    # /ai/query exception for env key only
    scope = getattr(request, "scope", None) or {}
    path = None
    try:
        path = getattr(getattr(request, "url", None), "path", None) or scope.get("path")
    except Exception:
        path = scope.get("path")

    presented = None
    try:
        presented = headers.get("X-API-Key")
    except Exception:
        presented = None
    env_key = os.getenv("FG_API_KEY")

    if path == "/ai/query" and env_key and presented and presented == env_key:
        if hdr_tenant:
            st.tenant_id = hdr_tenant
            st.tenant_is_key_bound = False
            return str(hdr_tenant)
        raise HTTPException(
            status_code=400,
            detail=redact_detail(
                "tenant_id required for unscoped keys", generic="invalid request"
            ),
        )

    # Otherwise, unscoped keys cannot act on any tenant
    if require_explicit_for_unscoped:
        raise HTTPException(
            status_code=400,
            detail=redact_detail(
                "tenant_id required for unscoped keys", generic="invalid request"
            ),
        )

    if default_unscoped:
        st.tenant_id = default_unscoped
        st.tenant_is_key_bound = False
        return str(default_unscoped)

    raise HTTPException(
        status_code=400,
        detail=redact_detail(
            "tenant_id required for unscoped keys", generic="invalid request"
        ),
    )


def require_bound_tenant(request: Request, x_tenant_id: Optional[str] = None) -> str:
    """
    Callable helper (NOT a FastAPI Header dependency).
    Must work with real Requests and test DummyReq objects without .headers.
    """
    headers = getattr(request, "headers", None) or {}
    if x_tenant_id is None:
        try:
            x_tenant_id = headers.get("X-Tenant-Id")
        except Exception:
            x_tenant_id = None
    return bind_tenant_id(
        request,
        (x_tenant_id or "").strip() or None,
        require_explicit_for_unscoped=True,
    )


def require_tenant_id(
    request: Request,
    x_tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-Id"),
) -> str:
    """Require a tenant id for unscoped keys (accept X-Tenant-Id)."""
    tenant = (x_tenant_id or "").strip()
    if not tenant:
        raise HTTPException(
            status_code=400,
            detail=redact_detail("tenant_id required", generic="invalid request"),
        )
    valid, _err = _validate_tenant_id(tenant)
    if not valid:
        raise HTTPException(
            status_code=400,
            detail=redact_detail("invalid tenant_id", generic="invalid request"),
        )

    st = getattr(request, "state", None)
    if st is not None:
        setattr(st, "tenant_id", tenant)
        setattr(st, "tenant_is_key_bound", False)

    return tenant


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
