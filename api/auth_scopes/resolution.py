from __future__ import annotations

import hashlib
import logging
import os
import re
import time
from typing import Callable, Optional, Set

from fastapi import Depends, Header, HTTPException, Request

from api.config.internal_gateway_secret import resolve_internal_gateway_secret
from api.db import set_tenant_context

from .definitions import AuthResult, ERR_INVALID
from .helpers import (
    _constant_time_compare,
)
from .validation import (
    _is_production_env,
    _validate_tenant_id,
)

log = logging.getLogger("frostgate")
_security_log = logging.getLogger("frostgate.security")


def _is_admin_route_path(request_path: Optional[str]) -> bool:
    if not request_path:
        return False
    return request_path == "/admin" or request_path.startswith("/admin/")


def _admin_gateway_internal_token() -> str:
    """Return the expected internal token for admin-gateway→core requests.

    Delegates to resolve_internal_gateway_secret() — same resolver as
    require_internal_admin_gateway() in api/admin.py so both guards always
    compute the same expected value.
    """
    return resolve_internal_gateway_secret()


def _internal_admin_scopes() -> Set[str]:
    return {
        "admin:read",
        "admin:write",
        "admin:config",
        "keys:read",
        "keys:write",
        "audit:read",
    }


def _is_gateway_internal_admin_request(request: Optional[Request]) -> bool:
    if request is None:
        return False
    internal_header = (
        (request.headers.get("X-Admin-Gateway-Internal") or "").strip().lower()
    )
    if internal_header == "true":
        return True
    caller = (request.headers.get("X-FG-Internal-Caller") or "").strip().lower()
    return caller == "admin-gateway"


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

    if request.client is not None:
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
      2. Cookie (for UI sessions — non-hosted profiles only)

    Cookie auth is a browser/human auth path and is rejected in hosted profiles
    (prod, production, staging) to enforce service-only auth at core.
    Query parameters are NOT supported.
    """
    if x_api_key and str(x_api_key).strip():
        return str(x_api_key).strip()

    # Reject cookie-based auth in hosted profiles (prod/staging).
    # Cookie auth is a human/browser auth path not permitted at core in hosted runtime.
    if is_prod_like_env():
        return None

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

    # Dedicated admin-gateway -> core token enforcement for admin paths.
    # Active when: prod/staging env, OR when a local internal token is configured.
    # This closes the dev/local drift gap — a dev running with FG_INTERNAL_AUTH_SECRET
    # set will get real enforcement, not a silent bypass.
    _configured_internal = _admin_gateway_internal_token()
    if (
        (_is_production_env() or bool(_configured_internal))
        and _is_admin_route_path(request_path)
        and _is_gateway_internal_admin_request(request)
    ):
        required_internal = _configured_internal
        if not required_internal:
            _log_auth_event(
                "admin_internal_auth",
                success=False,
                reason="missing_internal_token_config",
                request_path=request_path,
                client_ip=client_ip,
            )
            return AuthResult(
                valid=False,
                reason="missing_internal_token_config",
            )
        if not (raw and _constant_time_compare(raw, required_internal)):
            _log_auth_event(
                "admin_internal_auth",
                success=False,
                reason="invalid_internal_token",
                request_path=request_path,
                client_ip=client_ip,
            )
            return AuthResult(
                valid=False,
                reason="invalid_internal_token",
            )
        _log_auth_event(
            "admin_internal_auth",
            success=True,
            reason="valid_internal_token",
            request_path=request_path,
            client_ip=client_ip,
        )
        internal_scopes = _internal_admin_scopes()
        if required_scopes:
            missing = set(required_scopes) - internal_scopes
            if missing:
                return AuthResult(
                    valid=False,
                    reason="missing_required_scopes",
                    key_prefix="ag_internal",
                    scopes=internal_scopes,
                )
        return AuthResult(
            valid=True,
            reason="admin_internal_token",
            key_prefix="ag_internal",
            scopes=internal_scopes,
        )

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

    _db_backend = (os.getenv("FG_DB_BACKEND") or "").strip().lower()
    _is_postgres = _db_backend == "postgres"

    sqlite_path = (os.getenv("FG_SQLITE_PATH") or "").strip()
    if not _is_postgres and not sqlite_path:
        _log_auth_event(
            "auth_attempt",
            success=False,
            reason="no_db_configured",
            request_path=request_path,
            client_ip=client_ip,
        )
        return AuthResult(valid=False, reason="no_db_configured")

    # ------------------------------------------------------------------
    # R4.7 — Canonical authority path (dual-validation, Deploy 1)
    # Keys issued by the credential authority carry the "fgk." prefix.
    # Try tenant_credentials first; on CredentialNotFoundError fall through
    # to the legacy api_keys path below.  Any other exception also falls
    # through — the canonical path must never block the hot auth path.
    # Migration telemetry: reason="canonical_validated" in auth_attempt
    # log distinguishes canonical hits from legacy hits.
    # ------------------------------------------------------------------
    if raw.startswith("fgk.") and _is_postgres:
        _ca_principal = None
        try:
            from api.credential_authority import (  # noqa: PLC0415
                CredentialNotFoundError as _CaNotFound,
                TenantLifecycleError as _CaLifecycleError,
                validate_credential as _ca_validate,
            )
            from api.db import get_engine as _ca_get_engine  # noqa: PLC0415

            try:
                _ca_principal = _ca_validate(_ca_get_engine(), raw)
            except _CaNotFound as _ca_exc:
                if getattr(_ca_exc, "absent", True):
                    log.debug("auth_path=canonical_miss falling_back=legacy")
                else:
                    # Credential exists in canonical store but is denied (hash
                    # mismatch, revoked, expired, etc.) — must not fall through.
                    log.debug("auth_path=canonical_denied")
                    return AuthResult(
                        valid=False, reason="key_invalid", key_prefix="fgk"
                    )
            except _CaLifecycleError:
                # Tenant lifecycle denial (suspended, archived, deleted) must
                # never fall through to the legacy path — policy denials are
                # not transient outages or misses.
                log.debug("auth_path=canonical_lifecycle_denied")
                return AuthResult(
                    valid=False, reason="tenant_lifecycle_denied", key_prefix="fgk"
                )
            except Exception:
                log.warning(
                    "auth_path=canonical_error falling_back=legacy", exc_info=True
                )
        except ImportError:
            log.warning(
                "auth_path=canonical_import_error falling_back=legacy", exc_info=True
            )

        if _ca_principal is not None:
            _ca_scopes: Set[str] = set(_ca_principal.scopes)

            if required_scopes:
                if isinstance(required_scopes, str):
                    _ca_needed: Set[str] = {required_scopes}
                elif isinstance(required_scopes, (list, set, frozenset)):
                    _ca_needed = set(required_scopes)
                else:
                    _ca_needed = {str(required_scopes)}
                _ca_needed = {s.strip() for s in _ca_needed if str(s).strip()}
                if (
                    _ca_needed
                    and "*" not in _ca_scopes
                    and not _ca_needed.issubset(_ca_scopes)
                ):
                    return AuthResult(
                        valid=False,
                        reason=f"missing_scopes:{','.join(_ca_needed - _ca_scopes)}",
                        key_prefix="fgk",
                        tenant_id=_ca_principal.tenant_id,
                        scopes=_ca_scopes,
                    )

            _log_auth_event(
                "auth_attempt",
                success=True,
                key_prefix="fgk",
                tenant_id=_ca_principal.tenant_id,
                reason="canonical_validated",
                request_path=request_path,
                client_ip=client_ip,
            )
            log.debug(
                "auth_path=canonical tenant=%s cred=%s",
                _ca_principal.tenant_id,
                _ca_principal.credential_id,
            )
            return AuthResult(
                valid=True,
                reason="canonical_validated",
                key_prefix="fgk",
                tenant_id=_ca_principal.tenant_id,
                scopes=_ca_scopes,
                credential_id=_ca_principal.credential_id,
            )

    # R4.8: Legacy api_keys path retired. Only fgk. keys on Postgres are valid.
    # Non-fgk. keys, SQLite backend, and any key not found in tenant_credentials
    # are rejected here. No fallback.
    _log_auth_event(
        "auth_attempt",
        success=False,
        reason="key_not_found",
        request_path=request_path,
        client_ip=client_ip,
    )
    return AuthResult(valid=False, reason="key_not_found")


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
    scopes: set[str] = getattr(auth, "scopes", set())

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

    if getattr(auth, "reason", "") == "admin_internal_token":
        if not requested:
            raise HTTPException(
                status_code=400,
                detail=redact_detail(
                    "tenant_id required for unscoped keys", generic="invalid request"
                ),
            )
        valid, _error = _validate_tenant_id(requested)
        if not valid:
            raise HTTPException(
                status_code=400,
                detail=redact_detail("invalid tenant_id", generic="invalid request"),
            )
        request.state.tenant_id = requested
        request.state.tenant_is_key_bound = True
        _apply_tenant_context(request, requested)
        return requested

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


def _apply_tenant_context(request: Request, tenant_id: str) -> None:
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


def authz_scope(*scopes: str) -> Callable[..., None]:
    """Declare intended scope metadata for governance tooling and lint.

    Does NOT enforce scope at runtime. Use require_role() for authorization
    on routes where a role implies the scope rather than explicit scopes_csv.
    The scope names are extracted by route_checks.py for route inventory,
    scope lint, and compliance export — satisfying the same tooling that
    require_scopes() satisfies without blocking role-authorized requests.
    """
    _ = scopes  # consumed by AST; not used at runtime

    def _dep() -> None:
        return None

    return _dep
