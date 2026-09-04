from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import time
from typing import TYPE_CHECKING, Callable, Optional, Set

if TYPE_CHECKING:
    from api.actor_context import ActorContext

from fastapi import Depends, Header, HTTPException, Request

from api.config.internal_gateway_secret import resolve_internal_gateway_secret
from api.db import set_tenant_context
from api.platform_auth_mode import is_canonical_mode

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


def _lookup_canonical_platform_admin_role(
    engine, tenant_id: str, credential_id: str
) -> bool:
    """Return True iff the canonical credential holds the platform_admin RBAC role.

    Runs unconditionally for all authenticated canonical credentials — no
    tenant_id or credential_slot pre-condition. Fail closed: any exception
    returns False, collapsing platform authority to zero.
    """
    try:
        from api.tenant_rbac import get_credential_role as _gcr  # noqa: PLC0415
        from sqlalchemy import text as _text  # noqa: PLC0415

        with engine.connect() as _conn:
            # PostgreSQL RLS: tenant_credential_roles is protected by a policy
            # that requires app.tenant_id = tenant_id.  Set it before the query
            # so the row is visible to the RBAC lookup.
            if engine.dialect.name == "postgresql":
                _conn.execute(
                    _text("SELECT pg_catalog.set_config('app.tenant_id', :tid, true)"),
                    {"tid": tenant_id},
                )
            return (
                _gcr(_conn, tenant_id=tenant_id, credential_id=credential_id)
                == "platform_admin"
            )
    except Exception:
        log.warning(
            "canonical_platform_admin_role_lookup.failed",
            extra={
                "tenant_id": tenant_id,
                "cred_id": credential_id[:8] if credential_id else "",
            },
        )
        return False


_DELEGATION_CLOCK_TOLERANCE = 5  # seconds of future-dating tolerance
_DELEGATION_MAX_LIFETIME = 120  # reject proofs longer than 2 minutes

_ADMIN_GATEWAY_EXACT_PATHS = frozenset(
    {
        "/admin",
        "/portal/grants",
        "/portal/invitations",
        "/workforce/users",
    }
)
_ADMIN_GATEWAY_PREFIX_PATHS = (
    "/admin/",
    "/portal/grants/",
    "/workforce/users/",
)


def _is_admin_route_path(request_path: Optional[str]) -> bool:
    if not request_path:
        return False
    # Console tenant-admin operations are mediated by the Console BFF's
    # internal gateway identity plus explicit X-Tenant-ID. Keep this list in
    # lockstep with apps/console/app/api/core/[...path]/route.ts tenant-admin
    # surfaces so no tab falls back to ordinary tenant-credential auth.
    return request_path in _ADMIN_GATEWAY_EXACT_PATHS or request_path.startswith(
        _ADMIN_GATEWAY_PREFIX_PATHS
    )


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
        "governance:read",
        "governance:write",
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

    # ---------------------------------------------------------------------------
    # Path E — admin_internal_token  (P-113.6.1 corrected semantics)
    #
    # PLATFORM_AUTH_MODE controls whether Path E is active or retired.
    # Evaluated via is_canonical_mode() imported from api.platform_auth_mode.
    #
    # History and retirement plan
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Path E recognises X-API-Key == FG_INTERNAL_GATEWAY_SECRET on /admin/**
    # paths and returns reason="admin_internal_token".  Downstream, the api_key
    # identity provider maps admin_internal_token → _permissions_from_legacy_scopes()
    # → roles_to_permissions(["platform_admin"]) = ALL_PERMISSIONS ⊃ "platform.admin".
    #
    #   COMPATIBILITY (default) — Path E is active.  The console BFF sends the
    #     gateway secret as BOTH X-API-Key and X-FG-Internal-Token.
    #     Canonical fgk.* credentials are NOT Path-E credentials; they skip Path E
    #     entirely and proceed to canonical validation below.
    #
    #   CANONICAL (post-migration) — Path E is completely disabled as a source of
    #     platform.admin authority.  X-API-Key=FG_PLATFORM_ADMIN_KEY (a fgk.*
    #     credential) is required.  X-FG-Internal-Token=FG_INTERNAL_GATEWAY_SECRET
    #     independently authenticates gateway provenance via require_internal_admin_gateway().
    #
    #   Removal — Path E code deleted once all production environments have rotated
    #     to CANONICAL and the compatibility window has closed.
    #
    # Security invariants (P-113.6.1 defect fix)
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # The pre-fix defect: Path E evaluated BEFORE canonical credential validation.
    # When BFF sent X-API-Key=FG_PLATFORM_ADMIN_KEY (fgk.*) with CANONICAL intent,
    # Path E fired (admin route + gateway internal headers), then failed the secret
    # comparison (FG_PLATFORM_ADMIN_KEY != FG_INTERNAL_GATEWAY_SECRET) and returned
    # AuthResult(valid=False) — blocking canonical validation entirely.
    #
    # Fix applied here (Phase 3 / Phase 4):
    #   - CANONICAL mode: Path E is fully skipped; the request falls through to
    #     canonical credential validation.  Gateway provenance remains independently
    #     enforced by require_internal_admin_gateway() at the route layer.
    #   - COMPATIBILITY mode: Path E only fires if X-API-Key does NOT start with
    #     "fgk." (canonical prefix).  A fgk.* credential on an admin route is NOT
    #     a Path E credential — it is a canonical credential and must proceed to
    #     canonical validation.  Only the legacy non-fgk secret comparison is Path E.
    #   - A failed secret comparison in COMPATIBILITY mode (non-fgk credential that
    #     does not match FG_INTERNAL_GATEWAY_SECRET) is still fail-closed (reject),
    #     not a fall-through — consistent with existing security policy.
    #
    # NOTE: FG_PLATFORM_ADMIN_KEY and FG_INTERNAL_GATEWAY_SECRET MUST remain
    # distinct.  validate_canonical_mode_config() enforces this at startup.
    # ---------------------------------------------------------------------------
    _configured_internal = _admin_gateway_internal_token()
    _path_e_conditions_met = (
        (_is_production_env() or bool(_configured_internal))
        and _is_admin_route_path(request_path)
        and _is_gateway_internal_admin_request(request)
    )

    if _path_e_conditions_met:
        # CANONICAL mode: Path E is completely disabled.  The request MUST carry
        # a canonical fgk.* credential.  Fall through to canonical validation below.
        if is_canonical_mode():
            log.debug(
                "auth_path=path_e_skipped mode=CANONICAL reason=canonical_mode_enforced"
            )
            # Fall through — do not return here; let canonical validation run.
        elif raw.startswith("fgk."):
            # COMPATIBILITY mode + canonical fgk.* credential: not a Path E credential.
            # Continue to canonical validation — this is Phase 3 of the P-113.6
            # migration where both modes coexist.
            log.debug(
                "auth_path=path_e_skip_fgk mode=COMPATIBILITY reason=fgk_credential_not_path_e"
            )
            # Fall through — do not return here; let canonical validation run.
        else:
            # COMPATIBILITY mode + non-fgk credential on an admin route.
            # This is the legacy Path E path.  Validate the secret comparison.
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
                reason="legacy_path_e_authenticated",
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

    # Canary token detection: prefix-pattern only, zero DB access.
    _key_prefix_for_canary = raw.split(".")[0] if "." in raw else raw[:16]
    try:
        from api.tripwires import check_canary_key  # noqa: PLC0415

        if check_canary_key(_key_prefix_for_canary):
            _log_auth_event(
                "canary_token_accessed",
                success=False,
                key_prefix=_key_prefix_for_canary,
                reason="canary_token",
                request_path=request_path,
                client_ip=client_ip,
            )
            return AuthResult(
                valid=False, reason="canary_token", key_prefix=_key_prefix_for_canary
            )
    except ImportError:
        pass

    # ------------------------------------------------------------------
    # R4.7 — Canonical authority path.
    # All keys carry the "fgk." prefix and are resolved via tenant_credentials.
    # R4.11: legacy api_keys SQLite path removed; canonical auth is the only path.
    # ------------------------------------------------------------------
    if raw.startswith("fgk."):
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

            # Resolve RBAC classification BEFORE scope enforcement.
            # A platform_admin credential may be issued with empty scopes but
            # still holds platform.admin via RBAC, which subsumes all legacy
            # scope requirements.  Checking scopes first would reject a valid
            # platform-admin credential before its authority can be established.
            _ca_reason = (
                "canonical_platform_admin"
                if _lookup_canonical_platform_admin_role(
                    _ca_get_engine(),
                    _ca_principal.tenant_id,
                    _ca_principal.credential_id,
                )
                else "canonical_validated"
            )

            if required_scopes and _ca_reason != "canonical_platform_admin":
                # Scope enforcement applies only to non-platform-admin credentials.
                # canonical_platform_admin has platform.admin (all permissions) by
                # RBAC and is not constrained by legacy scope strings.
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
                reason=_ca_reason,
                request_path=request_path,
                client_ip=client_ip,
            )
            log.debug(
                "auth_path=canonical tenant=%s cred=%s reason=%s",
                _ca_principal.tenant_id,
                _ca_principal.credential_id,
                _ca_reason,
            )
            return AuthResult(
                valid=True,
                reason=_ca_reason,
                key_prefix="fgk",
                tenant_id=_ca_principal.tenant_id,
                scopes=_ca_scopes,
                credential_id=_ca_principal.credential_id,
                credential_slot=_ca_principal.credential_slot,
            )

    # R4.11: canonical path is the only valid path (legacy api_keys removed).
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


def _resolve_delegation_secrets() -> list[str]:
    current = (os.getenv("FG_GATEWAY_DELEGATION_SECRET_CURRENT") or "").strip()
    previous = (os.getenv("FG_GATEWAY_DELEGATION_SECRET_PREVIOUS") or "").strip()
    return [s for s in (current, previous) if s]


def validate_delegation_secret_config() -> None:
    """Called at startup. Raises RuntimeError in prod/strict if secret missing."""
    if (
        not _is_production_env()
        and (os.getenv("FG_STRICT_ENV") or "").strip().lower() != "true"
    ):
        return
    if not _resolve_delegation_secrets():
        raise RuntimeError(
            "FG_GATEWAY_DELEGATION_SECRET_CURRENT is required in production. "
            "Admin-gateway delegation proofs cannot be verified without it."
        )


def _verify_delegation_proof(request: Request, tenant_id: str) -> None:
    """Verify the short-lived HMAC delegation proof from the admin gateway BFF.

    Binds: version, request_id, tenant_id, HTTP method, canonical path,
    issued_at, expires_at. All six fields must match what Core independently
    derives from the live request.

    Non-prod bypass: if FG_GATEWAY_DELEGATION_SECRET_CURRENT is not configured,
    the check is skipped in non-prod/non-strict environments so local dev works.
    Fail-closed in production.
    """
    secrets = _resolve_delegation_secrets()
    if not secrets:
        if (
            _is_production_env()
            or (os.getenv("FG_STRICT_ENV") or "").strip().lower() == "true"
        ):
            log.error("delegation_proof.no_secret_configured")
            raise HTTPException(
                status_code=503,
                detail=redact_detail(
                    "delegation verification unavailable", generic="service unavailable"
                ),
            )
        log.debug("delegation_proof.dev_bypass_no_secret_configured")
        return

    version = (request.headers.get("x-fg-delegation-version") or "").strip()
    issued_at_str = (request.headers.get("x-fg-delegation-issued-at") or "").strip()
    expires_at_str = (request.headers.get("x-fg-delegation-expires-at") or "").strip()
    proof = (request.headers.get("x-fg-delegation-proof") or "").strip().lower()

    if not version or not issued_at_str or not expires_at_str or not proof:
        log.warning(
            "delegation_proof.missing",
            extra={"tenant_id": tenant_id, "has_version": bool(version)},
        )
        raise HTTPException(
            status_code=403,
            detail=redact_detail("delegation proof required", generic="forbidden"),
        )

    if version != "v1":
        log.warning("delegation_proof.unknown_version", extra={"version": version})
        raise HTTPException(
            status_code=403,
            detail=redact_detail("unknown delegation version", generic="forbidden"),
        )

    try:
        issued_at = int(issued_at_str)
        expires_at = int(expires_at_str)
    except ValueError:
        log.warning("delegation_proof.malformed_timestamps")
        raise HTTPException(
            status_code=403,
            detail=redact_detail(
                "malformed delegation timestamps", generic="forbidden"
            ),
        )

    now = int(time.time())

    if expires_at <= now:
        log.warning(
            "delegation_proof.expired",
            extra={"tenant_id": tenant_id, "expires_at": expires_at, "now": now},
        )
        raise HTTPException(
            status_code=403,
            detail=redact_detail("delegation proof expired", generic="forbidden"),
        )

    if issued_at > now + _DELEGATION_CLOCK_TOLERANCE:
        log.warning(
            "delegation_proof.future_dated",
            extra={"tenant_id": tenant_id, "issued_at": issued_at, "now": now},
        )
        raise HTTPException(
            status_code=403,
            detail=redact_detail(
                "delegation proof issued in future", generic="forbidden"
            ),
        )

    if expires_at - issued_at > _DELEGATION_MAX_LIFETIME:
        log.warning(
            "delegation_proof.lifetime_exceeded",
            extra={"tenant_id": tenant_id, "lifetime": expires_at - issued_at},
        )
        raise HTTPException(
            status_code=403,
            detail=redact_detail(
                "delegation proof lifetime too long", generic="forbidden"
            ),
        )

    req_id = _request_id(request) or ""
    method = (request.method or "").upper()
    path = str(request.url.path) if request.url else ""

    canonical = (
        f"v1\n{req_id}\n{tenant_id}\n{method}\n{path}\n{issued_at}\n{expires_at}"
    )

    for secret in secrets:
        expected = hmac.new(
            secret.encode(), canonical.encode(), hashlib.sha256
        ).hexdigest()
        if hmac.compare_digest(expected, proof):
            return

    log.warning(
        "delegation_proof.invalid",
        extra={"tenant_id": tenant_id, "method": method, "path": path},
    )
    raise HTTPException(
        status_code=403,
        detail=redact_detail("delegation proof invalid", generic="forbidden"),
    )


def _verify_admin_gateway_tenant(tenant_id: str) -> None:
    """Verify tenant exists and is active before binding admin-gateway authority.

    Called in the admin_internal_token branch of bind_tenant_id, after format
    validation and before request.state mutation. Fail closed: any DB error or
    non-active lifecycle state is treated as a denial.

    Without this check, a valid ADMIN_GATEWAY_TOKEN combined with a
    caller-controlled X-Tenant-ID could manufacture authority over any
    syntactically valid tenant string (PR-CORE-002).
    """
    try:
        from api.db import get_engine as _get_engine  # noqa: PLC0415
        from api.tenant_repository import TenantRepository  # noqa: PLC0415

        engine = _get_engine()
        repo = TenantRepository(engine)
        record = repo.get(tenant_id)
    except HTTPException:
        raise
    except Exception:
        log.warning(
            "admin_gateway_tenant_verify.db_error",
            extra={"tenant_id": tenant_id},
            exc_info=True,
        )
        raise HTTPException(
            status_code=503,
            detail=redact_detail(
                "tenant verification unavailable", generic="service unavailable"
            ),
        )

    if record is None:
        log.warning(
            "admin_gateway_tenant_verify.not_found",
            extra={"tenant_id": tenant_id},
        )
        raise HTTPException(
            status_code=404,
            detail=redact_detail(f"tenant not found: {tenant_id}", generic="not found"),
        )

    if record.lifecycle_state != "active":
        log.warning(
            "admin_gateway_tenant_verify.lifecycle_denied",
            extra={"tenant_id": tenant_id, "lifecycle_state": record.lifecycle_state},
        )
        raise HTTPException(
            status_code=403,
            detail=redact_detail(
                f"tenant {tenant_id} lifecycle={record.lifecycle_state}",
                generic="forbidden",
            ),
        )


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
        _pre_auth = getattr(getattr(request, "state", None), "auth", None)
        # PR-CORE-002C: for admin_internal_token, only trust the cached bind
        # when THIS request has already passed delegation proof + tenant
        # lifecycle verification (flagged via _admin_gateway_delegation_verified).
        # Without that flag we must fall through to the delegation branch
        # (defense-in-depth from PR-CORE-002B).
        _verified_flag = bool(
            getattr(
                getattr(request, "state", None),
                "_admin_gateway_delegation_verified",
                False,
            )
        )
        if (
            getattr(_pre_auth, "reason", "")
            in ("admin_internal_token", "canonical_platform_admin")
            and not _verified_flag
        ):
            # Defense-in-depth (PR-CORE-002B): admin_internal_token and
            # canonical_platform_admin must always pass delegation verification.
            # Clear pre-bound state so the branch below runs.
            request.state.tenant_is_key_bound = False
        else:
            cached = cached_tenant
            if requested and requested != cached:
                _tenant_denial_log(
                    request=request,
                    event="tenant_mismatch_denied",
                    reason="cached_tenant_mismatch",
                    tenant_from_key=cached,
                    tenant_supplied=requested,
                    key_prefix=getattr(_pre_auth, "key_prefix", None),
                    scopes=getattr(_pre_auth, "scopes", set()),
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

    if auth_tenant and getattr(auth, "reason", "") not in (
        "admin_internal_token",
        "canonical_platform_admin",
    ):
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

    if getattr(auth, "reason", "") in (
        "admin_internal_token",
        "canonical_platform_admin",
    ):
        if not requested:
            # PR-CORE-002C: fall back to X-Tenant-ID header when caller did not
            # forward the id explicitly. This is required for the second-hop
            # dependency (tenant_db_required) that runs after require_capability
            # has already verified the tenant against delegation + lifecycle.
            header_tenant = (
                request.headers.get("X-Tenant-Id") if request.headers else None
            )
            requested = (str(header_tenant).strip() if header_tenant else "") or None
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
        _verify_delegation_proof(request, requested)
        _verify_admin_gateway_tenant(requested)
        request.state.tenant_id = requested
        request.state.tenant_is_key_bound = True
        # PR-CORE-002C: mark this request as delegation-verified so subsequent
        # bind_tenant_id() calls (e.g. from tenant_db_required in the route
        # body) can trust the cached state and skip re-verification. Delegation
        # proof MUST have run at least once before this flag is set.
        request.state._admin_gateway_delegation_verified = True
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


def resolve_authoritative_tenant(
    request: Request,
    actor_ctx: "ActorContext",
    route_tenant_id: str,
) -> str:
    """Canonical tenant authority resolver for all tenant-admin mutations.

    Wraps bind_tenant_id() and adds an explicit actor_ctx.tenant_id cross-check.
    The route tenant is the only authoritative source; the actor session must
    agree or the request is rejected with 403.

    Audit event taxonomy:
    - identity.tenant.context_verified  — route, key binding, and actor session all agree
    - identity.tenant.stale_session     — actor_ctx.tenant_id disagrees with route tenant;
                                          the session is carrying a claim from a different
                                          (stale or revoked) tenant context
    - identity.tenant.resource_mismatch — reserved for downstream callers detecting that a
                                          fetched object's tenant_id differs from the
                                          authoritative route tenant
    - identity.auth.tenant_mismatch     — emitted by bind_tenant_id() for key/route
                                          disagreement; not re-emitted here
    """
    resolved = bind_tenant_id(request, route_tenant_id)
    actor_tenant = str(actor_ctx.tenant_id).strip() if actor_ctx.tenant_id else None
    if actor_tenant and actor_tenant != resolved:
        _log_auth_event(
            "identity.tenant.stale_session",
            success=False,
            tenant_id=resolved,
            reason="actor_tenant_mismatch",
        )
        raise HTTPException(
            status_code=403,
            detail=redact_detail("tenant mismatch", generic="forbidden"),
        )
    _log_auth_event(
        "identity.tenant.context_verified",
        success=True,
        tenant_id=resolved,
    )
    return resolved


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
