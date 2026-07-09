"""api/identity_authority/integration.py — FastAPI dependency bindings.

Provides FastAPI dependencies for the unified identity authority.
Routes should import from here, not from auth_dispatch directly.

Three dependency tiers:
  1. get_authorization_context()  — resolves a full AuthorizationContext
  2. require_permission_v2(*perms) — enforces permissions, returns AuthorizationContext
  3. get_actor_context_compat()   — backwards compat wrapper returning ActorContext

New routes should use get_authorization_context() or require_permission_v2().
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from api.deps import auth_ctx_db_session
from api.identity_authority.models import AuthorizationContext
from api.identity_authority.providers.base import (
    IdentityProviderError,
    IdentityValidationError,
)

log = logging.getLogger("frostgate.identity_authority.integration")

_AUTHORITY_ENABLED = os.getenv("FG_IDENTITY_AUTHORITY_ENABLED", "0").strip() == "1"


def get_authorization_context(
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> AuthorizationContext:
    """Resolve a full AuthorizationContext from the incoming request.

    Resolution order:
      1. Dev bypass (FG_AUTH_ENABLED=0) — full permissions, never in prod
      2. Bearer JWT — resolved via IdentityAuthority.authenticate_jwt()
      3. API key — resolved via MachineIdentityAuthority
      4. Anonymous context (no permissions)
    """
    if _is_auth_disabled(request):
        return _dev_bypass_context(request)

    bearer = (request.headers.get("Authorization") or "").strip()
    tenant_hint = request.headers.get("X-Tenant-Id") or None
    cid = request.headers.get("X-Correlation-Id") or None

    if bearer.lower().startswith("bearer "):
        token = bearer.split(" ", 1)[1].strip()
        if token:
            return _resolve_jwt(token, tenant_id_hint=tenant_hint, correlation_id=cid, db=db)

    api_key_ctx = _resolve_api_key(request, db=db, correlation_id=cid)
    if api_key_ctx is not None:
        return api_key_ctx

    return _anonymous_context(cid)


def require_permission_v2(*required_perms: str):
    """FastAPI dependency factory enforcing ALL listed permissions.

    Returns AuthorizationContext on success.
    Raises 403 on any missing permission.

    Usage:
        ctx: AuthorizationContext = Depends(require_permission_v2("risk.accept"))
    """
    perms_needed: frozenset[str] = frozenset(p.strip() for p in required_perms if p.strip())

    def _dep(
        ctx: AuthorizationContext = Depends(get_authorization_context),
    ) -> AuthorizationContext:
        missing = perms_needed - ctx.permissions
        if missing:
            identity = ctx.identity
            log.warning(
                "permission_denied",
                extra={
                    "subject_prefix": identity.subject[:16],
                    "provider": identity.provider.name,
                    "required": sorted(perms_needed),
                    "missing": sorted(missing),
                },
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "PERMISSION_DENIED",
                    "required_permissions": sorted(perms_needed),
                },
            )
        return ctx

    return _dep


def get_actor_context_compat(
    ctx: AuthorizationContext = Depends(get_authorization_context),
):
    """Backwards compatibility shim: returns ActorContext from AuthorizationContext.

    Use for routes not yet migrated to AuthorizationContext. Prefer
    get_authorization_context() for new routes.
    """
    return ctx.to_actor_context()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _is_auth_disabled(request: Request) -> bool:
    app = getattr(request, "app", None)
    if app is None:
        return False
    return not bool(getattr(getattr(app, "state", None), "auth_enabled", True))


def _dev_bypass_context(request: Request) -> AuthorizationContext:
    import secrets
    from datetime import datetime, timezone
    from api.actor_context import ALL_PERMISSIONS
    from api.identity_authority.models import (
        AuthenticationContext,
        CanonicalIdentity,
        IdentityProvider,
    )

    now = datetime.now(tz=timezone.utc)
    provider = IdentityProvider(name="dev_bypass", issuer="frostgate.local", subject="dev_bypass")
    auth_ctx = AuthenticationContext(
        mfa_verified=True,
        mfa_method=None,
        auth_time=now,
        amr=["dev"],
        acr=None,
        pkce_used=False,
        nonce_verified=False,
    )
    identity = CanonicalIdentity(
        subject="dev_bypass",
        email="dev@frostgate.local",
        name="Dev User",
        email_verified=True,
        provider=provider,
        auth_context=auth_ctx,
        tenant_binding=None,
        subscription=None,
        identity_type="human",
        issued_at=now,
        expires_at=now,
    )
    return AuthorizationContext(
        identity=identity,
        permissions=ALL_PERMISSIONS,
        capabilities=frozenset(),
        tenant_id=None,
        organization_id=None,
        session_id="",
        session_risk_score=0.0,
        correlation_id=secrets.token_hex(8),
    )


def _resolve_jwt(
    token: str,
    *,
    tenant_id_hint: Optional[str],
    correlation_id: Optional[str],
    db: Session,
) -> AuthorizationContext:
    from api.identity_authority.authority import get_identity_authority

    try:
        return get_identity_authority().authenticate_jwt(
            token,
            tenant_id_hint=tenant_id_hint,
            correlation_id=correlation_id,
            db=db,
        )
    except IdentityValidationError as exc:
        log.warning(
            "integration.jwt_rejected",
            extra={"code": exc.code, "provider": exc.provider},
        )
        raise HTTPException(
            status_code=401,
            detail={"code": "INVALID_JWT", "reason": exc.code},
        )
    except IdentityProviderError as exc:
        log.error(
            "integration.provider_error",
            extra={"provider": exc.provider, "reason": str(exc)},
        )
        raise HTTPException(
            status_code=503,
            detail={"code": "PROVIDER_UNAVAILABLE"},
        )


def _resolve_api_key(
    request: Request,
    *,
    db: Optional[Session],
    correlation_id: Optional[str],
) -> Optional[AuthorizationContext]:
    """Resolve an API key context from request.state.auth (set by middleware)."""
    from api.identity_authority.machine_identity import get_machine_authority

    machine_auth = get_machine_authority()
    identity = machine_auth.authenticate_api_key_from_state(request.state, db=db)
    if identity is None:
        return None

    import secrets
    from api.identity_authority.models import AuthorizationContext

    binding = identity.tenant_binding
    return AuthorizationContext(
        identity=identity,
        permissions=binding.permissions if binding else frozenset(),
        capabilities=frozenset(),
        tenant_id=binding.tenant_id if binding else None,
        organization_id=None,
        session_id="",
        session_risk_score=0.0,
        correlation_id=correlation_id or secrets.token_hex(8),
    )


def _anonymous_context(correlation_id: Optional[str]) -> AuthorizationContext:
    import secrets
    from datetime import datetime, timezone
    from api.identity_authority.models import (
        AuthenticationContext,
        CanonicalIdentity,
        IdentityProvider,
    )

    now = datetime.now(tz=timezone.utc)
    provider = IdentityProvider(name="anonymous", issuer="", subject="anonymous")
    auth_ctx = AuthenticationContext(
        mfa_verified=False,
        mfa_method=None,
        auth_time=now,
        amr=[],
        acr=None,
        pkce_used=False,
        nonce_verified=False,
    )
    identity = CanonicalIdentity(
        subject="anonymous",
        email="",
        name="",
        email_verified=False,
        provider=provider,
        auth_context=auth_ctx,
        tenant_binding=None,
        subscription=None,
        identity_type="human",
        issued_at=now,
        expires_at=now,
    )
    return AuthorizationContext(
        identity=identity,
        permissions=frozenset(),
        capabilities=frozenset(),
        tenant_id=None,
        organization_id=None,
        session_id="",
        session_risk_score=0.0,
        correlation_id=correlation_id or secrets.token_hex(8),
    )
