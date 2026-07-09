"""api/auth_dispatch.py — Provider resolution and permission enforcement (H14).

Public API:
  get_actor_context(request, conn) → ActorContext
      FastAPI dependency. Resolves ActorContext from whichever identity
      mechanism is present:
        1. Bearer JWT (Auth0; Entra/Okta when configured)
        2. API key from request.state.auth + DB role lookup
        3. Dev bypass when FG_AUTH_ENABLED=0 (full permissions, never in prod)

  require_permission(*perms) → FastAPI dependency factory
      Calls get_actor_context(), enforces ALL required permissions, returns
      the ActorContext for use in the route handler (actor attribution).

Routes never import from identity_providers directly. They depend on
ActorContext and require_permission() only.

Example usage:
    from api.auth_dispatch import require_permission
    from api.actor_context import ActorContext
    from fastapi import Depends

    @router.post("/risk-acceptances",
        dependencies=[Depends(require_scopes("governance:write"))])
    def create_risk_acceptance(
        body: RiskAcceptanceCreateBody,
        actor: ActorContext = Depends(require_permission("risk.accept")),
        db: Session = Depends(auth_ctx_db_session),
    ):
        # actor.subject, actor.email, actor.name, actor.primary_role() are
        # the authoritative attribution values — never from the request body.
        ...
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from api.actor_context import ActorContext, ALL_PERMISSIONS
from api.deps import auth_ctx_db_session

log = logging.getLogger("frostgate.auth_dispatch")


# ---------------------------------------------------------------------------
# Auth-disabled detection
# ---------------------------------------------------------------------------


def _auth_disabled(request: Request) -> bool:
    """Return True when FG_AUTH_ENABLED=0 disables auth globally."""
    app = getattr(request, "app", None)
    if app is None:
        return False
    return not bool(getattr(getattr(app, "state", None), "auth_enabled", True))


# ---------------------------------------------------------------------------
# Provider resolution
# ---------------------------------------------------------------------------


def _try_jwt_actor(request: Request, conn: Optional[Session] = None) -> Optional[ActorContext]:
    """Attempt to resolve an ActorContext from a Bearer JWT."""
    bearer = (request.headers.get("Authorization") or "").strip()
    if not bearer.lower().startswith("bearer "):
        return None
    token = bearer.split(" ", 1)[1].strip()
    if not token:
        return None

    # FIAP path — active when FG_IDENTITY_AUTHORITY_ENABLED=1
    if os.getenv("FG_IDENTITY_AUTHORITY_ENABLED", "0").strip() == "1":
        try:
            from api.identity_authority.providers.base import (
                IdentityProviderError,
                IdentityValidationError,
            )
            from api.identity_authority.authority import get_identity_authority

            tenant_hint = request.headers.get("X-Tenant-Id") or None
            cid = request.headers.get("X-Correlation-Id") or None
            ctx = get_identity_authority().authenticate_jwt(
                token, tenant_id_hint=tenant_hint, correlation_id=cid, db=conn
            )
            return ctx.to_actor_context()
        except IdentityValidationError as exc:
            log.warning(
                "auth_dispatch.jwt_validation_failed",
                extra={"provider": exc.provider, "reason": exc.code},
            )
            raise HTTPException(
                status_code=401,
                detail={"code": "INVALID_JWT", "reason": exc.code},
            )
        except IdentityProviderError as exc:
            log.error(
                "auth_dispatch.provider_error",
                extra={"provider": exc.provider, "reason": str(exc)},
            )
            raise HTTPException(
                status_code=503,
                detail={"code": "PROVIDER_UNAVAILABLE"},
            )
        except Exception as exc:
            log.exception("auth_dispatch.jwt_unexpected_error", extra={"exc": str(exc)})
            raise HTTPException(
                status_code=401,
                detail={"code": "AUTH_ERROR", "reason": "JWT validation error"},
            )

    # Auth0 provider — active when FG_AUTH0_DOMAIN is configured (legacy path)
    try:
        if (os.getenv("FG_AUTH0_DOMAIN") or "").strip():
            from api.identity_providers.auth0 import validate_auth0_token

            return validate_auth0_token(token)
    except ValueError as exc:
        # Validation failure (expired, bad signature, etc.) — log and fall through
        log.warning(
            "auth_dispatch.jwt_validation_failed",
            extra={"provider": "auth0", "reason": str(exc)},
        )
        # A malformed or invalid JWT is an authentication failure, not a missing
        # key fallback. Raise 401 so the caller knows the credential was rejected.
        raise HTTPException(
            status_code=401,
            detail={"code": "INVALID_JWT", "reason": str(exc)},
        )
    except ImportError:
        pass
    except Exception as exc:
        log.exception("auth_dispatch.jwt_unexpected_error", extra={"exc": str(exc)})
        # Unexpected errors should not silently fall through to API key auth
        raise HTTPException(
            status_code=401,
            detail={"code": "AUTH_ERROR", "reason": "JWT validation error"},
        )

    return None


def _try_api_key_actor(request: Request, conn: Session) -> Optional[ActorContext]:
    """Build ActorContext from the API key context set by auth middleware."""
    from api.identity_providers.api_key import extract_api_key_actor

    return extract_api_key_actor(request, conn)


def _bind_membership(actor: ActorContext, conn: Session) -> ActorContext:
    """Augment a JWT ActorContext with tenant_users membership_id.

    Looks up the bound membership record using the identity triple
    (provider=auth0, issuer, subject). Adds membership_id and enforces
    deactivation.

    Hard-fails 403 on MEMBERSHIP_NOT_FOUND: OIDC human actors must have a
    bound tenant_users record. Service accounts use API keys and never reach
    this function, so there is no legitimate "OIDC actor without membership"
    case in normal operation.

    Hard-fails 403 on MEMBERSHIP_INACTIVE: deactivated members are denied
    immediately regardless of when their session was issued.
    """
    try:
        from services.identity_resolver import IdentityResolver, IdentityResolutionError

        domain = (os.getenv("FG_AUTH0_DOMAIN") or "").strip().rstrip("/")
        if not domain or not actor.subject:
            return actor

        issuer = f"https://{domain}/"
        resolver = IdentityResolver()
        try:
            principal = resolver.resolve_or_deny(
                conn,
                provider="auth0",
                issuer=issuer,
                subject=actor.subject,
                tenant_id=actor.tenant_id,
            )
        except IdentityResolutionError as exc:
            # Both MEMBERSHIP_NOT_FOUND and MEMBERSHIP_INACTIVE are hard denials.
            # OIDC actors without a bound membership are not service accounts —
            # service accounts authenticate via API keys, not Bearer JWTs.
            log.warning(
                "auth_dispatch.membership_denied",
                extra={"code": exc.code, "subject_prefix": actor.subject[:16]},
            )
            raise HTTPException(
                status_code=403,
                detail={"code": exc.code, "reason": str(exc)},
            )

        return ActorContext(
            subject=actor.subject,
            email=actor.email,
            name=actor.name,
            permissions=actor.permissions,
            roles=actor.roles,
            auth_source=actor.auth_source,
            tenant_id=principal.tenant_id,
            membership_id=principal.membership_id,
        )
    except HTTPException:
        raise
    except Exception as exc:
        log.warning(
            "auth_dispatch.membership_lookup_error",
            extra={"exc": str(exc)},
        )
        return actor


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------


def get_actor_context(
    request: Request,
    conn: Session = Depends(auth_ctx_db_session),
) -> ActorContext:
    """Resolve ActorContext from whichever identity mechanism is present.

    Resolution order:
      1. Dev bypass (FG_AUTH_ENABLED=0) → full permissions, never in prod
      2. Bearer JWT (Auth0 when FG_AUTH0_DOMAIN is set)
      3. API key context from request.state.auth
      4. Anonymous context with no permissions
    """
    if _auth_disabled(request):
        return ActorContext(
            subject="dev_bypass",
            email="dev@frostgate.local",
            name="Dev User",
            permissions=ALL_PERMISSIONS,
            roles=["platform_admin"],
            auth_source="dev_bypass",
            tenant_id=None,
        )

    # JWT path takes priority when a Bearer token is present
    bearer = (request.headers.get("Authorization") or "").strip()
    if bearer.lower().startswith("bearer "):
        actor = _try_jwt_actor(request, conn)
        if actor:
            # Bind membership_id and enforce deactivation for Auth0 JWT actors
            if actor.auth_source == "oidc_auth0":
                actor = _bind_membership(actor, conn)
            return actor
        # _try_jwt_actor raises HTTPException on invalid token; if it returns
        # None the bearer was empty — fall through to API key auth

    actor = _try_api_key_actor(request, conn)
    if actor:
        return actor

    return ActorContext(
        subject="anonymous",
        email="",
        name="",
        permissions=frozenset(),
        roles=[],
        auth_source="none",
        tenant_id=None,
    )


def require_permission(*required_perms: str):
    """FastAPI dependency factory for permission-based authorization.

    Resolves ActorContext, verifies ALL required permissions, and returns
    the ActorContext for use in the route handler (actor attribution).

    Fail-closed: missing permission → 403 with the required permission list.
    Dev bypass (FG_AUTH_ENABLED=0) grants all permissions.

    Usage:
        actor: ActorContext = Depends(require_permission("risk.accept"))
    """
    perms_needed: frozenset[str] = frozenset(
        p.strip() for p in required_perms if p.strip()
    )

    def _dep(
        actor: ActorContext = Depends(get_actor_context),
    ) -> ActorContext:
        missing = perms_needed - actor.permissions
        if missing:
            log.warning(
                "permission_denied",
                extra={
                    "event": "permission_denied",
                    "actor_subject": actor.subject,
                    "actor_roles": actor.roles,
                    "actor_auth_source": actor.auth_source,
                    "required_permissions": sorted(perms_needed),
                    "missing_permissions": sorted(missing),
                },
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "PERMISSION_DENIED",
                    "required_permissions": sorted(perms_needed),
                },
            )
        return actor

    return _dep
