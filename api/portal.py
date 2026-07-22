"""Portal API router — C7 grant-based portal authentication.

Endpoints:
  POST /portal/authenticate    — exchange a grant secret for a server session
  GET  /portal/me              — return current session info + accessible engagements
  DELETE /portal/sessions/{id} — revoke a session (logout)
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

import api.credential_authority as ca
from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from api.db_models_portal import PortalGrant, PortalGrantSession
from api.deps import auth_ctx_db_session
from api.entitlements import require_capability
from api.error_contracts import api_error
from services.field_assessment.audit import audit_atomicity_svc
from services.portal_grant_service import _list_canonical_engagement_ids, portal_grant_svc
from services.identity_resolver import IdentityResolver, IdentityResolutionError
from api.identity_providers.auth0 import validate_auth0_token

log = logging.getLogger("frostgate.api.portal")

portal_router = APIRouter(prefix="/portal", tags=["portal"])

_PORTAL_SESSION_HEADER = "x-fg-portal-session"


def _resolve_tenant(request: Request) -> str:
    auth = getattr(getattr(request, "state", None), "auth", None)
    tenant_id = getattr(getattr(request, "state", None), "tenant_id", None) or getattr(
        auth, "tenant_id", None
    )
    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="tenant context required",
        )
    return str(tenant_id)


def _client_ip(request: Request) -> str:
    return (
        (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
        or request.headers.get("x-real-ip", "")
        or "unknown"
    )[:64]


# ---------------------------------------------------------------------------
# POST /portal/authenticate
# ---------------------------------------------------------------------------


class PortalAuthenticateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    secret: str


class PortalAuthenticateResponse(BaseModel):
    session_id: str
    expires_at: str
    client_id: str
    engagement_ids: list[str]


@portal_router.post(
    "/authenticate",
    response_model=PortalAuthenticateResponse,
    status_code=200,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def portal_authenticate(
    request: Request,
    body: PortalAuthenticateRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> PortalAuthenticateResponse:
    """Exchange a portal grant secret for a short-lived server-side session token.

    Called server-side by the portal BFF login handler — never exposed directly
    to the browser. The BFF authenticates with CORE_API_KEY; the portal user's
    secret is in the request body only.
    """
    tenant_id = _resolve_tenant(request)
    ip = _client_ip(request)
    ua = (request.headers.get("user-agent") or "")[:512]

    result = portal_grant_svc.authenticate(
        db,
        tenant_id=tenant_id,
        raw_secret=body.secret,
        ip_address=ip,
        user_agent=ua,
    )

    if not result.ok:
        db.commit()
        code = 429 if result.denial_reason == "rate_limited" else 401
        raise HTTPException(
            status_code=code,
            detail=api_error(
                "PORTAL_AUTH_FAILED",
                result.denial_reason or "Invalid portal secret",
            ),
        )

    db.commit()
    return PortalAuthenticateResponse(
        session_id=result.session_id,  # type: ignore[arg-type]
        expires_at=result.expires_at,  # type: ignore[arg-type]
        client_id=result.client_id,  # type: ignore[arg-type]
        engagement_ids=result.engagement_ids,
    )


# ---------------------------------------------------------------------------
# GET /portal/me
# ---------------------------------------------------------------------------


class PortalMeResponse(BaseModel):
    client_id: str
    session_expires_at: str
    engagement_ids: list[str]


@portal_router.get(
    "/me",
    response_model=PortalMeResponse,
    status_code=200,
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("portal.access")),
    ],
)
def portal_me(
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> PortalMeResponse:
    """Return session identity and accessible engagement IDs."""
    tenant_id = _resolve_tenant(request)
    session_id = request.headers.get(_PORTAL_SESSION_HEADER, "").strip()
    if not session_id:
        raise HTTPException(
            status_code=403,
            detail=api_error(
                "PORTAL_SESSION_REQUIRED", "X-FG-Portal-Session header required"
            ),
        )

    result = portal_grant_svc.validate_session(
        db, session_id=session_id, tenant_id=tenant_id
    )
    if not result.ok:
        raise HTTPException(
            status_code=403,
            detail=api_error(
                result.denial_code or "PORTAL_SESSION_INVALID",
                result.denial_reason or "Invalid session",
            ),
        )

    now_iso = datetime.now(timezone.utc).isoformat()
    grants = (
        db.execute(
            select(PortalGrant).where(
                PortalGrant.tenant_id == tenant_id,
                PortalGrant.client_id == result.client_id,
                PortalGrant.status == "active",
                PortalGrant.expires_at > now_iso,
                PortalGrant.revoked_at.is_(None),
            )
        )
        .scalars()
        .all()
    )

    session_row = db.execute(
        select(PortalGrantSession).where(
            PortalGrantSession.id == session_id,
            PortalGrantSession.tenant_id == tenant_id,
        )
    ).scalar_one_or_none()

    legacy_ids = [g.engagement_id for g in grants]
    canonical_ids = _list_canonical_engagement_ids(
        client_id=result.client_id or "",
        tenant_id=tenant_id,
    )
    engagement_ids = list(dict.fromkeys(canonical_ids + legacy_ids))  # dedup, preserve order

    return PortalMeResponse(
        client_id=result.client_id or "",
        session_expires_at=session_row.expires_at if session_row else "",
        engagement_ids=engagement_ids,
    )


# ---------------------------------------------------------------------------
# DELETE /portal/sessions/{session_id}
# ---------------------------------------------------------------------------


class RevokeSessionResponse(BaseModel):
    ok: bool


@portal_router.delete(
    "/sessions/{session_id}",
    response_model=RevokeSessionResponse,
    status_code=200,
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("portal.access")),
    ],
)
def portal_revoke_session(
    session_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> RevokeSessionResponse:
    """Revoke a portal session (server-side logout)."""
    tenant_id = _resolve_tenant(request)
    portal_grant_svc.revoke_session(db, session_id=session_id, tenant_id=tenant_id)
    db.commit()
    return RevokeSessionResponse(ok=True)


# ---------------------------------------------------------------------------
# Grant management — operator-facing (requires governance:write)
# ---------------------------------------------------------------------------

_VALID_PORTAL_ROLES = frozenset(
    {"general", "executive", "remediation", "technical", "compliance"}
)


class GrantItem(BaseModel):
    credential_id: str
    grant_id: str  # alias for credential_id — retained for backwards-compatibility
    client_id: str
    engagement_id: str
    portal_role: str
    status: str
    created_by: str | None
    created_at: str
    expires_at: str
    last_used_at: str | None
    rotation_counter: int
    source: str = "canonical"  # "canonical" | "legacy"


class ListGrantsResponse(BaseModel):
    items: list[GrantItem]
    total: int


@portal_router.get(
    "/grants",
    response_model=ListGrantsResponse,
    status_code=200,
    dependencies=[
        Depends(require_scopes("admin:read")),
    ],
)
def list_portal_grants(
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> ListGrantsResponse:
    """List all portal grants for the authenticated tenant.

    Returns canonical credentials (R4.9+) merged with active legacy grants
    that have not yet been migrated.  Sentinel migration records are excluded.
    """
    tenant_id = require_bound_tenant(request)
    items: list[GrantItem] = []
    canonical_grant_ids: set[str] = set()

    # Canonical grants — filter out legacy sentinel records.
    try:
        engine = get_engine()
        creds = ca.list_credentials(engine, tenant_id, credential_type="portal_access")
        for cred in creds:
            meta = cred.metadata or {}
            if meta.get("validation_mode") == "legacy_fallback_only":
                continue
            issued_at = cred.issued_at.isoformat() if cred.issued_at else ""
            expires_at = cred.expires_at.isoformat() if cred.expires_at else ""
            last_used = cred.last_used_at.isoformat() if cred.last_used_at else None
            items.append(
                GrantItem(
                    credential_id=cred.credential_id,
                    grant_id=cred.credential_id,
                    client_id=meta.get("client_id", ""),
                    engagement_id=meta.get("engagement_id", ""),
                    portal_role=_grant_type_to_role("client_portal"),
                    status=cred.status,
                    created_by=cred.created_by_actor_id,
                    created_at=issued_at,
                    expires_at=expires_at,
                    last_used_at=last_used,
                    rotation_counter=max(0, cred.generation - 1),
                    source="canonical",
                )
            )
            # Track legacy portal_grant_id cross-refs for deduplication below.
            if meta.get("portal_grant_id"):
                canonical_grant_ids.add(str(meta["portal_grant_id"]))
    except Exception:
        log.exception("list_credentials failed for tenant %s", tenant_id)

    # Legacy grants — only include those not already represented canonically.
    legacy_grants = (
        db.execute(
            select(PortalGrant)
            .where(PortalGrant.tenant_id == tenant_id)
            .order_by(PortalGrant.created_at.desc())
        )
        .scalars()
        .all()
    )
    for g in legacy_grants:
        if g.id in canonical_grant_ids:
            continue
        items.append(
            GrantItem(
                credential_id=g.id,
                grant_id=g.id,
                client_id=g.client_id,
                engagement_id=g.engagement_id,
                portal_role=_grant_type_to_role(g.grant_type),
                status=g.status,
                created_by=g.created_by,
                created_at=g.created_at,
                expires_at=g.expires_at,
                last_used_at=g.last_used_at,
                rotation_counter=g.rotation_counter,
                source="legacy",
            )
        )

    return ListGrantsResponse(items=items, total=len(items))


class CreateGrantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    client_id: str
    engagement_id: str
    portal_role: str = "general"
    ttl_days: int = 365


class CreateGrantResponse(BaseModel):
    credential_id: str
    grant_id: str  # alias for credential_id — retained for backwards-compatibility
    client_id: str
    engagement_id: str
    portal_role: str
    raw_secret: str
    expires_at: str
    portal_login_url: str
    source: str = "canonical"
    legacy_grant_id: str | None = None


@portal_router.post(
    "/grants",
    response_model=CreateGrantResponse,
    status_code=201,
    dependencies=[
        Depends(require_scopes("admin:write")),
    ],
)
def create_portal_grant(
    body: CreateGrantRequest,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> CreateGrantResponse:
    """Create a portal access grant. Returns the raw secret once — store it immediately."""
    tenant_id = require_bound_tenant(request)
    actor = getattr(getattr(request.state, "auth", None), "key_name", None) or "console"

    role = body.portal_role.lower().strip()
    if role not in _VALID_PORTAL_ROLES:
        raise HTTPException(
            status_code=422,
            detail=api_error(
                "INVALID_PORTAL_ROLE",
                f"portal_role must be one of: {', '.join(sorted(_VALID_PORTAL_ROLES))}",
            ),
        )

    result = portal_grant_svc.create_grant(
        db,
        tenant_id=tenant_id,
        client_id=body.client_id,
        engagement_id=body.engagement_id,
        created_by=actor,
        ttl_days=body.ttl_days,
        portal_role=role,
    )
    audit_atomicity_svc.emit(
        db,
        tenant_id=tenant_id,
        engagement_id=body.engagement_id,
        event_type="portal_grant.created",
        actor=actor,
        actor_type="human_operator",
        reason_code="PORTAL_GRANT_CREATED",
        entity_type="portal_grant",
        entity_id=result.credential_id,
        payload={
            "credential_id": result.credential_id,
            "client_id": result.client_id,
            "portal_role": role,
        },
    )
    db.commit()

    login_url = f"/login?tenant_id={tenant_id}"
    return CreateGrantResponse(
        credential_id=result.credential_id,
        grant_id=result.credential_id,
        client_id=result.client_id,
        engagement_id=result.engagement_id,
        portal_role=_grant_type_to_role(result.grant_type),
        raw_secret=result.raw_secret,
        expires_at=result.expires_at,
        portal_login_url=login_url,
        source="canonical",
        legacy_grant_id=result.legacy_grant_id,
    )


class RevokeGrantResponse(BaseModel):
    ok: bool


@portal_router.delete(
    "/grants/{grant_id}",
    response_model=RevokeGrantResponse,
    status_code=200,
    dependencies=[
        Depends(require_scopes("admin:write")),
    ],
)
def revoke_portal_grant(
    grant_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> RevokeGrantResponse:
    """Revoke a portal grant, immediately invalidating all active sessions for it."""
    tenant_id = require_bound_tenant(request)
    actor = getattr(getattr(request.state, "auth", None), "key_name", None) or "console"
    found = portal_grant_svc.revoke_grant(
        db, grant_id=grant_id, tenant_id=tenant_id, revoked_by=actor
    )
    if not found:
        raise HTTPException(
            status_code=404, detail=api_error("GRANT_NOT_FOUND", "Grant not found")
        )
    # For legacy grants grant_id matches portal_grants.id; for canonical grants it
    # matches tenant_credentials.credential_id and portal_grants row won't exist.
    legacy = db.execute(
        select(PortalGrant).where(
            PortalGrant.id == grant_id,
            PortalGrant.tenant_id == tenant_id,
        )
    ).scalar_one_or_none()
    engagement_id = legacy.engagement_id if legacy else None
    client_id = legacy.client_id if legacy else None
    audit_atomicity_svc.emit(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        event_type="portal_grant.revoked",
        actor=actor,
        actor_type="human_operator",
        reason_code="PORTAL_GRANT_REVOKED",
        entity_type="portal_grant",
        entity_id=grant_id,
        payload={"grant_id": grant_id, "client_id": client_id},
    )
    db.commit()
    return RevokeGrantResponse(ok=True)


def _grant_type_to_role(grant_type: str) -> str:
    prefix = "client_portal."
    if grant_type and grant_type.startswith(prefix):
        return grant_type[len(prefix) :]
    return "general"


# ---------------------------------------------------------------------------
# Named-user portal identity login (P1 — Auth0 OIDC for portal workforce users)
# ---------------------------------------------------------------------------


class PortalIdentityLoginBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    access_token: str


@portal_router.post(
    "/identity/login",
    summary="Verify Auth0 identity and resolve portal membership",
    dependencies=[Depends(require_scopes("governance:read"))],
)
def portal_identity_login(
    body: PortalIdentityLoginBody,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
):
    """Exchange a verified Auth0 access_token for portal user membership info.

    Called by the portal OIDC callback route after Auth0 code exchange. The
    endpoint:
      1. Validates the JWT via Auth0 JWKS (RS256, full signature + exp check).
      2. Resolves the identity triple (provider=auth0, issuer, sub) against
         tenant_users using IdentityResolver.
      3. Enforces deactivation: active=False → 403 membership_inactive.
      4. Returns user info for the portal to create a signed session cookie.

    Returns:
        200 — {user_id, email, display_name, role, tenant_id, membership_id}
        401 — invalid or expired token
        403 — membership inactive / revoked
        404 — no bound membership found
    """
    tenant_id = require_bound_tenant(request)

    # 1. Validate JWT
    try:
        actor = validate_auth0_token(body.access_token)
    except ValueError as exc:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_token", "reason": str(exc)},
        )

    # 2 + 3. Resolve membership and enforce deactivation
    domain = (os.getenv("FG_AUTH0_DOMAIN") or "").strip().rstrip("/")
    issuer = f"https://{domain}/" if domain else (actor.tenant_id or "")
    resolver = IdentityResolver()
    try:
        principal = resolver.resolve_or_deny(
            db,
            provider="auth0",
            issuer=issuer,
            subject=actor.subject,
            tenant_id=tenant_id,
        )
    except IdentityResolutionError as exc:
        if exc.code == "MEMBERSHIP_NOT_FOUND":
            raise HTTPException(
                status_code=404,
                detail={"error": "membership_not_found"},
            )
        raise HTTPException(
            status_code=403,
            detail={"error": exc.code.lower(), "reason": exc.reason},
        )

    return {
        "user_id": principal.membership_id,
        "email": principal.email,
        "display_name": principal.display_name or principal.email,
        "role": principal.roles[0] if principal.roles else "viewer",
        "tenant_id": principal.tenant_id,
        "membership_id": principal.membership_id,
        "membership_version": principal.membership_version,
    }
