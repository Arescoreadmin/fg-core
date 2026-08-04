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
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

import api.credential_authority as ca
import api.portal_user_authority as pua
from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from api.db_models_portal import PortalGrant, PortalGrantSession
from api.deps import auth_ctx_db_session, get_db
from api.entitlements import require_capability
from api.error_contracts import api_error
from services.field_assessment.audit import audit_atomicity_svc
from api.tenant_authority import TenantKindError, tenant_kind_http_error
from services.portal_grant_service import (
    _list_canonical_engagement_ids,
    portal_grant_svc,
)
from services.identity_resolver import IdentityResolver, IdentityResolutionError
from api.identity_providers.auth0 import validate_auth0_token
from api.notifications.email import build_invitation_url, send_portal_invitation

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
    engagement_ids = list(
        dict.fromkeys(canonical_ids + legacy_ids)
    )  # dedup, preserve order

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

    try:
        result = portal_grant_svc.create_grant(
            db,
            tenant_id=tenant_id,
            client_id=body.client_id,
            engagement_id=body.engagement_id,
            created_by=actor,
            ttl_days=body.ttl_days,
            portal_role=role,
        )
    except TenantKindError as exc:
        raise tenant_kind_http_error(exc) from exc
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
    if legacy is not None:
        engagement_id: str | None = legacy.engagement_id
        client_id: str | None = legacy.client_id
    else:
        # Canonical grant: portal_grants row is absent. Recover engagement_id
        # from tenant_credentials metadata so the FA engagement audit is still
        # emitted. grant_id == credential_id for canonical grants.
        try:
            canonical_meta = (
                ca.get_credential(get_engine(), grant_id, tenant_id).metadata or {}
            )
            engagement_id = canonical_meta.get("engagement_id")
            client_id = canonical_meta.get("client_id")
        except ca.CredentialNotFoundError:
            engagement_id = None
            client_id = None
    if engagement_id is not None:
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


# ---------------------------------------------------------------------------
# Portal Named-User Identity Authority (PR A — portal_users distinct from
# tenant_users; OIDC maps into portal_users, never tenant_users).
# ---------------------------------------------------------------------------


class PortalEnrollBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    access_token: str
    oidc_provider: str = "auth0"


class PortalEnrollResponse(BaseModel):
    portal_user_id: str
    email: str
    display_name: str | None
    session_token: str
    expires_at: str
    membership_id: str | None


@portal_router.post(
    "/named-users/enroll",
    response_model=PortalEnrollResponse,
    status_code=200,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def portal_named_user_enroll(
    body: PortalEnrollBody,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> PortalEnrollResponse:
    """OIDC callback: resolve/create a portal_users record, issue a named-user session.

    Maps OIDC identity into portal_users (NOT tenant_users). Called server-side
    by the portal BFF after Auth0 code exchange. Requires governance:read scope
    (BFF service account authentication).

    Returns a pnu1. prefixed session token. The BFF stores this in a dedicated
    cookie (separate from grant-based sessions).
    """
    tenant_id = _resolve_tenant(request)

    try:
        actor = validate_auth0_token(body.access_token)
    except ValueError as exc:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_token", "reason": str(exc)},
        )

    domain = (os.getenv("FG_AUTH0_DOMAIN") or "").strip().rstrip("/")
    issuer = f"https://{domain}/" if domain else (actor.tenant_id or "")

    try:
        user = pua.find_or_create_portal_user(
            db,
            tenant_id=tenant_id,
            oidc_provider=body.oidc_provider,
            oidc_issuer=issuer,
            oidc_subject=actor.subject,
            email=actor.email or "",
            display_name=getattr(actor, "name", None),
            request_id=request.headers.get("x-request-id"),
        )
    except pua.PortalUserSuspendedError as exc:
        raise HTTPException(
            status_code=403,
            detail=api_error("PORTAL_USER_SUSPENDED", str(exc)),
        )

    # Find the best active membership for this user in this tenant.
    # Prefers tenant-wide (engagement_id IS NULL); falls back to the most
    # recently created engagement-scoped membership so that a repeat SSO login
    # by an engagement-scoped invitee resolves to their real membership row
    # instead of returning None (which would produce PORTAL_MEMBERSHIP_REQUIRED
    # on every subsequent engagement request).
    membership = pua.get_best_active_membership(
        db, portal_user_id=user.id, tenant_id=tenant_id
    )

    session = pua.create_session(
        db,
        portal_user_id=user.id,
        portal_membership_id=membership.id if membership else None,
        tenant_id=tenant_id,
        auth_version_snapshot=membership.auth_version if membership else 0,
        ip_address=_client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:512],
        request_id=request.headers.get("x-request-id"),
    )

    db.commit()
    return PortalEnrollResponse(
        portal_user_id=user.id,
        email=user.email,
        display_name=user.display_name,
        session_token=session.raw_token,  # type: ignore[arg-type]
        expires_at=session.expires_at,
        membership_id=membership.id if membership else None,
    )


class PortalNamedUserMeResponse(BaseModel):
    portal_user_id: str
    tenant_id: str
    email: str
    display_name: str | None
    portal_role: str | None
    engagement_id: str | None
    membership_id: str | None
    session_id: str


@portal_router.get(
    "/named-users/me",
    response_model=PortalNamedUserMeResponse,
)
def portal_named_user_me(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> PortalNamedUserMeResponse:
    """Return the current named-user's identity from their pnu1. session token.

    Identity is resolved exclusively from the validated pnu1. session — no
    caller-supplied tenant or user override is accepted.

    The session token is read from X-FG-Portal-Session. Tenant is resolved
    server-side via lookup_portal_session_by_fingerprint() (SECURITY DEFINER,
    migration 0171) so no X-Tenant-Id header is trusted.

    Cache-Control: no-store is set on the response.
    """
    from sqlalchemy import text as _text

    raw_token = request.headers.get(_PORTAL_SESSION_HEADER, "").strip()
    if not raw_token:
        raise HTTPException(
            status_code=401,
            detail=api_error(
                "PORTAL_SESSION_REQUIRED", "X-FG-Portal-Session header required"
            ),
        )
    if not raw_token.startswith("pnu1."):
        raise HTTPException(
            status_code=401,
            detail=api_error("PORTAL_SESSION_INVALID", "session token format invalid"),
        )

    # Resolve tenant from the token itself (no caller-supplied context trusted).
    lookup = pua.lookup_session_by_token(db, raw_token=raw_token)
    if lookup is None:
        raise HTTPException(
            status_code=401,
            detail=api_error(
                "PORTAL_SESSION_NOT_FOUND", "session not found or expired"
            ),
        )

    # Full validation with RLS (auth_version check, membership active check, audit).
    vr = pua.validate_session(db, raw_token=raw_token, tenant_id=lookup.tenant_id)
    if not vr.ok:
        raise HTTPException(
            status_code=401,
            detail=api_error(
                vr.denial_code or "PORTAL_SESSION_INVALID", vr.denial_reason or ""
            ),
        )

    # Fetch portal_user for email/display_name (RLS is now set from validate_session).
    user_row = db.execute(
        _text(
            """
            SELECT id, email, display_name
            FROM   portal_users
            WHERE  id        = :user_id
              AND  tenant_id = :tenant_id
            """
        ),
        {"user_id": vr.portal_user_id, "tenant_id": vr.tenant_id},
    ).fetchone()

    if user_row is None:
        raise HTTPException(
            status_code=401,
            detail=api_error("PORTAL_USER_NOT_FOUND", "portal user not found"),
        )

    response.headers["Cache-Control"] = "no-store"
    return PortalNamedUserMeResponse(
        portal_user_id=vr.portal_user_id or "",
        tenant_id=vr.tenant_id or "",
        email=str(user_row.email),
        display_name=user_row.display_name,
        portal_role=vr.portal_role,
        engagement_id=vr.engagement_id,
        membership_id=vr.portal_membership_id,
        session_id=vr.session_id or "",
    )


class PortalIssueInvitationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str
    portal_role: str = "viewer"
    engagement_id: str | None = None
    ttl_seconds: int | None = None
    idempotency_key: str | None = None


class PortalIssueInvitationResponse(BaseModel):
    invitation_id: str
    email: str
    portal_role: str
    engagement_id: str | None
    expires_at: str
    delivery_state: str
    delivery_error_code: str | None = None
    retryable: bool = False
    request_id: str | None = None


@portal_router.post(
    "/invitations",
    response_model=PortalIssueInvitationResponse,
    status_code=201,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def portal_issue_invitation(
    body: PortalIssueInvitationBody,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> PortalIssueInvitationResponse:
    """Issue a named-user portal invitation and send it via email.

    Idempotent: if idempotency_key matches an existing invitation, returns the
    existing record (no new invitation, no new email).
    Delivery failure does not roll back the invitation — the invitation remains
    valid and the delivery_state is persisted for operator visibility.
    """
    from sqlalchemy.exc import IntegrityError

    tenant_id = _resolve_tenant(request)
    auth = getattr(getattr(request, "state", None), "auth", None)
    actor_id = getattr(auth, "actor_id", None) or getattr(auth, "tenant_id", None)
    request_id = request.headers.get("x-request-id")

    kwargs: dict = dict(
        tenant_id=tenant_id,
        email=body.email,
        portal_role=body.portal_role,
        engagement_id=body.engagement_id,
        invited_by_actor_id=str(actor_id) if actor_id else None,
        request_id=request_id,
        idempotency_key=body.idempotency_key,
    )
    if body.ttl_seconds is not None:
        kwargs["ttl_seconds"] = body.ttl_seconds

    # ── Step 1: persist the invitation ──────────────────────────────────────
    # Idempotency: duplicate idempotency_key → return the existing record.
    try:
        inv = pua.create_invitation(db, **kwargs)
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        orig = getattr(exc, "orig", None)
        is_unique = (
            "UniqueViolation" in type(orig).__name__
            if orig
            else "unique" in str(exc).lower()
        )
        if is_unique and body.idempotency_key:
            existing = pua.get_invitation_by_idempotency_key(
                db, idempotency_key=body.idempotency_key, tenant_id=tenant_id
            )
            if existing is not None:
                return PortalIssueInvitationResponse(
                    invitation_id=existing.id,
                    email=existing.email,
                    portal_role=existing.portal_role,
                    engagement_id=existing.engagement_id,
                    expires_at=existing.expires_at,
                    delivery_state=existing.delivery_state,
                    delivery_error_code=existing.delivery_error_code,
                    retryable=existing.delivery_state == "failed",
                    request_id=request_id,
                )
        raise HTTPException(
            status_code=409,
            detail=api_error(
                "PORTAL_INVITATION_DUPLICATE", "duplicate idempotency_key"
            ),
        )

    # ── Step 2: send email (post-commit, raw_token available here only) ──────
    invitation_url = build_invitation_url(inv.raw_token, tenant_id)  # type: ignore[arg-type]
    result = send_portal_invitation(
        to_email=inv.email,
        invitation_url=invitation_url,
        portal_role=inv.portal_role,
        expires_at=inv.expires_at,
    )

    # ── Step 3: persist delivery outcome ────────────────────────────────────
    pua.update_invitation_delivery(
        db,
        invitation_id=inv.id,
        tenant_id=tenant_id,
        delivery_state=result.state,
        email_message_id=result.message_id,
        delivery_error_code=result.error_code,
    )
    db.commit()

    return PortalIssueInvitationResponse(
        invitation_id=inv.id,
        email=inv.email,
        portal_role=inv.portal_role,
        engagement_id=inv.engagement_id,
        expires_at=inv.expires_at,
        delivery_state=result.state,
        delivery_error_code=result.error_code,
        retryable=result.retryable,
        request_id=request_id,
    )


class PortalAcceptInvitationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    access_token: str
    oidc_provider: str = "auth0"
    tenant_id: str  # BFF must pass; no service-account header on this route


class PortalAcceptInvitationResponse(BaseModel):
    portal_user_id: str
    membership_id: str
    session_token: str
    expires_at: str
    portal_role: str
    engagement_id: str | None


@portal_router.post(
    "/invitations/{token}/accept",
    response_model=PortalAcceptInvitationResponse,
    status_code=200,
)
def portal_accept_invitation(
    token: str,
    body: PortalAcceptInvitationBody,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> PortalAcceptInvitationResponse:
    """Accept a portal invitation.

    No service-account auth required — the invitation token IS the authorization.
    Validates the Auth0 access_token to establish the acceptor's OIDC identity,
    then atomically accepts the invitation and creates the portal_user + membership.

    Concurrent acceptance: SELECT FOR UPDATE ensures exactly one winner.
    """
    try:
        actor = validate_auth0_token(body.access_token)
    except ValueError as exc:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_token", "reason": str(exc)},
        )

    domain = (os.getenv("FG_AUTH0_DOMAIN") or "").strip().rstrip("/")
    issuer = f"https://{domain}/" if domain else (actor.tenant_id or "")

    # Preflight: verify the invitation exists and is pending before creating any rows.
    # get_invitation_by_token requires tenant_id to set RLS — BFF provides it in body.
    inv_preview = pua.get_invitation_by_token(
        db, raw_token=token, tenant_id=body.tenant_id
    )
    if inv_preview is None:
        raise HTTPException(
            status_code=404,
            detail=api_error(
                "PORTAL_INVITATION_NOT_FOUND", "Invitation not found or expired"
            ),
        )
    if inv_preview.status != "pending":
        status_map = {
            "accepted": (
                409,
                "PORTAL_INVITATION_ALREADY_ACCEPTED",
                "Invitation already used",
            ),
            "revoked": (
                410,
                "PORTAL_INVITATION_REVOKED",
                "Invitation has been revoked",
            ),
            "expired": (410, "PORTAL_INVITATION_EXPIRED", "Invitation has expired"),
        }
        code, err_code, msg = status_map.get(
            inv_preview.status,
            (400, "PORTAL_INVITATION_INVALID", "Invitation not valid"),
        )
        raise HTTPException(status_code=code, detail=api_error(err_code, msg))

    try:
        user, membership, _inv = pua.accept_invitation(
            db,
            raw_token=token,
            tenant_id=body.tenant_id,
            oidc_provider=body.oidc_provider,
            oidc_issuer=issuer,
            oidc_subject=actor.subject,
            email=actor.email or "",
            display_name=getattr(actor, "name", None),
            request_id=request.headers.get("x-request-id"),
        )
    except pua.PortalInvitationInvalidError as exc:
        raise HTTPException(
            status_code=400,
            detail=api_error("PORTAL_INVITATION_INVALID", exc.reason),
        )
    except pua.PortalInvitationAlreadyAcceptedError:
        raise HTTPException(
            status_code=409,
            detail=api_error(
                "PORTAL_INVITATION_ALREADY_ACCEPTED", "Invitation already used"
            ),
        )
    except pua.PortalInvitationRevokedError:
        raise HTTPException(
            status_code=410,
            detail=api_error(
                "PORTAL_INVITATION_REVOKED", "Invitation has been revoked"
            ),
        )

    session = pua.create_session(
        db,
        portal_user_id=user.id,
        portal_membership_id=membership.id,
        tenant_id=membership.tenant_id,
        auth_version_snapshot=membership.auth_version,
        ip_address=_client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:512],
        request_id=request.headers.get("x-request-id"),
    )

    db.commit()
    return PortalAcceptInvitationResponse(
        portal_user_id=user.id,
        membership_id=membership.id,
        session_token=session.raw_token,  # type: ignore[arg-type]
        expires_at=session.expires_at,
        portal_role=membership.portal_role,
        engagement_id=membership.engagement_id,
    )


@portal_router.delete(
    "/named-sessions/self",
    status_code=204,
)
def portal_revoke_named_session_self(
    request: Request,
    db: Session = Depends(get_db),
) -> None:
    """Revoke the caller's own named-user portal session (browser logout).

    Requires the session's own pnu1. token in X-FG-Portal-Session — the token
    IS the credential; no service-account API key or tenant header is trusted.
    Tenant is resolved server-side from the session record.

    Semantics:
      - Valid active token → mark session revoked; emit audit; 204
      - Well-formed but unknown/expired/already-revoked token → 204 (idempotent)
      - Malformed token → 401
      - Missing header → 401

    Callers (portal BFF logout handler) treat this route as fire-and-forget for
    cookie clearing: any non-2xx still results in the browser cookie being
    cleared, so a leaked cookie replay is bounded by the Core-side record.
    """
    raw_token = request.headers.get(_PORTAL_SESSION_HEADER, "").strip()
    if not raw_token:
        raise HTTPException(
            status_code=401,
            detail=api_error(
                "PORTAL_SESSION_REQUIRED", "X-FG-Portal-Session header required"
            ),
        )
    if not raw_token.startswith("pnu1."):
        raise HTTPException(
            status_code=401,
            detail=api_error("PORTAL_SESSION_INVALID", "session token format invalid"),
        )

    # Idempotent by design: revoke_session_by_token returns revoked=False for
    # unknown/terminal tokens. Either outcome yields 204 so the BFF can always
    # clear the cookie without differentiating "already revoked" from success.
    pua.revoke_session_by_token(
        db,
        raw_token=raw_token,
        request_id=request.headers.get("x-request-id"),
    )
    db.commit()


@portal_router.delete(
    "/named-sessions/{session_id}",
    status_code=204,
)
def portal_revoke_named_session(
    session_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> None:
    """Revoke a named-user portal session (logout).

    Requires the session's own pnu1. token in X-FG-Portal-Session — the session
    authorizes its own revocation without a separate service account.
    """
    tenant_id = _resolve_tenant(request)
    raw_token = request.headers.get(_PORTAL_SESSION_HEADER, "").strip()
    if not raw_token:
        raise HTTPException(
            status_code=401,
            detail=api_error(
                "PORTAL_SESSION_REQUIRED", "X-FG-Portal-Session header required"
            ),
        )
    # Validate the token before allowing revocation (prevents CSRF-style blind revoke).
    vr = pua.validate_session(db, raw_token=raw_token, tenant_id=tenant_id)
    if not vr.ok:
        raise HTTPException(
            status_code=403,
            detail=api_error(
                vr.denial_code or "PORTAL_SESSION_INVALID", vr.denial_reason or ""
            ),
        )
    # Cross-check: token must own the session_id in the path (prevents using
    # a valid pnu1. token to blindly revoke a different session).
    if vr.session_id != session_id:
        raise HTTPException(
            status_code=403,
            detail=api_error("PORTAL_SESSION_MISMATCH", "Token does not match session"),
        )

    pua.revoke_session(db, session_id=session_id, tenant_id=tenant_id)
    db.commit()
