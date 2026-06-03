"""Portal API router — C7 grant-based portal authentication.

Endpoints:
  POST /portal/authenticate    — exchange a grant secret for a server session
  GET  /portal/me              — return current session info + accessible engagements
  DELETE /portal/sessions/{id} — revoke a session (logout)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.auth_scopes import require_scopes
from api.db_models_portal import PortalGrant, PortalGrantSession
from api.deps import auth_ctx_db_session
from api.error_contracts import api_error
from services.portal_grant_service import portal_grant_svc

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
    dependencies=[Depends(require_scopes("governance:read"))],
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

    return PortalMeResponse(
        client_id=result.client_id or "",
        session_expires_at=session_row.expires_at if session_row else "",
        engagement_ids=[g.engagement_id for g in grants],
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
    dependencies=[Depends(require_scopes("governance:read"))],
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
