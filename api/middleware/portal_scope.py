"""Portal scope middleware — C7 grant-based engagement access.

Enforces that portal requests to /field-assessment/engagements/{id}/* carry
a valid server-side session token (X-FG-Portal-Session header) backed by an
active portal grant in the database.

Security invariants:
- Portal identity is derived server-side from the validated session record.
  It is NEVER derived from caller-asserted headers, query parameters, or the
  request body.
- X-Portal-Source marks a request as portal-origin; the middleware then
  requires X-FG-Portal-Session and validates it against the DB.
- Engagement binding: validated via portal_grants.(client_id, engagement_id).
  A valid session alone is insufficient; an active grant for the specific
  engagement must exist.
- Any DB or validation exception → 403 fail-closed.
"""

from __future__ import annotations

import re
from typing import Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from sqlalchemy import text

from api.db import get_sessionmaker
from api.portal_user_authority import (
    SESSION_TOKEN_PREFIX,
    validate_session as validate_named_session,
)
from services.portal_grant_service import portal_grant_svc

_PORTAL_ENGAGEMENT_RE = re.compile(r"^/field-assessment/engagements/([^/]+)")
_PORTAL_REMEDIATION_RE = re.compile(r"^/portal/remediation")
_PORTAL_SOURCE_HEADER = "x-portal-source"
_PORTAL_SOURCE_VALUE = "client-portal"
_PORTAL_SESSION_HEADER = "x-fg-portal-session"
_MEMBERSHIP_ID_HEADER = "x-fg-membership-id"
_MEMBERSHIP_VERSION_HEADER = "x-fg-membership-version"

_NAMED_USER_VERSION_SQL = text(
    """
    SELECT membership_version, active
    FROM tenant_users
    WHERE id        = :membership_id
      AND tenant_id = :tenant_id
      AND identity_binding_status = 'bound'
    LIMIT 1
    """
)


def _json_403(message: str, code: str) -> JSONResponse:
    return JSONResponse(
        {"detail": message, "code": code},
        status_code=403,
        headers={"Cache-Control": "no-store"},
    )


class PortalClientScopeMiddleware(BaseHTTPMiddleware):
    """Enforce session-based engagement access for portal requests.

    AuthGateMiddleware runs before this and populates request.state.tenant_id.
    No-op for requests without X-Portal-Source: client-portal.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.headers.get(_PORTAL_SOURCE_HEADER) != _PORTAL_SOURCE_VALUE:
            return await call_next(request)

        path = request.scope.get("path", "")
        session_token_raw = request.headers.get(_PORTAL_SESSION_HEADER, "").strip()

        # ── pnu1. catch-all (P1-A) ────────────────────────────────────────────
        # Any portal request that carries a pnu1. session token MUST be validated
        # server-side regardless of path. Previously only engagement/remediation
        # paths validated the token, which allowed a forged pnu1. cookie to
        # reach non-engagement handlers (e.g. /governance/assets/*) unchecked.
        # Path-specific engagement binding is applied after the session is proven
        # valid; other portal paths simply require a valid session.
        if session_token_raw.startswith(SESSION_TOKEN_PREFIX):
            tenant_id = getattr(getattr(request, "state", None), "tenant_id", None)
            if not tenant_id:
                return _json_403("Missing tenant context", "PORTAL_TENANT_MISSING")

            SessionLocal = get_sessionmaker()
            db = SessionLocal()
            try:
                named_result = validate_named_session(
                    db,
                    raw_token=session_token_raw,
                    tenant_id=str(tenant_id),
                )
                db.commit()  # persist last_validated_at + audit event
            except Exception:
                db.close()
                return _json_403(
                    "Access check unavailable", "PORTAL_ACCESS_CHECK_FAILED"
                )
            finally:
                db.close()

            if not named_result.ok:
                return _json_403(
                    named_result.denial_reason or "Access denied",
                    named_result.denial_code or "PORTAL_ACCESS_DENIED",
                )

            m_pnu = _PORTAL_ENGAGEMENT_RE.match(path)
            if m_pnu:
                engagement_id_pnu = m_pnu.group(1)
                # A session without a membership has no engagement scope — deny.
                # Distinguishes "no membership" (portal_membership_id=None) from
                # "tenant-wide membership" (engagement_id=None on membership row).
                if named_result.portal_membership_id is None:
                    return _json_403(
                        "Session has no active membership for engagement access",
                        "PORTAL_MEMBERSHIP_REQUIRED",
                    )
                # Engagement binding: membership engagement_id=None → tenant-wide.
                if (
                    named_result.engagement_id is not None
                    and named_result.engagement_id != engagement_id_pnu
                ):
                    return _json_403(
                        "Session not authorized for this engagement",
                        "PORTAL_ENGAGEMENT_MISMATCH",
                    )
                request.state.portal_user_id = named_result.portal_user_id
                request.state.portal_membership_id = named_result.portal_membership_id
                request.state.portal_engagement_id = engagement_id_pnu
            else:
                # Non-engagement portal path (e.g. /governance/*, /portal/remediation).
                # Session is validated; expose portal identity for downstream handlers.
                request.state.portal_user_id = named_result.portal_user_id
                request.state.portal_membership_id = named_result.portal_membership_id

            return await call_next(request)

        # ── Legacy grant path (non-pnu1. tokens) ─────────────────────────────
        m = _PORTAL_ENGAGEMENT_RE.match(path)
        if not m:
            if not _PORTAL_REMEDIATION_RE.match(path):
                return await call_next(request)

            # Remediation portal path — grant-based session validation, no engagement binding.
            tenant_id = getattr(getattr(request, "state", None), "tenant_id", None)
            if not tenant_id:
                return _json_403("Missing tenant context", "PORTAL_TENANT_MISSING")

            session_id = request.headers.get(_PORTAL_SESSION_HEADER, "").strip()
            if not session_id:
                return _json_403(
                    "Portal session required for remediation access",
                    "PORTAL_SESSION_REQUIRED",
                )

            SessionLocal = get_sessionmaker()
            db = SessionLocal()
            try:
                result = portal_grant_svc.validate_session(
                    db,
                    session_id=session_id,
                    tenant_id=str(tenant_id),
                )
            except Exception:
                db.close()
                return _json_403(
                    "Access check unavailable", "PORTAL_ACCESS_CHECK_FAILED"
                )
            finally:
                db.close()

            if not result.ok:
                return _json_403(
                    result.denial_reason or "Access denied",
                    result.denial_code or "PORTAL_ACCESS_DENIED",
                )

            request.state.portal_client_id = result.client_id
            return await call_next(request)

        engagement_id = m.group(1)

        tenant_id = getattr(getattr(request, "state", None), "tenant_id", None)
        if not tenant_id:
            return _json_403("Missing tenant context", "PORTAL_TENANT_MISSING")

        membership_id = request.headers.get(_MEMBERSHIP_ID_HEADER, "").strip()
        membership_version_raw = request.headers.get(
            _MEMBERSHIP_VERSION_HEADER, ""
        ).strip()

        if membership_id and membership_version_raw:
            # Named-user path (P1.1): OIDC portal user with membership versioning.
            # X-FG-Membership-* is an internal BFF-to-core protocol. Only the portal
            # BFF service account (global API key) may assert named-user identity;
            # tenant-scoped API keys cannot activate this path.
            # TODO: replace with portal:proxy scope for fine-grained enforcement.
            auth = getattr(getattr(request, "state", None), "auth", None)
            if getattr(auth, "reason", None) != "global_key":
                return _json_403(
                    "Named-user portal access requires service account authentication",
                    "PORTAL_AUTH_INVALID",
                )
            try:
                session_version = int(membership_version_raw)
            except ValueError:
                return _json_403("Invalid membership version", "PORTAL_INVALID_VERSION")

            SessionLocal = get_sessionmaker()
            db = SessionLocal()
            try:
                row = db.execute(
                    _NAMED_USER_VERSION_SQL,
                    {"membership_id": membership_id, "tenant_id": str(tenant_id)},
                ).one_or_none()
            except Exception:
                db.close()
                return _json_403(
                    "Access check unavailable", "PORTAL_ACCESS_CHECK_FAILED"
                )
            finally:
                db.close()

            if row is None:
                return _json_403(
                    "Membership not found or not bound", "MEMBERSHIP_NOT_BOUND"
                )

            if int(row.membership_version) != session_version:
                return _json_403(
                    "Session revoked: membership has changed",
                    "SESSION_REVOKED_VERSION_MISMATCH",
                )

            if not row.active:
                return _json_403("Membership is inactive", "MEMBERSHIP_INACTIVE")

            request.state.portal_membership_id = membership_id
            request.state.portal_engagement_id = engagement_id
            return await call_next(request)

        session_token = request.headers.get(_PORTAL_SESSION_HEADER, "").strip()
        if not session_token:
            return _json_403(
                "Portal session required for engagement access",
                "PORTAL_SESSION_REQUIRED",
            )

        # Note: pnu1. named-user sessions are handled by the catch-all at the
        # top of dispatch() so that they are validated on ALL portal paths
        # (not just engagement paths). If we reach this point, the token is a
        # legacy (non-pnu1.) grant-session opaque ID.

        # Grant-based path (C7): opaque session token (no versioned prefix).
        SessionLocal = get_sessionmaker()
        db = SessionLocal()
        try:
            result = portal_grant_svc.validate_session(
                db,
                session_id=session_token,
                tenant_id=str(tenant_id),
                engagement_id=engagement_id,
            )
        except Exception:
            db.close()
            return _json_403("Access check unavailable", "PORTAL_ACCESS_CHECK_FAILED")
        finally:
            db.close()

        if not result.ok:
            return _json_403(
                result.denial_reason or "Access denied",
                result.denial_code or "PORTAL_ACCESS_DENIED",
            )

        # Inject portal context for downstream handlers
        request.state.portal_client_id = result.client_id
        request.state.portal_engagement_id = engagement_id

        return await call_next(request)
