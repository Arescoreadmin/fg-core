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

from api.db import get_sessionmaker
from services.portal_grant_service import portal_grant_svc

_PORTAL_ENGAGEMENT_RE = re.compile(r"^/field-assessment/engagements/([^/]+)")
_PORTAL_SOURCE_HEADER = "x-portal-source"
_PORTAL_SOURCE_VALUE = "client-portal"
_PORTAL_SESSION_HEADER = "x-fg-portal-session"


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
        m = _PORTAL_ENGAGEMENT_RE.match(path)
        if not m:
            return await call_next(request)

        engagement_id = m.group(1)
        session_id = request.headers.get(_PORTAL_SESSION_HEADER, "").strip()
        if not session_id:
            return _json_403(
                "Portal session required for engagement access",
                "PORTAL_SESSION_REQUIRED",
            )

        tenant_id = getattr(getattr(request, "state", None), "tenant_id", None)
        if not tenant_id:
            return _json_403("Missing tenant context", "PORTAL_TENANT_MISSING")

        SessionLocal = get_sessionmaker()
        db = SessionLocal()
        try:
            result = portal_grant_svc.validate_session(
                db,
                session_id=session_id,
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
