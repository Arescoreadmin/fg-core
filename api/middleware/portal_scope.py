from __future__ import annotations

import re
from typing import Callable

from fastapi import Request
from sqlalchemy import func, select
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from api.db import get_sessionmaker
from api.db_models_field_assessment import FaEngagement

_PORTAL_ENGAGEMENT_RE = re.compile(r"^/field-assessment/engagements/([^/]+)")
_PORTAL_SOURCE_HEADER = "x-portal-source"
_PORTAL_SOURCE_VALUE = "client-portal"


def _json_403(message: str, code: str) -> JSONResponse:
    return JSONResponse(
        {"detail": message, "code": code},
        status_code=403,
        headers={"Cache-Control": "no-store"},
    )


class PortalClientScopeMiddleware(BaseHTTPMiddleware):
    """Enforce that portal requests to /field-assessment/engagements/{id}/* can
    only access engagements whose client_access_code matches the session value.

    AuthGateMiddleware runs before this middleware and populates
    request.state.tenant_id.  No-op for non-portal (operator/console) requests.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.headers.get(_PORTAL_SOURCE_HEADER) != _PORTAL_SOURCE_VALUE:
            return await call_next(request)

        path = request.scope.get("path", "")
        m = _PORTAL_ENGAGEMENT_RE.match(path)
        if not m:
            return await call_next(request)

        engagement_id = m.group(1)
        client_access_code = request.query_params.get("client_access_code")
        if not client_access_code:
            return _json_403(
                "client_access_code required for portal engagement access",
                "PORTAL_ACCESS_CODE_REQUIRED",
            )

        tenant_id = getattr(getattr(request, "state", None), "tenant_id", None)
        if not tenant_id:
            return _json_403("Missing tenant context", "PORTAL_TENANT_MISSING")

        SessionLocal = get_sessionmaker()
        db = SessionLocal()
        try:
            count = db.scalar(
                select(func.count(FaEngagement.id)).where(
                    FaEngagement.id == engagement_id,
                    FaEngagement.tenant_id == tenant_id,
                    FaEngagement.client_access_code == client_access_code,
                )
            )
        except Exception:
            db.close()
            return _json_403("Access check unavailable", "PORTAL_ACCESS_CHECK_FAILED")
        finally:
            db.close()

        if not count:
            return _json_403("Access denied", "PORTAL_ACCESS_DENIED")

        return await call_next(request)
