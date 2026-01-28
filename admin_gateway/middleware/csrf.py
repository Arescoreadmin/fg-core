"""CSRF protection middleware."""

from __future__ import annotations

import os
import secrets

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


def _env_bool(name: str, default: bool = False) -> bool:
    """Parse environment variable as boolean."""
    value = os.getenv(name)
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


class CSRFMiddleware(BaseHTTPMiddleware):
    """Enforce CSRF tokens on state-changing requests."""

    async def dispatch(self, request: Request, call_next):
        # Skip CSRF validation in dev mode with auth bypass
        env = os.getenv("FG_ENV", "dev").strip().lower()
        if env != "prod" and _env_bool("FG_DEV_AUTH_BYPASS"):
            return await call_next(request)

        if request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            session_token = (
                request.session.get("csrf_token")
                if hasattr(request, "session")
                else None
            )
            header_token = (
                request.headers.get("x-csrf-token")
                or request.headers.get("x-xsrf-token")
                or request.headers.get("x-csrf")
            )
            if (
                not session_token
                or not header_token
                or not secrets.compare_digest(session_token, header_token)
            ):
                return JSONResponse(
                    status_code=403,
                    content={"detail": "CSRF token missing or invalid"},
                )
        return await call_next(request)
