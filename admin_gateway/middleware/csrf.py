"""CSRF protection middleware."""

from __future__ import annotations

import os
from fastapi import HTTPException
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
            from admin_gateway.auth.csrf import CSRFProtection

            csrf = CSRFProtection()
            try:
                csrf.validate_request(request)
            except HTTPException as exc:
                return JSONResponse(
                    status_code=exc.status_code,
                    content={"detail": exc.detail},
                )
        return await call_next(request)
