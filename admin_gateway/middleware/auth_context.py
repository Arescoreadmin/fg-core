"""Middleware to attach authentication context to requests."""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from admin_gateway.auth import ensure_dev_user, get_user_from_session


class AuthContextMiddleware(BaseHTTPMiddleware):
    """Attach user context (if any) to request.state."""

    async def dispatch(self, request: Request, call_next):
        user = get_user_from_session(request)
        if not user:
            user = ensure_dev_user(request)
        request.state.user = user
        return await call_next(request)
