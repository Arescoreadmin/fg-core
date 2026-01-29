"""Middleware to attach authentication context to requests."""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from admin_gateway.auth.config import get_auth_config
from admin_gateway.auth.dev_bypass import get_dev_bypass_session
from admin_gateway.auth.session import SessionManager


class AuthContextMiddleware(BaseHTTPMiddleware):
    """Attach user context (if any) to request.state."""

    async def dispatch(self, request: Request, call_next):
        config = get_auth_config()
        session_manager = SessionManager(config)
        session = session_manager.get_session(request)
        if not session:
            session = get_dev_bypass_session(config)
        request.state.session = session
        request.state.user = session
        request.state.user_id = session.user_id if session else None
        return await call_next(request)
