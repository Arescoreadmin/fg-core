"""Authentication middleware.

Provides request-level authentication and CSRF protection.
"""

from __future__ import annotations

import logging
from typing import Callable, Set

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from admin_gateway.auth.config import get_auth_config
from admin_gateway.auth.csrf import CSRFProtection, STATE_CHANGING_METHODS
from admin_gateway.auth.dev_bypass import get_dev_bypass_session
from admin_gateway.auth.session import Session, SessionManager

log = logging.getLogger("admin-gateway.auth-middleware")

# Paths that don't require authentication
PUBLIC_PATHS: Set[str] = {
    "/health",
    "/health/ready",
    "/health/live",
    "/version",
    "/openapi.json",
    "/docs",
    "/redoc",
    # Auth endpoints
    "/auth/login",
    "/auth/callback",
    "/auth/oidc/callback",
    "/auth/logout",
}

# Path prefixes that don't require authentication
PUBLIC_PATH_PREFIXES: tuple[str, ...] = (
    "/docs",
    "/redoc",
    "/openapi",
)


def is_public_path(path: str) -> bool:
    """Check if a path is public (no auth required)."""
    if path in PUBLIC_PATHS:
        return True

    for prefix in PUBLIC_PATH_PREFIXES:
        if path.startswith(prefix):
            return True

    return False


class AuthMiddleware(BaseHTTPMiddleware):
    """Middleware for authentication and CSRF protection.

    This middleware:
    1. Checks if path is public (skip auth)
    2. Validates session from cookie or dev bypass
    3. Validates CSRF for state-changing methods
    4. Sets session in request.state for handlers
    """

    def __init__(self, app, auto_csrf: bool = True):
        """Initialize auth middleware.

        Args:
            app: FastAPI application
            auto_csrf: Whether to auto-check CSRF (default True)
        """
        super().__init__(app)
        self.auto_csrf = auto_csrf
        self._config = None
        self._session_manager = None
        self._csrf = None

    @property
    def config(self):
        if self._config is None:
            self._config = get_auth_config()
        return self._config

    @property
    def session_manager(self):
        if self._session_manager is None:
            self._session_manager = SessionManager(self.config)
        return self._session_manager

    @property
    def csrf(self):
        if self._csrf is None:
            self._csrf = CSRFProtection(self.config)
        return self._csrf

    async def dispatch(
        self,
        request: Request,
        call_next: Callable,
    ) -> Response:
        """Process request through auth middleware."""
        path = request.url.path
        method = request.method.upper()

        # Public paths skip auth
        if is_public_path(path):
            return await call_next(request)

        # Try to get session
        session = self._get_session(request)

        # If no session and path requires auth, return 401
        if session is None:
            if self._requires_auth(path):
                return self._unauthorized_response(request)

        # Store session in request state
        request.state.session = session
        request.state.user_id = session.user_id if session else None

        # CSRF check for state-changing methods
        if self.auto_csrf and method in STATE_CHANGING_METHODS:
            try:
                self.csrf.validate_request(request)
            except Exception as e:
                log.warning("CSRF validation failed: %s", e)
                return JSONResponse(
                    status_code=403,
                    content={"detail": str(e)},
                )

        # Call the actual handler
        response = await call_next(request)

        # Ensure CSRF cookie is set for authenticated users
        if session and method == "GET":
            self._ensure_csrf_cookie(request, response)

        return response

    def _get_session(self, request: Request) -> Session | None:
        """Get session from request."""
        # Try session cookie
        session = self.session_manager.get_session(request)
        if session:
            return session

        # Try dev bypass
        return get_dev_bypass_session(self.config)

    def _requires_auth(self, path: str) -> bool:
        """Check if path requires authentication."""
        # All /admin/* and /api/* paths require auth
        return path.startswith("/admin") or path.startswith("/api")

    def _unauthorized_response(self, request: Request) -> Response:
        """Create 401 unauthorized response."""
        return JSONResponse(
            status_code=401,
            content={
                "detail": "Not authenticated",
                "login_url": "/auth/login",
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    def _ensure_csrf_cookie(self, request: Request, response: Response) -> None:
        """Ensure CSRF cookie is set."""
        existing = request.cookies.get(self.config.csrf_cookie_name)
        if not existing:
            self.csrf.set_token_cookie(response)
