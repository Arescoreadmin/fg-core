"""FastAPI dependencies for authentication.

Provides dependency injection for auth, CSRF, and session management.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import Depends, HTTPException, Request

from admin_gateway.auth.config import AuthConfig, get_auth_config
from admin_gateway.auth.csrf import CSRFProtection
from admin_gateway.auth.dev_bypass import get_dev_bypass_session
from admin_gateway.auth.scopes import Scope, has_scope
from admin_gateway.auth.session import Session, SessionManager
from admin_gateway.auth.tenant import TenantContext, validate_tenant_access

log = logging.getLogger("admin-gateway.auth")


def get_session_manager(
    config: AuthConfig = Depends(get_auth_config),
) -> SessionManager:
    """Get session manager dependency."""
    return SessionManager(config)


def get_csrf_protection(
    config: AuthConfig = Depends(get_auth_config),
) -> CSRFProtection:
    """Get CSRF protection dependency."""
    return CSRFProtection(config)


async def get_optional_session(
    request: Request,
    session_manager: SessionManager = Depends(get_session_manager),
    config: AuthConfig = Depends(get_auth_config),
) -> Optional[Session]:
    """Get session if available (does not require auth).

    This dependency:
    1. Tries to get session from cookie
    2. Falls back to dev bypass if enabled
    3. Returns None if no auth

    Use this for endpoints that work with or without auth.
    """
    # Try session cookie first
    session = session_manager.get_session(request)
    if session:
        return session

    # Try dev bypass
    return get_dev_bypass_session(config)


async def get_current_session(
    request: Request,
    session_manager: SessionManager = Depends(get_session_manager),
    config: AuthConfig = Depends(get_auth_config),
) -> Session:
    """Get current authenticated session (requires auth).

    Raises:
        HTTPException 401: If not authenticated
    """
    # Try session cookie first
    session = session_manager.get_session(request)
    if session:
        return session

    # Try dev bypass
    dev_session = get_dev_bypass_session(config)
    if dev_session:
        return dev_session

    # No valid session
    raise HTTPException(
        status_code=401,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def verify_csrf(
    request: Request,
    csrf: CSRFProtection = Depends(get_csrf_protection),
) -> None:
    """Verify CSRF token for state-changing requests.

    This dependency should be added to POST/PUT/PATCH/DELETE endpoints.
    """
    csrf.validate_request(request)


def require_scope_dependency(scope: str | Scope):
    """Create a dependency that requires a specific scope.

    Usage:
        @app.get("/admin/keys", dependencies=[Depends(require_scope_dependency(Scope.KEYS_READ))])
        async def list_keys():
            ...
    """

    async def _check_scope(
        session: Session = Depends(get_current_session),
    ) -> Session:
        scope_str = scope.value if isinstance(scope, Scope) else scope

        if not has_scope(session.scopes, scope_str):
            log.warning(
                "Access denied: user=%s lacks scope=%s (has=%s)",
                session.user_id,
                scope_str,
                session.scopes,
            )
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions: requires {scope_str}",
            )

        return session

    return _check_scope


def require_tenant_dependency(is_write: bool = False):
    """Create a dependency that requires tenant context.

    Usage:
        @app.post("/admin/keys", dependencies=[Depends(require_tenant_dependency(is_write=True))])
        async def create_key(tenant_id: str):
            ...
    """

    async def _check_tenant(
        request: Request,
        session: Session = Depends(get_current_session),
    ) -> TenantContext:
        # Get tenant_id from query params or body
        tenant_id = request.query_params.get("tenant_id")

        return validate_tenant_access(session, tenant_id, is_write=is_write)

    return _check_tenant


# Common dependency combinations
async def require_auth_with_csrf(
    session: Session = Depends(get_current_session),
    _csrf: None = Depends(verify_csrf),
) -> Session:
    """Require authentication and CSRF verification.

    Use for state-changing endpoints.
    """
    return session


async def require_admin(
    session: Session = Depends(get_current_session),
) -> Session:
    """Require console:admin scope."""
    if not has_scope(session.scopes, Scope.CONSOLE_ADMIN):
        raise HTTPException(
            status_code=403,
            detail="Admin access required",
        )
    return session
