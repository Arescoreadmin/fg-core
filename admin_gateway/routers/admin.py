"""Admin router.

Handles admin-specific endpoints including /admin/me.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from admin_gateway.auth import (
    Session,
    Scope,
    get_current_session,
    require_scope_dependency,
    verify_csrf,
)
from admin_gateway.auth.tenant import get_allowed_tenants

log = logging.getLogger("admin-gateway.admin-router")

router = APIRouter(prefix="/admin", tags=["admin"])


class UserInfo(BaseModel):
    """User information response."""

    user_id: str
    email: Optional[str] = None
    name: Optional[str] = None
    scopes: list[str]
    tenants: list[str]
    current_tenant: Optional[str] = None
    session_id: str
    expires_in: int


class CSRFTokenResponse(BaseModel):
    """CSRF token response."""

    csrf_token: str
    header_name: str


@router.get("/me", response_model=UserInfo)
async def get_current_user(
    request: Request,
    session: Session = Depends(get_current_session),
) -> UserInfo:
    """Get current authenticated user information.

    Returns user profile, scopes, and tenant access.
    """
    allowed_tenants = get_allowed_tenants(session)

    return UserInfo(
        user_id=session.user_id,
        email=session.email,
        name=session.name,
        scopes=sorted(session.scopes),
        tenants=sorted(allowed_tenants),
        current_tenant=session.tenant_id,
        session_id=session.session_id,
        expires_in=session.remaining_ttl,
    )


@router.get("/csrf-token", response_model=CSRFTokenResponse)
async def get_csrf_token(
    request: Request,
    session: Session = Depends(get_current_session),
) -> CSRFTokenResponse:
    """Get CSRF token for state-changing requests.

    The token is also set in a cookie. Include the token value
    in the X-CSRF-Token header for POST/PUT/PATCH/DELETE requests.
    """
    from admin_gateway.auth.csrf import CSRFProtection
    from admin_gateway.auth.config import get_auth_config

    config = get_auth_config()
    csrf = CSRFProtection(config)

    # Get token from cookie or generate new one
    token = request.cookies.get(config.csrf_cookie_name)
    if not token:
        token = csrf._generate_token()

    return CSRFTokenResponse(
        csrf_token=token,
        header_name=config.csrf_header_name,
    )


@router.get("/scopes")
async def list_scopes(
    session: Session = Depends(get_current_session),
) -> dict[str, Any]:
    """List all available scopes and user's current scopes."""
    from admin_gateway.auth.scopes import get_all_scopes

    return {
        "available_scopes": get_all_scopes(),
        "user_scopes": sorted(session.scopes),
    }


@router.get(
    "/tenants",
    dependencies=[Depends(require_scope_dependency(Scope.PRODUCT_READ))],
)
async def list_tenants(
    request: Request,
    session: Session = Depends(get_current_session),
) -> dict[str, Any]:
    """List tenants the user has access to.

    Requires product:read or higher scope.
    """
    allowed = get_allowed_tenants(session)

    # Audit log
    audit_logger = getattr(request.app.state, "audit_logger", None)
    if audit_logger:
        await audit_logger.log(
            request_id=getattr(request.state, "request_id", "unknown"),
            action="list_tenants",
            resource="tenants",
            outcome="success",
            actor=session.user_id,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

    return {
        "tenants": [{"id": t, "name": t} for t in sorted(allowed)],
        "total": len(allowed),
    }


@router.get(
    "/keys",
    dependencies=[Depends(require_scope_dependency(Scope.KEYS_READ))],
)
async def list_keys(
    request: Request,
    tenant_id: Optional[str] = Query(None, description="Filter by tenant"),
    session: Session = Depends(get_current_session),
) -> dict[str, Any]:
    """List API keys (placeholder).

    Requires keys:read or higher scope.
    """
    # Validate tenant access if specified
    allowed = get_allowed_tenants(session)
    if tenant_id and tenant_id not in allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Access denied to tenant: {tenant_id}",
        )

    # Audit log
    audit_logger = getattr(request.app.state, "audit_logger", None)
    if audit_logger:
        await audit_logger.log(
            request_id=getattr(request.state, "request_id", "unknown"),
            action="list_keys",
            resource="keys",
            outcome="success",
            actor=session.user_id,
            details={"tenant_id": tenant_id},
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

    return {"keys": [], "total": 0, "tenant_id": tenant_id}


@router.post(
    "/keys",
    dependencies=[
        Depends(require_scope_dependency(Scope.KEYS_WRITE)),
        Depends(verify_csrf),
    ],
)
async def create_key(
    request: Request,
    tenant_id: str = Query(..., description="Tenant ID (required for writes)"),
    session: Session = Depends(get_current_session),
) -> dict[str, Any]:
    """Create a new API key (placeholder).

    Requires keys:write scope and tenant_id.
    """
    # Validate tenant access
    allowed = get_allowed_tenants(session)
    if tenant_id not in allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Access denied to tenant: {tenant_id}",
        )

    # Audit log
    audit_logger = getattr(request.app.state, "audit_logger", None)
    if audit_logger:
        await audit_logger.log(
            request_id=getattr(request.state, "request_id", "unknown"),
            action="create_key",
            resource="keys",
            outcome="success",
            actor=session.user_id,
            details={"tenant_id": tenant_id},
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

    return {
        "status": "placeholder",
        "message": "Key creation not yet implemented",
        "tenant_id": tenant_id,
    }


@router.get(
    "/audit",
    dependencies=[Depends(require_scope_dependency(Scope.AUDIT_READ))],
)
async def list_audit_events(
    request: Request,
    tenant_id: Optional[str] = Query(None, description="Filter by tenant"),
    limit: int = Query(100, ge=1, le=1000),
    session: Session = Depends(get_current_session),
) -> dict[str, Any]:
    """List audit events (placeholder).

    Requires audit:read scope.
    """
    # Validate tenant access if specified
    allowed = get_allowed_tenants(session)
    if tenant_id and tenant_id not in allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Access denied to tenant: {tenant_id}",
        )

    return {
        "events": [],
        "total": 0,
        "tenant_id": tenant_id,
        "limit": limit,
    }
