"""Admin router.

Handles admin-specific endpoints including /admin/me.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

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


class AdminCreateKeyRequest(BaseModel):
    """Request model for admin key creation."""

    name: Optional[str] = Field(None, max_length=128)
    scopes: list[str] = Field(default_factory=list)
    tenant_id: str = Field(..., max_length=128)
    ttl_seconds: int = Field(default=86400, ge=60, le=365 * 24 * 3600)


class AdminRotateKeyRequest(BaseModel):
    """Request model for admin key rotation."""

    ttl_seconds: int = Field(default=86400, ge=60, le=365 * 24 * 3600)
    revoke_old: bool = Field(default=True)


def _core_base_url() -> str:
    base_url = (os.getenv("AG_CORE_BASE_URL") or "").strip()
    if not base_url:
        raise HTTPException(
            status_code=503,
            detail="Core service unavailable: AG_CORE_BASE_URL not configured",
        )
    return base_url.rstrip("/")


def _core_api_key() -> str:
    api_key = (os.getenv("AG_CORE_API_KEY") or "").strip()
    if not api_key:
        raise HTTPException(
            status_code=503,
            detail="Core service unavailable: AG_CORE_API_KEY not configured",
        )
    return api_key


async def _proxy_to_core(
    request: Request,
    method: str,
    path: str,
    *,
    params: Optional[dict[str, Any]] = None,
    json_body: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    base_url = _core_base_url()
    headers = {
        "X-API-Key": _core_api_key(),
        "X-Request-Id": getattr(request.state, "request_id", ""),
    }

    async with httpx.AsyncClient(base_url=base_url, timeout=15.0) as client:
        response = await client.request(
            method,
            path,
            params=params,
            json=json_body,
            headers=headers,
        )

    if response.status_code >= 400:
        try:
            detail = response.json().get("detail")
        except ValueError:
            detail = response.text
        raise HTTPException(status_code=response.status_code, detail=detail)

    return response.json()


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
    """List API keys (proxied to core).

    Requires keys:read or higher scope.
    """
    allowed = get_allowed_tenants(session)
    if tenant_id and tenant_id not in allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Access denied to tenant: {tenant_id}",
        )

    payload = await _proxy_to_core(
        request,
        "GET",
        "/admin/keys",
        params={"tenant_id": tenant_id} if tenant_id else None,
    )

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

    return payload


@router.post(
    "/keys",
    dependencies=[
        Depends(require_scope_dependency(Scope.KEYS_WRITE)),
        Depends(verify_csrf),
    ],
)
async def create_key(
    request: Request,
    payload: AdminCreateKeyRequest,
    session: Session = Depends(get_current_session),
) -> dict[str, Any]:
    """Create a new API key (proxied to core).

    Requires keys:write scope and tenant_id.
    """
    allowed = get_allowed_tenants(session)
    if payload.tenant_id not in allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Access denied to tenant: {payload.tenant_id}",
        )

    response = await _proxy_to_core(
        request,
        "POST",
        "/admin/keys",
        json_body=payload.model_dump(),
    )

    audit_logger = getattr(request.app.state, "audit_logger", None)
    if audit_logger:
        await audit_logger.log(
            request_id=getattr(request.state, "request_id", "unknown"),
            action="create_key",
            resource="keys",
            outcome="success",
            actor=session.user_id,
            details={"tenant_id": payload.tenant_id},
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

    return response


@router.post(
    "/keys/{prefix}/revoke",
    dependencies=[
        Depends(require_scope_dependency(Scope.KEYS_WRITE)),
        Depends(verify_csrf),
    ],
)
async def revoke_key(
    prefix: str,
    request: Request,
    tenant_id: str = Query(..., description="Tenant ID (required for writes)"),
    session: Session = Depends(get_current_session),
) -> dict[str, Any]:
    """Revoke an API key (proxied to core)."""
    allowed = get_allowed_tenants(session)
    if tenant_id not in allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Access denied to tenant: {tenant_id}",
        )

    response = await _proxy_to_core(
        request,
        "POST",
        f"/admin/keys/{prefix}/revoke",
        params={"tenant_id": tenant_id},
    )

    audit_logger = getattr(request.app.state, "audit_logger", None)
    if audit_logger:
        await audit_logger.log(
            request_id=getattr(request.state, "request_id", "unknown"),
            action="revoke_key",
            resource="keys",
            outcome="success",
            actor=session.user_id,
            details={"tenant_id": tenant_id, "prefix": prefix},
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

    return response


@router.post(
    "/keys/{prefix}/rotate",
    dependencies=[
        Depends(require_scope_dependency(Scope.KEYS_WRITE)),
        Depends(verify_csrf),
    ],
)
async def rotate_key(
    prefix: str,
    payload: AdminRotateKeyRequest,
    request: Request,
    tenant_id: str = Query(..., description="Tenant ID (required for writes)"),
    session: Session = Depends(get_current_session),
) -> dict[str, Any]:
    """Rotate an API key (proxied to core)."""
    allowed = get_allowed_tenants(session)
    if tenant_id not in allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Access denied to tenant: {tenant_id}",
        )

    response = await _proxy_to_core(
        request,
        "POST",
        f"/admin/keys/{prefix}/rotate",
        params={"tenant_id": tenant_id},
        json_body=payload.model_dump(),
    )

    audit_logger = getattr(request.app.state, "audit_logger", None)
    if audit_logger:
        await audit_logger.log(
            request_id=getattr(request.state, "request_id", "unknown"),
            action="rotate_key",
            resource="keys",
            outcome="success",
            actor=session.user_id,
            details={"tenant_id": tenant_id, "prefix": prefix},
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

    return response


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
