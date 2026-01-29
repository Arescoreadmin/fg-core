"""Admin router.

Handles admin-specific endpoints including /admin/me.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
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


def _parse_tenant_ids(tenant_ids: Optional[str]) -> list[str]:
    if not tenant_ids:
        return []
    return [tenant.strip() for tenant in tenant_ids.split(",") if tenant.strip()]


def _ensure_allowed_tenants(
    session: Session,
    tenant_id: Optional[str],
    tenant_ids: Optional[str],
) -> tuple[Optional[str], Optional[list[str]]]:
    allowed = get_allowed_tenants(session)
    if tenant_id:
        if tenant_id not in allowed:
            raise HTTPException(
                status_code=403,
                detail=f"Access denied to tenant: {tenant_id}",
            )
        return tenant_id, None
    if tenant_ids:
        resolved = _parse_tenant_ids(tenant_ids)
        if not resolved:
            raise HTTPException(status_code=400, detail="tenant_ids must not be empty")
        for tenant in resolved:
            if tenant not in allowed:
                raise HTTPException(
                    status_code=403,
                    detail=f"Access denied to tenant: {tenant}",
                )
        return None, resolved
    raise HTTPException(
        status_code=400,
        detail="tenant_id or tenant_ids is required",
    )


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


async def _proxy_to_core_raw(
    request: Request,
    method: str,
    path: str,
    *,
    params: Optional[dict[str, Any]] = None,
) -> Response:
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
            headers=headers,
        )

    if response.status_code >= 400:
        try:
            detail = response.json().get("detail")
        except ValueError:
            detail = response.text
        raise HTTPException(status_code=response.status_code, detail=detail)

    content_type = response.headers.get("content-type", "application/octet-stream")
    proxy_response = Response(content=response.content, media_type=content_type)
    for header_name in ("content-disposition",):
        header_value = response.headers.get(header_name)
        if header_value:
            proxy_response.headers[header_name] = header_value
    return proxy_response


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

    response = JSONResponse(
        content={
            "csrf_token": token,
            "header_name": config.csrf_header_name,
        }
    )
    csrf.set_token_cookie(response, token)
    return response


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
    tenant_id: Optional[str] = Query(
        None, description="Single tenant filter (required unless using tenant_ids)"
    ),
    tenant_ids: Optional[str] = Query(
        None, description="Comma-separated tenant IDs (for multi-tenant admins)"
    ),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    success: Optional[bool] = Query(None, description="Filter by success flag"),
    request_id: Optional[str] = Query(None, description="Filter by request id"),
    key_prefix: Optional[str] = Query(None, description="Filter by key prefix"),
    start_time: Optional[str] = Query(None, description="Start time (ISO8601)"),
    end_time: Optional[str] = Query(None, description="End time (ISO8601)"),
    query_text: Optional[str] = Query(None, description="Search fragment"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_current_session),
) -> dict[str, Any]:
    """List audit events."""
    tenant_id, resolved_tenant_ids = _ensure_allowed_tenants(
        session, tenant_id, tenant_ids
    )

    params: dict[str, Any] = {
        "tenant_id": tenant_id,
        "tenant_ids": ",".join(resolved_tenant_ids) if resolved_tenant_ids else None,
        "event_type": event_type,
        "severity": severity,
        "success": success,
        "request_id": request_id,
        "key_prefix": key_prefix,
        "start_time": start_time,
        "end_time": end_time,
        "query_text": query_text,
        "limit": limit,
        "offset": offset,
    }
    params = {k: v for k, v in params.items() if v is not None}

    response = await _proxy_to_core(
        request,
        "GET",
        "/admin/audit",
        params=params,
    )

    return response


@router.get(
    "/audit/export",
    dependencies=[Depends(require_scope_dependency(Scope.AUDIT_READ))],
)
async def export_audit_events(
    request: Request,
    tenant_id: Optional[str] = Query(
        None, description="Single tenant filter (required unless using tenant_ids)"
    ),
    tenant_ids: Optional[str] = Query(
        None, description="Comma-separated tenant IDs (for multi-tenant admins)"
    ),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    success: Optional[bool] = Query(None, description="Filter by success flag"),
    request_id: Optional[str] = Query(None, description="Filter by request id"),
    key_prefix: Optional[str] = Query(None, description="Filter by key prefix"),
    start_time: Optional[str] = Query(None, description="Start time (ISO8601)"),
    end_time: Optional[str] = Query(None, description="End time (ISO8601)"),
    query_text: Optional[str] = Query(None, description="Search fragment"),
    format: str = Query("jsonl", pattern="^(jsonl|csv)$"),
    limit: int = Query(1000, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_current_session),
) -> Response:
    """Export audit events as CSV/JSONL."""
    tenant_id, resolved_tenant_ids = _ensure_allowed_tenants(
        session, tenant_id, tenant_ids
    )

    params: dict[str, Any] = {
        "tenant_id": tenant_id,
        "tenant_ids": ",".join(resolved_tenant_ids) if resolved_tenant_ids else None,
        "event_type": event_type,
        "severity": severity,
        "success": success,
        "request_id": request_id,
        "key_prefix": key_prefix,
        "start_time": start_time,
        "end_time": end_time,
        "query_text": query_text,
        "format": format,
        "limit": limit,
        "offset": offset,
    }
    params = {k: v for k, v in params.items() if v is not None}

    return await _proxy_to_core_raw(
        request,
        "GET",
        "/admin/audit/export",
        params=params,
    )
