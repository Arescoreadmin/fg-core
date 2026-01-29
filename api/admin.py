# api/admin.py
"""
Admin Router for SaaS Management.

Provides administrative endpoints for:
- Tenant management (suspension, activation)
- Usage monitoring and quota management
- API key rotation management
- System health and diagnostics
- Security alert configuration
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from api.auth_scopes import (
    _validate_tenant_id,
    list_api_keys,
    mint_key,
    require_scopes,
    revoke_api_key,
    rotate_api_key_by_prefix,
    verify_api_key,
)
from api.keys import (
    CreateKeyResponse,
    KeyInfo,
    ListKeysResponse,
    RevokeKeyResponse,
    RotateKeyResponse,
)
from api.security_audit import audit_key_created, audit_key_revoked, audit_key_rotated

log = logging.getLogger("frostgate.admin")

router = APIRouter(prefix="/admin", tags=["admin"])


# =============================================================================
# Request/Response Models
# =============================================================================


class TenantUsageResponse(BaseModel):
    """Response for tenant usage endpoint."""

    tenant_id: str
    period: str
    request_count: int
    decision_count: int
    bytes_processed: int
    quota_limit: int
    quota_remaining: int
    quota_pct_used: float
    tier: str


class TenantQuotaUpdate(BaseModel):
    """Request to update tenant quota."""

    quota: int = Field(..., ge=0, description="New daily quota (0 = unlimited)")


class TenantTierUpdate(BaseModel):
    """Request to update tenant tier."""

    tier: str = Field(
        ...,
        description="Subscription tier (free, starter, pro, enterprise, internal)",
    )


class KeyRotationResponse(BaseModel):
    """Response for key rotation."""

    success: bool
    old_key_prefix: str
    new_key_prefix: Optional[str]
    grace_period_until: Optional[str]
    message: str


class KeyRotationStatusResponse(BaseModel):
    """Response for key rotation status."""

    prefix: str
    status: str
    created_at: str
    expires_at: Optional[str]
    days_until_expiration: Optional[int]
    rotation_recommended: bool
    message: Optional[str]


class AdminCreateKeyRequest(BaseModel):
    """Request to create a new API key via admin."""

    name: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Human-readable name for the key",
    )
    scopes: list[str] = Field(
        default_factory=list,
        description="List of scopes to grant to the key",
    )
    tenant_id: str = Field(
        ...,
        max_length=128,
        description="Tenant ID to associate with the key",
    )
    ttl_seconds: int = Field(
        default=86400,
        ge=60,
        le=365 * 24 * 3600,
        description="Time-to-live in seconds (default 24 hours)",
    )


class AdminRotateKeyRequest(BaseModel):
    """Request to rotate an API key via admin."""

    ttl_seconds: int = Field(
        default=86400,
        ge=60,
        le=365 * 24 * 3600,
        description="TTL for the new key (default 24 hours)",
    )
    revoke_old: bool = Field(
        default=True,
        description="Whether to revoke the old key immediately",
    )
    tenant_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Optional tenant ID for validation",
    )


class CircuitBreakerStatsResponse(BaseModel):
    """Response for circuit breaker stats."""

    name: str
    state: str
    failure_count: int
    success_count: int
    total_calls: int
    total_failures: int
    total_successes: int


class SystemHealthResponse(BaseModel):
    """Response for detailed system health."""

    status: str
    shutdown_state: str
    active_connections: int
    circuit_breakers: List[CircuitBreakerStatsResponse]
    alert_stats: Dict[str, Any]


# =============================================================================
# Tenant Management Endpoints
# =============================================================================


@router.get(
    "/tenants/{tenant_id}/usage",
    response_model=TenantUsageResponse,
    dependencies=[Depends(require_scopes("admin:read"))],
)
async def get_tenant_usage(
    tenant_id: str,
    _: str = Depends(verify_api_key),
) -> TenantUsageResponse:
    """Get usage statistics for a tenant."""
    try:
        from api.tenant_usage import get_usage_tracker
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="Tenant usage tracking not available",
        )

    tracker = get_usage_tracker()
    record = tracker.get_usage_summary(tenant_id)

    if not record:
        # Return zero usage if no records
        quota_limit = tracker._get_quota_for_tenant(tenant_id)
        return TenantUsageResponse(
            tenant_id=tenant_id,
            period=tracker._get_current_period(),
            request_count=0,
            decision_count=0,
            bytes_processed=0,
            quota_limit=quota_limit,
            quota_remaining=quota_limit,
            quota_pct_used=0.0,
            tier=tracker._tenant_tiers.get(
                tenant_id, tracker._tenant_tiers.get(tenant_id, "free")
            )
            if hasattr(tracker, "_tenant_tiers")
            else "free",
        )

    quota_pct = (
        (record.request_count / record.quota_limit) * 100
        if record.quota_limit > 0
        else 0
    )

    return TenantUsageResponse(
        tenant_id=record.tenant_id,
        period=record.period,
        request_count=record.request_count,
        decision_count=record.decision_count,
        bytes_processed=record.bytes_processed,
        quota_limit=record.quota_limit,
        quota_remaining=record.quota_remaining,
        quota_pct_used=round(quota_pct, 2),
        tier=record.tier,
    )


@router.put(
    "/tenants/{tenant_id}/quota",
    dependencies=[Depends(require_scopes("admin:write"))],
)
async def update_tenant_quota(
    tenant_id: str,
    update: TenantQuotaUpdate,
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Update custom quota for a tenant."""
    try:
        from api.tenant_usage import get_usage_tracker
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="Tenant usage tracking not available",
        )

    tracker = get_usage_tracker()
    tracker.set_custom_quota(tenant_id, update.quota)

    return {
        "success": True,
        "tenant_id": tenant_id,
        "quota": update.quota,
        "message": "Quota updated successfully",
    }


@router.put(
    "/tenants/{tenant_id}/tier",
    dependencies=[Depends(require_scopes("admin:write"))],
)
async def update_tenant_tier(
    tenant_id: str,
    update: TenantTierUpdate,
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Update subscription tier for a tenant."""
    try:
        from api.tenant_usage import SubscriptionTier, get_usage_tracker
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="Tenant usage tracking not available",
        )

    # Validate tier
    try:
        tier = SubscriptionTier(update.tier.lower())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid tier: {update.tier}. "
            f"Valid tiers: {[t.value for t in SubscriptionTier]}",
        )

    tracker = get_usage_tracker()
    tracker.set_tenant_tier(tenant_id, tier)

    return {
        "success": True,
        "tenant_id": tenant_id,
        "tier": tier.value,
        "message": "Tier updated successfully",
    }


@router.post(
    "/tenants/{tenant_id}/suspend",
    dependencies=[Depends(require_scopes("admin:write"))],
)
async def suspend_tenant(
    tenant_id: str,
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Suspend a tenant (block all requests)."""
    try:
        from api.tenant_usage import get_usage_tracker
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="Tenant usage tracking not available",
        )

    tracker = get_usage_tracker()
    tracker.suspend_tenant(tenant_id)

    # Log security alert
    try:
        from api.security_alerts import AlertCategory, AlertSeverity, send_alert
        import asyncio

        asyncio.create_task(
            send_alert(
                severity=AlertSeverity.WARNING,
                category=AlertCategory.KEY_MANAGEMENT,
                title="Tenant suspended",
                message=f"Tenant {tenant_id[:8]}... has been suspended",
                tenant_id=tenant_id,
            )
        )
    except ImportError:
        pass

    return {
        "success": True,
        "tenant_id": tenant_id,
        "status": "suspended",
        "message": "Tenant suspended successfully",
    }


@router.post(
    "/tenants/{tenant_id}/activate",
    dependencies=[Depends(require_scopes("admin:write"))],
)
async def activate_tenant(
    tenant_id: str,
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Activate a suspended tenant."""
    try:
        from api.tenant_usage import get_usage_tracker
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="Tenant usage tracking not available",
        )

    tracker = get_usage_tracker()
    tracker.activate_tenant(tenant_id)

    return {
        "success": True,
        "tenant_id": tenant_id,
        "status": "active",
        "message": "Tenant activated successfully",
    }


# =============================================================================
# API Key Admin Endpoints
# =============================================================================


@router.get(
    "/keys",
    response_model=ListKeysResponse,
    dependencies=[Depends(require_scopes("keys:read"))],
)
async def admin_list_keys(
    tenant_id: Optional[str] = Query(default=None, max_length=128),
    include_disabled: bool = Query(default=False),
    _: str = Depends(verify_api_key),
) -> ListKeysResponse:
    """List API keys for admin usage."""
    if tenant_id:
        is_valid, error = _validate_tenant_id(tenant_id)
        if not is_valid:
            raise HTTPException(status_code=400, detail=error)

    keys = list_api_keys(tenant_id=tenant_id, include_disabled=include_disabled)
    key_infos = [KeyInfo(**k) for k in keys]
    return ListKeysResponse(keys=key_infos, total=len(key_infos))


@router.post(
    "/keys",
    response_model=CreateKeyResponse,
    dependencies=[Depends(require_scopes("keys:write"))],
)
async def admin_create_key(
    req: AdminCreateKeyRequest,
    request: Request,
    _: str = Depends(verify_api_key),
) -> CreateKeyResponse:
    """Create a new API key via admin."""
    is_valid, error = _validate_tenant_id(req.tenant_id)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error)

    key = mint_key(
        *req.scopes,
        ttl_seconds=req.ttl_seconds,
        tenant_id=req.tenant_id,
    )

    parts = key.split(".")
    prefix = parts[0] if parts else "fgk"

    expires_at = int(time.time()) + req.ttl_seconds

    audit_key_created(
        key_prefix=prefix,
        scopes=req.scopes,
        tenant_id=req.tenant_id,
        request=request,
        ttl_seconds=req.ttl_seconds,
    )

    return CreateKeyResponse(
        key=key,
        prefix=prefix,
        scopes=req.scopes,
        tenant_id=req.tenant_id,
        ttl_seconds=req.ttl_seconds,
        expires_at=expires_at,
    )


@router.post(
    "/keys/{key_prefix}/revoke",
    response_model=RevokeKeyResponse,
    dependencies=[Depends(require_scopes("keys:write"))],
)
async def admin_revoke_key(
    key_prefix: str,
    request: Request,
    tenant_id: Optional[str] = Query(default=None, max_length=128),
    _: str = Depends(verify_api_key),
) -> RevokeKeyResponse:
    """Revoke an API key by prefix."""
    if tenant_id:
        is_valid, error = _validate_tenant_id(tenant_id)
        if not is_valid:
            raise HTTPException(status_code=400, detail=error)
        keys = list_api_keys(tenant_id=tenant_id, include_disabled=True)
        if not any(k.get("prefix") == key_prefix for k in keys):
            raise HTTPException(status_code=404, detail="Key not found")

    revoked = revoke_api_key(key_prefix)
    if revoked:
        audit_key_revoked(key_prefix=key_prefix, request=request)
        return RevokeKeyResponse(
            revoked=True,
            prefix=key_prefix,
            message="Key successfully revoked",
        )

    return RevokeKeyResponse(
        revoked=False,
        prefix=key_prefix,
        message="Key not found or already revoked",
    )


@router.post(
    "/keys/{key_prefix}/rotate",
    response_model=RotateKeyResponse,
    dependencies=[Depends(require_scopes("keys:write"))],
)
async def admin_rotate_key(
    key_prefix: str,
    req: AdminRotateKeyRequest,
    request: Request,
    _: str = Depends(verify_api_key),
) -> RotateKeyResponse:
    """Rotate an API key by prefix."""
    try:
        result = rotate_api_key_by_prefix(
            key_prefix=key_prefix,
            ttl_seconds=req.ttl_seconds,
            tenant_id=req.tenant_id,
            revoke_old=req.revoke_old,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    audit_key_rotated(
        old_prefix=result["old_prefix"],
        new_prefix=result["new_prefix"],
        tenant_id=result["tenant_id"],
        request=request,
        old_key_revoked=result["old_key_revoked"],
    )

    return RotateKeyResponse(
        new_key=result["new_key"],
        new_prefix=result["new_prefix"],
        old_prefix=result["old_prefix"],
        scopes=result["scopes"],
        tenant_id=result["tenant_id"],
        expires_at=result["expires_at"],
        old_key_revoked=result["old_key_revoked"],
    )


# =============================================================================
# Key Rotation Endpoints
# =============================================================================


@router.get(
    "/keys/{key_prefix}/rotation-status",
    response_model=KeyRotationStatusResponse,
    dependencies=[Depends(require_scopes("admin:read"))],
)
async def get_key_rotation_status(
    key_prefix: str,
    _: str = Depends(verify_api_key),
) -> KeyRotationStatusResponse:
    """Get rotation status for an API key."""
    try:
        from api.key_rotation import check_key_rotation_status
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="Key rotation management not available",
        )

    info = check_key_rotation_status(key_prefix)
    if not info:
        raise HTTPException(status_code=404, detail="Key not found")

    return KeyRotationStatusResponse(
        prefix=info.prefix,
        status=info.status.value,
        created_at=info.created_at.isoformat(),
        expires_at=info.expires_at.isoformat() if info.expires_at else None,
        days_until_expiration=info.days_until_expiration,
        rotation_recommended=info.rotation_recommended,
        message=info.message,
    )


@router.get(
    "/keys/needing-rotation",
    response_model=List[KeyRotationStatusResponse],
    dependencies=[Depends(require_scopes("admin:read"))],
)
async def get_keys_needing_rotation(
    _: str = Depends(verify_api_key),
) -> List[KeyRotationStatusResponse]:
    """Get all keys that need rotation."""
    try:
        from api.key_rotation import get_rotation_manager
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="Key rotation management not available",
        )

    manager = get_rotation_manager()
    keys = manager.get_keys_needing_rotation()

    return [
        KeyRotationStatusResponse(
            prefix=info.prefix,
            status=info.status.value,
            created_at=info.created_at.isoformat(),
            expires_at=info.expires_at.isoformat() if info.expires_at else None,
            days_until_expiration=info.days_until_expiration,
            rotation_recommended=info.rotation_recommended,
            message=info.message,
        )
        for info in keys
    ]


@router.post(
    "/keys/{key_prefix}/rotate",
    response_model=KeyRotationResponse,
    dependencies=[Depends(require_scopes("admin:write"))],
)
async def rotate_key(
    key_prefix: str,
    _: str = Depends(verify_api_key),
) -> KeyRotationResponse:
    """Rotate an API key."""
    try:
        from api.key_rotation import rotate_api_key
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="Key rotation management not available",
        )

    result = rotate_api_key(key_prefix)

    if not result.success:
        raise HTTPException(status_code=400, detail=result.message)

    # Note: The new key is only returned once, on rotation
    # In a real SaaS, this would be sent securely to the tenant
    return KeyRotationResponse(
        success=result.success,
        old_key_prefix=result.old_key_prefix,
        new_key_prefix=result.new_key_prefix,
        grace_period_until=(
            result.grace_period_until.isoformat() if result.grace_period_until else None
        ),
        message=result.message,
    )


# =============================================================================
# System Health and Diagnostics
# =============================================================================


@router.get(
    "/system/health",
    response_model=SystemHealthResponse,
    dependencies=[Depends(require_scopes("admin:read"))],
)
async def get_system_health(
    _: str = Depends(verify_api_key),
) -> SystemHealthResponse:
    """Get detailed system health including circuit breakers and alerts."""
    # Get shutdown state
    shutdown_state = "running"
    active_connections = 0
    try:
        from api.graceful_shutdown import get_shutdown_manager

        manager = get_shutdown_manager()
        shutdown_state = manager.state.value
        active_connections = manager._active_connections
    except ImportError:
        pass

    # Get circuit breaker stats
    circuit_breakers = []
    try:
        from api.circuit_breaker import get_circuit_breaker_registry

        registry = get_circuit_breaker_registry()
        for name, stats in registry.get_all_stats().items():
            circuit_breakers.append(
                CircuitBreakerStatsResponse(
                    name=stats.name,
                    state=stats.state.value,
                    failure_count=stats.failure_count,
                    success_count=stats.success_count,
                    total_calls=stats.total_calls,
                    total_failures=stats.total_failures,
                    total_successes=stats.total_successes,
                )
            )
    except ImportError:
        pass

    # Get alert stats
    alert_stats = {}
    try:
        from api.security_alerts import get_alert_manager

        manager = get_alert_manager()
        alert_stats = manager.get_stats()
    except ImportError:
        pass

    return SystemHealthResponse(
        status="healthy" if shutdown_state == "running" else shutdown_state,
        shutdown_state=shutdown_state,
        active_connections=active_connections,
        circuit_breakers=circuit_breakers,
        alert_stats=alert_stats,
    )


@router.get(
    "/usage/all",
    dependencies=[Depends(require_scopes("admin:read"))],
)
async def get_all_usage(
    period: Optional[str] = Query(None, description="Period in YYYY-MM-DD format"),
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Get usage for all tenants (admin endpoint)."""
    try:
        from api.tenant_usage import get_usage_tracker
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="Tenant usage tracking not available",
        )

    tracker = get_usage_tracker()
    usage = tracker.get_all_usage(period)

    return {
        "period": period or tracker._get_current_period(),
        "tenant_count": len(usage),
        "tenants": {
            tid: {
                "request_count": record.request_count,
                "decision_count": record.decision_count,
                "quota_limit": record.quota_limit,
                "quota_remaining": record.quota_remaining,
                "tier": record.tier,
            }
            for tid, record in usage.items()
        },
    }


__all__ = ["router"]
