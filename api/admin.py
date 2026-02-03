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

import csv
import io
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from api.auth_scopes import (
    _validate_tenant_id,
    bind_tenant_id,
    list_api_keys,
    mint_key,
    require_scopes,
    revoke_api_key,
    rotate_api_key_by_prefix,
    verify_api_key,
)
from api.db import get_engine
from api.db_models import SecurityAuditLog
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


class AuditEvent(BaseModel):
    """Audit event response."""

    id: str
    ts: datetime
    tenant_id: str
    actor: Optional[str] = None
    action: str
    status: Literal["success", "deny", "error"]
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    request_id: Optional[str] = None
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    meta: Dict[str, Any]


class AuditSearchResponse(BaseModel):
    """Audit search response."""

    items: List[AuditEvent]
    next_cursor: Optional[str] = None


_SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api_key",
    "apikey",
    "client_secret",
    "client-secret",
    "access_token",
    "refresh_token",
    "id_token",
    "token",
    "secret",
}


def _is_sensitive_key(key: str) -> bool:
    normalized = key.strip().lower().replace(" ", "").replace("_", "-")
    if normalized in _SENSITIVE_KEYS:
        return True
    return any(fragment in normalized for fragment in ("token", "secret", "api-key"))


def _redact_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            if _is_sensitive_key(str(key)):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = _redact_secrets(item)
        return redacted
    if isinstance(value, list):
        return [_redact_secrets(item) for item in value]
    return value


def _audit_redaction_enabled() -> bool:
    value = os.getenv("FG_AUDIT_REDACT", "true").strip().lower()
    return value in {"1", "true", "yes", "y", "on"}


def _audit_filters(
    *,
    tenant_id: Optional[str],
    action: Optional[str],
    actor: Optional[str],
    status: Optional[str],
    request_id: Optional[str],
    resource_type: Optional[str],
    resource_id: Optional[str],
    from_ts: Optional[datetime],
    to_ts: Optional[datetime],
) -> list[Any]:
    filters: list[Any] = []

    if tenant_id:
        valid, message = _validate_tenant_id(tenant_id)
        if not valid:
            raise HTTPException(status_code=400, detail=message)
        filters.append(SecurityAuditLog.tenant_id == tenant_id)

    if action:
        filters.append(SecurityAuditLog.event_type == action)
    if actor:
        filters.append(SecurityAuditLog.key_prefix == actor)
    if status:
        normalized = status.lower()
        if normalized == "success":
            filters.append(SecurityAuditLog.success.is_(True))
        elif normalized == "error":
            filters.append(SecurityAuditLog.success.is_(False))
            filters.append(SecurityAuditLog.severity.in_(["error", "critical"]))
        elif normalized == "deny":
            filters.append(SecurityAuditLog.success.is_(False))
            filters.append(SecurityAuditLog.severity.not_in(["error", "critical"]))
        else:
            raise HTTPException(status_code=400, detail="Invalid status filter")
    if request_id:
        filters.append(SecurityAuditLog.request_id == request_id)
    if resource_type:
        filters.append(SecurityAuditLog.event_category == resource_type)
    if resource_id:
        filters.append(SecurityAuditLog.request_path == resource_id)
    if from_ts:
        filters.append(SecurityAuditLog.created_at >= from_ts)
    if to_ts:
        filters.append(SecurityAuditLog.created_at <= to_ts)

    return filters


def _cursor_from_record(record: SecurityAuditLog) -> str:
    return f"{record.created_at.isoformat()}|{record.id}"


def _parse_cursor(cursor: str) -> tuple[datetime, int]:
    try:
        ts_str, id_str = cursor.split("|", maxsplit=1)
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return ts, int(id_str)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid cursor")


def _derive_status(record: SecurityAuditLog) -> Literal["success", "deny", "error"]:
    if record.success:
        return "success"
    if record.severity in {"error", "critical"}:
        return "error"
    return "deny"


def _audit_meta(
    record: SecurityAuditLog, details: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    meta: Dict[str, Any] = {
        "event_category": record.event_category,
        "severity": record.severity,
        "request_path": record.request_path,
        "request_method": record.request_method,
        "reason": record.reason,
        "success": record.success,
    }
    if details:
        meta["details"] = details
    return meta


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
    request: Request,
    _: str = Depends(verify_api_key),
) -> TenantUsageResponse:
    """Get usage statistics for a tenant."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
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
    request: Request,
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Update custom quota for a tenant."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
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
    request: Request,
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Update subscription tier for a tenant."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
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
    request: Request,
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Suspend a tenant (block all requests)."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
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
    request: Request,
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Activate a suspended tenant."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
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
    request: Request,
    tenant_id: Optional[str] = Query(default=None, max_length=128),
    include_disabled: bool = Query(default=False),
    _: str = Depends(verify_api_key),
) -> ListKeysResponse:
    """List API keys for admin usage."""
    bound_tenant = bind_tenant_id(
        request,
        tenant_id,
        require_explicit_for_unscoped=True,
    )

    keys = list_api_keys(tenant_id=bound_tenant, include_disabled=include_disabled)
    key_infos = [KeyInfo(**k) for k in keys]
    return ListKeysResponse(keys=key_infos, total=len(key_infos))


@router.get(
    "/audit/search",
    response_model=AuditSearchResponse,
    dependencies=[Depends(require_scopes("audit:read"))],
)
async def search_audit_events(
    request: Request,
    tenant_id: Optional[str] = Query(None, description="Tenant filter"),
    action: Optional[str] = Query(None, description="Filter by action"),
    actor: Optional[str] = Query(None, description="Filter by actor"),
    status: Optional[str] = Query(None, description="Filter by status"),
    request_id: Optional[str] = Query(None, description="Filter by request id"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    resource_id: Optional[str] = Query(None, description="Filter by resource id"),
    from_ts: Optional[datetime] = Query(None, description="Start time (RFC3339)"),
    to_ts: Optional[datetime] = Query(None, description="End time (RFC3339)"),
    cursor: Optional[str] = Query(None, description="Cursor for pagination"),
    page_size: int = Query(100, ge=1, le=1000),
    _: str = Depends(verify_api_key),
) -> AuditSearchResponse:
    """Search audit events with tenant scoping enforced."""
    # Enforce tenant binding:
    # - Tenant-scoped keys can only query their own tenant (or omit to use auth tenant)
    # - Unscoped keys MUST provide explicit tenant_id (no "unknown" shadow tenant)
    effective_tenant = bind_tenant_id(
        request, tenant_id, require_explicit_for_unscoped=True
    )
    filters = _audit_filters(
        tenant_id=effective_tenant,
        action=action,
        actor=actor,
        status=status,
        request_id=request_id,
        resource_type=resource_type,
        resource_id=resource_id,
        from_ts=from_ts,
        to_ts=to_ts,
    )

    cursor_filter = None
    if cursor:
        cursor_ts, cursor_id = _parse_cursor(cursor)
        cursor_filter = or_(
            SecurityAuditLog.created_at < cursor_ts,
            and_(
                SecurityAuditLog.created_at == cursor_ts,
                SecurityAuditLog.id < cursor_id,
            ),
        )
        filters.append(cursor_filter)

    engine = get_engine()
    with Session(engine) as session:
        records = (
            session.execute(
                select(SecurityAuditLog)
                .where(*filters)
                .order_by(
                    SecurityAuditLog.created_at.desc(), SecurityAuditLog.id.desc()
                )
                .limit(page_size)
            )
            .scalars()
            .all()
        )

    items: list[AuditEvent] = []
    for record in records:
        details = None
        if record.details_json:
            if isinstance(record.details_json, str):
                try:
                    details = json.loads(record.details_json)
                except json.JSONDecodeError:
                    details = {"raw": record.details_json}
            else:
                details = record.details_json
        if details and _audit_redaction_enabled():
            details = _redact_secrets(details)

        ip = record.client_ip
        user_agent = record.user_agent
        if _audit_redaction_enabled():
            ip = None
            user_agent = None

        items.append(
            AuditEvent(
                id=str(record.id),
                ts=record.created_at,
                tenant_id=record.tenant_id or effective_tenant,
                actor=record.key_prefix,
                action=record.event_type,
                status=_derive_status(record),
                resource_type=record.event_category,
                resource_id=record.request_path,
                request_id=record.request_id,
                ip=ip,
                user_agent=user_agent,
                meta=_audit_meta(record, details),
            )
        )

    next_cursor = _cursor_from_record(records[-1]) if records else None

    return AuditSearchResponse(
        items=items,
        next_cursor=next_cursor,
    )


class AuditExportRequest(BaseModel):
    """Audit export request."""

    format: Literal["csv", "json"]
    tenant_id: Optional[str] = None
    action: Optional[str] = None
    actor: Optional[str] = None
    status: Optional[str] = None
    request_id: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    from_ts: Optional[datetime] = None
    to_ts: Optional[datetime] = None
    page_size: int = Field(default=1000, ge=1, le=5000)


@router.post(
    "/audit/export",
    dependencies=[Depends(require_scopes("audit:read"))],
)
async def export_audit_events(
    request: Request,
    payload: AuditExportRequest,
    _: str = Depends(verify_api_key),
) -> StreamingResponse:
    """Export audit events as NDJSON or CSV with tenant scoping enforced."""
    # Enforce tenant binding:
    # - Tenant-scoped keys can only export their own tenant (or omit to use auth tenant)
    # - Unscoped keys MUST provide explicit tenant_id (no "unknown" shadow tenant)
    effective_tenant = bind_tenant_id(
        request, payload.tenant_id, require_explicit_for_unscoped=True
    )
    filters = _audit_filters(
        tenant_id=effective_tenant,
        action=payload.action,
        actor=payload.actor,
        status=payload.status,
        request_id=payload.request_id,
        resource_type=payload.resource_type,
        resource_id=payload.resource_id,
        from_ts=payload.from_ts,
        to_ts=payload.to_ts,
    )

    engine = get_engine()

    def _event_rows():
        with Session(engine) as session:
            result = session.execute(
                select(SecurityAuditLog)
                .where(*filters)
                .order_by(
                    SecurityAuditLog.created_at.desc(),
                    SecurityAuditLog.id.desc(),
                )
                .limit(payload.page_size)
            ).scalars()
            for record in result:
                details = None
                if record.details_json:
                    if isinstance(record.details_json, str):
                        try:
                            details = json.loads(record.details_json)
                        except json.JSONDecodeError:
                            details = {"raw": record.details_json}
                    else:
                        details = record.details_json
                if details and _audit_redaction_enabled():
                    details = _redact_secrets(details)

                ip = record.client_ip
                user_agent = record.user_agent
                if _audit_redaction_enabled():
                    ip = None
                    user_agent = None

                event = AuditEvent(
                    id=str(record.id),
                    ts=record.created_at,
                    tenant_id=record.tenant_id or effective_tenant,
                    actor=record.key_prefix,
                    action=record.event_type,
                    status=_derive_status(record),
                    resource_type=record.event_category,
                    resource_id=record.request_path,
                    request_id=record.request_id,
                    ip=ip,
                    user_agent=user_agent,
                    meta=_audit_meta(record, details),
                )
                yield event

    # Generate deterministic filename with tenant and timestamp
    export_ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"audit-{effective_tenant}-{export_ts}"
    if payload.format == "csv":
        fieldnames = [
            "id",
            "ts",
            "tenant_id",
            "actor",
            "action",
            "status",
            "resource_type",
            "resource_id",
            "request_id",
            "ip",
            "user_agent",
            "meta",
        ]

        def _csv_stream():
            buffer = io.StringIO()
            writer = csv.DictWriter(buffer, fieldnames=fieldnames)
            writer.writeheader()
            yield buffer.getvalue()
            buffer.seek(0)
            buffer.truncate(0)
            for event in _event_rows():
                row = event.model_dump()
                row["ts"] = event.ts.isoformat()
                row["meta"] = json.dumps(row["meta"])
                writer.writerow(row)
                yield buffer.getvalue()
                buffer.seek(0)
                buffer.truncate(0)

        response = StreamingResponse(_csv_stream(), media_type="text/csv")
        response.headers["Content-Disposition"] = (
            f'attachment; filename="{filename}.csv"'
        )
        return response

    def _json_stream():
        for event in _event_rows():
            row = event.model_dump()
            row["ts"] = event.ts.isoformat()
            yield json.dumps(row) + "\n"

    response = StreamingResponse(_json_stream(), media_type="application/x-ndjson")
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}.json"'
    return response


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
    bound_tenant = bind_tenant_id(
        request,
        req.tenant_id,
        require_explicit_for_unscoped=True,
    )

    key = mint_key(
        *req.scopes,
        ttl_seconds=req.ttl_seconds,
        tenant_id=bound_tenant,
    )

    parts = key.split(".")
    prefix = parts[0] if parts else "fgk"

    expires_at = int(time.time()) + req.ttl_seconds

    audit_key_created(
        key_prefix=prefix,
        scopes=req.scopes,
        tenant_id=bound_tenant,
        request=request,
        ttl_seconds=req.ttl_seconds,
    )

    return CreateKeyResponse(
        key=key,
        prefix=prefix,
        scopes=req.scopes,
        tenant_id=bound_tenant,
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
    bound_tenant = bind_tenant_id(
        request,
        tenant_id,
        require_explicit_for_unscoped=True,
    )
    keys = list_api_keys(tenant_id=bound_tenant, include_disabled=True)
    if not any(k.get("prefix") == key_prefix for k in keys):
        raise HTTPException(status_code=404, detail="Key not found")

    revoked = revoke_api_key(key_prefix, tenant_id=bound_tenant)
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
        bound_tenant = bind_tenant_id(
            request,
            req.tenant_id,
            require_explicit_for_unscoped=True,
        )
        result = rotate_api_key_by_prefix(
            key_prefix=key_prefix,
            ttl_seconds=req.ttl_seconds,
            tenant_id=bound_tenant,
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
