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
import hashlib
import hmac
import io
import json
import logging
import os
import re
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import and_, or_, select, text
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError
from sqlalchemy.orm import Session

from api.config.internal_gateway_secret import resolve_internal_gateway_secret
from api.actor_context import ActorContext
from api.auth_dispatch import require_permission
from api.auth_scopes import (
    _validate_tenant_id,
    bind_tenant_id,
    require_scopes,
)
from api.credential_authority import (
    CredentialNotFoundError,
    CredentialSlotNotFoundError,
    CredentialStateError,
    CredentialTypeError,
    TenantLifecycleError,
    TenantNotFoundError,
    get_credential,
    issue_credential,
    list_credential_events,
    list_credentials,
    resume_credential,
    revoke_credential,
    rotate_credential,
    suspend_credential,
)
from api.tenant_rbac import (
    VALID_ROLE_NAMES,
    assign_role as rbac_assign_role,
)
from api.error_contracts import api_error
from api.db import get_engine, set_tenant_context
from api.internal_platform_authority import (
    CANONICAL_INTERNAL_TENANT_ID as _PLATFORM_TENANT_ID,
    OPERATOR_CREDENTIAL_SLOT,
    OPERATOR_CREDENTIAL_TYPE,
    InternalPlatformAuthorityError,
    emit_internal_authority_event,
    emit_internal_credential_event_if_applicable,
    read_internal_platform_authority_status,
)
from api.platform_service_principal import (
    PlatformServicePrincipalError,
    read_service_principal_status,
    resume_service_principal,
    revoke_service_principal,
    rotate_service_principal_credential,
    suspend_service_principal,
)
from api.db_models import SecurityAuditLog
from api.security_audit import (
    AuditPersistenceError,
    audit_admin_action,
)
from api.tenant_authority import (
    TenantKind,
    TenantKindError,
    policy_for_tenant_kind,
    tenant_kind_http_error,
)

log = logging.getLogger("frostgate.admin")


def require_internal_admin_gateway(request: Request) -> None:
    """Allow core /admin routes only for trusted internal gateway calls.

    Token resolution delegates to resolve_internal_gateway_secret() in
    api/config/internal_gateway_secret.py (must match _admin_gateway_internal_token()
    in api/auth_scopes/resolution.py — both use the same resolver).

    FG_API_KEY is intentionally NOT a fallback — conflating the global API key
    with the internal trust token is a security anti-pattern.
    """
    fg_env = (os.getenv("FG_ENV") or "").strip().lower()
    is_prod_like = fg_env in {"prod", "production", "staging"}

    expected = resolve_internal_gateway_secret()

    # Enforce when: (a) any internal token is configured, OR (b) prod/staging env.
    # Skip only when no token is configured AND non-prod — preserves dev convenience
    # while closing the gap for devs running with a configured internal secret.
    if not expected and not is_prod_like:
        return

    provided = (request.headers.get("x-fg-internal-token") or "").strip()
    if not expected or not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status_code=403,
            detail=api_error(
                "ADMIN_GATEWAY_FORBIDDEN",
                "internal admin gateway authentication required",
                action="provide X-FG-Internal-Token header with the configured internal secret",
            ),
        )


router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(require_internal_admin_gateway)],
)


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


class ConfigMutationRevertResponse(BaseModel):
    success: bool
    change_id: str
    tenant_id: str
    restored_field: str
    restored_value: Any
    already_reverted: bool = False


_CHANGE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")


def _sha256_json(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _coerce_tier_value(value: Any) -> str:
    if value is None:
        return "free"
    if hasattr(value, "value"):
        return str(getattr(value, "value"))
    return str(value)


def _auth_scopes(request: Request) -> set[str]:
    auth_ctx = getattr(getattr(request, "state", None), "auth", None)
    return set(getattr(auth_ctx, "scopes", set()) or set())


def _allow_admin_write_config_fallback() -> bool:
    explicit = os.getenv("FG_ADMIN_WRITE_CONFIG_FALLBACK")
    if explicit is not None:
        return explicit.strip().lower() in {"1", "true", "yes", "on"}

    env = (os.getenv("FG_ENV") or "").strip().lower()
    return env not in {"prod", "production", "staging"}


def _require_elevated_config_scope(request: Request) -> str:
    scopes = _auth_scopes(request)
    if "admin:config" in scopes:
        return "admin:config"
    if "admin:write" in scopes and _allow_admin_write_config_fallback():
        return "admin:write"
    raise HTTPException(
        status_code=403,
        detail=api_error(
            "ADMIN_SCOPE_INSUFFICIENT",
            "admin:config scope required; admin:write accepted only in non-production environments",
            action="request admin:config scope from your administrator",
        ),
    )


def _config_change_dir() -> Path:
    root = Path(os.getenv("FG_CONFIG_CHANGE_DIR", "artifacts/config_changes")).resolve()
    root.mkdir(parents=True, exist_ok=True)
    try:
        root.chmod(0o700)
    except Exception:
        pass
    return root


def _sanitize_change_id(change_id: str) -> str:
    if not _CHANGE_ID_RE.fullmatch(change_id or ""):
        raise HTTPException(status_code=400, detail="Invalid change id format")
    return change_id


def _state_for_field(*, tracker: Any, tenant_id: str, field: str) -> Any:
    if field == "custom_quota":
        return tracker._tenant_custom_quotas.get(tenant_id)
    if field == "tier":
        return _coerce_tier_value(tracker._tenant_tiers.get(tenant_id))
    raise HTTPException(status_code=400, detail="Unsupported config change field")


def _record_config_change(
    *,
    request: Request,
    tenant_id: str,
    field: str,
    before: Any,
    after: Any,
    scope: str,
) -> dict[str, Any]:
    created_at = datetime.now(timezone.utc).isoformat()
    request_id = getattr(getattr(request, "state", None), "request_id", None)
    change_id = uuid.uuid4().hex

    payload = {
        "change_id": change_id,
        "tenant_id": tenant_id,
        "field": field,
        "before": before,
        "after": after,
        "scope": scope,
        "timestamp": created_at,
        "request_id": request_id,
        "revert_supported": True,
        "reverted": False,
    }
    payload["snapshot_hash"] = _sha256_json(payload)

    out = (_config_change_dir() / f"{change_id}.json").resolve()
    if out.parent != _config_change_dir():
        raise HTTPException(status_code=400, detail="Invalid config change path")
    out.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    try:
        out.chmod(0o600)
    except Exception:
        pass
    return payload


def _load_config_change(change_id: str) -> tuple[Path, dict[str, Any]]:
    safe_change_id = _sanitize_change_id(change_id)
    path = (_config_change_dir() / f"{safe_change_id}.json").resolve()
    if path.parent != _config_change_dir():
        raise HTTPException(status_code=400, detail="Invalid config change path")
    if not path.exists():
        raise HTTPException(status_code=404, detail="Config change not found")

    payload = json.loads(path.read_text(encoding="utf-8"))
    expected = payload.get("snapshot_hash")
    body = dict(payload)
    body.pop("snapshot_hash", None)
    actual = _sha256_json(body)
    if not isinstance(expected, str) or expected != actual:
        raise HTTPException(
            status_code=409, detail="Config change integrity verification failed"
        )
    return path, payload


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
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
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
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
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

    scope_used = _require_elevated_config_scope(request)
    tracker = get_usage_tracker()
    before_quota = tracker._tenant_custom_quotas.get(tenant_id)
    tracker.set_custom_quota(tenant_id, update.quota)
    change = _record_config_change(
        request=request,
        tenant_id=tenant_id,
        field="custom_quota",
        before=before_quota,
        after=update.quota,
        scope=scope_used,
    )
    audit_admin_action(
        action="tenant_quota_updated",
        tenant_id=tenant_id,
        request=request,
        details={"quota": update.quota, "config_change": change},
    )

    return {
        "success": True,
        "tenant_id": tenant_id,
        "quota": update.quota,
        "message": "Quota updated successfully",
        "config_change_id": change["change_id"],
    }


@router.put(
    "/tenants/{tenant_id}/tier",
    dependencies=[Depends(require_scopes("admin:write"))],
)
async def update_tenant_tier(
    tenant_id: str,
    update: TenantTierUpdate,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
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

    scope_used = _require_elevated_config_scope(request)
    tracker = get_usage_tracker()
    previous_tier = _coerce_tier_value(tracker._tenant_tiers.get(tenant_id))
    tracker.set_tenant_tier(tenant_id, tier)
    change = _record_config_change(
        request=request,
        tenant_id=tenant_id,
        field="tier",
        before=previous_tier,
        after=tier.value,
        scope=scope_used,
    )
    audit_admin_action(
        action="tenant_tier_updated",
        tenant_id=tenant_id,
        request=request,
        details={"tier": tier.value, "config_change": change},
    )

    return {
        "success": True,
        "tenant_id": tenant_id,
        "tier": tier.value,
        "message": "Tier updated successfully",
        "config_change_id": change["change_id"],
    }


def _lifecycle_transition(
    tenant_id: str,
    to_state: str,
    *,
    request: Request,
    actor_ctx: ActorContext,
    reason: Optional[str] = None,
    idempotency_key: Optional[str] = None,
) -> None:
    """Execute a lifecycle transition through the R3 authority (no-op on non-Postgres)."""
    from api.tenant_lifecycle import (
        InvalidTransitionError,
        TenantNotFoundError,
        execute_transition,
    )

    engine = get_engine()
    if engine.dialect.name != "postgresql":
        return

    request_id = getattr(getattr(request, "state", None), "request_id", None)
    try:
        execute_transition(
            engine,
            tenant_id=tenant_id,
            to_state=to_state,
            reason=reason,
            actor_id=actor_ctx.subject,
            request_id=request_id,
            idempotency_key=idempotency_key,
        )
    except TenantNotFoundError:
        raise HTTPException(status_code=404, detail=f"Tenant not found: {tenant_id}")
    except InvalidTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@router.post(
    "/tenants/{tenant_id}/suspend",
    dependencies=[Depends(require_scopes("admin:write"))],
)
async def suspend_tenant(
    tenant_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
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

    _lifecycle_transition(tenant_id, "suspended", request=request, actor_ctx=actor_ctx)
    tracker = get_usage_tracker()
    tracker.suspend_tenant(tenant_id)
    audit_admin_action(
        action="tenant_suspended",
        tenant_id=tenant_id,
        request=request,
    )

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
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
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

    _lifecycle_transition(tenant_id, "active", request=request, actor_ctx=actor_ctx)
    tracker = get_usage_tracker()
    tracker.activate_tenant(tenant_id)
    audit_admin_action(
        action="tenant_activated",
        tenant_id=tenant_id,
        request=request,
    )

    return {
        "success": True,
        "tenant_id": tenant_id,
        "status": "active",
        "message": "Tenant activated successfully",
    }


@router.post(
    "/tenants/{tenant_id}/archive",
    dependencies=[Depends(require_scopes("admin:write"))],
)
async def archive_tenant(
    tenant_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
    reason: Optional[str] = Query(default=None, description="Reason for archival"),
) -> Dict[str, Any]:
    """Archive a tenant (active or suspended → archived)."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    _lifecycle_transition(
        tenant_id, "archived", request=request, actor_ctx=actor_ctx, reason=reason
    )
    audit_admin_action(
        action="tenant_archived",
        tenant_id=tenant_id,
        request=request,
        details={"reason": reason},
    )
    return {
        "success": True,
        "tenant_id": tenant_id,
        "status": "archived",
        "message": "Tenant archived successfully",
    }


@router.post(
    "/tenants/{tenant_id}/delete",
    dependencies=[Depends(require_scopes("admin:write"))],
)
async def delete_tenant(
    tenant_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
    reason: Optional[str] = Query(default=None, description="Reason for deletion"),
) -> Dict[str, Any]:
    """Mark an archived tenant as deleted (archived → deleted, terminal state)."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    _lifecycle_transition(
        tenant_id, "deleted", request=request, actor_ctx=actor_ctx, reason=reason
    )
    audit_admin_action(
        action="tenant_deleted",
        tenant_id=tenant_id,
        request=request,
        details={"reason": reason},
    )
    return {
        "success": True,
        "tenant_id": tenant_id,
        "status": "deleted",
        "message": "Tenant marked as deleted",
    }


@router.get(
    "/tenants/{tenant_id}/lifecycle-history",
    dependencies=[Depends(require_scopes("admin:read"))],
)
async def get_tenant_lifecycle_history(
    tenant_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
    limit: int = Query(default=50, ge=1, le=200),
) -> Dict[str, Any]:
    """Return the lifecycle transition history for a tenant."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    from api.tenant_lifecycle import get_transition_history

    engine = get_engine()
    if engine.dialect.name != "postgresql":
        return {"tenant_id": tenant_id, "transitions": []}

    records = get_transition_history(engine, tenant_id, limit=limit)
    return {
        "tenant_id": tenant_id,
        "transitions": [
            {
                "transition_id": r.transition_id,
                "from_state": r.from_state,
                "to_state": r.to_state,
                "reason": r.reason,
                "actor_id": r.actor_id,
                "request_id": r.request_id,
                "occurred_at": r.occurred_at.isoformat(),
            }
            for r in records
        ],
    }


# =============================================================================
# Tenant Credential Management (R4.6)
# =============================================================================


class IssueCredentialRequest(BaseModel):
    model_config = {"extra": "forbid"}

    credential_type: str = "tenant_api_key"
    credential_slot: str
    scopes: Optional[List[str]] = None
    expires_in_seconds: Optional[int] = None
    request_id: Optional[str] = None
    idempotency_key: Optional[str] = None


class RotateCredentialRequest(BaseModel):
    model_config = {"extra": "forbid"}

    expires_in_seconds: Optional[int] = None
    request_id: Optional[str] = None


class AssignCredentialRoleRequest(BaseModel):
    """Request to assign an RBAC role to a credential (operator/admin path)."""

    model_config = {"extra": "forbid"}

    role: str = Field(..., min_length=1, max_length=64)


class RevokeCredentialRequest(BaseModel):
    model_config = {"extra": "forbid"}

    reason: str
    request_id: Optional[str] = None


def _request_id_from_request(
    request: Request, explicit: Optional[str] = None
) -> Optional[str]:
    return explicit or getattr(getattr(request, "state", None), "request_id", None)


def _emit_internal_authority_event_best_effort(engine, **kwargs: Any) -> None:
    try:
        with engine.begin() as conn:
            emit_internal_authority_event(conn, **kwargs)
    except (OperationalError, ProgrammingError):
        log.debug("internal_platform_authority_events table unavailable", exc_info=True)


def _operator_policy_for_tenant(engine, tenant_id: str):
    from api.tenant_repository import TenantRepository

    try:
        record = TenantRepository(engine).get(tenant_id)
    except (OperationalError, ProgrammingError):
        return None, None
    if record is None:
        return None, None
    return record, policy_for_tenant_kind(record.tenant_kind)


def _reject_extra_internal_operator_credential_slots(
    engine,
    tenant_id: str,
    credential_type: str,
    credential_slot: str,
) -> None:
    record, policy = _operator_policy_for_tenant(engine, tenant_id)
    if record is None or policy is None or not policy.operator_authority_allowed:
        return
    if (
        credential_type != OPERATOR_CREDENTIAL_TYPE
        or credential_slot != OPERATOR_CREDENTIAL_SLOT
    ):
        raise HTTPException(
            status_code=403,
            detail=api_error(
                "INTERNAL_OPERATOR_CREDENTIAL_SLOT_FORBIDDEN",
                "internal platform authority may only use the canonical operator credential slot",
            ),
        )


def _credential_record_dict(rec) -> Dict[str, Any]:
    return {
        "credential_id": rec.credential_id,
        "tenant_id": rec.tenant_id,
        "credential_type": rec.credential_type,
        "credential_slot": rec.credential_slot,
        "generation": rec.generation,
        "status": rec.status,
        "expires_at": rec.expires_at.isoformat() if rec.expires_at else None,
        "issued_at": rec.issued_at.isoformat() if rec.issued_at else None,
        "last_used_at": rec.last_used_at.isoformat() if rec.last_used_at else None,
        "approximate_use_count": rec.approximate_use_count,
        "scopes": rec.scopes_csv.split(",") if rec.scopes_csv else None,
    }


@router.get(
    "/tenants/{tenant_id}/credentials",
    dependencies=[Depends(require_scopes("admin:read"))],
)
async def list_tenant_credentials(
    tenant_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
    credential_type: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
) -> Dict[str, Any]:
    """List credentials for a tenant."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    engine = get_engine()
    records = list_credentials(
        engine, tenant_id, credential_type=credential_type, status=status, limit=limit
    )
    return {
        "tenant_id": tenant_id,
        "credentials": [_credential_record_dict(r) for r in records],
    }


@router.post(
    "/tenants/{tenant_id}/credentials",
    status_code=201,
    dependencies=[Depends(require_scopes("admin:write"))],
)
async def issue_tenant_credential(
    tenant_id: str,
    req: IssueCredentialRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
) -> Dict[str, Any]:
    """Issue a new credential for a tenant slot. Plaintext secret returned once only."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    engine = get_engine()
    _reject_extra_internal_operator_credential_slots(
        engine, tenant_id, req.credential_type, req.credential_slot
    )
    try:
        result = issue_credential(
            engine,
            tenant_id=tenant_id,
            credential_type=req.credential_type,
            credential_slot=req.credential_slot,
            scopes=req.scopes,
            expires_in_seconds=req.expires_in_seconds,
            actor_id=actor_ctx.subject,
            request_id=req.request_id,
            idempotency_key=req.idempotency_key,
        )
    except TenantNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except TenantLifecycleError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except CredentialTypeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    emit_internal_credential_event_if_applicable(
        engine,
        tenant_id=tenant_id,
        event_type="credential_issued",
        actor_id=actor_ctx.subject,
        request_id=_request_id_from_request(request, req.request_id),
        credential_id=result.record.credential_id,
        credential_type=result.record.credential_type,
        credential_slot=result.record.credential_slot,
        generation=result.record.generation,
        metadata={"admin_route": "issue", "plaintext_exposed_once": True},
    )

    resp: Dict[str, Any] = _credential_record_dict(result.record)
    resp["plaintext_secret"] = result.plaintext_secret  # None on idempotency replay
    return resp


@router.get(
    "/tenants/{tenant_id}/credentials/{credential_id}",
    dependencies=[Depends(require_scopes("admin:read"))],
)
async def get_tenant_credential(
    tenant_id: str,
    credential_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
) -> Dict[str, Any]:
    """Get a specific credential by ID."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    engine = get_engine()
    try:
        rec = get_credential(engine, credential_id, tenant_id)
    except CredentialNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return _credential_record_dict(rec)


@router.post(
    "/tenants/{tenant_id}/credentials/{credential_id}/rotate",
    dependencies=[Depends(require_scopes("admin:write"))],
)
async def rotate_tenant_credential(
    tenant_id: str,
    credential_id: str,
    req: RotateCredentialRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
) -> Dict[str, Any]:
    """Rotate the slot that the given credential belongs to. Returns the new credential."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    engine = get_engine()
    try:
        existing = get_credential(engine, credential_id, tenant_id)
    except CredentialNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    try:
        result = rotate_credential(
            engine,
            tenant_id=tenant_id,
            credential_type=existing.credential_type,
            credential_slot=existing.credential_slot,
            expires_in_seconds=req.expires_in_seconds,
            actor_id=actor_ctx.subject,
            request_id=req.request_id,
        )
    except TenantLifecycleError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except CredentialStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    emit_internal_credential_event_if_applicable(
        engine,
        tenant_id=tenant_id,
        event_type="credential_rotated",
        actor_id=actor_ctx.subject,
        request_id=_request_id_from_request(request, req.request_id),
        credential_id=result.record.credential_id,
        credential_type=result.record.credential_type,
        credential_slot=result.record.credential_slot,
        generation=result.record.generation,
        metadata={"admin_route": "rotate", "replaced_credential_id": credential_id},
    )

    resp: Dict[str, Any] = _credential_record_dict(result.record)
    resp["plaintext_secret"] = result.plaintext_secret
    return resp


@router.post(
    "/tenants/{tenant_id}/credentials/{credential_id}/revoke",
    dependencies=[Depends(require_scopes("admin:write"))],
)
async def revoke_tenant_credential(
    tenant_id: str,
    credential_id: str,
    req: RevokeCredentialRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
) -> Dict[str, Any]:
    """Revoke a specific credential. Idempotent."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    engine = get_engine()
    try:
        rec = revoke_credential(
            engine,
            credential_id=credential_id,
            tenant_id=tenant_id,
            actor_id=actor_ctx.subject,
            reason=req.reason,
            request_id=req.request_id,
        )
    except CredentialNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except CredentialStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    emit_internal_credential_event_if_applicable(
        engine,
        tenant_id=tenant_id,
        event_type="credential_revoked",
        actor_id=actor_ctx.subject,
        request_id=_request_id_from_request(request, req.request_id),
        credential_id=rec.credential_id,
        credential_type=rec.credential_type,
        credential_slot=rec.credential_slot,
        generation=rec.generation,
        metadata={"admin_route": "revoke", "reason": req.reason},
    )
    return _credential_record_dict(rec)


@router.post(
    "/tenants/{tenant_id}/credentials/{credential_id}/role",
    status_code=201,
    dependencies=[Depends(require_scopes("admin:write"))],
)
async def assign_tenant_credential_role(
    tenant_id: str,
    credential_id: str,
    req: AssignCredentialRoleRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
) -> Dict[str, Any]:
    """Assign an RBAC role to a tenant credential via the operator (admin) path.

    This endpoint is used during provisioning to bootstrap the initial role for a
    new credential before the credential can self-serve via /rbac/assignments.
    It requires platform.admin permission (internal gateway auth) rather than
    require_role("tenant_admin") on the *target* credential.

    Idempotent: assigning the same role to an already-assigned credential replaces
    it (via assign_role's revoke-then-insert logic).
    """
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    if req.role not in VALID_ROLE_NAMES:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown role: {req.role!r}. Valid roles: {sorted(VALID_ROLE_NAMES)}",
        )
    engine = get_engine()
    try:
        with Session(engine) as session:
            set_tenant_context(session, tenant_id)
            result = rbac_assign_role(
                session,
                tenant_id=tenant_id,
                actor_key_prefix=actor_ctx.subject or "operator:admin",
                credential_id=credential_id,
                role_name=req.role,
            )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return result


@router.get(
    "/tenants/{tenant_id}/credential-events",
    dependencies=[Depends(require_scopes("admin:read"))],
)
async def list_tenant_credential_events(
    tenant_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
    credential_id: Optional[str] = Query(default=None),
    event_type: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> Dict[str, Any]:
    """List credential audit events for a tenant, newest first."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    engine = get_engine()
    events = list_credential_events(
        engine,
        tenant_id,
        credential_id=credential_id,
        event_type=event_type,
        limit=limit,
    )
    return {
        "tenant_id": tenant_id,
        "events": [
            {
                "event_id": e.event_id,
                "credential_id": e.credential_id,
                "credential_type": e.credential_type,
                "credential_slot": e.credential_slot,
                "generation": e.generation,
                "event_type": e.event_type,
                "outcome": e.outcome,
                "actor_id": e.actor_id,
                "request_id": e.request_id,
                "occurred_at": e.occurred_at.isoformat(),
                "failure_reason": e.failure_reason,
            }
            for e in events
        ],
    }


# =============================================================================
# Tenant Create / Read Endpoints
# =============================================================================

_TENANT_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")


class TenantCreateRequest(BaseModel):
    """Request to provision a new tenant."""

    model_config = {"extra": "forbid"}

    tenant_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Globally unique tenant identifier (alphanumeric, dash, underscore)",
    )
    name: Optional[str] = Field(
        default=None,
        max_length=256,
        description="Human-readable tenant display name",
    )


class TenantRecord(BaseModel):
    """Tenant record response."""

    tenant_id: str
    name: str
    status: str
    tenant_kind: TenantKind = "customer"
    created_at: str
    updated_at: str


class OperatorTenantAuthorityResponse(BaseModel):
    tenant_id: str
    tenant_kind: TenantKind
    lifecycle_state: str
    operator_authority_allowed: bool
    customer_visible: bool
    portal_enabled: bool
    billing_eligible: bool


class InternalPlatformAuthorityResponse(BaseModel):
    authority_exists: bool
    tenant_id: Optional[str]
    tenant_kind: Optional[str]
    lifecycle_state: Optional[str]
    authority_version: Optional[int]
    bootstrap_status: str
    credential_type: str
    credential_slot: str
    credential_current_generation: int
    credential_status: Optional[str]
    credential_id: Optional[str]
    credential_issued: bool = False


class ServicePrincipalStatusResponse(BaseModel):
    exists: bool
    id: Optional[str]
    stable_key: Optional[str]
    display_name: Optional[str]
    principal_kind: Optional[str]
    lifecycle_state: Optional[str]
    authority_tenant_id: Optional[str]
    authority_version: Optional[int]
    credential_type: Optional[str]
    credential_slot: Optional[str]
    credential_id: Optional[str]
    credential_status: Optional[str]
    credential_generation: int = 0
    last_rotated_at: Optional[str]
    created_at: Optional[str]
    updated_at: Optional[str]
    granted_permissions: List[str] = []


class ServicePrincipalRotationResponse(ServicePrincipalStatusResponse):
    new_credential_value: Optional[str] = None


class ServicePrincipalLifecycleResponse(BaseModel):
    action: str
    lifecycle_state: str
    service_principal_id: Optional[str]
    stable_key: Optional[str]


# ---------------------------------------------------------------------------
# P-113.6 — Platform Admin Credential Authority models
# ---------------------------------------------------------------------------


class PlatformAdminBootstrapResponse(BaseModel):
    """Response for POST /admin/system/platform-admin/bootstrap."""

    credential_id: str
    credential_slot: str
    status: str  # "bootstrapped" | "already_exists"
    plaintext_key: Optional[str] = None  # present only on first bootstrap


class PlatformAdminStatusResponse(BaseModel):
    """Response for GET /admin/system/platform-admin."""

    exists: bool
    credential_id: Optional[str] = None
    credential_slot: Optional[str] = None
    credential_status: Optional[str] = None
    created_at: Optional[str] = None
    last_rotated_at: Optional[str] = None


class PlatformAdminRotationResponse(BaseModel):
    """Response for POST /admin/system/platform-admin/rotate."""

    credential_id: str
    credential_slot: str
    action: str = "rotated"
    plaintext_key: Optional[str] = None


class PlatformAdminLifecycleResponse(BaseModel):
    """Response for suspend/resume/revoke platform-admin routes."""

    credential_id: str
    credential_slot: str
    action: str
    credential_status: str


@router.post(
    "/tenants",
    response_model=TenantRecord,
    status_code=201,
    dependencies=[Depends(require_scopes("admin:write"))],
)
async def create_tenant(
    req: TenantCreateRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
) -> TenantRecord:
    """Provision a new tenant.

    Enforces:
    - tenant_id format validation (alphanumeric, dash, underscore, max 128)
    - Uniqueness: returns 409 if tenant_id already exists
    - Audit log on creation
    - Persists to tenant registry
    """
    if not _TENANT_ID_RE.fullmatch(req.tenant_id):
        raise HTTPException(
            status_code=422,
            detail="tenant_id contains invalid characters (alphanumeric, dash, underscore only, max 128)",
        )

    # Derive actor from auth context early (needed for both Postgres and JSON paths).
    _auth_ctx = getattr(getattr(request, "state", None), "auth", None)
    _actor_id: str = (
        getattr(_auth_ctx, "key_prefix", None)
        or getattr(_auth_ctx, "subject", None)
        or "global"
    )
    _scope_values: list[str] = sorted(
        getattr(_auth_ctx, "scopes", set()) or {"admin:write"}
    )

    # Try Postgres-first (R7).
    from api.tenant_repository import get_tenant_repository

    repo = get_tenant_repository()
    if repo is not None:
        try:
            pg_record = repo.create(
                tenant_id=req.tenant_id,
                display_name=req.name or req.tenant_id,
                created_by=_actor_id,
                migration_source="api",
            )
        except (ValueError, IntegrityError):
            raise HTTPException(
                status_code=409, detail=f"Tenant already exists: {req.tenant_id}"
            )

        try:
            audit_admin_action(
                action="tenant_created",
                tenant_id=req.tenant_id,
                request=request,
                details={
                    "name": pg_record.display_name,
                    "actor_id": _actor_id,
                    "scope": _scope_values,
                },
            )
        except AuditPersistenceError:
            # Compensate: delete the orphan tenant row so no partial state persists.
            # JSON write is deferred until after audit succeeds, so no JSON cleanup needed.
            try:
                from sqlalchemy import text as _text

                with get_engine().begin() as _conn:
                    _conn.execute(
                        _text("DELETE FROM tenants WHERE tenant_id = :tid"),
                        {"tid": req.tenant_id},
                    )
            except Exception:
                log.error(
                    "tenant.orphan_compensation_failed",
                    extra={"tenant_id": req.tenant_id},
                )
            raise HTTPException(
                status_code=500,
                detail=api_error(
                    "AUDIT_PERSISTENCE_FAILED",
                    "tenant created but audit write failed; tenant rolled back",
                ),
            )

        # JSON write is best-effort during R7 transition. Deferred until after audit
        # succeeds so compensation on audit failure only needs to delete the Postgres row.
        try:
            from tools.tenants.registry import create_tenant_exclusive

            create_tenant_exclusive(
                tenant_id=req.tenant_id,
                name=req.name or req.tenant_id,
            )
        except Exception:
            pass  # best-effort during transition
        log.info(
            "tenant.created",
            extra={
                "tenant_id": req.tenant_id,
                "request_id": getattr(request.state, "request_id", None),
            },
        )
        return TenantRecord(
            tenant_id=pg_record.tenant_id,
            name=pg_record.display_name,
            status=pg_record.lifecycle_state,
            tenant_kind=pg_record.tenant_kind,
            created_at=str(pg_record.created_at),
            updated_at=str(pg_record.updated_at),
        )

    # Fallback: original JSON path (for non-Postgres environments).
    try:
        from tools.tenants.registry import (
            TenantAlreadyExistsError,
            create_tenant_exclusive,
            load_registry,
        )
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="Tenant registry not available",
        )

    # Non-authoritative fast path: avoid lock acquisition for obvious duplicates.
    # The authoritative uniqueness check is inside create_tenant_exclusive (under lock).
    existing = load_registry()
    if req.tenant_id in existing:
        raise HTTPException(
            status_code=409,
            detail=f"Tenant already exists: {req.tenant_id}",
        )

    try:
        record = create_tenant_exclusive(
            tenant_id=req.tenant_id,
            name=req.name or req.tenant_id,
        )
    except TenantAlreadyExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    audit_admin_action(
        action="tenant_created",
        tenant_id=req.tenant_id,
        request=request,
        details={
            "name": record.name,
            "actor_id": _actor_id,
            "scope": _scope_values,
        },
    )

    log.info(
        "tenant.created",
        extra={
            "tenant_id": req.tenant_id,
            "request_id": getattr(request.state, "request_id", None),
        },
    )

    return TenantRecord(
        tenant_id=record.tenant_id,
        name=record.name,
        status=record.status,
        tenant_kind="customer",
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


class TenantIdentityBindingRequest(BaseModel):
    """Request to provision an identity binding for a tenant."""

    model_config = {"extra": "forbid"}

    display_name: str = Field(
        ...,
        max_length=256,
        description="Auth0 Organization display name (human-readable)",
    )


class TenantIdentityBindingResponse(BaseModel):
    """Identity binding record returned to callers."""

    binding_id: str
    tenant_id: str
    provider: str
    provider_org_id: Optional[str]
    provider_org_name: Optional[str]
    provisioning_state: str
    idempotency_key: str
    last_sync_at: Optional[str]
    last_error_code: Optional[str]
    created_at: str
    updated_at: str


@router.post(
    "/tenants/{tenant_id}/identity-bindings",
    dependencies=[Depends(require_scopes("admin:write"))],
)
async def provision_tenant_identity_binding(
    tenant_id: str,
    req: TenantIdentityBindingRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
) -> Any:
    """Provision an Auth0 organization for the given tenant (IA-1).

    Idempotent: returns existing active binding without a new Auth0 call.
    Retryable: calling again when state='failed' reattempts provisioning.
    """
    from api.tenant_identity_authority import (
        ProvisioningFailedError,
        provision_tenant_organization,
    )

    if not _TENANT_ID_RE.fullmatch(tenant_id):
        raise HTTPException(
            status_code=422,
            detail=api_error(
                "TENANT_ID_FORMAT_INVALID",
                "tenant_id does not match required format",
            ),
        )

    # Verify tenant exists
    from api.tenant_repository import get_tenant_repository

    repo = get_tenant_repository()
    if repo is not None:
        tenant_record = repo.get(tenant_id)
        if tenant_record is None:
            raise HTTPException(
                status_code=404,
                detail=api_error("TENANT_NOT_FOUND", f"tenant not found: {tenant_id}"),
            )

    request_id = _request_id_from_request(request) or str(uuid.uuid4())
    _auth_ctx = getattr(getattr(request, "state", None), "auth", None)
    actor_id: str = (
        getattr(_auth_ctx, "key_prefix", None)
        or getattr(_auth_ctx, "subject", None)
        or actor_ctx.subject
        or "admin"
    )

    engine = get_engine()
    from api.tenant_identity_authority import get_tenant_binding

    # Capture pre-call state to determine 200 vs 201
    with engine.connect() as pre_conn:
        pre_binding = get_tenant_binding(
            tenant_id=tenant_id,
            db_conn=pre_conn,
        )
    was_already_active = (
        pre_binding is not None and pre_binding.provisioning_state == "active"
    )

    try:
        # Pass the Engine directly (not a connection) so provision_tenant_organization
        # can open independent transactions for each state transition. Passing a
        # connection here would wrap the entire call in a single outer transaction,
        # causing failed-state binding rows and audit events to be rolled back on
        # Auth0 failure — making failures invisible to retries and operators.
        binding = provision_tenant_organization(
            tenant_id=tenant_id,
            display_name=req.display_name,
            actor_id=actor_id,
            request_id=request_id,
            db_conn=engine,
        )
    except ProvisioningFailedError as exc:
        from fastapi.responses import JSONResponse

        audit_admin_action(
            action="tenant_org_provisioning_failed",
            tenant_id=tenant_id,
            request=request,
            details={
                "actor_id": actor_id,
                "error_code": exc.error_code,
                "retryable": exc.retryable,
                "provider": "auth0",
            },
        )
        if exc.retryable:
            return JSONResponse(
                status_code=503,
                content={
                    "error": "PROVISIONING_FAILED",
                    "retryable": True,
                    "error_code": exc.error_code,
                },
            )
        if exc.error_code == "AUTH0_ORG_OWNERSHIP_CONFLICT":
            return JSONResponse(
                status_code=409,
                content={
                    "error": "AUTH0_ORG_OWNERSHIP_CONFLICT",
                    "retryable": False,
                    "operator_action_required": True,
                },
            )
        return JSONResponse(
            status_code=502,
            content={
                "error": "PROVISIONING_FAILED",
                "retryable": False,
                "error_code": exc.error_code,
            },
        )

    audit_admin_action(
        action="tenant_org_provisioned",
        tenant_id=tenant_id,
        request=request,
        details={
            "actor_id": actor_id,
            "provider": binding.provider,
            "provider_org_id": binding.provider_org_id,
            "provisioning_state": binding.provisioning_state,
        },
    )

    response_body = TenantIdentityBindingResponse(
        binding_id=binding.binding_id,
        tenant_id=binding.tenant_id,
        provider=binding.provider,
        provider_org_id=binding.provider_org_id,
        provider_org_name=binding.provider_org_name,
        provisioning_state=binding.provisioning_state,
        idempotency_key=binding.idempotency_key,
        last_sync_at=binding.last_sync_at,
        last_error_code=binding.last_error_code,
        created_at=binding.created_at,
        updated_at=binding.updated_at,
    )

    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=200 if was_already_active else 201,
        content=response_body.model_dump(),
    )


@router.get(
    "/tenants",
    dependencies=[Depends(require_scopes("admin:read"))],
)
async def list_tenants(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
    include_revoked: bool = Query(default=False),
) -> Dict[str, Any]:
    """List all provisioned tenants."""
    # Try Postgres-first (R7).
    from api.tenant_repository import get_tenant_repository

    repo = get_tenant_repository()
    if repo is not None:
        records_pg = repo.list_all(include_archived=include_revoked)
        return {
            "tenants": [
                {
                    "tenant_id": r.tenant_id,
                    "name": r.display_name,
                    "status": r.lifecycle_state,
                    "tenant_kind": r.tenant_kind,
                    "created_at": str(r.created_at),
                    "updated_at": str(r.updated_at),
                }
                for r in records_pg
            ],
            "total": len(records_pg),
        }

    # Fallback: original JSON path.
    try:
        from tools.tenants.registry import list_tenants as _list_tenants
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="Tenant registry not available",
        )

    records = _list_tenants(include_revoked=include_revoked)
    return {
        "tenants": [
            {
                "tenant_id": r.tenant_id,
                "name": r.name,
                "status": r.status,
                "tenant_kind": "customer",
                "created_at": r.created_at,
                "updated_at": r.updated_at,
            }
            for r in records
        ],
        "total": len(records),
    }


@router.get(
    "/tenants/{tenant_id}/operator-authority",
    response_model=OperatorTenantAuthorityResponse,
    dependencies=[Depends(require_scopes("admin:read"))],
)
async def validate_operator_tenant_authority(
    tenant_id: str,
    request: Request,
) -> OperatorTenantAuthorityResponse:
    """Validate whether a tenant may act as configured Console operator authority."""
    if not _TENANT_ID_RE.fullmatch(tenant_id):
        raise HTTPException(
            status_code=422,
            detail=api_error(
                "TENANT_ID_FORMAT_INVALID",
                "tenant_id does not match required format",
            ),
        )

    from api.tenant_repository import get_tenant_repository

    repo = get_tenant_repository()
    if repo is None:
        raise HTTPException(
            status_code=503,
            detail=api_error(
                "TENANT_AUTHORITY_UNAVAILABLE",
                "tenant authority repository is unavailable",
            ),
        )

    record = repo.get(tenant_id)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail=api_error("TENANT_NOT_FOUND", f"tenant not found: {tenant_id}"),
        )

    try:
        policy = policy_for_tenant_kind(record.tenant_kind)
    except TenantKindError as exc:
        raise tenant_kind_http_error(exc) from exc

    engine = get_engine()
    request_id = _request_id_from_request(request)
    if record.lifecycle_state != "active" or not policy.operator_authority_allowed:
        _emit_internal_authority_event_best_effort(
            engine,
            event_type="authority_denied",
            actor_id="admin-gateway",
            service_id="console-bff",
            target_tenant_id=tenant_id,
            authority_tenant_id=record.tenant_id,
            request_id=request_id,
            outcome="denied",
            failure_reason="OPERATOR_TENANT_NOT_ALLOWED",
            metadata={
                "tenant_kind": record.tenant_kind,
                "lifecycle_state": record.lifecycle_state,
            },
        )
        raise HTTPException(
            status_code=403,
            detail={
                "code": "OPERATOR_TENANT_NOT_ALLOWED",
                "tenant_id": tenant_id,
                "tenant_kind": record.tenant_kind,
                "lifecycle_state": record.lifecycle_state,
            },
        )

    _emit_internal_authority_event_best_effort(
        engine,
        event_type="authority_validated",
        actor_id="admin-gateway",
        service_id="console-bff",
        target_tenant_id=tenant_id,
        authority_tenant_id=record.tenant_id,
        request_id=request_id,
        metadata={
            "tenant_kind": record.tenant_kind,
            "lifecycle_state": record.lifecycle_state,
        },
    )

    return OperatorTenantAuthorityResponse(
        tenant_id=record.tenant_id,
        tenant_kind=record.tenant_kind,
        lifecycle_state=record.lifecycle_state,
        operator_authority_allowed=policy.operator_authority_allowed,
        customer_visible=policy.customer_visible,
        portal_enabled=policy.portal_enabled,
        billing_eligible=policy.billing_eligible,
    )


@router.get(
    "/tenants/{tenant_id}",
    response_model=TenantRecord,
    dependencies=[Depends(require_scopes("admin:read"))],
)
async def get_tenant(
    tenant_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
) -> TenantRecord:
    """Get a single tenant by ID."""
    if not _TENANT_ID_RE.fullmatch(tenant_id):
        raise HTTPException(
            status_code=422,
            detail=api_error(
                "TENANT_ID_FORMAT_INVALID",
                "tenant_id does not match required format",
                action="use only alphanumeric characters, hyphens, and underscores (max 128 chars)",
            ),
        )

    # Try Postgres-first (R7); repo.get() handles JSON fallback internally.
    from api.tenant_repository import get_tenant_repository

    repo = get_tenant_repository()
    if repo is not None:
        pg_record = repo.get(tenant_id)
        if pg_record is None:
            raise HTTPException(
                status_code=404,
                detail=api_error(
                    "TENANT_NOT_FOUND",
                    f"tenant not found: {tenant_id}",
                ),
            )
        return TenantRecord(
            tenant_id=pg_record.tenant_id,
            name=pg_record.display_name,
            status=pg_record.lifecycle_state,
            tenant_kind=pg_record.tenant_kind,
            created_at=str(pg_record.created_at),
            updated_at=str(pg_record.updated_at),
        )

    # Fallback: original JSON path.
    try:
        from tools.tenants.registry import load_registry
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="Tenant registry not available",
        )

    records = load_registry()
    record = records.get(tenant_id)
    if not record:
        raise HTTPException(
            status_code=404,
            detail=api_error(
                "TENANT_NOT_FOUND",
                f"tenant not found: {tenant_id}",
            ),
        )

    return TenantRecord(
        tenant_id=record.tenant_id,
        name=record.name,
        status=record.status,
        tenant_kind="customer",
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


# =============================================================================
# API Key Admin Endpoints (legacy — retired R4.9)
# =============================================================================
# POST /admin/keys is retained as a 410 stub for one deprecation window so
# existing callers get an explicit migration signal instead of a 404.
# GET /admin/keys and POST /admin/keys/{prefix}/revoke are removed — they read
# and write api_keys which is no longer the canonical credential store.
# Issue, list, rotate, and revoke credentials via:
#   POST   /admin/tenants/{tenant_id}/credentials
#   GET    /admin/tenants/{tenant_id}/credentials
#   POST   /admin/tenants/{tenant_id}/credentials/{id}/rotate
#   POST   /admin/tenants/{tenant_id}/credentials/{id}/revoke


@router.get(
    "/audit/search",
    response_model=AuditSearchResponse,
    dependencies=[Depends(require_scopes("audit:read"))],
)
async def search_audit_events(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
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
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
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
    else:

        def _json_stream():
            for event in _event_rows():
                row = event.model_dump()
                row["ts"] = event.ts.isoformat()
                yield json.dumps(row) + "\n"

        response = StreamingResponse(_json_stream(), media_type="application/x-ndjson")
        response.headers["Content-Disposition"] = (
            f'attachment; filename="{filename}.json"'
        )

    audit_admin_action(
        action="admin_audit_export",
        tenant_id=effective_tenant,
        request=request,
        details={"format": payload.format, "page_size": payload.page_size},
    )
    return response


@router.post(
    "/keys",
    dependencies=[Depends(require_scopes("keys:write"))],
)
async def admin_create_key(request: Request) -> dict:
    """Retired in R4.9. Issue credentials via POST /admin/tenants/{tenant_id}/credentials."""
    raise HTTPException(
        status_code=410,
        detail={
            "code": "ENDPOINT_RETIRED",
            "message": (
                "POST /admin/keys is retired. "
                "Issue credentials via POST /admin/tenants/{tenant_id}/credentials."
            ),
        },
    )


# =============================================================================
# System Health and Diagnostics
# =============================================================================


@router.get(
    "/system/internal-authority",
    response_model=InternalPlatformAuthorityResponse,
    dependencies=[
        Depends(require_scopes("admin:read")),
        Depends(require_internal_admin_gateway),
    ],
)
async def get_internal_platform_authority(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
) -> InternalPlatformAuthorityResponse:
    """Return safe internal platform authority bootstrap status."""
    try:
        status = read_internal_platform_authority_status(get_engine())
    except InternalPlatformAuthorityError as exc:
        raise HTTPException(
            status_code=409,
            detail=api_error(exc.code, str(exc)),
        ) from exc
    return InternalPlatformAuthorityResponse(**status.safe_dict())


@router.get(
    "/system/service-principal",
    response_model=ServicePrincipalStatusResponse,
    dependencies=[
        Depends(require_scopes("admin:read")),
        Depends(require_internal_admin_gateway),
    ],
)
async def get_service_principal(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
) -> ServicePrincipalStatusResponse:
    """Return safe, secret-free status of the canonical platform service principal."""
    status = read_service_principal_status(get_engine())
    return ServicePrincipalStatusResponse(**status.safe_dict())


@router.post(
    "/system/service-principal/rotate",
    response_model=ServicePrincipalRotationResponse,
    dependencies=[
        Depends(require_scopes("admin:write")),
        Depends(require_internal_admin_gateway),
    ],
)
async def rotate_service_principal(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
) -> ServicePrincipalRotationResponse:
    """Rotate the platform service principal credential."""
    actor_id = actor_ctx.subject or "admin:rotate"
    request_id = getattr(getattr(request, "state", None), "request_id", None)
    try:
        result = rotate_service_principal_credential(
            get_engine(),
            actor_id=actor_id,
            request_id=request_id,
        )
    except PlatformServicePrincipalError as exc:
        raise HTTPException(
            status_code=409,
            detail=api_error(exc.code, str(exc)),
        ) from exc
    return ServicePrincipalRotationResponse(
        **result.status.safe_dict(),
        new_credential_value=result.plaintext_secret,
    )


@router.post(
    "/system/service-principal/suspend",
    response_model=ServicePrincipalLifecycleResponse,
    dependencies=[
        Depends(require_scopes("admin:write")),
        Depends(require_internal_admin_gateway),
    ],
)
async def suspend_service_principal_route(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
) -> ServicePrincipalLifecycleResponse:
    """Suspend the canonical platform service principal."""
    actor_id = actor_ctx.subject or "admin:suspend"
    request_id = getattr(getattr(request, "state", None), "request_id", None)
    try:
        status = suspend_service_principal(
            get_engine(),
            actor_id=actor_id,
            request_id=request_id,
        )
    except PlatformServicePrincipalError as exc:
        raise HTTPException(
            status_code=409,
            detail=api_error(exc.code, str(exc)),
        ) from exc
    return ServicePrincipalLifecycleResponse(
        action="suspended",
        lifecycle_state=status.lifecycle_state or "unknown",
        service_principal_id=status.id,
        stable_key=status.stable_key,
    )


@router.post(
    "/system/service-principal/resume",
    response_model=ServicePrincipalLifecycleResponse,
    dependencies=[
        Depends(require_scopes("admin:write")),
        Depends(require_internal_admin_gateway),
    ],
)
async def resume_service_principal_route(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
) -> ServicePrincipalLifecycleResponse:
    """Resume a suspended platform service principal."""
    actor_id = actor_ctx.subject or "admin:resume"
    request_id = getattr(getattr(request, "state", None), "request_id", None)
    try:
        status = resume_service_principal(
            get_engine(),
            actor_id=actor_id,
            request_id=request_id,
        )
    except PlatformServicePrincipalError as exc:
        raise HTTPException(
            status_code=409,
            detail=api_error(exc.code, str(exc)),
        ) from exc
    return ServicePrincipalLifecycleResponse(
        action="resumed",
        lifecycle_state=status.lifecycle_state or "unknown",
        service_principal_id=status.id,
        stable_key=status.stable_key,
    )


@router.post(
    "/system/service-principal/revoke",
    response_model=ServicePrincipalLifecycleResponse,
    dependencies=[
        Depends(require_scopes("admin:write")),
        Depends(require_internal_admin_gateway),
    ],
)
async def revoke_service_principal_route(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
) -> ServicePrincipalLifecycleResponse:
    """Permanently revoke the canonical platform service principal.

    This action is irreversible. The credential is also revoked.
    A new PSP must be bootstrapped to recover.
    """
    actor_id = actor_ctx.subject or "admin:revoke"
    request_id = getattr(getattr(request, "state", None), "request_id", None)
    try:
        status = revoke_service_principal(
            get_engine(),
            actor_id=actor_id,
            request_id=request_id,
        )
    except PlatformServicePrincipalError as exc:
        raise HTTPException(
            status_code=409,
            detail=api_error(exc.code, str(exc)),
        ) from exc
    return ServicePrincipalLifecycleResponse(
        action="revoked",
        lifecycle_state=status.lifecycle_state or "revoked",
        service_principal_id=status.id,
        stable_key=status.stable_key,
    )


# =============================================================================
# P-113.6 — Platform Administrator Credential Authority
#
# These endpoints manage the canonical platform_admin credential stored under
# the frostgate-internal tenant.  This credential is entirely separate from:
#   • FG_INTERNAL_GATEWAY_SECRET  — internal machine-to-machine trust token
#   • Platform Service Principal  — workload identity with explicit scopes
#   • CORE_API_KEY / FG_API_KEY   — dev-mode global bypass
#
# The platform_admin credential is issued by this bootstrap endpoint and
# rotated/suspended/revoked via the lifecycle endpoints below.  It carries the
# platform_admin role (stored in tenant_credential_roles) which resolves via
# roles_to_permissions(["platform_admin"]) = ALL_PERMISSIONS ⊃ "platform.admin".
#
# Path E (admin_internal_token) is retained as a COMPATIBILITY path for the
# current production deployment.  See resolution.py for the retirement comment.
# =============================================================================

# Slot name that uniquely identifies the platform-admin credential within the
# frostgate-internal tenant's credential_slots table.
_PLATFORM_ADMIN_SLOT = "platform-admin-credential:v1"
_PLATFORM_ADMIN_CREDENTIAL_TYPE = "tenant_api_key"
_PLATFORM_ADMIN_IDEMPOTENCY_KEY = "platform-admin-credential:v1:bootstrap"
_PLATFORM_ADMIN_ACTOR = "system:platform-admin-authority"


def _find_active_platform_admin_credential(engine) -> Optional[dict]:
    """Return the active platform_admin credential record, or None if absent.

    Queries tenant_credentials for the frostgate-internal tenant, slot
    platform-admin-credential:v1, status=active.  Returns None if not found.
    """
    with engine.connect() as conn:
        is_pg = engine.dialect.name == "postgresql"
        if is_pg:
            conn.execute(
                text("SELECT set_config('app.tenant_id', :tid, true)"),
                {"tid": _PLATFORM_TENANT_ID},
            )
        row = conn.execute(
            text(
                "SELECT credential_id, credential_slot, status, issued_at, rotated_at "
                "FROM tenant_credentials "
                "WHERE tenant_id = :tid "
                "  AND credential_slot = :slot "
                "  AND status = 'active'"
            ),
            {"tid": _PLATFORM_TENANT_ID, "slot": _PLATFORM_ADMIN_SLOT},
        ).fetchone()
    if row is None:
        return None
    return {
        "credential_id": str(row[0]),
        "credential_slot": str(row[1]),
        "status": str(row[2]),
        "created_at": str(row[3]) if row[3] else None,
        "last_rotated_at": str(row[4]) if row[4] else None,
    }


@router.get(
    "/system/platform-admin",
    response_model=PlatformAdminStatusResponse,
    dependencies=[
        Depends(require_scopes("admin:read")),
        Depends(require_internal_admin_gateway),
    ],
)
async def get_platform_admin_status(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
) -> PlatformAdminStatusResponse:
    """Return whether an active canonical platform-admin credential exists.

    Does not expose any credential material.  Returns exists=False if no
    active credential is present in the frostgate-internal tenant slot.
    """
    rec = _find_active_platform_admin_credential(get_engine())
    if rec is None:
        return PlatformAdminStatusResponse(exists=False)
    return PlatformAdminStatusResponse(
        exists=True,
        credential_id=rec["credential_id"],
        credential_slot=rec["credential_slot"],
        credential_status=rec["status"],
        created_at=rec["created_at"],
        last_rotated_at=rec["last_rotated_at"],
    )


@router.post(
    "/system/platform-admin/bootstrap",
    response_model=PlatformAdminBootstrapResponse,
    status_code=201,
    dependencies=[
        Depends(require_scopes("admin:write")),
        Depends(require_internal_admin_gateway),
    ],
)
async def bootstrap_platform_admin_credential(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
) -> PlatformAdminBootstrapResponse:
    """Bootstrap the canonical platform_admin credential.

    Idempotency:
      • 409 PLATFORM_ADMIN_ALREADY_EXISTS if an active credential already
        occupies the platform-admin-credential:v1 slot.
      • 201 + plaintext_key on first successful bootstrap.

    The issued credential is stored under the frostgate-internal tenant with
    the platform_admin role assigned via tenant_credential_roles.  Once issued,
    the plaintext key is never retrievable — rotation is required to replace it.

    Security invariants:
      • Requires both X-FG-Internal-Token AND platform.admin permission.
      • The credential is NOT the gateway secret — they are distinct values.
      • No direct SQL credential issuance; all writes go through CredentialAuthority.
    """
    engine = get_engine()

    # Idempotency guard: refuse if an active credential already exists.
    existing = _find_active_platform_admin_credential(engine)
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail=api_error(
                "PLATFORM_ADMIN_ALREADY_EXISTS",
                "A platform_admin credential already exists. "
                "Use /system/platform-admin/rotate to replace it.",
                action="rotate the existing credential instead of bootstrapping",
            ),
        )

    actor_id = actor_ctx.subject or _PLATFORM_ADMIN_ACTOR
    request_id = getattr(getattr(request, "state", None), "request_id", None)

    result = issue_credential(
        engine,
        tenant_id=_PLATFORM_TENANT_ID,
        credential_type=_PLATFORM_ADMIN_CREDENTIAL_TYPE,
        credential_slot=_PLATFORM_ADMIN_SLOT,
        scopes=None,  # role-based, not scope-based
        metadata={"purpose": "platform_admin_credential"},
        actor_id=actor_id,
        request_id=request_id,
        idempotency_key=_PLATFORM_ADMIN_IDEMPOTENCY_KEY,
    )

    credential_id = result.record.credential_id

    # Assign platform_admin role via the canonical assign_role path.
    # VALID_ROLE_NAMES now includes platform_admin (Defect 1 fix).
    with Session(engine) as session:
        set_tenant_context(session, _PLATFORM_TENANT_ID)
        rbac_assign_role(
            session,
            tenant_id=_PLATFORM_TENANT_ID,
            actor_key_prefix=actor_id,
            credential_id=credential_id,
            role_name="platform_admin",
        )

    log.info(
        "platform_admin credential bootstrapped",
        extra={
            "credential_id": credential_id,
            "slot": _PLATFORM_ADMIN_SLOT,
            "actor": actor_id,
            "request_id": request_id,
        },
    )

    # Emit bootstrap event to internal_platform_authority_events.
    # tenant_credential_events already received "issued" from issue_credential().
    # This second event marks the operation as a platform_admin bootstrap
    # (not a routine credential issuance) so the audit log is unambiguous.
    _emit_internal_authority_event_best_effort(
        engine,
        event_type="bootstrap_created",
        actor_id=actor_id,
        service_id="platform-admin-authority",
        target_tenant_id=_PLATFORM_TENANT_ID,
        authority_tenant_id=_PLATFORM_TENANT_ID,
        request_id=request_id,
        credential_id=credential_id,
        credential_type=_PLATFORM_ADMIN_CREDENTIAL_TYPE,
        credential_slot=_PLATFORM_ADMIN_SLOT,
        metadata={"purpose": "platform_admin_credential", "role": "platform_admin"},
    )

    return PlatformAdminBootstrapResponse(
        credential_id=credential_id,
        credential_slot=_PLATFORM_ADMIN_SLOT,
        status="bootstrapped",
        plaintext_key=result.plaintext_secret,
    )


@router.post(
    "/system/platform-admin/rotate",
    response_model=PlatformAdminRotationResponse,
    dependencies=[
        Depends(require_scopes("admin:write")),
        Depends(require_internal_admin_gateway),
    ],
)
async def rotate_platform_admin_credential(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
) -> PlatformAdminRotationResponse:
    """Rotate the canonical platform_admin credential.

    Issues a new credential generation; the old credential is marked rotated.
    The new plaintext key is returned exactly once.  Requires an active
    credential to exist (bootstrap first if not).
    """
    engine = get_engine()
    existing = _find_active_platform_admin_credential(engine)
    if existing is None:
        raise HTTPException(
            status_code=404,
            detail=api_error(
                "PLATFORM_ADMIN_NOT_FOUND",
                "No active platform_admin credential found. Bootstrap first.",
                action="call POST /admin/system/platform-admin/bootstrap",
            ),
        )

    actor_id = actor_ctx.subject or _PLATFORM_ADMIN_ACTOR
    request_id = getattr(getattr(request, "state", None), "request_id", None)

    try:
        result = rotate_credential(
            engine,
            tenant_id=_PLATFORM_TENANT_ID,
            credential_type=_PLATFORM_ADMIN_CREDENTIAL_TYPE,
            credential_slot=_PLATFORM_ADMIN_SLOT,
            actor_id=actor_id,
            request_id=request_id,
        )
    except (
        CredentialNotFoundError,
        CredentialSlotNotFoundError,
        CredentialStateError,
    ) as exc:
        raise HTTPException(
            status_code=409,
            detail=api_error("PLATFORM_ADMIN_ROTATE_CONFLICT", str(exc)),
        ) from exc

    new_credential_id = result.record.credential_id

    # Carry the platform_admin role to the new credential generation.
    with Session(engine) as session:
        set_tenant_context(session, _PLATFORM_TENANT_ID)
        rbac_assign_role(
            session,
            tenant_id=_PLATFORM_TENANT_ID,
            actor_key_prefix=actor_id,
            credential_id=new_credential_id,
            role_name="platform_admin",
        )

    # tenant_credential_events already received "rotated" from rotate_credential().
    # Emit to internal_platform_authority_events so the rotation is visible in the
    # platform-level audit trail alongside the bootstrap event.
    _emit_internal_authority_event_best_effort(
        engine,
        event_type="credential_rotated",
        actor_id=actor_id,
        service_id="platform-admin-authority",
        target_tenant_id=_PLATFORM_TENANT_ID,
        authority_tenant_id=_PLATFORM_TENANT_ID,
        request_id=request_id,
        credential_id=new_credential_id,
        credential_type=_PLATFORM_ADMIN_CREDENTIAL_TYPE,
        credential_slot=_PLATFORM_ADMIN_SLOT,
        metadata={"role": "platform_admin"},
    )

    return PlatformAdminRotationResponse(
        credential_id=new_credential_id,
        credential_slot=_PLATFORM_ADMIN_SLOT,
        action="rotated",
        plaintext_key=result.plaintext_secret,
    )


@router.post(
    "/system/platform-admin/suspend",
    response_model=PlatformAdminLifecycleResponse,
    dependencies=[
        Depends(require_scopes("admin:write")),
        Depends(require_internal_admin_gateway),
    ],
)
async def suspend_platform_admin_credential(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
) -> PlatformAdminLifecycleResponse:
    """Suspend the canonical platform_admin credential.

    Suspended credentials are rejected at validation.  Use resume to re-enable.
    This is the recommended emergency revocation path when rotation is not yet
    possible — it preserves the credential_id for audit continuity.
    """
    engine = get_engine()
    existing = _find_active_platform_admin_credential(engine)
    if existing is None:
        raise HTTPException(
            status_code=404,
            detail=api_error(
                "PLATFORM_ADMIN_NOT_FOUND",
                "No active platform_admin credential found.",
            ),
        )

    actor_id = actor_ctx.subject or _PLATFORM_ADMIN_ACTOR
    try:
        rec = suspend_credential(
            engine,
            credential_id=existing["credential_id"],
            tenant_id=_PLATFORM_TENANT_ID,
            actor_id=actor_id,
            reason="operator_suspend",
        )
    except (CredentialNotFoundError, CredentialStateError) as exc:
        raise HTTPException(
            status_code=409,
            detail=api_error("PLATFORM_ADMIN_SUSPEND_CONFLICT", str(exc)),
        ) from exc

    return PlatformAdminLifecycleResponse(
        credential_id=rec.credential_id,
        credential_slot=_PLATFORM_ADMIN_SLOT,
        action="suspended",
        credential_status=rec.status,
    )


@router.post(
    "/system/platform-admin/resume",
    response_model=PlatformAdminLifecycleResponse,
    dependencies=[
        Depends(require_scopes("admin:write")),
        Depends(require_internal_admin_gateway),
    ],
)
async def resume_platform_admin_credential(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
) -> PlatformAdminLifecycleResponse:
    """Resume a suspended canonical platform_admin credential."""
    engine = get_engine()
    # Find suspended credential (not active — it was suspended)
    with engine.connect() as conn:
        is_pg = engine.dialect.name == "postgresql"
        if is_pg:
            conn.execute(
                text("SELECT set_config('app.tenant_id', :tid, true)"),
                {"tid": _PLATFORM_TENANT_ID},
            )
        row = conn.execute(
            text(
                "SELECT credential_id FROM tenant_credentials "
                "WHERE tenant_id = :tid "
                "  AND credential_slot = :slot "
                "  AND status = 'suspended'"
            ),
            {"tid": _PLATFORM_TENANT_ID, "slot": _PLATFORM_ADMIN_SLOT},
        ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=404,
            detail=api_error(
                "PLATFORM_ADMIN_NOT_SUSPENDED",
                "No suspended platform_admin credential found to resume.",
            ),
        )

    actor_id = actor_ctx.subject or _PLATFORM_ADMIN_ACTOR
    credential_id = str(row[0])
    try:
        rec = resume_credential(
            engine,
            credential_id=credential_id,
            tenant_id=_PLATFORM_TENANT_ID,
            actor_id=actor_id,
        )
    except (CredentialNotFoundError, CredentialStateError) as exc:
        raise HTTPException(
            status_code=409,
            detail=api_error("PLATFORM_ADMIN_RESUME_CONFLICT", str(exc)),
        ) from exc

    return PlatformAdminLifecycleResponse(
        credential_id=rec.credential_id,
        credential_slot=_PLATFORM_ADMIN_SLOT,
        action="resumed",
        credential_status=rec.status,
    )


@router.post(
    "/system/platform-admin/revoke",
    response_model=PlatformAdminLifecycleResponse,
    dependencies=[
        Depends(require_scopes("admin:write")),
        Depends(require_internal_admin_gateway),
    ],
)
async def revoke_platform_admin_credential(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
) -> PlatformAdminLifecycleResponse:
    """Permanently revoke the canonical platform_admin credential.

    This action is irreversible.  A new credential must be bootstrapped to
    recover platform_admin authority.  Use suspend/resume for temporary
    disablement.
    """
    engine = get_engine()
    existing = _find_active_platform_admin_credential(engine)
    if existing is None:
        raise HTTPException(
            status_code=404,
            detail=api_error(
                "PLATFORM_ADMIN_NOT_FOUND",
                "No active platform_admin credential found.",
            ),
        )

    actor_id = actor_ctx.subject or _PLATFORM_ADMIN_ACTOR
    request_id = getattr(getattr(request, "state", None), "request_id", None)
    try:
        rec = revoke_credential(
            engine,
            credential_id=existing["credential_id"],
            tenant_id=_PLATFORM_TENANT_ID,
            actor_id=actor_id,
            reason="operator_revoke",
            request_id=request_id,
        )
    except (CredentialNotFoundError, CredentialStateError) as exc:
        raise HTTPException(
            status_code=409,
            detail=api_error("PLATFORM_ADMIN_REVOKE_CONFLICT", str(exc)),
        ) from exc

    # tenant_credential_events already received "revoked" from revoke_credential().
    # Emit to internal_platform_authority_events for platform-level audit continuity.
    _emit_internal_authority_event_best_effort(
        engine,
        event_type="credential_revoked",
        actor_id=actor_id,
        service_id="platform-admin-authority",
        target_tenant_id=_PLATFORM_TENANT_ID,
        authority_tenant_id=_PLATFORM_TENANT_ID,
        request_id=request_id,
        credential_id=rec.credential_id,
        credential_type=_PLATFORM_ADMIN_CREDENTIAL_TYPE,
        credential_slot=_PLATFORM_ADMIN_SLOT,
        metadata={"reason": "operator_revoke", "role": "platform_admin"},
    )

    return PlatformAdminLifecycleResponse(
        credential_id=rec.credential_id,
        credential_slot=_PLATFORM_ADMIN_SLOT,
        action="revoked",
        credential_status=rec.status,
    )


@router.get(
    "/system/health",
    response_model=SystemHealthResponse,
    dependencies=[Depends(require_scopes("admin:read"))],
)
async def get_system_health() -> SystemHealthResponse:
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

        alert_manager = get_alert_manager()
        alert_stats = alert_manager.get_stats()
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
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
    period: Optional[str] = Query(None, description="Period in YYYY-MM-DD format"),
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


@router.post(
    "/config/changes/{change_id}/revert",
    response_model=ConfigMutationRevertResponse,
    dependencies=[Depends(require_scopes("admin:write"))],
)
async def revert_config_change(
    change_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
) -> ConfigMutationRevertResponse:
    """Revert a previously recorded config mutation."""
    _require_elevated_config_scope(request)

    try:
        from api.tenant_usage import SubscriptionTier, get_usage_tracker
    except ImportError:
        raise HTTPException(
            status_code=501, detail="Tenant usage tracking not available"
        )

    path, change = _load_config_change(change_id)
    tenant_id = str(change.get("tenant_id") or "")
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)

    tracker = get_usage_tracker()
    field = str(change.get("field") or "")

    if bool(change.get("reverted", False)):
        return ConfigMutationRevertResponse(
            success=True,
            already_reverted=True,
            change_id=str(change.get("change_id") or change_id),
            tenant_id=tenant_id,
            restored_field=field,
            restored_value=change.get("before"),
        )

    current = _state_for_field(tracker=tracker, tenant_id=tenant_id, field=field)
    expected_current = change.get("after")
    if field == "tier":
        current = _coerce_tier_value(current)
        expected_current = _coerce_tier_value(expected_current)
    if current != expected_current:
        raise HTTPException(
            status_code=409,
            detail="Config has changed since snapshot; revert rejected",
        )

    restored = change.get("before")
    if field == "custom_quota":
        if restored is None:
            tracker._tenant_custom_quotas.pop(tenant_id, None)
        else:
            tracker.set_custom_quota(tenant_id, int(restored))
    elif field == "tier":
        fallback = (
            SubscriptionTier.FREE
            if restored is None
            else SubscriptionTier(str(restored).lower())
        )
        tracker.set_tenant_tier(tenant_id, fallback)
        restored = fallback.value
    else:
        raise HTTPException(status_code=400, detail="Unsupported config change field")

    new_hash_source = {
        "tenant_id": tenant_id,
        "field": field,
        "value": restored,
        "at": datetime.now(timezone.utc).isoformat(),
    }
    new_hash = _sha256_json(new_hash_source)
    prev_hash = str(change.get("snapshot_hash") or "")

    change["reverted"] = True
    change["reverted_at"] = datetime.now(timezone.utc).isoformat()
    change["reverted_value"] = restored
    change["revert_prev_hash"] = prev_hash
    change["revert_new_hash"] = new_hash
    change["snapshot_hash"] = _sha256_json(
        {k: v for k, v in change.items() if k != "snapshot_hash"}
    )
    path.write_text(
        json.dumps(change, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    try:
        path.chmod(0o600)
    except Exception:
        pass

    audit_admin_action(
        action="config_revert",
        tenant_id=tenant_id,
        request=request,
        details={
            "change_id": change_id,
            "field": field,
            "restored": restored,
            "prev_hash": prev_hash,
            "new_hash": new_hash,
        },
    )
    return ConfigMutationRevertResponse(
        success=True,
        already_reverted=False,
        change_id=change_id,
        tenant_id=tenant_id,
        restored_field=field,
        restored_value=restored,
    )


__all__ = ["router"]
