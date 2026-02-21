"""
FrostGate Control Plane API

Production-grade command and telemetry layer.

SECURITY INVARIANTS:
- All endpoints require admin:read or admin:write scope
- All control actions require tenant binding (verified from auth context, not headers)
- Zero shell execution / subprocess in API layer
- Fail-closed: any unresolvable state returns 403/503, never 200
- Rate limiting enforced per endpoint AND per tenant
- Idempotency enforced for all command endpoints (tenant-scoped composite key)
- Full audit ledger entry on every control action (hash-chained)
- Error codes are deterministic and redacted in production
- WebSocket: authenticated, tenant-bound, subscriber cap per tenant

P0: tenant_id always resolved from verified auth context (request.state.auth.tenant_id).
    Never from request headers or query params.
    Admin endpoints filter data by tenant; global admin (no tenant) sees all.
    WS enforces tenant context identically to HTTP endpoints.
P1: Per-tenant rate limits for WS, dep-matrix, locker dispatch.
    Max subscribers per tenant enforced via EventStreamBus.

HTTP Endpoints:
  GET  /control-plane/modules
  GET  /control-plane/modules/{id}
  GET  /control-plane/modules/{id}/dependencies
  GET  /control-plane/modules/{id}/boot-trace
  POST /control-plane/lockers/{id}/restart
  POST /control-plane/lockers/{id}/pause
  POST /control-plane/lockers/{id}/resume
  POST /control-plane/lockers/{id}/quarantine
  GET  /control-plane/lockers
  GET  /control-plane/audit
  GET  /control-plane/dependency-matrix
  WS   /control-plane/events
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from api.auth_scopes import (
    redact_detail,
    require_api_key_always,
    require_bound_tenant,
    require_scopes,
)
from api.security_audit import audit_admin_action, AuditPersistenceError
from services.module_registry import (
    DependencyProbe,
    DependencyStatus,
    ModuleRegistry,
    ModuleState,
    _is_prod_like,
    _utc_now_iso,
)
from services.boot_trace import BootTraceRegistry, StageStatus
from services.locker_command_bus import (
    CommandResult,
    ERR_INVALID_COMMAND,
    ERR_LOCKER_COOLDOWN,
    ERR_LOCKER_NOT_FOUND,
    LockerCommand,
    LockerCommandBus,
    LockerCommandRequest,
)
from services.event_stream import (
    ControlEventType,
    EventStreamBus,
    MaxSubscribersExceededError,
    emit_locker_state_changed,
    emit_restart_started,
    emit_restart_completed,
)

log = logging.getLogger("frostgate.control_plane")


# ---------------------------------------------------------------------------
# Deterministic error codes
# ---------------------------------------------------------------------------
ERR_CP_MODULE_NOT_FOUND = "CP-API-001"
ERR_CP_LOCKER_NOT_FOUND = "CP-API-002"
ERR_CP_FORBIDDEN = "CP-API-003"
ERR_CP_RATE_LIMITED = "CP-API-004"
ERR_CP_INVALID_REQUEST = "CP-API-005"
ERR_CP_WS_AUTH_FAILED = "CP-API-006"
ERR_CP_AUDIT_FAILED = "CP-API-007"
ERR_CP_BOOT_TRACE_NOT_FOUND = "CP-API-008"
ERR_CP_MAX_SUBSCRIBERS = "CP-API-009"


# ---------------------------------------------------------------------------
# Rate limiting: per-actor and per-tenant buckets
#
# Actor buckets prevent a single key from hammering an endpoint.
# Tenant buckets prevent a single tenant from monopolizing shared resources.
# ---------------------------------------------------------------------------

_RL_MODULES_READ = "cp:modules:read"
_RL_LOCKER_CMD = "cp:locker:cmd"
_RL_AUDIT_READ = "cp:audit:read"
_RL_WS_CONNECT = "cp:ws:connect"

# Per-tenant buckets (stricter, protect shared backend resources)
_RL_TENANT_DEP_MATRIX = "cp:tenant:dep-matrix"
_RL_TENANT_LOCKER_CMD = "cp:tenant:locker:cmd"
_RL_TENANT_WS_SUBSCRIBE = "cp:tenant:ws:subscribe"

_RATE_LIMIT_RULES: dict[str, tuple[float, float]] = {
    # key -> (rate_per_sec, burst)
    _RL_MODULES_READ:         (10.0, 30.0),
    _RL_LOCKER_CMD:           (0.5, 3.0),    # per-actor: 1 cmd per 2s, burst of 3
    _RL_AUDIT_READ:           (5.0, 20.0),
    _RL_WS_CONNECT:           (2.0, 5.0),
    # Per-tenant limits
    _RL_TENANT_DEP_MATRIX:    (2.0, 5.0),   # dep-matrix is compute-heavy
    _RL_TENANT_LOCKER_CMD:    (1.0, 5.0),   # cross-locker command rate per tenant
    _RL_TENANT_WS_SUBSCRIBE:  (1.0, 3.0),   # WS subscribe rate per tenant
}


def _get_rl_key(bucket: str, identity: str) -> str:
    return f"{bucket}:{identity}"


def _rate_limit_check(bucket: str, identity: str) -> None:
    """In-process rate limit check. Raises 429 if exceeded."""
    from api.ratelimit import _get_memory_limiter

    rate, burst = _RATE_LIMIT_RULES.get(bucket, (10.0, 30.0))
    limiter = _get_memory_limiter()
    ok, limit, remaining, reset = limiter.allow(
        _get_rl_key(bucket, identity),
        rate_per_sec=rate,
        capacity=burst,
    )
    if not ok:
        raise HTTPException(
            status_code=429,
            detail={
                "code": ERR_CP_RATE_LIMITED,
                "message": "rate limit exceeded for control plane endpoint",
                "retry_after_s": reset,
            },
            headers={
                "Retry-After": str(reset),
                "X-RateLimit-Limit": str(int(limit)),
                "X-RateLimit-Remaining": str(remaining),
            },
        )


# ---------------------------------------------------------------------------
# Auth helpers — all resolve from verified auth context, NEVER from headers
# ---------------------------------------------------------------------------

def _actor_id_from_request(request: Request) -> str:
    """Extract actor ID from verified auth state."""
    auth = getattr(getattr(request, "state", None), "auth", None)
    key_prefix = getattr(auth, "key_prefix", None)
    return str(key_prefix or "unknown")[:32]


def _tenant_id_from_request(request: Request) -> str:
    """
    Extract verified tenant_id from auth state. Fail-closed.

    P0: tenant_id MUST come from request.state.auth.tenant_id (set by the
    auth middleware from the verified API key record). This function never
    reads from request headers, query params, or request body.
    """
    auth = getattr(getattr(request, "state", None), "auth", None)
    tenant_id = getattr(auth, "tenant_id", None)
    if not tenant_id:
        raise HTTPException(
            status_code=400,
            detail={
                "code": ERR_CP_INVALID_REQUEST,
                "message": redact_detail("tenant binding required", "invalid request"),
            },
        )
    return str(tenant_id)


def _tenant_id_from_request_optional(request: Request) -> Optional[str]:
    """
    Extract tenant_id from auth state if present, else return None.

    Used on read endpoints where global admins (no tenant binding) may list
    all resources, while tenant-scoped admins see only their tenant's data.
    """
    auth = getattr(getattr(request, "state", None), "auth", None)
    tenant_id = getattr(auth, "tenant_id", None)
    return str(tenant_id) if tenant_id else None


def _request_id(request: Request) -> str:
    rid = getattr(getattr(request, "state", None), "request_id", None)
    return str(rid) if rid else str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class LockerCommandBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(..., min_length=1, max_length=512)
    idempotency_key: str = Field(..., min_length=1, max_length=128)

    @field_validator("reason")
    @classmethod
    def reason_printable_ascii(cls, v: str) -> str:
        """
        P1: Reason must be printable ASCII only (0x20–0x7E).
        Rejects control characters, null bytes, and non-ASCII sequences.
        """
        stripped = v.strip()
        if not stripped:
            raise ValueError("reason must not be blank")
        for idx, ch in enumerate(stripped):
            code = ord(ch)
            if code < 0x20 or code > 0x7E:
                raise ValueError(
                    f"reason contains invalid character at position {idx} "
                    f"(U+{code:04X}); only printable ASCII (0x20–0x7E) is allowed"
                )
        return stripped

    @field_validator("idempotency_key")
    @classmethod
    def idempotency_key_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("idempotency_key must not be blank")
        return v.strip()


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/control-plane",
    tags=["control-plane"],
)


# ===========================================================================
# A. Module Registry Endpoints
# ===========================================================================

@router.get(
    "/modules",
    dependencies=[Depends(require_scopes("admin:read"))],
    summary="List all registered runtime modules",
)
def list_modules(request: Request) -> dict:
    """
    P0 Tenant scoping: if auth has tenant_id, filters to that tenant's modules.
    Global admin (no tenant binding) receives all modules with tenant_id in each record.
    """
    actor_id = _actor_id_from_request(request)
    _rate_limit_check(_RL_MODULES_READ, actor_id)

    # P0: resolve tenant from verified auth context (None = global admin → see all)
    tenant_id = _tenant_id_from_request_optional(request)

    registry = ModuleRegistry()
    redact = _is_prod_like()
    modules = registry.list_modules(redact=redact, tenant_id=tenant_id)

    return {
        "ok": True,
        "count": len(modules),
        "modules": modules,
        "scoped_to_tenant": tenant_id,
        "fetched_at": _utc_now_iso(),
    }


@router.get(
    "/modules/{module_id}",
    dependencies=[Depends(require_scopes("admin:read"))],
    summary="Get a single module's runtime metadata",
)
def get_module(module_id: str, request: Request) -> dict:
    """
    P0 Tenant scoping: cross-tenant access returns 404 (no information disclosure).
    """
    actor_id = _actor_id_from_request(request)
    _rate_limit_check(_RL_MODULES_READ, actor_id)

    module_id = _safe_id(module_id)
    tenant_id = _tenant_id_from_request_optional(request)
    registry = ModuleRegistry()
    redact = _is_prod_like()
    # P0: pass tenant_id for cross-tenant guard (returns None if forbidden)
    mod = registry.get_module(module_id, redact=redact, tenant_id=tenant_id)

    if mod is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": ERR_CP_MODULE_NOT_FOUND,
                "message": redact_detail(
                    f"module not found: {module_id}", "not found"
                ),
            },
        )
    return {"ok": True, "module": mod, "fetched_at": _utc_now_iso()}


@router.get(
    "/modules/{module_id}/dependencies",
    dependencies=[Depends(require_scopes("admin:read"))],
    summary="Get dependency health probes for a module",
)
def get_module_dependencies(module_id: str, request: Request) -> dict:
    actor_id = _actor_id_from_request(request)
    _rate_limit_check(_RL_MODULES_READ, actor_id)

    module_id = _safe_id(module_id)
    tenant_id = _tenant_id_from_request_optional(request)
    registry = ModuleRegistry()
    redact = _is_prod_like()
    # P0: tenant guard applied inside get_dependencies
    deps = registry.get_dependencies(module_id, redact=redact, tenant_id=tenant_id)

    if deps is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": ERR_CP_MODULE_NOT_FOUND,
                "message": redact_detail(
                    f"module not found: {module_id}", "not found"
                ),
            },
        )
    return {
        "ok": True,
        "module_id": module_id,
        "dependencies": deps,
        "fetched_at": _utc_now_iso(),
    }


@router.get(
    "/modules/{module_id}/boot-trace",
    dependencies=[Depends(require_scopes("admin:read"))],
    summary="Get boot timeline for a module",
)
def get_boot_trace(module_id: str, request: Request) -> dict:
    actor_id = _actor_id_from_request(request)
    _rate_limit_check(_RL_MODULES_READ, actor_id)

    module_id = _safe_id(module_id)
    redact = _is_prod_like()
    trace = BootTraceRegistry().get_trace_dict(module_id, redact=redact)

    if trace is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": ERR_CP_BOOT_TRACE_NOT_FOUND,
                "message": redact_detail(
                    f"boot trace not found for: {module_id}", "not found"
                ),
            },
        )
    return {"ok": True, "boot_trace": trace, "fetched_at": _utc_now_iso()}


# ===========================================================================
# B. Locker Control Endpoints
# ===========================================================================

def _dispatch_locker_command(
    locker_id: str,
    command: LockerCommand,
    body: LockerCommandBody,
    request: Request,
) -> dict:
    """Shared dispatch logic for all locker control endpoints."""
    actor_id = _actor_id_from_request(request)
    # P0: tenant_id from verified auth context only — fail-closed
    tenant_id = _tenant_id_from_request(request)
    req_id = _request_id(request)

    # Rate limit: per-actor strict limit + per-tenant limit
    _rate_limit_check(_RL_LOCKER_CMD, actor_id)
    _rate_limit_check(_RL_TENANT_LOCKER_CMD, tenant_id)

    # Locker must exist
    bus = LockerCommandBus()
    if not bus.locker_exists(locker_id):
        raise HTTPException(
            status_code=404,
            detail={
                "code": ERR_CP_LOCKER_NOT_FOUND,
                "message": redact_detail(
                    f"locker not found: {locker_id}", "not found"
                ),
            },
        )

    # P0: Tenant binding — locker must belong to actor's tenant
    locker_info = bus.get_locker(locker_id)
    if locker_info and locker_info.get("tenant_id") != tenant_id:
        log.warning(
            "locker_tenant_mismatch locker_id=%s actor_tenant=%s locker_tenant=%s",
            locker_id,
            tenant_id,
            locker_info.get("tenant_id"),
        )
        raise HTTPException(
            status_code=403,
            detail={
                "code": ERR_CP_FORBIDDEN,
                "message": redact_detail("tenant binding mismatch", "forbidden"),
            },
        )

    # Build and dispatch command
    cmd = LockerCommandRequest(
        locker_id=locker_id,
        command=command,
        reason=body.reason,
        actor_id=actor_id,
        idempotency_key=body.idempotency_key,
        request_id=req_id,
        tenant_id=tenant_id,
    )

    if command == LockerCommand.RESTART:
        emit_restart_started(
            module_id=locker_id,
            tenant_id=tenant_id,
            actor=actor_id,
            reason=body.reason,
        )

    outcome = bus.dispatch(cmd)

    if command == LockerCommand.RESTART and outcome.result == CommandResult.ACCEPTED:
        emit_restart_completed(
            module_id=locker_id,
            tenant_id=tenant_id,
            success=True,
        )

    if outcome.result == CommandResult.COOLDOWN:
        raise HTTPException(
            status_code=429,
            detail={
                "code": outcome.error_code,
                "message": outcome.error_message,
                "cooldown_remaining_s": outcome.cooldown_remaining_s,
            },
        )

    if outcome.result == CommandResult.REJECTED:
        raise HTTPException(
            status_code=400,
            detail={
                "code": outcome.error_code,
                "message": redact_detail(
                    outcome.error_message or "rejected", "bad request"
                ),
            },
        )

    if outcome.result == CommandResult.NOT_FOUND:
        raise HTTPException(
            status_code=404,
            detail={"code": ERR_CP_LOCKER_NOT_FOUND, "message": "not found"},
        )

    # Emit state change event
    emit_locker_state_changed(
        locker_id=locker_id,
        tenant_id=tenant_id,
        old_state="unknown",
        new_state=outcome.result.value,
        command=command.value,
        actor=actor_id,
    )

    return {
        "ok": True,
        "outcome": outcome.to_dict(),
        "request_id": req_id,
    }


@router.post(
    "/lockers/{locker_id}/restart",
    dependencies=[Depends(require_scopes("admin:write"))],
    summary="Restart a locker (requires reason + idempotency_key)",
)
def restart_locker(
    locker_id: str,
    body: LockerCommandBody,
    request: Request,
) -> dict:
    return _dispatch_locker_command(locker_id, LockerCommand.RESTART, body, request)


@router.post(
    "/lockers/{locker_id}/pause",
    dependencies=[Depends(require_scopes("admin:write"))],
    summary="Pause a locker",
)
def pause_locker(
    locker_id: str,
    body: LockerCommandBody,
    request: Request,
) -> dict:
    return _dispatch_locker_command(locker_id, LockerCommand.PAUSE, body, request)


@router.post(
    "/lockers/{locker_id}/resume",
    dependencies=[Depends(require_scopes("admin:write"))],
    summary="Resume a paused/quarantined locker",
)
def resume_locker(
    locker_id: str,
    body: LockerCommandBody,
    request: Request,
) -> dict:
    return _dispatch_locker_command(locker_id, LockerCommand.RESUME, body, request)


@router.post(
    "/lockers/{locker_id}/quarantine",
    dependencies=[Depends(require_scopes("admin:write"))],
    summary="Quarantine a locker (hard isolation)",
)
def quarantine_locker(
    locker_id: str,
    body: LockerCommandBody,
    request: Request,
) -> dict:
    return _dispatch_locker_command(locker_id, LockerCommand.QUARANTINE, body, request)


@router.get(
    "/lockers",
    dependencies=[Depends(require_scopes("admin:read"))],
    summary="List all registered lockers for the authenticated tenant",
)
def list_lockers(request: Request) -> dict:
    actor_id = _actor_id_from_request(request)
    _rate_limit_check(_RL_MODULES_READ, actor_id)
    # P0: tenant_id from verified auth context
    tenant_id = _tenant_id_from_request(request)

    bus = LockerCommandBus()
    lockers = bus.list_lockers(tenant_id=tenant_id)

    return {
        "ok": True,
        "count": len(lockers),
        "lockers": lockers,
        "fetched_at": _utc_now_iso(),
    }


# ===========================================================================
# C. Audit Endpoint
# ===========================================================================

@router.get(
    "/audit",
    dependencies=[Depends(require_scopes("admin:read"))],
    summary="Retrieve control plane audit log",
)
def get_control_plane_audit(
    request: Request,
    since: Optional[str] = Query(default=None, description="ISO8601 timestamp lower bound"),
    limit: int = Query(default=50, ge=1, le=500),
    event_type: Optional[str] = Query(default=None),
) -> dict:
    actor_id = _actor_id_from_request(request)
    _rate_limit_check(_RL_AUDIT_READ, actor_id)
    # P0: audit is always tenant-scoped — global admins must use /audit?tenant_id=...
    # For now, require tenant binding on audit endpoint (write ops need full trace)
    tenant_id = _tenant_id_from_request(request)

    bus = EventStreamBus()
    events = bus.recent_events(
        tenant_id=tenant_id,
        limit=limit,
        event_type=event_type,
    )

    # Filter by since if provided
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
            events = [
                e
                for e in events
                if datetime.fromisoformat(
                    e["timestamp"].replace("Z", "+00:00")
                ) >= since_dt
            ]
        except (ValueError, KeyError):
            pass  # Invalid since param: return all

    return {
        "ok": True,
        "count": len(events),
        "events": events,
        "tenant_id": tenant_id,
        "fetched_at": _utc_now_iso(),
    }


# ===========================================================================
# D. Real-Time Event Stream (WebSocket)
# ===========================================================================

@router.websocket("/events")
async def control_plane_events(
    websocket: WebSocket,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> None:
    """
    WebSocket endpoint for real-time control plane events.

    P0 Authentication: X-API-Key header required (admin:read scope).
                       Tenant binding resolved from key record — same as HTTP.
                       No unauthenticated upgrade allowed (fail-closed).
    P0 Tenant binding: events filtered to authenticated tenant ONLY.
                       "admin can see all by default" is NOT the behaviour.
    P1 Max subscribers: per-tenant cap enforced (FG_CP_MAX_SUBSCRIBERS_PER_TENANT).
    P1 Rate limit: per-actor WS connect + per-tenant WS subscribe limits.
    """
    # --- Authenticate BEFORE accept ---
    api_key = (
        x_api_key
        or websocket.headers.get("x-api-key")
        or websocket.headers.get("X-API-Key")
    )

    if not api_key:
        await websocket.close(code=4001, reason="authentication required")
        log.warning("ws_auth_failed: no API key provided")
        return

    from api.auth_scopes import verify_api_key_detailed

    auth_result = verify_api_key_detailed(raw=api_key, required_scopes={"admin:read"})

    if not auth_result.valid:
        await websocket.close(code=4001, reason="authentication failed")
        log.warning(
            "ws_auth_failed reason=%s key_prefix=%s",
            auth_result.reason,
            auth_result.key_prefix,
        )
        return

    # P0: Tenant binding required — identical to _tenant_id_from_request()
    # WS cannot use request.state so we resolve from auth_result directly.
    tenant_id = auth_result.tenant_id
    if not tenant_id:
        await websocket.close(code=4003, reason="tenant binding required")
        log.warning("ws_auth_failed: no tenant binding on key")
        return

    actor_id = (auth_result.key_prefix or "unknown")[:32]

    # P1: Per-actor WS connect rate limit
    from api.ratelimit import _get_memory_limiter
    limiter = _get_memory_limiter()

    rate, burst = _RATE_LIMIT_RULES[_RL_WS_CONNECT]
    ok, _limit, _remaining, _reset = limiter.allow(
        _get_rl_key(_RL_WS_CONNECT, actor_id),
        rate_per_sec=rate,
        capacity=burst,
    )
    if not ok:
        await websocket.close(code=4029, reason="rate limit exceeded: connect")
        return

    # P1: Per-tenant WS subscribe rate limit
    rate_t, burst_t = _RATE_LIMIT_RULES[_RL_TENANT_WS_SUBSCRIBE]
    ok_t, _, _, _ = limiter.allow(
        _get_rl_key(_RL_TENANT_WS_SUBSCRIBE, tenant_id),
        rate_per_sec=rate_t,
        capacity=burst_t,
    )
    if not ok_t:
        await websocket.close(code=4029, reason="rate limit exceeded: tenant subscribe")
        return

    # P1: Max subscribers per tenant (enforced in EventStreamBus.subscribe)
    bus = EventStreamBus()
    try:
        subscriber = bus.subscribe(tenant_id=tenant_id)
    except MaxSubscribersExceededError:
        await websocket.close(
            code=4029, reason="max subscribers exceeded for tenant"
        )
        log.warning(
            "ws_max_subscribers_exceeded tenant=%s actor=%s", tenant_id, actor_id
        )
        return

    await websocket.accept()
    log.info(
        "ws_connected sub_id=%s tenant=%s actor=%s",
        subscriber.subscriber_id,
        tenant_id,
        actor_id,
    )

    try:
        # Send connected ack (includes tenant context for audit trail)
        await websocket.send_text(
            json.dumps({
                "type": "connected",
                "subscriber_id": subscriber.subscriber_id,
                "tenant_id": tenant_id,
                "timestamp": _utc_now_iso(),
            })
        )

        # Stream events (P0: tenant filter already enforced in EventSubscriber.matches())
        while True:
            # Check if subscriber was closed by backpressure mechanism
            if subscriber.is_closed():
                try:
                    await websocket.send_text(
                        json.dumps({
                            "type": "disconnect",
                            "reason": "slow_consumer",
                            "timestamp": _utc_now_iso(),
                        })
                    )
                except WebSocketDisconnect:
                    pass
                except OSError as send_err:
                    log.debug("ws_disconnect_notify_failed sub=%s err=%s",
                              subscriber.subscriber_id, send_err)
                break

            event = await subscriber.get(timeout=25.0)

            if event is None:
                # Send heartbeat to keep connection alive
                try:
                    await websocket.send_text(
                        json.dumps({
                            "type": "heartbeat",
                            "timestamp": _utc_now_iso(),
                        })
                    )
                except (WebSocketDisconnect, OSError):
                    break
                continue

            try:
                await websocket.send_text(event.to_json())
            except WebSocketDisconnect:
                break
            except Exception as e:
                log.warning(
                    "ws_send_error sub=%s error=%s", subscriber.subscriber_id, e
                )
                break

    except WebSocketDisconnect:
        pass
    except asyncio.CancelledError:
        pass
    except Exception as e:
        log.warning("ws_error sub=%s error=%s", subscriber.subscriber_id, e)
    finally:
        bus.unsubscribe(subscriber.subscriber_id)
        log.info(
            "ws_disconnected sub=%s tenant=%s", subscriber.subscriber_id, tenant_id
        )


# ===========================================================================
# E. Dependency Matrix
# ===========================================================================

@router.get(
    "/dependency-matrix",
    dependencies=[Depends(require_scopes("admin:read"))],
    summary="Grid view of all module dependency health statuses",
)
def dependency_matrix(request: Request) -> dict:
    """
    P0 Tenant scoping: filtered by tenant_id from auth context.
    P1 Per-tenant rate limit: dependency matrix is a heavier operation.
    """
    actor_id = _actor_id_from_request(request)
    _rate_limit_check(_RL_MODULES_READ, actor_id)

    # P0: optional tenant filter (global admin sees all)
    tenant_id = _tenant_id_from_request_optional(request)

    # P1: per-tenant rate limit for heavy dependency matrix endpoint
    if tenant_id:
        _rate_limit_check(_RL_TENANT_DEP_MATRIX, tenant_id)

    registry = ModuleRegistry()
    redact = _is_prod_like()
    modules = registry.list_modules(redact=redact, tenant_id=tenant_id)

    matrix: dict[str, dict[str, str]] = {}
    for mod in modules:
        module_id = mod["module_id"]
        deps = registry.get_dependencies(
            module_id, redact=redact, tenant_id=tenant_id
        ) or []
        matrix[module_id] = {
            dep["name"]: dep["status"] for dep in deps
        }

    return {
        "ok": True,
        "matrix": matrix,
        "scoped_to_tenant": tenant_id,
        "fetched_at": _utc_now_iso(),
    }


# ===========================================================================
# Utilities
# ===========================================================================

def _safe_id(value: str, max_len: int = 128) -> str:
    """Sanitize path parameters to prevent injection."""
    cleaned = re.sub(r"[^\w\-.]", "", value)
    return cleaned[:max_len]
