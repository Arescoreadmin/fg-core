"""
api/control_plane.py — FrostGate Control Plane API.

Endpoints:
  GET  /control-plane/modules
  GET  /control-plane/modules/{id}/dependencies
  GET  /control-plane/modules/{id}/boot-trace
  POST /control-plane/lockers/{id}/restart
  POST /control-plane/lockers/{id}/pause
  POST /control-plane/lockers/{id}/resume
  POST /control-plane/lockers/{id}/quarantine
  GET  /control-plane/audit
  WS   /control-plane/events

Security invariants (all enforced, no bypass):
  - All HTTP endpoints require explicit scope dependency.
  - All control (write) endpoints require control-plane:admin scope.
  - All read endpoints require control-plane:read scope.
  - WebSocket auth enforced identically to HTTP (no weaker path).
  - tenant_id ALWAYS derived from auth context — never from request headers.
  - Global admin (tenant_id=None in auth context) sees all tenants.
  - Tenant admin sees only their own tenant scope.
  - Tenant admin cannot subscribe to another tenant's events.
  - Rate limiting applied per endpoint.
  - Locker commands enforced with cooldown + idempotency.
  - Every control action emits an audit entry.
  - No subprocess. No shell. Fail-closed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from pydantic import BaseModel, ConfigDict, Field

from api.auth_scopes import (
    require_scopes,
    is_prod_like_env,
)
from api.ratelimit import MemoryRateLimiter
from services.boot_trace import get_trace, BOOT_STAGE_ORDER
from services.event_stream import (
    get_event_bus,
    make_event,
)
from services.locker_command_bus import (
    get_command_bus,
    ERR_UNKNOWN_LOCKER,
    ERR_QUARANTINE_LOCKED,
    ERR_COOLDOWN_ACTIVE,
    ERR_REASON_REQUIRED,
    ERR_REASON_TOO_LONG,
    ERR_REASON_INVALID_CHARS,
)
from services.module_registry import get_registry

log = logging.getLogger("frostgate.control_plane")

router = APIRouter(tags=["control-plane"])

# ---------------------------------------------------------------------------
# Rate limiting (per-endpoint token bucket, in-memory)
# ---------------------------------------------------------------------------

_rl = MemoryRateLimiter()

# Rates: (rate_per_sec, burst_capacity)
_RL_READ = (5.0, 30)  # module list / dependencies / boot trace
_RL_CMD = (0.5, 5)  # locker commands (very conservative)
_RL_WS = (2.0, 10)  # WS connect attempts
_RL_AUDIT = (2.0, 20)  # audit reads


def _rl_key(tenant_id: Optional[str], endpoint: str) -> str:
    t = tenant_id or "global"
    return f"cp:{endpoint}:{t}"


def _enforce_rate_limit(
    key: str,
    rate: float,
    burst: int,
    *,
    error_code: str = "CP_RATE_LIMIT_EXCEEDED",
) -> None:
    ok, limit, remaining, reset = _rl.allow(key, rate, burst)
    if not ok:
        raise HTTPException(
            status_code=429,
            detail={
                "error": {
                    "code": error_code,
                    "message": "Rate limit exceeded",
                    "retry_after_seconds": reset,
                }
            },
            headers={
                "Retry-After": str(reset),
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": str(remaining),
            },
        )


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------


def _get_auth(request: Request) -> Any:
    return getattr(getattr(request, "state", None), "auth", None)


def _tenant_from_auth(request: Request) -> Optional[str]:
    auth = _get_auth(request)
    if auth is None:
        return None
    tid = getattr(auth, "tenant_id", None)
    return str(tid).strip() if tid else None


def _is_global_admin(request: Request) -> bool:
    """
    A key with no tenant binding (tenant_id=None) is treated as a global platform admin.
    """
    return _tenant_from_auth(request) is None


def _actor_id(request: Request) -> str:
    auth = _get_auth(request)
    prefix = getattr(auth, "key_prefix", None)
    return str(prefix)[:32] if prefix else "unknown"


# ---------------------------------------------------------------------------
# Audit emission helper
# ---------------------------------------------------------------------------


def _emit_audit(
    *,
    audit_type: str,
    actor: str,
    target_module: str,
    target_id: str,
    reason: str,
    request_id: str,
    tenant_id: Optional[str],
    result: str,
    config_hash: str = "",
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Emit a structured audit log entry and broadcast as a control event.

    This is append-only — never mutable.
    """
    entry = {
        "audit_type": audit_type,
        "actor": actor,
        "target_module": target_module,
        "target_id": target_id,
        "reason": reason,
        "request_id": request_id,
        "tenant_id": tenant_id or "global",
        "result": result,
        "config_hash": config_hash,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **(extra or {}),
    }
    log.info(
        "control_plane.audit audit_type=%s actor=%s target=%s result=%s",
        audit_type,
        actor,
        target_id,
        result,
    )
    # Broadcast to event bus
    try:
        bus = get_event_bus()
        ev = make_event(
            "locker_state_changed"
            if "locker" in audit_type.lower()
            else "config_changed",
            module_id=target_module,
            tenant_id=tenant_id or "global",
            payload=entry,
        )
        bus.publish(ev)
    except Exception as exc:
        log.warning("control_plane.audit_event_broadcast_failed error=%s", exc)


def _request_id(request: Request) -> str:
    rid = getattr(getattr(request, "state", None), "request_id", None)
    if rid:
        return str(rid)
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class LockerCommandRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(..., min_length=4, max_length=512)
    idempotency_key: str = Field(..., min_length=1, max_length=128)


# ---------------------------------------------------------------------------
# A. Module Registry Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/control-plane/modules",
    dependencies=[Depends(require_scopes("control-plane:read"))],
    summary="List all registered runtime modules",
)
def list_modules(request: Request) -> Dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    is_global = _is_global_admin(request)
    redact = is_prod_like_env()

    _enforce_rate_limit(
        _rl_key(tenant_id, "modules"),
        *_RL_READ,
        error_code="CP_MODULES_RATE_LIMIT",
    )

    registry = get_registry()
    modules = registry.snapshot_for_api(
        tenant_id=tenant_id,
        is_global_admin=is_global,
        redact=redact,
    )
    return {
        "modules": modules,
        "total": len(modules),
        "tenant_scope": tenant_id or "global",
        "is_global_admin": is_global,
    }


@router.get(
    "/control-plane/modules/{module_id}/dependencies",
    dependencies=[Depends(require_scopes("control-plane:read"))],
    summary="Get dependency health matrix for a module",
)
def get_module_dependencies(
    module_id: str,
    request: Request,
) -> Dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    is_global = _is_global_admin(request)

    _enforce_rate_limit(
        _rl_key(tenant_id, "deps"),
        *_RL_READ,
        error_code="CP_DEPS_RATE_LIMIT",
    )

    registry = get_registry()
    rec = registry.get(module_id)

    if rec is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": {"code": "CP_MODULE_NOT_FOUND", "message": "Module not found"}
            },
        )

    # Tenant binding check
    if not is_global and tenant_id:
        if rec.tenant_id is not None and rec.tenant_id != tenant_id:
            # Return same as not-found to prevent enumeration
            raise HTTPException(
                status_code=404,
                detail={
                    "error": {
                        "code": "CP_MODULE_NOT_FOUND",
                        "message": "Module not found",
                    }
                },
            )

    deps = registry.get_dependencies(module_id) or {}
    return {
        "module_id": module_id,
        "dependencies": {name: dep.to_dict() for name, dep in deps.items()},
        "dependency_count": len(deps),
    }


# ---------------------------------------------------------------------------
# B. Boot Trace Endpoint
# ---------------------------------------------------------------------------


@router.get(
    "/control-plane/modules/{module_id}/boot-trace",
    dependencies=[Depends(require_scopes("control-plane:read"))],
    summary="Get boot stage timeline for a module",
)
def get_boot_trace(
    module_id: str,
    request: Request,
) -> Dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    is_global = _is_global_admin(request)

    _enforce_rate_limit(
        _rl_key(tenant_id, "boottrace"),
        *_RL_READ,
        error_code="CP_BOOT_TRACE_RATE_LIMIT",
    )

    # Tenant binding
    registry = get_registry()
    rec = registry.get(module_id)
    if rec is not None and not is_global and tenant_id:
        if rec.tenant_id is not None and rec.tenant_id != tenant_id:
            raise HTTPException(
                status_code=404,
                detail={
                    "error": {
                        "code": "CP_MODULE_NOT_FOUND",
                        "message": "Module not found",
                    }
                },
            )

    trace = get_trace(module_id)
    stages = trace.to_dict_list()
    summary = trace.summary()

    return {
        "module_id": module_id,
        "stages": stages,
        "stage_order": BOOT_STAGE_ORDER,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# D. Locker Runtime Control
# ---------------------------------------------------------------------------


def _locker_command(
    locker_id: str,
    command: str,
    body: LockerCommandRequest,
    request: Request,
) -> Dict[str, Any]:
    """Common handler for all locker commands."""
    tenant_id = _tenant_from_auth(request)
    is_global = _is_global_admin(request)
    actor = _actor_id(request)
    req_id = _request_id(request)

    # Fail-closed: locker commands require a bound tenant
    if not is_global and not tenant_id:
        raise HTTPException(
            status_code=400,
            detail={
                "error": {
                    "code": "CP_TENANT_REQUIRED",
                    "message": "Tenant binding required for locker commands",
                }
            },
        )

    effective_tenant = tenant_id or "global"

    _enforce_rate_limit(
        _rl_key(effective_tenant, f"cmd:{command}"),
        *_RL_CMD,
        error_code="CP_CMD_RATE_LIMIT",
    )

    bus = get_command_bus()
    result = bus.dispatch_command(
        locker_id=locker_id,
        command=command,
        reason=body.reason,
        actor_id=actor,
        tenant_id=effective_tenant,
        idempotency_key=body.idempotency_key,
    )

    # Always emit audit — even on failure
    _emit_audit(
        audit_type=f"locker_{command}",
        actor=actor,
        target_module="locker",
        target_id=locker_id,
        reason=body.reason,
        request_id=req_id,
        tenant_id=effective_tenant,
        result="ok" if result.ok else "failed",
        extra={
            "command_id": result.command_id,
            "error_code": result.error_code,
            "idempotent": result.idempotent,
        },
    )

    if not result.ok:
        # Map error codes to HTTP status
        status_map = {
            ERR_UNKNOWN_LOCKER: 404,
            ERR_QUARANTINE_LOCKED: 409,
            ERR_COOLDOWN_ACTIVE: 429,
            ERR_REASON_REQUIRED: 400,
            ERR_REASON_TOO_LONG: 400,
            ERR_REASON_INVALID_CHARS: 400,
        }
        http_status = status_map.get(result.error_code or "", 422)
        raise HTTPException(
            status_code=http_status,
            detail={
                "error": {
                    "code": result.error_code,
                    "message": result.error_message,
                    "command_id": result.command_id,
                }
            },
        )

    # Broadcast state change event
    try:
        bus_ev = get_event_bus()
        ev = make_event(
            "locker_state_changed" if command not in {"restart"} else "restart_started",
            module_id=locker_id,
            tenant_id=effective_tenant,
            payload={
                "command": command,
                "command_id": result.command_id,
                "actor": actor,
                "reason": body.reason,
                "idempotent": result.idempotent,
            },
        )
        bus_ev.publish(ev)
    except Exception as exc:
        log.warning("control_plane.event_broadcast_failed error=%s", exc)

    return result.to_dict()


@router.post(
    "/control-plane/lockers/{locker_id}/restart",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
    summary="Restart a locker (safe command bus — no subprocess)",
)
def locker_restart(
    locker_id: str,
    body: LockerCommandRequest,
    request: Request,
) -> Dict[str, Any]:
    return _locker_command(locker_id, "restart", body, request)


@router.post(
    "/control-plane/lockers/{locker_id}/pause",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
    summary="Pause a locker",
)
def locker_pause(
    locker_id: str,
    body: LockerCommandRequest,
    request: Request,
) -> Dict[str, Any]:
    return _locker_command(locker_id, "pause", body, request)


@router.post(
    "/control-plane/lockers/{locker_id}/resume",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
    summary="Resume a locker (also used to un-quarantine)",
)
def locker_resume(
    locker_id: str,
    body: LockerCommandRequest,
    request: Request,
) -> Dict[str, Any]:
    return _locker_command(locker_id, "resume", body, request)


@router.post(
    "/control-plane/lockers/{locker_id}/quarantine",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
    summary="Quarantine a locker (only RESUME accepted while quarantined)",
)
def locker_quarantine(
    locker_id: str,
    body: LockerCommandRequest,
    request: Request,
) -> Dict[str, Any]:
    return _locker_command(locker_id, "quarantine", body, request)


@router.get(
    "/control-plane/lockers",
    dependencies=[Depends(require_scopes("control-plane:read"))],
    summary="List lockers in scope",
)
def list_lockers(request: Request) -> Dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    is_global = _is_global_admin(request)

    _enforce_rate_limit(
        _rl_key(tenant_id, "lockers"),
        *_RL_READ,
        error_code="CP_LOCKERS_RATE_LIMIT",
    )

    bus = get_command_bus()
    if is_global:
        lockers = bus.list_all_lockers()
    elif tenant_id:
        lockers = bus.list_lockers(tenant_id)
    else:
        lockers = []

    return {
        "lockers": [lk.to_dict() for lk in lockers],
        "total": len(lockers),
    }


# ---------------------------------------------------------------------------
# F. Audit Endpoint
# ---------------------------------------------------------------------------


@router.get(
    "/control-plane/audit",
    dependencies=[Depends(require_scopes("control-plane:audit:read"))],
    summary="Query control-plane audit log",
)
def get_audit(
    request: Request,
    since: Optional[str] = Query(None, description="ISO-8601 timestamp filter"),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    is_global = _is_global_admin(request)

    _enforce_rate_limit(
        _rl_key(tenant_id, "audit"),
        *_RL_AUDIT,
        error_code="CP_AUDIT_RATE_LIMIT",
    )

    bus = get_event_bus()
    events = bus.get_history(
        since=since,
        tenant_id=tenant_id,
        is_global_admin=is_global,
        limit=limit,
    )
    return {
        "events": events,
        "total": len(events),
        "tenant_scope": tenant_id or "global",
        "since": since,
    }


# ---------------------------------------------------------------------------
# E. WebSocket Real-Time Event Stream
# ---------------------------------------------------------------------------


async def _ws_authenticate(
    websocket: WebSocket,
) -> Optional[Any]:
    """
    Authenticate a WebSocket connection using the same mechanism as HTTP.

    Returns the AuthResult or None if auth fails.
    Auth is NEVER weaker than HTTP.
    """
    from api.auth_scopes import verify_api_key_detailed

    # Extract key from headers — same as HTTP
    raw_key = websocket.headers.get("x-api-key") or websocket.headers.get("X-API-Key")
    if not raw_key:
        # Also check cookie
        cookie_name = (os.getenv("FG_UI_COOKIE_NAME") or "fg_api_key").strip()
        raw_key = websocket.cookies.get(cookie_name)

    if not raw_key:
        await websocket.close(code=4401, reason="Missing API key")
        return None

    result = verify_api_key_detailed(
        raw=raw_key, required_scopes={"control-plane:events:subscribe"}
    )
    if not result.valid:
        await websocket.close(code=4403, reason="Unauthorized")
        return None

    return result


@router.websocket("/control-plane/events")
async def ws_events(websocket: WebSocket) -> None:
    """
    Real-time event stream over WebSocket.

    Auth: same as HTTP (no weaker path).
    Tenant scoping: tenant admin sees only their events; global admin sees all.
    Per-tenant subscriber cap enforced.
    Slow consumers are disconnected.
    """
    await websocket.accept()

    auth = await _ws_authenticate(websocket)
    if auth is None:
        return  # already closed with error code

    tenant_id: Optional[str] = getattr(auth, "tenant_id", None)
    is_global = tenant_id is None

    # Rate limit WS connect attempts per tenant
    rl_key = _rl_key(tenant_id, "ws_connect")
    try:
        _enforce_rate_limit(rl_key, *_RL_WS, error_code="CP_WS_RATE_LIMIT")
    except HTTPException:
        await websocket.close(code=4429, reason="Rate limit exceeded")
        return

    event_bus = get_event_bus()

    try:
        sub = event_bus.add_subscriber(
            tenant_id=tenant_id,
            is_global_admin=is_global,
        )
    except ValueError as exc:
        err_code = str(exc)
        await websocket.close(code=4503, reason=err_code)
        return

    # Emit audit for WS subscription
    log.info(
        "control_plane.ws_subscribed sid=%s tenant_id=%s global_admin=%s",
        sub.subscriber_id,
        tenant_id,
        is_global,
    )

    try:
        while True:
            # Check for incoming messages (ping/disconnect detection)
            try:
                raw = await asyncio.wait_for(websocket.receive_text(), timeout=0.05)
                # Accept ping messages
                if raw.strip() in {"ping", "PING"}:
                    await websocket.send_text('{"type":"pong"}')
            except asyncio.TimeoutError:
                pass
            except WebSocketDisconnect:
                break

            # Drain event queue
            drained = 0
            while drained < 50:  # max events per loop iteration
                try:
                    event_dict = sub.queue.get_nowait()
                    await websocket.send_text(json.dumps(event_dict))
                    drained += 1
                except asyncio.QueueEmpty:
                    break

            await asyncio.sleep(0.1)

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        log.warning(
            "control_plane.ws_error sid=%s error=%s",
            sub.subscriber_id,
            exc,
        )
    finally:
        event_bus.remove_subscriber(sub.subscriber_id)
        log.info(
            "control_plane.ws_disconnected sid=%s tenant_id=%s",
            sub.subscriber_id,
            tenant_id,
        )


# ---------------------------------------------------------------------------
# Dependency matrix overview
# ---------------------------------------------------------------------------


@router.get(
    "/control-plane/dependency-matrix",
    dependencies=[Depends(require_scopes("control-plane:read"))],
    summary="Get dependency matrix across all visible modules",
)
def dependency_matrix(request: Request) -> Dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    is_global = _is_global_admin(request)

    _enforce_rate_limit(
        _rl_key(tenant_id, "depmatrix"),
        *_RL_READ,
        error_code="CP_DEP_MATRIX_RATE_LIMIT",
    )

    registry = get_registry()
    if is_global:
        records = registry.list_all()
    elif tenant_id:
        records = registry.list_for_tenant(tenant_id)
    else:
        records = []

    matrix: List[Dict[str, Any]] = []
    for rec in records:
        row: Dict[str, Any] = {
            "module_id": rec.module_id,
            "module_name": rec.name,
            "state": rec.state,
            "tenant_id": rec.tenant_id,
        }
        for dep_name, probe in rec.dependencies.items():
            row[dep_name] = probe.status
        matrix.append(row)

    return {
        "matrix": matrix,
        "module_count": len(matrix),
        "tenant_scope": tenant_id or "global",
    }
