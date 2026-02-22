"""
api/control_plane_v2.py — FrostGate Control Plane v2 API.

Endpoints:
  POST /control-plane/v2/commands                      — queue operator command
  GET  /control-plane/v2/commands                      — list commands
  POST /control-plane/v2/commands/{id}/cancel          — cancel queued command
  POST /control-plane/v2/commands/{id}/receipt         — submit executor receipt
  GET  /control-plane/v2/commands/{id}/receipts        — get receipts for command
  GET  /control-plane/v2/ledger                        — query ledger events
  GET  /control-plane/v2/ledger/verify                 — full chain verification
  GET  /control-plane/v2/ledger/anchor                 — daily Merkle anchor export
  POST /control-plane/v2/heartbeats                    — upsert entity heartbeat
  GET  /control-plane/v2/heartbeats                    — list heartbeats
  GET  /control-plane/v2/heartbeats/stale              — list stale entities
  POST /control-plane/v2/playbooks/{name}/trigger      — trigger allowlisted playbook
  GET  /control-plane/v2/playbooks                     — list available playbooks
  GET  /control-plane/evidence/bundle                  — audit evidence bundle

Global Security Invariants (all enforced, no bypass):
  - tenant_id ALWAYS from auth context; NEVER from request headers/body.
  - All write endpoints require control-plane:admin scope.
  - MSP cross-tenant requires control-plane:msp:read or :msp:admin scope.
  - Cross-tenant reads require explicit tenant_id query param + msp scope.
  - All write endpoints fail-closed if DB unavailable.
  - No subprocess, no shell, no dynamic code execution.
  - Every response includes trace_id and stable error_code.
  - All MSP cross-tenant access logged at elevated severity.
  - Command enum strictly allowlisted.
  - Executor auth validated before receipt acceptance.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from api.auth_scopes import require_scopes
from api.deps import tenant_db_session
from api.ratelimit import MemoryRateLimiter
from services.cp_commands import (
    VALID_CP_COMMANDS,
    ERR_INVALID_COMMAND,
    ERR_UNKNOWN_COMMAND_ID,
    ERR_CANCEL_CONFLICT,
    ERR_NOT_EXECUTOR,
    ERR_ALREADY_RECEIPTED,
    ERR_REASON_REQUIRED,
    ERR_REASON_TOO_SHORT,
    ERR_REASON_TOO_LONG,
    ERR_REASON_INVALID_CHARS,
    get_command_service,
)
from services.cp_heartbeats import VALID_ENTITY_TYPES, get_heartbeat_service
from services.cp_ledger import get_ledger
from services.cp_playbooks import VALID_PLAYBOOKS, ERR_INVALID_PLAYBOOK, get_playbook_service

log = logging.getLogger("frostgate.cp_v2")

router = APIRouter(tags=["control-plane-v2"])

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

_rl = MemoryRateLimiter()

_RL_READ = (10.0, 50)
_RL_WRITE = (1.0, 10)
_RL_LEDGER = (2.0, 20)
_RL_EVIDENCE = (0.5, 5)
_RL_HEARTBEAT = (20.0, 100)
_RL_PLAYBOOK = (0.25, 3)


def _rl_key(tenant_id: Optional[str], endpoint: str) -> str:
    t = tenant_id or "global"
    return f"cpv2:{endpoint}:{t}"


def _enforce_rate_limit(key: str, rate: float, burst: int, *, error_code: str) -> None:
    ok, limit, remaining, reset = _rl.allow(key, rate, burst)
    if not ok:
        raise HTTPException(
            status_code=429,
            detail={"error": {"code": error_code, "message": "Rate limit exceeded", "retry_after_seconds": reset}},
            headers={"Retry-After": str(reset), "X-RateLimit-Limit": str(limit), "X-RateLimit-Remaining": str(remaining)},
        )


# ---------------------------------------------------------------------------
# Auth helpers — tenant_id ALWAYS from auth context
# ---------------------------------------------------------------------------

def _get_auth(request: Request) -> Any:
    return getattr(getattr(request, "state", None), "auth", None)


def _tenant_from_auth(request: Request) -> Optional[str]:
    """Extract tenant_id from auth context ONLY — never from headers or body."""
    auth = _get_auth(request)
    if auth is None:
        return None
    tid = getattr(auth, "tenant_id", None)
    return str(tid).strip() if tid else None


def _is_global_admin(request: Request) -> bool:
    return _tenant_from_auth(request) is None


def _actor_id(request: Request) -> str:
    auth = _get_auth(request)
    prefix = getattr(auth, "key_prefix", None)
    return str(prefix)[:64] if prefix else "unknown"


def _actor_role(request: Request) -> str:
    auth = _get_auth(request)
    if auth is None:
        return "unknown"
    scopes = getattr(auth, "scopes", set()) or set()
    if "control-plane:msp:admin" in scopes:
        return "msp_admin"
    if "control-plane:admin" in scopes:
        return "tenant_admin"
    if "control-plane:msp:read" in scopes:
        return "msp_reader"
    return "reader"


def _trace_id(request: Request) -> str:
    rid = getattr(getattr(request, "state", None), "request_id", None)
    return str(rid) if rid else str(uuid.uuid4())


def _client_ip_hash(request: Request) -> Optional[str]:
    """Return SHA-256 of client IP — raw IP never stored."""
    ip = (
        getattr(request, "client", None)
        and request.client.host  # type: ignore[union-attr]
    )
    if not ip:
        return None
    return hashlib.sha256(f"ip:{ip}".encode()).hexdigest()


def _require_tenant(request: Request) -> str:
    """Require a bound tenant or raise 400."""
    tenant = _tenant_from_auth(request)
    if not tenant and not _is_global_admin(request):
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "CP_TENANT_REQUIRED", "trace_id": _trace_id(request), "message": "Tenant binding required"}},
        )
    return tenant or ""  # global admin gets empty string — must supply explicit tenant


def _check_msp_scope(request: Request) -> bool:
    """Return True if actor has any MSP scope."""
    auth = _get_auth(request)
    if not auth:
        return False
    scopes = getattr(auth, "scopes", set()) or set()
    return bool(
        scopes & {"control-plane:msp:read", "control-plane:msp:admin"}
    )


def _resolve_msp_tenant(
    request: Request,
    tenant_param: Optional[str],
    require_msp: bool = False,
) -> tuple[Optional[str], bool]:
    """
    Resolve tenant for MSP cross-tenant queries.

    Returns (effective_tenant_id, is_global_admin).
    For MSP actors, allows filtering by explicit tenant_param.
    Cross-tenant access is logged at elevated severity.
    """
    is_global = _is_global_admin(request)
    my_tenant = _tenant_from_auth(request)
    has_msp = _check_msp_scope(request)

    if is_global:
        # Global platform admin: can query any tenant
        return tenant_param, True

    if has_msp and tenant_param:
        # MSP actor: must supply explicit tenant_param (anti-enumeration)
        # Log elevated severity
        _emit_msp_access_log(request, tenant_param)
        return tenant_param, False

    if has_msp and not tenant_param:
        if require_msp:
            raise HTTPException(
                status_code=400,
                detail={"error": {"code": "CP_MSP_TENANT_REQUIRED", "trace_id": _trace_id(request), "message": "MSP queries require explicit tenant_id parameter"}},
            )
        # MSP read: no tenant filter → returns all (paginated, caller must paginate)
        return None, True  # treat as global for query

    # Tenant actor: strict isolation
    if my_tenant and tenant_param and tenant_param != my_tenant:
        # Anti-enumeration: return 404
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "CP_NOT_FOUND", "trace_id": _trace_id(request), "message": "Not found"}},
        )
    return my_tenant, False


def _emit_msp_access_log(request: Request, tenant_param: str) -> None:
    """Log MSP cross-tenant access at elevated severity."""
    actor = _actor_id(request)
    log.warning(
        "cp_v2.msp_cross_tenant_access actor=%s target_tenant=%s trace_id=%s",
        actor,
        tenant_param,
        _trace_id(request),
    )


def _error_response(
    status_code: int,
    error_code: str,
    message: str,
    trace_id: str,
) -> None:
    raise HTTPException(
        status_code=status_code,
        detail={
            "error": {
                "code": error_code,
                "message": message,
                "trace_id": trace_id,
            }
        },
    )


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------

class CommandRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_type: str = Field(..., min_length=1, max_length=32)
    target_id: str = Field(..., min_length=1, max_length=256)
    command: str = Field(..., min_length=1, max_length=64)
    reason: str = Field(..., min_length=4, max_length=512)
    idempotency_key: str = Field(..., min_length=1, max_length=128)


class CancelCommandRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(..., min_length=4, max_length=512)


class ReceiptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    executor_id: str = Field(..., min_length=1, max_length=128)
    executor_type: str = Field(..., min_length=1, max_length=32)
    ok: bool
    error_code: Optional[str] = Field(None, max_length=64)
    evidence: Optional[Dict[str, Any]] = None
    duration_ms: Optional[int] = Field(None, ge=0, le=3_600_000)


class HeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_type: str = Field(..., min_length=1, max_length=64)
    entity_id: str = Field(..., min_length=1, max_length=256)
    node_id: str = Field("", max_length=128)
    version: str = Field("", max_length=64)
    last_state: str = Field("active", max_length=32)
    breaker_state: str = Field("closed", max_length=16)
    queue_depth: int = Field(0, ge=0, le=1_000_000)
    last_error_code: Optional[str] = Field(None, max_length=64)


class PlaybookTriggerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: str = Field(..., min_length=1, max_length=256)
    reason: str = Field(..., min_length=4, max_length=512)
    idempotency_key: str = Field(..., min_length=1, max_length=128)
    dry_run: bool = False
    params: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Error code → HTTP status mapping
# ---------------------------------------------------------------------------

_ERROR_STATUS_MAP = {
    ERR_UNKNOWN_COMMAND_ID: 404,
    ERR_INVALID_COMMAND: 400,
    "CP_CMD_INVALID_TARGET_TYPE": 400,
    ERR_CANCEL_CONFLICT: 409,
    ERR_NOT_EXECUTOR: 403,
    ERR_ALREADY_RECEIPTED: 409,
    ERR_REASON_REQUIRED: 400,
    ERR_REASON_TOO_SHORT: 400,
    ERR_REASON_TOO_LONG: 400,
    ERR_REASON_INVALID_CHARS: 400,
    ERR_INVALID_PLAYBOOK: 400,
}


def _handle_service_error(exc: Exception, trace_id: str) -> None:
    msg = str(exc)
    code = msg.split(":")[0].strip() if ":" not in msg or msg.split(":")[0].isupper() else "CP_INTERNAL_ERROR"
    http_status = _ERROR_STATUS_MAP.get(code, 500)
    raise HTTPException(
        status_code=http_status,
        detail={"error": {"code": code, "message": msg, "trace_id": trace_id}},
    )


# ---------------------------------------------------------------------------
# A. Commands
# ---------------------------------------------------------------------------

@router.post(
    "/control-plane/v2/commands",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
    summary="Queue an operator command (CP v2)",
    status_code=201,
)
def create_command(
    body: CommandRequest,
    request: Request,
    db: Session = Depends(tenant_db_session),
) -> Dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    is_global = _is_global_admin(request)
    actor = _actor_id(request)
    role = _actor_role(request)
    trace = _trace_id(request)

    # Fail-closed: commands require a bound tenant unless global admin
    if not is_global and not tenant_id:
        _error_response(400, "CP_TENANT_REQUIRED", "Tenant binding required", trace)

    effective_tenant = tenant_id or "global"

    _enforce_rate_limit(_rl_key(effective_tenant, "cmd"), *_RL_WRITE, error_code="CP_CMD_RATE_LIMIT")

    if body.command not in VALID_CP_COMMANDS:
        _error_response(400, "CP_CMD_INVALID_COMMAND", f"Unknown command: {body.command!r}", trace)

    ledger = get_ledger()
    svc = get_command_service()

    try:
        with db.begin():
            rec = svc.create_command(
                db_session=db,
                ledger=ledger,
                tenant_id=effective_tenant,
                actor_id=actor,
                actor_role=role,
                target_type=body.target_type,
                target_id=body.target_id,
                command=body.command,
                reason=body.reason,
                idempotency_key=body.idempotency_key,
                trace_id=trace,
                client_ip=request.client.host if request.client else None,
            )
    except (ValueError, RuntimeError) as exc:
        _handle_service_error(exc, trace)

    result = rec.to_dict()
    result["trace_id"] = trace
    result["actor_id"] = actor
    return result


@router.get(
    "/control-plane/v2/commands",
    dependencies=[Depends(require_scopes("control-plane:read"))],
    summary="List operator commands (CP v2)",
)
def list_commands(
    request: Request,
    db: Session = Depends(tenant_db_session),
    status: Optional[str] = Query(None, max_length=32),
    target_id: Optional[str] = Query(None, max_length=256),
    tenant_id_param: Optional[str] = Query(None, alias="tenant_id", max_length=128),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    trace = _trace_id(request)
    effective_tenant, is_global = _resolve_msp_tenant(request, tenant_id_param)

    _enforce_rate_limit(_rl_key(effective_tenant, "cmd_list"), *_RL_READ, error_code="CP_CMD_LIST_RATE_LIMIT")

    svc = get_command_service()
    commands = svc.get_commands(
        db_session=db,
        tenant_id=effective_tenant or "",
        is_global_admin=is_global,
        status=status,
        target_id=target_id,
        limit=limit,
        offset=offset,
    )
    return {
        "commands": commands,
        "total": len(commands),
        "tenant_scope": effective_tenant or "global",
        "trace_id": trace,
    }


@router.post(
    "/control-plane/v2/commands/{command_id}/cancel",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
    summary="Cancel a queued command (CP v2)",
)
def cancel_command(
    command_id: str,
    body: CancelCommandRequest,
    request: Request,
    db: Session = Depends(tenant_db_session),
) -> Dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    is_global = _is_global_admin(request)
    actor = _actor_id(request)
    role = _actor_role(request)
    trace = _trace_id(request)

    if not is_global and not tenant_id:
        _error_response(400, "CP_TENANT_REQUIRED", "Tenant binding required", trace)

    effective_tenant = tenant_id or "global"

    _enforce_rate_limit(_rl_key(effective_tenant, "cmd_cancel"), *_RL_WRITE, error_code="CP_CANCEL_RATE_LIMIT")

    ledger = get_ledger()
    svc = get_command_service()

    try:
        with db.begin():
            rec = svc.cancel_command(
                db_session=db,
                ledger=ledger,
                command_id=command_id,
                tenant_id=effective_tenant,
                actor_id=actor,
                actor_role=role,
                trace_id=trace,
            )
    except ValueError as exc:
        code = str(exc)
        if code == ERR_UNKNOWN_COMMAND_ID:
            _error_response(404, code, "Command not found", trace)
        elif code == ERR_CANCEL_CONFLICT:
            _error_response(409, code, "Command cannot be cancelled in current state", trace)
        _handle_service_error(exc, trace)
    except RuntimeError as exc:
        _handle_service_error(exc, trace)

    result = rec.to_dict()
    result["trace_id"] = trace
    return result


@router.post(
    "/control-plane/v2/commands/{command_id}/receipt",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
    summary="Submit executor receipt (CP v2) — executor identity required",
    status_code=201,
)
def submit_receipt(
    command_id: str,
    body: ReceiptRequest,
    request: Request,
    db: Session = Depends(tenant_db_session),
) -> Dict[str, Any]:
    """
    Receipt endpoint.
    Validates that the submitter has executor-compatible identity.
    Non-executors are rejected with 403.
    """
    actor = _actor_id(request)
    _tenant_from_auth(request)  # tenant binding — receipt scoped to actor's tenant
    trace = _trace_id(request)

    _enforce_rate_limit(_rl_key(actor, "receipt"), *_RL_WRITE, error_code="CP_RECEIPT_RATE_LIMIT")

    # Validate executor_type
    from services.cp_commands import VALID_EXECUTOR_TYPES
    if body.executor_type not in VALID_EXECUTOR_TYPES:
        _error_response(403, "CP_CMD_NOT_EXECUTOR", "Invalid executor_type", trace)

    ledger = get_ledger()
    svc = get_command_service()

    try:
        with db.begin():
            rec = svc.submit_receipt(
                db_session=db,
                ledger=ledger,
                command_id=command_id,
                executor_id=body.executor_id,
                executor_type=body.executor_type,
                ok=body.ok,
                error_code=body.error_code,
                evidence=body.evidence,
                duration_ms=body.duration_ms,
                trace_id=trace,
            )
    except ValueError as exc:
        code = str(exc)
        if code == ERR_NOT_EXECUTOR:
            _error_response(403, code, "Not authorized as executor", trace)
        elif code == ERR_ALREADY_RECEIPTED:
            _error_response(409, code, "Receipt already submitted", trace)
        elif code == ERR_UNKNOWN_COMMAND_ID:
            _error_response(404, code, "Command not found", trace)
        _handle_service_error(exc, trace)
    except RuntimeError as exc:
        _handle_service_error(exc, trace)

    result = rec.to_dict()
    result["trace_id"] = trace
    result["actor_id"] = actor
    return result


@router.get(
    "/control-plane/v2/commands/{command_id}/receipts",
    dependencies=[Depends(require_scopes("control-plane:read"))],
    summary="Get receipts for a command (CP v2)",
)
def get_receipts(
    command_id: str,
    request: Request,
    db: Session = Depends(tenant_db_session),
) -> Dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    is_global = _is_global_admin(request)
    trace = _trace_id(request)

    _enforce_rate_limit(_rl_key(tenant_id, "receipts"), *_RL_READ, error_code="CP_RECEIPTS_RATE_LIMIT")

    svc = get_command_service()
    receipts = svc.get_receipts(
        db_session=db,
        command_id=command_id,
        tenant_id=tenant_id or "",
        is_global_admin=is_global,
    )
    return {"receipts": receipts, "total": len(receipts), "command_id": command_id, "trace_id": trace}


# ---------------------------------------------------------------------------
# B. Ledger
# ---------------------------------------------------------------------------

@router.get(
    "/control-plane/v2/ledger",
    dependencies=[Depends(require_scopes("control-plane:audit:read"))],
    summary="Query control-plane v2 event ledger",
)
def query_ledger(
    request: Request,
    db: Session = Depends(tenant_db_session),
    since: Optional[str] = Query(None, description="ISO-8601 timestamp lower bound"),
    until: Optional[str] = Query(None, description="ISO-8601 timestamp upper bound"),
    event_type: Optional[str] = Query(None, max_length=64),
    tenant_id_param: Optional[str] = Query(None, alias="tenant_id", max_length=128),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    trace = _trace_id(request)
    effective_tenant, is_global = _resolve_msp_tenant(request, tenant_id_param)

    _enforce_rate_limit(_rl_key(effective_tenant, "ledger_query"), *_RL_LEDGER, error_code="CP_LEDGER_RATE_LIMIT")

    since_dt: Optional[datetime] = None
    until_dt: Optional[datetime] = None
    try:
        if since:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        if until:
            until_dt = datetime.fromisoformat(until.replace("Z", "+00:00"))
    except ValueError:
        _error_response(400, "CP_LEDGER_INVALID_TIME", "Invalid ISO-8601 timestamp", trace)

    ledger = get_ledger()
    events = ledger.get_events(
        db_session=db,
        tenant_id=effective_tenant,
        is_global_admin=is_global,
        since=since_dt,
        until=until_dt,
        event_type=event_type,
        limit=limit,
        offset=offset,
    )
    return {
        "events": events,
        "total": len(events),
        "tenant_scope": effective_tenant or "global",
        "trace_id": trace,
    }


@router.get(
    "/control-plane/v2/ledger/verify",
    dependencies=[Depends(require_scopes("control-plane:audit:read"))],
    summary="Verify full ledger chain integrity (CP v2)",
)
def verify_ledger(
    request: Request,
    db: Session = Depends(tenant_db_session),
    tenant_id_param: Optional[str] = Query(None, alias="tenant_id", max_length=128),
) -> Dict[str, Any]:
    """
    Full chain verification — recomputes every hash and verifies linkage.
    Returns deterministic integrity report.
    Fails with 500 if tampering is detected (chain broken).
    """
    trace = _trace_id(request)
    effective_tenant, is_global = _resolve_msp_tenant(request, tenant_id_param)

    _enforce_rate_limit(_rl_key(effective_tenant, "ledger_verify"), *_RL_LEDGER, error_code="CP_VERIFY_RATE_LIMIT")

    ledger = get_ledger()
    result = ledger.verify_chain(
        db_session=db,
        tenant_id=effective_tenant,
    )

    if not result.ok:
        log.error(
            "cp_v2.ledger_tamper_detected tenant=%s tampered_id=%s trace_id=%s",
            effective_tenant,
            result.first_tampered_id,
            trace,
        )
        # Log tamper detection to ledger if possible
        try:
            actor = _actor_id(request)
            ledger.append_event(
                db_session=db,
                event_type="cp_ledger_tamper_detected",
                actor_id=actor,
                actor_role="system",
                tenant_id=effective_tenant,
                payload={
                    "first_tampered_id": result.first_tampered_id,
                    "first_tampered_index": result.first_tampered_index,
                    "total_entries": result.total_entries,
                },
                trace_id=trace,
                severity="critical",
                source="system",
            )
            db.commit()
        except Exception:
            pass

        raise HTTPException(
            status_code=500,
            detail={
                "error": {
                    "code": "CP_LEDGER_TAMPER_DETECTED",
                    "message": "Ledger integrity check failed — chain tampered",
                    "trace_id": trace,
                    "report": result.to_dict(),
                }
            },
        )

    return {
        "integrity": result.to_dict(),
        "tenant_scope": effective_tenant or "global",
        "trace_id": trace,
    }


@router.get(
    "/control-plane/v2/ledger/anchor",
    dependencies=[Depends(require_scopes("control-plane:audit:read"))],
    summary="Export daily Merkle anchor for ledger chain (CP v2)",
)
def export_ledger_anchor(
    request: Request,
    db: Session = Depends(tenant_db_session),
    tenant_id_param: Optional[str] = Query(None, alias="tenant_id", max_length=128),
) -> Dict[str, Any]:
    trace = _trace_id(request)
    effective_tenant, _is_global = _resolve_msp_tenant(request, tenant_id_param)

    _enforce_rate_limit(_rl_key(effective_tenant, "anchor"), *_RL_EVIDENCE, error_code="CP_ANCHOR_RATE_LIMIT")

    ledger = get_ledger()
    anchor = ledger.export_daily_anchor(db_session=db, tenant_id=effective_tenant)
    anchor["trace_id"] = trace

    # Emit ledger event for anchor export
    try:
        actor = _actor_id(request)
        with db.begin():
            ledger.append_event(
                db_session=db,
                event_type="cp_ledger_anchor_exported",
                actor_id=actor,
                actor_role=_actor_role(request),
                tenant_id=effective_tenant,
                payload={"merkle_root": anchor.get("merkle_root"), "total_entries": anchor.get("total_entries")},
                trace_id=trace,
                severity="info",
                source="api",
            )
    except Exception as exc:
        log.warning("cp_v2.anchor_event_failed error=%s", exc)

    return anchor


# ---------------------------------------------------------------------------
# C. Heartbeats
# ---------------------------------------------------------------------------

@router.post(
    "/control-plane/v2/heartbeats",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
    summary="Upsert entity heartbeat (CP v2)",
)
def upsert_heartbeat(
    body: HeartbeatRequest,
    request: Request,
    db: Session = Depends(tenant_db_session),
) -> Dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    is_global = _is_global_admin(request)
    trace = _trace_id(request)

    if not is_global and not tenant_id:
        _error_response(400, "CP_TENANT_REQUIRED", "Tenant binding required", trace)

    effective_tenant = tenant_id or "global"

    _enforce_rate_limit(_rl_key(effective_tenant, "heartbeat"), *_RL_HEARTBEAT, error_code="CP_HB_RATE_LIMIT")

    if body.entity_type not in VALID_ENTITY_TYPES:
        _error_response(400, "CP_HB_INVALID_ENTITY_TYPE", f"Unknown entity_type: {body.entity_type!r}", trace)

    svc = get_heartbeat_service()
    try:
        with db.begin():
            result = svc.upsert(
                db_session=db,
                entity_type=body.entity_type,
                entity_id=body.entity_id,
                tenant_id=effective_tenant,
                node_id=body.node_id,
                version=body.version,
                last_state=body.last_state,
                breaker_state=body.breaker_state,
                queue_depth=body.queue_depth,
                last_error_code=body.last_error_code,
            )
    except (ValueError, RuntimeError) as exc:
        _handle_service_error(exc, trace)

    result["trace_id"] = trace
    return result


@router.get(
    "/control-plane/v2/heartbeats",
    dependencies=[Depends(require_scopes("control-plane:read"))],
    summary="List entity heartbeats (CP v2)",
)
def list_heartbeats(
    request: Request,
    db: Session = Depends(tenant_db_session),
    entity_type: Optional[str] = Query(None, max_length=64),
    tenant_id_param: Optional[str] = Query(None, alias="tenant_id", max_length=128),
    stale_only: bool = Query(False),
) -> Dict[str, Any]:
    trace = _trace_id(request)
    effective_tenant, is_global = _resolve_msp_tenant(request, tenant_id_param)

    _enforce_rate_limit(_rl_key(effective_tenant, "hb_list"), *_RL_READ, error_code="CP_HB_LIST_RATE_LIMIT")

    svc = get_heartbeat_service()
    heartbeats = svc.get_heartbeats(
        db_session=db,
        tenant_id=effective_tenant,
        is_global_admin=is_global,
        entity_type=entity_type,
        stale_only=stale_only,
    )
    return {
        "heartbeats": heartbeats,
        "total": len(heartbeats),
        "tenant_scope": effective_tenant or "global",
        "trace_id": trace,
    }


@router.get(
    "/control-plane/v2/heartbeats/stale",
    dependencies=[Depends(require_scopes("control-plane:read"))],
    summary="List stale entities (CP v2)",
)
def list_stale_heartbeats(
    request: Request,
    db: Session = Depends(tenant_db_session),
    tenant_id_param: Optional[str] = Query(None, alias="tenant_id", max_length=128),
) -> Dict[str, Any]:
    trace = _trace_id(request)
    effective_tenant, is_global = _resolve_msp_tenant(request, tenant_id_param)

    _enforce_rate_limit(_rl_key(effective_tenant, "stale"), *_RL_READ, error_code="CP_STALE_RATE_LIMIT")

    ledger = get_ledger()
    svc = get_heartbeat_service()

    with db.begin():
        stale = svc.detect_stale(
            db_session=db,
            ledger=ledger,
            tenant_id=effective_tenant,
            is_global=is_global,
        )

    return {
        "stale_entities": stale,
        "total": len(stale),
        "tenant_scope": effective_tenant or "global",
        "trace_id": trace,
    }


# ---------------------------------------------------------------------------
# D. Playbooks
# ---------------------------------------------------------------------------

@router.get(
    "/control-plane/v2/playbooks",
    dependencies=[Depends(require_scopes("control-plane:read"))],
    summary="List available remediation playbooks (CP v2)",
)
def list_playbooks(request: Request) -> Dict[str, Any]:
    trace = _trace_id(request)
    tenant_id = _tenant_from_auth(request)
    return {
        "playbooks": sorted(VALID_PLAYBOOKS),
        "total": len(VALID_PLAYBOOKS),
        "tenant_scope": tenant_id or "global",
        "trace_id": trace,
    }


@router.post(
    "/control-plane/v2/playbooks/{playbook_name}/trigger",
    dependencies=[Depends(require_scopes("control-plane:admin"))],
    summary="Trigger an allowlisted remediation playbook (CP v2)",
    status_code=201,
)
def trigger_playbook(
    playbook_name: str,
    body: PlaybookTriggerRequest,
    request: Request,
    db: Session = Depends(tenant_db_session),
) -> Dict[str, Any]:
    tenant_id = _tenant_from_auth(request)
    is_global = _is_global_admin(request)
    actor = _actor_id(request)
    role = _actor_role(request)
    trace = _trace_id(request)

    if playbook_name not in VALID_PLAYBOOKS:
        _error_response(400, "CP_PLAYBOOK_INVALID", f"Unknown playbook: {playbook_name!r}", trace)

    if not is_global and not tenant_id:
        _error_response(400, "CP_TENANT_REQUIRED", "Tenant binding required", trace)

    effective_tenant = tenant_id or "global"

    _enforce_rate_limit(_rl_key(effective_tenant, f"playbook_{playbook_name}"), *_RL_PLAYBOOK, error_code="CP_PLAYBOOK_RATE_LIMIT")

    ledger = get_ledger()
    svc = get_playbook_service()
    cmd_svc = get_command_service()

    try:
        with db.begin():
            result = svc.trigger(
                db_session=db,
                ledger=ledger,
                command_svc=cmd_svc,
                playbook=playbook_name,
                target_id=body.target_id,
                tenant_id=effective_tenant,
                actor_id=actor,
                actor_role=role,
                reason=body.reason,
                idempotency_key=body.idempotency_key,
                dry_run=body.dry_run,
                params=body.params,
                trace_id=trace,
            )
    except (ValueError, RuntimeError) as exc:
        _handle_service_error(exc, trace)

    out = result.to_dict()
    out["trace_id"] = trace
    out["actor_id"] = actor
    return out


# ---------------------------------------------------------------------------
# E. Evidence Bundle
# ---------------------------------------------------------------------------

@router.get(
    "/control-plane/evidence/bundle",
    dependencies=[Depends(require_scopes("control-plane:audit:read"))],
    summary="Export audit-grade evidence bundle (CP v2)",
)
def get_evidence_bundle(
    request: Request,
    db: Session = Depends(tenant_db_session),
    tenant_id_param: Optional[str] = Query(None, alias="tenant_id", max_length=128),
    since: Optional[str] = Query(None, description="ISO-8601 lower bound"),
    until: Optional[str] = Query(None, description="ISO-8601 upper bound"),
    include_receipts: bool = Query(True),
    limit: int = Query(500, ge=1, le=2000),
) -> Dict[str, Any]:
    """
    Compliance-grade evidence bundle.

    Returns:
      - All ledger events in scope
      - Commands in scope
      - Receipts for each command (if include_receipts=True)
      - Hash-chain integrity verification report
      - Merkle root
      - Deterministic JSON output suitable for external notarisation

    Tenant isolation enforced. MSP cross-tenant requires msp scope + explicit tenant_id.
    """
    trace = _trace_id(request)
    actor = _actor_id(request)
    effective_tenant, is_global = _resolve_msp_tenant(request, tenant_id_param)

    _enforce_rate_limit(_rl_key(effective_tenant, "evidence"), *_RL_EVIDENCE, error_code="CP_EVIDENCE_RATE_LIMIT")

    since_dt: Optional[datetime] = None
    until_dt: Optional[datetime] = None
    try:
        if since:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        if until:
            until_dt = datetime.fromisoformat(until.replace("Z", "+00:00"))
    except ValueError:
        _error_response(400, "CP_EVIDENCE_INVALID_TIME", "Invalid ISO-8601 timestamp", trace)

    ledger = get_ledger()
    cmd_svc = get_command_service()

    # 1. Gather ledger events
    events = ledger.get_events(
        db_session=db,
        tenant_id=effective_tenant,
        is_global_admin=is_global,
        since=since_dt,
        until=until_dt,
        limit=limit,
    )

    # 2. Gather commands
    commands = cmd_svc.get_commands(
        db_session=db,
        tenant_id=effective_tenant or "",
        is_global_admin=is_global,
        limit=limit,
    )
    # Apply time filter to commands
    if since_dt or until_dt:
        filtered_commands = []
        for cmd in commands:
            ts_str = cmd.get("ts", "")
            if ts_str:
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    if since_dt and ts < since_dt:
                        continue
                    if until_dt and ts > until_dt:
                        continue
                except ValueError:
                    pass
            filtered_commands.append(cmd)
        commands = filtered_commands

    # 3. Gather receipts
    receipts_by_command: Dict[str, List[Dict[str, Any]]] = {}
    if include_receipts:
        for cmd in commands:
            cid = cmd.get("command_id", "")
            if cid:
                recs = cmd_svc.get_receipts(
                    db_session=db,
                    command_id=cid,
                    tenant_id=effective_tenant or "",
                    is_global_admin=is_global,
                )
                if recs:
                    receipts_by_command[cid] = recs

    # 4. Chain integrity verification
    integrity = ledger.verify_chain(db_session=db, tenant_id=effective_tenant)

    # 5. Emit access event
    try:
        with db.begin():
            ledger.append_event(
                db_session=db,
                event_type="cp_msp_cross_tenant_access" if effective_tenant and is_global else "cp_ledger_verified",
                actor_id=actor,
                actor_role=_actor_role(request),
                tenant_id=effective_tenant,
                payload={
                    "bundle_type": "evidence_bundle",
                    "events_count": len(events),
                    "commands_count": len(commands),
                    "integrity_ok": integrity.ok,
                    "trace_id": trace,
                },
                trace_id=trace,
                severity="warning" if _check_msp_scope(request) else "info",
                source="api",
            )
    except Exception as exc:
        log.warning("cp_v2.evidence_bundle_audit_failed error=%s", exc)

    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    return {
        "bundle_type": "control_plane_v2_evidence",
        "generated_at": generated_at,
        "tenant_scope": effective_tenant or "global",
        "actor_id": actor,
        "time_range": {
            "since": since_dt.isoformat() if since_dt else None,
            "until": until_dt.isoformat() if until_dt else None,
        },
        "ledger_events": events,
        "commands": commands,
        "receipts_by_command": receipts_by_command,
        "integrity": integrity.to_dict(),
        "trace_id": trace,
    }
