from __future__ import annotations

import hashlib
import os
import re
import unicodedata
from datetime import UTC, datetime

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from api.auth_scopes import bind_tenant_id, require_scopes, verify_api_key
from api.db import set_tenant_context
from api.db_models import AuditExportJob, AuditLedgerRecord
from api.deps import tenant_db_session
from api.ratelimit import MemoryRateLimiter
from services.audit_engine import (
    apply_retention,
    cancel_export_job,
    enqueue_export_job,
    export_evidence_bundle,
    list_exports,
    record_bypass_event,
    reproduce_audit_session,
    run_export_job,
)

router = APIRouter(prefix="/audit", tags=["audit"], dependencies=[Depends(verify_api_key)])
_limiter = MemoryRateLimiter()
_bypass_limiter = MemoryRateLimiter()
_cancel_bypass_limiter = MemoryRateLimiter()
_cancel_limiter = MemoryRateLimiter()
_VALID_CANCEL_REASONS = {"SECURITY_INCIDENT", "CUSTOMER_REQUEST", "LEGAL_HOLD", "OPERATOR_ERROR", "DATA_CORRECTION", "OTHER"}
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class RetentionRequest(BaseModel):
    retention_days: int = 365
    dry_run: bool = True
    reason_code: str
    ticket_id: str
    allow_delete_exports: bool = False
    confirmation_token: str | None = None


class ExportJobRequest(BaseModel):
    start: str
    end: str
    purpose: str = "compliance-review"
    retention_class: str = "regulated"
    force: bool = False
    signing_kid: str = ""
    end_inclusive: bool = True


class ReproduceRequest(BaseModel):
    audit_session_id: int


class CancelJobRequest(BaseModel):
    reason: str = Field(default="OPERATOR_ERROR", max_length=64)
    ticket_id: str = Field(default="", max_length=128)
    notes: str = Field(default="", max_length=512)


def _resolve_tenant(request: Request, tenant_id: str | None) -> str:
    resolved = bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    if not resolved:
        raise HTTPException(status_code=403, detail={"code": "FG-AUDIT-AUTH-403", "message": "tenant binding required"})
    return resolved


def _principal(request: Request) -> str:
    auth = getattr(request.state, "auth", None)
    return str(getattr(auth, "key_prefix", "unknown") or "unknown")


def _principal_strict(request: Request) -> str:
    principal = _principal(request)
    if principal == "unknown":
        raise HTTPException(status_code=403, detail={"job_id": None, "status": None, "error_code": "AUDIT_EXPORT_JOB_FORBIDDEN"})
    return principal


def _scopes(request: Request) -> set[str]:
    auth = getattr(request.state, "auth", None)
    return set(getattr(auth, "scopes", set()) or set())


def _cancel_ticket_required() -> bool:
    env = (os.getenv("FG_ENV") or "dev").strip().lower()
    if env in {"prod", "production", "staging"}:
        return True
    return (os.getenv("FG_AUDIT_CANCEL_REQUIRE_TICKET_NONPROD") or "0").strip() == "1"


def _normalize_notes(value: str) -> str:
    v = unicodedata.normalize("NFKC", str(value))
    v = " ".join(v.strip().split())
    if _CONTROL_CHAR_RE.search(v):
        raise HTTPException(status_code=400, detail={"job_id": None, "status": None, "error_code": "AUDIT_EXPORT_JOB_BAD_REQUEST"})
    if len(v) > 512:
        raise HTTPException(status_code=400, detail={"job_id": None, "status": None, "error_code": "AUDIT_EXPORT_JOB_BAD_REQUEST"})
    return v


def _enforce_cancel_rate_limit(*, tenant_id: str, actor: str) -> None:
    allowed, _limit, _remaining, reset = _cancel_limiter.allow(
        key=f"audit:cancel:{tenant_id}:{actor}:cancel",
        rate_per_sec=float(os.getenv("FG_AUDIT_CANCEL_RATE_LIMIT_RPS", "0.25")),
        capacity=float(os.getenv("FG_AUDIT_CANCEL_RATE_LIMIT_BURST", "5")),
    )
    if not allowed:
        raise HTTPException(status_code=429, detail={"job_id": None, "status": None, "error_code": "AUDIT_EXPORT_JOB_RATE_LIMIT", "reset_seconds": reset})


def _assert_cancel_payload(body: CancelJobRequest) -> tuple[str, str, str]:
    reason = str(body.reason).strip().upper()
    ticket_id = str(body.ticket_id).strip()
    notes = _normalize_notes(str(body.notes))
    if reason not in _VALID_CANCEL_REASONS:
        raise HTTPException(status_code=400, detail={"job_id": None, "status": None, "error_code": "AUDIT_EXPORT_JOB_BAD_REQUEST"})
    if reason == "OTHER" and not notes:
        raise HTTPException(status_code=400, detail={"job_id": None, "status": None, "error_code": "AUDIT_EXPORT_JOB_BAD_REQUEST"})
    if _cancel_ticket_required() and not ticket_id:
        raise HTTPException(status_code=400, detail={"job_id": None, "status": None, "error_code": "AUDIT_EXPORT_JOB_TICKET_REQUIRED"})
    return reason, ticket_id, notes


def _can_cancel_job(*, row: AuditExportJob, actor: str, scopes: set[str]) -> tuple[bool, bool]:
    is_admin = "audit:admin" in scopes
    is_bypass = "audit:auditor_bypass" in scopes
    is_owner = str(row.triggered_by) == actor
    return is_owner or is_admin or is_bypass, is_bypass


def _enforce_cancel_bypass_rate_limit(*, tenant_id: str, actor: str) -> None:
    max_per_hour = float(os.getenv("FG_AUDIT_CANCEL_BYPASS_MAX_PER_HOUR", "30"))
    allowed, _limit, _remaining, reset = _cancel_bypass_limiter.allow(
        key=f"audit:cancel-bypass:{tenant_id}:{actor}:{datetime.now(tz=UTC).strftime('%Y%m%d%H')}",
        rate_per_sec=max_per_hour / 3600.0,
        capacity=max_per_hour,
    )
    if not allowed:
        raise HTTPException(status_code=429, detail={"job_id": None, "status": None, "error_code": "AUDIT_EXPORT_JOB_BYPASS_RATE_LIMIT", "reset_seconds": reset})


def _bypass_details(request: Request) -> tuple[str, str, int]:
    reason = str(request.headers.get("X-Audit-Bypass-Reason", "")).strip()
    ticket = str(request.headers.get("X-Audit-Bypass-Ticket", "")).strip()
    ttl = int(str(request.headers.get("X-Audit-Bypass-TTL-Seconds", "0") or "0"))
    if not reason or not ticket:
        raise HTTPException(status_code=400, detail={"code": "FG-AUDIT-BYPASS-400", "message": "bypass requires reason and ticket"})
    max_ttl = int(os.getenv("FG_AUDIT_BYPASS_MAX_TTL_SECONDS", "3600"))
    if ttl <= 0 or ttl > max_ttl:
        raise HTTPException(status_code=400, detail={"code": "FG-AUDIT-BYPASS-TTL-400", "message": f"ttl must be 1..{max_ttl}"})
    return reason, ticket, ttl


def _maybe_bypass_rate_limit(request: Request, tenant_id: str, op: str, db: Session) -> bool:
    scopes = _scopes(request)
    bypass_scopes = {s.strip() for s in (os.getenv("FG_AUDIT_AUDITOR_BYPASS_SCOPES") or "audit:auditor,audit:admin").split(",") if s.strip()}
    if not scopes.intersection(bypass_scopes):
        return False

    principal = _principal(request)
    reason, ticket, ttl = _bypass_details(request)
    super_scopes = {s.strip() for s in (os.getenv("FG_AUDIT_SUPERADMIN_SCOPES") or "audit:super-admin").split(",") if s.strip()}
    if not scopes.intersection(super_scopes):
        max_per_hour = float(os.getenv("FG_AUDIT_BYPASS_MAX_PER_HOUR", "20"))
        allowed, _limit, _remaining, reset = _bypass_limiter.allow(
            key=f"audit:bypass:{tenant_id}:{principal}:{datetime.now(tz=UTC).strftime('%Y%m%d%H')}",
            rate_per_sec=max_per_hour / 3600.0,
            capacity=max_per_hour,
        )
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail={"code": "FG-AUDIT-BYPASS-RATE-429", "message": "bypass quota exceeded", "reset_seconds": reset},
            )

    record_bypass_event(
        db,
        tenant_id=tenant_id,
        principal_id=principal,
        operation=op,
        reason_code=reason,
        ticket_id=ticket,
        ttl_seconds=ttl,
    )
    db.commit()
    return True


def _rate_limit(request: Request, tenant_id: str, op: str, db: Session) -> None:
    if _maybe_bypass_rate_limit(request, tenant_id, op, db):
        return

    allowed, limit, _remaining, reset = _limiter.allow(
        key=f"audit:{tenant_id}:{op}",
        rate_per_sec=float((os.getenv("FG_AUDIT_RATE_LIMIT_RPS") or "0.5")),
        capacity=float((os.getenv("FG_AUDIT_RATE_LIMIT_BURST") or "5")),
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail={"code": "FG-AUDIT-RATE-429", "message": "rate limited", "limit": limit, "reset_seconds": reset},
        )


@router.get("/sessions", dependencies=[Depends(require_scopes("audit:read"))])
def audit_sessions(request: Request, tenant_id: str | None = Query(default=None), db: Session = Depends(tenant_db_session)):
    tid = _resolve_tenant(request, tenant_id)
    set_tenant_context(db, tid)
    rows = (
        db.query(
            AuditLedgerRecord.invariant_id,
            func.count(AuditLedgerRecord.id).label("count"),
            func.max(AuditLedgerRecord.created_at).label("last_seen"),
        )
        .filter(AuditLedgerRecord.tenant_id == tid)
        .group_by(AuditLedgerRecord.invariant_id)
        .order_by(AuditLedgerRecord.invariant_id.asc())
        .all()
    )
    return {
        "tenant_id": tid,
        "sessions": [
            {"invariant_id": r.invariant_id, "count": int(r.count), "last_seen": r.last_seen.astimezone(UTC).isoformat() if r.last_seen else None}
            for r in rows
        ],
    }


@router.get("/exports", dependencies=[Depends(require_scopes("audit:read"))])
def audit_exports_index(
    request: Request,
    tenant_id: str | None = Query(default=None),
    retention_class: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(tenant_db_session),
):
    tid = _resolve_tenant(request, tenant_id)
    set_tenant_context(db, tid)
    rows = list_exports(db, tenant_id=tid, retention_class=retention_class, limit=limit, offset=offset)
    return {
        "tenant_id": tid,
        "items": [
            {
                "export_id": r.export_id,
                "created_at": r.created_at.astimezone(UTC).isoformat(),
                "export_hash": r.export_hash,
                "manifest_hash": r.manifest_hash,
                "storage_uri": r.storage_uri,
                "size_bytes": r.size_bytes,
                "retention_class": r.retention_class,
                "range_start_utc": r.export_range_start_utc,
                "range_end_utc": r.export_range_end_utc,
                "range_end_inclusive": bool(r.export_range_end_inclusive),
                "signature_algo": r.signature_algo,
                "kid": r.kid,
            }
            for r in rows
        ],
    }


@router.post("/retention/apply", dependencies=[Depends(require_scopes("audit:export"))])
def audit_apply_retention(
    request: Request,
    body: RetentionRequest = Body(...),
    tenant_id: str | None = Query(default=None),
    db: Session = Depends(tenant_db_session),
):
    tid = _resolve_tenant(request, tenant_id)
    set_tenant_context(db, tid)
    retention_days = int(body.retention_days)
    dry_run = bool(body.dry_run)
    reason = str(body.reason_code).strip()
    ticket = str(body.ticket_id).strip()
    if not reason or not ticket:
        raise HTTPException(status_code=400, detail={"code": "FG-AUDIT-RETENTION-400", "message": "reason_code and ticket_id required"})

    policy_obj = {
        "retention_days": retention_days,
        "allow_delete_exports": bool(body.allow_delete_exports),
        "allow_delete_jobs": True,
        "policy_version": "retention-v1",
    }

    preview = apply_retention(
        db,
        tenant_id=tid,
        retention_days=retention_days,
        policy_obj=policy_obj,
        triggered_by=_principal(request),
        reason_code=reason,
        ticket_id=ticket,
        dry_run=True,
        confirmation_token=None,
    )
    if dry_run:
        token = hashlib.sha256(
            (
                f"{tid}:{retention_days}:{preview['policy_hash']}:{preview['affected_exports_digest']}:"
                f"{preview['affected_jobs_digest']}:{ticket}"
            ).encode("utf-8")
        ).hexdigest()
        return {"tenant_id": tid, **preview, "confirmation_token": token}

    confirmation_token = str(body.confirmation_token or "").strip()
    try:
        result = apply_retention(
            db,
            tenant_id=tid,
            retention_days=retention_days,
            policy_obj=policy_obj,
            triggered_by=_principal(request),
            reason_code=reason,
            ticket_id=ticket,
            dry_run=False,
            confirmation_token=confirmation_token,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail={"code": str(exc), "message": "confirmation required"})
    return {"tenant_id": tid, **result}


@router.get("/export", dependencies=[Depends(require_scopes("audit:export"))])
def audit_export(
    request: Request,
    start: str = Query(...),
    end: str = Query(...),
    tenant_id: str | None = Query(default=None),
    purpose: str = Query(default="compliance-review"),
    retention_class: str = Query(default="regulated"),
    force: bool = Query(default=False),
    db: Session = Depends(tenant_db_session),
):
    tid = _resolve_tenant(request, tenant_id)
    _rate_limit(request, tid, "export", db)
    set_tenant_context(db, tid)
    try:
        start_dt = datetime.fromisoformat(start.replace("Z", "+00:00")).astimezone(UTC)
        end_dt = datetime.fromisoformat(end.replace("Z", "+00:00")).astimezone(UTC)
    except Exception:
        raise HTTPException(status_code=400, detail={"code": "FG-AUDIT-TIME-400", "message": "invalid UTC range"})

    actor = _principal_strict(request)
    row_count = (
        db.query(AuditLedgerRecord.id)
        .filter(AuditLedgerRecord.tenant_id == tid, AuditLedgerRecord.created_at >= start_dt, AuditLedgerRecord.created_at <= end_dt)
        .count()
    )
    if row_count > int(os.getenv("FG_AUDIT_SYNC_EXPORT_MAX_ROWS", "5000")):
        job = enqueue_export_job(
            db,
            tenant_id=tid,
            start=start_dt,
            end=end_dt,
            purpose=purpose,
            retention_class=retention_class,
            triggered_by=str(actor),
            force=force,
        )
        raise HTTPException(status_code=202, detail={"code": "FG-AUDIT-EXPORT-QUEUED", "job_id": job.job_id, "status": job.status})

    return export_evidence_bundle(
        db,
        tenant_id=tid,
        start=start_dt,
        end=end_dt,
        purpose=purpose,
        triggered_by=str(actor),
        retention_class=retention_class,
        force=force,
    )


@router.post("/export-jobs", dependencies=[Depends(require_scopes("audit:export"))])
def create_export_job(request: Request, body: ExportJobRequest = Body(...), tenant_id: str | None = Query(default=None), db: Session = Depends(tenant_db_session)):
    tid = _resolve_tenant(request, tenant_id)
    set_tenant_context(db, tid)
    start_dt = datetime.fromisoformat(str(body.start).replace("Z", "+00:00")).astimezone(UTC)
    end_dt = datetime.fromisoformat(str(body.end).replace("Z", "+00:00")).astimezone(UTC)
    actor = _principal(request)
    job = enqueue_export_job(
        db,
        tenant_id=tid,
        start=start_dt,
        end=end_dt,
        purpose=str(body.purpose),
        retention_class=str(body.retention_class),
        triggered_by=str(actor),
        force=bool(body.force),
        signing_kid=str(body.signing_kid),
        end_inclusive=bool(body.end_inclusive),
    )
    return {"tenant_id": tid, "job_id": job.job_id, "status": job.status, "idempotency_key": job.idempotency_key}


@router.get("/export-jobs/{job_id}", dependencies=[Depends(require_scopes("audit:read"))])
def get_export_job(request: Request, job_id: str, tenant_id: str | None = Query(default=None), db: Session = Depends(tenant_db_session)):
    tid = _resolve_tenant(request, tenant_id)
    set_tenant_context(db, tid)
    row = db.query(AuditExportJob).filter(AuditExportJob.tenant_id == tid, AuditExportJob.job_id == job_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail={"code": "FG-AUDIT-JOB-404", "message": "job not found"})
    return {
        "tenant_id": tid,
        "job_id": row.job_id,
        "status": row.status,
        "attempts": row.attempts,
        "last_error_code": row.last_error_code,
        "export_id": row.export_id,
        "storage_uri": row.storage_uri,
    }


@router.post("/export-jobs/{job_id}/run", dependencies=[Depends(require_scopes("audit:export"))])
def run_job(request: Request, job_id: str, tenant_id: str | None = Query(default=None), db: Session = Depends(tenant_db_session)):
    tid = _resolve_tenant(request, tenant_id)
    set_tenant_context(db, tid)
    try:
        row = run_export_job(db, tenant_id=tid, job_id=job_id, worker_id=_principal(request))
    except RuntimeError as exc:
        if str(exc) == "AUDIT_EXPORT_JOB_LEASED":
            raise HTTPException(status_code=409, detail={"job_id": job_id, "status": "running", "error_code": "AUDIT_EXPORT_JOB_LEASED"})
        raise HTTPException(status_code=409, detail={"job_id": job_id, "status": None, "error_code": "AUDIT_EXPORT_JOB_TERMINAL_STATE"})
    except ValueError:
        raise HTTPException(status_code=404, detail={"job_id": job_id, "status": None, "error_code": "AUDIT_EXPORT_JOB_NOT_FOUND"})

    if row.status == "failed":
        raise HTTPException(status_code=500, detail={"job_id": row.job_id, "status": row.status, "error_code": row.last_error_code or "AUDIT_EXPORT_JOB_RUN_FAILED"})
    if row.status == "cancelled":
        raise HTTPException(status_code=409, detail={"job_id": row.job_id, "status": row.status, "error_code": "AUDIT_EXPORT_JOB_CANCELLED"})
    return {"tenant_id": tid, "job_id": row.job_id, "status": row.status, "export_id": row.export_id, "storage_uri": row.storage_uri}


@router.post("/export-jobs/{job_id}/cancel", dependencies=[Depends(require_scopes("audit:export"))])
def cancel_job(
    request: Request,
    job_id: str,
    body: CancelJobRequest = Body(default_factory=CancelJobRequest),
    tenant_id: str | None = Query(default=None),
    db: Session = Depends(tenant_db_session),
):
    tid = _resolve_tenant(request, tenant_id)
    set_tenant_context(db, tid)
    row = db.query(AuditExportJob).filter(AuditExportJob.tenant_id == tid, AuditExportJob.job_id == job_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail={"job_id": job_id, "status": None, "error_code": "AUDIT_EXPORT_JOB_NOT_FOUND"})

    reason, ticket_id, notes = _assert_cancel_payload(body)
    actor = _principal_strict(request)
    _enforce_cancel_rate_limit(tenant_id=tid, actor=actor)
    scopes = _scopes(request)
    allowed, is_bypass = _can_cancel_job(row=row, actor=actor, scopes=scopes)
    if not allowed:
        raise HTTPException(status_code=403, detail={"job_id": job_id, "status": row.status, "error_code": "AUDIT_EXPORT_JOB_FORBIDDEN"})

    if is_bypass:
        if not str(body.ticket_id).strip():
            raise HTTPException(status_code=400, detail={"job_id": job_id, "status": row.status, "error_code": "AUDIT_EXPORT_JOB_TICKET_REQUIRED"})
        _enforce_cancel_bypass_rate_limit(tenant_id=tid, actor=actor)

    try:
        row = cancel_export_job(
            db,
            tenant_id=tid,
            job_id=job_id,
            cancelled_by=actor,
            reason_code=reason,
            ticket_id=ticket_id,
            notes=notes,
            bypass=is_bypass,
        )
    except RuntimeError:
        raise HTTPException(status_code=409, detail={"job_id": row.job_id, "status": row.status, "error_code": "AUDIT_EXPORT_JOB_TERMINAL_STATE"})

    return {"job_id": row.job_id, "status": row.status, "error_code": None}


@router.post("/reproduce", dependencies=[Depends(require_scopes("audit:reproduce"))])
def audit_reproduce(request: Request, body: ReproduceRequest = Body(...), tenant_id: str | None = Query(default=None), db: Session = Depends(tenant_db_session)):
    tid = _resolve_tenant(request, tenant_id)
    _rate_limit(request, tid, "reproduce", db)
    set_tenant_context(db, tid)
    session_id = int(body.audit_session_id)
    result = reproduce_audit_session(db, tenant_id=tid, session_id=session_id)
    if result.get("verification_result") != "pass":
        raise HTTPException(status_code=409, detail=result)
    return result
