from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from api.db_models import AuditLedgerRecord
from services.audit_engine import AuditEngine
from services.audit_engine.engine import AuditIntegrityError
from services.compliance_registry import ComplianceRegistry

router = APIRouter(tags=["audit"])


class ReproduceRequest(BaseModel):
    session_id: str


class ExamRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    window_start_utc: str
    window_end_utc: str


@router.get("/audit/sessions", dependencies=[Depends(require_scopes("audit:read"))])
def audit_sessions(request: Request) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as session:
        rows = (
            session.query(
                AuditLedgerRecord.session_id,
                AuditLedgerRecord.cycle_kind,
                func.min(AuditLedgerRecord.timestamp_utc).label("started_at"),
                func.max(AuditLedgerRecord.timestamp_utc).label("ended_at"),
                func.count(AuditLedgerRecord.id).label("records"),
            )
            .filter(AuditLedgerRecord.tenant_id == tenant_id)
            .group_by(AuditLedgerRecord.session_id, AuditLedgerRecord.cycle_kind)
            .order_by(func.max(AuditLedgerRecord.id).desc())
            .all()
        )
    return {
        "sessions": [
            {
                "session_id": r[0],
                "cycle_kind": r[1],
                "started_at": r[2],
                "ended_at": r[3],
                "records": int(r[4]),
            }
            for r in rows
        ]
    }


@router.get("/audit/export", dependencies=[Depends(require_scopes("audit:export"))])
def audit_export(
    request: Request,
    start: str = Query(...),
    end: str = Query(...),
) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    engine = AuditEngine()
    try:
        return engine.export_bundle(
            start=start,
            end=end,
            tenant_id=tenant_id,
            app_openapi=request.app.openapi(),
        )
    except AuditIntegrityError as exc:
        raise HTTPException(
            status_code=409, detail={"code": exc.code, "message": str(exc)}
        )


@router.post("/audit/reproduce", dependencies=[Depends(require_scopes("audit:write"))])
def audit_reproduce(body: ReproduceRequest) -> dict[str, object]:
    engine = AuditEngine()
    result = engine.reproduce_session(body.session_id)
    if not result.get("ok"):
        raise HTTPException(
            status_code=409,
            detail={"code": result.get("code", "AUDIT_REPRO_FAILED"), **result},
        )
    return result


@router.get(
    "/audit/exam-snapshot", dependencies=[Depends(require_scopes("audit:read"))]
)
def exam_snapshot(request: Request) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    engine = AuditEngine()
    exams = engine.list_exams(tenant_id)
    latest = exams[0] if exams else None
    snap = ComplianceRegistry().snapshot(tenant_id)
    with Session(get_engine()) as session:
        integrity_ok = engine.verify_chain_integrity(session)
    return {
        "integrity_status": "ok" if integrity_ok else "failed",
        "last_exam": latest,
        "required_controls_status": snap.get("coverage"),
        "waiver_counts": {
            "expired_waiver_count": snap.get("expired_waiver_count", 0),
            "unknown_critical_count": snap.get("unknown_critical_count", 0),
            "unknown_critical_threshold": snap.get("unknown_critical_threshold", 0),
        },
        "requirements_stale": snap.get("requirements_stale", False),
        "stale_requirement_sources": snap.get("stale_requirement_sources", []),
    }


@router.get("/audit/exams", dependencies=[Depends(require_scopes("audit:read"))])
def list_exams(request: Request) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    return {"exams": AuditEngine().list_exams(tenant_id)}


@router.post("/audit/exams/run", dependencies=[Depends(require_scopes("audit:write"))])
def run_exam(request: Request, body: ExamRunRequest) -> dict[str, str]:
    tenant_id = require_bound_tenant(request)
    exam_id = AuditEngine().create_exam(
        tenant_id=tenant_id,
        name=body.name,
        window_start=body.window_start_utc,
        window_end=body.window_end_utc,
    )
    return {"exam_id": exam_id}


@router.get(
    "/audit/exams/{exam_id}/export",
    dependencies=[Depends(require_scopes("audit:export"))],
)
def export_exam(exam_id: str, request: Request) -> dict[str, object]:
    return AuditEngine().export_exam_bundle(
        exam_id=exam_id, app_openapi=request.app.openapi()
    )


@router.post(
    "/audit/exams/{exam_id}/reproduce",
    dependencies=[Depends(require_scopes("audit:write"))],
)
def reproduce_exam(exam_id: str) -> dict[str, object]:
    result = AuditEngine().reproduce_exam(exam_id)
    if not result.get("ok"):
        raise HTTPException(
            status_code=409,
            detail={"code": result.get("code", "AUDIT_REPRO_FAILED"), **result},
        )
    return result
