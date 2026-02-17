from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from api.db_models import AuditExamSession, AuditLedgerRecord, ComplianceSnapshotRecord
from services.audit_engine import AuditEngine

router = APIRouter(tags=["ui-audit"], dependencies=[Depends(require_scopes("ui:read"))])


@router.get("/ui/audit/overview")
def ui_audit_overview(request: Request) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as session:
        latest = (
            session.query(AuditLedgerRecord)
            .filter(AuditLedgerRecord.tenant_id == tenant_id)
            .order_by(AuditLedgerRecord.id.desc())
            .limit(1)
            .one_or_none()
        )
        snap = (
            session.query(ComplianceSnapshotRecord)
            .filter(ComplianceSnapshotRecord.tenant_id == tenant_id)
            .order_by(ComplianceSnapshotRecord.id.desc())
            .limit(1)
            .one_or_none()
        )
    return {
        "current_invariant_status": latest.decision if latest else "unknown",
        "drift_status": latest.decision
        if latest and latest.invariant_id == "drift-verification"
        else "unknown",
        "last_reproducibility_test": (snap.summary_json or {}).get(
            "last_reproduce_result"
        )
        if snap
        else None,
        "policy_hash": latest.policy_hash if latest else None,
        "config_hash": latest.config_hash if latest else None,
    }


@router.get("/ui/audit/status")
def ui_audit_status(request: Request) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as session:
        counts = (
            session.query(
                func.count(AuditLedgerRecord.id),
                func.sum(case((AuditLedgerRecord.decision == "fail", 1), else_=0)),
            )
            .filter(AuditLedgerRecord.tenant_id == tenant_id)
            .one()
        )
    return {"records": int(counts[0] or 0), "failed_records": int(counts[1] or 0)}


@router.get("/ui/audit/chain-integrity")
def ui_audit_chain_integrity(request: Request) -> dict[str, object]:
    _ = require_bound_tenant(request)
    with Session(get_engine()) as session:
        ok = AuditEngine().verify_chain_integrity(session)
    return {"audit_chain_integrity": "ok" if ok else "broken"}


@router.get("/ui/audit/export-link")
def ui_audit_export_link(request: Request) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as session:
        exam = (
            session.query(AuditExamSession)
            .filter(AuditExamSession.tenant_id == tenant_id)
            .order_by(AuditExamSession.id.desc())
            .limit(1)
            .one_or_none()
        )
    if exam is None:
        return {"download_evidence_bundle": None}
    return {"download_evidence_bundle": f"/audit/exams/{exam.exam_id}/export"}
