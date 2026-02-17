from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from api.auth_scopes import bind_tenant_id, require_api_key_always, require_scopes
from api.deps import tenant_db_session
from api.db import set_tenant_context
from api.db_models import AuditLedgerRecord
from services.audit_engine.engine import verify_audit_chain

router = APIRouter(prefix="/ui/audit", tags=["ui-audit"], dependencies=[Depends(require_api_key_always)])


def _tenant(request: Request, tenant_id: str | None) -> str:
    resolved = bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    if not resolved:
        raise HTTPException(status_code=403, detail={"code": "FG-AUDIT-AUTH-403", "message": "tenant binding required"})
    return resolved


@router.get("/overview", dependencies=[Depends(require_scopes("audit:read"))])
def ui_audit_overview(request: Request, tenant_id: str | None = Query(default=None), db: Session = Depends(tenant_db_session)):
    tid = _tenant(request, tenant_id)
    set_tenant_context(db, tid)
    last = (
        db.query(AuditLedgerRecord)
        .filter(AuditLedgerRecord.tenant_id == tid)
        .order_by(AuditLedgerRecord.id.desc())
        .first()
    )
    return {
        "tenant_id": tid,
        "current_invariant_status": last.decision if last else "unknown",
        "drift_status": "pass" if (last and last.invariant_id == "drift-verification" and last.decision == "pass") else "unknown",
        "last_reproducibility_test": last.timestamp_utc if last else None,
        "policy_hash": last.policy_hash if last else None,
        "config_hash": last.config_hash if last else None,
    }


@router.get("/status", dependencies=[Depends(require_scopes("audit:read"))])
def ui_audit_status(request: Request, tenant_id: str | None = Query(default=None), db: Session = Depends(tenant_db_session)):
    tid = _tenant(request, tenant_id)
    set_tenant_context(db, tid)
    since = datetime.now(tz=UTC) - timedelta(hours=1)
    rows = (
        db.query(AuditLedgerRecord)
        .filter(AuditLedgerRecord.tenant_id == tid, AuditLedgerRecord.created_at >= since)
        .order_by(AuditLedgerRecord.id.asc())
        .all()
    )
    return {"tenant_id": tid, "window": "1h", "pass": sum(1 for r in rows if r.decision == "pass"), "fail": sum(1 for r in rows if r.decision == "fail")}


@router.get("/chain-integrity", dependencies=[Depends(require_scopes("audit:read"))])
def ui_audit_chain_integrity(request: Request, tenant_id: str | None = Query(default=None), db: Session = Depends(tenant_db_session)):
    tid = _tenant(request, tenant_id)
    set_tenant_context(db, tid)
    result = verify_audit_chain(db, tenant_id=tid)
    return {"tenant_id": tid, "status": "ok" if result.get("ok") else "failed", "details": result}


@router.get("/export-link", dependencies=[Depends(require_scopes("audit:read"))])
def ui_audit_export_link():
    return {"download_evidence_bundle": "/audit/export?start=2020-01-01T00:00:00Z&end=2100-01-01T00:00:00Z"}
