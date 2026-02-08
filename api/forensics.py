from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from api.auth_scopes import require_scopes
from api.db_models import DecisionRecord
from api.deps import tenant_db_required
from api.evidence_chain import verify_chain_for_tenant


def _forensics_enabled() -> bool:
    # default ON; tests toggle this to "0" and expect 404
    return (os.getenv("FG_FORENSICS_ENABLED", "1") or "1").strip() == "1"


def require_forensics_enabled() -> None:
    # IMPORTANT: raise 404 (not 403/401) when disabled
    if not _forensics_enabled():
        raise HTTPException(status_code=404, detail="Not Found")


def forensics_enabled() -> bool:
    # used by api/main.py to decide whether to include router
    return _forensics_enabled()


router = APIRouter(prefix="/forensics", tags=["forensics"])


def _validate_event_id(event_id: str) -> str:
    eid = (event_id or "").strip()
    if not eid or len(eid) > 256:
        raise HTTPException(status_code=422, detail="Invalid event_id")
    return eid


@router.get(
    "/snapshot/{event_id}",
    dependencies=[
        Depends(require_forensics_enabled),
        Depends(require_scopes("forensics:read")),
    ],
)
def snapshot(
    event_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = getattr(request.state, "tenant_id", None)
    eid = _validate_event_id(event_id)

    rec = (
        db.query(DecisionRecord)
        .filter(
            DecisionRecord.tenant_id == tenant_id,
            DecisionRecord.event_id == eid,
        )
        .order_by(DecisionRecord.id.desc())
        .first()
    )
    if rec is None:
        # cross-tenant must look like not found
        raise HTTPException(status_code=404, detail="Not Found")

    created_at = getattr(rec, "created_at", None)
    return {
        "event_id": getattr(rec, "event_id", eid),
        "tenant_id": getattr(rec, "tenant_id", tenant_id),
        "created_at": created_at.isoformat() if created_at else None,
        "threat_level": getattr(rec, "threat_level", None),
        "rules_triggered": getattr(rec, "rules_triggered_json", None),
        "request": getattr(rec, "request_json", None),
        "response": getattr(rec, "response_json", None),
    }


@router.get(
    "/audit_trail/{event_id}",
    dependencies=[
        Depends(require_forensics_enabled),
        Depends(require_scopes("forensics:read")),
    ],
)
def audit_trail(
    event_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = getattr(request.state, "tenant_id", None)
    eid = _validate_event_id(event_id)

    rec = (
        db.query(DecisionRecord)
        .filter(
            DecisionRecord.tenant_id == tenant_id,
            DecisionRecord.event_id == eid,
        )
        .order_by(DecisionRecord.id.desc())
        .first()
    )
    if rec is None:
        raise HTTPException(status_code=404, detail="Not Found")

    created_at = getattr(rec, "created_at", None)
    chain_hash = getattr(rec, "chain_hash", None)
    prev_hash = getattr(rec, "prev_hash", None)

    return {
        "event_id": getattr(rec, "event_id", eid),
        "tenant_id": getattr(rec, "tenant_id", tenant_id),
        "timeline": [
            {
                "timestamp": created_at.isoformat() if created_at else None,
                "summary": "Decision recorded",
            }
        ],
        "reproducible": bool(chain_hash is not None or prev_hash is not None),
        "chain_hash": chain_hash,
        "prev_hash": prev_hash,
    }


@router.get(
    "/chain/verify",
    dependencies=[
        Depends(require_forensics_enabled),
        Depends(require_scopes("forensics:verify")),
    ],
)
def chain_verify(
    request: Request,
    db: Session = Depends(tenant_db_required),
    limit: int = Query(10, ge=1, le=500),
) -> dict[str, Any]:
    tenant_id = getattr(request.state, "tenant_id", None)
    result = verify_chain_for_tenant(db, tenant_id=tenant_id, limit=limit)

    if isinstance(result, dict):
        result.setdefault("tenant_id", tenant_id)
        return result

    return {"ok": True, "tenant_id": tenant_id, "result": result}
