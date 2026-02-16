# api/decisions.py
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from api.auth_scopes import redact_detail, require_bound_tenant, require_scopes
from api.deps import tenant_db_required
from api.db_models import DecisionRecord

log = logging.getLogger("frostgate.decisions")

router = APIRouter(prefix="/decisions", tags=["decisions"])


# -------------------------
# Helpers
# -------------------------


def _iso(dt: Any) -> Optional[str]:
    if dt is None:
        return None
    if isinstance(dt, datetime):
        try:
            return dt.isoformat()
        except Exception:
            return str(dt)
    try:
        return str(dt)
    except Exception:
        return None


def _loads_json_text(v):
    if v is None:
        return None
    # if ORM gives us dict/list already, keep it
    if isinstance(v, (dict, list)):
        return v
    if isinstance(v, (bytes, bytearray)):
        v = v.decode("utf-8", errors="ignore")
    if isinstance(v, str):
        v = v.strip()
        if not v:
            return None
        try:
            import json

            return json.loads(v)
        except Exception:
            return None
    return None


# -------------------------
# Response Models
# -------------------------


class DecisionOut(BaseModel):
    id: int
    created_at: Optional[str] = None

    tenant_id: Optional[str]
    source: str
    event_id: str
    event_type: str

    threat_level: str
    anomaly_score: float
    ai_adversarial_score: float
    pq_fallback: bool
    config_hash: str

    rules_triggered: Optional[Any] = None
    explain_summary: Optional[str] = None
    latency_ms: int = 0

    request: Optional[Any] = None
    response: Optional[Any] = None
    decision_diff: Optional[Any] = None


class DecisionsPage(BaseModel):
    items: list[DecisionOut] = Field(default_factory=list)
    limit: int
    offset: int
    total: int


# -------------------------
# Routes
# -------------------------


@router.get(
    "",
    response_model=DecisionsPage,
    dependencies=[Depends(require_scopes("decisions:read"))],
)
def list_decisions(
    request: Request,
    db: Session = Depends(tenant_db_required),
    limit: int = Query(20, ge=1, le=200),
    offset: int = Query(0, ge=0, le=200000),
    include_raw: bool = Query(
        False, description="Include request/response JSON blobs (slower)"
    ),
    tenant_id: Optional[str] = Query(None, min_length=1),
    event_type: Optional[str] = Query(None, min_length=1),
    threat_level: Optional[str] = Query(None, min_length=1),
) -> DecisionsPage:
    try:
        # P0: Require tenant_id for all requests - no cross-tenant access allowed
        tenant_id = require_bound_tenant(request)

        # Build WHERE clauses once - tenant_id is ALWAYS required
        where = [DecisionRecord.tenant_id == tenant_id]  # P0: Always filter by tenant
        if event_type:
            where.append(DecisionRecord.event_type == event_type)
        if threat_level:
            where.append(DecisionRecord.threat_level == threat_level)

        # Total count
        count_stmt = select(func.count()).select_from(DecisionRecord)
        if where:
            for w in where:
                count_stmt = count_stmt.where(w)
        total = int(db.execute(count_stmt).scalar_one())

        # Page rows
        stmt = select(DecisionRecord)
        if where:
            for w in where:
                stmt = stmt.where(w)

        stmt = (
            stmt.order_by(desc(DecisionRecord.created_at), desc(DecisionRecord.id))
            .limit(limit)
            .offset(offset)
        )

        rows = db.execute(stmt).scalars().all()

        items: list[DecisionOut] = []
        for r in rows:
            out = DecisionOut(
                id=int(r.id),
                created_at=_iso(getattr(r, "created_at", None)),
                tenant_id=r.tenant_id,
                source=r.source,
                event_id=str(r.event_id),
                event_type=r.event_type,
                threat_level=r.threat_level,
                anomaly_score=float(getattr(r, "anomaly_score", 0.0) or 0.0),
                ai_adversarial_score=float(
                    getattr(r, "ai_adversarial_score", 0.0) or 0.0
                ),
                pq_fallback=bool(getattr(r, "pq_fallback", False)),
                config_hash=str(getattr(r, "config_hash", "")),
                rules_triggered=_loads_json_text(
                    getattr(r, "rules_triggered_json", None)
                ),
                explain_summary=getattr(r, "explain_summary", None),
                decision_diff=_loads_json_text(getattr(r, "decision_diff_json", None)),
                latency_ms=int(getattr(r, "latency_ms", 0) or 0),
            )

            if include_raw:
                out.request = _loads_json_text(getattr(r, "request_json", None))
                out.response = _loads_json_text(getattr(r, "response_json", None))

            items.append(out)

        return DecisionsPage(items=items, limit=limit, offset=offset, total=total)

    except HTTPException:
        raise
    except Exception:
        log.exception("decisions.list FAILED")
        raise HTTPException(status_code=500, detail="Internal Server Error")


@router.get(
    "/{decision_id}",
    response_model=DecisionOut,
    dependencies=[Depends(require_scopes("decisions:read"))],
)
def get_decision(
    decision_id: int,
    request: Request,
    db: Session = Depends(tenant_db_required),
    include_raw: bool = Query(True, description="Include request/response JSON blobs"),
    tenant_id: Optional[str] = Query(None, min_length=1),
) -> DecisionOut:
    try:
        # P0: Require tenant_id for all requests - no cross-tenant access allowed
        resolved_tenant = require_bound_tenant(request)

        r = db.get(DecisionRecord, decision_id)
        if r is None:
            raise HTTPException(status_code=404, detail="Decision not found")

        # P0: ALWAYS check tenant isolation - no exceptions
        if r.tenant_id != resolved_tenant:
            raise HTTPException(
                status_code=403,
                detail=redact_detail("tenant mismatch", generic="forbidden"),
            )

        out = DecisionOut(
            id=int(r.id),
            created_at=_iso(getattr(r, "created_at", None)),
            tenant_id=r.tenant_id,
            source=r.source,
            event_id=str(r.event_id),
            event_type=r.event_type,
            threat_level=r.threat_level,
            anomaly_score=float(getattr(r, "anomaly_score", 0.0) or 0.0),
            ai_adversarial_score=float(getattr(r, "ai_adversarial_score", 0.0) or 0.0),
            pq_fallback=bool(getattr(r, "pq_fallback", False)),
            config_hash=str(getattr(r, "config_hash", "")),
            rules_triggered=_loads_json_text(getattr(r, "rules_triggered_json", None)),
            explain_summary=getattr(r, "explain_summary", None),
            latency_ms=int(getattr(r, "latency_ms", 0) or 0),
        )

        if include_raw:
            out.request = _loads_json_text(getattr(r, "request_json", None))
            out.response = _loads_json_text(getattr(r, "response_json", None))

        return out

    except HTTPException:
        raise
    except Exception:
        log.exception("decisions.get FAILED id=%s", decision_id)
        raise HTTPException(status_code=500, detail="Internal Server Error")
