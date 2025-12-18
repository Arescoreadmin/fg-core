from __future__ import annotations

import json
import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from api.auth_scopes import require_scope, verify_api_key
from api.db import get_db
from api.db_models import DecisionRecord
from api.ratelimit import rate_limit_guard

log = logging.getLogger("frostgate.decisions")

router = APIRouter(
    prefix="/decisions",
    tags=["decisions"],
    dependencies=[
        Depends(verify_api_key),
        Depends(require_scope("decisions:read")),
        Depends(rate_limit_guard),
    ],
)

# -------------------------
# Helpers
# -------------------------

def _iso(dt: Any) -> Optional[str]:
    if dt is None:
        return None
    try:
        return dt.isoformat()
    except Exception:
        return str(dt)

def _loads_maybe(s: Optional[str]) -> Any:
    if not s:
        return None
    try:
        return json.loads(s)
    except Exception:
        return s  # keep raw string if it's not valid JSON

# -------------------------
# Response Models
# -------------------------

class DecisionOut(BaseModel):
    id: int
    created_at: Optional[str] = None

    tenant_id: str
    source: str
    event_id: str
    event_type: str

    threat_level: str
    anomaly_score: float
    ai_adversarial_score: float
    pq_fallback: bool

    rules_triggered: Optional[Any] = None
    explain_summary: Optional[str] = None
    latency_ms: int = 0

    request: Optional[Any] = None
    response: Optional[Any] = None


class DecisionsPage(BaseModel):
    items: list[DecisionOut] = Field(default_factory=list)
    limit: int
    offset: int
    total: int


# -------------------------
# Routes
# -------------------------

@router.get("", response_model=DecisionsPage)
def list_decisions(
    db: Session = Depends(get_db),
    tenant_id: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    include_raw: bool = Query(default=False),
) -> DecisionsPage:
    try:
        log.info("decisions.list start tenant_id=%s limit=%s offset=%s include_raw=%s", tenant_id, limit, offset, include_raw)

        # total count (fast and boring)
        count_stmt = select(func.count()).select_from(DecisionRecord)
        if tenant_id:
            count_stmt = count_stmt.where(DecisionRecord.tenant_id == tenant_id)
        total = int(db.execute(count_stmt).scalar_one())

        # page items
        stmt = select(DecisionRecord)
        if tenant_id:
            stmt = stmt.where(DecisionRecord.tenant_id == tenant_id)

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
                event_id=r.event_id,
                event_type=r.event_type,
                threat_level=r.threat_level,
                anomaly_score=float(r.anomaly_score or 0.0),
                ai_adversarial_score=float(r.ai_adversarial_score or 0.0),
                pq_fallback=bool(r.pq_fallback),
                rules_triggered=_loads_maybe(getattr(r, "rules_triggered_json", None)),
                explain_summary=getattr(r, "explain_summary", None),
                latency_ms=int(getattr(r, "latency_ms", 0) or 0),
            )

            if include_raw:
                out.request = _loads_maybe(getattr(r, "request_json", None))
                out.response = _loads_maybe(getattr(r, "response_json", None))

            items.append(out)

        log.info("decisions.list ok total=%s returned=%s", total, len(items))
        return DecisionsPage(items=items, limit=limit, offset=offset, total=total)

    except Exception:
        log.exception("decisions.list FAILED")
        # If this throws, it's a server bug. We want the stack trace in logs.
        raise HTTPException(status_code=500, detail="Internal Server Error")


@router.get("/{decision_id}", response_model=DecisionOut)
def get_decision(
    decision_id: int,
    db: Session = Depends(get_db),
    include_raw: bool = Query(default=True),
) -> DecisionOut:
    try:
        r = db.get(DecisionRecord, decision_id)
        if r is None:
            raise HTTPException(status_code=404, detail="Decision not found")

        out = DecisionOut(
            id=int(r.id),
            created_at=_iso(getattr(r, "created_at", None)),
            tenant_id=r.tenant_id,
            source=r.source,
            event_id=r.event_id,
            event_type=r.event_type,
            threat_level=r.threat_level,
            anomaly_score=float(r.anomaly_score or 0.0),
            ai_adversarial_score=float(r.ai_adversarial_score or 0.0),
            pq_fallback=bool(r.pq_fallback),
            rules_triggered=_loads_maybe(getattr(r, "rules_triggered_json", None)),
            explain_summary=getattr(r, "explain_summary", None),
            latency_ms=int(getattr(r, "latency_ms", 0) or 0),
        )

        if include_raw:
            out.request = _loads_maybe(getattr(r, "request_json", None))
            out.response = _loads_maybe(getattr(r, "response_json", None))

        return out

    except HTTPException:
        raise
    except Exception:
        log.exception("decisions.get FAILED id=%s", decision_id)
        raise HTTPException(status_code=500, detail="Internal Server Error")
