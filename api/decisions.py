from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session

from api.auth import verify_api_key
from api.db import get_db
from api.db_models import DecisionRecord

router = APIRouter(
    prefix="/decisions",
    tags=["decisions"],
    dependencies=[Depends(verify_api_key)],
)

MAX_PAGE_SIZE = 100


def _clamp_page_size(n: int) -> int:
    return max(1, min(MAX_PAGE_SIZE, n))


def _parse_cursor(cursor: Optional[str]) -> Optional[tuple[datetime, str]]:
    if not cursor:
        return None
    try:
        ts_str, id_str = cursor.split("|", 1)
        ts = datetime.fromisoformat(ts_str)
        return ts, id_str
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid cursor format. Expected '<iso>|<id>'")


@router.get("")
def list_decisions(
    db: Session = Depends(get_db),
    cursor: Optional[str] = Query(None, description="Keyset cursor: '<iso_created_at>|<id>'"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=MAX_PAGE_SIZE),
    tenant_id: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    threat_level: Optional[str] = Query(None),
    since: Optional[datetime] = Query(None),
    until: Optional[datetime] = Query(None),
) -> dict[str, Any]:
    page_size = _clamp_page_size(page_size)

    q = db.query(
        DecisionRecord.id,
        DecisionRecord.created_at,
        DecisionRecord.tenant_id,
        DecisionRecord.source,
        DecisionRecord.event_type,
        DecisionRecord.threat_level,
        DecisionRecord.anomaly_score,
        DecisionRecord.ai_adversarial_score,
        DecisionRecord.pq_fallback,
        DecisionRecord.rules_triggered,
        DecisionRecord.explain_summary,
        DecisionRecord.latency_ms,
    )

    filters = []
    if tenant_id:
        filters.append(DecisionRecord.tenant_id == tenant_id)
    if source:
        filters.append(DecisionRecord.source == source)
    if event_type:
        filters.append(DecisionRecord.event_type == event_type)
    if threat_level:
        filters.append(DecisionRecord.threat_level == threat_level)
    if since:
        filters.append(DecisionRecord.created_at >= since)
    if until:
        filters.append(DecisionRecord.created_at <= until)

    if filters:
        q = q.filter(and_(*filters))

    total = db.query(func.count(DecisionRecord.id))
    if filters:
        total = total.filter(and_(*filters))
    total_count = int(total.scalar() or 0)

    q = q.order_by(DecisionRecord.created_at.desc(), DecisionRecord.id.desc())

    cur = _parse_cursor(cursor)
    if cur:
        cur_ts, cur_id = cur
        q = q.filter(
            or_(
                DecisionRecord.created_at < cur_ts,
                and_(DecisionRecord.created_at == cur_ts, DecisionRecord.id < cur_id),
            )
        )
        rows = q.limit(page_size).all()
    else:
        rows = q.offset((page - 1) * page_size).limit(page_size).all()

    items = [{
        "id": r.id,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "tenant_id": r.tenant_id,
        "source": r.source,
        "event_type": r.event_type,
        "threat_level": r.threat_level,
        "anomaly_score": r.anomaly_score,
        "ai_adversarial_score": r.ai_adversarial_score,
        "pq_fallback": bool(r.pq_fallback),
        "rules_triggered": r.rules_triggered,
        "explain_summary": r.explain_summary,
        "latency_ms": r.latency_ms,
    } for r in rows]

    next_cursor = None
    if items:
        last = items[-1]
        if last["created_at"] and last["id"]:
            next_cursor = f'{last["created_at"]}|{last["id"]}'

    return {
        "items": items,
        "total": total_count,
        "page": page,
        "page_size": page_size,
        "next_cursor": next_cursor,
    }
