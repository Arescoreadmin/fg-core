from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import and_, asc, desc, or_
from sqlalchemy.orm import Session

from api.auth_scopes import bind_tenant_id, require_scopes
from api.db import get_engine
from api.db_models import SecurityAuditLog
from api.entitlements import require_capability

router = APIRouter(
    tags=["ui-forensics"], dependencies=[Depends(require_scopes("ui:read"))]
)


def _safe_event(row: SecurityAuditLog) -> dict[str, Any]:
    created_at = row.created_at
    if created_at is not None and created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return {
        "event_id": row.id,
        "event_type": row.event_type,
        "event_category": getattr(row, "event_category", "security"),
        "severity": row.severity,
        "request_id": row.request_id,
        "request_path": row.request_path,
        "request_method": row.request_method,
        "success": row.success,
        "reason": row.reason,
        "created_at": created_at.isoformat() if created_at else None,
    }


def _tenant_filter(tenant_id: str):  # type: ignore[return]
    """Return a SQLAlchemy filter covering modern AND legacy-migrated rows.

    Modern rows:   chain_id == tenant_id (set by SecurityAuditor._persist_event)
    Legacy rows:   tenant_id == tenant_id AND chain_id IN ('global', NULL)
                   (chain_id column added by _auto_migrate_sqlite with DEFAULT 'global')

    This preserves tenant isolation: the legacy branch requires tenant_id to match, so
    chain_id='global' rows belonging to other tenants or system-only events
    (tenant_id IS NULL) are never returned.
    """
    return or_(
        SecurityAuditLog.chain_id == tenant_id,
        and_(
            SecurityAuditLog.tenant_id == tenant_id,
            SecurityAuditLog.chain_id.in_(["global", None]),
        ),
    )


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


@router.get("/ui/forensics/events")
def ui_forensics_events(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    event_type: Optional[str] = Query(default=None, max_length=64),
    severity: Optional[str] = Query(default=None, max_length=16),
    success: Optional[bool] = Query(default=None),
    request_id: Optional[str] = Query(default=None, max_length=64),
    from_: Optional[str] = Query(default=None, alias="from"),
    to: Optional[str] = Query(default=None),
) -> dict[str, Any]:
    tenant_id = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    engine = get_engine()
    with Session(engine) as session:
        q = session.query(SecurityAuditLog).filter(_tenant_filter(tenant_id))
        if event_type:
            q = q.filter(SecurityAuditLog.event_type == event_type)
        if severity:
            q = q.filter(SecurityAuditLog.severity == severity)
        if success is not None:
            q = q.filter(SecurityAuditLog.success == success)
        if request_id:
            q = q.filter(SecurityAuditLog.request_id == request_id)
        from_dt = _parse_dt(from_)
        if from_dt is not None:
            q = q.filter(SecurityAuditLog.created_at >= from_dt)
        to_dt = _parse_dt(to)
        if to_dt is not None:
            q = q.filter(SecurityAuditLog.created_at <= to_dt)

        total = q.count()
        rows = (
            q.order_by(desc(SecurityAuditLog.created_at), desc(SecurityAuditLog.id))
            .offset(offset)
            .limit(limit)
            .all()
        )

    return {
        "events": [_safe_event(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/ui/forensics/trace/{request_id}")
def ui_forensics_trace(
    request: Request,
    request_id: str,
) -> dict[str, Any]:
    if not request_id or len(request_id) > 64:
        raise HTTPException(
            status_code=422,
            detail="request_id must be non-empty and at most 64 characters",
        )
    tenant_id = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    engine = get_engine()
    with Session(engine) as session:
        rows = (
            session.query(SecurityAuditLog)
            .filter(
                _tenant_filter(tenant_id),
                SecurityAuditLog.request_id == request_id,
            )
            .order_by(asc(SecurityAuditLog.created_at), asc(SecurityAuditLog.id))
            .limit(200)
            .all()
        )

    events = [_safe_event(row) for row in rows]
    return {
        "request_id": request_id,
        "events": events,
        "event_count": len(events),
        "trace_available": len(events) > 0,
    }


@router.get(
    "/ui/forensics/events/export",
    dependencies=[Depends(require_capability("audit.forensics"))],
)
def ui_forensics_export(
    request: Request,
    from_: Optional[str] = Query(default=None, alias="from"),
    to: Optional[str] = Query(default=None),
    event_type: Optional[str] = Query(default=None, max_length=64),
    severity: Optional[str] = Query(default=None, max_length=16),
) -> dict[str, Any]:
    tenant_id = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    engine = get_engine()

    filters_applied: dict[str, str] = {}
    if event_type:
        filters_applied["event_type"] = event_type
    if severity:
        filters_applied["severity"] = severity
    if from_:
        filters_applied["from"] = from_
    if to:
        filters_applied["to"] = to

    with Session(engine) as session:
        q = session.query(SecurityAuditLog).filter(_tenant_filter(tenant_id))
        if event_type:
            q = q.filter(SecurityAuditLog.event_type == event_type)
        if severity:
            q = q.filter(SecurityAuditLog.severity == severity)
        from_dt = _parse_dt(from_)
        if from_dt is not None:
            q = q.filter(SecurityAuditLog.created_at >= from_dt)
        to_dt = _parse_dt(to)
        if to_dt is not None:
            q = q.filter(SecurityAuditLog.created_at <= to_dt)

        rows = (
            q.order_by(desc(SecurityAuditLog.created_at), desc(SecurityAuditLog.id))
            .limit(500)
            .all()
        )

    events = [_safe_event(row) for row in rows]
    return {
        "export_safe": True,
        "redactions_applied": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "filters_applied": filters_applied,
        "event_count": len(events),
        "limitation_note": "Export is limited to 500 events. Excludes key_prefix, client_ip, user_agent, prev_hash, entry_hash, chain_id, and details_json fields.",
        "events": events,
    }
