"""Timeline Authority API — PR 14.6.2: Canonical Governance Ledger."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.deps import tenant_db_required
from services.timeline_authority import (
    TimelineAuthorityEngine,
    TimelineConflict,
    TimelineEventNotFound,
    TimelineEventRecordRequest,
    TimelineEventResponse,
    TimelineExportResponse,
    TimelineIntegrityResponse,
    TimelineReplayResponse,
    TimelineStatisticsResponse,
)

router = APIRouter(tags=["timeline-authority"])
engine = TimelineAuthorityEngine()


def _actor_from_request(request: Request) -> str:
    return (request.headers.get("X-Actor") or "unknown").strip() or "unknown"


def _translate_error(exc: Exception) -> HTTPException:
    if isinstance(exc, TimelineEventNotFound):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, TimelineConflict):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=500, detail="timeline_authority_error")


@router.post(
    "/timeline-authority/events",
    response_model=TimelineEventResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def record_timeline_event(
    request: Request,
    payload: TimelineEventRecordRequest,
    db: Session = Depends(tenant_db_required),
) -> TimelineEventResponse:
    tenant_id = require_bound_tenant(request)
    try:
        result = engine.record_event(
            db,
            tenant_id=tenant_id,
            actor=_actor_from_request(request),
            payload=payload,
        )
        db.commit()
        return result
    except Exception as exc:
        db.rollback()
        raise _translate_error(exc) from exc


@router.get(
    "/timeline-authority/events",
    response_model=list[TimelineEventResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_timeline_events(
    request: Request,
    entity_type: Optional[str] = Query(None),
    source_system: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(tenant_db_required),
) -> list[TimelineEventResponse]:
    tenant_id = require_bound_tenant(request)
    return engine.list_events(
        db,
        tenant_id=tenant_id,
        entity_type=entity_type,
        source_system=source_system,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/timeline-authority/events/{event_id}",
    response_model=TimelineEventResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_timeline_event(
    event_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> TimelineEventResponse:
    tenant_id = require_bound_tenant(request)
    try:
        return engine.get_event(db, tenant_id=tenant_id, event_id=event_id)
    except Exception as exc:
        raise _translate_error(exc) from exc


@router.get(
    "/timeline-authority/entities/{entity_type}/{entity_id}",
    response_model=list[TimelineEventResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_entity_timeline(
    entity_type: str,
    entity_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> list[TimelineEventResponse]:
    tenant_id = require_bound_tenant(request)
    return engine.get_entity_timeline(
        db,
        tenant_id=tenant_id,
        entity_type=entity_type,
        entity_id=entity_id,
    )


@router.get(
    "/timeline-authority/replay",
    response_model=TimelineReplayResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def replay_timeline(
    request: Request,
    entity_type: Optional[str] = Query(None),
    entity_id: Optional[str] = Query(None),
    source_system: Optional[str] = Query(None),
    db: Session = Depends(tenant_db_required),
) -> TimelineReplayResponse:
    tenant_id = require_bound_tenant(request)
    return engine.replay(
        db,
        tenant_id=tenant_id,
        entity_type=entity_type,
        entity_id=entity_id,
        source_system=source_system,
    )


@router.get(
    "/timeline-authority/export",
    response_model=TimelineExportResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def export_timeline(
    request: Request,
    entity_type: Optional[str] = Query(None),
    entity_id: Optional[str] = Query(None),
    db: Session = Depends(tenant_db_required),
) -> TimelineExportResponse:
    tenant_id = require_bound_tenant(request)
    return engine.export(
        db,
        tenant_id=tenant_id,
        entity_type=entity_type,
        entity_id=entity_id,
    )


@router.get(
    "/timeline-authority/integrity",
    response_model=TimelineIntegrityResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def verify_integrity(
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> TimelineIntegrityResponse:
    tenant_id = require_bound_tenant(request)
    return engine.verify_integrity(db, tenant_id=tenant_id)


@router.get(
    "/timeline-authority/statistics",
    response_model=TimelineStatisticsResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_statistics(
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> TimelineStatisticsResponse:
    tenant_id = require_bound_tenant(request)
    return engine.get_statistics(db, tenant_id=tenant_id)
