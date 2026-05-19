"""Governance Timeline API — tenant-scoped, append-only, cursor-paginated."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.assessments import _resolve_caller_tenant
from api.auth_scopes.resolution import bind_tenant_id, require_scopes
from api.deps import auth_ctx_db_session
from services.governance.timeline import TimelineStore

logger = logging.getLogger("frostgate.api.governance_timeline")

router = APIRouter(
    prefix="/governance/timeline",
    tags=["governance-timeline"],
    dependencies=[Depends(require_scopes("governance:read"))],
)

_store = TimelineStore()


class TimelineEventResponse(BaseModel):
    event_id: str
    tenant_id: str
    source_type: str
    source_id: str
    event_type: str
    occurred_at: str
    recorded_at: str
    classification: str
    manifest_hash: str | None
    replay_eligible: bool
    schema_version: str
    payload: dict[str, Any]
    display: dict[str, Any] | None = None


class TimelinePageResponse(BaseModel):
    tenant_id: str
    events: list[TimelineEventResponse]
    cursor: str | None
    schema_version: str = "1.0"


def _record_to_response(rec) -> TimelineEventResponse:
    return TimelineEventResponse(
        event_id=rec.id,
        tenant_id=rec.tenant_id,
        source_type=rec.source_type,
        source_id=rec.source_id,
        event_type=rec.event_type,
        occurred_at=rec.occurred_at,
        recorded_at=rec.recorded_at,
        classification=rec.classification,
        manifest_hash=rec.manifest_hash,
        replay_eligible=rec.replay_eligible,
        schema_version=rec.schema_version,
        payload=rec.payload or {},
        display=None,
    )


@router.get("", response_model=TimelinePageResponse)
def list_timeline_events(
    request: Request,
    source_type: str | None = Query(None, description="Filter by source type"),
    event_type: str | None = Query(None, description="Filter by event type"),
    from_dt: str | None = Query(None, alias="from"),
    to_dt: str | None = Query(None, alias="to"),
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(auth_ctx_db_session),
) -> TimelinePageResponse:
    resolved_tenant_id = _resolve_caller_tenant(request)
    if resolved_tenant_id is None:
        logger.warning(
            "governance_timeline_missing_tenant_context",
            extra={"path": str(request.url.path), "method": request.method},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="tenant context required",
        )

    tenant_id = bind_tenant_id(
        request,
        resolved_tenant_id,
        require_explicit_for_unscoped=True,
    )

    if cursor:
        from services.governance.timeline.identity import decode_cursor

        try:
            decode_cursor(cursor)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid pagination cursor",
            ) from exc

    rows, next_cursor = _store.list(
        db,
        tenant_id,
        source_type=source_type,
        event_type=event_type,
        from_dt=from_dt,
        to_dt=to_dt,
        cursor=cursor,
        limit=limit,
    )

    return TimelinePageResponse(
        tenant_id=tenant_id,
        events=[_record_to_response(row) for row in rows],
        cursor=next_cursor,
    )


@router.get("/{event_id}", response_model=TimelineEventResponse)
def get_timeline_event(
    event_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> TimelineEventResponse:
    resolved_tenant_id = _resolve_caller_tenant(request)
    if resolved_tenant_id is None:
        logger.warning(
            "governance_timeline_missing_tenant_context",
            extra={"path": str(request.url.path), "method": request.method},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="tenant context required",
        )

    tenant_id = bind_tenant_id(
        request,
        resolved_tenant_id,
        require_explicit_for_unscoped=True,
    )

    rec = _store.get(db, event_id, tenant_id)
    if rec is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Timeline event not found",
        )

    return _record_to_response(rec)
