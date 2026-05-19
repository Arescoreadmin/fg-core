"""Governance Timeline API — tenant-scoped, append-only, cursor-paginated.

Routes:
  GET /governance/timeline
      List timeline events for the caller's tenant.
      Supports source_type, event_type, from/to range, cursor pagination.

  GET /governance/timeline/{event_id}
      Retrieve a single timeline event.

Security invariants:
  - tenant_id resolved from auth context only — never from query params.
  - All routes fail-closed on tenant mismatch or missing event.
  - No PII, PHI, or raw secrets in response payloads.
  - Timeline is append-only; no mutation routes exist.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.assessments import _resolve_caller_tenant
from api.auth_scopes.resolution import require_scopes
from api.deps import auth_ctx_db_session
from services.governance.timeline import TimelineStore

logger = logging.getLogger("frostgate.api.governance_timeline")

router = APIRouter(
    prefix="/governance/timeline",
    tags=["governance-timeline"],
    dependencies=[Depends(require_scopes("governance:read"))],
)

_store = TimelineStore()


# ---------------------------------------------------------------------------
# Pydantic response models
# ---------------------------------------------------------------------------


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
    display: dict[str, Any] | None = None  # populated in PR 103


class TimelinePageResponse(BaseModel):
    tenant_id: str
    events: list[TimelineEventResponse]
    cursor: str | None
    schema_version: str = "1.0"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=TimelinePageResponse)
def list_timeline_events(
    request: Request,
    source_type: str | None = Query(None, description="Filter by source type"),
    event_type: str | None = Query(None, description="Filter by event type"),
    from_dt: str | None = Query(
        None,
        alias="from",
        description="ISO 8601 lower bound on occurred_at (inclusive)",
    ),
    to_dt: str | None = Query(
        None, alias="to", description="ISO 8601 upper bound on occurred_at (exclusive)"
    ),
    cursor: str | None = Query(
        None, description="Pagination cursor from previous response"
    ),
    limit: int = Query(50, ge=1, le=100, description="Results per page (max 100)"),
    db: Session = Depends(auth_ctx_db_session),
) -> TimelinePageResponse:
    """List governance timeline events for the caller's tenant.

    Results are ordered newest-first.  Use the returned cursor to fetch the
    next page.  A null cursor means there are no more results.
    """
    tenant_id = _resolve_caller_tenant(request)

    if cursor:
        from services.governance.timeline.identity import decode_cursor

        try:
            decode_cursor(cursor)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid pagination cursor")

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
        events=[_record_to_response(r) for r in rows],
        cursor=next_cursor,
    )


@router.get("/{event_id}", response_model=TimelineEventResponse)
def get_timeline_event(
    event_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> TimelineEventResponse:
    """Retrieve a single timeline event by ID."""
    tenant_id = _resolve_caller_tenant(request)

    rec = _store.get(db, event_id, tenant_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="Timeline event not found")

    return _record_to_response(rec)
