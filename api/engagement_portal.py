"""Engagement Portal Authority API router — PR 18.2.

All routes are tenant-scoped. Tenant is resolved from auth context only.

Security invariants:
  - tenant_id always from auth context via require_bound_tenant()
  - No route bypasses tenant checks, scope checks, or audit generation
  - No direct ORM access — all DB ops go through EngagementPortalEngine
  - portal_engagement_activity is append-only
  - /portal/engagement/health is the only public route

Route ordering note:
  Static/literal paths are declared before any parametric paths. Currently all
  routes under /portal/engagement are literal (no path parameters).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine, set_tenant_context
from api.field_assessment import (
    EngagementReportListResponse,
    EngagementReportSummary,
    _authoritative_report_state,
    _customer_report_status,
)
from services.field_assessment.store import EngagementNotFound, get_engagement
from services.engagement_portal.engine import EngagementPortalEngine
from services.engagement_portal.schemas import (
    ActivityFeedResponse,
    DashboardResponse,
    EvidenceWorkspaceResponse,
    HealthResponse,
    NotificationListResponse,
    PortalStatisticsResponse,
    PreferencesResponse,
    RecordActivityRequest,
    RemediationWorkspaceResponse,
    SearchResponse,
    TimelineResponse,
    TransparencyWorkspaceResponse,
    TrustWorkspaceResponse,
    UpdatePreferencesRequest,
)
from services.engagement_portal.health import get_health_response

router = APIRouter(tags=["engagement-portal"])

_ACTOR_UNKNOWN = "unknown"


def _actor(request: Request) -> str:
    return str(
        getattr(getattr(request, "state", None), "key_prefix", None) or _ACTOR_UNKNOWN
    )


# ---------------------------------------------------------------------------
# GET /portal/engagement/health  (public, no auth)
# ---------------------------------------------------------------------------


@router.get("/portal/engagement/health", response_model=HealthResponse)
def portal_engagement_health() -> HealthResponse:
    return get_health_response()


# ---------------------------------------------------------------------------
# GET /portal/engagement/dashboard
# ---------------------------------------------------------------------------


@router.get(
    "/portal/engagement/dashboard",
    dependencies=[Depends(require_scopes("portal:read"))],
    response_model=DashboardResponse,
)
def portal_engagement_dashboard(
    request: Request,
    assessment_id: str | None = Query(default=None),
) -> DashboardResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        set_tenant_context(db, tenant_id)
        svc = EngagementPortalEngine(db, tenant_id=tenant_id)
        result = svc.get_dashboard(assessment_id=assessment_id)
        db.commit()
    return result


# ---------------------------------------------------------------------------
# GET /portal/engagement/timeline
# ---------------------------------------------------------------------------


@router.get(
    "/portal/engagement/timeline",
    dependencies=[Depends(require_scopes("portal:read"))],
    response_model=TimelineResponse,
)
def portal_engagement_timeline(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> TimelineResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        set_tenant_context(db, tenant_id)
        svc = EngagementPortalEngine(db, tenant_id=tenant_id)
        result = svc.get_timeline(limit=limit, offset=offset)
        db.commit()
    return result


# ---------------------------------------------------------------------------
# GET /portal/engagement/evidence
# ---------------------------------------------------------------------------


@router.get(
    "/portal/engagement/evidence",
    dependencies=[Depends(require_scopes("portal:read"))],
    response_model=EvidenceWorkspaceResponse,
)
def portal_engagement_evidence(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> EvidenceWorkspaceResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        set_tenant_context(db, tenant_id)
        svc = EngagementPortalEngine(db, tenant_id=tenant_id)
        result = svc.get_evidence_workspace(limit=limit, offset=offset)
        db.commit()
    return result


# ---------------------------------------------------------------------------
# GET /portal/engagement/reports
# ---------------------------------------------------------------------------


@router.get(
    "/portal/engagement/reports",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=EngagementReportListResponse,
)
def portal_engagement_reports(
    request: Request,
    engagement_id: str | None = Query(default=None, min_length=1),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> EngagementReportListResponse:
    """Compatibility adapter over the canonical Field Assessment report store."""
    tenant_id = require_bound_tenant(request)
    if not engagement_id:
        # Never fall back to the legacy tenant-wide report authority.
        return EngagementReportListResponse(
            items=[], limit=limit, offset=offset, total=0
        )
    portal_engagement_id = getattr(request.state, "portal_engagement_id", None)
    if (request.headers.get("x-portal-source") == "client-portal") and (
        portal_engagement_id != engagement_id
    ):
        raise HTTPException(status_code=404, detail="Engagement not found")
    engine = get_engine()
    with Session(engine) as db:
        set_tenant_context(db, tenant_id)
        try:
            get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
        except EngagementNotFound as exc:
            raise HTTPException(status_code=404, detail="Engagement not found") from exc
        from services.governance.report.versioning import list_versions

        versions = list_versions(db, tenant_id=tenant_id, engagement_id=engagement_id)
        page = versions[offset : offset + limit]
        items = []
        for report in page:
            state, _ = _authoritative_report_state(
                db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                record=report,
            )
            items.append(
                EngagementReportSummary(
                    report_id=report.id,
                    version=report.version,
                    status=_customer_report_status(state),
                    compiled_at=report.generated_at,
                    compiled_by=None,
                    report_type=report.report_type,
                    qa_approved_by=None,
                    qa_approved_at=report.qa_approved_at,
                    report_state={
                        "state": state.get("state", "UNKNOWN"),
                        "marking": state.get("marking"),
                        "release_blockers": state.get("release_blockers", []),
                    },
                    manifest_hash=report.manifest_hash,
                )
            )
        return EngagementReportListResponse(
            items=items,
            limit=limit,
            offset=offset,
            total=len(versions),
        )


# ---------------------------------------------------------------------------
# GET /portal/engagement/remediation
# ---------------------------------------------------------------------------


@router.get(
    "/portal/engagement/remediation",
    dependencies=[Depends(require_scopes("portal:read"))],
    response_model=RemediationWorkspaceResponse,
)
def portal_engagement_remediation(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> RemediationWorkspaceResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        set_tenant_context(db, tenant_id)
        svc = EngagementPortalEngine(db, tenant_id=tenant_id)
        result = svc.get_remediation_workspace(limit=limit, offset=offset)
        db.commit()
    return result


# ---------------------------------------------------------------------------
# GET /portal/engagement/trust
# ---------------------------------------------------------------------------


@router.get(
    "/portal/engagement/trust",
    dependencies=[Depends(require_scopes("portal:read"))],
    response_model=TrustWorkspaceResponse,
)
def portal_engagement_trust(request: Request) -> TrustWorkspaceResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        set_tenant_context(db, tenant_id)
        svc = EngagementPortalEngine(db, tenant_id=tenant_id)
        result = svc.get_trust_workspace()
        db.commit()
    return result


# ---------------------------------------------------------------------------
# GET /portal/engagement/transparency
# ---------------------------------------------------------------------------


@router.get(
    "/portal/engagement/transparency",
    dependencies=[Depends(require_scopes("portal:read"))],
    response_model=TransparencyWorkspaceResponse,
)
def portal_engagement_transparency(
    request: Request,
) -> TransparencyWorkspaceResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        set_tenant_context(db, tenant_id)
        svc = EngagementPortalEngine(db, tenant_id=tenant_id)
        result = svc.get_transparency_workspace()
        db.commit()
    return result


# ---------------------------------------------------------------------------
# GET /portal/engagement/activity
# ---------------------------------------------------------------------------


@router.get(
    "/portal/engagement/activity",
    dependencies=[Depends(require_scopes("portal:read"))],
    response_model=ActivityFeedResponse,
)
def portal_engagement_activity_feed(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    workspace: str | None = Query(default=None),
) -> ActivityFeedResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        set_tenant_context(db, tenant_id)
        svc = EngagementPortalEngine(db, tenant_id=tenant_id)
        result = svc.get_activity_feed(limit=limit, offset=offset, workspace=workspace)
        db.commit()
    return result


# ---------------------------------------------------------------------------
# GET /portal/engagement/statistics
# ---------------------------------------------------------------------------


@router.get(
    "/portal/engagement/statistics",
    dependencies=[Depends(require_scopes("portal:read"))],
    response_model=PortalStatisticsResponse,
)
def portal_engagement_statistics(request: Request) -> PortalStatisticsResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        set_tenant_context(db, tenant_id)
        svc = EngagementPortalEngine(db, tenant_id=tenant_id)
        result = svc.get_statistics()
        db.commit()
    return result


# ---------------------------------------------------------------------------
# GET /portal/engagement/search
# ---------------------------------------------------------------------------


@router.get(
    "/portal/engagement/search",
    dependencies=[Depends(require_scopes("portal:read"))],
    response_model=SearchResponse,
)
def portal_engagement_search(
    request: Request,
    q: str = Query(..., min_length=1, max_length=512),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> SearchResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        set_tenant_context(db, tenant_id)
        svc = EngagementPortalEngine(db, tenant_id=tenant_id)
        result = svc.search(query=q, limit=limit, offset=offset)
        db.commit()
    return result


# ---------------------------------------------------------------------------
# GET /portal/engagement/notifications
# ---------------------------------------------------------------------------


@router.get(
    "/portal/engagement/notifications",
    dependencies=[Depends(require_scopes("portal:read"))],
    response_model=NotificationListResponse,
)
def portal_engagement_notifications(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> NotificationListResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        set_tenant_context(db, tenant_id)
        svc = EngagementPortalEngine(db, tenant_id=tenant_id)
        result = svc.get_notifications(limit=limit, offset=offset)
        db.commit()
    return result


# ---------------------------------------------------------------------------
# GET /portal/engagement/preferences
# ---------------------------------------------------------------------------


@router.get(
    "/portal/engagement/preferences",
    dependencies=[Depends(require_scopes("portal:read"))],
    response_model=PreferencesResponse,
)
def portal_engagement_preferences_get(request: Request) -> PreferencesResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        set_tenant_context(db, tenant_id)
        svc = EngagementPortalEngine(db, tenant_id=tenant_id)
        result = svc.get_preferences()
        db.commit()
    return result


# ---------------------------------------------------------------------------
# PUT /portal/engagement/preferences
# ---------------------------------------------------------------------------


@router.put(
    "/portal/engagement/preferences",
    dependencies=[Depends(require_scopes("portal:write"))],
    response_model=PreferencesResponse,
)
def portal_engagement_preferences_put(
    body: UpdatePreferencesRequest,
    request: Request,
) -> PreferencesResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        set_tenant_context(db, tenant_id)
        svc = EngagementPortalEngine(db, tenant_id=tenant_id)
        result = svc.update_preferences(body)
        db.commit()
    return result


# ---------------------------------------------------------------------------
# POST /portal/engagement/activity
# ---------------------------------------------------------------------------


@router.post(
    "/portal/engagement/activity",
    dependencies=[Depends(require_scopes("portal:write"))],
    status_code=204,
)
def portal_engagement_activity_record(
    body: RecordActivityRequest, request: Request
) -> None:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        set_tenant_context(db, tenant_id)
        svc = EngagementPortalEngine(db, tenant_id=tenant_id)
        svc.record_activity(
            event_type=body.event_type,
            workspace=body.workspace,
            entity_id=body.entity_id,
            actor_id=_actor(request),
            metadata=body.metadata,
        )
        db.commit()
    return None
