# api/evidence_authority.py
"""Canonical Evidence Authority API — PR 14.6.1.

All routes are tenant-scoped. Tenant is resolved from auth context only —
never from the request body.

Route ordering note:
  /evidence/dashboard and /evidence/by-entity/* MUST appear before
  /evidence/{ev_id} to prevent FastAPI matching them as evidence IDs.

Security invariants:
  - tenant_id always from auth context via require_bound_tenant()
  - No route bypasses tenant checks or scope checks
  - No direct ORM access — all ops go through EvidenceAuthorityEngine
  - audit events always written (never skipped)
  - actor_id always from request state (key_prefix) — never from body
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from api.observability.metrics import (
    EVIDENCE_ARCHIVED_TOTAL,
    EVIDENCE_CONTROL_LINKS_TOTAL,
    EVIDENCE_COVERAGE_CALCULATIONS_TOTAL,
    EVIDENCE_CREATED_TOTAL,
    EVIDENCE_EXPIRED_TOTAL,
    EVIDENCE_HEALTH_UPDATES_TOTAL,
    EVIDENCE_QUALITY_SCORE_UPDATES_TOTAL,
    EVIDENCE_REJECTED_TOTAL,
    EVIDENCE_RISK_LINKS_TOTAL,
    EVIDENCE_STATUS_TRANSITIONS_TOTAL,
    EVIDENCE_SUPERSEDED_TOTAL,
    EVIDENCE_TRUST_CHANGES_TOTAL,
    EVIDENCE_VERIFICATION_FAILURES_TOTAL,
    EVIDENCE_VERIFICATIONS_TOTAL,
    EVIDENCE_VERIFIED_TOTAL,
)
from services.evidence_authority.engine import EvidenceAuthorityEngine
from services.evidence_authority.schemas import (
    AssignOwnershipRequest,
    CGINSnapshotBundle,
    ControlLinkConflict,
    ControlLinkListResponse,
    ControlLinkResponse,
    CoverageAnalyticsResponse,
    CreateEvidenceRequest,
    CreateVerificationRequest,
    EvidenceAuditListResponse,
    EvidenceConflict,
    EvidenceDashboardResponse,
    EvidenceImmutableState,
    EvidenceInvalidTransition,
    EvidenceInvalidTrustTransition,
    EvidenceListResponse,
    EvidenceNotFound,
    EvidenceOwnershipListResponse,
    EvidenceOwnershipNotFound,
    EvidenceOwnershipResponse,
    EvidenceQualityScoreResponse,
    EvidenceRelationshipConflict,
    EvidenceRelationshipListResponse,
    EvidenceRelationshipResponse,
    EvidenceResponse,
    EvidenceStatusReportResponse,
    EvidenceTrustHistoryResponse,
    HealthSignalsResponse,
    LinkControlRequest,
    LinkRelationshipRequest,
    LinkRiskRequest,
    RevokeOwnershipRequest,
    RiskLinkConflict,
    RiskLinkListResponse,
    RiskLinkResponse,
    SetSlaDeadlinesRequest,
    SlaStatusResponse,
    TransitionLifecycleRequest,
    UpdateEvidenceMetadataRequest,
    VerificationListResponse,
    VerificationResponse,
    VerificationSummaryResponse,
    VerifyEvidenceRequest,
)
from services.evidence_authority.models import (
    EvidenceLifecycleState,
    VerificationResult,
)

router = APIRouter(tags=["evidence-authority"])

_ACTOR_UNKNOWN = "unknown"


def _actor(request: Request) -> str:
    return str(
        getattr(getattr(request, "state", None), "key_prefix", None) or _ACTOR_UNKNOWN
    )


def _actor_type(request: Request) -> str:
    """Resolve actor type from request state. Defaults to 'human'."""
    return str(getattr(getattr(request, "state", None), "actor_type", None) or "human")


# ---------------------------------------------------------------------------
# Dashboard (must be before /{ev_id})
# ---------------------------------------------------------------------------


@router.get(
    "/evidence/dashboard",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=EvidenceDashboardResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def evidence_dashboard(request: Request) -> EvidenceDashboardResponse:
    """Evidence posture dashboard for the tenant."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        return svc.dashboard()


# ---------------------------------------------------------------------------
# Evidence by related entity (must be before /{ev_id})
# ---------------------------------------------------------------------------


@router.get(
    "/evidence/by-entity/{entity_type}/{entity_id}",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=EvidenceRelationshipListResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def list_evidence_for_entity(
    entity_type: str,
    entity_id: str,
    request: Request,
) -> EvidenceRelationshipListResponse:
    """List all evidence relationships for a governed entity (finding, control, etc.)."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        return svc.list_evidence_for_entity(entity_type, entity_id)


# ---------------------------------------------------------------------------
# PR 14.6.5 — Governance Status Report (must be before /{ev_id})
# ---------------------------------------------------------------------------


@router.get(
    "/evidence/status/report",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=EvidenceStatusReportResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def evidence_status_report(
    request: Request,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=500),
) -> EvidenceStatusReportResponse:
    """Governance-ready evidence status report for the tenant.

    All status information originates from Canonical Evidence Authority.
    Downstream consumers (Governance Reporting, Attestation Engine,
    Executive Dashboard, CGIN) must consume this endpoint — never
    recompute status independently.
    """
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        return svc.get_status_report(offset=offset, limit=limit)


# ---------------------------------------------------------------------------
# PR 14.6.5A — Coverage Analytics (must be before /{ev_id})
# ---------------------------------------------------------------------------


@router.get(
    "/evidence/coverage",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=CoverageAnalyticsResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def evidence_coverage(request: Request) -> CoverageAnalyticsResponse:
    """Coverage analytics — controls, risks, and evidence density for the tenant."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        result = svc.get_coverage_analytics()
        EVIDENCE_COVERAGE_CALCULATIONS_TOTAL.inc()
        return result


@router.get(
    "/evidence/health",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=HealthSignalsResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def evidence_health(request: Request) -> HealthSignalsResponse:
    """Health signals — SLA overdue counts, orphaned evidence, trust posture."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        result = svc.get_health_signals()
        EVIDENCE_HEALTH_UPDATES_TOTAL.inc()
        return result


@router.get(
    "/evidence/cgin/snapshot",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=CGINSnapshotBundle,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def evidence_cgin_snapshot(request: Request) -> CGINSnapshotBundle:
    """CGIN-ready canonical evidence snapshot bundle (deterministic, versioned)."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        return svc.get_cgin_snapshot()


# ---------------------------------------------------------------------------
# Create Evidence
# ---------------------------------------------------------------------------


@router.post(
    "/evidence",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=EvidenceResponse,
    status_code=201,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def create_evidence(
    req: CreateEvidenceRequest,
    request: Request,
) -> EvidenceResponse:
    """Create a new canonical evidence record."""
    tenant_id = require_bound_tenant(request)
    actor_id = _actor(request)
    actor_type = _actor_type(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_evidence(req, actor_id=actor_id, actor_type=actor_type)
        except EvidenceConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        EVIDENCE_CREATED_TOTAL.inc()
        return result


# ---------------------------------------------------------------------------
# List Evidence
# ---------------------------------------------------------------------------


@router.get(
    "/evidence",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=EvidenceListResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def list_evidence(
    request: Request,
    lifecycle_state: str | None = Query(default=None),
    trust_state: str | None = Query(default=None),
    classification: str | None = Query(default=None),
    source_type: str | None = Query(default=None),
    engagement_id: str | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
) -> EvidenceListResponse:
    """List evidence records for the tenant with optional filters."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        return svc.list_evidence(
            lifecycle_state=lifecycle_state,
            trust_state=trust_state,
            classification=classification,
            source_type=source_type,
            engagement_id=engagement_id,
            offset=offset,
            limit=limit,
        )


# ---------------------------------------------------------------------------
# Get Evidence
# ---------------------------------------------------------------------------


@router.get(
    "/evidence/{ev_id}",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=EvidenceResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def get_evidence(ev_id: str, request: Request) -> EvidenceResponse:
    """Get a single evidence record by ID."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_evidence(ev_id)
        except EvidenceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# Update Metadata
# ---------------------------------------------------------------------------


@router.patch(
    "/evidence/{ev_id}",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=EvidenceResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def update_evidence_metadata(
    ev_id: str,
    req: UpdateEvidenceMetadataRequest,
    request: Request,
) -> EvidenceResponse:
    """Update mutable metadata on a non-immutable evidence record."""
    tenant_id = require_bound_tenant(request)
    actor_id = _actor(request)
    actor_type = _actor_type(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.update_metadata(
                ev_id, req, actor_id=actor_id, actor_type=actor_type
            )
        except EvidenceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except EvidenceImmutableState as exc:
            raise HTTPException(status_code=409, detail=str(exc))


# ---------------------------------------------------------------------------
# Lifecycle Transition
# ---------------------------------------------------------------------------


@router.post(
    "/evidence/{ev_id}/lifecycle",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=EvidenceResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def transition_lifecycle(
    ev_id: str,
    req: TransitionLifecycleRequest,
    request: Request,
) -> EvidenceResponse:
    """Transition evidence lifecycle state through the formal state machine."""
    tenant_id = require_bound_tenant(request)
    actor_id = _actor(request)
    actor_type = _actor_type(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        try:
            result = svc.transition_lifecycle(
                ev_id, req, actor_id=actor_id, actor_type=actor_type
            )
        except EvidenceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except EvidenceInvalidTransition as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        # Increment per-state metrics
        to_state = req.to_state
        if to_state == EvidenceLifecycleState.VERIFIED:
            EVIDENCE_VERIFIED_TOTAL.inc()
        elif to_state == EvidenceLifecycleState.REJECTED:
            EVIDENCE_REJECTED_TOTAL.inc()
        elif to_state == EvidenceLifecycleState.SUPERSEDED:
            EVIDENCE_SUPERSEDED_TOTAL.inc()
        elif to_state == EvidenceLifecycleState.EXPIRED:
            EVIDENCE_EXPIRED_TOTAL.inc()
        elif to_state == EvidenceLifecycleState.ARCHIVED:
            EVIDENCE_ARCHIVED_TOTAL.inc()
        EVIDENCE_STATUS_TRANSITIONS_TOTAL.labels(to_status=to_state.value).inc()
        return result


# ---------------------------------------------------------------------------
# Ownership
# ---------------------------------------------------------------------------


@router.post(
    "/evidence/{ev_id}/ownership",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=EvidenceOwnershipResponse,
    status_code=201,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def assign_ownership(
    ev_id: str,
    req: AssignOwnershipRequest,
    request: Request,
) -> EvidenceOwnershipResponse:
    """Assign an ownership role (OWNER/REVIEWER/VERIFIER/APPROVER/CUSTODIAN) to an actor."""
    tenant_id = require_bound_tenant(request)
    actor_id = _actor(request)
    actor_type = _actor_type(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.assign_ownership(
                ev_id, req, actor_id=actor_id, actor_type=actor_type
            )
        except EvidenceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))


@router.delete(
    "/evidence/{ev_id}/ownership/{ownership_id}",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=EvidenceOwnershipResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def revoke_ownership(
    ev_id: str,
    ownership_id: str,
    request: Request,
) -> EvidenceOwnershipResponse:
    """Revoke an ownership assignment (sets is_active=0; row is preserved)."""
    tenant_id = require_bound_tenant(request)
    actor_id = _actor(request)
    actor_type = _actor_type(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.revoke_ownership(
                ev_id,
                RevokeOwnershipRequest(ownership_id=ownership_id),
                actor_id=actor_id,
                actor_type=actor_type,
            )
        except EvidenceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except EvidenceOwnershipNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))


@router.get(
    "/evidence/{ev_id}/ownership",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=EvidenceOwnershipListResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def list_ownership(
    ev_id: str,
    request: Request,
    active_only: bool = Query(default=False),
) -> EvidenceOwnershipListResponse:
    """List ownership records for an evidence record."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_ownership(ev_id, active_only=active_only)
        except EvidenceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# Verification (Trust State)
# ---------------------------------------------------------------------------


@router.post(
    "/evidence/{ev_id}/verify",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=EvidenceTrustHistoryResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def verify_evidence(
    ev_id: str,
    req: VerifyEvidenceRequest,
    request: Request,
) -> EvidenceTrustHistoryResponse:
    """Transition evidence trust state and record a trust event (hash-chained)."""
    tenant_id = require_bound_tenant(request)
    actor_id = _actor(request)
    actor_type = _actor_type(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        try:
            result = svc.verify_evidence(
                ev_id, req, actor_id=actor_id, actor_type=actor_type
            )
        except EvidenceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except EvidenceInvalidTrustTransition as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        EVIDENCE_TRUST_CHANGES_TOTAL.inc()
        return result


@router.get(
    "/evidence/{ev_id}/trust",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=EvidenceTrustHistoryResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def query_trust_state(ev_id: str, request: Request) -> EvidenceTrustHistoryResponse:
    """Query the trust state and full trust event history for an evidence record."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.query_trust_history(ev_id)
        except EvidenceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# Relationships
# ---------------------------------------------------------------------------


@router.post(
    "/evidence/{ev_id}/relationships",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=EvidenceRelationshipResponse,
    status_code=201,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def link_relationship(
    ev_id: str,
    req: LinkRelationshipRequest,
    request: Request,
) -> EvidenceRelationshipResponse:
    """Link an evidence record to a governed entity (finding, control, risk, etc.)."""
    tenant_id = require_bound_tenant(request)
    actor_id = _actor(request)
    actor_type = _actor_type(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.link_relationship(
                ev_id, req, actor_id=actor_id, actor_type=actor_type
            )
        except EvidenceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except EvidenceRelationshipConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc))


@router.get(
    "/evidence/{ev_id}/relationships",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=EvidenceRelationshipListResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def list_relationships(
    ev_id: str,
    request: Request,
    entity_type: str | None = Query(default=None),
) -> EvidenceRelationshipListResponse:
    """List all relationships from an evidence record to governed entities."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_relationships(ev_id, related_entity_type=entity_type)
        except EvidenceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# Audit Trail
# ---------------------------------------------------------------------------


@router.get(
    "/evidence/{ev_id}/audit",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=EvidenceAuditListResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def list_audit_events(
    ev_id: str,
    request: Request,
    event_type: str | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
) -> EvidenceAuditListResponse:
    """List the full audit trail for an evidence record."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_audit_events(
                ev_id, event_type=event_type, offset=offset, limit=limit
            )
        except EvidenceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# PR 14.6.5 — Quality Scores (must be before /{ev_id} catch-all)
# ---------------------------------------------------------------------------


@router.post(
    "/evidence/{ev_id}/quality/compute",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=EvidenceQualityScoreResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def compute_quality_scores(
    ev_id: str,
    request: Request,
) -> EvidenceQualityScoreResponse:
    """Recompute and persist deterministic quality scores for an evidence record.

    Scores are also automatically recomputed on every mutating operation.
    Use this endpoint for explicit recomputes (bulk refresh, freshness update).
    """
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        try:
            result = svc.recompute_quality_scores(
                ev_id,
                actor_id=_actor(request),
                actor_type=_actor_type(request),
            )
        except EvidenceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        EVIDENCE_QUALITY_SCORE_UPDATES_TOTAL.inc()
        return result


# ---------------------------------------------------------------------------
# PR 14.6.5A — Verifications (per-evidence)
# ---------------------------------------------------------------------------


@router.post(
    "/evidence/{ev_id}/verifications",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=VerificationResponse,
    status_code=201,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def create_verification(
    ev_id: str,
    req: CreateVerificationRequest,
    request: Request,
) -> VerificationResponse:
    """Record a verification attempt for an evidence record."""
    tenant_id = require_bound_tenant(request)
    actor_id = _actor(request)
    actor_type = _actor_type(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_verification(
                ev_id, req, actor_id=actor_id, actor_type=actor_type
            )
        except EvidenceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        EVIDENCE_VERIFICATIONS_TOTAL.inc()
        if req.verification_result == VerificationResult.FAIL:
            EVIDENCE_VERIFICATION_FAILURES_TOTAL.inc()
        return result


@router.get(
    "/evidence/{ev_id}/verifications",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=VerificationListResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def list_verifications(ev_id: str, request: Request) -> VerificationListResponse:
    """List all verifications for an evidence record."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_verifications(ev_id)
        except EvidenceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))


@router.get(
    "/evidence/{ev_id}/verifications/summary",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=VerificationSummaryResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def get_verification_summary(
    ev_id: str, request: Request
) -> VerificationSummaryResponse:
    """Get verification summary statistics for an evidence record."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_verification_summary(ev_id)
        except EvidenceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# PR 14.6.5A — SLA Deadlines (per-evidence)
# ---------------------------------------------------------------------------


@router.put(
    "/evidence/{ev_id}/sla",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=SlaStatusResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def set_sla_deadlines(
    ev_id: str,
    req: SetSlaDeadlinesRequest,
    request: Request,
) -> SlaStatusResponse:
    """Set SLA deadlines for an evidence record."""
    tenant_id = require_bound_tenant(request)
    actor_id = _actor(request)
    actor_type = _actor_type(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.set_sla_deadlines(
                ev_id, req, actor_id=actor_id, actor_type=actor_type
            )
        except EvidenceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))


@router.get(
    "/evidence/{ev_id}/sla",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=SlaStatusResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def get_sla_status(ev_id: str, request: Request) -> SlaStatusResponse:
    """Get SLA status for an evidence record."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_sla_status(ev_id)
        except EvidenceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# PR 14.6.5A — Control Links (per-evidence)
# ---------------------------------------------------------------------------


@router.post(
    "/evidence/{ev_id}/control-links",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=ControlLinkResponse,
    status_code=201,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def link_to_control(
    ev_id: str,
    req: LinkControlRequest,
    request: Request,
) -> ControlLinkResponse:
    """Link an evidence record to a control."""
    tenant_id = require_bound_tenant(request)
    actor_id = _actor(request)
    actor_type = _actor_type(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        try:
            result = svc.link_to_control(
                ev_id, req, actor_id=actor_id, actor_type=actor_type
            )
        except EvidenceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except ControlLinkConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        EVIDENCE_CONTROL_LINKS_TOTAL.inc()
        return result


@router.get(
    "/evidence/{ev_id}/control-links",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=ControlLinkListResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def list_control_links(ev_id: str, request: Request) -> ControlLinkListResponse:
    """List all control links for an evidence record."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_control_links(ev_id)
        except EvidenceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))


# ---------------------------------------------------------------------------
# PR 14.6.5A — Risk Links (per-evidence)
# ---------------------------------------------------------------------------


@router.post(
    "/evidence/{ev_id}/risk-links",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=RiskLinkResponse,
    status_code=201,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def link_to_risk(
    ev_id: str,
    req: LinkRiskRequest,
    request: Request,
) -> RiskLinkResponse:
    """Link an evidence record to a risk, finding, or exception."""
    tenant_id = require_bound_tenant(request)
    actor_id = _actor(request)
    actor_type = _actor_type(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        try:
            result = svc.link_to_risk(
                ev_id, req, actor_id=actor_id, actor_type=actor_type
            )
        except EvidenceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except RiskLinkConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        EVIDENCE_RISK_LINKS_TOTAL.inc()
        return result


@router.get(
    "/evidence/{ev_id}/risk-links",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=RiskLinkListResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def list_risk_links(
    ev_id: str,
    request: Request,
    link_type: str | None = Query(default=None),
) -> RiskLinkListResponse:
    """List risk/finding/exception links for an evidence record."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_risk_links(ev_id, link_type=link_type)
        except EvidenceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
