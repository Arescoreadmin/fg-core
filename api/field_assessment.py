"""Field Assessment Engagement Substrate API router.

All routes are tenant-scoped. Tenant is resolved from auth context only —
never from the request body.

Security invariants:
- tenant_id always from auth context, never request body.
- engagement_id scoped to (engagement_id, tenant_id) pair in all DB queries.
- Write routes emit audit events before returning.
- No raw payloads or credentials in audit event payloads.
- All list endpoints capped at 100 rows.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.auth_scopes import require_scopes
from api.deps import auth_ctx_db_session
from api.error_contracts import api_error
from services.field_assessment.audit import emit_engagement_audit_event
from services.field_assessment.connectors.msgraph_bridge import (
    ConnectorAcknowledgmentRequired,
    ConnectorBridgeError,
    ConnectorExportUnsafe,
    ConnectorImportEnvelope,
    ConnectorManifestUnverified,
    ConnectorSchemaUnsupported,
    ConnectorTenantMismatch,
    import_msgraph_scan_result,
)
from services.field_assessment.models import (
    AssessmentType,
    DocumentClassification,
    EngagementNotFound,
    EvidenceLinkDuplicate,
    EvidenceLinkType,
    FindingNotFound,
    InvalidEngagementTransition,
    ObservationDomain,
    ObservationSeverity,
    ObservationType,
    ScanQuarantinedError,
    ScanResultNotFound,
    ScanSourceType,
    ScanValidationError,
)
from services.canonical import utc_iso8601_z_now
from services.field_assessment.playbooks import get_playbook
from services.field_assessment.finding_explainer import explain_finding
from services.field_assessment.progress import compute_next_actions
from services.field_assessment.readiness import build_execution_state
from services.field_assessment.redaction import redact_payload
from services.field_assessment.scan_registry import validate_scan_payload
from services.field_assessment.store import (
    compute_evidence_hash,
    create_document_analysis,
    create_engagement,
    create_evidence_link,
    create_observation,
    create_quarantined_scan,
    create_scan_result,
    get_engagement,
    get_finding,
    get_scan_result,
    list_audit_events,
    list_document_analyses,
    list_engagements,
    list_evidence_links,
    list_findings,
    list_observations,
    list_scan_results,
    transition_engagement,
)
from services.field_assessment.timeline import emit_fa_timeline_event
from api.db_models_field_assessment import (
    FaDocumentAnalysis,
    FaEngagement,
    FaEvidenceLink,
    FaFieldObservation,
    FaNormalizedFinding,
    FaScanResult,
)

from api.db_models_governance_asset_candidates import GaAssetCandidate
from api.db_models_governance_assets import GaAsset
from api.db_models_governance_promotion import GovernancePromotion
from api.db_models_governance_report import GovernanceReportRecord
from services.field_assessment.normalizer import normalize_scan_findings
from services.field_assessment.promotion import promote_engagement_to_governance
from services.field_assessment.promotion_store import get_promotion
from services.governance_asset_registry.promotion import (
    promote_candidate_to_asset as _promote_candidate,
)

from api.db_models_drift import FaDriftBaseline
from services.connectors.drift.engine import compute_drift
from services.connectors.drift.scorer import compute_posture_delta
from services.connectors.drift.alerts import emit_drift_alerts
from services.connectors.drift.correlation import find_root_cause_candidates
from services.connectors.drift.velocity import compute_drift_velocity
from services.connectors.drift.scheduler import (
    InvalidCronExpression,
    upsert_schedule,
    list_schedules,
)

log = logging.getLogger("frostgate.api.field_assessment")

# Statuses whose transition requires all blocking readiness gates to be satisfied.
# Ungated transitions (e.g. scheduled→pre_visit) skip the expensive gate evaluation.
_GATED_STATUSES: frozenset[str] = frozenset(
    {"evidence_collected", "report_generation", "delivered"}
)

router = APIRouter(
    prefix="/field-assessment",
    tags=["field-assessment"],
)


# ---------------------------------------------------------------------------
# Tenant + actor resolution
# ---------------------------------------------------------------------------


def _resolve_caller_tenant(request: Request) -> str:
    auth = getattr(getattr(request, "state", None), "auth", None)
    tenant_id = getattr(getattr(request, "state", None), "tenant_id", None) or getattr(
        auth, "tenant_id", None
    )
    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="tenant context required",
        )
    return str(tenant_id)


def _actor_from_request(request: Request) -> str:
    auth = getattr(getattr(request, "state", None), "auth", None)
    prefix = getattr(auth, "key_prefix", None)
    return str(prefix) if prefix else "unknown"


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------


class CreateEngagementRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    client_name: str
    client_domain: str | None = None
    assessor_id: str
    assessment_type: AssessmentType
    scheduled_date: str | None = None
    engagement_metadata: dict[str, Any] = Field(default_factory=dict)


class TransitionEngagementRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    new_status: str
    reason: str = Field(..., min_length=1)


class IngestScanResultRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_type: ScanSourceType
    schema_version: str
    collected_at: str
    raw_payload: dict[str, Any]
    normalized_payload: dict[str, Any] | None = None
    object_count: int = Field(default=0, ge=0)
    expected_evidence_hash: str | None = None

    @field_validator("collected_at")
    @classmethod
    def _validate_collected_at(cls, v: str) -> str:
        from datetime import datetime

        from pydantic_core import PydanticCustomError

        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            raise PydanticCustomError(
                "iso8601_datetime",
                "collected_at must be a valid ISO 8601 datetime",
            ) from None
        return v

    @field_validator("raw_payload")
    @classmethod
    def _validate_payload_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        import json

        if len(json.dumps(v)) > 5 * 1024 * 1024:
            raise ValueError("raw_payload exceeds 5MB limit")
        return v


class RegisterDocumentAnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    document_name: str
    document_classification: DocumentClassification
    document_hash: str | None = None
    version_label: str | None = None
    approved_by: str | None = None
    approval_date: str | None = None
    freshness_date: str | None = None
    analysis_findings: list[Any] = Field(default_factory=list)
    gaps_identified: list[Any] = Field(default_factory=list)


class CaptureObservationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: ObservationDomain
    observation_type: ObservationType
    severity: ObservationSeverity
    title: str
    description: str
    interview_role: str | None = None
    structured_evidence: dict[str, Any] = Field(default_factory=dict)
    linked_finding_ids: list[Any] = Field(default_factory=list)


class CreateEvidenceLinkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_entity_type: str
    source_entity_id: str
    evidence_entity_type: EvidenceLinkType
    evidence_entity_id: str
    link_metadata: dict[str, Any] = Field(default_factory=dict)


class ConnectorImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    connector_type: Literal["microsoft_graph"]
    connector_run_id: str
    connector_manifest_hash: str | None = None
    import_review_status: str = "imported"
    scan_result: dict[str, Any]


# ---------------------------------------------------------------------------
# Pydantic response models
# ---------------------------------------------------------------------------


class EngagementResponse(BaseModel):
    id: str
    tenant_id: str
    client_name: str
    client_domain: str | None
    assessor_id: str
    assessment_type: str
    status: str
    scheduled_date: str | None
    engagement_metadata: dict[str, Any]
    schema_version: str
    created_at: str
    updated_at: str


class EngagementListResponse(BaseModel):
    items: list[EngagementResponse]
    cursor: str | None
    total_count: int


class ScanResultSummaryResponse(BaseModel):
    """Metadata-only view returned by list endpoints — raw_payload excluded."""

    id: str
    tenant_id: str
    engagement_id: str
    source_type: str
    schema_version: str
    collected_at: str
    evidence_hash: str
    object_count: int
    created_at: str


class ScanResultResponse(BaseModel):
    """Full detail view returned by single-record GET and POST ingest."""

    id: str
    tenant_id: str
    engagement_id: str
    source_type: str
    schema_version: str
    collected_at: str
    evidence_hash: str
    raw_payload: dict[str, Any]
    normalized_payload: dict[str, Any] | None
    object_count: int
    finding_count: int = 0
    created_at: str


class DocumentAnalysisResponse(BaseModel):
    id: str
    tenant_id: str
    engagement_id: str
    document_name: str
    document_classification: str
    document_hash: str | None
    version_label: str | None
    approved_by: str | None
    approval_date: str | None
    freshness_date: str | None
    analysis_findings: list[Any]
    gaps_identified: list[Any]
    schema_version: str
    created_at: str
    updated_at: str


class ObservationResponse(BaseModel):
    id: str
    tenant_id: str
    engagement_id: str
    domain: str
    observation_type: str
    severity: str
    title: str
    description: str
    interview_role: str | None
    structured_evidence: dict[str, Any]
    linked_finding_ids: list[Any]
    assessor_id: str
    schema_version: str
    created_at: str


class FindingResponse(BaseModel):
    id: str
    tenant_id: str
    engagement_id: str
    finding_type: str
    findings_hash: str
    severity: str
    status: str
    title: str
    description: str
    source_attribution: str
    confidence_score: int
    framework_mappings: list[Any]
    nist_ai_rmf_mappings: list[Any]
    evidence_ref_ids: list[Any]
    remediation_hint: str | None
    schema_version: str
    created_at: str
    updated_at: str


class FindingListResponse(BaseModel):
    items: list[FindingResponse]
    total_count: int


class EvidenceLinkResponse(BaseModel):
    id: str
    tenant_id: str
    engagement_id: str
    source_entity_type: str
    source_entity_id: str
    evidence_entity_type: str
    evidence_entity_id: str
    link_metadata: dict[str, Any]
    created_at: str
    schema_version: str


class EngagementSummaryResponse(BaseModel):
    engagement_id: str
    tenant_id: str
    client_name: str
    status: str
    total_scan_results: int
    total_document_analyses: int
    total_observations: int
    total_findings: int
    total_evidence_links: int
    findings_by_severity: dict[str, int]
    open_findings_count: int
    critical_findings_count: int
    schema_version: str


class AuditEventResponse(BaseModel):
    id: str
    engagement_id: str
    event_type: str
    actor: str
    reason_code: str
    payload: dict[str, Any]
    schema_version: str
    created_at: str


class ConfidenceImpactResponse(BaseModel):
    reason: str
    delta: int
    affected_scope: str


class ReadinessGateResponse(BaseModel):
    gate_id: str
    gate_type: str
    readiness_category: str
    severity: str
    priority: int
    status: str
    title: str
    explanation: str
    why_it_matters: str
    evidence_required: list[str]
    evidence_present: list[str]
    missing_items: list[str]
    related_entity_ids: list[str]
    blocks_status_transition: list[str]
    recommended_action_id: str | None
    confidence_impact: ConfidenceImpactResponse | None


class NextActionResponse(BaseModel):
    action_id: str
    priority: int
    title: str
    instruction: str
    why_it_matters: str
    closes_gate_ids: list[str]
    required_input_type: str
    target_ui_section: str
    expected_evidence: list[str]
    safe_for_junior_assessor: bool
    severity: str


class EscalationItemResponse(BaseModel):
    escalation_id: str
    severity: str
    reason: str
    ambiguity_type: str
    related_entities: list[str]
    recommended_reviewer_role: str
    must_block_progression: bool


class TransitionBlockerResponse(BaseModel):
    target_status: str
    blocked_by_gate_ids: list[str]
    explanation: str


class AssetCandidateActionResponse(BaseModel):
    candidate_action_id: str
    source_type: str
    source_entity_id: str
    title: str
    instruction: str
    lineage_refs: list[str]
    candidate_type: str
    risk_signal: str
    confidence: int
    evidence_refs: list[str]
    promotion_state: str
    target_ui_section: str


class ContinuityOpportunityResponse(BaseModel):
    opportunity_id: str
    opportunity_type: str
    title: str
    related_entity_ids: list[str]
    recommended_follow_up: str


class ExecutionStateResponse(BaseModel):
    engagement_id: str
    assessment_type: str
    playbook_id: str
    playbook_version: str
    overall_readiness_state: str
    readiness_score: int
    completion_ratio: float
    blocking_gate_count: int
    warning_gate_count: int
    completed_gate_count: int
    gates: list[ReadinessGateResponse]
    next_actions: list[NextActionResponse]
    escalation_items: list[EscalationItemResponse]
    transition_blockers: list[TransitionBlockerResponse]
    asset_candidate_actions: list[AssetCandidateActionResponse]
    continuity_opportunities: list[ContinuityOpportunityResponse]
    readiness_categories: dict[str, str]
    generated_at: str
    schema_version: str


class PlaybookNextActionResponse(BaseModel):
    action_id: str
    priority: int
    title: str
    instruction: str
    why_it_matters: str
    closes_gate_ids: list[str]
    required_input_type: str
    target_ui_section: str
    expected_evidence: list[str]
    safe_for_junior_assessor: bool
    severity: str
    blocking: bool
    action_type: str
    deep_link: str | None


class PlaybookProgressResponse(BaseModel):
    engagement_id: str
    current_status: str
    completion_pct: float
    blocking_count: int
    actions: list[PlaybookNextActionResponse]
    generated_at: str


class AffectedEntitySummaryResponse(BaseModel):
    entity_type: str
    count: int
    label: str


class FindingExplanationResponse(BaseModel):
    finding_id: str
    finding_type: str
    severity: str
    title: str
    plain_summary: str
    what_it_means: str
    affected_entities: list[AffectedEntitySummaryResponse]
    registry_recommendation: str
    evidence_count: int
    source_scan_ids: list[str]
    last_seen: str
    explanation_confidence: float
    signals_used: list[str]
    framework_impact: list[str]
    template: str
    explanation_version: str
    generated_at: str
    schema_version: str


class ConnectorImportResponse(BaseModel):
    engagement_id: str
    scan_result_id: str
    connector_type: str
    connector_run_id: str
    connector_import_id: str
    manifest_hash: str
    integrity_hash: str
    verification_status: str
    verification_checks: list[str]
    findings_imported: int
    evidence_links_imported: int
    asset_candidates_detected: int
    import_status: str
    report_id: str | None = None
    schema_version: str


# ---------------------------------------------------------------------------
# Converters
# ---------------------------------------------------------------------------


def _engagement_to_response(eng: FaEngagement) -> EngagementResponse:
    return EngagementResponse(
        id=eng.id,
        tenant_id=eng.tenant_id,
        client_name=eng.client_name,
        client_domain=eng.client_domain,
        assessor_id=eng.assessor_id,
        assessment_type=eng.assessment_type,
        status=eng.status,
        scheduled_date=eng.scheduled_date,
        engagement_metadata=eng.engagement_metadata or {},
        schema_version=eng.schema_version,
        created_at=eng.created_at,
        updated_at=eng.updated_at,
    )


def _scan_result_to_summary(r: FaScanResult) -> ScanResultSummaryResponse:
    return ScanResultSummaryResponse(
        id=r.id,
        tenant_id=r.tenant_id,
        engagement_id=r.engagement_id,
        source_type=r.source_type,
        schema_version=r.schema_version,
        collected_at=r.collected_at,
        evidence_hash=r.evidence_hash,
        object_count=r.object_count,
        created_at=r.created_at,
    )


def _scan_result_to_response(r: FaScanResult) -> ScanResultResponse:
    return ScanResultResponse(
        id=r.id,
        tenant_id=r.tenant_id,
        engagement_id=r.engagement_id,
        source_type=r.source_type,
        schema_version=r.schema_version,
        collected_at=r.collected_at,
        evidence_hash=r.evidence_hash,
        raw_payload=r.raw_payload or {},
        normalized_payload=r.normalized_payload,
        object_count=r.object_count,
        finding_count=r.finding_count,
        created_at=r.created_at,
    )


def _doc_analysis_to_response(a: FaDocumentAnalysis) -> DocumentAnalysisResponse:
    return DocumentAnalysisResponse(
        id=a.id,
        tenant_id=a.tenant_id,
        engagement_id=a.engagement_id,
        document_name=a.document_name,
        document_classification=a.document_classification,
        document_hash=a.document_hash,
        version_label=a.version_label,
        approved_by=a.approved_by,
        approval_date=a.approval_date,
        freshness_date=a.freshness_date,
        analysis_findings=a.analysis_findings or [],
        gaps_identified=a.gaps_identified or [],
        schema_version=a.schema_version,
        created_at=a.created_at,
        updated_at=a.updated_at,
    )


def _observation_to_response(o: FaFieldObservation) -> ObservationResponse:
    return ObservationResponse(
        id=o.id,
        tenant_id=o.tenant_id,
        engagement_id=o.engagement_id,
        domain=o.domain,
        observation_type=o.observation_type,
        severity=o.severity,
        title=o.title,
        description=o.description,
        interview_role=o.interview_role,
        structured_evidence=o.structured_evidence or {},
        linked_finding_ids=o.linked_finding_ids or [],
        assessor_id=o.assessor_id,
        schema_version=o.schema_version,
        created_at=o.created_at,
    )


def _finding_to_response(f: FaNormalizedFinding) -> FindingResponse:
    return FindingResponse(
        id=f.id,
        tenant_id=f.tenant_id,
        engagement_id=f.engagement_id,
        finding_type=f.finding_type,
        findings_hash=f.findings_hash,
        severity=f.severity,
        status=f.status,
        title=f.title,
        description=f.description,
        source_attribution=f.source_attribution,
        confidence_score=f.confidence_score,
        framework_mappings=f.framework_mappings or [],
        nist_ai_rmf_mappings=f.nist_ai_rmf_mappings or [],
        evidence_ref_ids=f.evidence_ref_ids or [],
        remediation_hint=f.remediation_hint,
        schema_version=f.schema_version,
        created_at=f.created_at,
        updated_at=f.updated_at,
    )


def _evidence_link_to_response(lnk: FaEvidenceLink) -> EvidenceLinkResponse:
    return EvidenceLinkResponse(
        id=lnk.id,
        tenant_id=lnk.tenant_id,
        engagement_id=lnk.engagement_id,
        source_entity_type=lnk.source_entity_type,
        source_entity_id=lnk.source_entity_id,
        evidence_entity_type=lnk.evidence_entity_type,
        evidence_entity_id=lnk.evidence_entity_id,
        link_metadata=lnk.link_metadata or {},
        created_at=lnk.created_at,
        schema_version=lnk.schema_version,
    )


# ---------------------------------------------------------------------------
# Routes — Engagements
# ---------------------------------------------------------------------------


@router.get(
    "/engagements",
    response_model=EngagementListResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_engagements_route(
    request: Request,
    status_filter: str | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=100),
    cursor: str | None = Query(None),
    db: Session = Depends(auth_ctx_db_session),
) -> EngagementListResponse:
    tenant_id = _resolve_caller_tenant(request)
    rows = list_engagements(
        db,
        tenant_id=tenant_id,
        status_filter=status_filter,
        limit=limit,
        cursor=cursor,
    )
    next_cursor = rows[-1].created_at if len(rows) == limit else None
    total = db.execute(
        select(func.count(FaEngagement.id)).where(FaEngagement.tenant_id == tenant_id)
    ).scalar_one()
    return EngagementListResponse(
        items=[_engagement_to_response(r) for r in rows],
        cursor=next_cursor,
        total_count=total,
    )


@router.post(
    "/engagements",
    response_model=EngagementResponse,
    status_code=201,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def create_engagement_route(
    request: Request,
    body: CreateEngagementRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> EngagementResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)
    eng = create_engagement(
        db,
        tenant_id=tenant_id,
        client_name=body.client_name,
        client_domain=body.client_domain,
        assessor_id=body.assessor_id,
        assessment_type=body.assessment_type.value,
        scheduled_date=body.scheduled_date,
        engagement_metadata=body.engagement_metadata,
        actor=actor,
    )
    audit_payload = {
        "client_name": body.client_name,
        "assessment_type": body.assessment_type.value,
        "assessor_id": body.assessor_id,
    }
    emit_engagement_audit_event(
        db,
        tenant_id=tenant_id,
        engagement_id=eng.id,
        event_type="engagement.created",
        actor=actor,
        reason_code="ENGAGEMENT_CREATED",
        payload=audit_payload,
    )
    emit_fa_timeline_event(
        db,
        tenant_id=tenant_id,
        engagement_id=eng.id,
        event_type="field_assessment.engagement.created",
        occurred_at=eng.created_at,
        payload=audit_payload,
    )
    db.commit()
    db.refresh(eng)
    return _engagement_to_response(eng)


@router.get(
    "/engagements/{engagement_id}",
    response_model=EngagementResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_engagement_route(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> EngagementResponse:
    tenant_id = _resolve_caller_tenant(request)
    try:
        eng = get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    return _engagement_to_response(eng)


@router.patch(
    "/engagements/{engagement_id}/status",
    response_model=EngagementResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def transition_engagement_route(
    engagement_id: str,
    request: Request,
    body: TransitionEngagementRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> EngagementResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)

    # Resolve engagement first so gate evaluation has the eng object.
    try:
        eng = get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    # Gate enforcement: only run the expensive evaluation for statuses that have
    # readiness gate requirements. Ungated transitions (e.g. scheduled→pre_visit)
    # skip it entirely.
    gate_snapshot: dict[str, Any] = {}
    if body.new_status in _GATED_STATUSES:
        execution_state = _evaluate_execution_state(db, eng=eng, tenant_id=tenant_id)
        blockers = [
            b
            for b in execution_state.transition_blockers
            if b.target_status == body.new_status
        ]
        if blockers:
            blocker = blockers[0]
            blocked_gate_ids = blocker.blocked_by_gate_ids
            not_ready_reasons = [
                {
                    "gate_id": g.gate_id,
                    "title": g.title,
                    "missing_items": g.missing_items,
                    "recommended_action_id": g.recommended_action_id,
                }
                for g in execution_state.gates
                if g.gate_id in blocked_gate_ids and g.status == "blocked"
            ]
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "ENGAGEMENT_GATE_BLOCKED",
                    "message": blocker.explanation,
                    "blocked_by_gate_ids": blocked_gate_ids,
                    "not_ready_reasons": not_ready_reasons,
                    "readiness_score": execution_state.readiness_score,
                },
            )
        # Snapshot of gate state at transition time — verifiable audit anchor.
        gate_snapshot = {
            "gates_evaluated": [g.gate_id for g in execution_state.gates],
            "gates_passed": [
                g.gate_id for g in execution_state.gates if g.status == "passed"
            ],
            "readiness_score": execution_state.readiness_score,
        }

    try:
        eng = transition_engagement(
            db,
            engagement_id=engagement_id,
            tenant_id=tenant_id,
            new_status=body.new_status,
            actor=actor,
        )
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    except InvalidEngagementTransition as exc:
        raise HTTPException(
            status_code=409,
            detail=api_error("INVALID_ENGAGEMENT_TRANSITION", exc.message),
        )

    transition_payload: dict[str, Any] = {
        "new_status": body.new_status,
        "reason": body.reason,
        **gate_snapshot,
    }
    emit_engagement_audit_event(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        event_type="engagement.status_transitioned",
        actor=actor,
        reason_code="ENGAGEMENT_STATUS_TRANSITIONED",
        payload=transition_payload,
    )
    emit_fa_timeline_event(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        event_type="field_assessment.engagement.transitioned",
        occurred_at=eng.updated_at,
        payload=transition_payload,
    )
    if body.new_status == "delivered":
        promote_engagement_to_governance(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            gate_snapshot=gate_snapshot,
            baseline_readiness_score=gate_snapshot.get("readiness_score", 0),
        )
    db.commit()
    db.refresh(eng)
    return _engagement_to_response(eng)


# ---------------------------------------------------------------------------
# Routes — Scan results
# ---------------------------------------------------------------------------


@router.post(
    "/engagements/{engagement_id}/scan-results",
    response_model=ScanResultResponse,
    status_code=201,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def ingest_scan_result_route(
    engagement_id: str,
    request: Request,
    body: IngestScanResultRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> ScanResultResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)

    # Verify engagement belongs to tenant
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    # Compute evidence hash over the original payload first so we can record it
    # in the quarantine store even if validation fails.
    original_hash = compute_evidence_hash(body.raw_payload)

    # Schema version allowlist + quarantine + required-field checks.
    # On failure: record to quarantine store for audit, then reject with 422.
    deprecation_notice: str | None = None
    try:
        deprecation_notice = validate_scan_payload(
            body.source_type.value, body.schema_version, body.raw_payload
        )
    except ScanValidationError as exc:
        create_quarantined_scan(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            source_type=body.source_type.value,
            schema_version=body.schema_version,
            quarantine_reason="SCAN_VALIDATION_ERROR",
            quarantine_detail=exc.message,
            payload_hash=original_hash,
            object_count=body.object_count,
        )
        emit_engagement_audit_event(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            event_type="scan_result.quarantined",
            actor=actor,
            reason_code="SCAN_VALIDATION_ERROR",
            payload={
                "source_type": body.source_type.value,
                "schema_version": body.schema_version,
                "payload_hash": original_hash,
                "quarantine_detail": exc.message,
            },
        )
        db.commit()
        raise HTTPException(
            status_code=422, detail=api_error("SCAN_VALIDATION_ERROR", exc.message)
        )
    except ScanQuarantinedError as exc:
        create_quarantined_scan(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            source_type=body.source_type.value,
            schema_version=body.schema_version,
            quarantine_reason="SCAN_QUARANTINED",
            quarantine_detail=exc.message,
            payload_hash=original_hash,
            object_count=body.object_count,
        )
        emit_engagement_audit_event(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            event_type="scan_result.quarantined",
            actor=actor,
            reason_code="SCAN_QUARANTINED",
            payload={
                "source_type": body.source_type.value,
                "schema_version": body.schema_version,
                "payload_hash": original_hash,
                "quarantine_detail": exc.message,
            },
        )
        db.commit()
        raise HTTPException(
            status_code=422, detail=api_error("SCAN_QUARANTINED", exc.message)
        )

    if body.expected_evidence_hash is not None:
        if original_hash != body.expected_evidence_hash:
            raise HTTPException(
                status_code=422,
                detail=api_error(
                    "EVIDENCE_HASH_MISMATCH", "payload hash does not match expected"
                ),
            )

    # Redact credentials/secrets before storage.
    redaction = redact_payload(body.raw_payload)

    result = create_scan_result(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        source_type=body.source_type.value,
        schema_version=body.schema_version,
        collected_at=body.collected_at,
        raw_payload=redaction.payload,
        normalized_payload=body.normalized_payload,
        object_count=body.object_count,
        evidence_hash=original_hash,
    )

    # If the caller provided a normalized_payload with a "findings" key, extract
    # and persist FaNormalizedFinding rows now. This closes the evidence pipeline
    # gap between manual uploads and connector-driven imports.
    normalized_finding_count = 0
    if body.normalized_payload and isinstance(body.normalized_payload, dict):
        findings_from_payload = normalize_scan_findings(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            scan_result=result,
            normalized_payload=body.normalized_payload,
            source_attribution=f"manual_upload:{body.source_type.value}",
        )
        normalized_finding_count = len(findings_from_payload)

    scan_audit_payload: dict[str, Any] = {
        "scan_result_id": result.id,
        "source_type": body.source_type.value,
        "object_count": body.object_count,
        "evidence_hash": result.evidence_hash,
        "redacted_field_count": redaction.redacted_count,
        "redacted_paths": redaction.redacted_paths,
        "normalized_finding_count": normalized_finding_count,
    }
    if deprecation_notice:
        scan_audit_payload["schema_version_deprecation_notice"] = deprecation_notice
    emit_engagement_audit_event(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        event_type="scan_result.ingested",
        actor=actor,
        reason_code="SCAN_RESULT_INGESTED",
        payload=scan_audit_payload,
    )
    emit_fa_timeline_event(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        event_type="field_assessment.scan.ingested",
        occurred_at=result.created_at,
        payload=scan_audit_payload,
        replay_eligible=True,
    )
    db.commit()
    db.refresh(result)
    return _scan_result_to_response(result)


@router.get(
    "/engagements/{engagement_id}/scan-results",
    response_model=list[ScanResultSummaryResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_scan_results_route(
    engagement_id: str,
    request: Request,
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(auth_ctx_db_session),
) -> list[ScanResultSummaryResponse]:
    tenant_id = _resolve_caller_tenant(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    rows = list_scan_results(
        db, engagement_id=engagement_id, tenant_id=tenant_id, limit=limit
    )
    return [_scan_result_to_summary(r) for r in rows]


@router.get(
    "/engagements/{engagement_id}/scan-results/{scan_result_id}",
    response_model=ScanResultResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_scan_result_route(
    engagement_id: str,
    scan_result_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> ScanResultResponse:
    tenant_id = _resolve_caller_tenant(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    try:
        result = get_scan_result(
            db,
            scan_result_id=scan_result_id,
            engagement_id=engagement_id,
            tenant_id=tenant_id,
        )
    except ScanResultNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("SCAN_RESULT_NOT_FOUND", exc.message)
        )
    return _scan_result_to_response(result)


# ---------------------------------------------------------------------------
# Routes — Document analyses
# ---------------------------------------------------------------------------


@router.post(
    "/engagements/{engagement_id}/document-analyses",
    response_model=DocumentAnalysisResponse,
    status_code=201,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def register_document_analysis_route(
    engagement_id: str,
    request: Request,
    body: RegisterDocumentAnalysisRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> DocumentAnalysisResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    analysis = create_document_analysis(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        document_name=body.document_name,
        document_classification=body.document_classification.value,
        document_hash=body.document_hash,
        version_label=body.version_label,
        approved_by=body.approved_by,
        approval_date=body.approval_date,
        freshness_date=body.freshness_date,
        analysis_findings=body.analysis_findings,
        gaps_identified=body.gaps_identified,
    )
    emit_engagement_audit_event(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        event_type="document_analysis.registered",
        actor=actor,
        reason_code="DOCUMENT_ANALYSIS_REGISTERED",
        payload={
            "analysis_id": analysis.id,
            "document_name": body.document_name,
            "document_classification": body.document_classification.value,
        },
    )
    db.commit()
    db.refresh(analysis)
    return _doc_analysis_to_response(analysis)


@router.get(
    "/engagements/{engagement_id}/document-analyses",
    response_model=list[DocumentAnalysisResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_document_analyses_route(
    engagement_id: str,
    request: Request,
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(auth_ctx_db_session),
) -> list[DocumentAnalysisResponse]:
    tenant_id = _resolve_caller_tenant(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    rows = list_document_analyses(
        db, engagement_id=engagement_id, tenant_id=tenant_id, limit=limit
    )
    return [_doc_analysis_to_response(r) for r in rows]


# ---------------------------------------------------------------------------
# Routes — Observations
# ---------------------------------------------------------------------------


@router.post(
    "/engagements/{engagement_id}/observations",
    response_model=ObservationResponse,
    status_code=201,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def capture_observation_route(
    engagement_id: str,
    request: Request,
    body: CaptureObservationRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> ObservationResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)
    try:
        eng = get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    observation = create_observation(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        domain=body.domain.value,
        observation_type=body.observation_type.value,
        severity=body.severity.value,
        title=body.title,
        description=body.description,
        interview_role=body.interview_role,
        structured_evidence=body.structured_evidence,
        linked_finding_ids=body.linked_finding_ids,
        assessor_id=eng.assessor_id,
    )
    emit_engagement_audit_event(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        event_type="observation.captured",
        actor=actor,
        reason_code="OBSERVATION_CAPTURED",
        payload={
            "observation_id": observation.id,
            "domain": body.domain.value,
            "severity": body.severity.value,
        },
    )
    db.commit()
    db.refresh(observation)
    return _observation_to_response(observation)


@router.get(
    "/engagements/{engagement_id}/observations",
    response_model=list[ObservationResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_observations_route(
    engagement_id: str,
    request: Request,
    observation_type: str | None = Query(None),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(auth_ctx_db_session),
) -> list[ObservationResponse]:
    tenant_id = _resolve_caller_tenant(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    rows = list_observations(
        db,
        engagement_id=engagement_id,
        tenant_id=tenant_id,
        limit=limit,
        observation_type=observation_type,
    )
    return [_observation_to_response(r) for r in rows]


# ---------------------------------------------------------------------------
# Routes — Findings
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/findings",
    response_model=FindingListResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_findings_route(
    engagement_id: str,
    request: Request,
    severity: str | None = Query(None),
    finding_status: str | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(auth_ctx_db_session),
) -> FindingListResponse:
    tenant_id = _resolve_caller_tenant(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    rows = list_findings(
        db,
        engagement_id=engagement_id,
        tenant_id=tenant_id,
        severity_filter=severity,
        status_filter=finding_status,
        limit=limit,
    )
    count_stmt = select(func.count(FaNormalizedFinding.id)).where(
        FaNormalizedFinding.engagement_id == engagement_id,
        FaNormalizedFinding.tenant_id == tenant_id,
    )
    if severity:
        count_stmt = count_stmt.where(FaNormalizedFinding.severity == severity)
    if finding_status:
        count_stmt = count_stmt.where(FaNormalizedFinding.status == finding_status)
    total = db.execute(count_stmt).scalar_one()
    return FindingListResponse(
        items=[_finding_to_response(r) for r in rows],
        total_count=total,
    )


@router.get(
    "/engagements/{engagement_id}/findings/{finding_id}",
    response_model=FindingResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_finding_route(
    engagement_id: str,
    finding_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> FindingResponse:
    tenant_id = _resolve_caller_tenant(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    try:
        finding = get_finding(
            db,
            finding_id=finding_id,
            engagement_id=engagement_id,
            tenant_id=tenant_id,
        )
    except FindingNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("FINDING_NOT_FOUND", exc.message)
        )
    return _finding_to_response(finding)


# ---------------------------------------------------------------------------
# Routes — Evidence links
# ---------------------------------------------------------------------------


@router.post(
    "/engagements/{engagement_id}/evidence-links",
    response_model=EvidenceLinkResponse,
    status_code=201,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def create_evidence_link_route(
    engagement_id: str,
    request: Request,
    body: CreateEvidenceLinkRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> EvidenceLinkResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    # Orphan prevention: verify evidence entity exists in this engagement
    _EVIDENCE_ENTITY_TABLES: dict[str, type] = {
        "scan_result": FaScanResult,
        "document_analysis": FaDocumentAnalysis,
        "field_observation": FaFieldObservation,
    }
    evidence_model = _EVIDENCE_ENTITY_TABLES.get(body.evidence_entity_type.value)
    if evidence_model is not None:
        exists = db.execute(
            select(evidence_model.id).where(  # type: ignore[attr-defined]
                evidence_model.id == body.evidence_entity_id,  # type: ignore[attr-defined]
                evidence_model.engagement_id == engagement_id,  # type: ignore[attr-defined]
                evidence_model.tenant_id == tenant_id,  # type: ignore[attr-defined]
            )
        ).scalar_one_or_none()
        if exists is None:
            raise HTTPException(
                status_code=422,
                detail=api_error(
                    "EVIDENCE_ENTITY_NOT_FOUND",
                    f"evidence entity {body.evidence_entity_id!r} not found in engagement",
                ),
            )

    try:
        link = create_evidence_link(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            source_entity_type=body.source_entity_type,
            source_entity_id=body.source_entity_id,
            evidence_entity_type=body.evidence_entity_type.value,
            evidence_entity_id=body.evidence_entity_id,
            link_metadata=body.link_metadata,
        )
    except EvidenceLinkDuplicate:
        raise HTTPException(
            status_code=409,
            detail=api_error("EVIDENCE_LINK_DUPLICATE", "evidence link already exists"),
        )
    link_audit_payload = {
        "link_id": link.id,
        "source_entity_type": body.source_entity_type,
        "source_entity_id": body.source_entity_id,
        "evidence_entity_type": body.evidence_entity_type.value,
        "evidence_entity_id": body.evidence_entity_id,
    }
    emit_engagement_audit_event(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        event_type="evidence_link.created",
        actor=actor,
        reason_code="EVIDENCE_LINK_CREATED",
        payload=link_audit_payload,
    )
    emit_fa_timeline_event(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        event_type="field_assessment.evidence.linked",
        occurred_at=link.created_at,
        payload=link_audit_payload,
    )
    db.commit()
    db.refresh(link)
    return _evidence_link_to_response(link)


@router.get(
    "/engagements/{engagement_id}/evidence-links",
    response_model=list[EvidenceLinkResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_evidence_links_route(
    engagement_id: str,
    request: Request,
    source_entity_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(auth_ctx_db_session),
) -> list[EvidenceLinkResponse]:
    tenant_id = _resolve_caller_tenant(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    rows = list_evidence_links(
        db,
        engagement_id=engagement_id,
        tenant_id=tenant_id,
        source_entity_id=source_entity_id,
        limit=limit,
    )
    return [_evidence_link_to_response(r) for r in rows]


# ---------------------------------------------------------------------------
# Route — Summary
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/summary",
    response_model=EngagementSummaryResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_engagement_summary_route(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> EngagementSummaryResponse:
    tenant_id = _resolve_caller_tenant(request)
    try:
        eng = get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    total_scan_results = db.execute(
        select(func.count(FaScanResult.id)).where(
            FaScanResult.engagement_id == engagement_id,
            FaScanResult.tenant_id == tenant_id,
        )
    ).scalar_one()

    total_document_analyses = db.execute(
        select(func.count(FaDocumentAnalysis.id)).where(
            FaDocumentAnalysis.engagement_id == engagement_id,
            FaDocumentAnalysis.tenant_id == tenant_id,
        )
    ).scalar_one()

    total_observations = db.execute(
        select(func.count(FaFieldObservation.id)).where(
            FaFieldObservation.engagement_id == engagement_id,
            FaFieldObservation.tenant_id == tenant_id,
        )
    ).scalar_one()

    total_findings = db.execute(
        select(func.count(FaNormalizedFinding.id)).where(
            FaNormalizedFinding.engagement_id == engagement_id,
            FaNormalizedFinding.tenant_id == tenant_id,
        )
    ).scalar_one()

    # Findings by severity
    severity_rows = db.execute(
        select(FaNormalizedFinding.severity, func.count(FaNormalizedFinding.id))
        .where(
            FaNormalizedFinding.engagement_id == engagement_id,
            FaNormalizedFinding.tenant_id == tenant_id,
        )
        .group_by(FaNormalizedFinding.severity)
    ).all()
    findings_by_severity: dict[str, int] = {row[0]: row[1] for row in severity_rows}

    open_findings_count = db.execute(
        select(func.count(FaNormalizedFinding.id)).where(
            FaNormalizedFinding.engagement_id == engagement_id,
            FaNormalizedFinding.tenant_id == tenant_id,
            FaNormalizedFinding.status == "open",
        )
    ).scalar_one()

    total_evidence_links = db.execute(
        select(func.count(FaEvidenceLink.id)).where(
            FaEvidenceLink.engagement_id == engagement_id,
            FaEvidenceLink.tenant_id == tenant_id,
        )
    ).scalar_one()

    return EngagementSummaryResponse(
        engagement_id=engagement_id,
        tenant_id=tenant_id,
        client_name=eng.client_name,
        status=eng.status,
        total_scan_results=total_scan_results,
        total_document_analyses=total_document_analyses,
        total_observations=total_observations,
        total_findings=total_findings,
        total_evidence_links=total_evidence_links,
        findings_by_severity=findings_by_severity,
        open_findings_count=open_findings_count,
        critical_findings_count=findings_by_severity.get("critical", 0),
        schema_version="1.0",
    )


# ---------------------------------------------------------------------------
# Internal helper — shared execution state evaluation
# ---------------------------------------------------------------------------


def _evaluate_execution_state(db: Session, *, eng: Any, tenant_id: str) -> Any:
    """Fetch all engagement evidence and build a deterministic ExecutionState.

    Shared by the GET /execution-state route and the gate enforcement check in
    PATCH /status. Queries are identical; the only difference is who uses the result.
    """
    engagement_id = eng.id
    scans = list_scan_results(
        db, engagement_id=engagement_id, tenant_id=tenant_id, limit=100
    )
    documents = list_document_analyses(
        db, engagement_id=engagement_id, tenant_id=tenant_id, limit=100
    )
    observations = list_observations(
        db, engagement_id=engagement_id, tenant_id=tenant_id, limit=100
    )
    findings = list_findings(
        db,
        engagement_id=engagement_id,
        tenant_id=tenant_id,
        severity_filter=None,
        status_filter=None,
        limit=100,
    )
    evidence_links = list_evidence_links(
        db,
        engagement_id=engagement_id,
        tenant_id=tenant_id,
        source_entity_id=None,
        limit=100,
    )
    reports = list(
        db.execute(
            select(GovernanceReportRecord).where(
                GovernanceReportRecord.assessment_id == engagement_id,
                GovernanceReportRecord.tenant_id == tenant_id,
            )
        )
        .scalars()
        .all()
    )
    playbook = get_playbook(eng.assessment_type)
    return build_execution_state(
        engagement=eng,
        playbook=playbook,
        scan_results=scans,
        document_analyses=documents,
        observations=observations,
        findings=findings,
        evidence_links=evidence_links,
        generated_at=utc_iso8601_z_now(),
        reports=reports,
    )


# ---------------------------------------------------------------------------
# Route — Deterministic execution state
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/execution-state",
    response_model=ExecutionStateResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_engagement_execution_state_route(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> ExecutionStateResponse:
    tenant_id = _resolve_caller_tenant(request)
    try:
        eng = get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    execution_state = _evaluate_execution_state(db, eng=eng, tenant_id=tenant_id)
    return ExecutionStateResponse(**execution_state.to_dict())


# ---------------------------------------------------------------------------
# Route — Playbook progress + enriched next actions
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/next-actions",
    response_model=PlaybookProgressResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_engagement_next_actions_route(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> PlaybookProgressResponse:
    tenant_id = _resolve_caller_tenant(request)
    try:
        eng = get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    execution_state = _evaluate_execution_state(db, eng=eng, tenant_id=tenant_id)
    progress = compute_next_actions(
        execution_state,
        engagement_id=engagement_id,
        current_status=eng.status,
    )
    return PlaybookProgressResponse(
        engagement_id=progress.engagement_id,
        current_status=progress.current_status,
        completion_pct=progress.completion_pct,
        blocking_count=progress.blocking_count,
        actions=[
            PlaybookNextActionResponse(
                action_id=a.action_id,
                priority=a.priority,
                title=a.title,
                instruction=a.instruction,
                why_it_matters=a.why_it_matters,
                closes_gate_ids=a.closes_gate_ids,
                required_input_type=a.required_input_type,
                target_ui_section=a.target_ui_section,
                expected_evidence=a.expected_evidence,
                safe_for_junior_assessor=a.safe_for_junior_assessor,
                severity=a.severity,
                blocking=a.blocking,
                action_type=a.action_type,
                deep_link=a.deep_link,
            )
            for a in progress.actions
        ],
        generated_at=progress.generated_at,
    )


# ---------------------------------------------------------------------------
# Route — Verified connector imports
# ---------------------------------------------------------------------------


@router.post(
    "/engagements/{engagement_id}/connector-runs/msgraph/import",
    response_model=ConnectorImportResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def import_msgraph_connector_run_route(
    engagement_id: str,
    request: Request,
    body: ConnectorImportRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> ConnectorImportResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    try:
        envelope = ConnectorImportEnvelope.model_validate(body.model_dump())
        result = import_msgraph_scan_result(
            db=db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            envelope=envelope,
            actor=actor,
        )
    except ValidationError as exc:
        emit_engagement_audit_event(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            event_type="connector.msgraph.import_integrity_failed",
            actor=actor,
            reason_code="CONNECTOR_PAYLOAD_INVALID",
            payload={
                "connector_type": body.connector_type,
                "connector_run_id": body.connector_run_id,
            },
        )
        db.commit()
        raise HTTPException(
            status_code=422,
            detail=api_error(
                "CONNECTOR_PAYLOAD_INVALID",
                "connector scan_result payload failed schema validation",
            ),
        ) from exc
    except ConnectorTenantMismatch as exc:
        emit_engagement_audit_event(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            event_type="connector.msgraph.import_denied",
            actor=actor,
            reason_code=exc.code,
            payload={
                "connector_type": body.connector_type,
                "connector_run_id": body.connector_run_id,
            },
        )
        db.commit()
        raise HTTPException(
            status_code=404, detail=api_error(exc.code, exc.message)
        ) from exc
    except (
        ConnectorManifestUnverified,
        ConnectorSchemaUnsupported,
        ConnectorAcknowledgmentRequired,
        ConnectorExportUnsafe,
    ) as exc:
        emit_engagement_audit_event(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            event_type="connector.msgraph.import_integrity_failed",
            actor=actor,
            reason_code=exc.code,
            payload={
                "connector_type": body.connector_type,
                "connector_run_id": body.connector_run_id,
            },
        )
        db.commit()
        raise HTTPException(
            status_code=422, detail=api_error(exc.code, exc.message)
        ) from exc
    except ConnectorBridgeError as exc:
        emit_engagement_audit_event(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            event_type="connector.msgraph.import_denied",
            actor=actor,
            reason_code=exc.code,
            payload={
                "connector_type": body.connector_type,
                "connector_run_id": body.connector_run_id,
            },
        )
        db.commit()
        raise HTTPException(
            status_code=422, detail=api_error(exc.code, exc.message)
        ) from exc
    db.commit()
    return ConnectorImportResponse(**result.to_dict())


# ---------------------------------------------------------------------------
# Route — Connector-run asset promotion
# ---------------------------------------------------------------------------


class PromoteConnectorAssetsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dry_run: bool = False


class PromoteConnectorAssetsResponse(BaseModel):
    promoted: int
    updated: int
    skipped: int
    assets: list[dict[str, Any]]


@router.post(
    "/engagements/{engagement_id}/connector-runs/{run_id}/promote-assets",
    response_model=PromoteConnectorAssetsResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def promote_connector_run_assets(
    engagement_id: str,
    run_id: str,
    body: PromoteConnectorAssetsRequest,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> PromoteConnectorAssetsResponse:
    """Promote connector-detected candidates from a specific run to governed assets.

    Idempotent: repeated calls return promoted=0 once all candidates are promoted.
    dry_run=true performs no writes and returns the projected outcome.
    Tenant isolation: only candidates belonging to the caller's tenant are processed.
    """
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)

    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    candidates = (
        db.execute(
            select(GaAssetCandidate).where(
                GaAssetCandidate.tenant_id == tenant_id,
                GaAssetCandidate.engagement_id == engagement_id,
                GaAssetCandidate.scan_result_id == run_id,
                GaAssetCandidate.status == "detected",
            )
        )
        .scalars()
        .all()
    )

    if body.dry_run:
        projected: list[dict[str, Any]] = []
        for c in candidates:
            external_id = f"{c.source_type}:{c.risk_signal}"
            existing = (
                db.execute(
                    select(GaAsset)
                    .where(
                        GaAsset.tenant_id == tenant_id,
                        GaAsset.external_id == external_id,
                    )
                    .limit(1)
                )
                .scalars()
                .first()
            )
            projected.append(
                {
                    "id": c.candidate_id,
                    "type": c.suggested_asset_type,
                    "action": "updated" if existing else "promoted",
                }
            )
        n_promoted = sum(1 for a in projected if a["action"] == "promoted")
        n_updated = sum(1 for a in projected if a["action"] == "updated")
        return PromoteConnectorAssetsResponse(
            promoted=n_promoted,
            updated=n_updated,
            skipped=0,
            assets=projected,
        )

    n_promoted = n_updated = n_skipped = 0
    assets_out: list[dict[str, Any]] = []

    for c in candidates:
        external_id = f"{c.source_type}:{c.risk_signal}"
        existing = (
            db.execute(
                select(GaAsset)
                .where(
                    GaAsset.tenant_id == tenant_id,
                    GaAsset.external_id == external_id,
                )
                .limit(1)
            )
            .scalars()
            .first()
        )

        try:
            asset = _promote_candidate(
                db, candidate=c, actor_email=actor, auto_promoted=False
            )
        except Exception as exc:
            log.warning(
                "promote_connector_assets.skip candidate_id=%s error=%s",
                c.candidate_id,
                exc,
            )
            n_skipped += 1
            continue

        action = "updated" if existing is not None else "promoted"
        if action == "promoted":
            n_promoted += 1
        else:
            n_updated += 1

        assets_out.append(
            {
                "id": asset.asset_id,
                "type": asset.asset_type,
                "action": action,
            }
        )

    db.commit()
    return PromoteConnectorAssetsResponse(
        promoted=n_promoted,
        updated=n_updated,
        skipped=n_skipped,
        assets=assets_out,
    )


# ---------------------------------------------------------------------------
# Route — Audit events (append-only; read-only surface)
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/audit-events",
    response_model=list[AuditEventResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_audit_events_route(
    engagement_id: str,
    request: Request,
    limit: int = Query(100, ge=1, le=100),
    db: Session = Depends(auth_ctx_db_session),
) -> list[AuditEventResponse]:
    tenant_id = _resolve_caller_tenant(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    rows = list_audit_events(
        db, engagement_id=engagement_id, tenant_id=tenant_id, limit=limit
    )
    return [
        AuditEventResponse(
            id=r.id,
            engagement_id=r.engagement_id,
            event_type=r.event_type,
            actor=r.actor,
            reason_code=r.reason_code,
            payload=r.payload or {},
            schema_version=r.schema_version,
            created_at=r.created_at,
        )
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Route — Baseline pinning (Trust but Verify: explicit, named, audited)
# ---------------------------------------------------------------------------


class PinBaselineBody(BaseModel):
    scan_result_id: str = Field(..., min_length=1, max_length=64)
    rationale: str | None = Field(None, max_length=1024)


class PinBaselineResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    engagement_id: str
    pinned_scan_id: str
    actor_email: str
    rationale: str | None
    is_active: bool
    pinned_at: str


@router.post(
    "/engagements/{engagement_id}/baseline",
    response_model=PinBaselineResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def pin_baseline(
    engagement_id: str,
    body: PinBaselineBody,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> PinBaselineResponse:
    """Pin a scan result as the canonical drift baseline for this engagement.

    Drift reports always compute against the active baseline — never auto-select.
    Pinning de-activates the previous baseline and emits an audit event.
    """
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    # Verify the scan belongs to this engagement/tenant
    scan_row = db.execute(
        select(FaScanResult).where(
            FaScanResult.id == body.scan_result_id,
            FaScanResult.tenant_id == tenant_id,
            FaScanResult.engagement_id == engagement_id,
        )
    ).scalar_one_or_none()
    if scan_row is None:
        raise HTTPException(
            status_code=404,
            detail=api_error(
                "SCAN_NOT_FOUND", "scan_result_id not found for this engagement"
            ),
        )

    now = utc_iso8601_z_now()

    # De-activate previous active baseline
    prev = db.execute(
        select(FaDriftBaseline).where(
            FaDriftBaseline.tenant_id == tenant_id,
            FaDriftBaseline.engagement_id == engagement_id,
            FaDriftBaseline.is_active.is_(True),
        )
    ).scalar_one_or_none()
    if prev is not None:
        prev.is_active = False

    import hashlib

    baseline_id = hashlib.sha256(
        f"{tenant_id}:{engagement_id}:{body.scan_result_id}:{now}".encode()
    ).hexdigest()[:32]
    baseline = FaDriftBaseline(
        id=baseline_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        pinned_scan_id=body.scan_result_id,
        actor_email=actor,
        rationale=body.rationale,
        is_active=True,
        pinned_at=now,
    )
    db.add(baseline)
    emit_engagement_audit_event(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        event_type="drift.baseline_pinned",
        actor=actor,
        reason_code="BASELINE_PINNED",
        payload={"pinned_scan_id": body.scan_result_id, "rationale": body.rationale},
    )
    db.commit()
    return PinBaselineResponse(
        id=baseline.id,
        engagement_id=baseline.engagement_id,
        pinned_scan_id=baseline.pinned_scan_id,
        actor_email=baseline.actor_email,
        rationale=baseline.rationale,
        is_active=baseline.is_active,
        pinned_at=baseline.pinned_at,
    )


# ---------------------------------------------------------------------------
# Route — Drift report
# ---------------------------------------------------------------------------


class DriftFindingOut(BaseModel):
    finding_id: str
    findings_hash: str
    title: str
    severity: str
    baseline_severity: str | None
    delta_class: str
    evidence_ref_ids: list[str]
    rationale: str


class DriftReportResponse(BaseModel):
    tenant_id: str
    engagement_id: str
    baseline_scan_id: str
    current_scan_id: str
    baseline_pinned_at: str
    baseline_pinned_by: str
    baseline_scan_signature: str | None
    current_scan_signature: str | None
    drift_severity: str
    drift_confidence: int
    drift_confidence_reason: str
    baseline_gps: int
    current_gps: int
    gps_delta: int
    counts: dict[str, int]
    domain_subscores: list[dict]
    findings: list[DriftFindingOut]
    alerts_emitted: int
    computed_at: str


@router.get(
    "/engagements/{engagement_id}/drift-report",
    response_model=DriftReportResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_drift_report(
    engagement_id: str,
    request: Request,
    current_scan_id: str = Query(..., description="ID of the current FaScanResult"),
    emit_alerts: bool = Query(
        True, description="Persist alert records for this drift run"
    ),
    db: Session = Depends(auth_ctx_db_session),
) -> DriftReportResponse:
    """Compute drift between the pinned baseline and a specified current scan.

    Returns delta-classified findings, GPS scores, drift severity, NIST subscores,
    and chained scan signatures for independent auditability.
    Requires a pinned baseline — returns 409 when none exists.
    """
    tenant_id = _resolve_caller_tenant(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    baseline_row = db.execute(
        select(FaDriftBaseline).where(
            FaDriftBaseline.tenant_id == tenant_id,
            FaDriftBaseline.engagement_id == engagement_id,
            FaDriftBaseline.is_active.is_(True),
        )
    ).scalar_one_or_none()
    if baseline_row is None:
        raise HTTPException(
            status_code=409,
            detail=api_error(
                "NO_BASELINE",
                "no pinned baseline for this engagement; POST /baseline first",
            ),
        )

    try:
        drift = compute_drift(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            baseline_scan_id=baseline_row.pinned_scan_id,
            current_scan_id=current_scan_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=404, detail=api_error("SCAN_NOT_FOUND", str(exc))
        )

    # Collect open findings for GPS computation
    current_finding_ids_set = {
        f.finding_id for f in drift.findings if f.delta_class != "resolved"
    }
    # Regressed findings were absent from the baseline by definition — exclude them.
    # Only persisted/resolved/escalated/de_escalated represent findings that were
    # actually in the baseline scan.
    baseline_finding_ids_set = {
        f.finding_id
        for f in drift.findings
        if f.delta_class in ("persisted", "resolved", "escalated", "de_escalated")
    }

    current_rows = (
        db.execute(
            select(FaNormalizedFinding).where(
                FaNormalizedFinding.tenant_id == tenant_id,
                FaNormalizedFinding.engagement_id == engagement_id,
                FaNormalizedFinding.id.in_(current_finding_ids_set),
                FaNormalizedFinding.status == "open",
            )
        )
        .scalars()
        .all()
        if current_finding_ids_set
        else []
    )
    baseline_rows = (
        db.execute(
            select(FaNormalizedFinding).where(
                FaNormalizedFinding.tenant_id == tenant_id,
                FaNormalizedFinding.engagement_id == engagement_id,
                FaNormalizedFinding.id.in_(baseline_finding_ids_set),
            )
        )
        .scalars()
        .all()
        if baseline_finding_ids_set
        else []
    )

    current_open_dicts = [
        {
            "severity": r.severity,
            "nist_ai_rmf_mappings": r.nist_ai_rmf_mappings or [],
        }
        for r in current_rows
    ]
    baseline_open_dicts = [
        {
            "severity": r.severity,
            "nist_ai_rmf_mappings": r.nist_ai_rmf_mappings or [],
        }
        for r in baseline_rows
    ]

    # Fetch scan timestamps for confidence + verifiability
    current_scan = db.get(FaScanResult, current_scan_id)
    baseline_scan = db.get(FaScanResult, baseline_row.pinned_scan_id)
    current_collected_at = (
        current_scan.collected_at if current_scan else utc_iso8601_z_now()
    )
    baseline_collected_at = baseline_scan.collected_at if baseline_scan else None

    # Scan signatures from stored manifest (verifiability chain).
    # The MS Graph bridge stores manifest data under normalized_payload["manifest"],
    # not "integrity_manifest". Try both keys for forward compatibility.
    def _extract_signature(scan: Any) -> str | None:
        if not scan:
            return None
        payload = scan.normalized_payload or {}
        manifest = payload.get("manifest") or payload.get("integrity_manifest") or {}
        return (
            manifest.get("integrity_hash")
            or manifest.get("manifest_hash")
            or manifest.get("manifest_signature")
        )

    posture = compute_posture_delta(
        drift,
        current_open_findings=current_open_dicts,
        baseline_open_findings=baseline_open_dicts,
        current_scan_collected_at=current_collected_at,
        baseline_scan_collected_at=baseline_collected_at,
    )

    # Emit alerts if requested
    drift_finding_dicts: list[dict[str, Any]] = [
        {
            "finding_id": f.finding_id,
            "severity": f.severity,
            "title": f.title,
            "delta_class": f.delta_class,
            "baseline_severity": f.baseline_severity,
            "nist_ai_rmf_mappings": [],  # enriched from DB above
        }
        for f in drift.findings
    ]
    # Enrich nist mappings for alert family grouping
    finding_nist_map: dict[str, list[Any]] = {
        r.id: r.nist_ai_rmf_mappings or []
        for r in list(current_rows) + list(baseline_rows)
    }
    for d in drift_finding_dicts:
        finding_id = d.get("finding_id")
        d["nist_ai_rmf_mappings"] = (
            finding_nist_map.get(finding_id, []) if isinstance(finding_id, str) else []
        )

    alerts_emitted = 0
    if emit_alerts:
        alerts = emit_drift_alerts(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            drift_findings=drift_finding_dicts,
        )
        alerts_emitted = len(alerts)
        db.commit()

    now = utc_iso8601_z_now()
    return DriftReportResponse(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        baseline_scan_id=baseline_row.pinned_scan_id,
        current_scan_id=current_scan_id,
        baseline_pinned_at=baseline_row.pinned_at,
        baseline_pinned_by=baseline_row.actor_email,
        baseline_scan_signature=_extract_signature(baseline_scan),
        current_scan_signature=_extract_signature(current_scan),
        drift_severity=posture.drift_severity,
        drift_confidence=posture.drift_confidence,
        drift_confidence_reason=posture.drift_confidence_reason,
        baseline_gps=posture.baseline_gps,
        current_gps=posture.current_gps,
        gps_delta=posture.gps_delta,
        counts=posture.counts,
        domain_subscores=[
            {
                "function": s.function,
                "score": s.score,
                "open_finding_count": s.open_finding_count,
            }
            for s in posture.domain_subscores
        ],
        findings=[
            DriftFindingOut(
                finding_id=f.finding_id,
                findings_hash=f.findings_hash,
                title=f.title,
                severity=f.severity,
                baseline_severity=f.baseline_severity,
                delta_class=f.delta_class,
                evidence_ref_ids=f.evidence_ref_ids,
                rationale=f.rationale,
            )
            for f in drift.findings
        ],
        alerts_emitted=alerts_emitted,
        computed_at=now,
    )


# ---------------------------------------------------------------------------
# Route — Connector schedules
# ---------------------------------------------------------------------------


class ConnectorScheduleBody(BaseModel):
    source_type: str = Field(..., min_length=1, max_length=64)
    cron_expression: str = Field(..., min_length=9, max_length=128)
    trigger_type: str = Field("cron", min_length=1, max_length=64)


class ConnectorScheduleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    engagement_id: str
    source_type: str
    cron_expression: str
    trigger_type: str
    created_by: str
    is_active: bool
    created_at: str
    updated_at: str


@router.post(
    "/engagements/{engagement_id}/connector-schedules",
    response_model=ConnectorScheduleResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def create_connector_schedule(
    engagement_id: str,
    body: ConnectorScheduleBody,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> ConnectorScheduleResponse:
    """Create or update a cron schedule for a connector/engagement pair.

    One active schedule per (engagement_id, source_type). Providing a new
    cron expression for an existing source_type replaces the prior schedule.
    """
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    from services.connectors.drift.scheduler import InvalidTriggerType

    try:
        schedule, is_new = upsert_schedule(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            source_type=body.source_type,
            cron_expression=body.cron_expression,
            created_by=actor,
            trigger_type=body.trigger_type,
        )
    except InvalidCronExpression as exc:
        raise HTTPException(
            status_code=422,
            detail=api_error("INVALID_CRON_EXPRESSION", str(exc)),
        )
    except InvalidTriggerType as exc:
        raise HTTPException(
            status_code=422,
            detail=api_error("INVALID_TRIGGER_TYPE", str(exc)),
        )

    db.commit()
    return ConnectorScheduleResponse(
        id=schedule.id,
        engagement_id=schedule.engagement_id,
        source_type=schedule.source_type,
        cron_expression=schedule.cron_expression,
        trigger_type=schedule.trigger_type,
        created_by=schedule.created_by,
        is_active=schedule.is_active,
        created_at=schedule.created_at,
        updated_at=schedule.updated_at,
    )


@router.get(
    "/engagements/{engagement_id}/connector-schedules",
    response_model=list[ConnectorScheduleResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_connector_schedules(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> list[ConnectorScheduleResponse]:
    """List all connector schedules for an engagement."""
    tenant_id = _resolve_caller_tenant(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    rows = list_schedules(db, tenant_id=tenant_id, engagement_id=engagement_id)
    return [
        ConnectorScheduleResponse(
            id=r.id,
            engagement_id=r.engagement_id,
            source_type=r.source_type,
            cron_expression=r.cron_expression,
            trigger_type=r.trigger_type,
            created_by=r.created_by,
            is_active=r.is_active,
            created_at=r.created_at,
            updated_at=r.updated_at,
        )
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Route — Drift root-cause correlation
# ---------------------------------------------------------------------------


class RootCauseCandidateOut(BaseModel):
    edge_id: str
    edge_type: str
    source_node_id: str
    target_node_id: str
    rationale: str


@router.get(
    "/engagements/{engagement_id}/drift-report/correlation/{finding_id}",
    response_model=list[RootCauseCandidateOut],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_drift_correlation(
    engagement_id: str,
    finding_id: str,
    request: Request,
    baseline_collected_at: str = Query(
        ..., description="collected_at of the baseline scan (ISO 8601)"
    ),
    current_collected_at: str = Query(
        ..., description="collected_at of the current scan (ISO 8601)"
    ),
    db: Session = Depends(auth_ctx_db_session),
) -> list[RootCauseCandidateOut]:
    """Return graph edges that correlate with a finding across a drift window.

    Queries the governance topology graph for edges touching the finding's node
    that were derived between baseline_collected_at and current_collected_at.
    Returns empty list when no correlations are found — not an error.
    """
    tenant_id = _resolve_caller_tenant(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    candidates = find_root_cause_candidates(
        db,
        tenant_id=tenant_id,
        finding_id=finding_id,
        baseline_collected_at=baseline_collected_at,
        current_collected_at=current_collected_at,
    )
    return [
        RootCauseCandidateOut(
            edge_id=c.edge_id,
            edge_type=c.edge_type,
            source_node_id=c.source_node_id,
            target_node_id=c.target_node_id,
            rationale=c.rationale,
        )
        for c in candidates
    ]


# ---------------------------------------------------------------------------
# Route — Drift velocity
# ---------------------------------------------------------------------------


class DriftVelocityResponse(BaseModel):
    tenant_id: str
    engagement_id: str
    scans_analyzed: int
    new_per_day: float
    mttr_days: float | None
    regression_rate: float
    window_start: str
    window_end: str


@router.get(
    "/engagements/{engagement_id}/drift-velocity",
    response_model=DriftVelocityResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_drift_velocity(
    engagement_id: str,
    request: Request,
    n_scans: int = Query(10, ge=2, le=50, description="Max scan history to analyze"),
    db: Session = Depends(auth_ctx_db_session),
) -> DriftVelocityResponse:
    """Compute drift velocity metrics over the last n_scans scan results.

    Returns new_per_day rate, MTTR, and regression rate.
    Returns 404 when fewer than 2 scans exist for the engagement.
    """
    tenant_id = _resolve_caller_tenant(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    result = compute_drift_velocity(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        n_scans=n_scans,
    )
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=api_error(
                "INSUFFICIENT_SCAN_HISTORY",
                "At least 2 scans are required to compute drift velocity.",
            ),
        )
    return DriftVelocityResponse(
        tenant_id=result.tenant_id,
        engagement_id=result.engagement_id,
        scans_analyzed=result.scans_analyzed,
        new_per_day=result.new_per_day,
        mttr_days=result.mttr_days,
        regression_rate=result.regression_rate,
        window_start=result.window_start,
        window_end=result.window_end,
    )


# ---------------------------------------------------------------------------
# Route — Report QA approval
# ---------------------------------------------------------------------------


class ReportQaApproveResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    report_id: str
    qa_approved_by: str
    qa_approved_at: str


@router.post(
    "/engagements/{engagement_id}/reports/{report_id}/qa-approve",
    response_model=ReportQaApproveResponse,
    status_code=200,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def qa_approve_report_route(
    engagement_id: str,
    report_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> ReportQaApproveResponse:
    """Mark a finalized report as QA-approved for client delivery.

    Requires the report to be finalized (is_finalized=True). Once approved,
    the report.qa.approved readiness gate transitions to passed, unblocking
    the engagement from transitioning to 'delivered'.
    """
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)

    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    report = db.execute(
        select(GovernanceReportRecord).where(
            GovernanceReportRecord.id == report_id,
            GovernanceReportRecord.assessment_id == engagement_id,
            GovernanceReportRecord.tenant_id == tenant_id,
        )
    ).scalar_one_or_none()

    if report is None:
        raise HTTPException(
            status_code=404,
            detail=api_error("REPORT_NOT_FOUND", f"report {report_id!r} not found"),
        )

    if not report.is_finalized:
        raise HTTPException(
            status_code=422,
            detail=api_error(
                "REPORT_NOT_FINALIZED",
                "Only finalized reports can be QA-approved.",
            ),
        )

    now = utc_iso8601_z_now()
    report.qa_approved_by = actor
    report.qa_approved_at = now
    db.flush()

    emit_engagement_audit_event(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        event_type="report.qa_approved",
        actor=actor,
        reason_code="REPORT_QA_APPROVED",
        payload={
            "report_id": report_id,
            "qa_approved_by": actor,
            "qa_approved_at": now,
        },
    )
    db.commit()

    return ReportQaApproveResponse(
        report_id=report_id,
        qa_approved_by=actor,
        qa_approved_at=now,
    )


# ---------------------------------------------------------------------------
# Route — Governance promotion (admin retry / status check)
# ---------------------------------------------------------------------------


class PromotionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    tenant_id: str
    engagement_id: str
    status: str
    promoted_at: str
    completed_at: str | None = None
    asset_count: int
    workflow_count: int
    baseline_readiness_score: int
    error_detail: str | None = None


class ReadinessDriftResponse(BaseModel):
    has_prior: bool
    prior_engagement_id: str | None = None
    prior_score: float | None = None
    current_score: float | None = None
    delta: float | None = None
    pct_change: float | None = None
    direction: Literal["improved", "degraded", "stable"] | None = None
    detected_at: str | None = None


def _promotion_to_response(p: GovernancePromotion) -> PromotionResponse:
    return PromotionResponse(
        id=p.id,
        tenant_id=p.tenant_id,
        engagement_id=p.engagement_id,
        status=p.status,
        promoted_at=p.promoted_at,
        completed_at=p.completed_at,
        asset_count=p.asset_count,
        workflow_count=p.workflow_count,
        baseline_readiness_score=p.baseline_readiness_score,
        error_detail=p.error_detail,
    )


@router.post(
    "/engagements/{engagement_id}/promote",
    response_model=PromotionResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
    status_code=200,
)
def promote_engagement_route(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> PromotionResponse:
    """Admin retry / status route for governance promotion.

    Idempotent: returns the existing completed promotion without re-running.
    Retry: re-runs promotion steps if the previous attempt failed.
    Primary trigger is automatic on 'delivered' transition — this route is
    for operator retries and promotion status inspection.
    """
    tenant_id = _resolve_caller_tenant(request)

    try:
        eng = get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    if eng.status != "delivered":
        raise HTTPException(
            status_code=409,
            detail=api_error(
                "ENGAGEMENT_NOT_DELIVERED",
                "Promotion requires engagement status 'delivered'.",
            ),
        )

    existing = get_promotion(db, tenant_id=tenant_id, engagement_id=engagement_id)
    if existing is not None and existing.status == "completed":
        return _promotion_to_response(existing)

    execution_state = _evaluate_execution_state(db, eng=eng, tenant_id=tenant_id)
    gate_snapshot = {
        "gates_evaluated": [g.gate_id for g in execution_state.gates],
        "gates_passed": [
            g.gate_id for g in execution_state.gates if g.status == "passed"
        ],
        "readiness_score": execution_state.readiness_score,
    }

    promotion = promote_engagement_to_governance(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        gate_snapshot=gate_snapshot,
        baseline_readiness_score=execution_state.readiness_score,
    )
    db.commit()
    db.refresh(promotion)
    return _promotion_to_response(promotion)


# ---------------------------------------------------------------------------
# Route — Readiness drift (cross-engagement longitudinal comparison)
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/readiness-drift",
    response_model=ReadinessDriftResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_readiness_drift_route(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> ReadinessDriftResponse:
    """Return cross-engagement readiness drift for an engagement.

    Requires governance:read scope. Tenant is resolved from auth context only.
    Returns 404 for unknown or cross-tenant engagements without leaking existence.
    Returns has_prior=false when this is the tenant's first completed promotion
    or when the current promotion is not yet complete.
    """
    from services.field_assessment.promotion_drift import detect_readiness_drift

    tenant_id = _resolve_caller_tenant(request)

    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    promotion = get_promotion(db, tenant_id=tenant_id, engagement_id=engagement_id)
    if promotion is None or promotion.status != "completed":
        return ReadinessDriftResponse(has_prior=False)

    drift = detect_readiness_drift(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        new_score=promotion.baseline_readiness_score,
    )
    if drift is None:
        return ReadinessDriftResponse(has_prior=False)

    return ReadinessDriftResponse(
        has_prior=True,
        prior_engagement_id=drift.prior_engagement_id,
        prior_score=drift.prior_score,
        current_score=drift.new_score,
        delta=drift.delta,
        pct_change=drift.pct_change,
        direction=drift.direction,
        detected_at=drift.detected_at,
    )


# ---------------------------------------------------------------------------
# Report engine — engagement-scoped (PR 15)
# ---------------------------------------------------------------------------

_VALID_REPORT_TYPES: frozenset[str] = frozenset(
    {"full_assessment", "executive_summary", "findings_register", "control_gap"}
)

_ALL_SECTIONS: list[str] = [
    "findings",
    "remediations",
    "evidence_appendix",
    "framework_summary",
    "confidence",
    "normalized_findings",
]


class CreateEngagementReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_type: str
    include_sections: list[str] | None = None


class EngagementReportSummary(BaseModel):
    report_id: str
    version: int
    status: str
    compiled_at: str
    compiled_by: str | None
    report_type: str | None


class EngagementReportListResponse(BaseModel):
    items: list[EngagementReportSummary]
    limit: int
    offset: int
    total: int


class EngagementReportVerifyResponse(BaseModel):
    valid: bool
    manifest_hash: str
    signature: str | None
    verified_at: str


def _compute_section_hashes(sections: dict[str, Any]) -> dict[str, str]:
    import hashlib
    import json

    result: dict[str, str] = {}
    for name, content in sections.items():
        canonical = json.dumps(
            content, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        result[name] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return result


def _safe_finding_dict(f: FaNormalizedFinding) -> dict[str, Any]:
    return {
        "id": f.id,
        "finding_type": f.finding_type,
        "severity": f.severity,
        "status": f.status,
        "title": f.title,
        "description": f.description,
        "source_attribution": f.source_attribution,
        "confidence_score": f.confidence_score,
        "framework_mappings": f.framework_mappings or [],
        "nist_ai_rmf_mappings": f.nist_ai_rmf_mappings or [],
        "evidence_ref_ids": f.evidence_ref_ids or [],
        "schema_version": f.schema_version,
        "created_at": f.created_at,
    }


def _build_engagement_report_json(
    *,
    engagement_id: str,
    tenant_id: str,
    report_type: str,
    include_sections: list[str] | None,
    db: Session,
) -> tuple[dict[str, Any], dict[str, str]]:
    from services.governance.report import (
        GovernanceReportEngine,
        EvidenceRef,
        ValidationState,
    )
    from services.governance.report.serialization import (
        _serialize_finding,
        _serialize_remediation,
        _serialize_evidence_ref,
        _serialize_confidence,
    )

    active_sections = set(include_sections) if include_sections else set(_ALL_SECTIONS)

    # Collect normalized findings (safe: no raw scan payloads)
    all_findings: list[FaNormalizedFinding] = []
    offset = 0
    while True:
        batch = list_findings(
            db,
            engagement_id=engagement_id,
            tenant_id=tenant_id,
            severity_filter=None,
            status_filter=None,
            limit=100,
            offset=offset,
        )
        all_findings.extend(batch)
        if len(batch) < 100:
            break
        offset += 100

    # Derive synthetic domain scores from normalized findings
    # Maps confidence_score (0-100, higher=better) → domain score
    domain_scores: dict[str, list[float]] = {}
    for f in all_findings:
        mappings = f.framework_mappings or []
        if mappings:
            domain_key = str(
                mappings[0].get("domain", "data_governance")
                if isinstance(mappings[0], dict)
                else "data_governance"
            )
        else:
            domain_key = "data_governance"
        domain_scores.setdefault(domain_key, []).append(float(f.confidence_score))

    scores: dict[str, float] = {}
    for domain, values in domain_scores.items():
        scores[domain] = sum(values) / len(values)

    # Ensure engine has at least one domain to work with
    if not scores:
        scores = {"data_governance": 80.0}

    # Build evidence refs from scan results (metadata only, no raw payloads)
    scan_rows = list_scan_results(
        db, engagement_id=engagement_id, tenant_id=tenant_id, limit=100
    )
    evidence_refs: list[EvidenceRef] = [
        EvidenceRef(
            evidence_id=sr.id,
            source=sr.source_type,
            validation_state=ValidationState.VALIDATED,
            classification="scan_result",
            provenance=f"engagement:{engagement_id}",
            freshness_days=None,
        )
        for sr in scan_rows
    ]

    engine = GovernanceReportEngine()
    report = engine.generate(
        assessment_id=engagement_id,
        tenant_id=tenant_id,
        scores=scores,
        responses={},
        evidence_refs=evidence_refs,
        reviewer_validated=False,
        version=1,
    )

    # Build section content map
    section_content: dict[str, Any] = {}
    if "findings" in active_sections:
        section_content["findings"] = [_serialize_finding(f) for f in report.findings]
    if "remediations" in active_sections:
        section_content["remediations"] = [
            _serialize_remediation(r) for r in report.remediations
        ]
    if "evidence_appendix" in active_sections:
        section_content["evidence_appendix"] = [
            _serialize_evidence_ref(r) for r in report.evidence_appendix
        ]
    if "framework_summary" in active_sections:
        section_content["framework_summary"] = {
            k: sorted(v) for k, v in sorted(report.framework_summary.items())
        }
    if "confidence" in active_sections:
        section_content["confidence"] = _serialize_confidence(report.confidence)
    if "normalized_findings" in active_sections and report_type in (
        "findings_register",
        "full_assessment",
    ):
        section_content["normalized_findings"] = [
            _safe_finding_dict(f) for f in all_findings
        ]

    section_hashes = _compute_section_hashes(section_content)

    report_json: dict[str, Any] = {
        "report_id": report.report_id,
        "assessment_id": report.assessment_id,
        "tenant_id": report.tenant_id,
        "engagement_id": engagement_id,
        "report_type": report_type,
        "version": report.version,
        "schema_version": report.schema_version,
        "manifest_hash": report.manifest_hash,
        "generated_at": report.generated_at,
        **section_content,
    }
    return report_json, section_hashes


@router.post(
    "/engagements/{engagement_id}/reports",
    status_code=201,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def create_engagement_report_route(
    engagement_id: str,
    body: CreateEngagementReportRequest,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Generate a signed, versioned governance report for a field assessment engagement.

    This module is NOT standalone. It is a component of the Field Assessment
    Engagement Substrate and Governance Platform.

    Requires governance:write scope. Tenant is resolved from auth context only.
    Returns 422 for invalid report_type. Returns 404 for unknown or cross-tenant engagements.
    """
    import hashlib
    import json
    import uuid

    from sqlalchemy.exc import IntegrityError

    from services.governance.report.signing import ReportSigningKeyError, sign_report
    from services.governance.report.versioning import get_next_version

    if body.report_type not in _VALID_REPORT_TYPES:
        raise HTTPException(
            status_code=422,
            detail=api_error(
                "INVALID_REPORT_TYPE",
                f"report_type must be one of: {sorted(_VALID_REPORT_TYPES)}",
            ),
        )

    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)

    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    report_json, section_hashes = _build_engagement_report_json(
        engagement_id=engagement_id,
        tenant_id=tenant_id,
        report_type=body.report_type,
        include_sections=body.include_sections,
        db=db,
    )

    now = report_json.get("generated_at", "")
    record: GovernanceReportRecord | None = None
    _MAX_VERSION_RETRIES = 5

    for _attempt in range(_MAX_VERSION_RETRIES):
        # Version must be stamped into report_json before canonical serialization
        # and signing — the stored payload and the signed payload must be identical.
        version = get_next_version(db, tenant_id=tenant_id, engagement_id=engagement_id)
        report_json["version"] = version

        canonical_str = json.dumps(
            report_json, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        manifest_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

        try:
            signature = sign_report(canonical_str)
        except ReportSigningKeyError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=api_error("REPORT_SIGNING_KEY_MISSING", str(exc)),
            )

        record_id = (
            uuid.uuid4().hex[:16]
            + hashlib.sha256(
                f"{tenant_id}:{engagement_id}:{version}:{_attempt}".encode()
            ).hexdigest()[:16]
        )
        record = GovernanceReportRecord(
            id=record_id,
            assessment_id=engagement_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            version=version,
            schema_version="1.0",
            report_type=body.report_type,
            compiled_by=actor,
            manifest_hash=manifest_hash,
            report_json=report_json,
            section_hashes=section_hashes,
            signature=signature,
            generated_at=now,
            is_finalized=True,
        )
        db.add(record)
        try:
            db.flush()
            break
        except IntegrityError:
            db.rollback()
            record = None
            continue
    else:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=api_error(
                "REPORT_VERSION_CONFLICT",
                "Unable to assign a unique report version after concurrent requests. Retry.",
            ),
        )

    db.commit()
    db.refresh(record)

    emit_engagement_audit_event(
        db,
        engagement_id=engagement_id,
        tenant_id=tenant_id,
        event_type="engagement_report_created",
        actor=actor,
        reason_code="report_created",
        payload={
            "report_id": record.id,
            "version": version,
            "report_type": body.report_type,
            "manifest_hash": manifest_hash,
        },
    )

    return {
        "report_id": record.id,
        "version": version,
        "status": "finalized",
        "compiled_at": now,
    }


@router.get(
    "/engagements/{engagement_id}/reports",
    response_model=EngagementReportListResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_engagement_reports_route(
    engagement_id: str,
    request: Request,
    limit: int = Query(100, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> EngagementReportListResponse:
    """List report version summaries for a field assessment engagement.

    This module is NOT standalone. It is a component of the Field Assessment
    Engagement Substrate and Governance Platform.

    Requires governance:read scope. Tenant-scoped; returns 404 for unknown engagements.
    """
    from services.governance.report.versioning import list_versions

    tenant_id = _resolve_caller_tenant(request)

    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    versions = list_versions(db, tenant_id=tenant_id, engagement_id=engagement_id)
    total = len(versions)
    page = versions[offset : offset + limit]

    items = [
        EngagementReportSummary(
            report_id=r.id,
            version=r.version,
            status="finalized" if r.is_finalized else "draft",
            compiled_at=r.generated_at,
            compiled_by=r.compiled_by,
            report_type=r.report_type,
        )
        for r in page
    ]
    return EngagementReportListResponse(
        items=items,
        limit=limit,
        offset=offset,
        total=total,
    )


@router.get(
    "/engagements/{engagement_id}/reports/{version}",
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_engagement_report_route(
    engagement_id: str,
    version: int,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Return the full report document for a specific version.

    This module is NOT standalone. It is a component of the Field Assessment
    Engagement Substrate and Governance Platform.

    Requires governance:read scope. Returns 404 for unknown, cross-tenant, or
    out-of-range version without leaking existence.
    """
    from services.governance.report.versioning import get_version

    tenant_id = _resolve_caller_tenant(request)

    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    record = get_version(
        db, tenant_id=tenant_id, engagement_id=engagement_id, version=version
    )
    if record is None:
        raise HTTPException(
            status_code=404,
            detail=api_error("REPORT_VERSION_NOT_FOUND", "Report version not found."),
        )

    return {
        "report_id": record.id,
        "version": record.version,
        "report_type": record.report_type,
        "compiled_by": record.compiled_by,
        "manifest_hash": record.manifest_hash,
        "section_hashes": record.section_hashes or {},
        "signature": record.signature,
        "generated_at": record.generated_at,
        "schema_version": record.schema_version,
        "report": record.report_json,
    }


@router.get(
    "/engagements/{engagement_id}/reports/{version}/export",
    dependencies=[Depends(require_scopes("governance:read"))],
)
def export_engagement_report_route(
    engagement_id: str,
    version: int,
    request: Request,
    format: str = Query("json", pattern="^(json|pdf)$"),
    db: Session = Depends(auth_ctx_db_session),
) -> Any:
    """Export a report version as JSON or PDF.

    This module is NOT standalone. It is a component of the Field Assessment
    Engagement Substrate and Governance Platform.

    Requires governance:read scope. format=pdf returns 501 if reportlab is not available.
    """
    from services.governance.report.versioning import get_version
    from services.governance.report import (
        ExportUnavailableError,
        deserialize_report,
        export_pdf_bytes,
    )

    tenant_id = _resolve_caller_tenant(request)

    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    record = get_version(
        db, tenant_id=tenant_id, engagement_id=engagement_id, version=version
    )
    if record is None:
        raise HTTPException(
            status_code=404,
            detail=api_error("REPORT_VERSION_NOT_FOUND", "Report version not found."),
        )

    if format == "json":
        return {
            "report_id": record.id,
            "version": record.version,
            "report_type": record.report_type,
            "manifest_hash": record.manifest_hash,
            "signature": record.signature,
            "schema_version": record.schema_version,
            "report": record.report_json,
        }

    # format == "pdf"
    report_data = record.report_json or {}
    try:
        gov_report = deserialize_report(report_data)
    except (ValueError, KeyError):
        raise HTTPException(
            status_code=422,
            detail=api_error(
                "REPORT_DESERIALIZE_ERROR",
                "Stored report cannot be deserialized for PDF export.",
            ),
        )

    try:
        pdf_bytes = export_pdf_bytes(gov_report)
    except ExportUnavailableError:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=api_error(
                "PDF_EXPORT_UNAVAILABLE",
                "PDF export requires reportlab. Install it with: pip install reportlab",
            ),
        )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="report-{engagement_id}-v{version}.pdf"',
            "X-Manifest-Hash": record.manifest_hash,
        },
    )


@router.post(
    "/engagements/{engagement_id}/reports/{version}/verify",
    dependencies=[Depends(require_scopes("governance:read"))],
)
def verify_engagement_report_route(
    engagement_id: str,
    version: int,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> EngagementReportVerifyResponse:
    """Verify the Ed25519 signature of a stored report version.

    This module is NOT standalone. It is a component of the Field Assessment
    Engagement Substrate and Governance Platform.

    Requires governance:read scope. Returns 404 for unknown or cross-tenant reports.
    Missing signature returns valid=False without leaking existence.
    """
    import json

    from services.governance.report.versioning import get_version
    from services.governance.report.signing import ReportSigningKeyError, verify_report

    tenant_id = _resolve_caller_tenant(request)

    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    record = get_version(
        db, tenant_id=tenant_id, engagement_id=engagement_id, version=version
    )
    if record is None:
        raise HTTPException(
            status_code=404,
            detail=api_error("REPORT_VERSION_NOT_FOUND", "Report version not found."),
        )

    now = __import__(
        "services.canonical", fromlist=["utc_iso8601_z_now"]
    ).utc_iso8601_z_now()

    if not record.signature:
        return EngagementReportVerifyResponse(
            valid=False,
            manifest_hash=record.manifest_hash,
            signature=None,
            verified_at=now,
        )

    canonical_str = json.dumps(
        record.report_json, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )

    try:
        valid = verify_report(canonical_str, record.signature)
    except ReportSigningKeyError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=api_error(
                "REPORT_SIGNING_KEY_MISSING",
                "Signing key unavailable for verification.",
            ),
        )

    return EngagementReportVerifyResponse(
        valid=valid,
        manifest_hash=record.manifest_hash,
        signature=record.signature,
        verified_at=now,
    )


@router.get(
    "/engagements/{engagement_id}/findings/{finding_id}/explain",
    response_model=FindingExplanationResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_finding_explanation_route(
    engagement_id: str,
    finding_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> FindingExplanationResponse:
    """Plain-language explanation for a normalized finding.

    Tenant-isolated: resolves caller tenant and enforces it through
    the explain_finding service. Returns 404 for unknown or cross-tenant findings.
    """
    tenant_id = _resolve_caller_tenant(request)
    try:
        exp = explain_finding(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            finding_id=finding_id,
        )
    except FindingNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("FINDING_NOT_FOUND", str(exc))
        )
    try:
        finding = get_finding(
            db,
            finding_id=finding_id,
            engagement_id=engagement_id,
            tenant_id=tenant_id,
        )
    except FindingNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("FINDING_NOT_FOUND", str(exc))
        )
    return FindingExplanationResponse(
        finding_id=finding.id,
        finding_type=finding.finding_type,
        severity=finding.severity,
        title=finding.title,
        plain_summary=exp.plain_summary,
        what_it_means=exp.what_it_means,
        affected_entities=[
            AffectedEntitySummaryResponse(
                entity_type=e.entity_type,
                count=e.count,
                label=e.label,
            )
            for e in exp.affected_entities
        ],
        registry_recommendation=exp.registry_recommendation,
        evidence_count=exp.evidence_count,
        source_scan_ids=exp.source_scan_ids,
        last_seen=exp.last_seen,
        explanation_confidence=exp.explanation_confidence,
        signals_used=exp.signals_used,
        framework_impact=exp.framework_impact,
        template=exp.template,
        explanation_version=exp.explanation_version,
        generated_at=exp.generated_at,
        schema_version=exp.schema_version,
    )


# ---------------------------------------------------------------------------
# Routes — NIST AI RMF Questionnaire
# ---------------------------------------------------------------------------

from api.db_models_questionnaire import FaQuestionnaire, FaQuestionnaireResponse  # noqa: E402
from services.field_assessment.questionnaire_store import (  # noqa: E402
    ControlNotFound,
    VALID_RESPONSE_STATUSES,
    QuestionnaireAlreadySubmitted,
    QuestionnaireNotFound,
    get_coverage,
    get_or_create_questionnaire,
    get_questionnaire,
    list_responses,
    submit_questionnaire,
    update_response,
)


class QuestionnaireInitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework: str = "nist_ai_rmf"


class QuestionnaireResponseItem(BaseModel):
    id: str
    control_id: str
    category: str
    control_name: str
    response_status: str
    evidence_text: str | None
    confidence_score: float | None
    assessor_id: str | None
    updated_at: str


class QuestionnaireResponse(BaseModel):
    id: str
    engagement_id: str
    framework: str
    framework_version: str
    status: str
    submitted_at: str | None
    submitted_by: str | None
    schema_version: str
    created_at: str
    updated_at: str
    responses: list[QuestionnaireResponseItem] = []
    already_existed: bool = False


class UpdateResponseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    response_status: str
    evidence_text: str | None = None
    confidence_score: float | None = None


class UpdateResponseResponse(BaseModel):
    id: str
    control_id: str
    response_status: str
    evidence_text: str | None
    confidence_score: float | None
    updated_at: str


class QuestionnaireCoverageResponse(BaseModel):
    questionnaire_id: str
    total_controls: int
    assessed_count: int
    not_assessed_count: int
    implemented_count: int
    partial_count: int
    not_implemented_count: int
    not_applicable_count: int
    coverage_pct: float
    by_category: dict[str, dict[str, int]]


def _questionnaire_to_response(
    q: FaQuestionnaire,
    responses: list[FaQuestionnaireResponse],
    *,
    already_existed: bool = False,
) -> QuestionnaireResponse:
    return QuestionnaireResponse(
        id=q.id,
        engagement_id=q.engagement_id,
        framework=q.framework,
        framework_version=q.framework_version,
        status=q.status,
        submitted_at=q.submitted_at,
        submitted_by=q.submitted_by,
        schema_version=q.schema_version,
        created_at=q.created_at,
        updated_at=q.updated_at,
        responses=[
            QuestionnaireResponseItem(
                id=r.id,
                control_id=r.control_id,
                category=r.category,
                control_name=r.control_name,
                response_status=r.response_status,
                evidence_text=r.evidence_text,
                confidence_score=r.confidence_score,
                assessor_id=r.assessor_id,
                updated_at=r.updated_at,
            )
            for r in responses
        ],
        already_existed=already_existed,
    )


@router.post(
    "/engagements/{engagement_id}/questionnaires",
    response_model=QuestionnaireResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def create_or_get_questionnaire(
    engagement_id: str,
    request: Request,
    body: QuestionnaireInitRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> QuestionnaireResponse:
    """Idempotent questionnaire initialization.

    Creates a new questionnaire pre-seeded with all framework controls.
    If one already exists for this engagement+framework, returns it unchanged.
    """
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    q, created = get_or_create_questionnaire(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        assessor_id=actor,
        framework=body.framework,
    )
    if created:
        emit_engagement_audit_event(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            event_type="questionnaire.created",
            actor=actor,
            reason_code="QUESTIONNAIRE_INIT",
            payload={"questionnaire_id": q.id, "framework": body.framework},
        )
    db.commit()
    responses = list_responses(db, questionnaire_id=q.id, tenant_id=tenant_id)
    return _questionnaire_to_response(q, responses, already_existed=not created)


@router.get(
    "/engagements/{engagement_id}/questionnaires/{questionnaire_id}",
    response_model=QuestionnaireResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def get_questionnaire_route(
    engagement_id: str,
    questionnaire_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> QuestionnaireResponse:
    tenant_id = _resolve_caller_tenant(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    try:
        q = get_questionnaire(
            db, questionnaire_id=questionnaire_id, tenant_id=tenant_id
        )
    except QuestionnaireNotFound:
        raise HTTPException(
            status_code=404,
            detail=api_error("QUESTIONNAIRE_NOT_FOUND", "Questionnaire not found"),
        )
    responses = list_responses(db, questionnaire_id=q.id, tenant_id=tenant_id)
    return _questionnaire_to_response(q, responses)


@router.patch(
    "/engagements/{engagement_id}/questionnaires/{questionnaire_id}/responses/{control_id}",
    response_model=UpdateResponseResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def patch_questionnaire_response(
    engagement_id: str,
    questionnaire_id: str,
    control_id: str,
    request: Request,
    body: UpdateResponseRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> UpdateResponseResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    if body.response_status not in VALID_RESPONSE_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=api_error(
                "INVALID_RESPONSE_STATUS",
                f"response_status must be one of: {', '.join(sorted(VALID_RESPONSE_STATUSES))}",
            ),
        )
    try:
        r = update_response(
            db,
            questionnaire_id=questionnaire_id,
            control_id=control_id,
            tenant_id=tenant_id,
            response_status=body.response_status,
            evidence_text=body.evidence_text,
            confidence_score=body.confidence_score,
            assessor_id=actor,
        )
    except QuestionnaireNotFound:
        raise HTTPException(
            status_code=404,
            detail=api_error("QUESTIONNAIRE_NOT_FOUND", "Questionnaire not found"),
        )
    except QuestionnaireAlreadySubmitted as exc:
        raise HTTPException(
            status_code=409,
            detail=api_error("QUESTIONNAIRE_ALREADY_SUBMITTED", exc.message),
        )
    except ControlNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("CONTROL_NOT_FOUND", exc.message)
        )
    db.commit()
    return UpdateResponseResponse(
        id=r.id,
        control_id=r.control_id,
        response_status=r.response_status,
        evidence_text=r.evidence_text,
        confidence_score=r.confidence_score,
        updated_at=r.updated_at,
    )


@router.post(
    "/engagements/{engagement_id}/questionnaires/{questionnaire_id}/submit",
    response_model=QuestionnaireResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def submit_questionnaire_route(
    engagement_id: str,
    questionnaire_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> QuestionnaireResponse:
    """Finalize questionnaire and create evidence links to matching findings."""
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    try:
        q = submit_questionnaire(
            db, questionnaire_id=questionnaire_id, tenant_id=tenant_id, actor=actor
        )
    except QuestionnaireNotFound:
        raise HTTPException(
            status_code=404,
            detail=api_error("QUESTIONNAIRE_NOT_FOUND", "Questionnaire not found"),
        )
    emit_engagement_audit_event(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        event_type="questionnaire.submitted",
        actor=actor,
        reason_code="QUESTIONNAIRE_SUBMIT",
        payload={"questionnaire_id": q.id, "framework": q.framework},
    )
    db.commit()
    responses = list_responses(db, questionnaire_id=q.id, tenant_id=tenant_id)
    return _questionnaire_to_response(q, responses)


@router.get(
    "/engagements/{engagement_id}/questionnaires/{questionnaire_id}/coverage",
    response_model=QuestionnaireCoverageResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def get_questionnaire_coverage(
    engagement_id: str,
    questionnaire_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> QuestionnaireCoverageResponse:
    tenant_id = _resolve_caller_tenant(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    try:
        get_questionnaire(db, questionnaire_id=questionnaire_id, tenant_id=tenant_id)
    except QuestionnaireNotFound:
        raise HTTPException(
            status_code=404,
            detail=api_error("QUESTIONNAIRE_NOT_FOUND", "Questionnaire not found"),
        )
    cov = get_coverage(db, questionnaire_id=questionnaire_id, tenant_id=tenant_id)
    return QuestionnaireCoverageResponse(questionnaire_id=questionnaire_id, **cov)
