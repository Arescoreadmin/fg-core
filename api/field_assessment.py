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

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
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
    EvidenceLinkType,
    EngagementNotFound,
    EvidenceLinkDuplicate,
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

log = logging.getLogger("frostgate.api.field_assessment")

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
    transition_payload = {"new_status": body.new_status, "reason": body.reason}
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
    scan_audit_payload: dict[str, Any] = {
        "scan_result_id": result.id,
        "source_type": body.source_type.value,
        "object_count": body.object_count,
        "evidence_hash": result.evidence_hash,
        "redacted_field_count": redaction.redacted_count,
        "redacted_paths": redaction.redacted_paths,
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
    playbook = get_playbook(eng.assessment_type)
    execution_state = build_execution_state(
        engagement=eng,
        playbook=playbook,
        scan_results=scans,
        document_analyses=documents,
        observations=observations,
        findings=findings,
        evidence_links=evidence_links,
        generated_at=utc_iso8601_z_now(),
    )
    return ExecutionStateResponse(**execution_state.to_dict())


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
