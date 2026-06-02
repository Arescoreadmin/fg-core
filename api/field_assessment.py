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
import os
import secrets
import threading
import uuid as _uuid_module
from typing import Any, Literal

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from sqlalchemy import delete, func, select
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
from services.field_assessment.connectors.oauth_inventory_bridge import (
    import_oauth_inventory_scan,
)
from services.field_assessment.connectors.endpoint_inventory_bridge import (
    import_endpoint_inventory_scan,
)
from services.field_assessment.connectors.network_scan_bridge import (
    import_network_scan,
)
from services.field_assessment.connectors.dns_email_bridge import (
    import_dns_email_scan,
)
from services.field_assessment.connectors.web_headers_bridge import (
    import_web_headers_scan,
)
from services.field_assessment.connectors.entra_governance_bridge import (
    import_entra_governance_scan,
)
from services.field_assessment.connectors.sharepoint_bridge import (
    import_sharepoint_scan,
)
from services.field_assessment.connectors.oauth_risk_bridge import (
    import_oauth_risk_scan,
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
    update_finding_status,
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
from services.connectors.msgraph.acknowledgment import (
    generate_receipt as _generate_msgraph_receipt,
)
from services.connectors.msgraph.manifest import (
    AUTHORIZED_SCOPES as _MSGRAPH_AUTHORIZED_SCOPES,
    AcknowledgmentVerificationError as _MsgraphAcknowledgmentError,
)
from services.connectors.msgraph.runner import run_scan as _run_msgraph_scan
from services.connectors.msgraph.schema.scan_result import (
    AcknowledgmentReceipt as _MsgraphReceipt,
)

log = logging.getLogger("frostgate.api.field_assessment")

_MSGRAPH_RUNS: dict[str, dict[str, Any]] = {}
_MSGRAPH_RUNS_LOCK = threading.Lock()

# Statuses whose transition requires all blocking readiness gates to be satisfied.
_GATED_STATUSES: frozenset[str] = frozenset({"delivered"})

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

    @model_validator(mode="after")
    def _validate_audio_evidence(self) -> "CaptureObservationRequest":
        ev = self.structured_evidence
        url = ev.get("_audio_url")
        if url is not None:
            if not isinstance(url, str) or not url.startswith(("https://", "http://")):
                raise ValueError("_audio_url must be an http(s) URL string")
        for key in ("_audio_duration_sec", "_audio_size_kb"):
            val = ev.get(key)
            if val is not None and not isinstance(val, (int, float)):
                raise ValueError(f"{key} must be a number")
        audio_hash = ev.get("_audio_hash")
        if audio_hash is not None and not isinstance(audio_hash, str):
            raise ValueError("_audio_hash must be a string")
        return self


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
    client_access_code: str | None = None
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
    updated_at: str | None = None
    deleted_at: str | None = None


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
    evidence_age_days: int = 0
    framework_mappings: list[Any]
    nist_ai_rmf_mappings: list[Any]
    evidence_ref_ids: list[Any]
    remediation_hint: str | None
    remediation_priority: int = 0
    effort_level: str = "medium"
    schema_version: str
    created_at: str
    updated_at: str


class FindingListResponse(BaseModel):
    items: list[FindingResponse]
    total_count: int


class RemediationPhaseFinding(BaseModel):
    finding_id: str
    title: str
    severity: str
    status: str
    finding_type: str
    remediation_hint: str | None
    remediation_priority: int
    effort_level: str
    nist_ai_rmf_mappings: list[Any]
    framework_mappings: list[Any]
    nist_controls_addressed: int


class RemediationPhase(BaseModel):
    phase_id: str
    label: str
    window: str
    findings: list[RemediationPhaseFinding]
    compliance_delta_pct: float
    nist_controls_addressed: int


class RemediationRoadmapResponse(BaseModel):
    engagement_id: str
    current_coverage_pct: float
    projected_coverage_pct: float
    phases: list[RemediationPhase]
    total_open_findings: int
    is_truncated: bool = False
    schema_version: str = "1.0"


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


class FindingStatusPatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["remediated", "accepted", "false_positive"]
    notes: str = Field(..., min_length=1, max_length=2000)
    owner_email: str = Field(..., min_length=1)


class FindingRemediationPatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    remediation_hint: str = Field(..., min_length=1, max_length=2000)


class FindingStatusPatchResponse(BaseModel):
    finding: FindingResponse
    observation_id: str
    questionnaire_controls_updated: int


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
    remediation_steps: list[str] = []
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
    # Normalize legacy status values from before the 6-status simplification.
    raw_status = eng.status
    _LEGACY_STATUS_MAP = {
        "scheduled": "in_progress",
        "pre_visit": "in_progress",
        "evidence_collected": "in_progress",
        "report_generation": "in_progress",
    }
    status = _LEGACY_STATUS_MAP.get(raw_status, raw_status)
    return EngagementResponse(
        id=eng.id,
        tenant_id=eng.tenant_id,
        client_name=eng.client_name,
        client_domain=eng.client_domain,
        assessor_id=eng.assessor_id,
        assessment_type=eng.assessment_type,
        status=status,
        scheduled_date=eng.scheduled_date,
        client_access_code=eng.client_access_code,
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
        updated_at=getattr(o, "updated_at", None),
        deleted_at=getattr(o, "deleted_at", None),
    )


def _finding_to_response(f: FaNormalizedFinding) -> FindingResponse:
    from services.field_assessment.remediation import (
        compute_priority_score,
        compute_effort_level,
    )
    from services.field_assessment.confidence import (
        degrade_confidence,
        evidence_age_days,
    )

    age = evidence_age_days(f.updated_at)
    effective_confidence = degrade_confidence(f.confidence_score, f.updated_at)

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
        confidence_score=effective_confidence,
        evidence_age_days=age,
        framework_mappings=f.framework_mappings or [],
        nist_ai_rmf_mappings=f.nist_ai_rmf_mappings or [],
        evidence_ref_ids=f.evidence_ref_ids or [],
        remediation_hint=f.remediation_hint,
        remediation_priority=compute_priority_score(f),
        effort_level=compute_effort_level(f),
        schema_version=f.schema_version,
        created_at=f.created_at,
        updated_at=f.updated_at,
    )


_SCAN_SOURCE_LABELS: dict[str, str] = {
    "microsoft_graph": "MS Graph Core Scan",
    "oauth_inventory": "OAuth Inventory Scan",
    "oauth_risk": "OAuth Risk Scan",
    "entra_governance": "Entra Governance Scan",
    "endpoint_inventory": "Endpoint Inventory Scan",
    "sharepoint_onedrive": "SharePoint & OneDrive Scan",
    "dns_email": "DNS & Email Security Scan",
    "network_scan": "Network Scan",
    "web_headers": "Web Security Headers Scan",
    "google_workspace": "Google Workspace Scan",
    "aws": "AWS Scan",
    "azure": "Azure Scan",
    "gcp": "GCP Scan",
}


def _auto_link_scan_evidence(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    scan_result_id: str,
    source_type: str,
) -> None:
    """Create an engagement-level evidence link for a scan result if one doesn't already exist.

    Uses SELECT-first to avoid rolling back the parent transaction on duplicate.
    """
    existing = db.execute(
        select(FaEvidenceLink).where(
            FaEvidenceLink.tenant_id == tenant_id,
            FaEvidenceLink.engagement_id == engagement_id,
            FaEvidenceLink.evidence_entity_id == scan_result_id,
            FaEvidenceLink.source_entity_type == "engagement",
        )
    ).scalar_one_or_none()
    if existing is not None:
        return
    label = _SCAN_SOURCE_LABELS.get(
        source_type, source_type.replace("_", " ").title() + " Scan"
    )
    try:
        create_evidence_link(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            source_entity_type="engagement",
            source_entity_id=engagement_id,
            evidence_entity_type=EvidenceLinkType.SCAN_RESULT.value,
            evidence_entity_id=scan_result_id,
            link_metadata={
                "label": label,
                "source_type": source_type,
                "auto_linked": True,
            },
        )
    except EvidenceLinkDuplicate:
        pass


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
    client_access_code: str | None = Query(None),
    db: Session = Depends(auth_ctx_db_session),
) -> EngagementListResponse:
    tenant_id = _resolve_caller_tenant(request)
    rows = list_engagements(
        db,
        tenant_id=tenant_id,
        status_filter=status_filter,
        limit=limit,
        cursor=cursor,
        access_code_filter=client_access_code,
    )
    next_cursor = rows[-1].created_at if len(rows) == limit else None
    count_stmt = select(func.count(FaEngagement.id)).where(FaEngagement.tenant_id == tenant_id)
    if client_access_code:
        count_stmt = count_stmt.where(FaEngagement.client_access_code == client_access_code)
    total = db.execute(count_stmt).scalar_one()
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


class PatchEngagementRequest(BaseModel):
    engagement_metadata: dict[str, Any] | None = None


@router.patch(
    "/engagements/{engagement_id}",
    response_model=EngagementResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def patch_engagement_route(
    engagement_id: str,
    request: Request,
    body: PatchEngagementRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> EngagementResponse:
    """Shallow-merge engagement_metadata fields. Other top-level fields are immutable here."""
    tenant_id = _resolve_caller_tenant(request)
    try:
        eng = get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    if body.engagement_metadata is not None:
        eng.engagement_metadata = {**(eng.engagement_metadata or {}), **body.engagement_metadata}
        eng.updated_at = utc_iso8601_z_now()
    db.commit()
    db.refresh(eng)
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
    _auto_link_scan_evidence(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        scan_result_id=result.id,
        source_type=body.source_type.value,
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
    if body.interview_role:
        _playbook = get_playbook(eng.assessment_type)
        if body.interview_role not in _playbook.required_interview_roles:
            raise HTTPException(
                status_code=422,
                detail=api_error(
                    "INVALID_INTERVIEW_ROLE",
                    f"'{body.interview_role}' is not a valid role for this playbook. "
                    f"Valid roles: {list(_playbook.required_interview_roles)}",
                ),
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


class BulkObservationImportResult(BaseModel):
    created: int
    skipped: int
    errors: list[str]
    observation_ids: list[str]


@router.post(
    "/engagements/{engagement_id}/observations/bulk",
    response_model=BulkObservationImportResult,
    status_code=200,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def bulk_import_observations_route(
    engagement_id: str,
    request: Request,
    body: list[CaptureObservationRequest],
    db: Session = Depends(auth_ctx_db_session),
) -> BulkObservationImportResult:
    """Import multiple observations in a single call. Processes each row independently —
    invalid rows are collected in errors and skipped; valid rows are committed atomically."""
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)
    try:
        eng = get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    if not body:
        raise HTTPException(status_code=400, detail=api_error("EMPTY_IMPORT", "No observations provided"))
    if len(body) > 200:
        raise HTTPException(status_code=400, detail=api_error("IMPORT_TOO_LARGE", "Maximum 200 observations per import"))

    _playbook = get_playbook(eng.assessment_type)
    created_ids: list[str] = []
    errors: list[str] = []
    skipped = 0

    for idx, row in enumerate(body):
        try:
            if row.interview_role and row.interview_role not in _playbook.required_interview_roles:
                errors.append(f"Row {idx}: invalid interview_role '{row.interview_role}'")
                skipped += 1
                continue
            obs = create_observation(
                db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                domain=row.domain.value,
                observation_type=row.observation_type.value,
                severity=row.severity.value,
                title=row.title,
                description=row.description,
                interview_role=row.interview_role,
                structured_evidence=row.structured_evidence,
                linked_finding_ids=row.linked_finding_ids,
                assessor_id=eng.assessor_id,
            )
            created_ids.append(obs.id)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"Row {idx}: {exc}")
            skipped += 1

    if created_ids:
        emit_engagement_audit_event(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            event_type="observation.bulk_imported",
            actor=actor,
            reason_code="BULK_OBSERVATION_IMPORT",
            payload={"count": len(created_ids), "skipped": skipped},
        )
        db.commit()

    return BulkObservationImportResult(
        created=len(created_ids),
        skipped=skipped,
        errors=errors,
        observation_ids=created_ids,
    )


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


@router.get(
    "/interview-templates",
    response_model=list[ObservationResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_interview_templates_route(
    request: Request,
    interview_role: str | None = Query(None),
    assessment_type: str | None = Query(None),
    limit: int = Query(20, ge=1, le=50),
    db: Session = Depends(auth_ctx_db_session),
) -> list[ObservationResponse]:
    """Return recent interview observations across the tenant's engagements.
    Useful for seeding new interviews from prior assessment notes."""
    tenant_id = _resolve_caller_tenant(request)
    stmt = (
        select(FaFieldObservation)
        .where(
            FaFieldObservation.tenant_id == tenant_id,
            FaFieldObservation.observation_type == "interview",
            FaFieldObservation.deleted_at.is_(None),
        )
        .order_by(FaFieldObservation.created_at.desc())
        .limit(limit)
    )
    if interview_role:
        stmt = stmt.where(FaFieldObservation.interview_role == interview_role)
    if assessment_type:
        # Join via engagement to filter by assessment_type
        stmt = stmt.join(
            FaEngagement,
            (FaEngagement.id == FaFieldObservation.engagement_id)
            & (FaEngagement.tenant_id == FaFieldObservation.tenant_id),
        ).where(FaEngagement.assessment_type == assessment_type)
    rows = list(db.execute(stmt).scalars().all())
    return [_observation_to_response(r) for r in rows]


class UpdateObservationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = None
    description: str | None = None
    severity: ObservationSeverity | None = None
    structured_evidence: dict[str, Any] | None = None
    linked_finding_ids: list[Any] | None = None


@router.patch(
    "/engagements/{engagement_id}/observations/{observation_id}",
    response_model=ObservationResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def update_observation_route(
    engagement_id: str,
    observation_id: str,
    request: Request,
    body: UpdateObservationRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> ObservationResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)
    obs = db.execute(
        select(FaFieldObservation).where(
            FaFieldObservation.id == observation_id,
            FaFieldObservation.engagement_id == engagement_id,
            FaFieldObservation.tenant_id == tenant_id,
            FaFieldObservation.deleted_at.is_(None),
        )
    ).scalar_one_or_none()
    if obs is None:
        raise HTTPException(status_code=404, detail=api_error("OBSERVATION_NOT_FOUND", "Observation not found"))
    now = utc_iso8601_z_now()
    if body.title is not None:
        obs.title = body.title
    if body.description is not None:
        obs.description = body.description
    if body.severity is not None:
        obs.severity = body.severity.value
    if body.structured_evidence is not None:
        obs.structured_evidence = body.structured_evidence
    if body.linked_finding_ids is not None:
        obs.linked_finding_ids = body.linked_finding_ids
    obs.updated_at = now
    emit_engagement_audit_event(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        event_type="observation.updated",
        actor=actor,
        reason_code="OBSERVATION_UPDATED",
        payload={"observation_id": observation_id},
    )
    db.commit()
    db.refresh(obs)
    return _observation_to_response(obs)


@router.delete(
    "/engagements/{engagement_id}/observations/{observation_id}",
    status_code=204,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def delete_observation_route(
    engagement_id: str,
    observation_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> None:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)
    obs = db.execute(
        select(FaFieldObservation).where(
            FaFieldObservation.id == observation_id,
            FaFieldObservation.engagement_id == engagement_id,
            FaFieldObservation.tenant_id == tenant_id,
            FaFieldObservation.deleted_at.is_(None),
        )
    ).scalar_one_or_none()
    if obs is None:
        raise HTTPException(status_code=404, detail=api_error("OBSERVATION_NOT_FOUND", "Observation not found"))
    now = utc_iso8601_z_now()
    obs.deleted_at = now
    # Cascade-remove evidence links that source this observation (#17)
    db.execute(
        delete(FaEvidenceLink).where(
            FaEvidenceLink.tenant_id == tenant_id,
            FaEvidenceLink.source_entity_type == "field_observation",
            FaEvidenceLink.source_entity_id == observation_id,
        )
    )
    emit_engagement_audit_event(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        event_type="observation.deleted",
        actor=actor,
        reason_code="OBSERVATION_SOFT_DELETED",
        payload={"observation_id": observation_id},
    )
    db.commit()


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
# Route — Finding status update (closed-loop remediation)
# ---------------------------------------------------------------------------

_TERMINAL_FINDING_STATUSES: frozenset[str] = frozenset(
    {"remediated", "accepted", "false_positive"}
)


@router.patch(
    "/engagements/{engagement_id}/findings/{finding_id}",
    response_model=FindingStatusPatchResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def patch_finding_status_route(
    engagement_id: str,
    finding_id: str,
    request: Request,
    body: FindingStatusPatchRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> FindingStatusPatchResponse:
    """Mark a finding resolved, accepted, or false-positive.

    Side effects (all in one transaction):
    1. Creates a FaFieldObservation recording the client's evidence notes.
    2. Creates a FaEvidenceLink from the finding to that observation.
    3. Bumps matching NIST AI RMF questionnaire responses from
       not_implemented / not_assessed → partial (one step closer to implemented).
    4. Updates finding.status to the requested terminal value.
    5. Emits an audit event.
    """
    from services.field_assessment.questionnaire_store import (  # noqa: F811
        list_questionnaires,
        list_responses,
        normalize_nist_control,
    )

    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)

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

    if finding.status in _TERMINAL_FINDING_STATUSES:
        raise HTTPException(
            status_code=409,
            detail=api_error(
                "FINDING_ALREADY_RESOLVED",
                f"finding is already in terminal status '{finding.status}'",
            ),
        )

    # 1 — Create evidence observation.
    observation = create_observation(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        domain=ObservationDomain.COMPLIANCE.value,
        observation_type=ObservationType.NOTE.value,
        severity=finding.severity,
        title=f"Client remediation: {finding.title}",
        description=body.notes,
        interview_role=None,
        structured_evidence={
            "finding_id": finding_id,
            "new_status": body.status,
            "owner_email": body.owner_email,
        },
        linked_finding_ids=[finding_id],
        assessor_id=body.owner_email,
    )

    # 2 — Link observation to finding.
    try:
        create_evidence_link(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            source_entity_type="finding",
            source_entity_id=finding_id,
            evidence_entity_type=EvidenceLinkType.FIELD_OBSERVATION.value,
            evidence_entity_id=observation.id,
            link_metadata={
                "linked_by": "portal_closed_loop",
                "new_status": body.status,
            },
        )
    except Exception:
        pass  # duplicate link is acceptable — idempotent

    # 3 — Bump questionnaire responses for matched NIST controls.
    # Only remediated findings represent actual implementation evidence.
    # accepted / false_positive do not advance control coverage.
    controls_updated = 0
    if body.status == "remediated":
        nist_controls: set[str] = set()
        for raw in finding.nist_ai_rmf_mappings or []:
            cid = normalize_nist_control(raw)
            if cid:
                nist_controls.add(cid)

        if nist_controls:
            qs = list_questionnaires(
                db, engagement_id=engagement_id, tenant_id=tenant_id
            )
            for q in qs:
                responses = list_responses(
                    db, questionnaire_id=q.id, tenant_id=tenant_id
                )
                for r in responses:
                    if r.control_id in nist_controls and r.response_status in (
                        "not_implemented",
                        "not_assessed",
                    ):
                        r.response_status = "partial"
                        r.updated_at = utc_iso8601_z_now()
                        controls_updated += 1
                if controls_updated:
                    q.updated_at = utc_iso8601_z_now()
            db.flush()

    # 4 — Update finding status.
    updated_finding = update_finding_status(
        db,
        finding_id=finding_id,
        engagement_id=engagement_id,
        tenant_id=tenant_id,
        new_status=body.status,
    )

    # 5 — Audit.
    emit_engagement_audit_event(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        event_type="finding_status_updated",
        actor=actor,
        reason_code="client_remediation",
        payload={
            "finding_id": finding_id,
            "new_status": body.status,
            "observation_id": observation.id,
            "questionnaire_controls_updated": controls_updated,
        },
    )

    db.commit()
    db.refresh(updated_finding)

    return FindingStatusPatchResponse(
        finding=_finding_to_response(updated_finding),
        observation_id=observation.id,
        questionnaire_controls_updated=controls_updated,
    )


@router.patch(
    "/engagements/{engagement_id}/findings/{finding_id}/remediation",
    dependencies=[Depends(require_scopes("governance:write"))],
)
def patch_finding_remediation_route(
    engagement_id: str,
    finding_id: str,
    request: Request,
    body: FindingRemediationPatchRequest,
    db: Session = Depends(auth_ctx_db_session),
) -> dict:
    """Set remediation_hint on a finding to satisfy the readiness gate."""
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

    finding.remediation_hint = body.remediation_hint
    finding.updated_at = utc_iso8601_z_now()
    db.commit()
    db.refresh(finding)
    return {"finding_id": finding_id, "remediation_hint": finding.remediation_hint}


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
    from api.db_models_questionnaire import FaQuestionnaireResponse  # noqa: F811

    questionnaire_responses = list(
        db.execute(
            select(FaQuestionnaireResponse).where(
                FaQuestionnaireResponse.engagement_id == engagement_id,
                FaQuestionnaireResponse.tenant_id == tenant_id,
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
        questionnaire_responses=questionnaire_responses,
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
# Route — MS Graph live scan trigger (device-code flow)
# ---------------------------------------------------------------------------


class MsgraphScanInitiateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    azure_tenant_id: str
    operator_name: str = "operator"
    operator_org: str = "FrostGate"
    client_org_name: str = ""


class MsgraphScanInitiateResponse(BaseModel):
    run_id: str
    user_code: str
    verification_uri: str
    expires_in: int
    message: str


class MsgraphRunStatusResponse(BaseModel):
    run_id: str
    status: Literal[
        "pending_auth", "authenticating", "scanning", "importing", "complete", "failed"
    ]
    user_code: str | None = None
    verification_uri: str | None = None
    error: str | None = None
    scan_result_id: str | None = None


def _msgraph_scan_background(
    *,
    run_id: str,
    tenant_id: str,
    engagement_id: str,
    receipt: _MsgraphReceipt,
    msal_app: Any,
    flow: dict[str, Any],
    actor: str,
) -> None:
    def _set(**kw: Any) -> None:
        with _MSGRAPH_RUNS_LOCK:
            _MSGRAPH_RUNS[run_id].update(kw)

    try:
        _set(status="authenticating")
        token_result = msal_app.acquire_token_by_device_flow(flow)
        if "access_token" not in token_result:
            _set(
                status="failed",
                error=token_result.get("error_description", "Token acquisition failed"),
            )
            return

        _set(status="scanning")
        scan_result = _run_msgraph_scan(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            receipt=receipt,
            _test_token=token_result["access_token"],
        )

        _set(status="importing")
        from api.db import get_sessionmaker

        SessionLocal = get_sessionmaker()
        db = SessionLocal()
        try:
            envelope = ConnectorImportEnvelope.model_validate(
                {
                    "connector_type": "microsoft_graph",
                    "connector_run_id": scan_result.scan_id,
                    "import_review_status": "imported",
                    "scan_result": scan_result.model_dump(mode="json"),
                }
            )
            import_result = import_msgraph_scan_result(
                db=db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                envelope=envelope,
                actor=actor,
            )
            _auto_link_scan_evidence(
                db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                scan_result_id=import_result.scan_result_id,
                source_type="microsoft_graph",
            )
            db.commit()
            _set(status="complete", scan_result_id=import_result.scan_result_id)
        except Exception as exc:
            log.error("msgraph_background: import failed — %s", exc)
            db.rollback()
            _set(status="failed", error=f"Import failed: {str(exc)[:200]}")
        finally:
            db.close()
    except Exception as exc:
        log.error("msgraph_background: scan failed — %s", exc)
        _set(status="failed", error=str(exc)[:200])


@router.post(
    "/engagements/{engagement_id}/connector-runs/msgraph/initiate",
    response_model=MsgraphScanInitiateResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def initiate_msgraph_scan(
    engagement_id: str,
    request: Request,
    body: MsgraphScanInitiateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(auth_ctx_db_session),
) -> MsgraphScanInitiateResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)
    try:
        eng = get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    client_id = os.environ.get("FG_MSAL_CLIENT_ID", "")
    if not client_id:
        raise HTTPException(
            status_code=503,
            detail=api_error("MSAL_NOT_CONFIGURED", "FG_MSAL_CLIENT_ID is not set"),
        )

    try:
        receipt = _generate_msgraph_receipt(
            operator_name=body.operator_name,
            operator_org=body.operator_org,
            client_org_name=body.client_org_name or eng.client_name,
            scan_authorized_at=utc_iso8601_z_now(),
            engagement_id=engagement_id,
        )
    except _MsgraphAcknowledgmentError as exc:
        raise HTTPException(
            status_code=503,
            detail=api_error("ACKNOWLEDGMENT_KEY_MISSING", str(exc)),
        )

    try:
        import msal  # type: ignore[import-untyped]
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail=api_error("MSAL_NOT_INSTALLED", "msal package is not installed"),
        )

    authority = f"https://login.microsoftonline.com/{body.azure_tenant_id}"
    msal_app = msal.PublicClientApplication(client_id, authority=authority)
    flow = msal_app.initiate_device_flow(scopes=list(_MSGRAPH_AUTHORIZED_SCOPES))
    if "user_code" not in flow:
        raise HTTPException(
            status_code=502,
            detail=api_error(
                "DEVICE_FLOW_FAILED",
                flow.get("error_description", "Device flow initiation failed"),
            ),
        )

    run_id = str(_uuid_module.uuid4())
    with _MSGRAPH_RUNS_LOCK:
        _MSGRAPH_RUNS[run_id] = {
            "status": "pending_auth",
            "user_code": flow["user_code"],
            "verification_uri": flow["verification_uri"],
            "error": None,
            "scan_result_id": None,
        }

    background_tasks.add_task(
        _msgraph_scan_background,
        run_id=run_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        receipt=receipt,
        msal_app=msal_app,
        flow=flow,
        actor=actor,
    )

    return MsgraphScanInitiateResponse(
        run_id=run_id,
        user_code=flow["user_code"],
        verification_uri=flow["verification_uri"],
        expires_in=flow.get("expires_in", 900),
        message=flow.get("message", ""),
    )


# ---------------------------------------------------------------------------
# Route — OAuth Inventory scan (MSAL device-code, MS Graph)
# ---------------------------------------------------------------------------


def _oauth_inventory_scan_background(
    *,
    run_id: str,
    tenant_id: str,
    engagement_id: str,
    msal_app: Any,
    flow: dict[str, Any],
    actor: str,
) -> None:
    def _set(**kw: Any) -> None:
        with _MSGRAPH_RUNS_LOCK:
            _MSGRAPH_RUNS[run_id].update(kw)

    try:
        _set(status="authenticating")
        token_result = msal_app.acquire_token_by_device_flow(flow)
        if "access_token" not in token_result:
            _set(
                status="failed",
                error=token_result.get("error_description", "Token acquisition failed"),
            )
            return

        _set(status="scanning")
        from services.connectors.oauth_inventory.runner import run_oauth_inventory

        scan_result = run_oauth_inventory(
            access_token=token_result["access_token"],
            tenant_id=tenant_id,
            engagement_id=engagement_id,
        )

        _set(status="importing")
        from api.db import get_sessionmaker

        SessionLocal = get_sessionmaker()
        db = SessionLocal()
        try:
            result = import_oauth_inventory_scan(
                db=db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                scan_result=scan_result,
                actor=actor,
            )
            _auto_link_scan_evidence(
                db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                scan_result_id=result.scan_result_id,
                source_type="oauth_inventory",
            )
            db.commit()
            _set(status="complete", scan_result_id=result.scan_result_id)
        except Exception as exc:
            log.error("oauth_inventory_background: import failed — %s", exc)
            db.rollback()
            _set(status="failed", error=f"Import failed: {str(exc)[:200]}")
        finally:
            db.close()
    except Exception as exc:
        log.error("oauth_inventory_background: scan failed — %s", exc)
        _set(status="failed", error=str(exc)[:200])


@router.post(
    "/engagements/{engagement_id}/connector-runs/oauth-inventory/initiate",
    response_model=MsgraphScanInitiateResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def initiate_oauth_inventory_scan(
    engagement_id: str,
    request: Request,
    body: MsgraphScanInitiateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(auth_ctx_db_session),
) -> MsgraphScanInitiateResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    client_id = os.environ.get("FG_MSAL_CLIENT_ID", "")
    if not client_id:
        raise HTTPException(
            status_code=503,
            detail=api_error("MSAL_NOT_CONFIGURED", "FG_MSAL_CLIENT_ID is not set"),
        )
    try:
        import msal  # type: ignore[import-untyped]
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail=api_error("MSAL_NOT_INSTALLED", "msal package is not installed"),
        )

    authority = f"https://login.microsoftonline.com/{body.azure_tenant_id}"
    msal_app = msal.PublicClientApplication(client_id, authority=authority)
    flow = msal_app.initiate_device_flow(scopes=list(_MSGRAPH_AUTHORIZED_SCOPES))
    if "user_code" not in flow:
        raise HTTPException(
            status_code=502,
            detail=api_error(
                "DEVICE_FLOW_FAILED",
                flow.get("error_description", "Device flow initiation failed"),
            ),
        )

    run_id = str(_uuid_module.uuid4())
    with _MSGRAPH_RUNS_LOCK:
        _MSGRAPH_RUNS[run_id] = {
            "status": "pending_auth",
            "user_code": flow["user_code"],
            "verification_uri": flow["verification_uri"],
            "error": None,
            "scan_result_id": None,
        }

    background_tasks.add_task(
        _oauth_inventory_scan_background,
        run_id=run_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        msal_app=msal_app,
        flow=flow,
        actor=actor,
    )

    return MsgraphScanInitiateResponse(
        run_id=run_id,
        user_code=flow["user_code"],
        verification_uri=flow["verification_uri"],
        expires_in=flow.get("expires_in", 900),
        message=flow.get("message", ""),
    )


# ---------------------------------------------------------------------------
# Route — Endpoint Inventory scan (MSAL device-code, MS Graph)
# ---------------------------------------------------------------------------


def _endpoint_inventory_scan_background(
    *,
    run_id: str,
    tenant_id: str,
    engagement_id: str,
    msal_app: Any,
    flow: dict[str, Any],
    actor: str,
) -> None:
    def _set(**kw: Any) -> None:
        with _MSGRAPH_RUNS_LOCK:
            _MSGRAPH_RUNS[run_id].update(kw)

    try:
        _set(status="authenticating")
        token_result = msal_app.acquire_token_by_device_flow(flow)
        if "access_token" not in token_result:
            _set(
                status="failed",
                error=token_result.get("error_description", "Token acquisition failed"),
            )
            return

        _set(status="scanning")
        from services.connectors.endpoint_inventory.runner import run_endpoint_inventory

        scan_result = run_endpoint_inventory(
            access_token=token_result["access_token"],
            tenant_id=tenant_id,
            engagement_id=engagement_id,
        )

        _set(status="importing")
        from api.db import get_sessionmaker

        SessionLocal = get_sessionmaker()
        db = SessionLocal()
        try:
            result = import_endpoint_inventory_scan(
                db=db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                scan_result=scan_result,
                actor=actor,
            )
            _auto_link_scan_evidence(
                db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                scan_result_id=result.scan_result_id,
                source_type="endpoint_inventory",
            )
            db.commit()
            _set(status="complete", scan_result_id=result.scan_result_id)
        except Exception as exc:
            log.error("endpoint_inventory_background: import failed — %s", exc)
            db.rollback()
            _set(status="failed", error=f"Import failed: {str(exc)[:200]}")
        finally:
            db.close()
    except Exception as exc:
        log.error("endpoint_inventory_background: scan failed — %s", exc)
        _set(status="failed", error=str(exc)[:200])


@router.post(
    "/engagements/{engagement_id}/connector-runs/endpoint-inventory/initiate",
    response_model=MsgraphScanInitiateResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def initiate_endpoint_inventory_scan(
    engagement_id: str,
    request: Request,
    body: MsgraphScanInitiateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(auth_ctx_db_session),
) -> MsgraphScanInitiateResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    client_id = os.environ.get("FG_MSAL_CLIENT_ID", "")
    if not client_id:
        raise HTTPException(
            status_code=503,
            detail=api_error("MSAL_NOT_CONFIGURED", "FG_MSAL_CLIENT_ID is not set"),
        )
    try:
        import msal  # type: ignore[import-untyped]
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail=api_error("MSAL_NOT_INSTALLED", "msal package is not installed"),
        )

    authority = f"https://login.microsoftonline.com/{body.azure_tenant_id}"
    msal_app = msal.PublicClientApplication(client_id, authority=authority)
    flow = msal_app.initiate_device_flow(scopes=list(_MSGRAPH_AUTHORIZED_SCOPES))
    if "user_code" not in flow:
        raise HTTPException(
            status_code=502,
            detail=api_error(
                "DEVICE_FLOW_FAILED",
                flow.get("error_description", "Device flow initiation failed"),
            ),
        )

    run_id = str(_uuid_module.uuid4())
    with _MSGRAPH_RUNS_LOCK:
        _MSGRAPH_RUNS[run_id] = {
            "status": "pending_auth",
            "user_code": flow["user_code"],
            "verification_uri": flow["verification_uri"],
            "error": None,
            "scan_result_id": None,
        }

    background_tasks.add_task(
        _endpoint_inventory_scan_background,
        run_id=run_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        msal_app=msal_app,
        flow=flow,
        actor=actor,
    )

    return MsgraphScanInitiateResponse(
        run_id=run_id,
        user_code=flow["user_code"],
        verification_uri=flow["verification_uri"],
        expires_in=flow.get("expires_in", 900),
        message=flow.get("message", ""),
    )


# ---------------------------------------------------------------------------
# Route — Network Scan (pure Python, no auth required)
# ---------------------------------------------------------------------------


class NetworkScanInitiateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_hosts: list[str] = Field(..., min_length=1, max_length=50)
    operator_name: str | None = None
    operator_org: str | None = None


class NetworkScanInitiateResponse(BaseModel):
    run_id: str
    status: str
    target_count: int


def _network_scan_background(
    *,
    run_id: str,
    tenant_id: str,
    engagement_id: str,
    target_hosts: list[str],
    actor: str,
) -> None:
    def _set(**kw: Any) -> None:
        with _MSGRAPH_RUNS_LOCK:
            _MSGRAPH_RUNS[run_id].update(kw)

    try:
        _set(status="scanning")
        from services.connectors.network_scan.runner import run_network_scan

        scan_result = run_network_scan(
            target_hosts=target_hosts,
            engagement_id=engagement_id,
        )

        _set(status="importing")
        from api.db import get_sessionmaker

        SessionLocal = get_sessionmaker()
        db = SessionLocal()
        try:
            result = import_network_scan(
                db=db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                scan_result=scan_result,
                actor=actor,
            )
            _auto_link_scan_evidence(
                db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                scan_result_id=result.scan_result_id,
                source_type="network_scan",
            )
            db.commit()
            _set(status="complete", scan_result_id=result.scan_result_id)
        except Exception as exc:
            log.error("network_scan_background: import failed — %s", exc)
            db.rollback()
            _set(status="failed", error=f"Import failed: {str(exc)[:200]}")
        finally:
            db.close()
    except Exception as exc:
        log.error("network_scan_background: scan failed — %s", exc)
        _set(status="failed", error=str(exc)[:200])


@router.post(
    "/engagements/{engagement_id}/connector-runs/network-scan/initiate",
    response_model=NetworkScanInitiateResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def initiate_network_scan(
    engagement_id: str,
    request: Request,
    body: NetworkScanInitiateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(auth_ctx_db_session),
) -> NetworkScanInitiateResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    run_id = str(_uuid_module.uuid4())
    with _MSGRAPH_RUNS_LOCK:
        _MSGRAPH_RUNS[run_id] = {
            "status": "scanning",
            "user_code": None,
            "verification_uri": None,
            "error": None,
            "scan_result_id": None,
        }

    background_tasks.add_task(
        _network_scan_background,
        run_id=run_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        target_hosts=body.target_hosts,
        actor=actor,
    )

    return NetworkScanInitiateResponse(
        run_id=run_id,
        status="scanning",
        target_count=len(body.target_hosts),
    )


# ---------------------------------------------------------------------------
# DNS & Email Security connector
# ---------------------------------------------------------------------------


class DnsEmailScanInitiateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domains: list[str] = Field(..., min_length=1, max_length=50)
    dkim_selectors: list[str] | None = None
    operator_name: str | None = None
    operator_org: str | None = None


class DnsEmailScanInitiateResponse(BaseModel):
    run_id: str
    status: str
    domain_count: int


def _dns_email_scan_background(
    *,
    run_id: str,
    tenant_id: str,
    engagement_id: str,
    domains: list[str],
    dkim_selectors: list[str] | None,
    actor: str,
) -> None:
    def _set(**kw: Any) -> None:
        with _MSGRAPH_RUNS_LOCK:
            _MSGRAPH_RUNS[run_id].update(kw)

    try:
        _set(status="scanning")
        from services.connectors.dns_email.runner import run as run_dns_email

        scan_result = run_dns_email(domains=domains, dkim_selectors=dkim_selectors)

        _set(status="importing")
        from api.db import get_sessionmaker

        SessionLocal = get_sessionmaker()
        db = SessionLocal()
        try:
            result = import_dns_email_scan(
                db=db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                scan_result=scan_result,
                actor=actor,
            )
            _auto_link_scan_evidence(
                db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                scan_result_id=result.scan_result_id,
                source_type="dns_email",
            )
            db.commit()
            _set(status="complete", scan_result_id=result.scan_result_id)
        except Exception as exc:
            log.error("dns_email_scan_background: import failed — %s", exc)
            db.rollback()
            _set(status="failed", error=f"Import failed: {str(exc)[:200]}")
        finally:
            db.close()
    except Exception as exc:
        log.error("dns_email_scan_background: scan failed — %s", exc)
        _set(status="failed", error=str(exc)[:200])


@router.post(
    "/engagements/{engagement_id}/connector-runs/dns-email/initiate",
    response_model=DnsEmailScanInitiateResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def initiate_dns_email_scan(
    engagement_id: str,
    request: Request,
    body: DnsEmailScanInitiateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(auth_ctx_db_session),
) -> DnsEmailScanInitiateResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    run_id = str(_uuid_module.uuid4())
    with _MSGRAPH_RUNS_LOCK:
        _MSGRAPH_RUNS[run_id] = {
            "status": "scanning",
            "user_code": None,
            "verification_uri": None,
            "error": None,
            "scan_result_id": None,
        }

    background_tasks.add_task(
        _dns_email_scan_background,
        run_id=run_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        domains=body.domains,
        dkim_selectors=body.dkim_selectors,
        actor=actor,
    )

    return DnsEmailScanInitiateResponse(
        run_id=run_id,
        status="scanning",
        domain_count=len(body.domains),
    )


# ---------------------------------------------------------------------------
# Web Security Headers connector
# ---------------------------------------------------------------------------


class WebHeadersScanInitiateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    targets: list[str] = Field(..., min_length=1, max_length=50)
    operator_name: str | None = None
    operator_org: str | None = None


class WebHeadersScanInitiateResponse(BaseModel):
    run_id: str
    status: str
    target_count: int


def _web_headers_scan_background(
    *,
    run_id: str,
    tenant_id: str,
    engagement_id: str,
    targets: list[str],
    actor: str,
) -> None:
    def _set(**kw: Any) -> None:
        with _MSGRAPH_RUNS_LOCK:
            _MSGRAPH_RUNS[run_id].update(kw)

    try:
        _set(status="scanning")
        from services.connectors.web_headers.runner import run as run_web_headers

        scan_result = run_web_headers(targets=targets)

        _set(status="importing")
        from api.db import get_sessionmaker

        SessionLocal = get_sessionmaker()
        db = SessionLocal()
        try:
            result = import_web_headers_scan(
                db=db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                scan_result=scan_result,
                actor=actor,
            )
            _auto_link_scan_evidence(
                db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                scan_result_id=result.scan_result_id,
                source_type="web_headers",
            )
            db.commit()
            _set(status="complete", scan_result_id=result.scan_result_id)
        except Exception as exc:
            log.error("web_headers_scan_background: import failed — %s", exc)
            db.rollback()
            _set(status="failed", error=f"Import failed: {str(exc)[:200]}")
        finally:
            db.close()
    except Exception as exc:
        log.error("web_headers_scan_background: scan failed — %s", exc)
        _set(status="failed", error=str(exc)[:200])


@router.post(
    "/engagements/{engagement_id}/connector-runs/web-headers/initiate",
    response_model=WebHeadersScanInitiateResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def initiate_web_headers_scan(
    engagement_id: str,
    request: Request,
    body: WebHeadersScanInitiateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(auth_ctx_db_session),
) -> WebHeadersScanInitiateResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    run_id = str(_uuid_module.uuid4())
    with _MSGRAPH_RUNS_LOCK:
        _MSGRAPH_RUNS[run_id] = {
            "status": "scanning",
            "user_code": None,
            "verification_uri": None,
            "error": None,
            "scan_result_id": None,
        }

    background_tasks.add_task(
        _web_headers_scan_background,
        run_id=run_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        targets=body.targets,
        actor=actor,
    )

    return WebHeadersScanInitiateResponse(
        run_id=run_id,
        status="scanning",
        target_count=len(body.targets),
    )


# ---------------------------------------------------------------------------
# Entra ID Governance connector (MSAL device-code, MS Graph)
# ---------------------------------------------------------------------------

_ENTRA_GOVERNANCE_SCOPES: tuple[str, ...] = (
    "Directory.Read.All",
    "Policy.Read.All",
    "AccessReview.Read.All",
    "IdentityRiskyUser.Read.All",
    "IdentityRiskEvent.Read.All",
    "RoleEligibilitySchedule.Read.Directory",
    "RoleAssignmentSchedule.Read.Directory",
)


def _entra_governance_scan_background(
    *,
    run_id: str,
    tenant_id: str,
    engagement_id: str,
    msal_app: Any,
    flow: dict[str, Any],
    actor: str,
) -> None:
    def _set(**kw: Any) -> None:
        with _MSGRAPH_RUNS_LOCK:
            _MSGRAPH_RUNS[run_id].update(kw)

    try:
        _set(status="authenticating")
        token_result = msal_app.acquire_token_by_device_flow(flow)
        if "access_token" not in token_result:
            _set(
                status="failed",
                error=token_result.get("error_description", "Token acquisition failed"),
            )
            return

        _set(status="scanning")
        from services.connectors.entra_governance.runner import run_entra_governance

        scan_result = run_entra_governance(
            access_token=token_result["access_token"],
            tenant_id=tenant_id,
            engagement_id=engagement_id,
        )

        _set(status="importing")
        from api.db import get_sessionmaker

        SessionLocal = get_sessionmaker()
        db = SessionLocal()
        try:
            result = import_entra_governance_scan(
                db=db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                scan_result=scan_result,
                actor=actor,
            )
            _auto_link_scan_evidence(
                db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                scan_result_id=result.scan_result_id,
                source_type="entra_governance",
            )
            db.commit()
            _set(status="complete", scan_result_id=result.scan_result_id)
        except Exception as exc:
            log.error("entra_governance_background: import failed — %s", exc)
            db.rollback()
            _set(status="failed", error=f"Import failed: {str(exc)[:200]}")
        finally:
            db.close()
    except Exception as exc:
        log.error("entra_governance_background: scan failed — %s", exc)
        _set(status="failed", error=str(exc)[:200])


@router.post(
    "/engagements/{engagement_id}/connector-runs/entra-governance/initiate",
    response_model=MsgraphScanInitiateResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def initiate_entra_governance_scan(
    engagement_id: str,
    request: Request,
    body: MsgraphScanInitiateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(auth_ctx_db_session),
) -> MsgraphScanInitiateResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    client_id = os.environ.get("FG_MSAL_CLIENT_ID", "")
    if not client_id:
        raise HTTPException(
            status_code=503,
            detail=api_error("MSAL_NOT_CONFIGURED", "FG_MSAL_CLIENT_ID is not set"),
        )
    try:
        import msal  # type: ignore[import-untyped]
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail=api_error("MSAL_NOT_INSTALLED", "msal package is not installed"),
        )

    authority = f"https://login.microsoftonline.com/{body.azure_tenant_id}"
    msal_app = msal.PublicClientApplication(client_id, authority=authority)
    flow = msal_app.initiate_device_flow(scopes=list(_ENTRA_GOVERNANCE_SCOPES))
    if "user_code" not in flow:
        raise HTTPException(
            status_code=502,
            detail=api_error(
                "DEVICE_FLOW_FAILED",
                flow.get("error_description", "Device flow initiation failed"),
            ),
        )

    run_id = str(_uuid_module.uuid4())
    with _MSGRAPH_RUNS_LOCK:
        _MSGRAPH_RUNS[run_id] = {
            "status": "pending_auth",
            "user_code": flow["user_code"],
            "verification_uri": flow["verification_uri"],
            "error": None,
            "scan_result_id": None,
        }

    background_tasks.add_task(
        _entra_governance_scan_background,
        run_id=run_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        msal_app=msal_app,
        flow=flow,
        actor=actor,
    )

    return MsgraphScanInitiateResponse(
        run_id=run_id,
        user_code=flow["user_code"],
        verification_uri=flow["verification_uri"],
        expires_in=flow.get("expires_in", 900),
        message=flow.get("message", ""),
    )


# ---------------------------------------------------------------------------
# SharePoint & OneDrive Data Exposure connector (MSAL device-code, MS Graph)
# ---------------------------------------------------------------------------

_SHAREPOINT_SCOPES: tuple[str, ...] = (
    "Sites.Read.All",
    "Files.Read.All",
    "Directory.Read.All",
)


def _sharepoint_scan_background(
    *,
    run_id: str,
    tenant_id: str,
    engagement_id: str,
    msal_app: Any,
    flow: dict[str, Any],
    actor: str,
) -> None:
    def _set(**kw: Any) -> None:
        with _MSGRAPH_RUNS_LOCK:
            _MSGRAPH_RUNS[run_id].update(kw)

    try:
        _set(status="authenticating")
        token_result = msal_app.acquire_token_by_device_flow(flow)
        if "access_token" not in token_result:
            _set(
                status="failed",
                error=token_result.get("error_description", "Token acquisition failed"),
            )
            return

        _set(status="scanning")
        from services.connectors.sharepoint.runner import run_sharepoint_scan

        scan_result = run_sharepoint_scan(
            access_token=token_result["access_token"],
            tenant_id=tenant_id,
            engagement_id=engagement_id,
        )

        _set(status="importing")
        from api.db import get_sessionmaker

        SessionLocal = get_sessionmaker()
        db = SessionLocal()
        try:
            result = import_sharepoint_scan(
                db=db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                scan_result=scan_result,
                actor=actor,
            )
            _auto_link_scan_evidence(
                db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                scan_result_id=result.scan_result_id,
                source_type="sharepoint_onedrive",
            )
            db.commit()
            _set(status="complete", scan_result_id=result.scan_result_id)
        except Exception as exc:
            log.error("sharepoint_scan_background: import failed — %s", exc)
            db.rollback()
            _set(status="failed", error=f"Import failed: {str(exc)[:200]}")
        finally:
            db.close()
    except Exception as exc:
        log.error("sharepoint_scan_background: scan failed — %s", exc)
        _set(status="failed", error=str(exc)[:200])


@router.post(
    "/engagements/{engagement_id}/connector-runs/sharepoint/initiate",
    response_model=MsgraphScanInitiateResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def initiate_sharepoint_scan(
    engagement_id: str,
    request: Request,
    body: MsgraphScanInitiateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(auth_ctx_db_session),
) -> MsgraphScanInitiateResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    client_id = os.environ.get("FG_MSAL_CLIENT_ID", "")
    if not client_id:
        raise HTTPException(
            status_code=503,
            detail=api_error("MSAL_NOT_CONFIGURED", "FG_MSAL_CLIENT_ID is not set"),
        )
    try:
        import msal  # type: ignore[import-untyped]
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail=api_error("MSAL_NOT_INSTALLED", "msal package is not installed"),
        )

    authority = f"https://login.microsoftonline.com/{body.azure_tenant_id}"
    msal_app = msal.PublicClientApplication(client_id, authority=authority)
    flow = msal_app.initiate_device_flow(scopes=list(_SHAREPOINT_SCOPES))
    if "user_code" not in flow:
        raise HTTPException(
            status_code=502,
            detail=api_error(
                "DEVICE_FLOW_FAILED",
                flow.get("error_description", "Device flow initiation failed"),
            ),
        )

    run_id = str(_uuid_module.uuid4())
    with _MSGRAPH_RUNS_LOCK:
        _MSGRAPH_RUNS[run_id] = {
            "status": "pending_auth",
            "user_code": flow["user_code"],
            "verification_uri": flow["verification_uri"],
            "error": None,
            "scan_result_id": None,
        }

    background_tasks.add_task(
        _sharepoint_scan_background,
        run_id=run_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        msal_app=msal_app,
        flow=flow,
        actor=actor,
    )

    return MsgraphScanInitiateResponse(
        run_id=run_id,
        user_code=flow["user_code"],
        verification_uri=flow["verification_uri"],
        expires_in=flow.get("expires_in", 900),
        message=flow.get("message", ""),
    )


# ---------------------------------------------------------------------------
# OAuth Risk Deep Scan connector (MSAL device-code, MS Graph)
# ---------------------------------------------------------------------------

_OAUTH_RISK_SCOPES: tuple[str, ...] = (
    "Application.Read.All",
    "Directory.Read.All",
    "AuditLog.Read.All",
)


def _oauth_risk_scan_background(
    *,
    run_id: str,
    tenant_id: str,
    engagement_id: str,
    msal_app: Any,
    flow: dict[str, Any],
    actor: str,
) -> None:
    def _set(**kw: Any) -> None:
        with _MSGRAPH_RUNS_LOCK:
            _MSGRAPH_RUNS[run_id].update(kw)

    try:
        _set(status="authenticating")
        token_result = msal_app.acquire_token_by_device_flow(flow)
        if "access_token" not in token_result:
            _set(
                status="failed",
                error=token_result.get("error_description", "Token acquisition failed"),
            )
            return

        _set(status="scanning")
        from services.connectors.oauth_risk.runner import run_oauth_risk

        scan_result = run_oauth_risk(
            access_token=token_result["access_token"],
            tenant_id=tenant_id,
            engagement_id=engagement_id,
        )

        _set(status="importing")
        from api.db import get_sessionmaker

        SessionLocal = get_sessionmaker()
        db = SessionLocal()
        try:
            result = import_oauth_risk_scan(
                db=db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                scan_result=scan_result,
                actor=actor,
            )
            _auto_link_scan_evidence(
                db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                scan_result_id=result.scan_result_id,
                source_type="oauth_risk",
            )
            db.commit()
            _set(status="complete", scan_result_id=result.scan_result_id)
        except Exception as exc:
            log.error("oauth_risk_scan_background: import failed — %s", exc)
            db.rollback()
            _set(status="failed", error=f"Import failed: {str(exc)[:200]}")
        finally:
            db.close()
    except Exception as exc:
        log.error("oauth_risk_scan_background: scan failed — %s", exc)
        _set(status="failed", error=str(exc)[:200])


@router.post(
    "/engagements/{engagement_id}/connector-runs/oauth-risk/initiate",
    response_model=MsgraphScanInitiateResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def initiate_oauth_risk_scan(
    engagement_id: str,
    request: Request,
    body: MsgraphScanInitiateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(auth_ctx_db_session),
) -> MsgraphScanInitiateResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor_from_request(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    client_id = os.environ.get("FG_MSAL_CLIENT_ID", "")
    if not client_id:
        raise HTTPException(
            status_code=503,
            detail=api_error("MSAL_NOT_CONFIGURED", "FG_MSAL_CLIENT_ID is not set"),
        )
    try:
        import msal  # type: ignore[import-untyped]
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail=api_error("MSAL_NOT_INSTALLED", "msal package is not installed"),
        )

    authority = f"https://login.microsoftonline.com/{body.azure_tenant_id}"
    msal_app = msal.PublicClientApplication(client_id, authority=authority)
    flow = msal_app.initiate_device_flow(scopes=list(_OAUTH_RISK_SCOPES))
    if "user_code" not in flow:
        raise HTTPException(
            status_code=502,
            detail=api_error(
                "DEVICE_FLOW_FAILED",
                flow.get("error_description", "Device flow initiation failed"),
            ),
        )

    run_id = str(_uuid_module.uuid4())
    with _MSGRAPH_RUNS_LOCK:
        _MSGRAPH_RUNS[run_id] = {
            "status": "pending_auth",
            "user_code": flow["user_code"],
            "verification_uri": flow["verification_uri"],
            "error": None,
            "scan_result_id": None,
        }

    background_tasks.add_task(
        _oauth_risk_scan_background,
        run_id=run_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        msal_app=msal_app,
        flow=flow,
        actor=actor,
    )

    return MsgraphScanInitiateResponse(
        run_id=run_id,
        user_code=flow["user_code"],
        verification_uri=flow["verification_uri"],
        expires_in=flow.get("expires_in", 900),
        message=flow.get("message", ""),
    )


@router.get(
    "/engagements/{engagement_id}/connector-runs/{run_id}/status",
    response_model=MsgraphRunStatusResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def get_msgraph_run_status(
    engagement_id: str,
    run_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> MsgraphRunStatusResponse:
    tenant_id = _resolve_caller_tenant(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    with _MSGRAPH_RUNS_LOCK:
        state = _MSGRAPH_RUNS.get(run_id)
    if state is None:
        raise HTTPException(
            status_code=404,
            detail=api_error("RUN_NOT_FOUND", f"No active run found for id {run_id}"),
        )
    return MsgraphRunStatusResponse(run_id=run_id, **state)


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
    engagement_status: str
    client_access_code: str | None = None


class ReportQaApproveBody(BaseModel):
    reviewer_name: str | None = None  # Human-readable name; falls back to JWT actor if omitted


@router.post(
    "/engagements/{engagement_id}/reports/{report_id}/qa-approve",
    response_model=ReportQaApproveResponse,
    status_code=200,
    dependencies=[Depends(require_scopes("governance:qa_approve"))],
)
def qa_approve_report_route(
    engagement_id: str,
    report_id: str,
    request: Request,
    body: ReportQaApproveBody = ReportQaApproveBody(),
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
    # reviewer_name is the human-readable display name (e.g. "Jane Smith, Senior Assessor").
    # The JWT actor is always recorded in the audit event for non-repudiation.
    display_name = (body.reviewer_name.strip() if body.reviewer_name and body.reviewer_name.strip() else None) or actor
    report.qa_approved_by = display_name
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
            "qa_approved_by": display_name,
            "qa_approved_at": now,
            "jwt_actor": actor,
        },
    )

    # Auto-advance in_progress → delivered and issue client access code.
    eng = db.execute(
        select(FaEngagement).where(
            FaEngagement.id == engagement_id,
            FaEngagement.tenant_id == tenant_id,
        )
    ).scalar_one()
    client_access_code: str | None = None
    if eng.status == "in_progress":
        eng.status = "delivered"
        eng.updated_at = now
        # Reuse any existing code already issued for this client so they can
        # log in with one password and see all their engagements over time.
        existing_code = db.execute(
            select(FaEngagement.client_access_code)
            .where(
                FaEngagement.tenant_id == tenant_id,
                FaEngagement.client_name == eng.client_name,
                FaEngagement.client_access_code.isnot(None),
                FaEngagement.id != engagement_id,
            )
            .limit(1)
        ).scalar_one_or_none()
        if existing_code:
            client_access_code = existing_code
        else:
            alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
            client_access_code = "".join(secrets.choice(alphabet) for _ in range(8))
        eng.client_access_code = client_access_code
        db.flush()
        emit_engagement_audit_event(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            event_type="engagement.status_transitioned",
            actor=actor,
            reason_code="AUTO_ADVANCE_QA_APPROVED",
            payload={"new_status": "delivered", "triggered_by": "report.qa_approved"},
        )
    else:
        client_access_code = eng.client_access_code

    db.commit()

    return ReportQaApproveResponse(
        report_id=report_id,
        qa_approved_by=actor,
        qa_approved_at=now,
        engagement_status=eng.status,
        client_access_code=client_access_code,
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
    "executive_summary",
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
    compiled_by: str | None = None


class EngagementReportSummary(BaseModel):
    report_id: str
    version: int
    status: str
    compiled_at: str
    compiled_by: str | None
    report_type: str | None
    qa_approved_by: str | None = None
    qa_approved_at: str | None = None


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
    from services.governance.report.framework_mappings import get_framework_mappings as _get_fw_maps

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
    # Maps effective confidence (0-100, decay-adjusted) → domain score
    from services.field_assessment.confidence import degrade_confidence as _degrade

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
        effective = _degrade(f.confidence_score, f.updated_at)
        domain_scores.setdefault(domain_key, []).append(float(effective))

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
        # Observation domains → framework_mappings lookup keys
        _OBS_DOMAIN_MAP = {
            "ai_governance": "ai_maturity",
            "data_security": "data_governance",
            "access_management": "access_control",
            "operational_security": "security_posture",
            "compliance": "compliance_awareness",
            "vendor_management": "vendor_management",
            "incident_response": "incident_response",
            "training": "ai_maturity",
        }

        # Frameworks relevant to each assessment type — None means all frameworks shown
        _ASSESSMENT_FRAMEWORK_ALLOW: dict[str, set[str] | None] = {
            "ai_governance": {"NIST-AI-RMF", "SOC2", "ISO-27001"},
            "hipaa": {"HIPAA", "NIST-AI-RMF", "SOC2"},
            "soc2": {"SOC2", "NIST-AI-RMF", "ISO-27001"},
            "cmmc": {"CMMC", "NIST-AI-RMF"},
            "iso27001": {"ISO-27001", "SOC2", "NIST-AI-RMF"},
            "pci_dss": {"SOC2", "NIST-AI-RMF", "ISO-27001"},
            "dora": {"ISO-27001", "NIST-AI-RMF"},
            "fedramp": {"NIST-AI-RMF", "CMMC"},
            "nist_800_171": {"NIST-AI-RMF", "CMMC"},
            "comprehensive": None,
        }
        _allowed_fws: set[str] | None = _ASSESSMENT_FRAMEWORK_ALLOW.get(eng.assessment_type)

        fw_summary: dict[str, set[str]] = {}

        def _add_fw_refs(fw: str, ctrl: str) -> None:
            fw_key = fw.replace("_", "-")
            if _allowed_fws is not None and fw_key not in _allowed_fws:
                return
            fw_summary.setdefault(fw_key, set()).add(ctrl)

        # 1. Derive from field observations (manual assessment) — gap/finding types
        obs_rows = db.execute(
            select(FaFieldObservation).where(
                FaFieldObservation.engagement_id == engagement_id,
                FaFieldObservation.tenant_id == tenant_id,
                FaFieldObservation.observation_type.in_(["finding", "gap", "concern"]),
                FaFieldObservation.deleted_at.is_(None),
            )
        ).scalars().all()
        for obs in obs_rows:
            fw_domain = _OBS_DOMAIN_MAP.get(obs.domain)
            if fw_domain is None:
                log.warning("Observation domain '%s' has no framework mapping — skipping", obs.domain)
                continue
            for fm in _get_fw_maps(control_id=fw_domain, domain=fw_domain):
                _add_fw_refs(fm.framework, fm.control_ref)

        # 2. Derive from connector-driven normalized findings (framework_mappings field)
        for f in all_findings:
            for fm in (f.framework_mappings or []):
                if isinstance(fm, dict):
                    fw = fm.get("framework", "")
                    ctrl = fm.get("control_id") or fm.get("control_ref") or ""
                    if fw and ctrl:
                        _add_fw_refs(fw, ctrl)

        # 3. Fall back to engine-derived summary if both sources are empty
        if not fw_summary:
            for fw, refs in report.framework_summary.items():
                for ctrl in refs:
                    _add_fw_refs(fw, ctrl)

        section_content["framework_summary"] = {
            k: sorted(v) for k, v in sorted(fw_summary.items())
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

    if "executive_summary" in active_sections and report_type in (
        "executive_summary",
        "full_assessment",
    ):
        from services.field_assessment.executive_summary import (
            generate_executive_summary,
        )

        confidence_overall = report.confidence.overall if report.confidence else 0.0
        section_content["executive_summary"] = generate_executive_summary(
            engagement_id=engagement_id,
            tenant_id=tenant_id,
            findings=[
                {
                    "severity": f.severity,
                    "domain": f.domain,
                    "gap_classification": f.gap_classification,
                }
                for f in report.findings
            ],
            framework_summary=dict(report.framework_summary),
            confidence_overall=confidence_overall,
        )

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
            compiled_by=(body.compiled_by.strip() if body.compiled_by and body.compiled_by.strip() else None) or actor,
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
            qa_approved_by=r.qa_approved_by,
            qa_approved_at=r.qa_approved_at,
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
        engagement = get_engagement(
            db, engagement_id=engagement_id, tenant_id=tenant_id
        )
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
    exec_summary = report_data.get("executive_summary")
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

    # Build data disclosure — query distinct connectors that ran for this engagement.
    scan_rows = db.execute(
        select(
            FaScanResult.source_type,
            FaScanResult.collected_at,
        )
        .where(
            FaScanResult.engagement_id == engagement_id,
            FaScanResult.tenant_id == tenant_id,
        )
        .order_by(FaScanResult.collected_at.asc())
    ).all()
    seen: set[str] = set()
    connectors_ordered: list[str] = []
    for row in scan_rows:
        if row.source_type not in seen:
            seen.add(row.source_type)
            connectors_ordered.append(row.source_type)
    first_collected_at = scan_rows[0].collected_at if scan_rows else ""
    operator_authorized = any(r.source_type == "microsoft_graph" for r in scan_rows)
    data_disclosure = {
        "connectors": connectors_ordered,
        "collected_at": str(first_collected_at),
        "retention_days": 90,
        "redaction_mode": "strict",
        "operator_authorized": operator_authorized,
    }

    try:
        pdf_bytes = export_pdf_bytes(
            gov_report,
            executive_summary=exec_summary if isinstance(exec_summary, dict) else None,
            engagement_name=engagement.client_name,
            data_disclosure=data_disclosure,
        )
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
    from services.field_assessment.remediation import generate_remediation_steps

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
        remediation_steps=generate_remediation_steps(finding),
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
    list_questionnaires,
    list_responses,
    normalize_nist_control,  # noqa: F401 — exported for test access
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
    evidence_sources: list[str] = []
    scan_finding_count: int = 0
    fused_confidence: float | None = None
    evidence_doc_id: str | None = None


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
    evidence_doc_id: str | None = None


class UpdateResponseResponse(BaseModel):
    id: str
    control_id: str
    response_status: str
    evidence_text: str | None
    confidence_score: float | None
    updated_at: str
    evidence_doc_id: str | None = None


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


def _fuse_response_item(
    r: FaQuestionnaireResponse,
    scan_count: int,
    *,
    evidence_doc_id: str | None = None,
) -> QuestionnaireResponseItem:
    sources: list[str] = ["questionnaire"]
    if scan_count > 0:
        sources.append("scan")
    if evidence_doc_id:
        sources.append("document")

    fused: float | None = None
    if r.confidence_score is not None:
        if scan_count > 0:
            fused = round(min(1.0, r.confidence_score + 0.1 * min(scan_count, 3)), 3)
        else:
            fused = r.confidence_score
    elif scan_count > 0:
        fused = round(min(0.7, 0.3 + 0.1 * scan_count), 3)

    return QuestionnaireResponseItem(
        id=r.id,
        control_id=r.control_id,
        category=r.category,
        control_name=r.control_name,
        response_status=r.response_status,
        evidence_text=r.evidence_text,
        confidence_score=r.confidence_score,
        assessor_id=r.assessor_id,
        updated_at=r.updated_at,
        evidence_sources=sources,
        scan_finding_count=scan_count,
        fused_confidence=fused,
        evidence_doc_id=evidence_doc_id,
    )


def _build_response_evidence_map(
    db: Session,
    *,
    engagement_id: str,
    tenant_id: str,
    response_ids: list[str],
) -> dict[str, str]:
    """Return {response_id: doc_id} for questionnaire_response→document_analysis links."""
    if not response_ids:
        return {}
    links = list(
        db.scalars(
            select(FaEvidenceLink).where(
                FaEvidenceLink.tenant_id == tenant_id,
                FaEvidenceLink.engagement_id == engagement_id,
                FaEvidenceLink.source_entity_type == "questionnaire_response",
                FaEvidenceLink.evidence_entity_type == "document_analysis",
                FaEvidenceLink.source_entity_id.in_(response_ids),
            )
        )
    )
    return {lnk.source_entity_id: lnk.evidence_entity_id for lnk in links}


def _build_scan_counts(
    db: Session,
    *,
    engagement_id: str,
    tenant_id: str,
) -> dict[str, int]:
    """Return {canonical_control_id: finding_count} for all findings in an engagement."""
    findings = list(
        db.scalars(
            select(FaNormalizedFinding).where(
                FaNormalizedFinding.engagement_id == engagement_id,
                FaNormalizedFinding.tenant_id == tenant_id,
            )
        )
    )
    counts: dict[str, int] = {}
    for f in findings:
        for raw in f.nist_ai_rmf_mappings or []:
            cid = normalize_nist_control(raw)
            if cid:
                counts[cid] = counts.get(cid, 0) + 1
    return counts


def _questionnaire_to_response(
    q: FaQuestionnaire,
    responses: list[FaQuestionnaireResponse],
    *,
    already_existed: bool = False,
    scan_counts: dict[str, int] | None = None,
    evidence_map: dict[str, str] | None = None,
) -> QuestionnaireResponse:
    sc = scan_counts or {}
    em = evidence_map or {}
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
            _fuse_response_item(r, sc.get(r.control_id, 0), evidence_doc_id=em.get(r.id))
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
    evidence_map = _build_response_evidence_map(
        db,
        engagement_id=engagement_id,
        tenant_id=tenant_id,
        response_ids=[r.id for r in responses],
    )
    return _questionnaire_to_response(q, responses, already_existed=not created, evidence_map=evidence_map)


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
            db,
            questionnaire_id=questionnaire_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
        )
    except QuestionnaireNotFound:
        raise HTTPException(
            status_code=404,
            detail=api_error("QUESTIONNAIRE_NOT_FOUND", "Questionnaire not found"),
        )
    responses = list_responses(db, questionnaire_id=q.id, tenant_id=tenant_id)
    evidence_map = _build_response_evidence_map(
        db,
        engagement_id=engagement_id,
        tenant_id=tenant_id,
        response_ids=[r.id for r in responses],
    )
    return _questionnaire_to_response(q, responses, evidence_map=evidence_map)


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
            engagement_id=engagement_id,
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

    # Manage questionnaire_response → document_analysis evidence link.
    resolved_doc_id: str | None = None
    if body.evidence_doc_id and body.response_status in ("implemented", "partial"):
        # Delete any existing doc link for this response (upsert semantics).
        db.execute(
            delete(FaEvidenceLink).where(
                FaEvidenceLink.tenant_id == tenant_id,
                FaEvidenceLink.engagement_id == engagement_id,
                FaEvidenceLink.source_entity_type == "questionnaire_response",
                FaEvidenceLink.source_entity_id == r.id,
                FaEvidenceLink.evidence_entity_type == "document_analysis",
            )
        )
        db.add(
            FaEvidenceLink(
                id=secrets.token_hex(32),
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                source_entity_type="questionnaire_response",
                source_entity_id=r.id,
                evidence_entity_type="document_analysis",
                evidence_entity_id=body.evidence_doc_id,
                link_metadata={
                    "control_id": r.control_id,
                    "response_status": body.response_status,
                },
                created_at=utc_iso8601_z_now(),
                schema_version="1.0",
            )
        )
        resolved_doc_id = body.evidence_doc_id

        # Auto-link matching findings → document_analysis for full traceability.
        findings = list(
            db.scalars(
                select(FaNormalizedFinding).where(
                    FaNormalizedFinding.engagement_id == engagement_id,
                    FaNormalizedFinding.tenant_id == tenant_id,
                )
            )
        )
        for finding in findings:
            matched = any(
                normalize_nist_control(raw) == r.control_id
                for raw in (finding.nist_ai_rmf_mappings or [])
            )
            if not matched:
                continue
            exists = db.scalar(
                select(func.count(FaEvidenceLink.id)).where(
                    FaEvidenceLink.tenant_id == tenant_id,
                    FaEvidenceLink.engagement_id == engagement_id,
                    FaEvidenceLink.source_entity_type == "finding",
                    FaEvidenceLink.source_entity_id == finding.id,
                    FaEvidenceLink.evidence_entity_type == "document_analysis",
                    FaEvidenceLink.evidence_entity_id == body.evidence_doc_id,
                )
            )
            if not exists:
                db.add(
                    FaEvidenceLink(
                        id=secrets.token_hex(32),
                        tenant_id=tenant_id,
                        engagement_id=engagement_id,
                        source_entity_type="finding",
                        source_entity_id=finding.id,
                        evidence_entity_type="document_analysis",
                        evidence_entity_id=body.evidence_doc_id,
                        link_metadata={"control_id": r.control_id, "via": "questionnaire"},
                        created_at=utc_iso8601_z_now(),
                        schema_version="1.0",
                    )
                )
    elif body.response_status not in ("implemented", "partial"):
        # Status no longer warrants a doc link — remove it if present.
        db.execute(
            delete(FaEvidenceLink).where(
                FaEvidenceLink.tenant_id == tenant_id,
                FaEvidenceLink.engagement_id == engagement_id,
                FaEvidenceLink.source_entity_type == "questionnaire_response",
                FaEvidenceLink.source_entity_id == r.id,
                FaEvidenceLink.evidence_entity_type == "document_analysis",
            )
        )

    db.commit()
    return UpdateResponseResponse(
        id=r.id,
        control_id=r.control_id,
        response_status=r.response_status,
        evidence_text=r.evidence_text,
        confidence_score=r.confidence_score,
        updated_at=r.updated_at,
        evidence_doc_id=resolved_doc_id,
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
            db,
            questionnaire_id=questionnaire_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            actor=actor,
        )
    except QuestionnaireNotFound:
        raise HTTPException(
            status_code=404,
            detail=api_error("QUESTIONNAIRE_NOT_FOUND", "Questionnaire not found"),
        )
    # Audit against q.engagement_id (verified from DB), not the route path param.
    emit_engagement_audit_event(
        db,
        tenant_id=tenant_id,
        engagement_id=q.engagement_id,
        event_type="questionnaire.submitted",
        actor=actor,
        reason_code="QUESTIONNAIRE_SUBMIT",
        payload={"questionnaire_id": q.id, "framework": q.framework},
    )
    db.commit()
    responses = list_responses(db, questionnaire_id=q.id, tenant_id=tenant_id)
    evidence_map = _build_response_evidence_map(
        db,
        engagement_id=q.engagement_id,
        tenant_id=tenant_id,
        response_ids=[r.id for r in responses],
    )
    return _questionnaire_to_response(q, responses, evidence_map=evidence_map)


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
        get_questionnaire(
            db,
            questionnaire_id=questionnaire_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
        )
    except QuestionnaireNotFound:
        raise HTTPException(
            status_code=404,
            detail=api_error("QUESTIONNAIRE_NOT_FOUND", "Questionnaire not found"),
        )
    cov = get_coverage(db, questionnaire_id=questionnaire_id, tenant_id=tenant_id)
    return QuestionnaireCoverageResponse(questionnaire_id=questionnaire_id, **cov)


@router.get(
    "/engagements/{engagement_id}/questionnaires",
    response_model=list[QuestionnaireResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_questionnaires_route(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> list[QuestionnaireResponse]:
    """List all questionnaires for an engagement with per-control evidence fusion.

    Returns questionnaire responses augmented with scan finding counts per control
    so callers can show a confidence-weighted coverage matrix without a second request.
    """
    tenant_id = _resolve_caller_tenant(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )
    qs = list_questionnaires(db, engagement_id=engagement_id, tenant_id=tenant_id)
    if not qs:
        return []
    scan_counts = _build_scan_counts(
        db, engagement_id=engagement_id, tenant_id=tenant_id
    )
    result = []
    for q in qs:
        responses = list_responses(db, questionnaire_id=q.id, tenant_id=tenant_id)
        evidence_map = _build_response_evidence_map(
            db,
            engagement_id=engagement_id,
            tenant_id=tenant_id,
            response_ids=[r.id for r in responses],
        )
        result.append(_questionnaire_to_response(q, responses, scan_counts=scan_counts, evidence_map=evidence_map))
    return result


# ---------------------------------------------------------------------------
# Routes — Remediation Roadmap
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/remediation-roadmap",
    response_model=RemediationRoadmapResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_remediation_roadmap(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> RemediationRoadmapResponse:
    """Phased remediation roadmap with compliance delta preview.

    Groups open/in-progress findings into three execution phases based on
    priority score (severity × scan evidence × NIST control coverage).
    Per-phase compliance delta is computed against the current questionnaire
    baseline so clients see projected NIST AI RMF coverage improvement.
    """
    from services.field_assessment.remediation import (
        compute_priority_score,
        compute_effort_level,
        assign_phase,
        PHASE_META,
        PHASE_ORDER,
        NIST_TOTAL_CONTROLS,
    )

    tenant_id = _resolve_caller_tenant(request)
    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404, detail=api_error("ENGAGEMENT_NOT_FOUND", exc.message)
        )

    # All open or in-progress findings for this engagement.
    # list_findings is capped at MAX_PAGE_SIZE=100, so paginate up to HARD_MAX=2000.
    _PAGE = 100
    _HARD_MAX = (
        2000  # safety cap — roadmaps beyond this are truncated with is_truncated=True
    )
    _offset = 0
    all_findings = []
    while True:
        _page = list_findings(
            db,
            engagement_id=engagement_id,
            tenant_id=tenant_id,
            severity_filter=None,
            status_filter=None,
            limit=_PAGE,
            offset=_offset,
        )
        all_findings.extend(_page)
        if len(_page) < _PAGE or len(all_findings) >= _HARD_MAX:
            break
        _offset += _PAGE
    _truncated = len(all_findings) >= _HARD_MAX
    active = [f for f in all_findings if f.status in ("open", "in_progress")]

    # Build current NIST AI RMF coverage baseline from questionnaire.
    current_coverage_pct = 0.0
    implemented_controls: set[str] = set()
    qs = list_questionnaires(db, engagement_id=engagement_id, tenant_id=tenant_id)
    if qs:
        responses = list_responses(db, questionnaire_id=qs[0].id, tenant_id=tenant_id)
        implemented = [r for r in responses if r.response_status == "implemented"]
        current_coverage_pct = round((len(implemented) / NIST_TOTAL_CONTROLS) * 100, 1)
        implemented_controls = {r.control_id for r in implemented}

    # Group findings into phases; track NIST controls addressed per phase.
    phase_buckets: dict[str, list[FaNormalizedFinding]] = {p: [] for p in PHASE_ORDER}
    for f in active:
        score = compute_priority_score(f)
        phase_buckets[assign_phase(score)].append(f)

    # Compute cumulative projected coverage.
    covered_so_far: set[str] = set(implemented_controls)
    phases: list[RemediationPhase] = []

    for phase_id in PHASE_ORDER:
        findings = sorted(
            phase_buckets[phase_id],
            key=lambda f: compute_priority_score(f),
            reverse=True,
        )
        # Unique NIST controls addressed by this phase that are not yet implemented.
        phase_new_controls: set[str] = set()
        for f in findings:
            for raw in f.nist_ai_rmf_mappings or []:
                cid = normalize_nist_control(raw)
                if cid and cid not in covered_so_far:
                    phase_new_controls.add(cid)

        delta_pct = round((len(phase_new_controls) / NIST_TOTAL_CONTROLS) * 100, 1)
        covered_so_far |= phase_new_controls

        phase_findings = [
            RemediationPhaseFinding(
                finding_id=f.id,
                title=f.title,
                severity=f.severity,
                status=f.status,
                finding_type=f.finding_type,
                remediation_hint=f.remediation_hint,
                remediation_priority=compute_priority_score(f),
                effort_level=compute_effort_level(f),
                nist_ai_rmf_mappings=f.nist_ai_rmf_mappings or [],
                framework_mappings=f.framework_mappings or [],
                nist_controls_addressed=len(
                    {
                        normalize_nist_control(r)
                        for r in (f.nist_ai_rmf_mappings or [])
                        if normalize_nist_control(r)
                    }
                ),
            )
            for f in findings
        ]

        meta = PHASE_META[phase_id]
        phases.append(
            RemediationPhase(
                phase_id=phase_id,
                label=meta["label"],
                window=meta["window"],
                findings=phase_findings,
                compliance_delta_pct=delta_pct,
                nist_controls_addressed=len(phase_new_controls),
            )
        )

    projected_coverage_pct = round((len(covered_so_far) / NIST_TOTAL_CONTROLS) * 100, 1)

    return RemediationRoadmapResponse(
        engagement_id=engagement_id,
        current_coverage_pct=current_coverage_pct,
        projected_coverage_pct=projected_coverage_pct,
        phases=phases,
        total_open_findings=len(active),
        is_truncated=_truncated,
    )
