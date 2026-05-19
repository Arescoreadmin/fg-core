"""Readiness Manager API — canonical AI readiness domain model endpoints.

All routes require control-plane:read (read) or control-plane:admin (write).
Tenant isolation: tenant_id for assessments/evidence is always resolved from
auth context, never from the request body. Platform-level framework records
(tenant_id=None) are readable by any sufficiently-scoped operator.

Routes are under /control-plane/readiness/ — covered by the existing
control-plane route prefix and its governance gates.

Security invariants:
- No secrets, credentials, or infrastructure topology in any response.
- tenant_id from auth context only for tenant-scoped resources.
- All mutations are audit-logged (ReadinessAuditEventRecord) before returning.
- Framework/assessment lifecycle transitions validated against state machines.
- All list endpoints page-capped at 200 rows.
- Finalized/archived assessments are immutable — mutations are rejected.
- Activated/deprecated/retired frameworks are structurally immutable.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from api.auth_scopes import require_scopes
from api.deps import auth_ctx_db_session
from api.error_contracts import api_error
from services.readiness import (
    AssessmentOutcome,
    AssessmentStatus,
    EvidenceType,
    FrameworkStatus,
    ReadinessStore,
)
from services.readiness.scoring import (
    FrameworkMismatchError as ScoringFrameworkMismatchError,
    ReadinessScoreEngine,
    ScoringContractMismatchError,
    ScoringError,
    ScoringInput,
    TenantIsolationViolation as ScoringTenantIsolationViolation,
)
from services.readiness.store import (
    AssessmentImmutableError,
    AssessmentNotFound,
    ConcurrentModificationError,
    ControlNotFound,
    DomainNotFound,
    DuplicateSlug,
    EvidenceReferenceNotFound,
    FrameworkImmutableError,
    FrameworkNotActiveError,
    FrameworkNotFound,
    FrameworkVersionNotFound,
    InvalidAssessmentTransition,
    InvalidFrameworkTransition,
    MaturityTierNotFound,
    ReadinessStoreError,
    ScoringContractNotFound,
)

from services.governance.timeline import TimelineStore
from services.governance.timeline.adapters import evidence_submitted_to_timeline_event

log = logging.getLogger("frostgate.readiness")
router = APIRouter(tags=["readiness"])

_store = ReadinessStore()
_timeline_store = TimelineStore()

# ---------------------------------------------------------------------------
# Error codes
# ---------------------------------------------------------------------------

ERR_FRAMEWORK_NOT_FOUND = "READY-API-001"
ERR_DOMAIN_NOT_FOUND = "READY-API-002"
ERR_CONTROL_NOT_FOUND = "READY-API-003"
ERR_MATURITY_TIER_NOT_FOUND = "READY-API-004"
ERR_ASSESSMENT_NOT_FOUND = "READY-API-005"
ERR_EVIDENCE_NOT_FOUND = "READY-API-006"
ERR_SCORING_CONTRACT_NOT_FOUND = "READY-API-007"
ERR_INVALID_FRAMEWORK_TRANSITION = "READY-API-008"
ERR_INVALID_ASSESSMENT_TRANSITION = "READY-API-009"
ERR_ASSESSMENT_IMMUTABLE = "READY-API-010"
ERR_FRAMEWORK_IMMUTABLE = "READY-API-011"
ERR_DUPLICATE_SLUG = "READY-API-012"
ERR_CONCURRENT_MODIFICATION = "READY-API-013"
ERR_INVALID_INPUT = "READY-API-014"
ERR_FRAMEWORK_VERSION_NOT_FOUND = "READY-API-015"
ERR_FRAMEWORK_NOT_ACTIVE = "READY-API-016"
ERR_SCORING_ENGINE_ERROR = "READY-API-017"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tenant_from_auth(request: Request) -> Optional[str]:
    """Resolve tenant_id from auth context. Never from request body."""
    auth = getattr(getattr(request, "state", None), "auth", None)
    return getattr(getattr(request, "state", None), "tenant_id", None) or getattr(
        auth, "tenant_id", None
    )


def _actor_from_request(request: Request) -> str:
    auth = getattr(getattr(request, "state", None), "auth", None)
    prefix = getattr(auth, "key_prefix", None)
    return str(prefix) if prefix else "unknown"


def _handle_store_error(exc: ReadinessStoreError) -> HTTPException:
    if isinstance(exc, FrameworkNotFound):
        return HTTPException(
            status_code=404, detail=api_error(ERR_FRAMEWORK_NOT_FOUND, exc.message)
        )
    if isinstance(exc, FrameworkVersionNotFound):
        return HTTPException(
            status_code=404,
            detail=api_error(ERR_FRAMEWORK_VERSION_NOT_FOUND, exc.message),
        )
    if isinstance(exc, DomainNotFound):
        return HTTPException(
            status_code=404, detail=api_error(ERR_DOMAIN_NOT_FOUND, exc.message)
        )
    if isinstance(exc, ControlNotFound):
        return HTTPException(
            status_code=404, detail=api_error(ERR_CONTROL_NOT_FOUND, exc.message)
        )
    if isinstance(exc, MaturityTierNotFound):
        return HTTPException(
            status_code=404,
            detail=api_error(ERR_MATURITY_TIER_NOT_FOUND, exc.message),
        )
    if isinstance(exc, AssessmentNotFound):
        return HTTPException(
            status_code=404, detail=api_error(ERR_ASSESSMENT_NOT_FOUND, exc.message)
        )
    if isinstance(exc, EvidenceReferenceNotFound):
        return HTTPException(
            status_code=404, detail=api_error(ERR_EVIDENCE_NOT_FOUND, exc.message)
        )
    if isinstance(exc, ScoringContractNotFound):
        return HTTPException(
            status_code=404,
            detail=api_error(ERR_SCORING_CONTRACT_NOT_FOUND, exc.message),
        )
    if isinstance(exc, InvalidFrameworkTransition):
        return HTTPException(
            status_code=409,
            detail=api_error(ERR_INVALID_FRAMEWORK_TRANSITION, exc.message),
        )
    if isinstance(exc, InvalidAssessmentTransition):
        return HTTPException(
            status_code=409,
            detail=api_error(ERR_INVALID_ASSESSMENT_TRANSITION, exc.message),
        )
    if isinstance(exc, AssessmentImmutableError):
        return HTTPException(
            status_code=409, detail=api_error(ERR_ASSESSMENT_IMMUTABLE, exc.message)
        )
    if isinstance(exc, FrameworkImmutableError):
        return HTTPException(
            status_code=409, detail=api_error(ERR_FRAMEWORK_IMMUTABLE, exc.message)
        )
    if isinstance(exc, FrameworkNotActiveError):
        return HTTPException(
            status_code=409, detail=api_error(ERR_FRAMEWORK_NOT_ACTIVE, exc.message)
        )
    if isinstance(exc, DuplicateSlug):
        return HTTPException(
            status_code=409, detail=api_error(ERR_DUPLICATE_SLUG, exc.message)
        )
    if isinstance(exc, ConcurrentModificationError):
        return HTTPException(
            status_code=409,
            detail=api_error(ERR_CONCURRENT_MODIFICATION, exc.message),
        )
    return HTTPException(
        status_code=500, detail=api_error("READY-API-500", exc.message)
    )


# ---------------------------------------------------------------------------
# Pydantic request/response models
# ---------------------------------------------------------------------------


class CreateFrameworkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework_name: str = Field(..., min_length=1, max_length=256)
    framework_slug: str = Field(..., min_length=1, max_length=128)
    framework_version: str = Field(..., min_length=1, max_length=64)
    framework_description: Optional[str] = None
    framework_metadata: dict[str, Any] = Field(default_factory=dict)
    compatibility_metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("framework_slug")
    @classmethod
    def slug_safe(cls, v: str) -> str:
        if not v.replace("-", "").replace("_", "").replace(".", "").isalnum():
            raise ValueError(
                "framework_slug must be alphanumeric with hyphens/underscores/dots only"
            )
        return v.lower()


class FrameworkTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_status: FrameworkStatus


class FrameworkResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    framework_id: str
    framework_name: str
    framework_slug: str
    framework_version: str
    framework_status: str
    framework_description: Optional[str]
    tenant_id: Optional[str]
    framework_metadata: dict[str, Any]
    compatibility_metadata: dict[str, Any]
    created_by: str
    created_at: str
    updated_at: str
    activated_at: Optional[str]
    deprecated_at: Optional[str]
    retired_at: Optional[str]
    state_version: int

    @classmethod
    def from_domain(cls, fw: Any) -> "FrameworkResponse":
        return cls(
            framework_id=fw.framework_id,
            framework_name=fw.framework_name,
            framework_slug=fw.framework_slug,
            framework_version=fw.framework_version,
            framework_status=fw.framework_status.value,
            framework_description=fw.framework_description,
            tenant_id=fw.tenant_id,
            framework_metadata=fw.framework_metadata,
            compatibility_metadata=fw.compatibility_metadata,
            created_by=fw.created_by,
            created_at=fw.created_at.isoformat(),
            updated_at=fw.updated_at.isoformat(),
            activated_at=fw.activated_at.isoformat() if fw.activated_at else None,
            deprecated_at=fw.deprecated_at.isoformat() if fw.deprecated_at else None,
            retired_at=fw.retired_at.isoformat() if fw.retired_at else None,
            state_version=fw.state_version,
        )


class CreateFrameworkVersionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version_tag: str = Field(..., min_length=1, max_length=64)
    schema_hash: Optional[str] = None
    compatibility_metadata: dict[str, Any] = Field(default_factory=dict)


class FrameworkVersionResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    version_id: str
    framework_id: str
    version_tag: str
    version_status: str
    schema_hash: Optional[str]
    created_by: str
    created_at: str
    compatibility_metadata: dict[str, Any]
    deprecation_note: Optional[str]

    @classmethod
    def from_domain(cls, v: Any) -> "FrameworkVersionResponse":
        return cls(
            version_id=v.version_id,
            framework_id=v.framework_id,
            version_tag=v.version_tag,
            version_status=v.version_status,
            schema_hash=v.schema_hash,
            created_by=v.created_by,
            created_at=v.created_at.isoformat(),
            compatibility_metadata=v.compatibility_metadata,
            deprecation_note=v.deprecation_note,
        )


class CreateDomainRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework_id: str
    domain_name: str = Field(..., min_length=1, max_length=256)
    domain_slug: str = Field(..., min_length=1, max_length=128)
    domain_description: str = Field(default="")
    domain_order: int = Field(default=0, ge=0)
    domain_metadata: dict[str, Any] = Field(default_factory=dict)
    maturity_applicability: dict[str, Any] = Field(default_factory=dict)
    domain_parent_id: Optional[str] = None


class DomainResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    domain_id: str
    framework_id: str
    domain_name: str
    domain_slug: str
    domain_description: str
    domain_order: int
    tenant_id: Optional[str]
    domain_metadata: dict[str, Any]
    maturity_applicability: dict[str, Any]
    domain_parent_id: Optional[str]
    created_by: str
    created_at: str

    @classmethod
    def from_domain(cls, d: Any) -> "DomainResponse":
        return cls(
            domain_id=d.domain_id,
            framework_id=d.framework_id,
            domain_name=d.domain_name,
            domain_slug=d.domain_slug,
            domain_description=d.domain_description,
            domain_order=d.domain_order,
            tenant_id=d.tenant_id,
            domain_metadata=d.domain_metadata,
            maturity_applicability=d.maturity_applicability,
            domain_parent_id=d.domain_parent_id,
            created_by=d.created_by,
            created_at=d.created_at.isoformat(),
        )


class CreateControlRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework_id: str
    domain_id: str
    control_identifier: str = Field(..., min_length=1, max_length=128)
    control_name: str = Field(..., min_length=1, max_length=256)
    control_description: str = Field(default="")
    control_metadata: dict[str, Any] = Field(default_factory=dict)
    applicability_metadata: dict[str, Any] = Field(default_factory=dict)
    evidence_requirements: dict[str, Any] = Field(default_factory=dict)
    maturity_mapping_metadata: dict[str, Any] = Field(default_factory=dict)
    scoring_compatibility_metadata: dict[str, Any] = Field(default_factory=dict)


class ControlResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    control_id: str
    framework_id: str
    domain_id: str
    control_identifier: str
    control_name: str
    control_description: str
    tenant_id: Optional[str]
    control_metadata: dict[str, Any]
    applicability_metadata: dict[str, Any]
    evidence_requirements: dict[str, Any]
    maturity_mapping_metadata: dict[str, Any]
    scoring_compatibility_metadata: dict[str, Any]
    created_by: str
    created_at: str

    @classmethod
    def from_domain(cls, c: Any) -> "ControlResponse":
        return cls(
            control_id=c.control_id,
            framework_id=c.framework_id,
            domain_id=c.domain_id,
            control_identifier=c.control_identifier,
            control_name=c.control_name,
            control_description=c.control_description,
            tenant_id=c.tenant_id,
            control_metadata=c.control_metadata,
            applicability_metadata=c.applicability_metadata,
            evidence_requirements=c.evidence_requirements,
            maturity_mapping_metadata=c.maturity_mapping_metadata,
            scoring_compatibility_metadata=c.scoring_compatibility_metadata,
            created_by=c.created_by,
            created_at=c.created_at.isoformat(),
        )


class CreateMaturityTierRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework_id: str
    tier_identifier: str = Field(..., min_length=1, max_length=64)
    tier_name: str = Field(..., min_length=1, max_length=256)
    tier_order: int = Field(..., ge=0)
    tier_criteria: str = Field(default="")
    tier_metadata: dict[str, Any] = Field(default_factory=dict)
    readiness_classification: Optional[str] = None


class MaturityTierResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    tier_id: str
    framework_id: str
    tier_identifier: str
    tier_name: str
    tier_order: int
    tier_criteria: str
    tenant_id: Optional[str]
    tier_metadata: dict[str, Any]
    readiness_classification: Optional[str]
    created_by: str
    created_at: str

    @classmethod
    def from_domain(cls, t: Any) -> "MaturityTierResponse":
        return cls(
            tier_id=t.tier_id,
            framework_id=t.framework_id,
            tier_identifier=t.tier_identifier,
            tier_name=t.tier_name,
            tier_order=t.tier_order,
            tier_criteria=t.tier_criteria,
            tenant_id=t.tenant_id,
            tier_metadata=t.tier_metadata,
            readiness_classification=t.readiness_classification,
            created_by=t.created_by,
            created_at=t.created_at.isoformat(),
        )


class CreateAssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework_id: str
    framework_version_tag: str = Field(..., min_length=1, max_length=64)
    assessment_name: Optional[str] = None
    assessment_description: Optional[str] = None
    assessment_metadata: dict[str, Any] = Field(default_factory=dict)
    scoring_contract_id: Optional[str] = None


class AssessmentTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_status: AssessmentStatus


class AssessmentResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    assessment_id: str
    tenant_id: str
    framework_id: str
    framework_version_tag: str
    assessment_status: str
    snapshot_version: int
    assessment_name: Optional[str]
    assessment_description: Optional[str]
    assessment_metadata: dict[str, Any]
    scoring_contract_id: Optional[str]
    created_by: str
    created_at: str
    updated_at: str
    activated_at: Optional[str]
    finalized_at: Optional[str]
    archived_at: Optional[str]
    state_version: int

    @classmethod
    def from_domain(cls, a: Any) -> "AssessmentResponse":
        return cls(
            assessment_id=a.assessment_id,
            tenant_id=a.tenant_id,
            framework_id=a.framework_id,
            framework_version_tag=a.framework_version_tag,
            assessment_status=a.assessment_status.value,
            snapshot_version=a.snapshot_version,
            assessment_name=a.assessment_name,
            assessment_description=a.assessment_description,
            assessment_metadata=a.assessment_metadata,
            scoring_contract_id=a.scoring_contract_id,
            created_by=a.created_by,
            created_at=a.created_at.isoformat(),
            updated_at=a.updated_at.isoformat(),
            activated_at=a.activated_at.isoformat() if a.activated_at else None,
            finalized_at=a.finalized_at.isoformat() if a.finalized_at else None,
            archived_at=a.archived_at.isoformat() if a.archived_at else None,
            state_version=a.state_version,
        )


class RecordAssessmentResultRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_id: str
    outcome: AssessmentOutcome
    maturity_tier_id: Optional[str] = None
    evaluation_metadata: dict[str, Any] = Field(default_factory=dict)
    scoring_metadata: dict[str, Any] = Field(default_factory=dict)
    evidence_reference_ids: list[str] = Field(default_factory=list)
    notes: Optional[str] = None


class AssessmentResultResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    result_id: str
    assessment_id: str
    control_id: str
    maturity_tier_id: Optional[str]
    outcome: str
    actor: str
    timestamp: str
    tenant_id: str
    evaluation_metadata: dict[str, Any]
    scoring_metadata: dict[str, Any]
    evidence_reference_ids: list[str]
    notes: Optional[str]

    @classmethod
    def from_domain(cls, r: Any) -> "AssessmentResultResponse":
        return cls(
            result_id=r.result_id,
            assessment_id=r.assessment_id,
            control_id=r.control_id,
            maturity_tier_id=r.maturity_tier_id,
            outcome=r.outcome.value,
            actor=r.actor,
            timestamp=r.timestamp.isoformat(),
            tenant_id=r.tenant_id,
            evaluation_metadata=r.evaluation_metadata,
            scoring_metadata=r.scoring_metadata,
            evidence_reference_ids=r.evidence_reference_ids,
            notes=r.notes,
        )


class AttachEvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_type: EvidenceType
    evidence_title: str = Field(..., min_length=1, max_length=512)
    evidence_source_metadata: dict[str, Any] = Field(default_factory=dict)
    evidence_ownership_metadata: dict[str, Any] = Field(default_factory=dict)
    evidence_integrity_metadata: dict[str, Any] = Field(default_factory=dict)
    evidence_classification: Optional[str] = None
    control_ids: list[str] = Field(default_factory=list)
    notes: Optional[str] = None


class EvidenceReferenceResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    evidence_id: str
    assessment_id: str
    evidence_type: str
    evidence_title: str
    submitted_by: str
    submitted_at: str
    tenant_id: str
    evidence_source_metadata: dict[str, Any]
    evidence_classification: Optional[str]
    control_ids: list[str]
    notes: Optional[str]

    @classmethod
    def from_domain(cls, e: Any) -> "EvidenceReferenceResponse":
        return cls(
            evidence_id=e.evidence_id,
            assessment_id=e.assessment_id,
            evidence_type=e.evidence_type.value,
            evidence_title=e.evidence_title,
            submitted_by=e.submitted_by,
            submitted_at=e.submitted_at.isoformat(),
            tenant_id=e.tenant_id,
            evidence_source_metadata=e.evidence_source_metadata,
            evidence_classification=e.evidence_classification,
            control_ids=e.control_ids,
            notes=e.notes,
        )


class CreateScoringContractRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework_id: str
    scoring_schema_version: str = Field(..., min_length=1, max_length=64)
    normalization_metadata: dict[str, Any] = Field(default_factory=dict)
    weighting_metadata: dict[str, Any] = Field(default_factory=dict)
    compatibility_metadata: dict[str, Any] = Field(default_factory=dict)
    scoring_metadata: dict[str, Any] = Field(default_factory=dict)


class ScoringContractResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    contract_id: str
    framework_id: str
    scoring_schema_version: str
    tenant_id: Optional[str]
    normalization_metadata: dict[str, Any]
    weighting_metadata: dict[str, Any]
    compatibility_metadata: dict[str, Any]
    scoring_metadata: dict[str, Any]
    is_active: bool
    created_by: str
    created_at: str

    @classmethod
    def from_domain(cls, sc: Any) -> "ScoringContractResponse":
        return cls(
            contract_id=sc.contract_id,
            framework_id=sc.framework_id,
            scoring_schema_version=sc.scoring_schema_version,
            tenant_id=sc.tenant_id,
            normalization_metadata=sc.normalization_metadata,
            weighting_metadata=sc.weighting_metadata,
            compatibility_metadata=sc.compatibility_metadata,
            scoring_metadata=sc.scoring_metadata,
            is_active=sc.is_active,
            created_by=sc.created_by,
            created_at=sc.created_at.isoformat(),
        )


# ---------------------------------------------------------------------------
# Score response models
# ---------------------------------------------------------------------------


class ControlScoreResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    control_id: str
    control_identifier: str
    domain_id: str
    outcome: str
    raw_score: float
    weight: float
    is_evaluated: bool
    is_applicable: bool
    evidence_count: int


class DomainScoreResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    domain_id: str
    domain_name: str
    raw_score: float
    normalized_score: float
    weight: float
    completion_percentage: float
    missing_control_count: int
    incomplete_control_count: int
    failed_control_count: int
    risk_classification: str
    threshold_failed: bool


class ThresholdFailureResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    threshold_type: str
    threshold_name: str
    required_value: float
    actual_value: float
    message: str


class RemediationFactorResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    factor_type: str
    description: str
    severity: str


class ScoreOutputResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    assessment_id: str
    tenant_id: str
    framework_id: str
    framework_version_tag: str
    overall_score: float
    normalized_score: float
    domain_scores: dict[str, DomainScoreResponse]
    control_scores: dict[str, ControlScoreResponse]
    maturity_tier: Optional[str]
    maturity_tier_id: Optional[str]
    risk_classification: str
    remediation_priority: str
    remediation_factors: list[RemediationFactorResponse]
    missing_controls: list[str]
    incomplete_controls: list[str]
    failed_controls: list[str]
    not_applicable_controls: list[str]
    threshold_failures: list[ThresholdFailureResponse]
    scoring_warnings: list[str]
    completion_state: str
    completion_percentage: float
    is_complete: bool
    computed_at: str
    score_version: str
    scoring_contract_id: Optional[str]
    scoring_contract_version: Optional[str]

    @classmethod
    def from_domain(cls, out: Any) -> "ScoreOutputResponse":
        return cls(
            assessment_id=out.assessment_id,
            tenant_id=out.tenant_id,
            framework_id=out.framework_id,
            framework_version_tag=out.framework_version_tag,
            overall_score=out.overall_score,
            normalized_score=out.normalized_score,
            domain_scores={
                did: DomainScoreResponse(
                    domain_id=ds.domain_id,
                    domain_name=ds.domain_name,
                    raw_score=ds.raw_score,
                    normalized_score=ds.normalized_score,
                    weight=ds.weight,
                    completion_percentage=ds.completion_percentage,
                    missing_control_count=ds.missing_control_count,
                    incomplete_control_count=ds.incomplete_control_count,
                    failed_control_count=ds.failed_control_count,
                    risk_classification=ds.risk_classification.value,
                    threshold_failed=ds.threshold_failed,
                )
                for did, ds in out.domain_scores.items()
            },
            control_scores={
                cid: ControlScoreResponse(
                    control_id=cs.control_id,
                    control_identifier=cs.control_identifier,
                    domain_id=cs.domain_id,
                    outcome=cs.outcome.value,
                    raw_score=cs.raw_score,
                    weight=cs.weight,
                    is_evaluated=cs.is_evaluated,
                    is_applicable=cs.is_applicable,
                    evidence_count=cs.evidence_count,
                )
                for cid, cs in out.control_scores.items()
            },
            maturity_tier=out.maturity_tier,
            maturity_tier_id=out.maturity_tier_id,
            risk_classification=out.risk_classification.value,
            remediation_priority=out.remediation_priority.value,
            remediation_factors=[
                RemediationFactorResponse(
                    factor_type=f.factor_type,
                    description=f.description,
                    severity=f.severity,
                )
                for f in out.remediation_factors
            ],
            missing_controls=list(out.missing_controls),
            incomplete_controls=list(out.incomplete_controls),
            failed_controls=list(out.failed_controls),
            not_applicable_controls=list(out.not_applicable_controls),
            threshold_failures=[
                ThresholdFailureResponse(
                    threshold_type=tf.threshold_type,
                    threshold_name=tf.threshold_name,
                    required_value=tf.required_value,
                    actual_value=tf.actual_value,
                    message=tf.message,
                )
                for tf in out.threshold_failures
            ],
            scoring_warnings=list(out.scoring_warnings),
            completion_state=out.completion_state.value,
            completion_percentage=out.completion_percentage,
            is_complete=out.is_complete,
            computed_at=out.computed_at.isoformat(),
            score_version=out.score_version,
            scoring_contract_id=out.scoring_contract_id,
            scoring_contract_version=out.scoring_contract_version,
        )


_score_engine = ReadinessScoreEngine()
_SCORE_PAGE = 200  # store clamps at _MAX_PAGE=200; page until exhausted


def _fetch_all(fn, **kwargs) -> list:  # type: ignore[type-arg]
    """Page through a capped store list method until exhausted."""
    items: list = []
    offset = 0
    while True:
        page = fn(**kwargs, limit=_SCORE_PAGE, offset=offset)
        items.extend(page)
        if len(page) < _SCORE_PAGE:
            break
        offset += _SCORE_PAGE
    return items


# ---------------------------------------------------------------------------
# Framework routes
# ---------------------------------------------------------------------------


@router.post(
    "/control-plane/readiness/frameworks",
    status_code=201,
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def create_framework(
    req: CreateFrameworkRequest,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> FrameworkResponse:
    try:
        actor = _actor_from_request(request)
        tenant_id = _tenant_from_auth(request)
        fw = _store.create_framework(
            db,
            framework_name=req.framework_name,
            framework_slug=req.framework_slug,
            framework_version=req.framework_version,
            framework_description=req.framework_description,
            created_by=actor,
            tenant_id=tenant_id,
            framework_metadata=req.framework_metadata,
            compatibility_metadata=req.compatibility_metadata,
        )
        db.commit()
        return FrameworkResponse.from_domain(fw)
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


@router.get(
    "/control-plane/readiness/frameworks",
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def list_frameworks(
    request: Request,
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> list[FrameworkResponse]:
    tenant_id = _tenant_from_auth(request)
    fw_status: Optional[FrameworkStatus] = None
    if status is not None:
        try:
            fw_status = FrameworkStatus(status)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=api_error(ERR_INVALID_INPUT, f"Invalid status: {status!r}"),
            )
    try:
        frameworks = _store.list_frameworks(
            db, tenant_id=tenant_id, status=fw_status, limit=limit, offset=offset
        )
        return [FrameworkResponse.from_domain(fw) for fw in frameworks]
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


@router.get(
    "/control-plane/readiness/frameworks/{framework_id}",
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def get_framework(
    framework_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> FrameworkResponse:
    tenant_id = _tenant_from_auth(request)
    try:
        fw = _store.get_framework(db, framework_id=framework_id, tenant_id=tenant_id)
        return FrameworkResponse.from_domain(fw)
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


@router.post(
    "/control-plane/readiness/frameworks/{framework_id}/transition",
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def transition_framework(
    framework_id: str,
    req: FrameworkTransitionRequest,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> FrameworkResponse:
    try:
        actor = _actor_from_request(request)
        tenant_id = _tenant_from_auth(request)
        fw = _store.transition_framework_status(
            db,
            framework_id=framework_id,
            to_status=req.to_status,
            actor=actor,
            tenant_id=tenant_id,
        )
        db.commit()
        return FrameworkResponse.from_domain(fw)
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


# ---------------------------------------------------------------------------
# Framework version routes
# ---------------------------------------------------------------------------


@router.post(
    "/control-plane/readiness/frameworks/{framework_id}/versions",
    status_code=201,
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def create_framework_version(
    framework_id: str,
    req: CreateFrameworkVersionRequest,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> FrameworkVersionResponse:
    try:
        actor = _actor_from_request(request)
        tenant_id = _tenant_from_auth(request)
        version = _store.create_framework_version(
            db,
            framework_id=framework_id,
            version_tag=req.version_tag,
            created_by=actor,
            tenant_id=tenant_id,
            schema_hash=req.schema_hash,
            compatibility_metadata=req.compatibility_metadata,
        )
        db.commit()
        return FrameworkVersionResponse.from_domain(version)
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


@router.get(
    "/control-plane/readiness/frameworks/{framework_id}/versions",
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def list_framework_versions(
    framework_id: str,
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> list[FrameworkVersionResponse]:
    tenant_id = _tenant_from_auth(request)
    try:
        versions = _store.list_framework_versions(
            db,
            framework_id=framework_id,
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
        )
        return [FrameworkVersionResponse.from_domain(v) for v in versions]
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


# ---------------------------------------------------------------------------
# Domain routes
# ---------------------------------------------------------------------------


@router.post(
    "/control-plane/readiness/domains",
    status_code=201,
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def create_domain(
    req: CreateDomainRequest,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> DomainResponse:
    try:
        actor = _actor_from_request(request)
        tenant_id = _tenant_from_auth(request)
        domain = _store.create_domain(
            db,
            framework_id=req.framework_id,
            domain_name=req.domain_name,
            domain_slug=req.domain_slug,
            domain_description=req.domain_description,
            domain_order=req.domain_order,
            created_by=actor,
            tenant_id=tenant_id,
            domain_metadata=req.domain_metadata,
            maturity_applicability=req.maturity_applicability,
            domain_parent_id=req.domain_parent_id,
        )
        db.commit()
        return DomainResponse.from_domain(domain)
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


@router.get(
    "/control-plane/readiness/frameworks/{framework_id}/domains",
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def list_domains(
    framework_id: str,
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> list[DomainResponse]:
    tenant_id = _tenant_from_auth(request)
    try:
        domains = _store.list_domains(
            db,
            framework_id=framework_id,
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
        )
        return [DomainResponse.from_domain(d) for d in domains]
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


@router.get(
    "/control-plane/readiness/domains/{domain_id}",
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def get_domain(
    domain_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> DomainResponse:
    tenant_id = _tenant_from_auth(request)
    try:
        domain = _store.get_domain(db, domain_id=domain_id, tenant_id=tenant_id)
        return DomainResponse.from_domain(domain)
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


# ---------------------------------------------------------------------------
# Control routes
# ---------------------------------------------------------------------------


@router.post(
    "/control-plane/readiness/controls",
    status_code=201,
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def create_control(
    req: CreateControlRequest,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> ControlResponse:
    try:
        actor = _actor_from_request(request)
        tenant_id = _tenant_from_auth(request)
        control = _store.create_control(
            db,
            framework_id=req.framework_id,
            domain_id=req.domain_id,
            control_identifier=req.control_identifier,
            control_name=req.control_name,
            control_description=req.control_description,
            created_by=actor,
            tenant_id=tenant_id,
            control_metadata=req.control_metadata,
            applicability_metadata=req.applicability_metadata,
            evidence_requirements=req.evidence_requirements,
            maturity_mapping_metadata=req.maturity_mapping_metadata,
            scoring_compatibility_metadata=req.scoring_compatibility_metadata,
        )
        db.commit()
        return ControlResponse.from_domain(control)
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


@router.get(
    "/control-plane/readiness/frameworks/{framework_id}/controls",
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def list_controls(
    framework_id: str,
    request: Request,
    domain_id: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> list[ControlResponse]:
    tenant_id = _tenant_from_auth(request)
    try:
        controls = _store.list_controls(
            db,
            framework_id=framework_id,
            domain_id=domain_id,
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
        )
        return [ControlResponse.from_domain(c) for c in controls]
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


@router.get(
    "/control-plane/readiness/controls/{control_id}",
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def get_control(
    control_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> ControlResponse:
    tenant_id = _tenant_from_auth(request)
    try:
        control = _store.get_control(db, control_id=control_id, tenant_id=tenant_id)
        return ControlResponse.from_domain(control)
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


# ---------------------------------------------------------------------------
# Maturity tier routes
# ---------------------------------------------------------------------------


@router.post(
    "/control-plane/readiness/maturity-tiers",
    status_code=201,
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def create_maturity_tier(
    req: CreateMaturityTierRequest,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> MaturityTierResponse:
    try:
        actor = _actor_from_request(request)
        tenant_id = _tenant_from_auth(request)
        tier = _store.create_maturity_tier(
            db,
            framework_id=req.framework_id,
            tier_identifier=req.tier_identifier,
            tier_name=req.tier_name,
            tier_order=req.tier_order,
            tier_criteria=req.tier_criteria,
            created_by=actor,
            tenant_id=tenant_id,
            tier_metadata=req.tier_metadata,
            readiness_classification=req.readiness_classification,
        )
        db.commit()
        return MaturityTierResponse.from_domain(tier)
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


@router.get(
    "/control-plane/readiness/frameworks/{framework_id}/maturity-tiers",
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def list_maturity_tiers(
    framework_id: str,
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> list[MaturityTierResponse]:
    tenant_id = _tenant_from_auth(request)
    try:
        tiers = _store.list_maturity_tiers(
            db,
            framework_id=framework_id,
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
        )
        return [MaturityTierResponse.from_domain(t) for t in tiers]
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


@router.get(
    "/control-plane/readiness/maturity-tiers/{tier_id}",
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def get_maturity_tier(
    tier_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> MaturityTierResponse:
    tenant_id = _tenant_from_auth(request)
    try:
        tier = _store.get_maturity_tier(db, tier_id=tier_id, tenant_id=tenant_id)
        return MaturityTierResponse.from_domain(tier)
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


# ---------------------------------------------------------------------------
# Assessment routes
# ---------------------------------------------------------------------------


@router.post(
    "/control-plane/readiness/assessments",
    status_code=201,
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def create_assessment(
    req: CreateAssessmentRequest,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> AssessmentResponse:
    try:
        actor = _actor_from_request(request)
        tenant_id = _tenant_from_auth(request)
        if not tenant_id:
            raise HTTPException(
                status_code=403,
                detail=api_error(
                    "READY-API-403",
                    "Assessments require a tenant-scoped auth context",
                ),
            )
        assessment = _store.create_assessment(
            db,
            tenant_id=tenant_id,
            framework_id=req.framework_id,
            framework_version_tag=req.framework_version_tag,
            created_by=actor,
            assessment_name=req.assessment_name,
            assessment_description=req.assessment_description,
            assessment_metadata=req.assessment_metadata,
            scoring_contract_id=req.scoring_contract_id,
        )
        db.commit()
        return AssessmentResponse.from_domain(assessment)
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


@router.get(
    "/control-plane/readiness/assessments",
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def list_assessments(
    request: Request,
    framework_id: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> list[AssessmentResponse]:
    tenant_id = _tenant_from_auth(request)
    if not tenant_id:
        raise HTTPException(
            status_code=403,
            detail=api_error(
                "READY-API-403", "Assessments require tenant auth context"
            ),
        )
    assess_status: Optional[AssessmentStatus] = None
    if status is not None:
        try:
            assess_status = AssessmentStatus(status)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=api_error(ERR_INVALID_INPUT, f"Invalid status: {status!r}"),
            )
    try:
        assessments = _store.list_assessments(
            db,
            tenant_id=tenant_id,
            framework_id=framework_id,
            status=assess_status,
            limit=limit,
            offset=offset,
        )
        return [AssessmentResponse.from_domain(a) for a in assessments]
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


@router.get(
    "/control-plane/readiness/assessments/{assessment_id}",
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def get_assessment(
    assessment_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> AssessmentResponse:
    tenant_id = _tenant_from_auth(request)
    if not tenant_id:
        raise HTTPException(
            status_code=403,
            detail=api_error(
                "READY-API-403", "Assessments require tenant auth context"
            ),
        )
    try:
        assessment = _store.get_assessment(
            db, assessment_id=assessment_id, tenant_id=tenant_id
        )
        return AssessmentResponse.from_domain(assessment)
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


@router.post(
    "/control-plane/readiness/assessments/{assessment_id}/transition",
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def transition_assessment(
    assessment_id: str,
    req: AssessmentTransitionRequest,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> AssessmentResponse:
    try:
        actor = _actor_from_request(request)
        tenant_id = _tenant_from_auth(request)
        if not tenant_id:
            raise HTTPException(
                status_code=403,
                detail=api_error(
                    "READY-API-403", "Assessments require tenant auth context"
                ),
            )
        assessment = _store.transition_assessment_status(
            db,
            assessment_id=assessment_id,
            to_status=req.to_status,
            actor=actor,
            tenant_id=tenant_id,
        )
        db.commit()
        return AssessmentResponse.from_domain(assessment)
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


# ---------------------------------------------------------------------------
# Assessment result routes
# ---------------------------------------------------------------------------


@router.post(
    "/control-plane/readiness/assessments/{assessment_id}/results",
    status_code=201,
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def record_assessment_result(
    assessment_id: str,
    req: RecordAssessmentResultRequest,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> AssessmentResultResponse:
    try:
        actor = _actor_from_request(request)
        tenant_id = _tenant_from_auth(request)
        if not tenant_id:
            raise HTTPException(
                status_code=403,
                detail=api_error(
                    "READY-API-403", "Assessments require tenant auth context"
                ),
            )
        result = _store.record_assessment_result(
            db,
            assessment_id=assessment_id,
            control_id=req.control_id,
            outcome=req.outcome,
            actor=actor,
            tenant_id=tenant_id,
            maturity_tier_id=req.maturity_tier_id,
            evaluation_metadata=req.evaluation_metadata,
            scoring_metadata=req.scoring_metadata,
            evidence_reference_ids=req.evidence_reference_ids,
            notes=req.notes,
        )
        db.commit()
        return AssessmentResultResponse.from_domain(result)
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


@router.get(
    "/control-plane/readiness/assessments/{assessment_id}/results",
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def list_assessment_results(
    assessment_id: str,
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> list[AssessmentResultResponse]:
    tenant_id = _tenant_from_auth(request)
    if not tenant_id:
        raise HTTPException(
            status_code=403,
            detail=api_error(
                "READY-API-403", "Assessments require tenant auth context"
            ),
        )
    try:
        results = _store.list_assessment_results(
            db,
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
        )
        return [AssessmentResultResponse.from_domain(r) for r in results]
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


# ---------------------------------------------------------------------------
# Evidence reference routes
# ---------------------------------------------------------------------------


@router.post(
    "/control-plane/readiness/assessments/{assessment_id}/evidence",
    status_code=201,
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def attach_evidence(
    assessment_id: str,
    req: AttachEvidenceRequest,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> EvidenceReferenceResponse:
    try:
        actor = _actor_from_request(request)
        tenant_id = _tenant_from_auth(request)
        if not tenant_id:
            raise HTTPException(
                status_code=403,
                detail=api_error(
                    "READY-API-403", "Evidence requires tenant auth context"
                ),
            )
        evidence = _store.attach_evidence_reference(
            db,
            assessment_id=assessment_id,
            evidence_type=req.evidence_type,
            evidence_title=req.evidence_title,
            submitted_by=actor,
            tenant_id=tenant_id,
            evidence_source_metadata=req.evidence_source_metadata,
            evidence_ownership_metadata=req.evidence_ownership_metadata,
            evidence_integrity_metadata=req.evidence_integrity_metadata,
            evidence_classification=req.evidence_classification,
            control_ids=req.control_ids,
            notes=req.notes,
        )
        try:
            _tl_event = evidence_submitted_to_timeline_event(evidence)
            _timeline_store.record(db, _tl_event)
        except Exception:
            log.warning(
                "evidence.timeline_emit_failed evidence_id=%s", evidence.evidence_id
            )
        db.commit()
        return EvidenceReferenceResponse.from_domain(evidence)
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


@router.get(
    "/control-plane/readiness/assessments/{assessment_id}/evidence",
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def list_evidence(
    assessment_id: str,
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> list[EvidenceReferenceResponse]:
    tenant_id = _tenant_from_auth(request)
    if not tenant_id:
        raise HTTPException(
            status_code=403,
            detail=api_error("READY-API-403", "Evidence requires tenant auth context"),
        )
    try:
        evidence_list = _store.list_evidence_references(
            db,
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
        )
        return [EvidenceReferenceResponse.from_domain(e) for e in evidence_list]
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


# ---------------------------------------------------------------------------
# Scoring contract routes
# ---------------------------------------------------------------------------


@router.post(
    "/control-plane/readiness/scoring-contracts",
    status_code=201,
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:admin"))],
)
def create_scoring_contract(
    req: CreateScoringContractRequest,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> ScoringContractResponse:
    try:
        actor = _actor_from_request(request)
        tenant_id = _tenant_from_auth(request)
        contract = _store.create_scoring_contract(
            db,
            framework_id=req.framework_id,
            scoring_schema_version=req.scoring_schema_version,
            created_by=actor,
            tenant_id=tenant_id,
            normalization_metadata=req.normalization_metadata,
            weighting_metadata=req.weighting_metadata,
            compatibility_metadata=req.compatibility_metadata,
            scoring_metadata=req.scoring_metadata,
        )
        db.commit()
        return ScoringContractResponse.from_domain(contract)
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


@router.get(
    "/control-plane/readiness/scoring-contracts/{contract_id}",
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def get_scoring_contract(
    contract_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> ScoringContractResponse:
    tenant_id = _tenant_from_auth(request)
    try:
        contract = _store.get_scoring_contract(
            db, contract_id=contract_id, tenant_id=tenant_id
        )
        return ScoringContractResponse.from_domain(contract)
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


@router.get(
    "/control-plane/readiness/frameworks/{framework_id}/scoring-contracts",
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def list_scoring_contracts(
    framework_id: str,
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> list[ScoringContractResponse]:
    tenant_id = _tenant_from_auth(request)
    try:
        contracts = _store.list_scoring_contracts(
            db,
            framework_id=framework_id,
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
        )
        return [ScoringContractResponse.from_domain(sc) for sc in contracts]
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)


# ---------------------------------------------------------------------------
# Score route
# ---------------------------------------------------------------------------


@router.get(
    "/control-plane/readiness/assessments/{assessment_id}/score",
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def score_assessment(
    assessment_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> ScoreOutputResponse:
    """Compute a deterministic readiness score for an assessment.

    Loads all framework, domain, control, maturity, result, and evidence data
    from the store, scores deterministically, and returns a frozen ScoreOutput.
    No data is mutated. Score is not persisted — call again for a fresh score.
    """
    tenant_id = _tenant_from_auth(request)
    if not tenant_id:
        raise HTTPException(
            status_code=403,
            detail=api_error(
                "READY-API-403", "Assessments require tenant auth context"
            ),
        )
    try:
        assessment = _store.get_assessment(
            db, assessment_id=assessment_id, tenant_id=tenant_id
        )
    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)

    try:
        framework = _store.get_framework(db, framework_id=assessment.framework_id)
        domains = _fetch_all(
            _store.list_domains, db=db, framework_id=assessment.framework_id
        )
        controls = _fetch_all(
            _store.list_controls, db=db, framework_id=assessment.framework_id
        )
        maturity_tiers = _fetch_all(
            _store.list_maturity_tiers, db=db, framework_id=assessment.framework_id
        )
        results = _fetch_all(
            _store.list_assessment_results,
            db=db,
            assessment_id=assessment_id,
            tenant_id=tenant_id,
        )
        evidence_refs = _fetch_all(
            _store.list_evidence_references,
            db=db,
            assessment_id=assessment_id,
            tenant_id=tenant_id,
        )
        scoring_contract = None
        if assessment.scoring_contract_id:
            try:
                scoring_contract = _store.get_scoring_contract(
                    db,
                    contract_id=assessment.scoring_contract_id,
                    tenant_id=tenant_id,
                )
            except ScoringContractNotFound:
                pass  # missing contract → score without one, engine will warn

        inp = ScoringInput(
            assessment=assessment,
            framework=framework,
            controls=tuple(controls),
            domains=tuple(domains),
            maturity_tiers=tuple(maturity_tiers),
            results=tuple(results),
            evidence_refs=tuple(evidence_refs),
            scoring_contract=scoring_contract,
        )
        out = _score_engine.score(inp)
        return ScoreOutputResponse.from_domain(out)

    except ReadinessStoreError as exc:
        raise _handle_store_error(exc)
    except (
        ScoringTenantIsolationViolation,
        ScoringFrameworkMismatchError,
        ScoringContractMismatchError,
    ) as exc:
        raise HTTPException(
            status_code=422,
            detail=api_error(ERR_SCORING_ENGINE_ERROR, str(exc)),
        )
    except ScoringError as exc:
        raise HTTPException(
            status_code=422,
            detail=api_error(ERR_SCORING_ENGINE_ERROR, str(exc)),
        )
