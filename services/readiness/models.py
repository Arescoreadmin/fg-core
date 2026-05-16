"""Readiness domain models — pure Python, no I/O, no SQLAlchemy.

All identifiers are immutable after creation. Assessment lifecycle transitions
are gated by VALID_ASSESSMENT_TRANSITIONS. Framework definitions are immutable
once activated. Historical assessments are immutable once finalized.

No mutable module-level state.
No scoring logic. No reporting logic. No evidence automation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class FrameworkStatus(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    RETIRED = "retired"


class AssessmentStatus(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    FINALIZED = "finalized"
    ARCHIVED = "archived"


class EvidenceType(str, Enum):
    DOCUMENT = "document"
    ATTESTATION = "attestation"
    AUTOMATED_SCAN = "automated_scan"
    INTERVIEW = "interview"
    OBSERVATION = "observation"
    POLICY = "policy"
    LOG_RECORD = "log_record"
    EXTERNAL_CERTIFICATION = "external_certification"
    OTHER = "other"


class AssessmentOutcome(str, Enum):
    NOT_EVALUATED = "not_evaluated"
    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"


class ReadinessEventType(str, Enum):
    FRAMEWORK_CREATED = "framework_created"
    FRAMEWORK_ACTIVATED = "framework_activated"
    FRAMEWORK_DEPRECATED = "framework_deprecated"
    FRAMEWORK_RETIRED = "framework_retired"
    FRAMEWORK_VERSION_CREATED = "framework_version_created"
    DOMAIN_CREATED = "domain_created"
    CONTROL_CREATED = "control_created"
    CONTROL_REFERENCE_CREATED = "control_reference_created"
    MATURITY_TIER_CREATED = "maturity_tier_created"
    ASSESSMENT_CREATED = "assessment_created"
    ASSESSMENT_ACTIVATED = "assessment_activated"
    ASSESSMENT_FINALIZED = "assessment_finalized"
    ASSESSMENT_ARCHIVED = "assessment_archived"
    ASSESSMENT_RESULT_RECORDED = "assessment_result_recorded"
    EVIDENCE_REFERENCE_ATTACHED = "evidence_reference_attached"
    SCORING_CONTRACT_CREATED = "scoring_contract_created"


# ---------------------------------------------------------------------------
# Valid state transitions (deterministic state machines)
# ---------------------------------------------------------------------------


#: Framework lifecycle: active frameworks are immutable (no structural changes).
#: Retired is terminal — no outbound transitions.
VALID_FRAMEWORK_TRANSITIONS: dict[FrameworkStatus, frozenset[FrameworkStatus]] = {
    FrameworkStatus.DRAFT: frozenset({FrameworkStatus.ACTIVE}),
    FrameworkStatus.ACTIVE: frozenset({FrameworkStatus.DEPRECATED}),
    FrameworkStatus.DEPRECATED: frozenset({FrameworkStatus.RETIRED}),
    FrameworkStatus.RETIRED: frozenset(),  # terminal
}

#: Assessment lifecycle: finalized assessments are immutable (history preserved).
#: Archived is terminal — no outbound transitions.
VALID_ASSESSMENT_TRANSITIONS: dict[AssessmentStatus, frozenset[AssessmentStatus]] = {
    AssessmentStatus.DRAFT: frozenset({AssessmentStatus.ACTIVE}),
    AssessmentStatus.ACTIVE: frozenset(
        {AssessmentStatus.FINALIZED, AssessmentStatus.DRAFT}
    ),
    AssessmentStatus.FINALIZED: frozenset({AssessmentStatus.ARCHIVED}),
    AssessmentStatus.ARCHIVED: frozenset(),  # terminal
}

#: Terminal assessment statuses — immutable once reached.
IMMUTABLE_ASSESSMENT_STATUSES: frozenset[AssessmentStatus] = frozenset(
    {AssessmentStatus.FINALIZED, AssessmentStatus.ARCHIVED}
)

#: Terminal framework statuses — immutable structural state once reached.
IMMUTABLE_FRAMEWORK_STATUSES: frozenset[FrameworkStatus] = frozenset(
    {FrameworkStatus.ACTIVE, FrameworkStatus.DEPRECATED, FrameworkStatus.RETIRED}
)


def validate_framework_transition(
    from_status: FrameworkStatus, to_status: FrameworkStatus
) -> None:
    """Raise ValueError if the framework lifecycle transition is not permitted."""
    allowed = VALID_FRAMEWORK_TRANSITIONS.get(from_status, frozenset())
    if to_status not in allowed:
        raise ValueError(
            f"Invalid framework lifecycle transition: {from_status!r} → {to_status!r}. "
            f"Allowed: {sorted(s.value for s in allowed) or 'none (terminal state)'}"
        )


def validate_assessment_transition(
    from_status: AssessmentStatus, to_status: AssessmentStatus
) -> None:
    """Raise ValueError if the assessment lifecycle transition is not permitted."""
    allowed = VALID_ASSESSMENT_TRANSITIONS.get(from_status, frozenset())
    if to_status not in allowed:
        raise ValueError(
            f"Invalid assessment lifecycle transition: {from_status!r} → {to_status!r}. "
            f"Allowed: {sorted(s.value for s in allowed) or 'none (terminal state)'}"
        )


def assert_assessment_mutable(assessment: "Assessment") -> None:
    """Raise ValueError if the assessment is in an immutable (finalized/archived) state."""
    if assessment.assessment_status in IMMUTABLE_ASSESSMENT_STATUSES:
        raise ValueError(
            f"Assessment {assessment.assessment_id!r} is immutable: "
            f"status={assessment.assessment_status.value!r}. "
            "Finalized and archived assessments cannot be modified."
        )


# ---------------------------------------------------------------------------
# Domain dataclasses (export-safe: no secrets, no credentials)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Framework:
    """Immutable snapshot of a readiness framework definition.

    Once activated, framework structure is frozen — controls, domains, and
    maturity tiers cannot be mutated. Parallel framework_version tags allow
    future versioning without altering historical assessments.

    tenant_id=None denotes a platform-level framework (available to all tenants).
    """

    framework_id: str
    framework_name: str
    framework_slug: str
    framework_version: str
    framework_status: FrameworkStatus
    created_by: str
    created_at: datetime
    updated_at: datetime
    tenant_id: Optional[str] = None
    framework_description: Optional[str] = None
    framework_metadata: dict[str, Any] = field(default_factory=dict)
    compatibility_metadata: dict[str, Any] = field(default_factory=dict)
    deprecation_metadata: dict[str, Any] = field(default_factory=dict)
    activated_at: Optional[datetime] = None
    deprecated_at: Optional[datetime] = None
    retired_at: Optional[datetime] = None
    state_version: int = 0


@dataclass(frozen=True)
class FrameworkVersion:
    """Snapshot metadata for a specific framework version tag.

    Enables parallel versions and frozen historical assessment reconstruction.
    Once a version is referenced by a finalized assessment it must not be deleted.
    """

    version_id: str
    framework_id: str
    version_tag: str
    version_status: str
    schema_hash: Optional[str]
    created_by: str
    created_at: datetime
    compatibility_metadata: dict[str, Any] = field(default_factory=dict)
    deprecation_note: Optional[str] = None


@dataclass(frozen=True)
class Domain:
    """Readiness domain within a framework.

    Domains group controls into logical areas of AI readiness assessment.
    Architecture supports future hierarchical domains and weighted domains
    without redesign — domain_parent_id and weight_metadata are extension hooks.
    """

    domain_id: str
    framework_id: str
    domain_name: str
    domain_slug: str
    domain_description: str
    domain_order: int
    created_by: str
    created_at: datetime
    tenant_id: Optional[str] = None
    domain_metadata: dict[str, Any] = field(default_factory=dict)
    maturity_applicability: dict[str, Any] = field(default_factory=dict)
    domain_parent_id: Optional[str] = None


@dataclass(frozen=True)
class Control:
    """Readiness control within a domain.

    Controls are framework-version aware and remain immutable once the
    parent framework is activated. Evidence requirements and maturity mapping
    metadata are declarative contracts — scoring logic is deferred.

    Architecture supports future: weighted scoring, evidence automation,
    dependency graphs, regulatory overlays — without schema redesign.
    """

    control_id: str
    framework_id: str
    domain_id: str
    control_identifier: str
    control_name: str
    control_description: str
    created_by: str
    created_at: datetime
    tenant_id: Optional[str] = None
    control_metadata: dict[str, Any] = field(default_factory=dict)
    applicability_metadata: dict[str, Any] = field(default_factory=dict)
    evidence_requirements: dict[str, Any] = field(default_factory=dict)
    maturity_mapping_metadata: dict[str, Any] = field(default_factory=dict)
    scoring_compatibility_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ControlReference:
    """Cross-framework control mapping contract.

    Enables future cross-framework translation and regulatory overlay mappings
    (e.g. NIST AI RMF → ISO/IEC AI governance) without schema redesign.
    """

    reference_id: str
    source_control_id: str
    source_framework_id: str
    target_control_id: str
    target_framework_id: str
    mapping_type: str
    created_by: str
    created_at: datetime
    mapping_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MaturityTier:
    """Maturity tier definition within a framework.

    Tiers are ordered by tier_order (ascending = lower maturity).
    Architecture supports non-linear progression, weighted maturity models,
    and framework-specific maturity semantics without redesign.
    """

    tier_id: str
    framework_id: str
    tier_identifier: str
    tier_name: str
    tier_order: int
    tier_criteria: str
    created_by: str
    created_at: datetime
    tenant_id: Optional[str] = None
    tier_metadata: dict[str, Any] = field(default_factory=dict)
    readiness_classification: Optional[str] = None


@dataclass(frozen=True)
class Assessment:
    """Snapshot of a tenant's readiness assessment against a framework.

    Assessments are tenant-scoped. Once finalized, the assessment becomes
    immutable — framework structure, controls, evidence references, and
    scoring contracts must not mutate retroactively.

    snapshot_version pins the assessment to a specific framework state for
    deterministic reconstruction even after framework evolution.

    state_version: optimistic-lock counter; incremented on every status change.
    """

    assessment_id: str
    tenant_id: str
    framework_id: str
    framework_version_tag: str
    assessment_status: AssessmentStatus
    snapshot_version: int
    created_by: str
    created_at: datetime
    updated_at: datetime
    assessment_name: Optional[str] = None
    assessment_description: Optional[str] = None
    assessment_metadata: dict[str, Any] = field(default_factory=dict)
    actor_metadata: dict[str, Any] = field(default_factory=dict)
    scoring_contract_id: Optional[str] = None
    activated_at: Optional[datetime] = None
    finalized_at: Optional[datetime] = None
    archived_at: Optional[datetime] = None
    state_version: int = 0


@dataclass(frozen=True)
class AssessmentResult:
    """Per-control result record within an assessment.

    Results are append-only within a non-finalized assessment.
    Once the assessment is finalized, result records are frozen.

    Scoring metadata is a contract field — no score calculation logic here.
    """

    result_id: str
    assessment_id: str
    control_id: str
    maturity_tier_id: Optional[str]
    outcome: AssessmentOutcome
    actor: str
    timestamp: datetime
    tenant_id: str
    evaluation_metadata: dict[str, Any] = field(default_factory=dict)
    scoring_metadata: dict[str, Any] = field(default_factory=dict)
    evidence_reference_ids: list[str] = field(default_factory=list)
    notes: Optional[str] = None


@dataclass(frozen=True)
class EvidenceReference:
    """Evidence reference contract for an assessment.

    This is a contract/schema object only — no evidence ingestion,
    extraction, or automation is implemented here.

    evidence_integrity contains hash/checksum metadata for future
    tamper-evidence verification. Evidence classification supports
    future regulatory export requirements.
    """

    evidence_id: str
    assessment_id: str
    evidence_type: EvidenceType
    evidence_title: str
    submitted_by: str
    submitted_at: datetime
    tenant_id: str
    evidence_source_metadata: dict[str, Any] = field(default_factory=dict)
    evidence_ownership_metadata: dict[str, Any] = field(default_factory=dict)
    evidence_integrity_metadata: dict[str, Any] = field(default_factory=dict)
    evidence_classification: Optional[str] = None
    effective_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    control_ids: list[str] = field(default_factory=list)
    notes: Optional[str] = None


@dataclass(frozen=True)
class ScoringContract:
    """Scoring schema contract for a framework.

    Declares the scoring architecture without implementing score calculation.
    Scoring engines (future) must validate against this contract before
    computing scores. This ensures forward compatibility and prevents
    hidden scoring logic coupling.

    No weighting calculations, normalization engines, or reporting logic here.
    """

    contract_id: str
    framework_id: str
    scoring_schema_version: str
    created_by: str
    created_at: datetime
    tenant_id: Optional[str] = None
    normalization_metadata: dict[str, Any] = field(default_factory=dict)
    weighting_metadata: dict[str, Any] = field(default_factory=dict)
    compatibility_metadata: dict[str, Any] = field(default_factory=dict)
    scoring_metadata: dict[str, Any] = field(default_factory=dict)
    is_active: bool = True


@dataclass(frozen=True)
class ReadinessAuditEvent:
    """Append-only audit record for a readiness lifecycle event.

    Every state change and readiness action MUST produce a ReadinessAuditEvent.
    Records are never updated or deleted.

    event_hash: SHA-256 of canonical event fields for tamper-evidence.
    previous_event_hash: hash of the prior event for this resource,
    forming a tamper-evident chain.
    """

    event_id: str
    resource_type: str
    resource_id: str
    event_type: ReadinessEventType
    actor: str
    outcome: str
    timestamp: datetime
    tenant_id: Optional[str] = None
    framework_id: Optional[str] = None
    assessment_id: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)
    event_hash: Optional[str] = None
    previous_event_hash: Optional[str] = None
