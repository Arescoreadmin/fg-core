"""Enterprise Continuous Readiness Monitoring — domain models.

All types are:
  - Pure Python. No I/O. No randomness. No SQLAlchemy.
  - Frozen after construction (immutable).
  - Deterministic: identical governance state → identical canonical form.
  - Tenant-safe: all evaluation contexts carry tenant_id.
  - Export-safe: no secrets, vectors, raw evidence bodies, provider payloads,
    prompts, PHI, or internal topology.
  - Additive: new drift types integrate through DriftType enum extension only.

Uncertainty contract:
  - Monitoring failures MUST NOT collapse into "healthy" state.
  - Unverifiable, incomplete, and unknown states remain explicit via DriftCertainty.
  - CONFIRMED drift requires observable governance state evidence.
  - SUSPECTED drift has partial evidence; certainty is flagged explicitly.

Replay contract:
  - DriftSnapshot carries monitoring_contract_version, evaluation_engine_version,
    drift_classification_version, severity_classification_version.
  - Historical snapshots remain reconstructable against the version that produced them.
  - replay_contract_metadata carries all version pins for forensic replay.

Severity contract:
  - Severity is deterministic given input state.
  - BLOCKING implies readiness gating — no readiness milestone achievable until resolved.
  - CRITICAL requires immediate operator attention.
  - Do NOT silently downgrade CRITICAL/BLOCKING events.

Deduplication contract:
  - Each DriftEvent carries an event_fingerprint derived deterministically from
    drift_type, affected_scope, run_id, and sorted affected_control_ids.
  - Duplicate fingerprints within a single run → highest-severity wins.
  - Deduplication is explainable: the fingerprint encodes what was collapsed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class DriftSeverity(str, Enum):
    """Deterministic severity classification for a readiness drift event.

    INFORMATIONAL: Noted; no immediate action required.
    LOW:           Minor degradation; addressable in routine maintenance.
    MODERATE:      Significant degradation; plan for remediation.
    HIGH:          Major degradation; remediation required before readiness milestone.
    CRITICAL:      Severe degradation; blocks readiness classification.
    BLOCKING:      Absolute blocker; no readiness or maturity eligibility until resolved.
    """

    INFORMATIONAL = "informational"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"
    BLOCKING = "blocking"


# Ordering for severity comparison (higher index = higher severity).
_SEVERITY_ORDER: dict[DriftSeverity, int] = {
    DriftSeverity.INFORMATIONAL: 0,
    DriftSeverity.LOW: 1,
    DriftSeverity.MODERATE: 2,
    DriftSeverity.HIGH: 3,
    DriftSeverity.CRITICAL: 4,
    DriftSeverity.BLOCKING: 5,
}


def severity_rank(s: DriftSeverity) -> int:
    return _SEVERITY_ORDER[s]


class DriftType(str, Enum):
    """Deterministic classification of detected readiness drift."""

    POLICY_DRIFT = "policy_drift"
    PROVENANCE_ENFORCEMENT_DISABLED = "provenance_enforcement_disabled"
    PROVENANCE_DEGRADATION = "provenance_degradation"
    PROVIDER_GOVERNANCE_CHANGE = "provider_governance_change"
    PROVIDER_BLOCKED = "provider_blocked"
    RETRIEVAL_DEGRADATION = "retrieval_degradation"
    RETRIEVAL_POLICY_MISMATCH = "retrieval_policy_mismatch"
    STALE_EVIDENCE = "stale_evidence"
    MISSING_EVIDENCE = "missing_evidence"
    INVALID_EVIDENCE_INTEGRITY = "invalid_evidence_integrity"
    INVALID_EVIDENCE_LINKAGE = "invalid_evidence_linkage"
    AUDIT_INTEGRITY_FAILURE = "audit_integrity_failure"
    AUDIT_CHAIN_BROKEN = "audit_chain_broken"
    READINESS_REGRESSION = "readiness_regression"
    FRAMEWORK_COMPLIANCE_DEGRADATION = "framework_compliance_degradation"
    MISSING_REQUIRED_CONTROL = "missing_required_control"
    RUNTIME_GOVERNANCE_DEGRADATION = "runtime_governance_degradation"
    GROUNDED_ANSWER_ENFORCEMENT_FAILED = "grounded_answer_enforcement_failed"
    REPLAY_INTEGRITY_DEGRADATION = "replay_integrity_degradation"
    MONITORING_VISIBILITY_DEGRADATION = "monitoring_visibility_degradation"


class DriftCertainty(str, Enum):
    """Explicit certainty classification for a drift event.

    Never collapses unverifiable/unknown/incomplete into CONFIRMED.
    Unknown governance states remain explicitly unknown — not healthy.
    """

    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    UNVERIFIABLE = "unverifiable"
    INCOMPLETE_EVALUATION = "incomplete_evaluation"
    DEGRADED_VISIBILITY = "degraded_visibility"
    MONITORING_SOURCE_FAILURE = "monitoring_source_failure"
    STALE_MONITORING_STATE = "stale_monitoring_state"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Evaluation context — temporal boundaries
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MonitoringEvaluationContext:
    """Temporal and versioning boundaries for a monitoring evaluation.

    All temporal boundaries are ISO 8601 strings to avoid TZ ambiguity.
    All version fields are required for replay reconstruction.

    assessment_id is required for replay fidelity: the snapshot must carry the
    evaluation scope even when evaluator inputs are empty (e.g. an assessment
    with no controls yet). Without it the embedded snapshot_json loses scope.
    """

    tenant_id: str
    evaluation_window_start_iso: str
    evaluation_window_end_iso: str
    evidence_freshness_window_days: int
    retrieval_degradation_window_hours: int
    policy_drift_comparison_window_hours: int
    audit_continuity_window_hours: int
    runtime_governance_window_hours: int
    monitoring_contract_version: str
    evaluation_engine_version: str
    drift_classification_version: str
    severity_classification_version: str
    assessment_id: Optional[str] = None
    # sovereignty_seam: residency_region: Optional[str] = None  — for residency-aware
    # monitoring, prohibited-region detection, and export boundary governance (EU, govcon).
    # Add as a typed field when sovereign deployment policy enforcement is introduced.
    # region_enforcement_seam: sovereign AI governance, EU residency enforcement, gov-region
    # routing governance, and export boundary detection extend from residency_region. The
    # evaluator layer gains a ProhibitedRegionEvaluator that emits BLOCKING drift events when
    # provider routing or data residency violates the tenant's declared sovereignty policy.
    # This becomes commercially critical for EU enterprise deployments and govcon contracts.


# ---------------------------------------------------------------------------
# Evaluator input types — export-safe governance metadata only
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyDriftInput:
    """Export-safe governance metadata for a single policy."""

    policy_id: str
    policy_name: str
    policy_enabled: bool
    enforcement_mode: str  # "strict" | "permissive" | "disabled" | "unknown"
    policy_state: str  # "active" | "suspended" | "rolled_back" | "unknown"
    policy_hash: str
    policy_version: str
    previous_policy_hash: Optional[str]  # None = no baseline available
    source: str  # monitoring source identifier


@dataclass(frozen=True)
class ProvenanceEnforcementInput:
    """Export-safe provenance enforcement governance state."""

    provenance_validation_enabled: bool
    citation_enforcement_enabled: bool
    grounded_answer_enforcement_enabled: bool
    provenance_trust_status: str  # "valid" | "invalid" | "degraded" | "unknown"
    invalid_provenance_count: int
    total_provenance_checked: int


@dataclass(frozen=True)
class ProviderGovernanceInput:
    """Export-safe provider governance state — no credentials, tokens, or payloads."""

    provider_id: str
    provider_name: str
    provider_status: str  # "allowed" | "blocked" | "restricted" | "unknown"
    governance_classification: str
    routing_governance_state: str
    compliance_classification: str
    region: Optional[str]


@dataclass(frozen=True)
class RetrievalDegradationInput:
    """Export-safe retrieval governance state — no embeddings, vectors, or prompts."""

    retrieval_policy_id: str
    retrieval_policy_enabled: bool
    reranker_governance_state: str  # "active" | "degraded" | "disabled" | "unknown"
    grounded_answer_failure_count: int
    provenance_validation_failure_count: int
    total_retrievals: int


@dataclass(frozen=True)
class EvidenceFreshnessInput:
    """Export-safe evidence freshness metadata for a single evidence reference."""

    evidence_id: str
    evidence_title: str
    evidence_type: str
    submitted_at_iso: str
    control_ids: tuple[str, ...]
    integrity_verified: Optional[bool]
    validation_status: str  # "valid" | "invalid" | "missing" | "stale" | "unknown"
    staleness_days: Optional[float]  # None = not computed; computed by caller


@dataclass(frozen=True)
class AuditIntegrityInput:
    """Export-safe audit chain governance state."""

    audit_chain_status: str  # "ok" | "broken" | "unknown"
    total_records: int
    failed_records: int
    current_invariant_status: str
    drift_status: str
    policy_hash: Optional[str]
    config_hash: Optional[str]


@dataclass(frozen=True)
class ReadinessRegressionInput:
    """Baseline vs. current readiness scores for regression detection."""

    assessment_id: str
    framework_id: str
    current_completion_percentage: float
    baseline_completion_percentage: Optional[float]  # None = no baseline
    current_failed_controls: int
    baseline_failed_controls: Optional[int]  # None = no baseline
    regression_threshold: float  # 0.05 = 5-percentage-point drop triggers detection


@dataclass(frozen=True)
class RuntimeGovernanceInput:
    """Export-safe runtime governance state — no raw telemetry payloads."""

    enforcement_mode: str  # "strict" | "permissive" | "disabled" | "unknown"
    governance_signal_count: int
    failed_governance_signals: int
    last_signal_timestamp_iso: Optional[str]


@dataclass(frozen=True)
class FrameworkComplianceInput:
    """Export-safe framework compliance metadata for an assessment."""

    framework_id: str
    framework_version_tag: str
    framework_status: str
    assessment_id: str
    total_controls: int
    evaluated_controls: int
    failed_controls: int
    not_evaluated_controls: int
    missing_required_control_ids: tuple[str, ...]
    invalid_evidence_linkage_ids: tuple[str, ...]
    assessment_completion_percentage: float


# ---------------------------------------------------------------------------
# Engine input — aggregates all evaluator inputs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MonitoringEngineInput:
    """Aggregated input for the monitoring engine.

    Empty tuples mean the corresponding monitoring domain was not evaluated.
    No evaluator input means no events are emitted for that domain.
    This is honest about monitoring coverage — not silently healthy.
    """

    context: MonitoringEvaluationContext
    policy_inputs: tuple[PolicyDriftInput, ...]
    provenance_inputs: tuple[ProvenanceEnforcementInput, ...]
    provider_inputs: tuple[ProviderGovernanceInput, ...]
    retrieval_inputs: tuple[RetrievalDegradationInput, ...]
    evidence_inputs: tuple[EvidenceFreshnessInput, ...]
    audit_inputs: tuple[AuditIntegrityInput, ...]
    regression_input: Optional[ReadinessRegressionInput]
    runtime_inputs: tuple[RuntimeGovernanceInput, ...]
    framework_inputs: tuple[FrameworkComplianceInput, ...]


# ---------------------------------------------------------------------------
# Drift event — immutable output of a single evaluator
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DriftEvent:
    """Immutable, audit-safe drift event.

    event_fingerprint is deterministic: identical drift_type + affected_scope +
    run_id + sorted(affected_control_ids) → identical fingerprint. Used for
    deduplication within a single monitoring run.

    No prompts, vectors, embeddings, provider payloads, secrets, PHI, or
    raw evidence bodies appear in any field.
    """

    event_fingerprint: str
    drift_type: DriftType
    severity: DriftSeverity
    certainty: DriftCertainty
    affected_scope: str
    affected_control_ids: tuple[str, ...]
    affected_evidence_ids: tuple[str, ...]
    affected_framework_ids: tuple[str, ...]
    drift_detail: str  # export-safe human-readable summary
    monitoring_source: str
    evaluation_timestamp_iso: str
    temporal_boundary_start: str
    temporal_boundary_end: str
    provenance_metadata: tuple[tuple[str, str], ...]  # export-safe key-value pairs


# ---------------------------------------------------------------------------
# Drift snapshot — immutable evaluation result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DriftSnapshot:
    """Immutable, replay-safe drift snapshot.

    All fields required for forensic replay. Version pins ensure historical
    snapshots remain reconstructable against the evaluation contract that
    produced them.

    domains_evaluated lists which monitoring domains were included in this
    evaluation (empty domain = not evaluated, not assumed healthy).
    """

    snapshot_id: str
    monitoring_run_id: str
    evaluation_timestamp_iso: str
    monitoring_contract_version: str
    evaluation_engine_version: str
    drift_classification_version: str
    severity_classification_version: str
    events: tuple[DriftEvent, ...]
    tenant_id: str
    assessment_id: Optional[str]
    framework_ids: tuple[str, ...]
    eval_window_start_iso: str
    eval_window_end_iso: str
    evidence_freshness_window_days: int
    total_drift_events: int
    critical_or_blocking_count: int
    domains_evaluated: tuple[str, ...]
    replay_contract_metadata: tuple[tuple[str, str], ...]


# ---------------------------------------------------------------------------
# Monitoring result — top-level output
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MonitoringResult:
    """Top-level monitoring run result, including replay metadata."""

    run_id: str
    snapshot: DriftSnapshot
    completed_at_iso: str
    evaluation_success: bool
    error_summary: Optional[str]  # export-safe only; None on success


# ---------------------------------------------------------------------------
# Stored monitoring run record — domain object for persistence layer
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MonitoringRunRecord:
    """Domain object returned by MonitoringRunStore — no SQLAlchemy types."""

    run_id: str
    tenant_id: str
    assessment_id: Optional[str]
    framework_ids: tuple[str, ...]
    eval_window_start_iso: str
    eval_window_end_iso: str
    monitoring_contract_version: str
    evaluation_engine_version: str
    snapshot_id: str
    snapshot_json: str  # export-safe JSON string
    domains_evaluated: tuple[str, ...]
    total_drift_events: int
    critical_or_blocking_count: int
    completed_at_iso: str
    evaluation_success: bool
    error_summary: Optional[str]
    created_at_iso: str
