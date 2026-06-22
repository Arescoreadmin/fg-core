"""Enterprise Gap Analysis & Remediation Prioritization Engine — models.

All types in this module are:
  - Pure Python. No I/O. No randomness.
  - Frozen after construction (immutable).
  - Deterministic: identical gap state → identical canonical form.
  - Tenant-safe: tenant-scoped gaps are isolated from other tenants.
  - Export-safe: no secrets, credentials, raw evidence bodies, provider payloads.
  - Additive: new gap classifications integrate through explicit model contracts only.

Framework isolation contract:
  - All gaps are scoped to (framework_id, framework_version). Bare framework_id
    lookups are prohibited; analysis is always version-pinned.

Tenant isolation contract:
  - PLATFORM-scope analysis has tenant_id=None.
  - TENANT-scope analysis has a non-None tenant_id.
  - All detection and prioritization functions respect tenant_id scoping.

Immutability contract:
  - GapAnalysisResult is immutable after generation.
  - Corrections create new records; prior records are never mutated.
  - GovernanceOverride does NOT mutate original calculated outputs.
  - CompensatingControl does NOT suppress original gap lineage.
  - Residual governance risk remains reconstructable even when a compensating
    control is present.

Deterministic ordering contract:
  - All gap ordering uses explicit sort keys with stable tie-breakers.
  - Ordering NEVER depends on insertion order, hash randomization, or
    nondeterministic iteration.
  - Tie-breaking always terminates at gap_id (stable string comparison).

Replay contract:
  - GapReplayContract carries all version pins for forensic replay.
  - RemediationIntegrityRecord carries SHA-256 of stable result fields.
  - Historical gap-analysis outputs remain reconstructable after framework evolution.
  - inputs_canonical on RemediationIntegrityRecord is preserved for replay without
    rerunning gap detection.

Metadata field immutability contract:
  - All *_metadata dict fields are wrapped in MappingProxyType on construction.
  - A defensive copy is taken of the caller's dict at construction time.
  - Callers cannot mutate stored metadata content after construction.

Hash exclusion contract:
  - Excluded from gap analysis hash: analyzed_at, tenant_id, result_metadata,
    and all governance_override / policy_exception extension dicts.
  - Stable hash inputs: result_id, framework_id, framework_version, assessment_id,
    gap_ids, blocker_ids, chain_ids, analysis_version, version pins.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from types import MappingProxyType
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class GapSeverity(str, Enum):
    """Risk severity classification for a readiness gap.

    INFORMATIONAL: Noted; no immediate action required.
    LOW:           Minor deficiency; addressable in routine maintenance.
    MODERATE:      Significant deficiency; plan for remediation.
    HIGH:          Major deficiency; remediation required before readiness milestone.
    CRITICAL:      Severe deficiency; blocks readiness classification.
    BLOCKING:      Absolute blocker; no readiness or maturity eligibility until resolved.
    """

    INFORMATIONAL = "informational"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"
    BLOCKING = "blocking"


class GapClassification(str, Enum):
    """Classification of the specific type of readiness gap.

    Future extensions append new values; existing values are stable and never
    change meaning once published.
    """

    MISSING_CONTROL = "missing_control"
    PARTIALLY_IMPLEMENTED = "partially_implemented"
    WEAK_CONTROL = "weak_control"
    FAILED_CONTROL = "failed_control"
    STALE_EVIDENCE = "stale_evidence"
    INCOMPLETE_ASSESSMENT = "incomplete_assessment"
    MISSING_REQUIRED_EVIDENCE = "missing_required_evidence"
    FAILED_MATURITY_GATE = "failed_maturity_gate"
    FAILED_READINESS_THRESHOLD = "failed_readiness_threshold"
    MISSING_FRAMEWORK_MAPPING = "missing_framework_mapping"
    UNSUPPORTED_GOVERNANCE_COVERAGE = "unsupported_governance_coverage"
    MISSING_DEPENDENCY_CHAIN = "missing_dependency_chain"
    FAILED_PREREQUISITE_CONTROL = "failed_prerequisite_control"
    UNSUPPORTED_OPERATIONAL_GOVERNANCE = "unsupported_operational_governance"
    UNSUPPORTED_RUNTIME_GOVERNANCE = "unsupported_runtime_governance"
    UNSUPPORTED_PROVENANCE_ENFORCEMENT = "unsupported_provenance_enforcement"


class GapDependencyType(str, Enum):
    """Semantic type of a dependency relationship between two gaps.

    PREREQUISITE:        The prerequisite gap MUST be resolved before the dependent gap.
    INHERITED:           The dependent gap inherits from the prerequisite gap's context.
    FRAMEWORK_REQUIRED:  The prerequisite gap is required by the framework contract.
    """

    PREREQUISITE = "prerequisite"
    INHERITED = "inherited"
    FRAMEWORK_REQUIRED = "framework_required"


class ExceptionType(str, Enum):
    """Type of policy exception applied to a gap.

    Architecture supports future: regulatory_overlay, sovereign_exemption.
    """

    APPROVED_EXCEPTION = "approved_exception"
    TEMPORARY_WAIVER = "temporary_waiver"
    COMPENSATING_CONTROL = "compensating_control"
    JURISDICTIONAL = "jurisdictional"
    CONTRACTUAL = "contractual"
    REGULATORY = "regulatory"


class OverrideType(str, Enum):
    """Type of governed override applied to a gap analysis output.

    Overrides do NOT mutate original calculated values — they carry the
    override alongside the original for audit reconstruction.
    """

    SEVERITY = "severity"
    REMEDIATION_PRIORITY = "remediation_priority"
    BLOCKER_CLASSIFICATION = "blocker_classification"
    MATURITY_IMPACT = "maturity_impact"
    READINESS_IMPACT = "readiness_impact"


# ---------------------------------------------------------------------------
# Core gap model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReadinessGap:
    """A single detected readiness, compliance, or governance gap.

    gap_severity: risk classification (may be overridden via GovernanceOverride).
    gap_classification: specific gap type.
    gap_rationale: non-empty human-readable justification for detection.
    is_blocker: True if this gap blocks readiness classification.
    is_maturity_blocker: True if this gap blocks a maturity tier transition.
    affected_control_ids: controls affected by or causing this gap.
    affected_framework_ids: frameworks whose requirements surface this gap.
    evidence_ids: evidence records contributing to this gap detection.
    gap_metadata: extension hook for future remediation planning metadata.
    """

    gap_id: str
    gap_classification: GapClassification
    gap_severity: GapSeverity
    framework_id: str
    framework_version: str
    gap_rationale: str
    detected_at: datetime
    is_blocker: bool
    is_maturity_blocker: bool
    affected_control_ids: tuple[str, ...]
    affected_framework_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    control_id: Optional[str] = None
    domain_id: Optional[str] = None
    tenant_id: Optional[str] = None
    gap_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        meta = self.gap_metadata
        object.__setattr__(
            self,
            "gap_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )


# ---------------------------------------------------------------------------
# Evidence freshness
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceFreshnessRecord:
    """Deterministic staleness state for a single evidence reference.

    freshness_window_days: the window within which evidence is considered fresh.
    is_stale: True if (evaluated_at - submitted_at).days > freshness_window_days.
    staleness_days: how many days past the freshness window (None if not stale).
    evaluated_at: the datetime at which freshness was evaluated (analysis time).
    """

    freshness_id: str
    evidence_id: str
    control_id: Optional[str]
    framework_id: str
    framework_version: str
    submitted_at: datetime
    freshness_window_days: int
    is_stale: bool
    staleness_days: Optional[int]
    evaluated_at: datetime
    tenant_id: Optional[str] = None
    freshness_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        meta = self.freshness_metadata
        object.__setattr__(
            self,
            "freshness_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )


# ---------------------------------------------------------------------------
# Dependency chain
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GapDependency:
    """A single directed dependency between two gaps.

    dependent_gap_id must be resolved AFTER prerequisite_gap_id.
    dependency_type declares the semantic meaning of the dependency.
    """

    dependency_id: str
    dependent_gap_id: str
    prerequisite_gap_id: str
    dependency_type: GapDependencyType
    dependency_rationale: str
    dependency_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        meta = self.dependency_metadata
        object.__setattr__(
            self,
            "dependency_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )


@dataclass(frozen=True)
class DependencyChain:
    """An ordered sequence of gap IDs forming a remediation dependency chain.

    ordered_gap_ids: gaps ordered from first-to-resolve to last.
    has_cycle: True if the dependency subgraph contains a cycle.
    cycle_gap_ids: gap IDs participating in the detected cycle.

    A chain with has_cycle=True is a deadlock — no valid resolution order exists
    until the cycle is broken by governance intervention.
    """

    chain_id: str
    ordered_gap_ids: tuple[str, ...]
    has_cycle: bool
    cycle_gap_ids: tuple[str, ...]
    chain_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        meta = self.chain_metadata
        object.__setattr__(
            self,
            "chain_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )


# ---------------------------------------------------------------------------
# Blockers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReadinessBlocker:
    """A gap that blocks tenant readiness classification.

    severity: may reflect a GovernanceOverride if one applies to the source gap.
    blocker_rationale: non-empty explanation of why this blocks readiness.
    """

    blocker_id: str
    gap_id: str
    blocker_rationale: str
    severity: GapSeverity
    affected_framework_ids: tuple[str, ...]
    affected_control_ids: tuple[str, ...]
    tenant_id: Optional[str] = None
    blocker_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        meta = self.blocker_metadata
        object.__setattr__(
            self,
            "blocker_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )


@dataclass(frozen=True)
class MaturityBlocker:
    """A gap that blocks a specific maturity tier transition.

    maturity_tier_id: the tier that cannot be achieved until this gap is resolved.
    """

    blocker_id: str
    gap_id: str
    maturity_tier_id: str
    blocker_rationale: str
    affected_control_ids: tuple[str, ...]
    tenant_id: Optional[str] = None
    blocker_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        meta = self.blocker_metadata
        object.__setattr__(
            self,
            "blocker_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )


# ---------------------------------------------------------------------------
# Impact estimation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReadinessImpactEstimate:
    """Deterministic readiness impact estimate for a single gap.

    All impact values are in [0.0, 1.0] and represent estimated fractional
    improvement if the gap were resolved.

    maturity_impact: estimated improvement in maturity tier eligibility.
    framework_impact: estimated improvement in overall framework compliance score.
    remediation_impact: composite estimated remediation value (0.0–1.0).
    governance_coverage_impact: estimated improvement in governance coverage.
    domain_impact: per-domain_id estimated improvement.
    estimation_rationale: non-empty explanation of how the estimate was derived.
    """

    estimate_id: str
    gap_id: str
    maturity_impact: float
    framework_impact: float
    remediation_impact: float
    governance_coverage_impact: float
    domain_impact: Mapping[str, float]
    estimation_rationale: str
    estimate_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        di = self.domain_impact
        object.__setattr__(
            self,
            "domain_impact",
            MappingProxyType(dict(di) if di is not None else {}),
        )
        meta = self.estimate_metadata
        object.__setattr__(
            self,
            "estimate_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )


# ---------------------------------------------------------------------------
# Remediation recommendation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RemediationRecommendation:
    """Structured deterministic remediation metadata for a gap.

    This is NOT a narrative AI recommendation. It is structured governance
    metadata describing what must be addressed and why.

    remediation_classification: the category of remediation required
        ("address_missing_control" | "refresh_evidence" | "improve_control_score" |
         "resolve_maturity_gate" | "resolve_threshold_failure" | "break_dependency_cycle").
    remediation_rationale: non-empty structured rationale.
    dependency_ids: GapDependency IDs that must be resolved first.
    blocker_ids: ReadinessBlocker or MaturityBlocker IDs linked to this gap.
    compensating_control_ids: CompensatingControl IDs linked to this gap.
    """

    recommendation_id: str
    gap_id: str
    remediation_classification: str
    remediation_rationale: str
    affected_control_ids: tuple[str, ...]
    affected_domain_ids: tuple[str, ...]
    affected_framework_ids: tuple[str, ...]
    estimated_readiness_impact: float
    maturity_implications: str
    governance_rationale: str
    dependency_ids: tuple[str, ...]
    blocker_ids: tuple[str, ...]
    compensating_control_ids: tuple[str, ...]
    recommendation_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        meta = self.recommendation_metadata
        object.__setattr__(
            self,
            "recommendation_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )


# ---------------------------------------------------------------------------
# Policy exception, compensating controls, overrides
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyException:
    """Deterministic policy exception record for a gap.

    Exceptions do NOT suppress gap lineage — the gap remains visible in the
    analysis output alongside the exception record.

    exception_authority: organization or role that approved the exception.
    approval_rationale: non-empty structured rationale.
    expires_at: None means the exception does not expire.
    """

    exception_id: str
    exception_type: ExceptionType
    exception_authority: str
    approval_rationale: str
    affected_control_ids: tuple[str, ...]
    affected_framework_ids: tuple[str, ...]
    approved_at: datetime
    tenant_id: Optional[str] = None
    provenance_id: Optional[str] = None
    expires_at: Optional[datetime] = None
    exception_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        meta = self.exception_metadata
        object.__setattr__(
            self,
            "exception_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )


@dataclass(frozen=True)
class CompensatingControl:
    """Deterministic compensating control record for a gap.

    A compensating control mitigates but does NOT fully suppress a gap.
    The original gap remains in the analysis output — residual risk is
    always reconstructable.

    residual_risk_metadata: describes the remaining governance risk after
        the compensating control is applied.
    """

    compensating_id: str
    gap_id: str
    mitigation_rationale: str
    framework_applicability: tuple[str, ...]
    approved_by: str
    approved_at: datetime
    residual_risk_metadata: Mapping[str, Any] = None  # type: ignore[assignment]
    governance_approval_metadata: Mapping[str, Any] = None  # type: ignore[assignment]
    tenant_id: Optional[str] = None
    compensating_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        for field_name in (
            "residual_risk_metadata",
            "governance_approval_metadata",
            "compensating_metadata",
        ):
            val = getattr(self, field_name)
            object.__setattr__(
                self,
                field_name,
                MappingProxyType(dict(val) if val is not None else {}),
            )


@dataclass(frozen=True)
class GovernanceOverride:
    """Deterministic governed override for a gap analysis output field.

    Overrides do NOT mutate the original calculated output. The original
    value is preserved alongside the overridden value for audit reconstruction.

    override_type: which field was overridden (see OverrideType).
    original_value: the value before override (string serialization).
    overridden_value: the value after override (string serialization).
    override_authority: the role or organization that authorized the override.
    """

    override_id: str
    gap_id: str
    override_type: OverrideType
    original_value: str
    overridden_value: str
    override_authority: str
    override_rationale: str
    approved_at: datetime
    tenant_id: Optional[str] = None
    replay_metadata: Mapping[str, Any] = None  # type: ignore[assignment]
    override_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        for field_name in ("replay_metadata", "override_metadata"):
            val = getattr(self, field_name)
            object.__setattr__(
                self,
                field_name,
                MappingProxyType(dict(val) if val is not None else {}),
            )


# ---------------------------------------------------------------------------
# Integrity record and replay contract
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RemediationIntegrityRecord:
    """Deterministic SHA-256 integrity record for a GapAnalysisResult.

    result_id: ID of the GapAnalysisResult this record covers.
    algorithm: hash algorithm (always "sha256" for current records).
    hash_value: hex-encoded SHA-256 digest of inputs_canonical.
    inputs_canonical: exact JSON string hashed — preserved for forensic replay.
    computed_at: timestamp when the hash was computed.
    is_replay_safe: True if inputs_canonical is complete for independent replay.
    """

    record_id: str
    result_id: str
    algorithm: str
    hash_value: str
    inputs_canonical: str
    computed_at: datetime
    is_replay_safe: bool


@dataclass(frozen=True)
class GapReplayContract:
    """Version pins required to reproduce a historical gap-analysis result.

    All version fields correspond to the state at analysis time. Any field
    that was not pinned at analysis time is None.
    """

    contract_id: str
    result_id: str
    framework_version: str
    analysis_version: str
    scoring_contract_version: Optional[str]
    maturity_model_version: Optional[str]
    mapping_version: Optional[str]
    evidence_snapshot_version: Optional[str]
    replay_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        meta = self.replay_metadata
        object.__setattr__(
            self,
            "replay_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )


# ---------------------------------------------------------------------------
# Full analysis result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GapAnalysisResult:
    """Immutable, versioned output of a full gap analysis run.

    Produced by GapAnalysisEngine.analyze(). Never mutated after construction.
    All fields are export-safe — no secrets, raw evidence bodies, provider
    payloads, or internal topology.

    gaps: all detected gaps, ordered by deterministic priority (severity DESC,
        classification rank DESC, gap_id ASC).
    readiness_blockers: subset of gaps that block readiness classification.
    maturity_blockers: subset of gaps that block maturity tier transitions.
    dependency_chains: ordered remediation dependency chains.
    remediation_recommendations: per-gap structured remediation metadata.
    impact_estimates: per-gap readiness impact estimates.
    policy_exceptions: active policy exceptions at analysis time.
    compensating_controls: active compensating controls at analysis time.
    governance_overrides: active governed overrides at analysis time.
    evidence_freshness_records: freshness evaluation for all evidence refs.
    replay_contract: version pins for forensic replay.
    result_metadata: extension hook for future export/attestation metadata.
    """

    result_id: str
    framework_id: str
    framework_version: str
    analysis_version: str
    analyzed_at: datetime
    gaps: tuple[ReadinessGap, ...]
    readiness_blockers: tuple[ReadinessBlocker, ...]
    maturity_blockers: tuple[MaturityBlocker, ...]
    dependency_chains: tuple[DependencyChain, ...]
    remediation_recommendations: tuple[RemediationRecommendation, ...]
    impact_estimates: tuple[ReadinessImpactEstimate, ...]
    policy_exceptions: tuple[PolicyException, ...]
    compensating_controls: tuple[CompensatingControl, ...]
    governance_overrides: tuple[GovernanceOverride, ...]
    evidence_freshness_records: tuple[EvidenceFreshnessRecord, ...]
    replay_contract: GapReplayContract
    assessment_id: Optional[str] = None
    tenant_id: Optional[str] = None
    scoring_contract_version: Optional[str] = None
    maturity_model_version: Optional[str] = None
    mapping_version: Optional[str] = None
    evidence_snapshot_version: Optional[str] = None
    result_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        meta = self.result_metadata
        object.__setattr__(
            self,
            "result_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )
