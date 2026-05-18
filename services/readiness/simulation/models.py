"""Enterprise Governance Simulation — domain models.

All types are:
  - Pure Python. No I/O. No randomness. No SQLAlchemy.
  - Frozen after construction (immutable).
  - Deterministic: identical simulation inputs → identical canonical form.
  - Tenant-safe: all simulation contexts carry tenant_id.
  - Export-safe: no secrets, vectors, raw evidence bodies, provider payloads,
    prompts, PHI, or internal topology.
  - Additive: new scenario types integrate through SimulationScenarioType extension only.

Uncertainty contract:
  - Simulation failures MUST NOT collapse into "safe" or "unchanged" state.
  - Unverifiable, insufficient, and stale evidence states remain explicit.
  - CONFIRMED projections require parseable and verifiable scenario parameters.
  - UNSUPPORTED_BOUNDARY is an honest acknowledgement of the evaluator's limits.

Replay contract:
  - SimulationProjection carries simulation_contract_version, simulation_engine_version,
    and framework_version_tag.
  - Historical projections remain reconstructable against the version that produced them.
  - replay_contract_metadata carries all version pins for forensic replay.

Blast radius contract:
  - Blast radius is always computed even for simple scenarios.
  - BLOCKING blast radius implies no readiness eligibility until resolved.
  - Cascade dependencies are tracked for longitudinal governance.

Capability governance seam:
  - SimulationCapabilityProjection is a seam for future autonomous-systems governance.
  - authority_degradation, escalation_risk_increase, auditability_degradation, and
    bounded_authority_degradation are explicitly tracked.

Longitudinal governance seam:
  - SimulationGovernanceTrajectory is a seam for multi-run drift trend analysis.
  - projected_drift_events and projected_critical_events enable governance forecasting.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class SimulationScenarioType(str, Enum):
    """Classification of the governance change being simulated."""

    PROVIDER_CHANGE = "provider_change"
    POLICY_CHANGE = "policy_change"
    RETRIEVAL_STRATEGY_CHANGE = "retrieval_strategy_change"
    TENANT_POLICY_RELAXATION = "tenant_policy_relaxation"
    FRAMEWORK_UPGRADE = "framework_upgrade"
    GOVERNANCE_ENFORCEMENT_CHANGE = "governance_enforcement_change"
    CAPABILITY_GOVERNANCE_CHANGE = "capability_governance_change"
    OPERATIONAL_GOVERNANCE_CHANGE = "operational_governance_change"


class SimulationSeverity(str, Enum):
    """Deterministic severity for simulation impacts and warnings.

    INFORMATIONAL: Noted; no governance concern.
    LOW:           Minor projected impact; addressable in routine governance.
    MODERATE:      Significant impact; plan for governance adjustment.
    HIGH:          Major impact; remediation required before readiness milestone.
    CRITICAL:      Severe projected degradation; blocks readiness eligibility.
    BLOCKING:      Absolute blocker; no readiness or maturity eligibility.
    """

    INFORMATIONAL = "informational"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"
    BLOCKING = "blocking"


class SimulationUncertainty(str, Enum):
    """Explicit uncertainty classification for simulation outputs.

    Never collapses insufficient/unverifiable states into CONFIRMED.
    Unknown parameter states remain explicitly unknown — not optimistic.
    """

    CONFIRMED = "confirmed"
    PARTIAL_CONFIDENCE = "partial_confidence"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    UNVERIFIABLE = "unverifiable"
    STALE_EVIDENCE = "stale_evidence"
    UNSUPPORTED_BOUNDARY = "unsupported_boundary"
    DEGRADED_VISIBILITY = "degraded_visibility"


class SimulationRiskDirection(str, Enum):
    """Projected risk direction after applying the scenario."""

    IMPROVED = "improved"
    UNCHANGED = "unchanged"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Simulation sub-types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SimulationConstraint:
    """Immutable constraint blocking or limiting a simulation.

    constraint_id is deterministic: derived from simulation context.
    blocks_simulation indicates whether this constraint prevents execution.
    """

    constraint_id: str
    constraint_type: str
    description: str
    severity: SimulationSeverity
    blocks_simulation: bool


@dataclass(frozen=True)
class SimulationWarning:
    """Immutable warning generated during scenario evaluation.

    warning_id is deterministic: derived from simulation_id + warning context.
    uncertainty reflects the evaluator's confidence in the warning.
    """

    warning_id: str
    warning_type: str
    description: str
    severity: SimulationSeverity
    affected_scope: str
    affected_control_ids: tuple[str, ...]
    uncertainty: SimulationUncertainty


@dataclass(frozen=True)
class SimulationInput:
    """Input to the simulation engine for a single scenario evaluation.

    scenario_parameters is a sorted tuple of (key, value) string pairs.
    simulation_contract_version and simulation_engine_version are required
    for replay reconstruction.
    """

    scenario_type: SimulationScenarioType
    scenario_parameters: tuple[tuple[str, str], ...]
    tenant_id: str
    assessment_id: Optional[str]
    framework_id: Optional[str]
    simulation_contract_version: str
    simulation_engine_version: str
    requested_at_iso: str


@dataclass(frozen=True)
class SimulationReadinessProjection:
    """Projected readiness state after applying the scenario.

    baseline and projected completion percentages are [0.0, 1.0].
    delta_pct is projected_completion_pct - baseline_completion_pct.
    """

    baseline_completion_pct: float
    projected_completion_pct: float
    delta_pct: float
    direction: SimulationRiskDirection
    impacted_control_ids: tuple[str, ...]
    newly_failing_control_ids: tuple[str, ...]
    newly_passing_control_ids: tuple[str, ...]
    uncertainty: SimulationUncertainty
    basis: str


@dataclass(frozen=True)
class SimulationRiskProjection:
    """Projected risk state after applying the scenario.

    risk_factors is a tuple of (factor_name, factor_description) pairs.
    """

    baseline_risk_score: float
    projected_risk_score: float
    delta: float
    direction: SimulationRiskDirection
    risk_factors: tuple[tuple[str, str], ...]
    uncertainty: SimulationUncertainty


@dataclass(frozen=True)
class SimulationComplianceProjection:
    """Projected compliance state after applying the scenario.

    baseline and projected framework coverage are [0.0, 1.0].
    maturity_regression and compliance_risk_increase are explicit flags.
    """

    baseline_framework_coverage: float
    projected_framework_coverage: float
    delta: float
    direction: SimulationRiskDirection
    newly_missing_required_controls: tuple[str, ...]
    newly_covered_controls: tuple[str, ...]
    maturity_regression: bool
    compliance_risk_increase: bool
    uncertainty: SimulationUncertainty


@dataclass(frozen=True)
class SimulationImpactRecord:
    """Immutable record of a single projected governance impact.

    impact_id is deterministic: derived from simulation_id + domain + scope.
    """

    impact_id: str
    impact_domain: str
    impact_description: str
    severity: SimulationSeverity
    affected_scope: str
    affected_ids: tuple[str, ...]
    direction: SimulationRiskDirection
    uncertainty: SimulationUncertainty


@dataclass(frozen=True)
class SimulationDiffRecord:
    """Immutable record of a governance state diff projected by the scenario.

    diff_id is deterministic: derived from simulation_id + type + values.
    """

    diff_id: str
    diff_type: str
    before_value: str
    after_value: str
    affected_scope: str
    severity: SimulationSeverity
    direction: SimulationRiskDirection


@dataclass(frozen=True)
class SimulationBlastRadius:
    """Projected blast radius of the scenario across governance domains.

    cascading_risk reflects the highest severity propagated across dependency chains.
    dependency_chains_impacted is the count of distinct affected chains.
    """

    total_affected_controls: int
    total_affected_evidence: int
    total_affected_frameworks: int
    cascading_risk: SimulationSeverity
    dependency_chains_impacted: int
    description: str
    uncertainty: SimulationUncertainty


@dataclass(frozen=True)
class SimulationCapabilityProjection:
    """Projected capability governance state — seam for autonomous-systems governance.

    authority_degradation: capability authority scope is projected to degrade.
    escalation_risk_increase: risk of uncontrolled escalation is projected to increase.
    auditability_degradation: audit trail coverage is projected to degrade.
    bounded_authority_degradation: bounded authority (principle of least privilege) degrades.

    # capability_governance_seam: autonomous-systems capability boundary enforcement,
    # multi-agent authority delegation, and AI system scope restriction extend from
    # capability_scope and authority_degradation. The projection layer becomes the
    # governance surface for bounded-authority AI deployments.
    # multi_agent_governance_seam: multi-agent orchestration governance, cross-agent
    # capability attestation, and delegation chain integrity verification extend here.
    """

    capability_scope: str
    authority_degradation: bool
    escalation_risk_increase: bool
    auditability_degradation: bool
    bounded_authority_degradation: bool
    uncertainty: SimulationUncertainty
    basis: str


@dataclass(frozen=True)
class SimulationGovernanceTrajectory:
    """Projected longitudinal governance trajectory — seam for multi-run trend analysis.

    projected_drift_events: expected number of governance drift events over horizon.
    projected_critical_events: expected critical/blocking events over horizon.
    governance_stability: projected overall governance stability direction.
    maturity_trajectory: projected maturity milestone trajectory.

    # longitudinal_simulation_seam: multi-run governance trend analysis, drift recurrence
    # forecasting, readiness volatility prediction, and chronic degradation detection
    # extend from this seam. Historical simulation runs + this trajectory object are the
    # inputs for a governance decay curve model and a readiness MTTR estimator.
    """

    trajectory_id: str
    scenario_type: SimulationScenarioType
    projected_drift_events: int
    projected_critical_events: int
    governance_stability: SimulationRiskDirection
    maturity_trajectory: SimulationRiskDirection
    uncertainty: SimulationUncertainty


# ---------------------------------------------------------------------------
# Top-level simulation projection — immutable output
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SimulationProjection:
    """Immutable, replay-safe simulation projection.

    All fields required for forensic replay. Version pins ensure historical
    projections remain reconstructable against the contract that produced them.

    projection_json is NEVER stored in this object — serialization is handled
    by the serialization module. This object is the canonical domain output.

    No prompts, vectors, embeddings, PHI, provider payloads, or secrets
    appear in any field.
    """

    simulation_id: str
    simulation_snapshot_id: str
    tenant_id: str
    assessment_id: Optional[str]
    framework_id: Optional[str]
    scenario_type: SimulationScenarioType
    readiness_projection: SimulationReadinessProjection
    risk_projection: SimulationRiskProjection
    compliance_projection: SimulationComplianceProjection
    blast_radius: SimulationBlastRadius
    impact_records: tuple[SimulationImpactRecord, ...]
    diff_records: tuple[SimulationDiffRecord, ...]
    warnings: tuple[SimulationWarning, ...]
    constraints: tuple[SimulationConstraint, ...]
    capability_projection: Optional[SimulationCapabilityProjection]
    governance_trajectory: Optional[SimulationGovernanceTrajectory]
    simulation_contract_version: str
    simulation_engine_version: str
    framework_version_tag: str
    simulated_at_iso: str
    uncertainty: SimulationUncertainty
    replay_contract_metadata: tuple[tuple[str, str], ...]


# ---------------------------------------------------------------------------
# Stored simulation run record — domain object for persistence layer
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SimulationRunRecord:
    """Domain object returned by SimulationRunStore — no SQLAlchemy types.

    projection_json is stored internally; never exposed directly in API responses.
    The API layer deserializes and returns the export-safe dict instead.
    """

    run_id: str
    tenant_id: str
    assessment_id: Optional[str]
    framework_id: Optional[str]
    scenario_type: str
    simulation_contract_version: str
    simulation_engine_version: str
    snapshot_id: str
    projection_json: str  # stored internally; never in API responses
    uncertainty: str
    total_warnings: int
    total_impacts: int
    total_critical_warnings: int
    simulated_at_iso: str
    completed: bool
    error_summary: Optional[str]
    created_at_iso: str
