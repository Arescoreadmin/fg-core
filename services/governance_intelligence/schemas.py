"""Pydantic schemas for the Governance Intelligence Authority (PR 18.5).

All schemas use ``ConfigDict(extra="forbid")`` to prevent field injection.

Exception hierarchy:
  GovernanceIntelligenceError
    +- GovernanceIntelligenceNotFound
    +- GovernanceIntelligenceTenantViolation
    +- GovernanceIntelligenceSimulationError
    +- GovernanceIntelligenceValidationError
    +- GovernanceIntelligencePolicyError
    +- GovernanceIntelligenceConflict
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Exception classes
# ---------------------------------------------------------------------------


class GovernanceIntelligenceError(Exception):
    """Base exception for all Governance Intelligence errors."""


class GovernanceIntelligenceNotFound(GovernanceIntelligenceError):
    """Entity not found for tenant."""


class GovernanceIntelligenceTenantViolation(GovernanceIntelligenceError):
    """Cross-tenant access attempt detected."""


class GovernanceIntelligenceSimulationError(GovernanceIntelligenceError):
    """Simulation could not be computed deterministically."""


class GovernanceIntelligenceValidationError(GovernanceIntelligenceError):
    """Input validation error at the schema-adjacent layer."""


class GovernanceIntelligencePolicyError(GovernanceIntelligenceError):
    """Policy lifecycle error (invalid transition, immutable state, etc.)."""


class GovernanceIntelligenceConflict(GovernanceIntelligenceError):
    """Conflict with an existing intelligence entity."""


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class CreateSimulationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4096)
    scenario_type: str = Field(..., max_length=64)
    parameters: dict[str, Any] = Field(default_factory=dict)


class UpdateSimulationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4096)
    parameters: dict[str, Any] | None = None


class RunSimulationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dry_run: bool = Field(default=False)


class CreateIntelligencePolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4096)
    policy_type: str = Field(..., max_length=64)
    policy_data: dict[str, Any] = Field(default_factory=dict)
    framework: str | None = Field(default=None, max_length=128)


class UpdateIntelligencePolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4096)
    policy_data: dict[str, Any] | None = None


class PolicyTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_state: str = Field(..., max_length=32)
    reason: str | None = Field(default=None, max_length=1024)
    actor_id: str = Field(..., min_length=1, max_length=255)


class CreateBenchmarkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework: str = Field(..., min_length=1, max_length=128)
    category: str = Field(..., min_length=1, max_length=128)
    metric_key: str = Field(..., min_length=1, max_length=255)
    value: float
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExternalEventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: str = Field(..., max_length=64)
    source: str = Field(..., min_length=1, max_length=255)
    payload: dict[str, Any] = Field(default_factory=dict)
    occurred_at: str | None = Field(default=None, max_length=64)


class FederationSyncRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instance_id: str = Field(..., min_length=1, max_length=255)
    role: str = Field(..., max_length=32)
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class SimulationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    name: str
    description: str | None
    scenario_type: str
    parameters: dict[str, Any]
    state: str
    result: dict[str, Any] | None
    created_at: str
    updated_at: str


class SimulationListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[SimulationResponse]
    total: int


class ExplainabilityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    decision_id: str
    trigger: str
    policy_version: str
    evaluation: dict[str, Any]
    decision: str
    authorities_invoked: list[str]
    expected_impact: dict[str, Any]
    observed_impact: dict[str, Any] | None
    created_at: str


class ExplainabilityListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ExplainabilityResponse]
    total: int


class IntelligencePolicyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    name: str
    description: str | None
    policy_type: str
    policy_data: dict[str, Any]
    framework: str | None
    lifecycle_state: str
    version: str
    created_at: str
    updated_at: str


class IntelligencePolicyListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[IntelligencePolicyResponse]
    total: int


class PolicyVersionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    policy_id: str
    version: str
    policy_data: dict[str, Any]
    changed_by: str | None
    created_at: str


class PolicyVersionListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[PolicyVersionResponse]
    total: int


class PolicyDiffResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: str
    from_version: str
    to_version: str
    added_rules: list[Any]
    removed_rules: list[Any]
    threshold_changes: list[dict[str, Any]]
    approval_changes: list[dict[str, Any]]
    governance_impact: dict[str, Any]


class BenchmarkResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    framework: str
    category: str
    metric_key: str
    value: float
    percentile: float | None
    tier: str | None
    metadata: dict[str, Any]
    created_at: str


class BenchmarkListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[BenchmarkResponse]
    total: int


class TrendResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    metric_key: str
    direction: str
    data_points: list[dict[str, Any]]
    window_days: int
    computed_at: str


class TrendListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[TrendResponse]
    total: int


class ForecastResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    metric_key: str
    horizon: str
    projected_values: list[dict[str, Any]]
    confidence_level: str
    model_type: str
    computed_at: str


class ForecastListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ForecastResponse]
    total: int


class ConfidenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dimension: str
    score: float
    level: str
    factors: dict[str, Any]
    computed_at: str


class ConfidenceListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ConfidenceResponse]
    total: int


class ExternalEventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    event_type: str
    source: str
    payload: dict[str, Any]
    occurred_at: str
    created_at: str


class ExternalEventListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ExternalEventResponse]
    total: int


class FederationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    instance_id: str
    role: str
    metadata: dict[str, Any]
    last_sync_at: str | None
    created_at: str


class FederationListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[FederationResponse]
    total: int


class DashboardResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    governance_score: float
    risk_level: str
    trend: str
    top_findings: list[dict[str, Any]]
    active_simulations: int
    benchmark_tier: str | None
    confidence: dict[str, Any]
    generated_at: str


class StatisticsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    total_simulations: int
    total_policies: int
    total_benchmarks: int
    total_external_events: int
    computed_at: str


class SearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    results: list[dict[str, Any]]
    total: int
    query: str


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    authority: str
    version: str
    schema_version: str
    checks: dict[str, str]


class TimelineResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[dict[str, Any]]
    total: int


# ---------------------------------------------------------------------------
# PR 18.5A — Request schemas
# ---------------------------------------------------------------------------


class CreateProvenanceNodeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    node_type: str
    authority: str
    source_object_id: str
    data: dict[str, Any] = Field(default_factory=dict)
    parent_ids: list[str] = Field(default_factory=list)


class ExportProvenanceGraphRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    node_ids: list[str]


class CreateEvidenceMatrixRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recommendation_id: str
    evidence_ids: list[str]
    control_ids: list[str] = Field(default_factory=list)
    framework_ids: list[str] = Field(default_factory=list)
    verification_ids: list[str] = Field(default_factory=list)
    trust_refs: list[str] = Field(default_factory=list)
    transparency_refs: list[str] = Field(default_factory=list)
    risk_factors: list[dict[str, Any]] = Field(default_factory=list)
    confidence: float = 0.0
    expected_improvement: float = 0.0
    simulation_ids: list[str] = Field(default_factory=list)


class CreateReplayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_version: str
    evidence_snapshot: dict[str, Any] = Field(default_factory=dict)
    trust_version: str
    transparency_snapshot: dict[str, Any] = Field(default_factory=dict)
    time_window: dict[str, Any] = Field(default_factory=dict)


class CreateCounterfactualRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario: str
    baseline: dict[str, Any] = Field(default_factory=dict)
    parameters: dict[str, Any] = Field(default_factory=dict)


class ComputeQualityScoreRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_id: str
    entity_type: str
    inputs: dict[str, float] = Field(default_factory=dict)


class ComputeBenchmarkConfidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    metric_key: str
    values: list[float]
    cohort_size: int
    data_recency_days: int


class ComputeTimelineDiffRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    period_a: dict[str, Any]
    period_b: dict[str, Any]
    window: str


class CompareSimulationsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    baseline_id: str
    proposed_id: str


class ComputeEvidenceImpactRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    evidence_data: dict[str, Any] = Field(default_factory=dict)
    downstream_data: dict[str, list[str]] = Field(default_factory=dict)


class CreateExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    node_ids: list[str] = Field(default_factory=list)
    export_format: str


# ---------------------------------------------------------------------------
# PR 18.5A — Response schemas
# ---------------------------------------------------------------------------


class ProvenanceNodeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    node_type: str
    authority: str
    authority_version: str
    source_object_id: str
    sha256_digest: str
    timestamp: str
    parent_ids: list[str]
    child_ids: list[str]
    trust_ref: str | None
    transparency_ref: str | None
    confidence_ref: str | None
    simulation_ref: str | None
    replay_ref: str | None
    created_at: str


class ProvenanceNodeListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ProvenanceNodeResponse]
    total: int


class ProvenanceGraphResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    node_count: int
    cycle_detected: bool


class EvidenceMatrixResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    recommendation_id: str
    matrix_data: dict[str, Any]
    coverage: float
    created_at: str


class EvidenceMatrixListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[EvidenceMatrixResponse]
    total: int


class ReplayResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    policy_version: str
    time_window: dict[str, Any]
    snapshot_data: dict[str, Any]
    result: dict[str, Any] | None
    replay_label: str
    created_at: str


class ReplayListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ReplayResponse]
    total: int


class CounterfactualResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    scenario: str
    baseline_data: dict[str, Any]
    parameters: dict[str, Any]
    result: dict[str, Any] | None
    created_at: str


class CounterfactualListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[CounterfactualResponse]
    total: int


class QualityScoreResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    entity_id: str
    entity_type: str
    score: float
    grade: str
    inputs: dict[str, Any]
    computed_at: str


class QualityScoreListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[QualityScoreResponse]
    total: int


class BenchmarkConfidenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    metric_key: str
    sample_size: int
    cohort_size: int
    data_recency_days: int
    confidence_interval: list[float]
    confidence_grade: str
    meets_threshold: bool
    min_sample_threshold: int
    benchmark_freshness: str


class BenchmarkConfidenceListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[BenchmarkConfidenceResponse]
    total: int


class TimelineDiffResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    window: str
    diff_data: dict[str, Any]
    created_at: str


class TimelineDiffListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[TimelineDiffResponse]
    total: int


class SimulationComparisonResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    baseline_id: str
    proposed_id: str
    comparison_data: dict[str, Any]
    created_at: str


class SimulationComparisonListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[SimulationComparisonResponse]
    total: int


class EvidenceImpactResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    impact_chain: list[dict[str, Any]]
    total_affected: int
    blast_radius_label: str


class ExportPackageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    package_id: str
    export_format: str
    contents_hash: str
    package_data: dict[str, Any]
    created_at: str


class ExportListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[dict[str, Any]]
    total: int


__all__ = [
    # Exceptions
    "GovernanceIntelligenceError",
    "GovernanceIntelligenceNotFound",
    "GovernanceIntelligenceTenantViolation",
    "GovernanceIntelligenceSimulationError",
    "GovernanceIntelligenceValidationError",
    "GovernanceIntelligencePolicyError",
    "GovernanceIntelligenceConflict",
    # Requests
    "CreateSimulationRequest",
    "UpdateSimulationRequest",
    "RunSimulationRequest",
    "CreateIntelligencePolicyRequest",
    "UpdateIntelligencePolicyRequest",
    "PolicyTransitionRequest",
    "CreateBenchmarkRequest",
    "ExternalEventRequest",
    "FederationSyncRequest",
    # PR 18.5A Requests
    "CreateProvenanceNodeRequest",
    "ExportProvenanceGraphRequest",
    "CreateEvidenceMatrixRequest",
    "CreateReplayRequest",
    "CreateCounterfactualRequest",
    "ComputeQualityScoreRequest",
    "ComputeBenchmarkConfidenceRequest",
    "ComputeTimelineDiffRequest",
    "CompareSimulationsRequest",
    "ComputeEvidenceImpactRequest",
    "CreateExportRequest",
    # Responses
    "SimulationResponse",
    "SimulationListResponse",
    "ExplainabilityResponse",
    "ExplainabilityListResponse",
    "IntelligencePolicyResponse",
    "IntelligencePolicyListResponse",
    "PolicyVersionResponse",
    "PolicyVersionListResponse",
    "PolicyDiffResponse",
    "BenchmarkResponse",
    "BenchmarkListResponse",
    "TrendResponse",
    "TrendListResponse",
    "ForecastResponse",
    "ForecastListResponse",
    "ConfidenceResponse",
    "ConfidenceListResponse",
    "ExternalEventResponse",
    "ExternalEventListResponse",
    "FederationResponse",
    "FederationListResponse",
    "DashboardResponse",
    "StatisticsResponse",
    "SearchResponse",
    "HealthResponse",
    "TimelineResponse",
    # PR 18.5A Responses
    "ProvenanceNodeResponse",
    "ProvenanceNodeListResponse",
    "ProvenanceGraphResponse",
    "EvidenceMatrixResponse",
    "EvidenceMatrixListResponse",
    "ReplayResponse",
    "ReplayListResponse",
    "CounterfactualResponse",
    "CounterfactualListResponse",
    "QualityScoreResponse",
    "QualityScoreListResponse",
    "BenchmarkConfidenceResponse",
    "BenchmarkConfidenceListResponse",
    "TimelineDiffResponse",
    "TimelineDiffListResponse",
    "SimulationComparisonResponse",
    "SimulationComparisonListResponse",
    "EvidenceImpactResponse",
    "ExportPackageResponse",
    "ExportListResponse",
]
