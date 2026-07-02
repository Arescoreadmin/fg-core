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
]
