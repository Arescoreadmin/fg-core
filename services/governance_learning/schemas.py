"""services/governance_learning/schemas.py

Pydantic schemas for the Governance Learning Loop Authority.
All schemas use extra="forbid" for contract stability.

PR 17.6B — Governance Learning Loop Authority
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict


# ---------------------------------------------------------------------------
# Learning record
# ---------------------------------------------------------------------------


class LearningRecordResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    learning_category: str
    control_id: Optional[str]
    remediation_category: str
    outcome_type: str
    effectiveness_before: Optional[float]
    effectiveness_after: Optional[float]
    effectiveness_delta: Optional[float]
    verification_before: Optional[float]
    verification_after: Optional[float]
    verification_delta: Optional[float]
    freshness_before: Optional[float]
    freshness_after: Optional[float]
    freshness_delta: Optional[float]
    forecast_before: Optional[float]
    forecast_after: Optional[float]
    forecast_delta: Optional[float]
    health_before: Optional[float]
    health_after: Optional[float]
    health_delta: Optional[float]
    success_score: float
    confidence_score: float
    source_outcome_id: Optional[str]
    created_at: str


class LearningRecordListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    records: list[LearningRecordResponse]
    total: int


# ---------------------------------------------------------------------------
# Learning aggregate
# ---------------------------------------------------------------------------


class LearningAggregateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    remediation_category: str
    success_count: int
    failure_count: int
    partial_success_count: int
    total_count: int
    success_rate: float
    failure_rate: float
    average_effectiveness_delta: Optional[float]
    average_verification_delta: Optional[float]
    average_freshness_delta: Optional[float]
    average_forecast_delta: Optional[float]
    average_health_delta: Optional[float]
    confidence: str
    last_updated_at: str
    signals: list[str]


class LearningAggregateListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    aggregates: list[LearningAggregateResponse]
    total: int


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------


class GovernanceRecommendation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recommendation_id: str
    recommended_next_action: str
    recommended_remediation_category: Optional[str]
    recommended_control_focus: Optional[str]
    recommendation_reason: str
    recommendation_confidence: str
    evidence_summary: str
    supporting_outcome_count: int
    expected_health_delta: Optional[float]
    generated_at: str


class RecommendationListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recommendations: list[GovernanceRecommendation]
    total: int
    generated_at: str


# ---------------------------------------------------------------------------
# Momentum
# ---------------------------------------------------------------------------


class GovernanceMomentumResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    momentum_class: str
    stability_class: str
    avg_health_delta_30d: Optional[float]
    avg_effectiveness_delta_30d: Optional[float]
    total_learning_records: int
    total_successful: int
    total_failed: int
    confidence: str
    computed_at: str


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


class LearningDashboardResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    total_learning_records: int
    total_aggregates: int
    top_performing_category: Optional[str]
    worst_performing_category: Optional[str]
    overall_success_rate: float
    overall_average_health_delta: Optional[float]
    momentum: str
    stability: str
    confidence: str
    active_signals: list[str]
    generated_at: str


# ---------------------------------------------------------------------------
# CGIN snapshot
# ---------------------------------------------------------------------------


class LearningCGINSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_fingerprint: str
    bundle_id: str
    bundle_version: str
    category_snapshots: list[dict]
    overall_success_rate: Optional[float]
    overall_avg_health_delta: Optional[float]
    total_records: int
    generated_at: str


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class IngestOutcomeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_outcome_id: str
    control_id: str
    outcome_classification: str
    score_delta: float
    remediation_category: str
    effectiveness_before: Optional[float] = None
    effectiveness_after: Optional[float] = None
    verification_before: Optional[float] = None
    verification_after: Optional[float] = None
    freshness_before: Optional[float] = None
    freshness_after: Optional[float] = None
    forecast_before: Optional[float] = None
    forecast_after: Optional[float] = None
    health_before: Optional[float] = None
    health_after: Optional[float] = None


class RecalculateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_id: Optional[str] = None
