"""services/governance_adaptive_intelligence/schemas.py

Pydantic schemas for the Governance Adaptive Intelligence Authority.
All schemas use extra="forbid" for contract stability.

PR 17.6C — Governance Adaptive Intelligence Authority
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict


# ---------------------------------------------------------------------------
# Recommendation history
# ---------------------------------------------------------------------------


class RecommendationHistoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    recommendation_id: str
    recommendation_type: str
    recommendation_category: Optional[str]
    recommendation_reason: str
    recommendation_confidence: str
    generated_at: str
    accepted_at: Optional[str]
    rejected_at: Optional[str]
    executed_at: Optional[str]
    closed_at: Optional[str]
    status: str
    source_learning_record_id: Optional[str]
    source_aggregate_id: Optional[str]
    source_authority: str
    outcome: Optional[RecommendationOutcomeResponse] = None


# ---------------------------------------------------------------------------
# Recommendation outcome
# ---------------------------------------------------------------------------


class RecommendationOutcomeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    recommendation_history_id: str
    health_before: Optional[float]
    health_after: Optional[float]
    health_delta: Optional[float]
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
    success: bool
    confidence_adjustment: Optional[float]
    recorded_at: str


# Resolve forward reference
RecommendationHistoryResponse.model_rebuild()


# ---------------------------------------------------------------------------
# Accuracy aggregate
# ---------------------------------------------------------------------------


class AccuracyAggregateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    recommendation_type: str
    recommendations_generated: int
    recommendations_accepted: int
    recommendations_executed: int
    recommendations_successful: int
    recommendations_failed: int
    avg_health_delta: Optional[float]
    avg_effectiveness_delta: Optional[float]
    avg_verification_delta: Optional[float]
    avg_freshness_delta: Optional[float]
    avg_forecast_delta: Optional[float]
    calibrated_confidence: str
    last_updated_at: str
    accuracy_score: float


# ---------------------------------------------------------------------------
# Playbook
# ---------------------------------------------------------------------------


class PlaybookResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    playbook_type: str
    recommended_path: str
    recommended_steps: list[str]
    success_rate: float
    avg_health_improvement: Optional[float]
    confidence: str
    sample_size: int
    last_updated_at: str


# ---------------------------------------------------------------------------
# Adaptive recommendation (generated, not persisted)
# ---------------------------------------------------------------------------


class AdaptiveRecommendation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recommendation_id: str
    type: str
    category: Optional[str]
    reason: str
    confidence: str
    expected_health_delta: Optional[float]
    historical_success_rate: Optional[float]
    should_deprioritize: bool
    supporting_outcome_count: int
    generated_at: str


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


class AdaptiveDashboardResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    total_recommendations: int
    total_executed: int
    total_successful: int
    overall_accuracy_score: float
    calibrated_confidence: str
    avg_health_delta: Optional[float]
    avg_effectiveness_delta: Optional[float]
    active_recommendation_count: int
    generated_at: str


# ---------------------------------------------------------------------------
# Accuracy breakdown
# ---------------------------------------------------------------------------


class AdaptiveAccuracyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    per_type: list[AccuracyAggregateResponse]
    overall_accuracy_score: float
    overall_calibrated_confidence: str
    generated_at: str


# ---------------------------------------------------------------------------
# Calibration
# ---------------------------------------------------------------------------


class CalibrationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    confidence_distribution: dict[str, str]
    overall_calibration: str
    generated_at: str


# ---------------------------------------------------------------------------
# CGIN snapshot
# ---------------------------------------------------------------------------


class CGINAdaptiveSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_fingerprint: str
    bundle_id: str
    overall_accuracy: Optional[float]
    avg_health_improvement: Optional[float]
    confidence_distribution: dict[str, str]
    playbook_statistics: list[dict]
    total_recommendations: int
    generated_at: str


# ---------------------------------------------------------------------------
# Strategy profile
# ---------------------------------------------------------------------------


class StrategyProfileResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile: str
    recommended_controls: list[str]
    recommended_remediation_types: list[str]
    historical_success_patterns: list[str]
    historical_failure_patterns: list[str]
    confidence: str


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class TrackRecommendationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recommendation_id: str
    recommendation_type: str
    recommendation_category: Optional[str] = None
    recommendation_reason: str
    recommendation_confidence: str
    source_learning_record_id: Optional[str] = None
    source_aggregate_id: Optional[str] = None
    source_authority: str = "governance_learning"


class AcceptRecommendationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recommendation_history_id: str
    accepted: bool


class ExecuteRecommendationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recommendation_history_id: str


class RecordOutcomeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recommendation_history_id: str
    success: bool
    health_before: Optional[float] = None
    health_after: Optional[float] = None
    effectiveness_before: Optional[float] = None
    effectiveness_after: Optional[float] = None
    verification_before: Optional[float] = None
    verification_after: Optional[float] = None
    freshness_before: Optional[float] = None
    freshness_after: Optional[float] = None
    forecast_before: Optional[float] = None
    forecast_after: Optional[float] = None


class RecalculateAdaptiveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recommendation_type: Optional[str] = None
