"""services/remediation_effectiveness/schemas.py

Pydantic schemas for the Remediation Effectiveness Analytics Authority.
All schemas use extra="forbid" for contract stability.

PR 17.5 — Remediation Effectiveness Analytics Authority
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict


# ---------------------------------------------------------------------------
# Core outcome response
# ---------------------------------------------------------------------------


class RemediationOutcomeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    remediation_task_id: str
    control_id: str
    before_score: float
    after_score: float
    score_delta: float
    before_effectiveness_level: str
    after_effectiveness_level: str
    outcome_classification: str
    remediation_effectiveness_score: float
    effectiveness_level: str
    roi_score: float
    roi_classification: str
    remediation_category: str
    verification_before: Optional[float]
    verification_after: Optional[float]
    verification_delta: Optional[float]
    freshness_before: Optional[float]
    freshness_after: Optional[float]
    freshness_delta: Optional[float]
    forecast_before: Optional[float]
    forecast_after: Optional[float]
    forecast_delta: Optional[float]
    governance_health_before: Optional[float]
    governance_health_after: Optional[float]
    governance_health_delta: Optional[float]
    status: str
    measured_at: str
    generated_at: str


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class RecordOutcomeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    remediation_task_id: str
    control_id: str
    before_score: float
    after_score: float
    before_effectiveness_level: str
    after_effectiveness_level: str
    remediation_category: Optional[str] = None
    verification_before: Optional[float] = None
    verification_after: Optional[float] = None
    freshness_before: Optional[float] = None
    freshness_after: Optional[float] = None
    forecast_before: Optional[float] = None
    forecast_after: Optional[float] = None
    governance_health_before: Optional[float] = None
    governance_health_after: Optional[float] = None


class UpdateOutcomeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Optional[str] = None


# ---------------------------------------------------------------------------
# Outcome list
# ---------------------------------------------------------------------------


class OutcomeListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    items: list[RemediationOutcomeResponse]
    total: int
    success_count: int
    failure_count: int
    generated_at: str


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


class PersistenceWindowItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    window_days: int
    score_at_window: float
    delta_from_close: float
    persistence_classification: str
    measured_at: str


class RemediationPersistenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    remediation_id: str
    control_id: str
    close_score: float
    windows: list[PersistenceWindowItem]
    generated_at: str


# ---------------------------------------------------------------------------
# Learning
# ---------------------------------------------------------------------------


class LearningItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    remediation_category: str
    total_remediations: int
    success_count: int
    partial_success_count: int
    no_change_count: int
    regression_count: int
    failure_count: int
    success_rate: float
    average_score_delta: float
    average_roi_score: float
    last_updated_at: str


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------


class PatternItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_id: str
    pattern_type: str
    severity: str
    occurrence_count: int
    description: str
    detected_at: str
    last_seen_at: str


class PatternsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    patterns: list[PatternItem]
    total: int
    critical_count: int
    high_count: int
    generated_at: str


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


class RemediationDashboardResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    total_remediations: int
    success_count: int
    partial_success_count: int
    no_change_count: int
    regression_count: int
    failure_count: int
    success_rate: float
    average_score_delta: float
    average_roi_score: float
    average_effectiveness_score: float
    top_performing_category: Optional[str]
    worst_performing_category: Optional[str]
    active_patterns: int
    critical_patterns: int
    learning: list[LearningItem]
    generated_at: str


# ---------------------------------------------------------------------------
# Top successes / Failures
# ---------------------------------------------------------------------------


class TopSuccessesResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    items: list[RemediationOutcomeResponse]
    generated_at: str


class FailuresResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    items: list[RemediationOutcomeResponse]
    total_failures: int
    total_regressions: int
    generated_at: str


# ---------------------------------------------------------------------------
# Recalculate
# ---------------------------------------------------------------------------


class RecalculateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    patterns_detected: int
    learning_categories_updated: int
    generated_at: str


# ---------------------------------------------------------------------------
# CGIN benchmark snapshot
# ---------------------------------------------------------------------------


class CGINRemediationSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    total_remediations: int
    success_rate: float
    average_score_delta: float
    average_roi_score: float
    patterns_detected: int
    snapshot_at: str
