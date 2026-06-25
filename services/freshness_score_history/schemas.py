"""services/freshness_score_history/schemas.py — Pydantic schemas for Freshness Score History.

All schemas use extra="forbid" for contract stability and input rejection.

PR 14.6.8 — Freshness Score History & Governance Trend Intelligence
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class FreshnessSnapshotNotFound(Exception):
    pass


class FreshnessTrendNotFound(Exception):
    pass


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class RunSnapshotRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capture_date: Optional[str] = None


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class FreshnessScoreSnapshotResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    evidence_id: str
    freshness_record_id: Optional[str]
    freshness_score: int
    freshness_state: str
    review_due_at: Optional[str]
    verification_due_at: Optional[str]
    expiration_due_at: Optional[str]
    captured_at: str
    capture_date: str


class FreshnessDailySnapshotResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    average_freshness_score: float
    fresh_evidence_count: int
    due_soon_count: int
    review_required_count: int
    verification_required_count: int
    expired_count: int
    coverage_at_risk_count: int
    total_evidence_count: int
    captured_at: str
    capture_date: str


class FreshnessHistoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    tenant_id: str
    snapshots: list[FreshnessScoreSnapshotResponse]
    total: int
    trend_direction: Optional[str]
    score_delta_7d: Optional[float]
    score_delta_30d: Optional[float]


class FreshnessTrendResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    period_days: int
    current_avg_score: float
    baseline_avg_score: Optional[float]
    score_delta: Optional[float]
    trend_direction: str
    fresh_delta: Optional[int]
    expired_delta: Optional[int]
    coverage_risk_delta: Optional[int]
    generated_at: str


class FreshnessTrendDashboardResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    current_avg_score: float
    score_delta_7d: Optional[float]
    score_delta_30d: Optional[float]
    score_delta_90d: Optional[float]
    trend_direction: str
    freshness_velocity: Optional[float]
    coverage_velocity: Optional[float]
    risk_velocity: Optional[float]
    generated_at: str


class FreshnessCGINTrendSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    average_score: float
    score_delta_30d: Optional[float]
    score_delta_90d: Optional[float]
    coverage_risk_delta: Optional[int]
    improvement_velocity: Optional[float]
    generated_at: str


class RunSnapshotResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capture_date: str
    evidence_snapshots_created: int
    daily_snapshot_created: bool
    already_exists: bool
    captured_at: str
