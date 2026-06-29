"""services/control_effectiveness/schemas.py — Pydantic schemas for Control Effectiveness Engine.

All schemas use extra="forbid" for contract stability.

PR 16.5 — Control Effectiveness Engine
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ControlNotFound(Exception):
    pass


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class RecalculateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_id: Optional[str] = None  # None = recalculate all


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class ControlEffectivenessResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    control_id: str
    effectiveness_score: float
    effectiveness_level: str
    effectiveness_risk: str
    coverage_score: Optional[float]
    verification_score: Optional[float]
    freshness_score: Optional[float]
    trend_score: Optional[float]
    forecast_score: Optional[float]
    evidence_density_score: Optional[float]
    exception_score: Optional[float]
    governance_health_score: Optional[float]
    trend_direction: Optional[str]
    score_delta_7d: Optional[float]
    score_delta_30d: Optional[float]
    score_delta_90d: Optional[float]
    last_calculated_at: str
    calculation_version: str


class ControlEffectivenessHistoryItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    control_id: str
    effectiveness_score: float
    effectiveness_level: str
    effectiveness_risk: str
    coverage_score: Optional[float]
    verification_score: Optional[float]
    freshness_score: Optional[float]
    trend_score: Optional[float]
    captured_at: str


class ControlEffectivenessHistoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    control_id: str
    items: list[ControlEffectivenessHistoryItem]
    total: int


class ControlEffectivenessDashboardResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    total_controls: int
    average_effectiveness_score: float
    highly_effective_count: int
    effective_count: int
    adequate_count: int
    weak_count: int
    ineffective_count: int
    critical_risk_count: int
    high_risk_count: int
    top_controls: list[ControlEffectivenessResponse]
    weak_controls: list[ControlEffectivenessResponse]
    high_risk_controls: list[ControlEffectivenessResponse]
    fastest_improving: list[ControlEffectivenessResponse]
    fastest_decaying: list[ControlEffectivenessResponse]
    generated_at: str


class ControlEffectivenessListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    items: list[ControlEffectivenessResponse]
    total: int


class RecalculateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    controls_recalculated: int
    control_id: Optional[str]
    calculated_at: str


class CGINEffectivenessSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_fingerprint: str
    average_effectiveness: float
    effectiveness_distribution: dict[str, int]
    total_controls: int
    high_risk_controls: int
    critical_risk_controls: int
    top_controls: list[str]
    weak_controls: list[str]
    generated_at: str
