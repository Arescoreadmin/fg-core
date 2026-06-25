"""services/control_effectiveness_explainability/schemas.py

Pydantic schemas for the Explainability & Governance Action Engine.
All schemas use extra="forbid" for contract stability.

PR 16.5.1 — Control Effectiveness Explainability & Governance Action Engine
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict


# ---------------------------------------------------------------------------
# Score contribution
# ---------------------------------------------------------------------------


class ScoreContributionItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    component_name: str
    raw_score: float
    weight: float
    weighted_score: float
    contribution_percentage: float
    impact: str  # POSITIVE | NEGATIVE | NEUTRAL


class ScoreContributorsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    control_id: str
    effectiveness_score: float
    effectiveness_level: str
    contributions: list[ScoreContributionItem]
    generated_at: str


# ---------------------------------------------------------------------------
# Root cause analysis
# ---------------------------------------------------------------------------


class RootCauseItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    root_cause_type: str
    impact: str  # POSITIVE | NEGATIVE
    severity: str  # CRITICAL | HIGH | MEDIUM | INFORMATIONAL
    impact_score: float
    description: str


# ---------------------------------------------------------------------------
# Governance actions
# ---------------------------------------------------------------------------


class GovernanceActionItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_type: str
    priority: str  # CRITICAL | HIGH | MEDIUM | LOW
    description: str
    rationale: str


class GovernanceActionsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    control_id: str
    governance_priority: str
    actions: list[GovernanceActionItem]
    generated_at: str


# ---------------------------------------------------------------------------
# Change detection
# ---------------------------------------------------------------------------


class ChangeDetectionSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str  # IMPROVED | IMPROVING | STABLE | DECLINING | CRITICAL
    explanation: str
    delta_7d: Optional[float]
    delta_30d: Optional[float]
    delta_90d: Optional[float]


# ---------------------------------------------------------------------------
# Full explain response
# ---------------------------------------------------------------------------


class ControlExplainResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    control_id: str
    effectiveness_score: float
    effectiveness_level: str
    effectiveness_risk: str
    governance_priority: str
    narrative: str
    contributions: list[ScoreContributionItem]
    positive_signals: list[RootCauseItem]
    negative_signals: list[RootCauseItem]
    actions: list[GovernanceActionItem]
    change_detection: ChangeDetectionSummary
    generated_at: str


# ---------------------------------------------------------------------------
# Priorities list
# ---------------------------------------------------------------------------


class ControlPriorityItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_id: str
    effectiveness_score: float
    effectiveness_level: str
    effectiveness_risk: str
    governance_priority: str
    trend_direction: Optional[str]
    priority_rationale: str


class PrioritiesResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    items: list[ControlPriorityItem]
    total: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    generated_at: str


# ---------------------------------------------------------------------------
# Rankings
# ---------------------------------------------------------------------------


class RankingItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_id: str
    rank_position: int
    effectiveness_score: float
    effectiveness_level: str
    effectiveness_risk: str
    rank_type: str


class RankingsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    top_controls: list[RankingItem]
    weakest_controls: list[RankingItem]
    fastest_improving: list[RankingItem]
    fastest_declining: list[RankingItem]
    highest_risk: list[RankingItem]
    most_fragile: list[RankingItem]
    most_valuable: list[RankingItem]
    generated_at: str


# ---------------------------------------------------------------------------
# Executive dashboard
# ---------------------------------------------------------------------------


class ExecutiveDashboardResponse(BaseModel):
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
    critical_priority_count: int
    high_priority_count: int
    medium_priority_count: int
    low_priority_count: int
    top_positive_signals: list[str]
    top_negative_signals: list[str]
    top_recommended_actions: list[str]
    top_controls: list[RankingItem]
    weakest_controls: list[RankingItem]
    highest_risk_controls: list[RankingItem]
    fastest_improving: list[RankingItem]
    fastest_declining: list[RankingItem]
    generated_at: str


# ---------------------------------------------------------------------------
# CGIN benchmark-ready snapshot schemas (structures only — no benchmarking yet)
# ---------------------------------------------------------------------------


class ControlContributionSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    control_id: str
    effectiveness_score: float
    contributions: list[ScoreContributionItem]
    snapshot_at: str


class ControlRiskSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    control_id: str
    effectiveness_score: float
    effectiveness_level: str
    effectiveness_risk: str
    governance_priority: str
    trend_direction: Optional[str]
    snapshot_at: str


class ControlActionSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    control_id: str
    governance_priority: str
    actions: list[GovernanceActionItem]
    snapshot_at: str


class ControlPrioritySnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    control_id: str
    governance_priority: str
    effectiveness_score: float
    effectiveness_level: str
    trend_direction: Optional[str]
    snapshot_at: str
