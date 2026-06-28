"""services/governance_optimization/schemas.py

Pydantic schemas for the Governance Optimization Engine API.
All schemas use extra="forbid" to prevent body tenant spoofing.

PR 17.6D — Governance Optimization Engine
"""

from __future__ import annotations

import json
from typing import Optional

from pydantic import BaseModel, ConfigDict, field_validator


class OptimizationDecisionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    optimization_id: str
    optimization_type: str
    target_type: str
    target_id: str
    priority_score: float
    rank: int
    reason: str
    evidence_summary: str
    source_authorities: list[str]
    source_record_ids: Optional[list[str]] = None
    confidence: str
    created_at: str

    @field_validator("source_authorities", mode="before")
    @classmethod
    def parse_source_authorities(cls, v):
        if isinstance(v, str):
            try:
                return json.loads(v)
            except Exception:
                return []
        return v

    @field_validator("source_record_ids", mode="before")
    @classmethod
    def parse_source_record_ids(cls, v):
        if v is None:
            return None
        if isinstance(v, str):
            try:
                return json.loads(v)
            except Exception:
                return []
        return v


class OptimizationAggregateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    target_type: str
    target_id: str
    optimization_type: str
    times_ranked: int
    average_priority_score: Optional[float] = None
    latest_priority_score: Optional[float] = None
    highest_priority_score: Optional[float] = None
    lowest_priority_score: Optional[float] = None
    average_health_lift: Optional[float] = None
    average_effectiveness_lift: Optional[float] = None
    average_confidence: Optional[float] = None
    last_ranked_at: str


class OptimizationSnapshotResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    snapshot_type: str
    total_items_ranked: int
    top_priority_target_id: Optional[str] = None
    top_priority_score: Optional[float] = None
    average_priority_score: Optional[float] = None
    optimization_confidence: str
    generated_at: str


class OptimizationDashboardResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    total_decisions: int
    total_aggregates: int
    top_recommendation_type: Optional[str] = None
    top_remediation_category: Optional[str] = None
    top_bridge: Optional[str] = None
    average_priority_score: Optional[float] = None
    overall_confidence: str
    generated_at: str


class CGINOptimizationSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_fingerprint: str
    bundle_id: str
    optimization_version: str
    average_priority_score: Optional[float] = None
    top_strategy_profile: Optional[str] = None
    recommendation_ranking_stats: dict
    control_priority_stats: dict
    remediation_priority_stats: dict
    bridge_priority_stats: dict
    confidence_distribution: dict
    generated_at: str


class RankRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    persist: bool = True


class RecalculateOptimizationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    optimization_type: Optional[str] = None
