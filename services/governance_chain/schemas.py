"""services/governance_chain/schemas.py — Request/response schemas for Governance Chain Authority.

All schemas use ConfigDict(extra="forbid") to prevent field injection.

PR 17.6 — Canonical Governance Chain Authority
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict


# ---------------------------------------------------------------------------
# Domain exceptions
# ---------------------------------------------------------------------------


class ChainEventNotFound(Exception):
    pass


class ChainExecutionNotFound(Exception):
    pass


class GovernanceHealthNotFound(Exception):
    pass


class ChainBridgeNotFound(Exception):
    pass


# ---------------------------------------------------------------------------
# Chain event schemas
# ---------------------------------------------------------------------------


class EmitChainEventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: str
    authority: str
    object_type: str
    object_id: str
    reason: str
    correlation_id: Optional[str] = None
    actor_id: Optional[str] = None
    actor_type: Optional[str] = None
    payload_json: Optional[str] = None


class ChainEventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    event_type: str
    authority: str
    object_type: str
    object_id: str
    correlation_id: Optional[str]
    actor_id: Optional[str]
    actor_type: Optional[str]
    reason: Optional[str]
    payload_json: Optional[str]
    created_at: str


class ChainEventListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[ChainEventResponse]
    total: int


# ---------------------------------------------------------------------------
# Chain execution schemas
# ---------------------------------------------------------------------------


class ExecuteBridgeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bridge: str
    trigger_object_id: str
    trigger_object_type: str
    trigger_reason: str
    correlation_id: Optional[str] = None
    actor_id: Optional[str] = None
    actor_type: Optional[str] = None
    # Bridge-specific optional fields
    control_id: Optional[str] = None
    verification_id: Optional[str] = None
    action_id: Optional[str] = None
    effectiveness_before: Optional[float] = None
    effectiveness_after: Optional[float] = None
    remediation_category: Optional[str] = None
    before_effectiveness_level: Optional[str] = None
    after_effectiveness_level: Optional[str] = None
    verification_before: Optional[float] = None
    verification_after: Optional[float] = None
    freshness_before: Optional[float] = None
    freshness_after: Optional[float] = None
    forecast_before: Optional[float] = None
    forecast_after: Optional[float] = None
    governance_health_before: Optional[float] = None
    governance_health_after: Optional[float] = None
    verified_at: Optional[str] = None


class ChainExecutionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    chain_execution_id: str
    source_authority: str
    target_authority: str
    bridge_type: str
    trigger_reason: Optional[str]
    trigger_object_id: str
    trigger_object_type: str
    execution_result: str
    success: bool
    failure_reason: Optional[str]
    duration_ms: Optional[float]
    executed_at: str


class ChainExecutionListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    executions: list[ChainExecutionResponse]
    total: int


# ---------------------------------------------------------------------------
# Governance health schemas
# ---------------------------------------------------------------------------


class RecalculateHealthRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_id: Optional[str] = None


class GovernanceHealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    verification_health: float
    freshness_health: float
    effectiveness_health: float
    remediation_health: float
    forecast_health: float
    governance_health_score: float
    governance_health_rating: str
    missing_inputs: list[str]
    snapshot_at: str
    calculation_version: str


class GovernanceHealthHistoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    snapshots: list[GovernanceHealthResponse]
    total: int


# ---------------------------------------------------------------------------
# CGIN snapshot schemas
# ---------------------------------------------------------------------------


class CGINChainAuthoritySnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    authority: str
    execution_count: int
    success_count: int
    failure_count: int
    skipped_count: int
    success_rate: float
    average_duration_ms: Optional[float]


class CGINChainSnapshotBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bundle_id: str
    bundle_version: str
    tenant_fingerprint: str
    authority_snapshots: list[CGINChainAuthoritySnapshot]
    total_chain_events: int
    governance_health_score: Optional[float]
    governance_health_rating: Optional[str]
    generated_at: str


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------


class AuthorityAvailability(BaseModel):
    model_config = ConfigDict(extra="forbid")

    authority: str
    available: bool
    reason: Optional[str]


class ChainDiagnosticsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    total_chain_events: int
    total_bridge_executions: int
    successful_executions: int
    failed_executions: int
    skipped_executions: int
    execution_success_rate: float
    event_type_distribution: dict[str, int]
    bridge_execution_distribution: dict[str, int]
    authority_availability: list[AuthorityAvailability]
    latest_governance_health: Optional[GovernanceHealthResponse]
    missing_inputs: list[str]
    generated_at: str
