"""Pure data models for the Governance Simulation Engine."""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any


GOVERNANCE_SIMULATION_VERSION = "18.8.2"
GOVERNANCE_SIMULATION_GRAPH_SCHEMA_VERSION = "1.0"
GOVERNANCE_SIMULATION_SIMULATOR_VERSION = "1.0.0"
GOVERNANCE_SIMULATION_REPLAY_VERSION = "1.0"
GOVERNANCE_SIMULATION_FINGERPRINT_DOMAIN = "FG_GOVERNANCE_SIMULATION_V1"
GOVERNANCE_SIMULATION_MCIM_VERSION = "MCIM-18.8.2-GOVERNANCE-SIMULATION"


class SimulationHorizon(str, Enum):
    immediate = "immediate"
    thirty_days = "30_days"
    ninety_days = "90_days"
    one_eighty_days = "180_days"
    one_year = "1_year"


class ScenarioCategory(str, Enum):
    PolicyChange = "PolicyChange"
    ControlChange = "ControlChange"
    EvidenceChange = "EvidenceChange"
    FindingResolution = "FindingResolution"
    Remediation = "Remediation"
    AuthorityChange = "AuthorityChange"
    OrganizationalChange = "OrganizationalChange"
    FrameworkMapping = "FrameworkMapping"
    RiskAcceptance = "RiskAcceptance"
    ReadinessImprovement = "ReadinessImprovement"
    ExecutiveDecision = "ExecutiveDecision"


# Mutable registry dict, exposed as immutable proxy — extensible pattern
_SCENARIO_CATEGORY_REGISTRY_SOURCE: dict[str, str] = {
    c.value: c.value for c in ScenarioCategory
}

SCENARIO_CATEGORY_REGISTRY: Mapping[str, str] = MappingProxyType(
    _SCENARIO_CATEGORY_REGISTRY_SOURCE
)


_SCENARIO_TEMPLATE_REGISTRY_SOURCE: dict[str, str] = {
    "zero_trust_rollout": "Zero Trust Network Access Rollout",
    "pci_remediation": "PCI DSS Remediation",
    "iso_readiness": "ISO 27001 Readiness",
    "ai_governance": "AI Governance Framework",
    "nist_migration": "NIST CSF Migration",
    "cis_improvement": "CIS Controls Improvement",
}
SCENARIO_TEMPLATE_REGISTRY: Mapping[str, str] = MappingProxyType(
    _SCENARIO_TEMPLATE_REGISTRY_SOURCE
)


class OverlayOperationType(str, Enum):
    add_entity = "add_entity"
    remove_entity = "remove_entity"
    modify_entity = "modify_entity"
    add_relationship = "add_relationship"
    remove_relationship = "remove_relationship"
    modify_relationship = "modify_relationship"


class SimulationValidationSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    FATAL = "FATAL"


class ImpactDomain(str, Enum):
    governance = "governance"
    control = "control"
    evidence = "evidence"
    framework = "framework"
    compliance = "compliance"
    operational = "operational"
    executive = "executive"
    risk = "risk"
    readiness = "readiness"
    authority = "authority"
    trust = "trust"


class ImpactConfidence(str, Enum):
    PROVEN = "PROVEN"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ScenarioOverlayOperation:
    op_id: str
    operation_type: str
    source_entity_id: str | None
    target_entity_id: str | None
    source_relationship_id: str | None
    entity_payload: Mapping[str, Any] | None
    relationship_payload: Mapping[str, Any] | None
    reason: str
    authoritative_basis: str
    authority: str


@dataclass(frozen=True)
class ScenarioOverlay:
    overlay_id: str
    scenario_id: str
    source_snapshot_id: str
    source_snapshot_fingerprint: str
    tenant_id: str
    operations: tuple[ScenarioOverlayOperation, ...]
    created_at: str
    overlay_hash: str


@dataclass(frozen=True)
class SimulationScenario:
    scenario_id: str
    parent_snapshot_id: str
    source_snapshot_fingerprint: str
    scenario_name: str
    category: str
    created_from: str
    scenario_version: str
    graph_schema_version: str
    simulator_version: str
    replay_version: str
    created_at: str
    simulation_fingerprint: str
    overlay: ScenarioOverlay
    tenant_id: str
    horizon: str = dataclasses.field(default="immediate")  # SimulationHorizon value
    template_id: str | None = dataclasses.field(default=None)
    estimated_cost: str | None = dataclasses.field(default=None)
    estimated_effort: str | None = dataclasses.field(default=None)
    estimated_duration: str | None = dataclasses.field(default=None)


@dataclass(frozen=True)
class GraphDiffEntry:
    diff_id: str
    domain: str
    operation: str
    entity_id: str | None
    relationship_id: str | None
    before: Mapping[str, Any] | None
    after: Mapping[str, Any] | None
    authority: str
    reason: str


@dataclass(frozen=True)
class GraphDiff:
    diff_id: str
    scenario_id: str
    source_snapshot_id: str
    entries: tuple[GraphDiffEntry, ...]
    diff_hash: str
    created_at: str


@dataclass(frozen=True)
class ImpactEntry:
    impact_id: str
    domain: str
    impacted_object_ids: tuple[str, ...]
    reason: str
    originating_authority: str
    confidence: str
    supporting_evidence_ids: tuple[str, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class ImpactChainNode:
    domain: str
    impacted_object_ids: tuple[str, ...]
    confidence: str


@dataclass(frozen=True)
class ImpactChain:
    chain_id: str
    scenario_id: str
    origin_domain: str
    chain: tuple[ImpactChainNode, ...]  # ordered root→leaf
    chain_hash: str


@dataclass(frozen=True)
class ImpactReport:
    report_id: str
    scenario_id: str
    source_snapshot_id: str
    entries: tuple[ImpactEntry, ...]
    report_hash: str
    created_at: str
    limitations: tuple[str, ...]
    chains: tuple[ImpactChain, ...] = dataclasses.field(default_factory=tuple)


@dataclass(frozen=True)
class ExecutiveComparisonRow:
    object_id: str
    object_type: str
    domain: str
    current_value: str | None
    scenario_value: str | None
    delta: str | None
    evidence_ids: tuple[str, ...]
    reason: str
    confidence: str
    authority: str
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class ExecutiveComparison:
    comparison_id: str
    scenario_id: str
    rows: tuple[ExecutiveComparisonRow, ...]
    comparison_hash: str
    created_at: str
    net_positive: int = dataclasses.field(default=0)
    net_negative: int = dataclasses.field(default=0)
    neutral: int = dataclasses.field(default=0)
    unknown_count: int = dataclasses.field(default=0)


@dataclass(frozen=True)
class SimulationValidationFinding:
    severity: str
    code: str
    message: str


@dataclass(frozen=True)
class SimulationValidationReport:
    valid: bool
    findings: tuple[SimulationValidationFinding, ...]
    highest_severity: str
    violations: tuple[str, ...]
    checked_invariants: tuple[str, ...]


@dataclass(frozen=True)
class SimulationManifest:
    manifest_schema_version: str
    scenario_id: str
    source_snapshot_id: str
    source_snapshot_fingerprint: str
    scenario_name: str
    scenario_category: str
    simulation_version: str
    graph_schema_version: str
    simulator_version: str
    replay_version: str
    tenant_id: str
    created_at: str
    simulation_fingerprint: str
    overlay_hash: str
    diff_hash: str
    impact_hash: str
    comparison_hash: str
    mcim_version: str
    lineage: str
    simulation_complexity: str = dataclasses.field(
        default="low"
    )  # "low" | "medium" | "high"
    objects_evaluated: int = dataclasses.field(default=0)
    objects_changed: int = dataclasses.field(default=0)
    objects_unaffected: int = dataclasses.field(default=0)
    validation_duration_ms: int | None = dataclasses.field(default=None)
    build_duration_ms: int | None = dataclasses.field(default=None)


@dataclass(frozen=True)
class ReplayPackage:
    package_id: str
    scenario_id: str
    source_snapshot_fingerprint: str
    manifest: SimulationManifest
    scenario: SimulationScenario
    overlay: ScenarioOverlay
    diff: GraphDiff
    impact_report: ImpactReport
    comparison: ExecutiveComparison
    validation_report: SimulationValidationReport
    fingerprint: str
    created_at: str
    mcim_version: str
    schema_version: str
    replay_version: str
    lineage: str
    rollback_reference: str | None = dataclasses.field(
        default=None
    )  # reserved for 18.8.3
    rollback_ready: bool = dataclasses.field(default=False)  # always False until 18.8.3
    rollback_dependencies: tuple[str, ...] = dataclasses.field(
        default_factory=tuple
    )  # reserved


@dataclass(frozen=True)
class SimulationResult:
    scenario: SimulationScenario
    overlay: ScenarioOverlay
    diff: GraphDiff
    impact_report: ImpactReport
    comparison: ExecutiveComparison
    validation_report: SimulationValidationReport
    replay_package: ReplayPackage
    simulation_fingerprint: str


@dataclass(frozen=True)
class SimulationRun:
    run_id: str  # independent of scenario_id
    scenario_id: str
    snapshot_id: str
    snapshot_fingerprint: str
    tenant_id: str
    run_at: str
    horizon: str
    simulator_version: str
    result: SimulationResult
