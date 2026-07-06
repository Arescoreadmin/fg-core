"""Pure data models for the Governance Digital Twin foundation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any


GOVERNANCE_DIGITAL_TWIN_SNAPSHOT_VERSION = "18.8.1"
GOVERNANCE_DIGITAL_TWIN_GRAPH_SCHEMA_VERSION = "1.0"
GOVERNANCE_DIGITAL_TWIN_BUILDER_VERSION = "1.2.0"
GOVERNANCE_DIGITAL_TWIN_EXPORT_VERSION = "1.0"
GOVERNANCE_DIGITAL_TWIN_MANIFEST_SCHEMA_VERSION = "1.0"
GOVERNANCE_DIGITAL_TWIN_VALIDATOR_VERSION = "1.1.0"
GOVERNANCE_DIGITAL_TWIN_TWIN_VERSION = "1.0"
GOVERNANCE_DIGITAL_TWIN_GOVERNANCE_MODEL_VERSION = "1.0"
GOVERNANCE_DIGITAL_TWIN_FINGERPRINT_DOMAIN = "FG_GOVERNANCE_DIGITAL_TWIN_V1"
GOVERNANCE_DIGITAL_TWIN_EPOCH = "1970-01-01T00:00:00Z"


class GovernanceDigitalTwinEntityType(str, Enum):
    policy = "policy"
    control = "control"
    evidence = "evidence"
    finding = "finding"
    remediation = "remediation"
    assessment = "assessment"
    report = "report"
    decision = "decision"
    workflow = "workflow"
    simulation = "simulation"
    replay = "replay"
    customer = "customer"
    framework = "framework"
    authority = "authority"


class GovernanceDigitalTwinRelationshipType(str, Enum):
    governs = "governs"
    verifies = "verifies"
    maps_to = "maps_to"
    supports = "supports"
    contradicts = "contradicts"
    remediates = "remediates"
    generated_from = "generated_from"
    published_to = "published_to"
    decided_by = "decided_by"
    depends_on = "depends_on"
    supersedes = "supersedes"
    derived_from = "derived_from"
    affects = "affects"
    owned_by = "owned_by"


class GovernanceDigitalTwinSnapshotCategory(str, Enum):
    operational = "operational"
    assessment = "assessment"
    executive = "executive"
    simulation = "simulation"
    compliance = "compliance"
    audit = "audit"
    baseline = "baseline"


class GovernanceDigitalTwinValidationSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    FATAL = "FATAL"


@dataclass(frozen=True)
class GovernanceDigitalTwinConfidenceProvenance:
    authority: str
    confidence_weight: int
    coverage_percent: int
    freshness_at: str
    trust_level: str
    method: str


@dataclass(frozen=True)
class GovernanceDigitalTwinEntityProvenance:
    origin_authority: str
    source_table: str
    source_object: str
    capture_method: str
    deterministic_extractor: str
    created_from: tuple[str, ...]


@dataclass(frozen=True)
class GovernanceDigitalTwinEntity:
    id: str
    canonical_entity_id: str
    type: str
    authority: str
    source_ref: str
    title: str
    status: str
    created_at: str
    updated_at: str
    confidence: int
    confidence_provenance: GovernanceDigitalTwinConfidenceProvenance
    tenant_scope: str
    replay_safe: bool
    redaction_state: str
    metadata_hash: str
    provenance: GovernanceDigitalTwinEntityProvenance


@dataclass(frozen=True)
class GovernanceDigitalTwinRelationship:
    id: str
    canonical_relationship_id: str
    type: str
    from_entity_id: str
    to_entity_id: str
    authority: str
    confidence: int
    confidence_provenance: GovernanceDigitalTwinConfidenceProvenance
    evidence_refs: tuple[str, ...]
    created_at: str
    replay_safe: bool
    metadata_hash: str


@dataclass(frozen=True)
class GovernanceDigitalTwinBaselineReference:
    baseline_id: str
    label: str
    fingerprint: str | None
    purpose: str | None
    available: bool


@dataclass(frozen=True)
class GovernanceDigitalTwinSourceAuthority:
    authority: str
    available: bool
    entity_count: int
    relationship_count: int
    source_tables: tuple[str, ...]
    source_routes: tuple[str, ...]
    produced_entity_types: tuple[str, ...]
    confidence_weight: int
    coverage_percent: int
    freshness_at: str
    trust_level: str


@dataclass(frozen=True)
class GovernanceDigitalTwinAuthorityNode:
    authority: str
    available: bool
    ownership: str
    source_tables: tuple[str, ...]
    source_routes: tuple[str, ...]
    capabilities: tuple[str, ...]
    produced_entity_types: tuple[str, ...]
    consumed_entity_types: tuple[str, ...]
    downstream_dependencies: tuple[str, ...]
    confidence_weight: int
    coverage_percent: int
    freshness_at: str
    trust_level: str


@dataclass(frozen=True)
class GovernanceDigitalTwinAuthorityEdge:
    authority: str
    downstream_authority: str
    relationship_type: str


@dataclass(frozen=True)
class GovernanceDigitalTwinAuthorityGraph:
    authorities: tuple[GovernanceDigitalTwinAuthorityNode, ...]
    dependencies: tuple[GovernanceDigitalTwinAuthorityEdge, ...]


@dataclass(frozen=True)
class GovernanceDigitalTwinTwinIdentity:
    twin_id: str
    twin_version: str
    twin_class: str
    tenant_id: str
    created_by: str
    governance_model_version: str


@dataclass(frozen=True)
class GovernanceDigitalTwinStateExtensions:
    memory_reference: str | None
    memory_sequence: int | None
    timeline_anchor: str | None


@dataclass(frozen=True)
class GovernanceDigitalTwinFutureReferences:
    simulation_overlay: str | None
    prediction_reference: str | None
    execution_reference: str | None
    learning_reference: str | None
    optimization_reference: str | None


@dataclass(frozen=True)
class GovernanceDigitalTwinValidationFinding:
    severity: str
    code: str
    message: str


@dataclass(frozen=True)
class GovernanceDigitalTwinValidationReport:
    validator_version: str
    valid: bool
    checked_invariants: tuple[str, ...]
    violations: tuple[str, ...]
    findings: tuple[GovernanceDigitalTwinValidationFinding, ...]
    highest_severity: str
    hash_uniqueness: bool
    replay_integrity: bool


@dataclass(frozen=True)
class GovernanceDigitalTwinManifest:
    manifest_schema_version: str
    snapshot_version: str
    graph_schema_version: str
    snapshot_category: str
    entity_counts: Mapping[str, int]
    relationship_counts: Mapping[str, int]
    authority_counts: Mapping[str, int]
    completeness_score: int
    fingerprint: str
    redaction_profile: str
    baseline_reference: str | None
    builder_version: str
    mcim_version: str
    export_version: str
    validator_version: str
    lineage_id: str
    generation: int


@dataclass(frozen=True)
class GovernanceDigitalTwinBaseline:
    baseline_id: str
    tenant_id: str
    snapshot_id: str
    fingerprint: str
    label: str
    created_at: str
    created_by: str
    purpose: str
    entity_counts: Mapping[str, int]
    relationship_counts: Mapping[str, int]
    authority_counts: Mapping[str, int]
    completeness: Mapping[str, Any]
    replay_safe: bool
    snapshot_category: str
    twin_id: str


@dataclass(frozen=True)
class GovernanceDigitalTwinSnapshot:
    snapshot_id: str
    canonical_snapshot_id: str
    tenant_id: str
    generated_at: str
    snapshot_version: str
    graph_schema_version: str
    builder_version: str
    category: str
    parent_snapshot_id: str | None
    previous_fingerprint: str | None
    generation: int
    lineage_id: str
    twin_identity: GovernanceDigitalTwinTwinIdentity
    source_authorities: tuple[GovernanceDigitalTwinSourceAuthority, ...]
    authority_graph: GovernanceDigitalTwinAuthorityGraph
    entities: tuple[GovernanceDigitalTwinEntity, ...]
    relationships: tuple[GovernanceDigitalTwinRelationship, ...]
    baselines: tuple[GovernanceDigitalTwinBaselineReference, ...]
    manifest: GovernanceDigitalTwinManifest | None
    replay_safe_export: Mapping[str, Any]
    fingerprint: str
    redaction_profile: str
    completeness: Mapping[str, Any]
    validation_report: GovernanceDigitalTwinValidationReport | None
    state_extensions: GovernanceDigitalTwinStateExtensions
    future_references: GovernanceDigitalTwinFutureReferences
    warnings: tuple[str, ...]
    limitations: tuple[str, ...]
