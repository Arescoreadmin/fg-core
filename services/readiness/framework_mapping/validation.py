"""Enterprise Framework Mapping & Crosswalk Governance Engine — validation.

All validation functions in this module are:
  - Pure Python. No I/O. No side effects.
  - Fail-closed: invalid mappings return is_valid=False with reason codes.
  - Deterministic: identical inputs → identical validation outcomes.
  - Tenant-safe: cross-tenant access fails deterministically.

Reason code contract:
  - All reason codes are module-level string constants.
  - Reason codes are stable across validator versions.
  - Multiple failure reasons are always fully reported (not short-circuited).

Validation coverage:
  - MappingRelationship: self-mapping, tenant isolation, provenance completeness,
    framework-compatibility consistency.
  - ControlInheritance: self-inheritance, tenant isolation, provenance completeness.
  - FrameworkMapping: duplicate detection, framework ID consistency,
    scope-tenant consistency, cyclic inheritance detection.
  - FrameworkMappingVersion: version tag format, self-supersession.
  - Cyclic inheritance: DFS-based cycle detection in the inheritance graph.
  - Mapping gaps: unmapped controls, orphaned relationships,
    missing inheritance targets.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from .models import (
    ControlInheritance,
    FrameworkMapping,
    FrameworkMappingVersion,
    MappingGapRecord,
    MappingGapType,
    MappingRelationship,
    MappingScope,
    MappingValidationRecord,
    MappingValidationType,
)

_VALIDATOR_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Stable failure reason codes
# ---------------------------------------------------------------------------

# Relationship validation
REASON_SELF_MAPPING = "MAPPING_SELF_MAPPING"
REASON_TENANT_ISOLATION_VIOLATION = "MAPPING_TENANT_ISOLATION_VIOLATION"
REASON_MISSING_SOURCE_AUTHORITY = "MAPPING_MISSING_SOURCE_AUTHORITY"
REASON_MISSING_MAPPING_RATIONALE = "MAPPING_MISSING_RATIONALE"
REASON_FRAMEWORK_ID_MISMATCH = "MAPPING_FRAMEWORK_ID_MISMATCH"

# Inheritance validation
REASON_SELF_INHERITANCE = "MAPPING_SELF_INHERITANCE"

# Framework mapping validation
REASON_DUPLICATE_RELATIONSHIP = "MAPPING_DUPLICATE_RELATIONSHIP"
REASON_SCOPE_TENANT_MISMATCH = "MAPPING_SCOPE_TENANT_MISMATCH"
REASON_CYCLIC_INHERITANCE = "MAPPING_CYCLIC_INHERITANCE"

# Mapping version validation
REASON_VERSION_TAG_EMPTY = "MAPPING_VERSION_TAG_EMPTY"
REASON_SELF_SUPERSESSION = "MAPPING_SELF_SUPERSESSION"


# ---------------------------------------------------------------------------
# Cyclic inheritance detection
# ---------------------------------------------------------------------------


def detect_cyclic_inheritance(
    inheritances: tuple[ControlInheritance, ...],
) -> tuple[tuple[str, str], ...]:
    """Detect cycles in the control inheritance graph using DFS.

    Returns a tuple of (child_control_id, parent_control_id) pairs that
    participate in a cycle. Empty tuple means no cycles detected.

    The graph is directed: child → parent (the direction of inheritance claim).
    A cycle exists when following parent links leads back to a visited node.
    """
    graph: dict[str, set[str]] = {}
    for inh in inheritances:
        if inh.child_control_id not in graph:
            graph[inh.child_control_id] = set()
        graph[inh.child_control_id].add(inh.parent_control_id)

    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {node: WHITE for node in graph}
    cycles: list[tuple[str, str]] = []

    def _dfs(node: str) -> None:
        color[node] = GRAY
        for parent in graph.get(node, set()):
            parent_color = color.get(parent, BLACK)
            if parent_color == GRAY:
                cycles.append((node, parent))
            elif parent_color == WHITE:
                _dfs(parent)
        color[node] = BLACK

    for node in list(graph):
        if color[node] == WHITE:
            _dfs(node)

    return tuple(cycles)


# ---------------------------------------------------------------------------
# Mapping relationship validation
# ---------------------------------------------------------------------------


def validate_mapping_relationship(
    relationship: MappingRelationship,
    *,
    validation_id: str,
    validated_at: datetime,
    required_tenant_id: Optional[str] = None,
) -> MappingValidationRecord:
    """Validate a single MappingRelationship.

    Checks performed (all failures are always fully reported):
    - Self-mapping: source and target are the same control in the same framework.
    - Tenant isolation: relationship.tenant_id must match required_tenant_id if given.
    - Provenance completeness: source_authority and mapping_rationale must be non-empty.
    - Framework-compatibility consistency: relationship framework IDs must match
      the compatibility record's framework IDs.

    Note: source_control_id == target_control_id across different frameworks is NOT
    a self-mapping (cross-framework control with identical ID is valid).
    """
    reasons: list[str] = []

    if (
        relationship.source_control_id == relationship.target_control_id
        and relationship.source_framework_id == relationship.target_framework_id
    ):
        reasons.append(REASON_SELF_MAPPING)

    if required_tenant_id is not None and relationship.tenant_id != required_tenant_id:
        reasons.append(REASON_TENANT_ISOLATION_VIOLATION)

    if not relationship.provenance.source_authority.strip():
        reasons.append(REASON_MISSING_SOURCE_AUTHORITY)

    if not relationship.provenance.mapping_rationale.strip():
        reasons.append(REASON_MISSING_MAPPING_RATIONALE)

    if (
        relationship.source_framework_id
        != relationship.compatibility.source_framework_id
        or relationship.target_framework_id
        != relationship.compatibility.target_framework_id
    ):
        reasons.append(REASON_FRAMEWORK_ID_MISMATCH)

    return MappingValidationRecord(
        validation_id=validation_id,
        subject_id=relationship.relationship_id,
        validation_type=MappingValidationType.RELATIONSHIP,
        is_valid=len(reasons) == 0,
        failure_reasons=tuple(reasons),
        validated_at=validated_at,
        validator_version=_VALIDATOR_VERSION,
    )


# ---------------------------------------------------------------------------
# Control inheritance validation
# ---------------------------------------------------------------------------


def validate_control_inheritance(
    inheritance: ControlInheritance,
    *,
    validation_id: str,
    validated_at: datetime,
    required_tenant_id: Optional[str] = None,
) -> MappingValidationRecord:
    """Validate a single ControlInheritance record.

    Checks performed:
    - Self-inheritance: child and parent are the same control in the same framework.
    - Tenant isolation: inheritance.tenant_id must match required_tenant_id if given.
    - Provenance completeness: source_authority and mapping_rationale must be non-empty.

    Note: same control_id across different frameworks (cross-framework inheritance)
    is valid and NOT treated as self-inheritance.
    """
    reasons: list[str] = []

    if (
        inheritance.child_control_id == inheritance.parent_control_id
        and inheritance.child_framework_id == inheritance.parent_framework_id
    ):
        reasons.append(REASON_SELF_INHERITANCE)

    if required_tenant_id is not None and inheritance.tenant_id != required_tenant_id:
        reasons.append(REASON_TENANT_ISOLATION_VIOLATION)

    if not inheritance.provenance.source_authority.strip():
        reasons.append(REASON_MISSING_SOURCE_AUTHORITY)

    if not inheritance.provenance.mapping_rationale.strip():
        reasons.append(REASON_MISSING_MAPPING_RATIONALE)

    return MappingValidationRecord(
        validation_id=validation_id,
        subject_id=inheritance.inheritance_id,
        validation_type=MappingValidationType.INHERITANCE,
        is_valid=len(reasons) == 0,
        failure_reasons=tuple(reasons),
        validated_at=validated_at,
        validator_version=_VALIDATOR_VERSION,
    )


# ---------------------------------------------------------------------------
# Framework mapping validation
# ---------------------------------------------------------------------------


def validate_framework_mapping(
    framework_mapping: FrameworkMapping,
    *,
    validation_id: str,
    validated_at: datetime,
) -> MappingValidationRecord:
    """Validate a FrameworkMapping (collection-level validation).

    Checks performed:
    - Scope-tenant consistency: TENANT scope requires non-None tenant_id.
    - Framework ID consistency: all relationships must have framework IDs
      matching the FrameworkMapping's declared source/target framework IDs.
    - Duplicate relationship detection: (source_control_id, target_control_id,
      relationship_type) must be unique within the mapping set.
    - Cyclic inheritance detection: inheritance graph must be acyclic.

    Each category of failure emits exactly one reason code regardless of how
    many individual violations exist (avoids reason code explosion).
    """
    reasons: list[str] = []

    if (
        framework_mapping.scope == MappingScope.TENANT
        and framework_mapping.tenant_id is None
    ):
        reasons.append(REASON_SCOPE_TENANT_MISMATCH)

    framework_id_mismatch = any(
        rel.source_framework_id != framework_mapping.source_framework_id
        or rel.target_framework_id != framework_mapping.target_framework_id
        for rel in framework_mapping.relationships
    )
    if framework_id_mismatch:
        reasons.append(REASON_FRAMEWORK_ID_MISMATCH)

    seen: set[tuple[str, str, str]] = set()
    for rel in framework_mapping.relationships:
        key = (
            rel.source_control_id,
            rel.target_control_id,
            rel.relationship_type.value,
        )
        if key in seen:
            reasons.append(REASON_DUPLICATE_RELATIONSHIP)
            break
        seen.add(key)

    if detect_cyclic_inheritance(framework_mapping.inheritances):
        reasons.append(REASON_CYCLIC_INHERITANCE)

    return MappingValidationRecord(
        validation_id=validation_id,
        subject_id=framework_mapping.framework_mapping_id,
        validation_type=MappingValidationType.FRAMEWORK,
        is_valid=len(reasons) == 0,
        failure_reasons=tuple(reasons),
        validated_at=validated_at,
        validator_version=_VALIDATOR_VERSION,
    )


# ---------------------------------------------------------------------------
# Mapping version validation
# ---------------------------------------------------------------------------


def validate_mapping_version(
    version: FrameworkMappingVersion,
    *,
    validation_id: str,
    validated_at: datetime,
) -> MappingValidationRecord:
    """Validate a FrameworkMappingVersion record.

    Checks performed:
    - mapping_version_tag must not be empty or whitespace-only.
    - superseded_by must not reference the version's own mapping_version_id.
    """
    reasons: list[str] = []

    if not version.mapping_version_tag.strip():
        reasons.append(REASON_VERSION_TAG_EMPTY)

    if (
        version.superseded_by is not None
        and version.superseded_by == version.mapping_version_id
    ):
        reasons.append(REASON_SELF_SUPERSESSION)

    return MappingValidationRecord(
        validation_id=validation_id,
        subject_id=version.mapping_version_id,
        validation_type=MappingValidationType.VERSION,
        is_valid=len(reasons) == 0,
        failure_reasons=tuple(reasons),
        validated_at=validated_at,
        validator_version=_VALIDATOR_VERSION,
    )


# ---------------------------------------------------------------------------
# Gap detection
# ---------------------------------------------------------------------------


def detect_unmapped_controls(
    control_ids: tuple[str, ...],
    framework_id: str,
    framework_version: str,
    relationships: tuple[MappingRelationship, ...],
    *,
    detected_at: datetime,
) -> tuple[MappingGapRecord, ...]:
    """Detect controls that have no outbound relationships to any target framework.

    A control is UNMAPPED if it does not appear as the source of any relationship
    where source_framework_id and source_framework_version match.

    Gap IDs are deterministic: "{framework_id}::{control_id}::unmapped".
    """
    mapped_sources: set[str] = {
        rel.source_control_id
        for rel in relationships
        if rel.source_framework_id == framework_id
        and rel.source_framework_version == framework_version
    }

    gaps: list[MappingGapRecord] = []
    for control_id in control_ids:
        if control_id not in mapped_sources:
            gaps.append(
                MappingGapRecord(
                    gap_id=f"{framework_id}::{control_id}::unmapped",
                    control_id=control_id,
                    framework_id=framework_id,
                    framework_version=framework_version,
                    gap_type=MappingGapType.UNMAPPED,
                    detected_at=detected_at,
                )
            )

    return tuple(gaps)


def detect_orphaned_relationships(
    relationships: tuple[MappingRelationship, ...],
    known_control_ids: frozenset[str],
    known_framework_ids: frozenset[str],
    *,
    detected_at: datetime,
) -> tuple[MappingGapRecord, ...]:
    """Detect relationships whose source or target is not in the known registry.

    A relationship is ORPHANED if its source_control_id, source_framework_id,
    target_control_id, or target_framework_id is not present in the provided
    known sets.

    Gap IDs are deterministic: "{relationship_id}::orphaned".
    """
    orphans: list[MappingGapRecord] = []
    for rel in relationships:
        is_orphan = (
            rel.source_control_id not in known_control_ids
            or rel.source_framework_id not in known_framework_ids
            or rel.target_control_id not in known_control_ids
            or rel.target_framework_id not in known_framework_ids
        )
        if is_orphan:
            orphans.append(
                MappingGapRecord(
                    gap_id=f"{rel.relationship_id}::orphaned",
                    control_id=rel.source_control_id,
                    framework_id=rel.source_framework_id,
                    framework_version=rel.source_framework_version,
                    gap_type=MappingGapType.ORPHANED,
                    detected_at=detected_at,
                )
            )

    return tuple(orphans)


def detect_missing_inheritance_targets(
    inheritances: tuple[ControlInheritance, ...],
    known_control_ids: frozenset[str],
    *,
    detected_at: datetime,
) -> tuple[MappingGapRecord, ...]:
    """Detect inheritances whose parent control is not in the known registry.

    Gap IDs are deterministic: "{inheritance_id}::missing_target".
    """
    gaps: list[MappingGapRecord] = []
    for inh in inheritances:
        if inh.parent_control_id not in known_control_ids:
            gaps.append(
                MappingGapRecord(
                    gap_id=f"{inh.inheritance_id}::missing_target",
                    control_id=inh.child_control_id,
                    framework_id=inh.child_framework_id,
                    framework_version=inh.child_framework_version,
                    gap_type=MappingGapType.MISSING_INHERITANCE_TARGET,
                    detected_at=detected_at,
                )
            )

    return tuple(gaps)
