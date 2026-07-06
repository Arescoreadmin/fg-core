"""Structural and replay-integrity validators for Governance Digital Twin snapshots."""

from __future__ import annotations

from collections import defaultdict

from services.governance_digital_twin.fingerprint import (
    compute_entity_hash,
    compute_metadata_hash,
    compute_relationship_hash,
)
from services.governance_digital_twin.models import (
    GOVERNANCE_DIGITAL_TWIN_VALIDATOR_VERSION,
    GovernanceDigitalTwinSnapshot,
    GovernanceDigitalTwinValidationFinding,
    GovernanceDigitalTwinValidationReport,
    GovernanceDigitalTwinValidationSeverity,
)
from services.governance_digital_twin.relationship_registry import RELATIONSHIP_REGISTRY

_REQUIRED_ROOT_AUTHORITIES = frozenset(
    {
        "field_assessment",
        "evidence_authority",
        "control_registry",
        "governance_orchestration",
    }
)
_INVARIANTS = (
    "tenant_isolation",
    "no_orphan_nodes",
    "no_broken_relationships",
    "no_duplicate_entity_ids",
    "no_duplicate_relationship_ids",
    "no_duplicate_hashes",
    "required_root_authorities_present",
    "no_circular_authority_chains",
    "relationship_cardinality_valid",
    "domain_invariants_valid",
    "replay_integrity",
)
_FATAL_PREFIXES = (
    "canonical_snapshot_id_mismatch",
    "snapshot_id_not_replay_deterministic",
    "manifest_missing",
    "manifest_fingerprint_mismatch",
    "manifest_lineage_mismatch",
    "export_snapshot_id_mismatch",
    "export_fingerprint_mismatch",
    "export_manifest_fingerprint_mismatch",
    "tenant_isolation",
    "duplicate_entity_ids",
    "duplicate_relationship_ids",
    "duplicate_hashes",
)
_ERROR_PREFIXES = (
    "orphan_relationship:",
    "self_loop_relationship:",
    "missing_root_authorities:",
    "circular_authority_chain",
    "invalid_cardinality:",
    "finding_missing_evidence:",
    "remediation_missing_finding:",
    "decision_missing_authority:",
    "unstable_evidence_refs:",
)


def _detect_authority_cycle(snapshot: GovernanceDigitalTwinSnapshot) -> bool:
    graph: dict[str, set[str]] = defaultdict(set)
    for edge in snapshot.authority_graph.dependencies:
        graph[edge.authority].add(edge.downstream_authority)

    visiting: set[str] = set()
    visited: set[str] = set()

    def walk(node: str) -> bool:
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        for child in sorted(graph.get(node, set())):
            if walk(child):
                return True
        visiting.remove(node)
        visited.add(node)
        return False

    return any(walk(node.authority) for node in snapshot.authority_graph.authorities)


def _replay_snapshot_id(snapshot: GovernanceDigitalTwinSnapshot) -> str:
    return f"gdts-{compute_metadata_hash({'tenant_id': snapshot.tenant_id, 'fingerprint': snapshot.fingerprint})[:24]}"


def _severity_for(code: str) -> str:
    if code.startswith(_FATAL_PREFIXES):
        return GovernanceDigitalTwinValidationSeverity.FATAL.value
    if code.startswith(_ERROR_PREFIXES):
        return GovernanceDigitalTwinValidationSeverity.ERROR.value
    return GovernanceDigitalTwinValidationSeverity.WARNING.value


def _highest_severity(findings: list[GovernanceDigitalTwinValidationFinding]) -> str:
    if not findings:
        return GovernanceDigitalTwinValidationSeverity.INFO.value
    rank = {
        GovernanceDigitalTwinValidationSeverity.INFO.value: 0,
        GovernanceDigitalTwinValidationSeverity.WARNING.value: 1,
        GovernanceDigitalTwinValidationSeverity.ERROR.value: 2,
        GovernanceDigitalTwinValidationSeverity.FATAL.value: 3,
    }
    return max(findings, key=lambda finding: rank[finding.severity]).severity


def validate_governance_digital_twin_snapshot(
    snapshot: GovernanceDigitalTwinSnapshot,
    *,
    require_replay_integrity: bool = True,
) -> GovernanceDigitalTwinValidationReport:
    violations: list[str] = []
    entity_ids = [entity.id for entity in snapshot.entities]
    relationship_ids = [relationship.id for relationship in snapshot.relationships]
    entity_by_id = {entity.id: entity for entity in snapshot.entities}
    entity_hashes = [compute_entity_hash(entity) for entity in snapshot.entities]
    relationship_hashes = [compute_relationship_hash(relationship) for relationship in snapshot.relationships]

    if any(entity.tenant_scope != snapshot.tenant_id for entity in snapshot.entities):
        violations.append("tenant_isolation")
    if len(entity_ids) != len(set(entity_ids)):
        violations.append("duplicate_entity_ids")
    if len(relationship_ids) != len(set(relationship_ids)):
        violations.append("duplicate_relationship_ids")
    if len(entity_hashes) != len(set(entity_hashes)) or len(relationship_hashes) != len(set(relationship_hashes)):
        violations.append("duplicate_hashes")

    for relationship in snapshot.relationships:
        if relationship.from_entity_id not in entity_by_id or relationship.to_entity_id not in entity_by_id:
            violations.append(f"orphan_relationship:{relationship.id}")
        if relationship.from_entity_id == relationship.to_entity_id:
            violations.append(f"self_loop_relationship:{relationship.id}")
        if tuple(sorted(set(relationship.evidence_refs))) != relationship.evidence_refs:
            violations.append(f"unstable_evidence_refs:{relationship.id}")

    authorities = {source.authority for source in snapshot.source_authorities}
    missing_roots = sorted(_REQUIRED_ROOT_AUTHORITIES - authorities)
    if missing_roots:
        violations.append("missing_root_authorities:" + ",".join(missing_roots))

    if _detect_authority_cycle(snapshot):
        violations.append("circular_authority_chain")

    rel_targets: dict[tuple[str, str], set[str]] = defaultdict(set)
    for relationship in snapshot.relationships:
        rel_targets[(relationship.type, relationship.from_entity_id)].add(relationship.to_entity_id)
    for (rel_type, from_entity_id), targets in rel_targets.items():
        spec = RELATIONSHIP_REGISTRY.get(rel_type)
        if spec and spec.max_targets_per_source is not None and len(targets) > spec.max_targets_per_source:
            violations.append(f"invalid_cardinality:{rel_type}:{from_entity_id}")

    for entity in snapshot.entities:
        if entity.type == "finding":
            has_evidence = any(
                relationship.from_entity_id == entity.id and entity_by_id.get(relationship.to_entity_id, None) and entity_by_id[relationship.to_entity_id].type == "evidence"
                for relationship in snapshot.relationships
            )
            if not has_evidence:
                violations.append(f"finding_missing_evidence:{entity.id}")
        if entity.type == "remediation":
            has_finding = any(
                relationship.from_entity_id == entity.id and entity_by_id.get(relationship.to_entity_id, None) and entity_by_id[relationship.to_entity_id].type == "finding"
                for relationship in snapshot.relationships
            )
            if not has_finding:
                violations.append(f"remediation_missing_finding:{entity.id}")
        if entity.type == "decision" and not entity.authority:
            violations.append(f"decision_missing_authority:{entity.id}")

    replay_integrity = True
    if require_replay_integrity:
        if snapshot.canonical_snapshot_id != snapshot.snapshot_id:
            violations.append("canonical_snapshot_id_mismatch")
            replay_integrity = False
        if snapshot.snapshot_id != _replay_snapshot_id(snapshot):
            violations.append("snapshot_id_not_replay_deterministic")
            replay_integrity = False
        if snapshot.manifest is None:
            violations.append("manifest_missing")
            replay_integrity = False
        else:
            if snapshot.manifest.fingerprint != snapshot.fingerprint:
                violations.append("manifest_fingerprint_mismatch")
                replay_integrity = False
            if snapshot.manifest.lineage_id != snapshot.lineage_id:
                violations.append("manifest_lineage_mismatch")
                replay_integrity = False
        export = snapshot.replay_safe_export
        if export:
            if export.get("snapshot_id") != snapshot.snapshot_id:
                violations.append("export_snapshot_id_mismatch")
                replay_integrity = False
            if export.get("fingerprint") != snapshot.fingerprint:
                violations.append("export_fingerprint_mismatch")
                replay_integrity = False
            manifest = export.get("manifest")
            if manifest and manifest.get("fingerprint") != snapshot.fingerprint:
                violations.append("export_manifest_fingerprint_mismatch")
                replay_integrity = False
    else:
        replay_integrity = False

    findings = [
        GovernanceDigitalTwinValidationFinding(
            severity=_severity_for(code),
            code=code,
            message=code.replace(":", " "),
        )
        for code in sorted(set(violations))
    ]
    findings.extend(
        GovernanceDigitalTwinValidationFinding(
            severity=GovernanceDigitalTwinValidationSeverity.WARNING.value,
            code="snapshot_warning",
            message=warning,
        )
        for warning in snapshot.warnings
    )
    findings.extend(
        GovernanceDigitalTwinValidationFinding(
            severity=GovernanceDigitalTwinValidationSeverity.INFO.value,
            code="snapshot_limitation",
            message=limitation,
        )
        for limitation in snapshot.limitations
    )

    highest_severity = _highest_severity(findings)
    valid = highest_severity not in {
        GovernanceDigitalTwinValidationSeverity.ERROR.value,
        GovernanceDigitalTwinValidationSeverity.FATAL.value,
    }

    return GovernanceDigitalTwinValidationReport(
        validator_version=GOVERNANCE_DIGITAL_TWIN_VALIDATOR_VERSION,
        valid=valid,
        checked_invariants=_INVARIANTS,
        violations=tuple(sorted(set(violations))),
        findings=tuple(findings),
        highest_severity=highest_severity,
        hash_uniqueness=(len(entity_hashes) == len(set(entity_hashes)) and len(relationship_hashes) == len(set(relationship_hashes))),
        replay_integrity=replay_integrity,
    )
