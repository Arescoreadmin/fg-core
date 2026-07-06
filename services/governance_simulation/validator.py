"""Simulation-specific validation for overlay, diff, and impact consistency."""

from __future__ import annotations

import hashlib

from services.canonical import canonical_json_bytes
from services.governance_digital_twin.models import (
    GovernanceDigitalTwinEntity,
    GovernanceDigitalTwinRelationship,
    GovernanceDigitalTwinSnapshot,
)
from services.governance_simulation.models import (
    SCENARIO_CATEGORY_REGISTRY,
    GraphDiff,
    ImpactReport,
    OverlayOperationType,
    ScenarioOverlay,
    SimulationValidationFinding,
    SimulationValidationReport,
    SimulationValidationSeverity,
)


class SimulationValidationError(Exception):
    """Raised when simulation validation finds ERROR or FATAL severity findings."""


_INVARIANTS = (
    "orphan_overlay",
    "invalid_reference",
    "cross_tenant_violation",
    "authority_violation",
    "duplicate_op_ids",
    "relationship_violation",
    "cycle_violation",
    "invalid_scenario_category",
    "invalid_graph_mutation",
    "missing_source_snapshot",
    "replay_integrity",
)

_SEVERITY_RANK = {
    SimulationValidationSeverity.INFO.value: 0,
    SimulationValidationSeverity.WARNING.value: 1,
    SimulationValidationSeverity.ERROR.value: 2,
    SimulationValidationSeverity.FATAL.value: 3,
}


def _highest_severity(findings: list[SimulationValidationFinding]) -> str:
    if not findings:
        return SimulationValidationSeverity.INFO.value
    return max(findings, key=lambda f: _SEVERITY_RANK[f.severity]).severity


def _detect_cycle(
    entities: tuple[GovernanceDigitalTwinEntity, ...],
    relationships: tuple[GovernanceDigitalTwinRelationship, ...],
) -> bool:
    """Simple DFS cycle detection on the relationship graph."""
    graph: dict[str, list[str]] = {e.id: [] for e in entities}
    for rel in relationships:
        if rel.from_entity_id in graph:
            graph[rel.from_entity_id].append(rel.to_entity_id)

    visiting: set[str] = set()
    visited: set[str] = set()

    def dfs(node: str) -> bool:
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        for neighbor in graph.get(node, []):
            if dfs(neighbor):
                return True
        visiting.discard(node)
        visited.add(node)
        return False

    return any(dfs(node) for node in list(graph))


def _recompute_overlay_hash(overlay: ScenarioOverlay) -> str:
    from dataclasses import asdict

    ops = [asdict(op) for op in overlay.operations]
    payload = {
        "overlay_id": overlay.overlay_id,
        "scenario_id": overlay.scenario_id,
        "source_snapshot_id": overlay.source_snapshot_id,
        "source_snapshot_fingerprint": overlay.source_snapshot_fingerprint,
        "tenant_id": overlay.tenant_id,
        "operations": ops,
        "created_at": overlay.created_at,
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def validate_simulation(
    snapshot: GovernanceDigitalTwinSnapshot,
    overlay: ScenarioOverlay,
    diff: GraphDiff,
    impact_report: ImpactReport,
    *,
    derived_entities: tuple[GovernanceDigitalTwinEntity, ...] | None = None,
    derived_relationships: tuple[GovernanceDigitalTwinRelationship, ...] | None = None,
    scenario_category: str | None = None,
) -> SimulationValidationReport:
    """Validate simulation components. Raises SimulationValidationError if ERROR or FATAL found."""
    violations: list[str] = []
    findings: list[SimulationValidationFinding] = []

    snapshot_entity_ids = {e.id for e in snapshot.entities}
    snapshot_relationship_ids = {r.id for r in snapshot.relationships}
    derived_entity_ids = (
        {e.id for e in derived_entities}
        if derived_entities is not None
        else snapshot_entity_ids
    )

    # missing_source_snapshot (FATAL)
    if not overlay.source_snapshot_id:
        violations.append("missing_source_snapshot")
        findings.append(
            SimulationValidationFinding(
                severity=SimulationValidationSeverity.FATAL.value,
                code="missing_source_snapshot",
                message="overlay.source_snapshot_id is empty",
            )
        )

    # duplicate_op_ids (ERROR)
    op_ids = [op.op_id for op in overlay.operations]
    if len(op_ids) != len(set(op_ids)):
        violations.append("duplicate_op_ids")
        findings.append(
            SimulationValidationFinding(
                severity=SimulationValidationSeverity.ERROR.value,
                code="duplicate_op_ids",
                message="overlay contains duplicate op_ids",
            )
        )

    # authority_violation (ERROR)
    for op in overlay.operations:
        if not op.authority:
            violations.append("authority_violation")
            findings.append(
                SimulationValidationFinding(
                    severity=SimulationValidationSeverity.ERROR.value,
                    code="authority_violation",
                    message=f"op {op.op_id} has empty authority",
                )
            )

    for op in overlay.operations:
        op_type = op.operation_type

        # orphan_overlay / invalid_reference (ERROR)
        if op_type in (
            OverlayOperationType.remove_entity.value,
            OverlayOperationType.modify_entity.value,
        ):
            eid = op.source_entity_id
            if eid and eid not in snapshot_entity_ids:
                violations.append(f"orphan_overlay:{eid}")
                findings.append(
                    SimulationValidationFinding(
                        severity=SimulationValidationSeverity.ERROR.value,
                        code=f"orphan_overlay:{eid}",
                        message=f"op {op.op_id}: entity '{eid}' not in snapshot",
                    )
                )

        if op_type in (
            OverlayOperationType.remove_relationship.value,
            OverlayOperationType.modify_relationship.value,
        ):
            rid = op.source_relationship_id
            if rid and rid not in snapshot_relationship_ids:
                violations.append(f"invalid_reference:{rid}")
                findings.append(
                    SimulationValidationFinding(
                        severity=SimulationValidationSeverity.ERROR.value,
                        code=f"invalid_reference:{rid}",
                        message=f"op {op.op_id}: relationship '{rid}' not in snapshot",
                    )
                )

        # invalid_graph_mutation (ERROR)
        if op_type == OverlayOperationType.modify_entity.value:
            eid = op.source_entity_id
            if eid and eid not in snapshot_entity_ids:
                violations.append(f"invalid_graph_mutation:{eid}")
                findings.append(
                    SimulationValidationFinding(
                        severity=SimulationValidationSeverity.ERROR.value,
                        code=f"invalid_graph_mutation:{eid}",
                        message=f"op {op.op_id}: modify on nonexistent entity '{eid}'",
                    )
                )

        # cross_tenant_violation (FATAL)
        if op_type == OverlayOperationType.add_entity.value and op.entity_payload:
            payload_tenant = op.entity_payload.get("tenant_scope")
            if payload_tenant and payload_tenant != snapshot.tenant_id:
                violations.append("cross_tenant_violation")
                findings.append(
                    SimulationValidationFinding(
                        severity=SimulationValidationSeverity.FATAL.value,
                        code="cross_tenant_violation",
                        message=(
                            f"op {op.op_id}: entity tenant_scope '{payload_tenant}' "
                            f"!= snapshot tenant '{snapshot.tenant_id}'"
                        ),
                    )
                )

        # relationship_violation (ERROR): add_relationship references nonexistent entity in derived set
        if (
            op_type == OverlayOperationType.add_relationship.value
            and op.relationship_payload
        ):
            from_id = op.relationship_payload.get("from_entity_id")
            to_id = op.relationship_payload.get("to_entity_id")
            if from_id and from_id not in derived_entity_ids:
                violations.append(f"relationship_violation:from:{from_id}")
                findings.append(
                    SimulationValidationFinding(
                        severity=SimulationValidationSeverity.ERROR.value,
                        code=f"relationship_violation:from:{from_id}",
                        message=f"op {op.op_id}: add_relationship from_entity_id '{from_id}' not in derived entities",
                    )
                )
            if to_id and to_id not in derived_entity_ids:
                violations.append(f"relationship_violation:to:{to_id}")
                findings.append(
                    SimulationValidationFinding(
                        severity=SimulationValidationSeverity.ERROR.value,
                        code=f"relationship_violation:to:{to_id}",
                        message=f"op {op.op_id}: add_relationship to_entity_id '{to_id}' not in derived entities",
                    )
                )

    # cycle_violation (WARNING)
    if derived_entities is not None and derived_relationships is not None:
        if _detect_cycle(derived_entities, derived_relationships):
            violations.append("cycle_violation")
            findings.append(
                SimulationValidationFinding(
                    severity=SimulationValidationSeverity.WARNING.value,
                    code="cycle_violation",
                    message="derived graph contains a cycle",
                )
            )

    # invalid_scenario_category (ERROR)
    if (
        scenario_category is not None
        and scenario_category not in SCENARIO_CATEGORY_REGISTRY
    ):
        violations.append("invalid_scenario_category")
        findings.append(
            SimulationValidationFinding(
                severity=SimulationValidationSeverity.ERROR.value,
                code="invalid_scenario_category",
                message=f"scenario category '{scenario_category}' not in registry",
            )
        )

    # replay_integrity (WARNING)
    recomputed_hash = _recompute_overlay_hash(overlay)
    if overlay.overlay_hash != recomputed_hash:
        violations.append("replay_integrity")
        findings.append(
            SimulationValidationFinding(
                severity=SimulationValidationSeverity.WARNING.value,
                code="replay_integrity",
                message="overlay_hash does not match recomputed hash",
            )
        )

    # Deduplicate by code
    seen_codes: set[str] = set()
    deduped: list[SimulationValidationFinding] = []
    for f in findings:
        if f.code not in seen_codes:
            seen_codes.add(f.code)
            deduped.append(f)

    highest = _highest_severity(deduped)
    valid = highest not in {
        SimulationValidationSeverity.ERROR.value,
        SimulationValidationSeverity.FATAL.value,
    }

    report = SimulationValidationReport(
        valid=valid,
        findings=tuple(sorted(deduped, key=lambda f: f.code)),
        highest_severity=highest,
        violations=tuple(sorted(set(violations))),
        checked_invariants=_INVARIANTS,
    )

    if not valid:
        raise SimulationValidationError(
            f"Simulation validation failed: highest_severity={highest}, "
            f"violations={sorted(set(violations))}"
        )

    return report
