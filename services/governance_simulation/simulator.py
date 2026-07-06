"""Main simulation orchestrator: apply overlay, compute diff, analyze impact, validate, package."""

from __future__ import annotations

import dataclasses
import hashlib
import time

from services.canonical import canonical_json_bytes, utc_iso8601_z_now
from services.governance_digital_twin.models import GovernanceDigitalTwinSnapshot
from services.governance_simulation.diff import compute_graph_diff
from services.governance_simulation.fingerprint import (
    compute_comparison_hash,
    compute_scenario_fingerprint,
)
from services.governance_simulation.impact import analyze_impact
from services.governance_simulation.models import (
    GOVERNANCE_SIMULATION_GRAPH_SCHEMA_VERSION,
    GOVERNANCE_SIMULATION_SIMULATOR_VERSION,
    GOVERNANCE_SIMULATION_VERSION,
    ExecutiveComparison,
    ExecutiveComparisonRow,
    GraphDiff,
    GraphDiffEntry,
    ImpactConfidence,
    ImpactReport,
    ScenarioOverlay,
    SimulationResult,
    SimulationRun,
    SimulationScenario,
    SimulationValidationReport,
)
from services.governance_simulation.overlay import apply_overlay
from services.governance_simulation.replay import build_replay_package
from services.governance_simulation.validator import validate_simulation


def _build_comparison_row(
    entry: GraphDiffEntry,
    scenario: SimulationScenario,
) -> ExecutiveComparisonRow | None:
    """Build one ExecutiveComparisonRow from a diff entry."""
    if entry.operation not in {"added", "removed", "modified"}:
        return None

    object_id = entry.entity_id or entry.relationship_id or "unknown"

    # Determine object type from before/after
    object_type = "unknown"
    if entry.before and isinstance(entry.before, dict):
        object_type = entry.before.get("type", "unknown")
    elif entry.after and isinstance(entry.after, dict):
        object_type = entry.after.get("type", "unknown")

    # current_value = entity status before change
    current_value: str | None = None
    if entry.before and isinstance(entry.before, dict):
        current_value = entry.before.get("status") or entry.before.get("type")

    # scenario_value = entity status after change
    scenario_value: str | None = None
    if entry.after and isinstance(entry.after, dict):
        scenario_value = entry.after.get("status") or entry.after.get("type")

    # delta description
    if entry.operation == "added":
        delta = f"added:{scenario_value or 'new'}"
    elif entry.operation == "removed":
        delta = f"removed:{current_value or 'gone'}"
    else:
        if current_value != scenario_value:
            delta = f"{current_value}->{scenario_value}"
        else:
            delta = "modified"

    # Collect evidence ids from before/after
    evidence_ids: list[str] = []
    if entry.before and isinstance(entry.before, dict):
        evidence_ids.extend(entry.before.get("evidence_refs", []))
    if entry.after and isinstance(entry.after, dict):
        evidence_ids.extend(entry.after.get("evidence_refs", []))

    return ExecutiveComparisonRow(
        object_id=object_id,
        object_type=object_type,
        domain=entry.domain,
        current_value=current_value,
        scenario_value=scenario_value,
        delta=delta,
        evidence_ids=tuple(sorted(set(evidence_ids))),
        reason=entry.reason,
        confidence=ImpactConfidence.INFERRED.value,
        authority=entry.authority,
        limitations=(),
    )


def _build_executive_comparison(
    diff: GraphDiff,
    scenario: SimulationScenario,
) -> ExecutiveComparison:
    """Build executive comparison rows from a graph diff."""
    rows: list[ExecutiveComparisonRow] = []
    for entry in diff.entries:
        row = _build_comparison_row(entry, scenario)
        if row is not None:
            rows.append(row)

    sorted_rows = tuple(sorted(rows, key=lambda r: r.object_id))

    comparison_id_seed = f"COMPARISON:{scenario.scenario_id}:{diff.diff_hash}"
    comparison_id = hashlib.sha256(comparison_id_seed.encode()).hexdigest()[:24]

    # Compute net summary counts
    net_positive = sum(1 for r in sorted_rows if r.delta and r.delta.startswith("added:"))
    net_negative = sum(1 for r in sorted_rows if r.delta and r.delta.startswith("removed:"))
    neutral = sum(1 for r in sorted_rows if r.delta == "modified")
    unknown_count = sum(1 for r in sorted_rows if r.confidence == ImpactConfidence.UNKNOWN.value)

    comparison = ExecutiveComparison(
        comparison_id=comparison_id,
        scenario_id=scenario.scenario_id,
        rows=sorted_rows,
        comparison_hash="",  # placeholder
        created_at=utc_iso8601_z_now(),
        net_positive=net_positive,
        net_negative=net_negative,
        neutral=neutral,
        unknown_count=unknown_count,
    )

    # Compute comparison_hash
    rows_dicts = sorted(
        (dataclasses.asdict(r) for r in sorted_rows),
        key=lambda x: x["object_id"],
    )
    comparison_hash = hashlib.sha256(canonical_json_bytes(rows_dicts)).hexdigest()

    # Replace with real hash
    comparison = dataclasses.replace(comparison, comparison_hash=comparison_hash)
    return comparison


def _finalize_scenario_fingerprint(
    scenario: SimulationScenario,
    overlay: ScenarioOverlay,
    diff: GraphDiff,
    impact_report: ImpactReport,
) -> str:
    """Compute the final scenario fingerprint after diff and impact are known."""
    return compute_scenario_fingerprint(
        scenario_version=scenario.scenario_version,
        overlay=overlay,
        diff=diff,
        impact_report=impact_report,
        builder_version=GOVERNANCE_SIMULATION_SIMULATOR_VERSION,
        graph_schema_version=GOVERNANCE_SIMULATION_GRAPH_SCHEMA_VERSION,
        simulation_version=GOVERNANCE_SIMULATION_VERSION,
    )


def simulate(
    snapshot: GovernanceDigitalTwinSnapshot,
    scenario: SimulationScenario,
) -> SimulationResult:
    """Main simulation entry point.

    Applies overlay → derives entities/relationships.
    Computes diff → analyzes impact → builds executive comparison.
    Runs validation (fail closed on ERROR/FATAL).
    Computes final fingerprint → builds replay package.
    Returns SimulationResult.

    Raises SimulationValidationError if validation finds ERROR or FATAL.
    """
    build_start = time.monotonic()
    overlay = scenario.overlay

    # 1. Apply overlay — derive entities/relationships
    derived_entities, derived_relationships = apply_overlay(snapshot, overlay)

    # 2. Compute deterministic diff
    diff = compute_graph_diff(
        snapshot, derived_entities, derived_relationships, scenario.scenario_id
    )

    # 3. Analyze impact
    impact_report = analyze_impact(snapshot, diff, scenario.scenario_id)

    # 4. Build executive comparison
    comparison = _build_executive_comparison(diff, scenario)

    # 5. Validate (fail closed — raises SimulationValidationError on ERROR/FATAL)
    val_start = time.monotonic()
    validation_report = validate_simulation(
        snapshot,
        overlay,
        diff,
        impact_report,
        derived_entities=derived_entities,
        derived_relationships=derived_relationships,
        scenario_category=scenario.category,
    )
    validation_duration_ms = int((time.monotonic() - val_start) * 1000)

    # 6. Compute final fingerprint
    final_fingerprint = _finalize_scenario_fingerprint(scenario, overlay, diff, impact_report)

    # 7. Update scenario with final fingerprint
    final_scenario = dataclasses.replace(scenario, simulation_fingerprint=final_fingerprint)

    # Compute manifest metrics
    objects_evaluated = len(snapshot.entities) + len(snapshot.relationships)
    objects_changed = len(diff.entries)
    objects_unaffected = max(0, objects_evaluated - objects_changed)
    num_ops = len(overlay.operations)
    if num_ops <= 3:
        simulation_complexity = "low"
    elif num_ops <= 10:
        simulation_complexity = "medium"
    else:
        simulation_complexity = "high"

    build_duration_ms = int((time.monotonic() - build_start) * 1000)

    manifest_metrics = {
        "simulation_complexity": simulation_complexity,
        "objects_evaluated": objects_evaluated,
        "objects_changed": objects_changed,
        "objects_unaffected": objects_unaffected,
        "validation_duration_ms": validation_duration_ms,
        "build_duration_ms": build_duration_ms,
    }

    # 8. Build replay package
    replay_package = build_replay_package(
        scenario=final_scenario,
        overlay=overlay,
        diff=diff,
        impact_report=impact_report,
        comparison=comparison,
        validation_report=validation_report,
        source_snapshot_fingerprint=snapshot.fingerprint,
        tenant_id=snapshot.tenant_id,
        manifest_metrics=manifest_metrics,
    )

    return SimulationResult(
        scenario=final_scenario,
        overlay=overlay,
        diff=diff,
        impact_report=impact_report,
        comparison=comparison,
        validation_report=validation_report,
        replay_package=replay_package,
        simulation_fingerprint=final_fingerprint,
    )


def run_simulation(
    snapshot: GovernanceDigitalTwinSnapshot,
    scenario: SimulationScenario,
) -> SimulationRun:
    """Run a simulation and wrap the result in a SimulationRun with a unique run_id."""
    result = simulate(snapshot, scenario)
    run_id = hashlib.sha256(
        f"RUN:{scenario.scenario_id}:{snapshot.snapshot_id}:{result.simulation_fingerprint}".encode()
    ).hexdigest()[:24]
    return SimulationRun(
        run_id=run_id,
        scenario_id=scenario.scenario_id,
        snapshot_id=snapshot.snapshot_id,
        snapshot_fingerprint=snapshot.fingerprint,
        tenant_id=snapshot.tenant_id,
        run_at=utc_iso8601_z_now(),
        horizon=scenario.horizon,
        simulator_version=scenario.simulator_version,
        result=result,
    )
