"""Replay package builder: assemble all simulation components into a ReplayPackage."""

from __future__ import annotations

import hashlib

from services.canonical import utc_iso8601_z_now
from services.governance_simulation.fingerprint import compute_replay_fingerprint
from services.governance_simulation.models import (
    GOVERNANCE_SIMULATION_MCIM_VERSION,
    GOVERNANCE_SIMULATION_REPLAY_VERSION,
    GOVERNANCE_SIMULATION_VERSION,
    ExecutiveComparison,
    GraphDiff,
    ImpactReport,
    ReplayPackage,
    ScenarioOverlay,
    SimulationManifest,
    SimulationScenario,
    SimulationValidationReport,
)


def build_replay_package(
    scenario: SimulationScenario,
    overlay: ScenarioOverlay,
    diff: GraphDiff,
    impact_report: ImpactReport,
    comparison: ExecutiveComparison,
    validation_report: SimulationValidationReport,
    source_snapshot_fingerprint: str,
    tenant_id: str,
    manifest_metrics: dict | None = None,
) -> ReplayPackage:
    """Assemble all simulation components into a ReplayPackage.

    The package is self-contained: it can be used to regenerate the simulation deterministically.
    """
    created_at = utc_iso8601_z_now()

    lineage = f"sim:{scenario.scenario_id}:snap:{scenario.parent_snapshot_id}"

    # Extract manifest metrics with defaults
    metrics = manifest_metrics or {}
    simulation_complexity: str = metrics.get("simulation_complexity", "low")
    objects_evaluated: int = metrics.get("objects_evaluated", 0)
    objects_changed: int = metrics.get("objects_changed", 0)
    objects_unaffected: int = metrics.get("objects_unaffected", 0)
    validation_duration_ms: int | None = metrics.get("validation_duration_ms", None)
    build_duration_ms: int | None = metrics.get("build_duration_ms", None)

    manifest = SimulationManifest(
        manifest_schema_version="1.0",
        scenario_id=scenario.scenario_id,
        source_snapshot_id=scenario.parent_snapshot_id,
        source_snapshot_fingerprint=source_snapshot_fingerprint,
        scenario_name=scenario.scenario_name,
        scenario_category=scenario.category,
        simulation_version=GOVERNANCE_SIMULATION_VERSION,
        graph_schema_version=scenario.graph_schema_version,
        simulator_version=scenario.simulator_version,
        replay_version=GOVERNANCE_SIMULATION_REPLAY_VERSION,
        tenant_id=tenant_id,
        created_at=created_at,
        simulation_fingerprint=scenario.simulation_fingerprint,
        overlay_hash=overlay.overlay_hash,
        diff_hash=diff.diff_hash,
        impact_hash=impact_report.report_hash,
        comparison_hash=comparison.comparison_hash,
        mcim_version=GOVERNANCE_SIMULATION_MCIM_VERSION,
        lineage=lineage,
        simulation_complexity=simulation_complexity,
        objects_evaluated=objects_evaluated,
        objects_changed=objects_changed,
        objects_unaffected=objects_unaffected,
        validation_duration_ms=validation_duration_ms,
        build_duration_ms=build_duration_ms,
    )

    package_id_seed = (
        f"REPLAY:{scenario.scenario_id}:{overlay.overlay_hash}:{diff.diff_hash}"
    )
    package_id = hashlib.sha256(package_id_seed.encode()).hexdigest()[:24]

    fingerprint = compute_replay_fingerprint(
        package_id=package_id,
        scenario_id=scenario.scenario_id,
        overlay_hash=overlay.overlay_hash,
        diff_hash=diff.diff_hash,
        impact_hash=impact_report.report_hash,
        tenant_id=tenant_id,
    )

    return ReplayPackage(
        package_id=package_id,
        scenario_id=scenario.scenario_id,
        source_snapshot_fingerprint=source_snapshot_fingerprint,
        manifest=manifest,
        scenario=scenario,
        overlay=overlay,
        diff=diff,
        impact_report=impact_report,
        comparison=comparison,
        validation_report=validation_report,
        fingerprint=fingerprint,
        created_at=created_at,
        mcim_version=GOVERNANCE_SIMULATION_MCIM_VERSION,
        schema_version=GOVERNANCE_SIMULATION_VERSION,
        replay_version=GOVERNANCE_SIMULATION_REPLAY_VERSION,
        lineage=lineage,
        rollback_reference=None,
        rollback_ready=False,
        rollback_dependencies=(),
    )
