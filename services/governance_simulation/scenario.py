"""Scenario builder: construct a SimulationScenario from a snapshot and raw operation dicts."""

from __future__ import annotations

import hashlib
from dataclasses import asdict
from typing import Any

from services.canonical import canonical_json_bytes, utc_iso8601_z_now
from services.governance_digital_twin.models import GovernanceDigitalTwinSnapshot
from services.governance_simulation.models import (
    GOVERNANCE_SIMULATION_GRAPH_SCHEMA_VERSION,
    GOVERNANCE_SIMULATION_REPLAY_VERSION,
    GOVERNANCE_SIMULATION_SIMULATOR_VERSION,
    GOVERNANCE_SIMULATION_VERSION,
    SCENARIO_CATEGORY_REGISTRY,
    ScenarioOverlay,
    ScenarioOverlayOperation,
    SimulationHorizon,
    SimulationScenario,
)
from services.governance_simulation.validator import SimulationValidationError


def _build_overlay_hash(
    overlay_id: str,
    scenario_id: str,
    source_snapshot_id: str,
    source_snapshot_fingerprint: str,
    tenant_id: str,
    operations: list[ScenarioOverlayOperation],
    created_at: str,
) -> str:
    ops = [asdict(op) for op in operations]
    payload = {
        "overlay_id": overlay_id,
        "scenario_id": scenario_id,
        "source_snapshot_id": source_snapshot_id,
        "source_snapshot_fingerprint": source_snapshot_fingerprint,
        "tenant_id": tenant_id,
        "operations": ops,
        "created_at": created_at,
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def build_scenario(
    snapshot: GovernanceDigitalTwinSnapshot,
    scenario_name: str,
    category: str,
    operations: list[dict[str, Any]],
    *,
    created_from: str = "system:governance_simulation",
    horizon: str = SimulationHorizon.immediate.value,
    template_id: str | None = None,
) -> SimulationScenario:
    """Build a SimulationScenario from a snapshot and raw operation dicts.

    Raises SimulationValidationError on invalid inputs.
    """
    if snapshot is None:
        raise SimulationValidationError("snapshot must not be None")

    if category not in SCENARIO_CATEGORY_REGISTRY:
        raise SimulationValidationError(
            f"scenario category '{category}' is not in SCENARIO_CATEGORY_REGISTRY"
        )

    created_at = utc_iso8601_z_now()

    # scenario_id: deterministic from tenant/snapshot/name/category/time
    scenario_id_seed = f"SCENARIO:{snapshot.tenant_id}:{snapshot.snapshot_id}:{scenario_name}:{category}:{created_at}"
    scenario_id = hashlib.sha256(scenario_id_seed.encode()).hexdigest()[:24]

    overlay_ops: list[ScenarioOverlayOperation] = []
    for raw_op in operations:
        op = ScenarioOverlayOperation(
            op_id=raw_op.get("op_id", ""),
            operation_type=raw_op.get("operation_type", ""),
            source_entity_id=raw_op.get("source_entity_id"),
            target_entity_id=raw_op.get("target_entity_id"),
            source_relationship_id=raw_op.get("source_relationship_id"),
            entity_payload=raw_op.get("entity_payload"),
            relationship_payload=raw_op.get("relationship_payload"),
            reason=raw_op.get("reason", ""),
            authoritative_basis=raw_op.get("authoritative_basis", ""),
            authority=raw_op.get("authority", ""),
        )
        overlay_ops.append(op)

    # overlay_id: deterministic from scenario + snapshot
    overlay_id_seed = f"OVERLAY:{scenario_id}:{snapshot.snapshot_id}:{created_at}"
    overlay_id = hashlib.sha256(overlay_id_seed.encode()).hexdigest()[:24]

    overlay_hash = _build_overlay_hash(
        overlay_id=overlay_id,
        scenario_id=scenario_id,
        source_snapshot_id=snapshot.snapshot_id,
        source_snapshot_fingerprint=snapshot.fingerprint,
        tenant_id=snapshot.tenant_id,
        operations=overlay_ops,
        created_at=created_at,
    )

    overlay = ScenarioOverlay(
        overlay_id=overlay_id,
        scenario_id=scenario_id,
        source_snapshot_id=snapshot.snapshot_id,
        source_snapshot_fingerprint=snapshot.fingerprint,
        tenant_id=snapshot.tenant_id,
        operations=tuple(overlay_ops),
        created_at=created_at,
        overlay_hash=overlay_hash,
    )

    # Preliminary fingerprint: diff and impact not yet computed — use zero placeholders
    preliminary_fp_payload = {
        "domain": "FG_GOVERNANCE_SIMULATION_V1",
        "scenario_version": GOVERNANCE_SIMULATION_VERSION,
        "overlay_hash": overlay_hash,
        "diff_hash": "0" * 64,
        "impact_hash": "0" * 64,
        "builder_version": GOVERNANCE_SIMULATION_SIMULATOR_VERSION,
        "graph_schema_version": GOVERNANCE_SIMULATION_GRAPH_SCHEMA_VERSION,
        "simulation_version": GOVERNANCE_SIMULATION_VERSION,
    }
    preliminary_fingerprint = hashlib.sha256(
        canonical_json_bytes(preliminary_fp_payload)
    ).hexdigest()

    return SimulationScenario(
        scenario_id=scenario_id,
        parent_snapshot_id=snapshot.snapshot_id,
        source_snapshot_fingerprint=snapshot.fingerprint,
        scenario_name=scenario_name,
        category=category,
        created_from=created_from,
        scenario_version=GOVERNANCE_SIMULATION_VERSION,
        graph_schema_version=GOVERNANCE_SIMULATION_GRAPH_SCHEMA_VERSION,
        simulator_version=GOVERNANCE_SIMULATION_SIMULATOR_VERSION,
        replay_version=GOVERNANCE_SIMULATION_REPLAY_VERSION,
        created_at=created_at,
        simulation_fingerprint=preliminary_fingerprint,
        overlay=overlay,
        tenant_id=snapshot.tenant_id,
        horizon=horizon,
        template_id=template_id,
    )
