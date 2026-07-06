"""Overlay engine: apply ScenarioOverlay operations onto a snapshot to produce a derived state."""

from __future__ import annotations

import dataclasses
import hashlib

from services.canonical import canonical_json_bytes, utc_iso8601_z_now
from services.governance_digital_twin.models import (
    GovernanceDigitalTwinEntity,
    GovernanceDigitalTwinRelationship,
    GovernanceDigitalTwinSnapshot,
)
from services.governance_simulation.models import (
    OverlayOperationType,
    ScenarioOverlay,
    ScenarioOverlayOperation,
)
from services.governance_simulation.validator import SimulationValidationError


def apply_overlay(
    snapshot: GovernanceDigitalTwinSnapshot,
    overlay: ScenarioOverlay,
) -> tuple[
    tuple[GovernanceDigitalTwinEntity, ...],
    tuple[GovernanceDigitalTwinRelationship, ...],
]:
    """Apply overlay operations onto snapshot entities/relationships.

    Returns a new (entities, relationships) tuple — the snapshot itself is never mutated.
    Raises OverlayError on invalid operations.
    """
    entities_by_id: dict[str, GovernanceDigitalTwinEntity] = {
        e.id: e for e in snapshot.entities
    }
    relationships_by_id: dict[str, GovernanceDigitalTwinRelationship] = {
        r.id: r for r in snapshot.relationships
    }

    for op in overlay.operations:
        op_type = op.operation_type

        if op_type == OverlayOperationType.add_entity.value:
            if op.entity_payload is None:
                raise OverlayError(f"op {op.op_id}: add_entity requires entity_payload")
            try:
                new_entity = GovernanceDigitalTwinEntity(**dict(op.entity_payload))
            except TypeError as exc:
                raise OverlayError(
                    f"op {op.op_id}: invalid entity_payload — {exc}"
                ) from exc
            entities_by_id[new_entity.id] = new_entity

        elif op_type == OverlayOperationType.remove_entity.value:
            eid = op.source_entity_id
            if eid is None or eid not in entities_by_id:
                raise OverlayError(
                    f"op {op.op_id}: remove_entity target '{eid}' not found in snapshot"
                )
            del entities_by_id[eid]

        elif op_type == OverlayOperationType.modify_entity.value:
            eid = op.source_entity_id
            if eid is None or eid not in entities_by_id:
                raise OverlayError(
                    f"op {op.op_id}: modify_entity target '{eid}' not found in snapshot"
                )
            if op.entity_payload is None:
                raise OverlayError(
                    f"op {op.op_id}: modify_entity requires entity_payload"
                )
            existing = entities_by_id[eid]
            try:
                updated = dataclasses.replace(existing, **dict(op.entity_payload))
            except TypeError as exc:
                raise OverlayError(
                    f"op {op.op_id}: invalid modify fields — {exc}"
                ) from exc
            entities_by_id[eid] = updated

        elif op_type == OverlayOperationType.add_relationship.value:
            if op.relationship_payload is None:
                raise OverlayError(
                    f"op {op.op_id}: add_relationship requires relationship_payload"
                )
            try:
                new_rel = GovernanceDigitalTwinRelationship(
                    **dict(op.relationship_payload)
                )
            except TypeError as exc:
                raise OverlayError(
                    f"op {op.op_id}: invalid relationship_payload — {exc}"
                ) from exc
            relationships_by_id[new_rel.id] = new_rel

        elif op_type == OverlayOperationType.remove_relationship.value:
            rid = op.source_relationship_id
            if rid is None or rid not in relationships_by_id:
                raise OverlayError(
                    f"op {op.op_id}: remove_relationship target '{rid}' not found in snapshot"
                )
            del relationships_by_id[rid]

        elif op_type == OverlayOperationType.modify_relationship.value:
            rid = op.source_relationship_id
            if rid is None or rid not in relationships_by_id:
                raise OverlayError(
                    f"op {op.op_id}: modify_relationship target '{rid}' not found in snapshot"
                )
            if op.relationship_payload is None:
                raise OverlayError(
                    f"op {op.op_id}: modify_relationship requires relationship_payload"
                )
            existing_rel = relationships_by_id[rid]
            try:
                updated_rel = dataclasses.replace(
                    existing_rel, **dict(op.relationship_payload)
                )
            except TypeError as exc:
                raise OverlayError(
                    f"op {op.op_id}: invalid modify_relationship fields — {exc}"
                ) from exc
            relationships_by_id[rid] = updated_rel

        else:
            raise OverlayError(f"op {op.op_id}: unknown operation_type '{op_type}'")

    # Sort by id for determinism
    sorted_entities = tuple(sorted(entities_by_id.values(), key=lambda e: e.id))
    sorted_relationships = tuple(
        sorted(relationships_by_id.values(), key=lambda r: r.id)
    )
    return sorted_entities, sorted_relationships


class OverlayError(SimulationValidationError):
    """Raised when an overlay operation is invalid."""


def compose_overlays(
    *overlays: ScenarioOverlay,
    composed_scenario_id: str,
) -> ScenarioOverlay:
    """Compose multiple overlays into one without mutating originals.

    All overlays must share the same tenant_id and source_snapshot_id.
    Operations are applied in overlay order (left to right).
    """
    if not overlays:
        raise OverlayError("compose_overlays requires at least one overlay")
    first = overlays[0]
    for ov in overlays[1:]:
        if ov.tenant_id != first.tenant_id:
            raise OverlayError(
                f"cannot compose overlays from different tenants: "
                f"'{ov.tenant_id}' != '{first.tenant_id}'"
            )
        if ov.source_snapshot_id != first.source_snapshot_id:
            raise OverlayError(
                f"cannot compose overlays from different source snapshots: "
                f"'{ov.source_snapshot_id}' != '{first.source_snapshot_id}'"
            )
    all_ops: list[ScenarioOverlayOperation] = []
    for ov in overlays:
        all_ops.extend(ov.operations)

    created_at = utc_iso8601_z_now()
    overlay_id_seed = (
        f"COMPOSED:{composed_scenario_id}:{first.source_snapshot_id}:{created_at}"
    )
    overlay_id = hashlib.sha256(overlay_id_seed.encode()).hexdigest()[:24]

    ops_list = [dataclasses.asdict(op) for op in all_ops]
    payload = {
        "overlay_id": overlay_id,
        "scenario_id": composed_scenario_id,
        "source_snapshot_id": first.source_snapshot_id,
        "source_snapshot_fingerprint": first.source_snapshot_fingerprint,
        "tenant_id": first.tenant_id,
        "operations": ops_list,
        "created_at": created_at,
    }
    overlay_hash = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()

    return ScenarioOverlay(
        overlay_id=overlay_id,
        scenario_id=composed_scenario_id,
        source_snapshot_id=first.source_snapshot_id,
        source_snapshot_fingerprint=first.source_snapshot_fingerprint,
        tenant_id=first.tenant_id,
        operations=tuple(all_ops),
        created_at=created_at,
        overlay_hash=overlay_hash,
    )
