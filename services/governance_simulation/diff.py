"""Deterministic graph diff engine: compare snapshot state with derived overlay state."""

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
    GraphDiff,
    GraphDiffEntry,
)


def _entity_domain(entity_type: str) -> str:
    """Map entity type to impact domain."""
    mapping = {
        "policy": "governance",
        "control": "control",
        "evidence": "evidence",
        "finding": "risk",
        "remediation": "readiness",
        "assessment": "operational",
        "report": "executive",
        "decision": "executive",
        "workflow": "operational",
        "simulation": "governance",
        "replay": "governance",
        "customer": "governance",
        "framework": "framework",
        "authority": "authority",
    }
    return mapping.get(entity_type, "governance")


def _relationship_domain(rel_type: str) -> str:
    """Map relationship type to impact domain."""
    mapping = {
        "governs": "governance",
        "verifies": "evidence",
        "maps_to": "framework",
        "supports": "compliance",
        "contradicts": "governance",
        "remediates": "risk",
        "generated_from": "governance",
        "published_to": "executive",
        "decided_by": "executive",
        "depends_on": "operational",
        "supersedes": "governance",
        "derived_from": "governance",
        "affects": "operational",
        "owned_by": "authority",
    }
    return mapping.get(rel_type, "governance")


def _diff_id(scenario_id: str, domain: str, operation: str, object_id: str, index: int) -> str:
    seed = f"DIFF:{scenario_id}:{domain}:{operation}:{object_id}:{index}"
    return hashlib.sha256(seed.encode()).hexdigest()[:16]


def compute_graph_diff(
    snapshot: GovernanceDigitalTwinSnapshot,
    derived_entities: tuple[GovernanceDigitalTwinEntity, ...],
    derived_relationships: tuple[GovernanceDigitalTwinRelationship, ...],
    scenario_id: str,
) -> GraphDiff:
    """Compute a deterministic diff between snapshot and derived state.

    Returns a GraphDiff with entries sorted by diff_id for determinism.
    """
    snap_entity_map = {e.id: e for e in snapshot.entities}
    snap_rel_map = {r.id: r for r in snapshot.relationships}
    derived_entity_map = {e.id: e for e in derived_entities}
    derived_rel_map = {r.id: r for r in derived_relationships}

    entries: list[GraphDiffEntry] = []
    index = 0

    # --- Entity diff ---
    all_entity_ids = sorted(set(snap_entity_map) | set(derived_entity_map))
    for eid in all_entity_ids:
        in_snap = eid in snap_entity_map
        in_derived = eid in derived_entity_map

        if in_snap and not in_derived:
            # removed
            entity = snap_entity_map[eid]
            domain = _entity_domain(entity.type)
            did = _diff_id(scenario_id, domain, "removed", eid, index)
            entries.append(GraphDiffEntry(
                diff_id=did,
                domain=domain,
                operation="removed",
                entity_id=eid,
                relationship_id=None,
                before=dataclasses.asdict(entity),
                after=None,
                authority=entity.authority,
                reason=f"entity '{eid}' removed by overlay",
            ))
            index += 1

        elif not in_snap and in_derived:
            # added
            entity = derived_entity_map[eid]
            domain = _entity_domain(entity.type)
            did = _diff_id(scenario_id, domain, "added", eid, index)
            entries.append(GraphDiffEntry(
                diff_id=did,
                domain=domain,
                operation="added",
                entity_id=eid,
                relationship_id=None,
                before=None,
                after=dataclasses.asdict(entity),
                authority=entity.authority,
                reason=f"entity '{eid}' added by overlay",
            ))
            index += 1

        else:
            # potentially modified
            snap_e = snap_entity_map[eid]
            derived_e = derived_entity_map[eid]
            snap_dict = dataclasses.asdict(snap_e)
            derived_dict = dataclasses.asdict(derived_e)
            if snap_dict != derived_dict:
                domain = _entity_domain(snap_e.type)
                did = _diff_id(scenario_id, domain, "modified", eid, index)
                entries.append(GraphDiffEntry(
                    diff_id=did,
                    domain=domain,
                    operation="modified",
                    entity_id=eid,
                    relationship_id=None,
                    before=snap_dict,
                    after=derived_dict,
                    authority=derived_e.authority,
                    reason=f"entity '{eid}' modified by overlay",
                ))
                index += 1

    # --- Relationship diff ---
    all_rel_ids = sorted(set(snap_rel_map) | set(derived_rel_map))
    for rid in all_rel_ids:
        in_snap = rid in snap_rel_map
        in_derived = rid in derived_rel_map

        if in_snap and not in_derived:
            rel = snap_rel_map[rid]
            domain = _relationship_domain(rel.type)
            did = _diff_id(scenario_id, domain, "removed", rid, index)
            entries.append(GraphDiffEntry(
                diff_id=did,
                domain=domain,
                operation="removed",
                entity_id=None,
                relationship_id=rid,
                before=dataclasses.asdict(rel),
                after=None,
                authority=rel.authority,
                reason=f"relationship '{rid}' removed by overlay",
            ))
            index += 1

        elif not in_snap and in_derived:
            rel = derived_rel_map[rid]
            domain = _relationship_domain(rel.type)
            did = _diff_id(scenario_id, domain, "added", rid, index)
            entries.append(GraphDiffEntry(
                diff_id=did,
                domain=domain,
                operation="added",
                entity_id=None,
                relationship_id=rid,
                before=None,
                after=dataclasses.asdict(rel),
                authority=rel.authority,
                reason=f"relationship '{rid}' added by overlay",
            ))
            index += 1

        else:
            snap_r = snap_rel_map[rid]
            derived_r = derived_rel_map[rid]
            snap_rdict = dataclasses.asdict(snap_r)
            derived_rdict = dataclasses.asdict(derived_r)
            if snap_rdict != derived_rdict:
                domain = _relationship_domain(snap_r.type)
                did = _diff_id(scenario_id, domain, "modified", rid, index)
                entries.append(GraphDiffEntry(
                    diff_id=did,
                    domain=domain,
                    operation="modified",
                    entity_id=None,
                    relationship_id=rid,
                    before=snap_rdict,
                    after=derived_rdict,
                    authority=derived_r.authority,
                    reason=f"relationship '{rid}' modified by overlay",
                ))
                index += 1

    # Sort entries by diff_id for full determinism
    sorted_entries = tuple(sorted(entries, key=lambda e: e.diff_id))

    # Compute diff_hash over sorted entries
    diff_id_master_seed = f"DIFFMASTER:{scenario_id}"
    diff_id_master = hashlib.sha256(diff_id_master_seed.encode()).hexdigest()[:24]

    import dataclasses as _dc
    diff_hash_payload = sorted([_dc.asdict(e) for e in sorted_entries], key=lambda x: x["diff_id"])
    diff_hash = hashlib.sha256(canonical_json_bytes(diff_hash_payload)).hexdigest()

    return GraphDiff(
        diff_id=diff_id_master,
        scenario_id=scenario_id,
        source_snapshot_id=snapshot.snapshot_id,
        entries=sorted_entries,
        diff_hash=diff_hash,
        created_at=utc_iso8601_z_now(),
    )
