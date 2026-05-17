"""Enterprise Framework Mapping & Crosswalk Governance Engine — crosswalk builder.

Crosswalk generation contract:
  - All functions are pure Python: no I/O, no side effects, no randomness.
  - Output is deterministic: identical inputs → identical crosswalk output.
  - Framework isolation: crosswalk queries are scoped to a specific
    (framework_id, framework_version) pair.
  - One-to-many and many-to-one mappings are supported and detected.
  - Gap detection is integrated into CrosswalkEntry gap_status.
  - No scoring logic, no recommendation generation, no AI inference.

Crosswalk query contract:
  - find_control_mappings() direction="outbound": source-side relationships.
  - find_control_mappings() direction="inbound": target-side relationships.
  - find_control_mappings() direction="both": all relationships for the control.
  - find_one_to_many_mappings(): sources with multiple distinct targets.
  - find_many_to_one_mappings(): targets with multiple distinct sources.
"""

from __future__ import annotations

from typing import Literal

from .models import (
    ControlInheritance,
    CrosswalkEntry,
    MappingGapType,
    MappingRelationship,
)


def find_control_mappings(
    control_id: str,
    framework_id: str,
    relationships: tuple[MappingRelationship, ...],
    *,
    direction: Literal["outbound", "inbound", "both"] = "outbound",
) -> tuple[MappingRelationship, ...]:
    """Find all mapping relationships for a specific control.

    direction="outbound": relationships where the control is the source.
    direction="inbound": relationships where the control is the target.
    direction="both": all relationships involving the control on either side.

    Framework identity is checked on both control_id and framework_id to avoid
    false matches when different frameworks share a control identifier string.
    """
    result: list[MappingRelationship] = []
    for rel in relationships:
        is_source = (
            rel.source_control_id == control_id
            and rel.source_framework_id == framework_id
        )
        is_target = (
            rel.target_control_id == control_id
            and rel.target_framework_id == framework_id
        )
        if direction == "outbound" and is_source:
            result.append(rel)
        elif direction == "inbound" and is_target:
            result.append(rel)
        elif direction == "both" and (is_source or is_target):
            result.append(rel)

    return tuple(result)


def find_one_to_many_mappings(
    relationships: tuple[MappingRelationship, ...],
) -> dict[str, tuple[MappingRelationship, ...]]:
    """Find source controls that map to multiple distinct target controls.

    Returns a dict keyed by "{source_framework_id}:{source_control_id}" containing
    all outbound relationships for that source (only entries with ≥2 targets).

    Distinct targets are determined by (target_framework_id, target_control_id).
    Multiple relationships to the SAME target with different relationship_types are
    counted as one target in the cardinality check but all returned as relationships.
    """
    by_source: dict[str, list[MappingRelationship]] = {}
    for rel in relationships:
        key = f"{rel.source_framework_id}:{rel.source_control_id}"
        if key not in by_source:
            by_source[key] = []
        by_source[key].append(rel)

    return {
        k: tuple(v)
        for k, v in by_source.items()
        if len({(r.target_framework_id, r.target_control_id) for r in v}) > 1
    }


def find_many_to_one_mappings(
    relationships: tuple[MappingRelationship, ...],
) -> dict[str, tuple[MappingRelationship, ...]]:
    """Find target controls that are mapped to by multiple distinct source controls.

    Returns a dict keyed by "{target_framework_id}:{target_control_id}" containing
    all inbound relationships for that target (only entries with ≥2 distinct sources).

    Distinct sources are determined by (source_framework_id, source_control_id).
    """
    by_target: dict[str, list[MappingRelationship]] = {}
    for rel in relationships:
        key = f"{rel.target_framework_id}:{rel.target_control_id}"
        if key not in by_target:
            by_target[key] = []
        by_target[key].append(rel)

    return {
        k: tuple(v)
        for k, v in by_target.items()
        if len({(r.source_framework_id, r.source_control_id) for r in v}) > 1
    }


def build_crosswalk(
    control_ids: tuple[str, ...],
    framework_id: str,
    framework_version: str,
    relationships: tuple[MappingRelationship, ...],
    inheritances: tuple[ControlInheritance, ...],
) -> tuple[CrosswalkEntry, ...]:
    """Build a framework crosswalk for a set of controls.

    For each control_id, produces a CrosswalkEntry with:
    - outbound_relationships: relationships where this control is the source
      in the specified framework version.
    - inbound_relationships: relationships where this control is the target
      in the specified framework version.
    - inheritances: inheritance records where this control is the child
      in the specified framework version.
    - gap_status: UNMAPPED if the control has no outbound or inbound relationships
      and no inheritances; None otherwise.

    The order of CrosswalkEntry in the returned tuple matches the order of
    control_ids in the input tuple — deterministic and caller-controlled.
    """
    outbound_idx: dict[str, list[MappingRelationship]] = {
        cid: [] for cid in control_ids
    }
    inbound_idx: dict[str, list[MappingRelationship]] = {cid: [] for cid in control_ids}
    inheritance_idx: dict[str, list[ControlInheritance]] = {
        cid: [] for cid in control_ids
    }

    for rel in relationships:
        if (
            rel.source_control_id in outbound_idx
            and rel.source_framework_id == framework_id
            and rel.source_framework_version == framework_version
        ):
            outbound_idx[rel.source_control_id].append(rel)
        if (
            rel.target_control_id in inbound_idx
            and rel.target_framework_id == framework_id
            and rel.target_framework_version == framework_version
        ):
            inbound_idx[rel.target_control_id].append(rel)

    for inh in inheritances:
        if (
            inh.child_control_id in inheritance_idx
            and inh.child_framework_id == framework_id
            and inh.child_framework_version == framework_version
        ):
            inheritance_idx[inh.child_control_id].append(inh)

    entries: list[CrosswalkEntry] = []
    for control_id in control_ids:
        out = tuple(outbound_idx[control_id])
        inn = tuple(inbound_idx[control_id])
        child_inhs = tuple(inheritance_idx[control_id])

        gap_status: MappingGapType | None = None
        if not out and not inn and not child_inhs:
            gap_status = MappingGapType.UNMAPPED

        entries.append(
            CrosswalkEntry(
                source_control_id=control_id,
                source_framework_id=framework_id,
                source_framework_version=framework_version,
                outbound_relationships=out,
                inbound_relationships=inn,
                inheritances=child_inhs,
                gap_status=gap_status,
            )
        )

    return tuple(entries)
