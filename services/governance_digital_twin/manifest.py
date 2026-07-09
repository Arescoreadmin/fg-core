"""Deterministic snapshot manifest helpers for the Governance Digital Twin."""

from __future__ import annotations

from collections import Counter

from services.governance_digital_twin.immutability import deep_freeze
from services.governance_digital_twin.mcim import GOVERNANCE_DIGITAL_TWIN_MCIM_VERSION
from services.governance_digital_twin.models import (
    GOVERNANCE_DIGITAL_TWIN_EXPORT_VERSION,
    GOVERNANCE_DIGITAL_TWIN_MANIFEST_SCHEMA_VERSION,
    GOVERNANCE_DIGITAL_TWIN_VALIDATOR_VERSION,
    GovernanceDigitalTwinManifest,
    GovernanceDigitalTwinSnapshot,
)


def build_snapshot_manifest(
    snapshot: GovernanceDigitalTwinSnapshot,
) -> GovernanceDigitalTwinManifest:
    entity_counts = Counter(entity.type for entity in snapshot.entities)
    relationship_counts = Counter(
        relationship.type for relationship in snapshot.relationships
    )
    authority_counts = Counter(entity.authority for entity in snapshot.entities)
    for relationship in snapshot.relationships:
        authority_counts[relationship.authority] += 1

    baseline_reference = (
        snapshot.baselines[0].baseline_id if snapshot.baselines else None
    )
    return GovernanceDigitalTwinManifest(
        manifest_schema_version=GOVERNANCE_DIGITAL_TWIN_MANIFEST_SCHEMA_VERSION,
        snapshot_version=snapshot.snapshot_version,
        graph_schema_version=snapshot.graph_schema_version,
        snapshot_category=snapshot.category,
        entity_counts=deep_freeze(dict(sorted(entity_counts.items()))),
        relationship_counts=deep_freeze(dict(sorted(relationship_counts.items()))),
        authority_counts=deep_freeze(dict(sorted(authority_counts.items()))),
        completeness_score=int(snapshot.completeness.get("score", 0)),
        fingerprint=snapshot.fingerprint,
        redaction_profile=snapshot.redaction_profile,
        baseline_reference=baseline_reference,
        builder_version=snapshot.builder_version,
        mcim_version=GOVERNANCE_DIGITAL_TWIN_MCIM_VERSION,
        export_version=GOVERNANCE_DIGITAL_TWIN_EXPORT_VERSION,
        validator_version=GOVERNANCE_DIGITAL_TWIN_VALIDATOR_VERSION,
        lineage_id=snapshot.lineage_id,
        generation=snapshot.generation,
    )
