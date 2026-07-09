"""Baseline helpers for future Governance Digital Twin comparison workflows."""

from __future__ import annotations

from collections import Counter

from services.governance_digital_twin.fingerprint import compute_metadata_hash
from services.governance_digital_twin.immutability import deep_freeze
from services.governance_digital_twin.models import (
    GovernanceDigitalTwinBaseline,
    GovernanceDigitalTwinSnapshot,
)


def create_comparison_baseline(
    snapshot: GovernanceDigitalTwinSnapshot,
    label: str,
    created_by: str,
    purpose: str,
) -> GovernanceDigitalTwinBaseline:
    entity_counts = Counter(entity.type for entity in snapshot.entities)
    relationship_counts = Counter(
        relationship.type for relationship in snapshot.relationships
    )
    authority_counts = Counter(entity.authority for entity in snapshot.entities)
    for relationship in snapshot.relationships:
        authority_counts[relationship.authority] += 1

    baseline_id = compute_metadata_hash(
        {
            "tenant_id": snapshot.tenant_id,
            "snapshot_id": snapshot.snapshot_id,
            "fingerprint": snapshot.fingerprint,
            "label": label,
            "created_by": created_by,
            "purpose": purpose,
            "category": snapshot.category,
            "twin_id": snapshot.twin_identity.twin_id,
        }
    )[:32]
    return GovernanceDigitalTwinBaseline(
        baseline_id=baseline_id,
        tenant_id=snapshot.tenant_id,
        snapshot_id=snapshot.snapshot_id,
        fingerprint=snapshot.fingerprint,
        label=label,
        created_at=snapshot.generated_at,
        created_by=created_by,
        purpose=purpose,
        entity_counts=deep_freeze(dict(sorted(entity_counts.items()))),
        relationship_counts=deep_freeze(dict(sorted(relationship_counts.items()))),
        authority_counts=deep_freeze(dict(sorted(authority_counts.items()))),
        completeness=deep_freeze(dict(snapshot.completeness)),
        replay_safe=True,
        snapshot_category=snapshot.category,
        twin_id=snapshot.twin_identity.twin_id,
    )
