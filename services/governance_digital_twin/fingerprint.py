"""Fingerprint helpers for Governance Digital Twin snapshots."""

from __future__ import annotations

import hashlib
from dataclasses import asdict
from typing import Any

from services.canonical import canonical_json_bytes
from services.governance_digital_twin.models import (
    GOVERNANCE_DIGITAL_TWIN_FINGERPRINT_DOMAIN,
    GovernanceDigitalTwinBaselineReference,
    GovernanceDigitalTwinEntity,
    GovernanceDigitalTwinRelationship,
    GovernanceDigitalTwinSnapshot,
)


def compute_metadata_hash(payload: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def compute_entity_hash(entity: GovernanceDigitalTwinEntity) -> str:
    return compute_metadata_hash(asdict(entity))


def compute_relationship_hash(relationship: GovernanceDigitalTwinRelationship) -> str:
    return compute_metadata_hash(asdict(relationship))


def compute_snapshot_fingerprint(snapshot: GovernanceDigitalTwinSnapshot) -> str:
    source_authorities = sorted(
        (asdict(source) for source in snapshot.source_authorities),
        key=lambda item: item["authority"],
    )
    authority_nodes = sorted(
        (asdict(node) for node in snapshot.authority_graph.authorities),
        key=lambda item: item["authority"],
    )
    authority_edges = sorted(
        (asdict(edge) for edge in snapshot.authority_graph.dependencies),
        key=lambda item: (
            item["authority"],
            item["downstream_authority"],
            item["relationship_type"],
        ),
    )
    baselines = sorted(
        (asdict(reference) for reference in snapshot.baselines),
        key=lambda item: item["baseline_id"],
    )
    entities = sorted(
        (
            {"entity_id": entity.id, "entity_hash": compute_entity_hash(entity)}
            for entity in snapshot.entities
        ),
        key=lambda item: item["entity_id"],
    )
    relationships = sorted(
        (
            {
                "relationship_id": relationship.id,
                "relationship_hash": compute_relationship_hash(relationship),
            }
            for relationship in snapshot.relationships
        ),
        key=lambda item: item["relationship_id"],
    )
    payload = {
        "fingerprint_domain": GOVERNANCE_DIGITAL_TWIN_FINGERPRINT_DOMAIN,
        "tenant_id": snapshot.tenant_id,
        "generated_at": snapshot.generated_at,
        "snapshot_version": snapshot.snapshot_version,
        "graph_schema_version": snapshot.graph_schema_version,
        "builder_version": snapshot.builder_version,
        "category": snapshot.category,
        "parent_snapshot_id": snapshot.parent_snapshot_id,
        "previous_fingerprint": snapshot.previous_fingerprint,
        "generation": snapshot.generation,
        "lineage_id": snapshot.lineage_id,
        "twin_identity": asdict(snapshot.twin_identity),
        "redaction_profile": snapshot.redaction_profile,
        "source_authorities": source_authorities,
        "authority_graph": {
            "authorities": authority_nodes,
            "dependencies": authority_edges,
        },
        "entities": entities,
        "relationships": relationships,
        "baselines": baselines,
        "completeness": snapshot.completeness,
        "state_extensions": asdict(snapshot.state_extensions),
        "future_references": asdict(snapshot.future_references),
        "warnings": list(snapshot.warnings),
        "limitations": list(snapshot.limitations),
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def compute_baseline_reference_id(
    reference: GovernanceDigitalTwinBaselineReference,
) -> str:
    return compute_metadata_hash(asdict(reference))
