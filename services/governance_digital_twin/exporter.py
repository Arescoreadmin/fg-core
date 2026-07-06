"""Replay-safe export helpers for Governance Digital Twin snapshots."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
from typing import Any

from services.governance_digital_twin.immutability import deep_freeze
from services.governance_digital_twin.models import GovernanceDigitalTwinSnapshot
from services.governance_digital_twin.redaction import (
    assert_no_forbidden_fields,
    redact_forbidden_fields,
)


def export_replay_safe_snapshot(
    snapshot: GovernanceDigitalTwinSnapshot,
) -> Mapping[str, Any]:
    warnings = list(snapshot.warnings)
    entity_summaries = [
        {
            "id": entity.id,
            "canonical_entity_id": entity.canonical_entity_id,
            "type": entity.type,
            "title": entity.title,
            "status": entity.status,
            "authority": entity.authority,
            "updated_at": entity.updated_at,
            "confidence": entity.confidence,
            "confidence_provenance": asdict(entity.confidence_provenance),
            "provenance": asdict(entity.provenance),
            "redaction_state": entity.redaction_state,
        }
        for entity in snapshot.entities
    ]
    relationship_summaries = [
        {
            "id": relationship.id,
            "canonical_relationship_id": relationship.canonical_relationship_id,
            "type": relationship.type,
            "from_entity_id": relationship.from_entity_id,
            "to_entity_id": relationship.to_entity_id,
            "authority": relationship.authority,
            "confidence": relationship.confidence,
            "confidence_provenance": asdict(relationship.confidence_provenance),
            "evidence_refs": list(relationship.evidence_refs),
        }
        for relationship in snapshot.relationships
    ]
    source_authorities = [asdict(source) for source in snapshot.source_authorities]
    export = {
        "snapshot_id": snapshot.snapshot_id,
        "canonical_snapshot_id": snapshot.canonical_snapshot_id,
        "fingerprint": snapshot.fingerprint,
        "generated_at": snapshot.generated_at,
        "snapshot_version": snapshot.snapshot_version,
        "graph_schema_version": snapshot.graph_schema_version,
        "builder_version": snapshot.builder_version,
        "snapshot_category": snapshot.category,
        "parent_snapshot_id": snapshot.parent_snapshot_id,
        "previous_fingerprint": snapshot.previous_fingerprint,
        "generation": snapshot.generation,
        "lineage_id": snapshot.lineage_id,
        "twin_identity": asdict(snapshot.twin_identity),
        "source_authorities": source_authorities,
        "redaction_profile": snapshot.redaction_profile,
        "entity_summaries": entity_summaries,
        "relationship_summaries": relationship_summaries,
        "manifest": asdict(snapshot.manifest) if snapshot.manifest is not None else None,
        "validation_report": asdict(snapshot.validation_report) if snapshot.validation_report is not None else None,
        "completeness": dict(snapshot.completeness),
        "state_extensions": asdict(snapshot.state_extensions),
        "future_references": asdict(snapshot.future_references),
        "limitations": list(snapshot.limitations),
        "warnings": warnings,
        "replay_instructions": {
            "verify_fingerprint_with": "sha256(canonical_json)",
            "canonical_json_rules": "sorted_keys+stable_array_order+normalized_timestamps",
            "replay_scope": snapshot.tenant_id,
            "replay_safe": True,
            "lineage_id": snapshot.lineage_id,
            "generation": snapshot.generation,
        },
    }
    redacted = redact_forbidden_fields(export, warnings=warnings)
    assert_no_forbidden_fields(redacted)
    return deep_freeze(redacted)
