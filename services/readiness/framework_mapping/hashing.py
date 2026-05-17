"""Enterprise Framework Mapping & Crosswalk Governance Engine — mapping integrity hashing.

Hashing contract:
  - All functions are pure Python: no I/O, no side effects, no randomness.
  - Output is deterministic: identical relationship stable-field state → identical hash.
  - Algorithm is SHA-256. Hash value is hex-encoded.
  - inputs_canonical is the exact JSON string that was hashed — preserved for
    independent forensic replay without rerunning relationship construction.
  - compute_mapping_hash() produces a MappingHashRecord.
  - replay_mapping_hash() recomputes a hash from a saved inputs_canonical string.
  - verify_mapping_hash() checks a stored hash_record against a live relationship.

Hash inputs (stable — included):
  relationship_id, source_control_id, source_framework_id, source_framework_version,
  target_control_id, target_framework_id, target_framework_version,
  relationship_type, mapping_authority_level, mapping_confidence,
  mapping_granularity, is_bidirectional,
  provenance.provenance_id, provenance.source_authority, provenance.mapping_rationale,
  provenance.mapping_origin, provenance.mapping_version,
  compatibility.source_framework_id, compatibility.source_version_tag,
  compatibility.target_framework_id, compatibility.target_version_tag,
  compatibility.is_compatible.

Hash excludes:
  created_at, tenant_id, mapping_status, mapping_review_status,
  mapping_metadata, jurisdiction, control_scope,
  supersedes_relationship_id, source_namespace_id, target_namespace_id.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime

from .models import MappingHashRecord, MappingRelationship

_HASH_ALGORITHM = "sha256"


def _build_canonical_inputs(relationship: MappingRelationship) -> dict:
    return {
        "relationship_id": relationship.relationship_id,
        "source_control_id": relationship.source_control_id,
        "source_framework_id": relationship.source_framework_id,
        "source_framework_version": relationship.source_framework_version,
        "target_control_id": relationship.target_control_id,
        "target_framework_id": relationship.target_framework_id,
        "target_framework_version": relationship.target_framework_version,
        "relationship_type": relationship.relationship_type.value,
        "mapping_authority_level": relationship.mapping_authority_level.value,
        "mapping_confidence": relationship.mapping_confidence,
        "mapping_granularity": relationship.mapping_granularity.value,
        "is_bidirectional": relationship.is_bidirectional,
        "provenance": {
            "provenance_id": relationship.provenance.provenance_id,
            "source_authority": relationship.provenance.source_authority,
            "mapping_rationale": relationship.provenance.mapping_rationale,
            "mapping_origin": relationship.provenance.mapping_origin,
            "mapping_version": relationship.provenance.mapping_version,
        },
        "compatibility": {
            "source_framework_id": relationship.compatibility.source_framework_id,
            "source_version_tag": relationship.compatibility.source_version_tag,
            "target_framework_id": relationship.compatibility.target_framework_id,
            "target_version_tag": relationship.compatibility.target_version_tag,
            "is_compatible": relationship.compatibility.is_compatible,
        },
    }


def compute_mapping_hash(
    relationship: MappingRelationship,
    *,
    computed_at: datetime,
) -> MappingHashRecord:
    """Compute a deterministic SHA-256 hash record for a mapping relationship."""
    canonical = _build_canonical_inputs(relationship)
    inputs_canonical = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    hash_value = hashlib.sha256(inputs_canonical.encode()).hexdigest()
    return MappingHashRecord(
        relationship_id=relationship.relationship_id,
        algorithm=_HASH_ALGORITHM,
        hash_value=hash_value,
        inputs_canonical=inputs_canonical,
        computed_at=computed_at,
        is_replay_safe=True,
    )


def replay_mapping_hash(inputs_canonical: str) -> str:
    """Recompute the SHA-256 hash from a saved inputs_canonical string."""
    return hashlib.sha256(inputs_canonical.encode()).hexdigest()


def verify_mapping_hash(
    relationship: MappingRelationship,
    hash_record: MappingHashRecord,
) -> bool:
    """Verify a hash_record matches the current stable state of a relationship.

    Returns True if hash_record.hash_value matches a freshly computed hash.
    Returns False on any mismatch — does not raise.
    """
    canonical = _build_canonical_inputs(relationship)
    inputs_canonical = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256(inputs_canonical.encode()).hexdigest()
    return hash_record.hash_value == expected
