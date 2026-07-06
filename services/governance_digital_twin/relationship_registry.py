"""Extensible relationship registry for Governance Digital Twin semantics."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from services.governance_digital_twin.models import GovernanceDigitalTwinRelationshipType


@dataclass(frozen=True)
class GovernanceDigitalTwinRelationshipSpec:
    relationship_type: str
    participates_in_authority_dependencies: bool
    max_targets_per_source: int | None


_RELATIONSHIP_SPECS = {
    GovernanceDigitalTwinRelationshipType.governs.value: GovernanceDigitalTwinRelationshipSpec(
        relationship_type=GovernanceDigitalTwinRelationshipType.governs.value,
        participates_in_authority_dependencies=True,
        max_targets_per_source=None,
    ),
    GovernanceDigitalTwinRelationshipType.verifies.value: GovernanceDigitalTwinRelationshipSpec(
        relationship_type=GovernanceDigitalTwinRelationshipType.verifies.value,
        participates_in_authority_dependencies=True,
        max_targets_per_source=None,
    ),
    GovernanceDigitalTwinRelationshipType.maps_to.value: GovernanceDigitalTwinRelationshipSpec(
        relationship_type=GovernanceDigitalTwinRelationshipType.maps_to.value,
        participates_in_authority_dependencies=True,
        max_targets_per_source=None,
    ),
    GovernanceDigitalTwinRelationshipType.supports.value: GovernanceDigitalTwinRelationshipSpec(
        relationship_type=GovernanceDigitalTwinRelationshipType.supports.value,
        participates_in_authority_dependencies=False,
        max_targets_per_source=None,
    ),
    GovernanceDigitalTwinRelationshipType.contradicts.value: GovernanceDigitalTwinRelationshipSpec(
        relationship_type=GovernanceDigitalTwinRelationshipType.contradicts.value,
        participates_in_authority_dependencies=False,
        max_targets_per_source=None,
    ),
    GovernanceDigitalTwinRelationshipType.remediates.value: GovernanceDigitalTwinRelationshipSpec(
        relationship_type=GovernanceDigitalTwinRelationshipType.remediates.value,
        participates_in_authority_dependencies=False,
        max_targets_per_source=None,
    ),
    GovernanceDigitalTwinRelationshipType.generated_from.value: GovernanceDigitalTwinRelationshipSpec(
        relationship_type=GovernanceDigitalTwinRelationshipType.generated_from.value,
        participates_in_authority_dependencies=True,
        max_targets_per_source=None,
    ),
    GovernanceDigitalTwinRelationshipType.published_to.value: GovernanceDigitalTwinRelationshipSpec(
        relationship_type=GovernanceDigitalTwinRelationshipType.published_to.value,
        participates_in_authority_dependencies=True,
        max_targets_per_source=1,
    ),
    GovernanceDigitalTwinRelationshipType.decided_by.value: GovernanceDigitalTwinRelationshipSpec(
        relationship_type=GovernanceDigitalTwinRelationshipType.decided_by.value,
        participates_in_authority_dependencies=True,
        max_targets_per_source=1,
    ),
    GovernanceDigitalTwinRelationshipType.depends_on.value: GovernanceDigitalTwinRelationshipSpec(
        relationship_type=GovernanceDigitalTwinRelationshipType.depends_on.value,
        participates_in_authority_dependencies=True,
        max_targets_per_source=None,
    ),
    GovernanceDigitalTwinRelationshipType.supersedes.value: GovernanceDigitalTwinRelationshipSpec(
        relationship_type=GovernanceDigitalTwinRelationshipType.supersedes.value,
        participates_in_authority_dependencies=True,
        max_targets_per_source=1,
    ),
    GovernanceDigitalTwinRelationshipType.derived_from.value: GovernanceDigitalTwinRelationshipSpec(
        relationship_type=GovernanceDigitalTwinRelationshipType.derived_from.value,
        participates_in_authority_dependencies=True,
        max_targets_per_source=1,
    ),
    GovernanceDigitalTwinRelationshipType.affects.value: GovernanceDigitalTwinRelationshipSpec(
        relationship_type=GovernanceDigitalTwinRelationshipType.affects.value,
        participates_in_authority_dependencies=False,
        max_targets_per_source=None,
    ),
    GovernanceDigitalTwinRelationshipType.owned_by.value: GovernanceDigitalTwinRelationshipSpec(
        relationship_type=GovernanceDigitalTwinRelationshipType.owned_by.value,
        participates_in_authority_dependencies=True,
        max_targets_per_source=1,
    ),
}

RELATIONSHIP_REGISTRY: Mapping[str, GovernanceDigitalTwinRelationshipSpec] = MappingProxyType(_RELATIONSHIP_SPECS)

__all__ = ["GovernanceDigitalTwinRelationshipSpec", "RELATIONSHIP_REGISTRY"]
