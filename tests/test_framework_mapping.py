"""Tests for the Enterprise Framework Mapping & Crosswalk Governance Engine.

No database. No I/O. Pure Python deterministic contracts.

Test categories:
- Enum value stability
- Model immutability (frozen dataclasses)
- Metadata dict immutability (MappingProxyType)
- Defensive copy on construction
- Mapping relationship validation
- Control inheritance validation
- Framework mapping validation (collection-level)
- Mapping version validation
- Cyclic inheritance detection
- One-to-many and many-to-one mapping detection
- Gap detection (unmapped, orphaned, missing inheritance targets)
- Crosswalk generation
- Tenant isolation
- Additive framework support
- Well-known slug constants
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from services.readiness.framework_mapping import (
    FRAMEWORK_SLUG_FROSTGATE,
    FRAMEWORK_SLUG_HIPAA_AI,
    FRAMEWORK_SLUG_ISO_42001,
    FRAMEWORK_SLUG_NIST_AI_RMF,
    FRAMEWORK_SLUG_SOC2_AI,
    REASON_CYCLIC_INHERITANCE,
    REASON_DUPLICATE_RELATIONSHIP,
    REASON_FRAMEWORK_ID_MISMATCH,
    REASON_MISSING_MAPPING_RATIONALE,
    REASON_MISSING_SOURCE_AUTHORITY,
    REASON_SCOPE_TENANT_MISMATCH,
    REASON_SELF_INHERITANCE,
    REASON_SELF_MAPPING,
    REASON_SELF_SUPERSESSION,
    REASON_TENANT_ISOLATION_VIOLATION,
    REASON_VERSION_TAG_EMPTY,
    ControlInheritance,
    CrosswalkEntry,
    FrameworkMapping,
    FrameworkMappingVersion,
    MappingCompatibilityRecord,
    MappingGapType,
    MappingProvenance,
    MappingRelationship,
    MappingRelationshipType,
    MappingScope,
    MappingStatus,
    MappingValidationType,
    _VALIDATOR_VERSION,
    build_crosswalk,
    detect_cyclic_inheritance,
    detect_missing_inheritance_targets,
    detect_orphaned_relationships,
    detect_unmapped_controls,
    find_control_mappings,
    find_many_to_one_mappings,
    find_one_to_many_mappings,
    validate_control_inheritance,
    validate_framework_mapping,
    validate_mapping_relationship,
    validate_mapping_version,
)

# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------

_TENANT = "tenant-abc"
_OTHER_TENANT = "tenant-xyz"
_FW_NIST = "fw-nist-001"
_FW_ISO = "fw-iso-001"
_FW_SOC2 = "fw-soc2-001"
_V1 = "1.0"
_CTRL_A = "ctrl-a"
_CTRL_B = "ctrl-b"
_CTRL_C = "ctrl-c"
_CTRL_D = "ctrl-d"
_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _make_provenance(
    *,
    provenance_id: str = "prov-001",
    source_authority: str = "FrostGate",
    mapping_rationale: str = "Controls address identical obligations",
    mapping_origin: str = "manual",
    mapping_version: str = "1.0.0",
) -> MappingProvenance:
    return MappingProvenance(
        provenance_id=provenance_id,
        source_authority=source_authority,
        mapping_rationale=mapping_rationale,
        mapping_origin=mapping_origin,
        mapping_version=mapping_version,
    )


def _make_compatibility(
    *,
    source_framework_id: str = _FW_NIST,
    source_version_tag: str = _V1,
    target_framework_id: str = _FW_ISO,
    target_version_tag: str = _V1,
    is_compatible: bool = True,
) -> MappingCompatibilityRecord:
    return MappingCompatibilityRecord(
        source_framework_id=source_framework_id,
        source_version_tag=source_version_tag,
        target_framework_id=target_framework_id,
        target_version_tag=target_version_tag,
        is_compatible=is_compatible,
        compatibility_notes="Compatible framework versions",
    )


def _make_relationship(
    *,
    relationship_id: str = "rel-001",
    source_control_id: str = _CTRL_A,
    source_framework_id: str = _FW_NIST,
    source_framework_version: str = _V1,
    target_control_id: str = _CTRL_B,
    target_framework_id: str = _FW_ISO,
    target_framework_version: str = _V1,
    relationship_type: MappingRelationshipType = MappingRelationshipType.EQUIVALENT,
    mapping_status: MappingStatus = MappingStatus.ACTIVE,
    is_bidirectional: bool = False,
    tenant_id: str | None = None,
    provenance: MappingProvenance | None = None,
    compatibility: MappingCompatibilityRecord | None = None,
) -> MappingRelationship:
    return MappingRelationship(
        relationship_id=relationship_id,
        source_control_id=source_control_id,
        source_framework_id=source_framework_id,
        source_framework_version=source_framework_version,
        target_control_id=target_control_id,
        target_framework_id=target_framework_id,
        target_framework_version=target_framework_version,
        relationship_type=relationship_type,
        mapping_status=mapping_status,
        provenance=provenance or _make_provenance(),
        compatibility=compatibility
        or _make_compatibility(
            source_framework_id=source_framework_id,
            target_framework_id=target_framework_id,
        ),
        is_bidirectional=is_bidirectional,
        created_by="test-actor",
        created_at=_NOW,
        tenant_id=tenant_id,
    )


def _make_inheritance(
    *,
    inheritance_id: str = "inh-001",
    parent_control_id: str = _CTRL_A,
    parent_framework_id: str = _FW_NIST,
    parent_framework_version: str = _V1,
    child_control_id: str = _CTRL_B,
    child_framework_id: str = _FW_ISO,
    child_framework_version: str = _V1,
    tenant_id: str | None = None,
    provenance: MappingProvenance | None = None,
) -> ControlInheritance:
    return ControlInheritance(
        inheritance_id=inheritance_id,
        parent_control_id=parent_control_id,
        parent_framework_id=parent_framework_id,
        parent_framework_version=parent_framework_version,
        child_control_id=child_control_id,
        child_framework_id=child_framework_id,
        child_framework_version=child_framework_version,
        inherited_obligations=True,
        inherited_maturity_semantics=True,
        inherited_evidence_expectations=True,
        inherited_applicability_metadata=False,
        inheritance_rationale="Child framework adopts parent obligations",
        provenance=provenance or _make_provenance(),
        created_by="test-actor",
        created_at=_NOW,
        tenant_id=tenant_id,
    )


def _make_mapping_version(
    *,
    mapping_version_id: str = "mv-001",
    source_framework_id: str = _FW_NIST,
    source_framework_version: str = _V1,
    target_framework_id: str = _FW_ISO,
    target_framework_version: str = _V1,
    mapping_version_tag: str = "1.0.0",
    mapping_status: MappingStatus = MappingStatus.ACTIVE,
    superseded_by: str | None = None,
) -> FrameworkMappingVersion:
    return FrameworkMappingVersion(
        mapping_version_id=mapping_version_id,
        source_framework_id=source_framework_id,
        source_framework_version=source_framework_version,
        target_framework_id=target_framework_id,
        target_framework_version=target_framework_version,
        mapping_version_tag=mapping_version_tag,
        mapping_status=mapping_status,
        superseded_by=superseded_by,
        created_by="test-actor",
        created_at=_NOW,
        deprecation_note=None,
    )


def _make_framework_mapping(
    *,
    framework_mapping_id: str = "fm-001",
    source_framework_id: str = _FW_NIST,
    target_framework_id: str = _FW_ISO,
    relationships: tuple[MappingRelationship, ...] = (),
    inheritances: tuple[ControlInheritance, ...] = (),
    scope: MappingScope = MappingScope.PLATFORM,
    tenant_id: str | None = None,
) -> FrameworkMapping:
    return FrameworkMapping(
        framework_mapping_id=framework_mapping_id,
        source_framework_id=source_framework_id,
        target_framework_id=target_framework_id,
        mapping_version=_make_mapping_version(
            source_framework_id=source_framework_id,
            target_framework_id=target_framework_id,
        ),
        relationships=relationships,
        inheritances=inheritances,
        scope=scope,
        tenant_id=tenant_id,
        created_by="test-actor",
        created_at=_NOW,
    )


# ---------------------------------------------------------------------------
# Enum value stability
# ---------------------------------------------------------------------------


def test_mapping_relationship_type_values_stable() -> None:
    assert MappingRelationshipType.EQUIVALENT.value == "equivalent"
    assert MappingRelationshipType.PARTIALLY_EQUIVALENT.value == "partially_equivalent"
    assert MappingRelationshipType.INHERITED.value == "inherited"
    assert MappingRelationshipType.DERIVED.value == "derived"
    assert MappingRelationshipType.SUPPLEMENTAL.value == "supplemental"
    assert MappingRelationshipType.DEPENDENT.value == "dependent"
    assert MappingRelationshipType.OVERLAPPING.value == "overlapping"
    assert MappingRelationshipType.BROADER_THAN.value == "broader_than"
    assert MappingRelationshipType.NARROWER_THAN.value == "narrower_than"


def test_mapping_status_values_stable() -> None:
    assert MappingStatus.DRAFT.value == "draft"
    assert MappingStatus.ACTIVE.value == "active"
    assert MappingStatus.DEPRECATED.value == "deprecated"
    assert MappingStatus.SUPERSEDED.value == "superseded"


def test_mapping_scope_values_stable() -> None:
    assert MappingScope.PLATFORM.value == "platform"
    assert MappingScope.TENANT.value == "tenant"


def test_mapping_validation_type_values_stable() -> None:
    assert MappingValidationType.RELATIONSHIP.value == "relationship"
    assert MappingValidationType.INHERITANCE.value == "inheritance"
    assert MappingValidationType.FRAMEWORK.value == "framework"
    assert MappingValidationType.VERSION.value == "version"


def test_mapping_gap_type_values_stable() -> None:
    assert MappingGapType.UNMAPPED.value == "unmapped"
    assert MappingGapType.PARTIALLY_MAPPED.value == "partially_mapped"
    assert MappingGapType.ORPHANED.value == "orphaned"
    assert (
        MappingGapType.MISSING_INHERITANCE_TARGET.value == "missing_inheritance_target"
    )
    assert MappingGapType.UNSUPPORTED_FRAMEWORK.value == "unsupported_framework"


# ---------------------------------------------------------------------------
# Well-known framework slug constants
# ---------------------------------------------------------------------------


def test_well_known_slug_constants_are_strings() -> None:
    assert isinstance(FRAMEWORK_SLUG_NIST_AI_RMF, str)
    assert isinstance(FRAMEWORK_SLUG_ISO_42001, str)
    assert isinstance(FRAMEWORK_SLUG_SOC2_AI, str)
    assert isinstance(FRAMEWORK_SLUG_HIPAA_AI, str)
    assert isinstance(FRAMEWORK_SLUG_FROSTGATE, str)


def test_well_known_slug_constants_are_stable() -> None:
    assert FRAMEWORK_SLUG_NIST_AI_RMF == "nist-ai-rmf"
    assert FRAMEWORK_SLUG_ISO_42001 == "iso-42001"
    assert FRAMEWORK_SLUG_SOC2_AI == "soc2-ai-overlay"
    assert FRAMEWORK_SLUG_HIPAA_AI == "hipaa-ai-safeguards"
    assert FRAMEWORK_SLUG_FROSTGATE == "frostgate"


# ---------------------------------------------------------------------------
# Model immutability (frozen dataclasses)
# ---------------------------------------------------------------------------


def test_mapping_relationship_is_frozen() -> None:
    rel = _make_relationship()
    with pytest.raises(Exception):
        rel.source_control_id = "mutated"  # type: ignore[misc]


def test_control_inheritance_is_frozen() -> None:
    inh = _make_inheritance()
    with pytest.raises(Exception):
        inh.parent_control_id = "mutated"  # type: ignore[misc]


def test_framework_mapping_version_is_frozen() -> None:
    mv = _make_mapping_version()
    with pytest.raises(Exception):
        mv.mapping_version_tag = "mutated"  # type: ignore[misc]


def test_framework_mapping_is_frozen() -> None:
    fm = _make_framework_mapping()
    with pytest.raises(Exception):
        fm.source_framework_id = "mutated"  # type: ignore[misc]


def test_crosswalk_entry_is_frozen() -> None:
    entry = CrosswalkEntry(
        source_control_id=_CTRL_A,
        source_framework_id=_FW_NIST,
        source_framework_version=_V1,
        outbound_relationships=(),
        inbound_relationships=(),
        inheritances=(),
        gap_status=MappingGapType.UNMAPPED,
    )
    with pytest.raises(Exception):
        entry.source_control_id = "mutated"  # type: ignore[misc]


def test_mapping_validation_record_is_frozen() -> None:
    record = validate_mapping_relationship(
        _make_relationship(),
        validation_id="v-001",
        validated_at=_NOW,
    )
    with pytest.raises(Exception):
        record.is_valid = False  # type: ignore[misc]


def test_mapping_gap_record_is_frozen() -> None:
    gaps = detect_unmapped_controls(
        (_CTRL_A,),
        _FW_NIST,
        _V1,
        (),
        detected_at=_NOW,
    )
    assert len(gaps) == 1
    with pytest.raises(Exception):
        gaps[0].gap_type = MappingGapType.ORPHANED  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Metadata dict immutability (MappingProxyType)
# ---------------------------------------------------------------------------


def test_relationship_mapping_metadata_is_read_only() -> None:
    rel = _make_relationship()
    with pytest.raises(TypeError):
        rel.mapping_metadata["injected"] = "bad"  # type: ignore[index]


def test_inheritance_metadata_is_read_only() -> None:
    inh = _make_inheritance()
    with pytest.raises(TypeError):
        inh.inheritance_metadata["injected"] = "bad"  # type: ignore[index]


def test_framework_mapping_metadata_is_read_only() -> None:
    fm = _make_framework_mapping()
    with pytest.raises(TypeError):
        fm.mapping_metadata["injected"] = "bad"  # type: ignore[index]


def test_provenance_author_metadata_is_read_only() -> None:
    prov = _make_provenance()
    with pytest.raises(TypeError):
        prov.author_metadata["injected"] = "bad"  # type: ignore[index]


def test_provenance_governance_metadata_is_read_only() -> None:
    prov = _make_provenance()
    with pytest.raises(TypeError):
        prov.governance_metadata["injected"] = "bad"  # type: ignore[index]


def test_compatibility_metadata_is_read_only() -> None:
    compat = _make_compatibility()
    with pytest.raises(TypeError):
        compat.compatibility_metadata["injected"] = "bad"  # type: ignore[index]


# ---------------------------------------------------------------------------
# Defensive copy: caller mutation after construction does not affect stored content
# ---------------------------------------------------------------------------


def test_provenance_caller_dict_mutation_does_not_affect_stored() -> None:
    caller_meta: dict[str, Any] = {"key": "original"}
    prov = MappingProvenance(
        provenance_id="p1",
        source_authority="FrostGate",
        mapping_rationale="test",
        mapping_origin="manual",
        mapping_version="1.0.0",
        author_metadata=caller_meta,
    )
    caller_meta["key"] = "mutated"
    assert prov.author_metadata["key"] == "original"


def test_relationship_metadata_caller_mutation_does_not_affect_stored() -> None:
    caller_meta: dict[str, Any] = {"tag": "original"}
    rel = MappingRelationship(
        relationship_id="r1",
        source_control_id=_CTRL_A,
        source_framework_id=_FW_NIST,
        source_framework_version=_V1,
        target_control_id=_CTRL_B,
        target_framework_id=_FW_ISO,
        target_framework_version=_V1,
        relationship_type=MappingRelationshipType.EQUIVALENT,
        mapping_status=MappingStatus.ACTIVE,
        provenance=_make_provenance(),
        compatibility=_make_compatibility(),
        is_bidirectional=False,
        created_by="actor",
        created_at=_NOW,
        tenant_id=None,
        mapping_metadata=caller_meta,
    )
    caller_meta["tag"] = "mutated"
    assert rel.mapping_metadata["tag"] == "original"


# ---------------------------------------------------------------------------
# validate_mapping_relationship
# ---------------------------------------------------------------------------


def test_valid_relationship_passes_validation() -> None:
    rel = _make_relationship()
    record = validate_mapping_relationship(
        rel, validation_id="v-001", validated_at=_NOW
    )
    assert record.is_valid is True
    assert record.failure_reasons == ()
    assert record.validation_type == MappingValidationType.RELATIONSHIP
    assert record.validator_version == _VALIDATOR_VERSION


def test_self_mapping_fails_validation() -> None:
    rel = _make_relationship(
        source_control_id=_CTRL_A,
        source_framework_id=_FW_NIST,
        target_control_id=_CTRL_A,
        target_framework_id=_FW_NIST,
        compatibility=_make_compatibility(
            source_framework_id=_FW_NIST,
            target_framework_id=_FW_NIST,
        ),
    )
    record = validate_mapping_relationship(
        rel, validation_id="v-001", validated_at=_NOW
    )
    assert record.is_valid is False
    assert REASON_SELF_MAPPING in record.failure_reasons


def test_same_control_id_different_framework_is_not_self_mapping() -> None:
    """Control IDs that match across different frameworks are valid (not self-mapping)."""
    rel = _make_relationship(
        source_control_id="CONTROL-1",
        source_framework_id=_FW_NIST,
        target_control_id="CONTROL-1",
        target_framework_id=_FW_ISO,
    )
    record = validate_mapping_relationship(
        rel, validation_id="v-001", validated_at=_NOW
    )
    assert REASON_SELF_MAPPING not in record.failure_reasons


def test_tenant_isolation_violation_fails() -> None:
    rel = _make_relationship(tenant_id="tenant-other")
    record = validate_mapping_relationship(
        rel,
        validation_id="v-001",
        validated_at=_NOW,
        required_tenant_id=_TENANT,
    )
    assert record.is_valid is False
    assert REASON_TENANT_ISOLATION_VIOLATION in record.failure_reasons


def test_tenant_match_passes_isolation_check() -> None:
    rel = _make_relationship(tenant_id=_TENANT)
    record = validate_mapping_relationship(
        rel,
        validation_id="v-001",
        validated_at=_NOW,
        required_tenant_id=_TENANT,
    )
    assert REASON_TENANT_ISOLATION_VIOLATION not in record.failure_reasons


def test_no_required_tenant_skips_isolation_check() -> None:
    rel = _make_relationship(tenant_id="any-tenant")
    record = validate_mapping_relationship(
        rel, validation_id="v-001", validated_at=_NOW
    )
    assert REASON_TENANT_ISOLATION_VIOLATION not in record.failure_reasons


def test_empty_source_authority_fails() -> None:
    prov = _make_provenance(source_authority="")
    rel = _make_relationship(provenance=prov)
    record = validate_mapping_relationship(
        rel, validation_id="v-001", validated_at=_NOW
    )
    assert record.is_valid is False
    assert REASON_MISSING_SOURCE_AUTHORITY in record.failure_reasons


def test_whitespace_only_source_authority_fails() -> None:
    prov = _make_provenance(source_authority="   ")
    rel = _make_relationship(provenance=prov)
    record = validate_mapping_relationship(
        rel, validation_id="v-001", validated_at=_NOW
    )
    assert REASON_MISSING_SOURCE_AUTHORITY in record.failure_reasons


def test_empty_mapping_rationale_fails() -> None:
    prov = _make_provenance(mapping_rationale="")
    rel = _make_relationship(provenance=prov)
    record = validate_mapping_relationship(
        rel, validation_id="v-001", validated_at=_NOW
    )
    assert record.is_valid is False
    assert REASON_MISSING_MAPPING_RATIONALE in record.failure_reasons


def test_framework_id_mismatch_in_compatibility_fails() -> None:
    wrong_compat = _make_compatibility(
        source_framework_id="wrong-fw",
        target_framework_id=_FW_ISO,
    )
    rel = _make_relationship(compatibility=wrong_compat)
    record = validate_mapping_relationship(
        rel, validation_id="v-001", validated_at=_NOW
    )
    assert record.is_valid is False
    assert REASON_FRAMEWORK_ID_MISMATCH in record.failure_reasons


def test_multiple_relationship_failures_all_reported() -> None:
    prov = _make_provenance(source_authority="", mapping_rationale="")
    rel = _make_relationship(
        source_control_id=_CTRL_A,
        source_framework_id=_FW_NIST,
        target_control_id=_CTRL_A,
        target_framework_id=_FW_NIST,
        provenance=prov,
        compatibility=_make_compatibility(
            source_framework_id=_FW_NIST,
            target_framework_id=_FW_NIST,
        ),
        tenant_id=_OTHER_TENANT,
    )
    record = validate_mapping_relationship(
        rel,
        validation_id="v-001",
        validated_at=_NOW,
        required_tenant_id=_TENANT,
    )
    assert record.is_valid is False
    assert REASON_SELF_MAPPING in record.failure_reasons
    assert REASON_TENANT_ISOLATION_VIOLATION in record.failure_reasons
    assert REASON_MISSING_SOURCE_AUTHORITY in record.failure_reasons
    assert REASON_MISSING_MAPPING_RATIONALE in record.failure_reasons


# ---------------------------------------------------------------------------
# validate_control_inheritance
# ---------------------------------------------------------------------------


def test_valid_inheritance_passes() -> None:
    inh = _make_inheritance()
    record = validate_control_inheritance(inh, validation_id="v-001", validated_at=_NOW)
    assert record.is_valid is True
    assert record.failure_reasons == ()
    assert record.validation_type == MappingValidationType.INHERITANCE


def test_self_inheritance_fails() -> None:
    inh = _make_inheritance(
        parent_control_id=_CTRL_A,
        parent_framework_id=_FW_NIST,
        child_control_id=_CTRL_A,
        child_framework_id=_FW_NIST,
    )
    record = validate_control_inheritance(inh, validation_id="v-001", validated_at=_NOW)
    assert record.is_valid is False
    assert REASON_SELF_INHERITANCE in record.failure_reasons


def test_cross_framework_same_control_id_inheritance_is_valid() -> None:
    """Same control_id across different frameworks is cross-framework inheritance — valid."""
    inh = _make_inheritance(
        parent_control_id="CTRL-1",
        parent_framework_id=_FW_NIST,
        child_control_id="CTRL-1",
        child_framework_id=_FW_ISO,
    )
    record = validate_control_inheritance(inh, validation_id="v-001", validated_at=_NOW)
    assert REASON_SELF_INHERITANCE not in record.failure_reasons


def test_cross_tenant_inheritance_fails() -> None:
    inh = _make_inheritance(tenant_id=_OTHER_TENANT)
    record = validate_control_inheritance(
        inh,
        validation_id="v-001",
        validated_at=_NOW,
        required_tenant_id=_TENANT,
    )
    assert record.is_valid is False
    assert REASON_TENANT_ISOLATION_VIOLATION in record.failure_reasons


def test_inheritance_missing_provenance_fields_fail() -> None:
    prov = _make_provenance(source_authority="", mapping_rationale="")
    inh = _make_inheritance(provenance=prov)
    record = validate_control_inheritance(inh, validation_id="v-001", validated_at=_NOW)
    assert record.is_valid is False
    assert REASON_MISSING_SOURCE_AUTHORITY in record.failure_reasons
    assert REASON_MISSING_MAPPING_RATIONALE in record.failure_reasons


# ---------------------------------------------------------------------------
# detect_cyclic_inheritance
# ---------------------------------------------------------------------------


def test_no_cycles_returns_empty_tuple() -> None:
    inheritances = (
        _make_inheritance(
            inheritance_id="i1",
            parent_control_id=_CTRL_A,
            child_control_id=_CTRL_B,
        ),
        _make_inheritance(
            inheritance_id="i2",
            parent_control_id=_CTRL_B,
            child_control_id=_CTRL_C,
        ),
    )
    assert detect_cyclic_inheritance(inheritances) == ()


def test_simple_direct_cycle_detected() -> None:
    """A → B and B → A forms a cycle."""
    inheritances = (
        _make_inheritance(
            inheritance_id="i1",
            parent_control_id=_CTRL_A,
            child_control_id=_CTRL_B,
        ),
        _make_inheritance(
            inheritance_id="i2",
            parent_control_id=_CTRL_B,
            child_control_id=_CTRL_A,
        ),
    )
    cycles = detect_cyclic_inheritance(inheritances)
    assert len(cycles) > 0


def test_longer_cycle_detected() -> None:
    """A → B → C → A forms a cycle."""
    inheritances = (
        _make_inheritance(
            inheritance_id="i1",
            parent_control_id=_CTRL_A,
            child_control_id=_CTRL_B,
        ),
        _make_inheritance(
            inheritance_id="i2",
            parent_control_id=_CTRL_B,
            child_control_id=_CTRL_C,
        ),
        _make_inheritance(
            inheritance_id="i3",
            parent_control_id=_CTRL_C,
            child_control_id=_CTRL_A,
        ),
    )
    cycles = detect_cyclic_inheritance(inheritances)
    assert len(cycles) > 0


def test_linear_chain_not_flagged_as_cycle() -> None:
    """A → B → C is a valid chain with no cycle."""
    inheritances = (
        _make_inheritance(
            inheritance_id="i1",
            parent_control_id=_CTRL_A,
            child_control_id=_CTRL_B,
        ),
        _make_inheritance(
            inheritance_id="i2",
            parent_control_id=_CTRL_B,
            child_control_id=_CTRL_C,
        ),
    )
    assert detect_cyclic_inheritance(inheritances) == ()


def test_empty_inheritances_no_cycle() -> None:
    assert detect_cyclic_inheritance(()) == ()


# ---------------------------------------------------------------------------
# validate_framework_mapping
# ---------------------------------------------------------------------------


def test_valid_framework_mapping_passes() -> None:
    rel = _make_relationship()
    fm = _make_framework_mapping(relationships=(rel,))
    record = validate_framework_mapping(fm, validation_id="v-001", validated_at=_NOW)
    assert record.is_valid is True
    assert record.validation_type == MappingValidationType.FRAMEWORK


def test_duplicate_relationship_fails() -> None:
    rel_a = _make_relationship(relationship_id="r1")
    rel_b = _make_relationship(relationship_id="r2")  # same source/target/type
    fm = _make_framework_mapping(relationships=(rel_a, rel_b))
    record = validate_framework_mapping(fm, validation_id="v-001", validated_at=_NOW)
    assert record.is_valid is False
    assert REASON_DUPLICATE_RELATIONSHIP in record.failure_reasons


def test_different_relationship_types_same_pair_not_duplicate() -> None:
    rel_a = _make_relationship(
        relationship_id="r1",
        relationship_type=MappingRelationshipType.EQUIVALENT,
    )
    rel_b = _make_relationship(
        relationship_id="r2",
        relationship_type=MappingRelationshipType.SUPPLEMENTAL,
    )
    fm = _make_framework_mapping(relationships=(rel_a, rel_b))
    record = validate_framework_mapping(fm, validation_id="v-001", validated_at=_NOW)
    assert REASON_DUPLICATE_RELATIONSHIP not in record.failure_reasons


def test_framework_id_mismatch_in_relationships_fails() -> None:
    wrong_rel = _make_relationship(source_framework_id="wrong-fw")
    fm = _make_framework_mapping(
        source_framework_id=_FW_NIST,
        relationships=(wrong_rel,),
    )
    record = validate_framework_mapping(fm, validation_id="v-001", validated_at=_NOW)
    assert record.is_valid is False
    assert REASON_FRAMEWORK_ID_MISMATCH in record.failure_reasons


def test_scope_tenant_without_tenant_id_fails() -> None:
    fm = _make_framework_mapping(scope=MappingScope.TENANT, tenant_id=None)
    record = validate_framework_mapping(fm, validation_id="v-001", validated_at=_NOW)
    assert record.is_valid is False
    assert REASON_SCOPE_TENANT_MISMATCH in record.failure_reasons


def test_scope_tenant_with_tenant_id_passes() -> None:
    fm = _make_framework_mapping(scope=MappingScope.TENANT, tenant_id=_TENANT)
    record = validate_framework_mapping(fm, validation_id="v-001", validated_at=_NOW)
    assert REASON_SCOPE_TENANT_MISMATCH not in record.failure_reasons


def test_cyclic_inheritance_fails_framework_validation() -> None:
    inh_ab = _make_inheritance(
        inheritance_id="i1",
        parent_control_id=_CTRL_A,
        child_control_id=_CTRL_B,
    )
    inh_ba = _make_inheritance(
        inheritance_id="i2",
        parent_control_id=_CTRL_B,
        child_control_id=_CTRL_A,
    )
    fm = _make_framework_mapping(inheritances=(inh_ab, inh_ba))
    record = validate_framework_mapping(fm, validation_id="v-001", validated_at=_NOW)
    assert record.is_valid is False
    assert REASON_CYCLIC_INHERITANCE in record.failure_reasons


def test_empty_mapping_passes_validation() -> None:
    fm = _make_framework_mapping()
    record = validate_framework_mapping(fm, validation_id="v-001", validated_at=_NOW)
    assert record.is_valid is True


# ---------------------------------------------------------------------------
# validate_mapping_version
# ---------------------------------------------------------------------------


def test_valid_mapping_version_passes() -> None:
    mv = _make_mapping_version()
    record = validate_mapping_version(mv, validation_id="v-001", validated_at=_NOW)
    assert record.is_valid is True
    assert record.validation_type == MappingValidationType.VERSION


def test_empty_version_tag_fails() -> None:
    mv = _make_mapping_version(mapping_version_tag="")
    record = validate_mapping_version(mv, validation_id="v-001", validated_at=_NOW)
    assert record.is_valid is False
    assert REASON_VERSION_TAG_EMPTY in record.failure_reasons


def test_whitespace_version_tag_fails() -> None:
    mv = _make_mapping_version(mapping_version_tag="   ")
    record = validate_mapping_version(mv, validation_id="v-001", validated_at=_NOW)
    assert REASON_VERSION_TAG_EMPTY in record.failure_reasons


def test_self_supersession_fails() -> None:
    mv = _make_mapping_version(
        mapping_version_id="mv-001",
        superseded_by="mv-001",
    )
    record = validate_mapping_version(mv, validation_id="v-001", validated_at=_NOW)
    assert record.is_valid is False
    assert REASON_SELF_SUPERSESSION in record.failure_reasons


def test_superseded_by_different_id_passes() -> None:
    mv = _make_mapping_version(
        mapping_version_id="mv-001",
        superseded_by="mv-002",
    )
    record = validate_mapping_version(mv, validation_id="v-001", validated_at=_NOW)
    assert REASON_SELF_SUPERSESSION not in record.failure_reasons


# ---------------------------------------------------------------------------
# One-to-many and many-to-one mappings
# ---------------------------------------------------------------------------


def test_find_one_to_many_mappings() -> None:
    rel_ab = _make_relationship(
        relationship_id="r1",
        source_control_id=_CTRL_A,
        source_framework_id=_FW_NIST,
        target_control_id=_CTRL_B,
        target_framework_id=_FW_ISO,
    )
    rel_ac = _make_relationship(
        relationship_id="r2",
        source_control_id=_CTRL_A,
        source_framework_id=_FW_NIST,
        target_control_id=_CTRL_C,
        target_framework_id=_FW_ISO,
        compatibility=_make_compatibility(
            source_framework_id=_FW_NIST,
            target_framework_id=_FW_ISO,
        ),
    )
    one_to_many = find_one_to_many_mappings((rel_ab, rel_ac))
    key = f"{_FW_NIST}:{_CTRL_A}"
    assert key in one_to_many
    assert len(one_to_many[key]) == 2


def test_single_mapping_not_in_one_to_many() -> None:
    rel = _make_relationship()
    assert find_one_to_many_mappings((rel,)) == {}


def test_find_many_to_one_mappings() -> None:
    rel_ab = _make_relationship(
        relationship_id="r1",
        source_control_id=_CTRL_A,
        source_framework_id=_FW_NIST,
        target_control_id=_CTRL_C,
        target_framework_id=_FW_ISO,
    )
    rel_bc = _make_relationship(
        relationship_id="r2",
        source_control_id=_CTRL_B,
        source_framework_id=_FW_NIST,
        target_control_id=_CTRL_C,
        target_framework_id=_FW_ISO,
        compatibility=_make_compatibility(
            source_framework_id=_FW_NIST,
            target_framework_id=_FW_ISO,
        ),
    )
    many_to_one = find_many_to_one_mappings((rel_ab, rel_bc))
    key = f"{_FW_ISO}:{_CTRL_C}"
    assert key in many_to_one
    assert len(many_to_one[key]) == 2


def test_single_target_not_in_many_to_one() -> None:
    rel = _make_relationship()
    assert find_many_to_one_mappings((rel,)) == {}


def test_many_to_many_detected_in_both() -> None:
    """A→C, A→D, B→C, B→D: A and B are one-to-many; C and D are many-to-one."""
    rel_ac = _make_relationship(
        relationship_id="r1",
        source_control_id=_CTRL_A,
        source_framework_id=_FW_NIST,
        target_control_id=_CTRL_C,
        target_framework_id=_FW_ISO,
    )
    rel_ad = _make_relationship(
        relationship_id="r2",
        source_control_id=_CTRL_A,
        source_framework_id=_FW_NIST,
        target_control_id=_CTRL_D,
        target_framework_id=_FW_ISO,
        compatibility=_make_compatibility(
            source_framework_id=_FW_NIST,
            target_framework_id=_FW_ISO,
        ),
    )
    rel_bc = _make_relationship(
        relationship_id="r3",
        source_control_id=_CTRL_B,
        source_framework_id=_FW_NIST,
        target_control_id=_CTRL_C,
        target_framework_id=_FW_ISO,
        compatibility=_make_compatibility(
            source_framework_id=_FW_NIST,
            target_framework_id=_FW_ISO,
        ),
    )
    rel_bd = _make_relationship(
        relationship_id="r4",
        source_control_id=_CTRL_B,
        source_framework_id=_FW_NIST,
        target_control_id=_CTRL_D,
        target_framework_id=_FW_ISO,
        compatibility=_make_compatibility(
            source_framework_id=_FW_NIST,
            target_framework_id=_FW_ISO,
        ),
    )
    rels = (rel_ac, rel_ad, rel_bc, rel_bd)
    one_to_many = find_one_to_many_mappings(rels)
    many_to_one = find_many_to_one_mappings(rels)
    assert f"{_FW_NIST}:{_CTRL_A}" in one_to_many
    assert f"{_FW_NIST}:{_CTRL_B}" in one_to_many
    assert f"{_FW_ISO}:{_CTRL_C}" in many_to_one
    assert f"{_FW_ISO}:{_CTRL_D}" in many_to_one


# ---------------------------------------------------------------------------
# find_control_mappings
# ---------------------------------------------------------------------------


def test_find_control_mappings_outbound() -> None:
    rel = _make_relationship(
        source_control_id=_CTRL_A,
        source_framework_id=_FW_NIST,
        target_control_id=_CTRL_B,
        target_framework_id=_FW_ISO,
    )
    result = find_control_mappings(_CTRL_A, _FW_NIST, (rel,), direction="outbound")
    assert len(result) == 1
    assert result[0].relationship_id == rel.relationship_id


def test_find_control_mappings_inbound() -> None:
    rel = _make_relationship(
        source_control_id=_CTRL_A,
        source_framework_id=_FW_NIST,
        target_control_id=_CTRL_B,
        target_framework_id=_FW_ISO,
    )
    result = find_control_mappings(_CTRL_B, _FW_ISO, (rel,), direction="inbound")
    assert len(result) == 1
    assert result[0].relationship_id == rel.relationship_id


def test_find_control_mappings_both() -> None:
    rel_out = _make_relationship(
        relationship_id="r-out",
        source_control_id=_CTRL_B,
        source_framework_id=_FW_NIST,
        target_control_id=_CTRL_C,
        target_framework_id=_FW_ISO,
    )
    rel_in = _make_relationship(
        relationship_id="r-in",
        source_control_id=_CTRL_A,
        source_framework_id=_FW_NIST,
        target_control_id=_CTRL_B,
        target_framework_id=_FW_NIST,
        compatibility=_make_compatibility(
            source_framework_id=_FW_NIST,
            target_framework_id=_FW_NIST,
        ),
    )
    result = find_control_mappings(
        _CTRL_B, _FW_NIST, (rel_out, rel_in), direction="both"
    )
    assert len(result) == 2


def test_find_control_mappings_wrong_framework_excluded() -> None:
    """Same control_id in a different framework must not appear in results."""
    rel = _make_relationship(
        source_control_id=_CTRL_A,
        source_framework_id=_FW_ISO,  # different framework
        target_control_id=_CTRL_B,
        target_framework_id=_FW_SOC2,
        compatibility=_make_compatibility(
            source_framework_id=_FW_ISO,
            target_framework_id=_FW_SOC2,
        ),
    )
    result = find_control_mappings(_CTRL_A, _FW_NIST, (rel,), direction="outbound")
    assert result == ()


# ---------------------------------------------------------------------------
# Gap detection
# ---------------------------------------------------------------------------


def test_detect_unmapped_controls_all_unmapped() -> None:
    gaps = detect_unmapped_controls(
        (_CTRL_A, _CTRL_B),
        _FW_NIST,
        _V1,
        (),
        detected_at=_NOW,
    )
    assert len(gaps) == 2
    assert all(g.gap_type == MappingGapType.UNMAPPED for g in gaps)


def test_detect_unmapped_controls_mapped_excluded() -> None:
    rel = _make_relationship(
        source_control_id=_CTRL_A,
        source_framework_id=_FW_NIST,
        source_framework_version=_V1,
        target_control_id=_CTRL_B,
        target_framework_id=_FW_ISO,
    )
    gaps = detect_unmapped_controls(
        (_CTRL_A, _CTRL_B),
        _FW_NIST,
        _V1,
        (rel,),
        detected_at=_NOW,
    )
    gap_control_ids = {g.control_id for g in gaps}
    assert _CTRL_A not in gap_control_ids
    assert _CTRL_B in gap_control_ids


def test_detect_unmapped_controls_different_framework_version_not_counted() -> None:
    """A relationship for version "2.0" does not count as mapped for version "1.0"."""
    rel = _make_relationship(
        source_control_id=_CTRL_A,
        source_framework_id=_FW_NIST,
        source_framework_version="2.0",
        target_control_id=_CTRL_B,
        target_framework_id=_FW_ISO,
    )
    gaps = detect_unmapped_controls(
        (_CTRL_A,),
        _FW_NIST,
        _V1,
        (rel,),
        detected_at=_NOW,
    )
    assert any(g.control_id == _CTRL_A for g in gaps)


def test_detect_unmapped_gap_ids_are_deterministic() -> None:
    gaps1 = detect_unmapped_controls((_CTRL_A,), _FW_NIST, _V1, (), detected_at=_NOW)
    gaps2 = detect_unmapped_controls((_CTRL_A,), _FW_NIST, _V1, (), detected_at=_NOW)
    assert gaps1[0].gap_id == gaps2[0].gap_id


def test_detect_orphaned_relationships() -> None:
    rel = _make_relationship(
        source_control_id="unknown-ctrl",
        source_framework_id=_FW_NIST,
        target_control_id=_CTRL_B,
        target_framework_id=_FW_ISO,
    )
    orphans = detect_orphaned_relationships(
        (rel,),
        known_control_ids=frozenset({_CTRL_A, _CTRL_B}),
        known_framework_ids=frozenset({_FW_NIST, _FW_ISO}),
        detected_at=_NOW,
    )
    assert len(orphans) == 1
    assert orphans[0].gap_type == MappingGapType.ORPHANED


def test_fully_registered_relationships_not_orphaned() -> None:
    rel = _make_relationship(
        source_control_id=_CTRL_A,
        source_framework_id=_FW_NIST,
        target_control_id=_CTRL_B,
        target_framework_id=_FW_ISO,
    )
    orphans = detect_orphaned_relationships(
        (rel,),
        known_control_ids=frozenset({_CTRL_A, _CTRL_B}),
        known_framework_ids=frozenset({_FW_NIST, _FW_ISO}),
        detected_at=_NOW,
    )
    assert orphans == ()


def test_detect_missing_inheritance_targets() -> None:
    inh = _make_inheritance(
        parent_control_id="unknown-parent",
        child_control_id=_CTRL_B,
    )
    gaps = detect_missing_inheritance_targets(
        (inh,),
        known_control_ids=frozenset({_CTRL_A, _CTRL_B}),
        detected_at=_NOW,
    )
    assert len(gaps) == 1
    assert gaps[0].gap_type == MappingGapType.MISSING_INHERITANCE_TARGET


def test_known_inheritance_targets_not_in_gaps() -> None:
    inh = _make_inheritance(
        parent_control_id=_CTRL_A,
        child_control_id=_CTRL_B,
    )
    gaps = detect_missing_inheritance_targets(
        (inh,),
        known_control_ids=frozenset({_CTRL_A, _CTRL_B}),
        detected_at=_NOW,
    )
    assert gaps == ()


# ---------------------------------------------------------------------------
# Crosswalk generation
# ---------------------------------------------------------------------------


def test_crosswalk_entry_count_matches_control_count() -> None:
    crosswalk = build_crosswalk(
        (_CTRL_A, _CTRL_B, _CTRL_C),
        _FW_NIST,
        _V1,
        (),
        (),
    )
    assert len(crosswalk) == 3


def test_crosswalk_entry_order_matches_input_order() -> None:
    crosswalk = build_crosswalk(
        (_CTRL_C, _CTRL_A, _CTRL_B),
        _FW_NIST,
        _V1,
        (),
        (),
    )
    assert crosswalk[0].source_control_id == _CTRL_C
    assert crosswalk[1].source_control_id == _CTRL_A
    assert crosswalk[2].source_control_id == _CTRL_B


def test_crosswalk_unmapped_control_has_gap_status() -> None:
    crosswalk = build_crosswalk((_CTRL_A,), _FW_NIST, _V1, (), ())
    assert crosswalk[0].gap_status == MappingGapType.UNMAPPED


def test_crosswalk_outbound_relationship_populated() -> None:
    rel = _make_relationship(
        source_control_id=_CTRL_A,
        source_framework_id=_FW_NIST,
        source_framework_version=_V1,
        target_control_id=_CTRL_B,
        target_framework_id=_FW_ISO,
    )
    crosswalk = build_crosswalk((_CTRL_A,), _FW_NIST, _V1, (rel,), ())
    entry = crosswalk[0]
    assert len(entry.outbound_relationships) == 1
    assert entry.outbound_relationships[0].relationship_id == rel.relationship_id
    assert entry.gap_status is None


def test_crosswalk_inbound_relationship_populated() -> None:
    rel = _make_relationship(
        source_control_id=_CTRL_B,
        source_framework_id=_FW_ISO,
        source_framework_version=_V1,
        target_control_id=_CTRL_A,
        target_framework_id=_FW_NIST,
        target_framework_version=_V1,
        compatibility=_make_compatibility(
            source_framework_id=_FW_ISO,
            target_framework_id=_FW_NIST,
        ),
    )
    crosswalk = build_crosswalk((_CTRL_A,), _FW_NIST, _V1, (rel,), ())
    entry = crosswalk[0]
    assert len(entry.inbound_relationships) == 1
    assert entry.gap_status is None


def test_crosswalk_inheritance_populated() -> None:
    inh = _make_inheritance(
        parent_control_id=_CTRL_B,
        parent_framework_id=_FW_ISO,
        child_control_id=_CTRL_A,
        child_framework_id=_FW_NIST,
        child_framework_version=_V1,
    )
    crosswalk = build_crosswalk((_CTRL_A,), _FW_NIST, _V1, (), (inh,))
    entry = crosswalk[0]
    assert len(entry.inheritances) == 1
    assert entry.gap_status is None


def test_crosswalk_version_scoped_correctly() -> None:
    """Relationships for a different framework version must not appear in crosswalk."""
    rel = _make_relationship(
        source_control_id=_CTRL_A,
        source_framework_id=_FW_NIST,
        source_framework_version="2.0",  # different version
        target_control_id=_CTRL_B,
        target_framework_id=_FW_ISO,
    )
    crosswalk = build_crosswalk((_CTRL_A,), _FW_NIST, _V1, (rel,), ())
    entry = crosswalk[0]
    assert len(entry.outbound_relationships) == 0
    assert entry.gap_status == MappingGapType.UNMAPPED


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


def test_platform_level_mapping_has_none_tenant_id() -> None:
    fm = _make_framework_mapping(scope=MappingScope.PLATFORM, tenant_id=None)
    assert fm.tenant_id is None
    assert fm.scope == MappingScope.PLATFORM


def test_tenant_scoped_mapping_has_tenant_id() -> None:
    fm = _make_framework_mapping(scope=MappingScope.TENANT, tenant_id=_TENANT)
    assert fm.tenant_id == _TENANT
    assert fm.scope == MappingScope.TENANT


def test_cross_tenant_relationship_fails_validation() -> None:
    rel = _make_relationship(tenant_id=_OTHER_TENANT)
    record = validate_mapping_relationship(
        rel,
        validation_id="v-001",
        validated_at=_NOW,
        required_tenant_id=_TENANT,
    )
    assert record.is_valid is False
    assert REASON_TENANT_ISOLATION_VIOLATION in record.failure_reasons


# ---------------------------------------------------------------------------
# Additive framework support
# ---------------------------------------------------------------------------


def test_new_framework_relationship_independent_of_existing() -> None:
    """Adding a relationship to FW_SOC2 must not affect NIST→ISO relationships."""
    rel_nist_iso = _make_relationship(
        relationship_id="r1",
        source_framework_id=_FW_NIST,
        target_framework_id=_FW_ISO,
    )
    rel_nist_soc2 = _make_relationship(
        relationship_id="r2",
        source_control_id=_CTRL_A,
        source_framework_id=_FW_NIST,
        target_control_id=_CTRL_C,
        target_framework_id=_FW_SOC2,
        compatibility=_make_compatibility(
            source_framework_id=_FW_NIST,
            target_framework_id=_FW_SOC2,
        ),
    )
    iso_results = find_control_mappings(
        _CTRL_A, _FW_NIST, (rel_nist_iso, rel_nist_soc2), direction="outbound"
    )
    iso_targets = {r.target_framework_id for r in iso_results}
    assert _FW_ISO in iso_targets
    assert _FW_SOC2 in iso_targets
    assert len(iso_results) == 2


def test_no_semantic_coupling_between_framework_definitions() -> None:
    """ControlReference stores IDs only — no framework-internal semantics are merged."""
    rel = _make_relationship(
        source_framework_id=_FW_NIST,
        target_framework_id=_FW_ISO,
        relationship_type=MappingRelationshipType.PARTIALLY_EQUIVALENT,
    )
    assert rel.source_framework_id == _FW_NIST
    assert rel.target_framework_id == _FW_ISO
    assert rel.relationship_type == MappingRelationshipType.PARTIALLY_EQUIVALENT
    # Frameworks remain isolated; no merged attributes


def test_mapping_version_tag_is_semver_string() -> None:
    parts = _VALIDATOR_VERSION.split(".")
    assert len(parts) == 3
    assert all(p.isdigit() for p in parts)
