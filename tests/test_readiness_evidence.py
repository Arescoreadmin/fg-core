"""Tests for the Enterprise Evidence Contract & Provenance Governance Layer.

No database. No I/O. Pure Python deterministic contracts.

Test categories:
- Hash stability and determinism
- Replay safety (inputs_canonical is sufficient to reproduce hash)
- Immutability (frozen dataclasses, terminal states)
- Provenance linkage and consistency
- Classification validation
- Tenant isolation (cross-tenant rejection)
- Lifecycle state machine
- Evidence linkage validation
- Integrity validation
- Invalid evidence rejection
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from services.readiness.evidence import (
    REASON_CLASSIFICATION_INVALID,
    REASON_CLASSIFICATION_MISSING,
    REASON_HASH_ALGORITHM_UNSUPPORTED,
    REASON_HASH_MISMATCH,
    REASON_LINKAGE_EMPTY,
    REASON_LINKAGE_TENANT_MISMATCH,
    REASON_PROVENANCE_SOURCE_MISSING,
    REASON_PROVENANCE_SOURCE_TENANT_MISMATCH,
    REASON_PROVENANCE_TENANT_MISMATCH,
    REASON_STATE_EXPIRED,
    REASON_STATE_INVALIDATED,
    REASON_STATE_SUPERSEDED,
    REASON_TENANT_MISMATCH,
    REASON_TENANT_MISSING,
    compute_evidence_hash,
    replay_hash_from_canonical,
    validate_evidence_classification,
    validate_evidence_integrity,
    validate_evidence_lifecycle,
    validate_evidence_linkage,
    validate_evidence_provenance,
    validate_evidence_lifecycle_transition,
    validate_tenant_isolation,
    verify_evidence_hash,
)
from services.readiness.evidence.models import (
    IMMUTABLE_EVIDENCE_STATES,
    EvidenceCategory,
    EvidenceClassificationLevel,
    EvidenceCollectionMethod,
    EvidenceHashRecord,
    EvidenceIntegrityRecord,
    EvidenceLifecycleState,
    EvidenceLink,
    EvidenceLinkType,
    EvidenceProvenance,
    EvidenceSource,
    EvidenceValidationType,
)

# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
_TENANT = "tenant-a"
_OTHER_TENANT = "tenant-b"
_EVIDENCE_ID = "ev-001"
_ASSESSMENT_ID = "assess-001"


def _source(tenant_id: str = _TENANT) -> EvidenceSource:
    return EvidenceSource(
        source_id="src-001",
        source_system="manual",
        collection_method=EvidenceCollectionMethod.MANUAL_UPLOAD,
        collection_actor="actor-x",
        collected_at=_NOW,
        tenant_id=tenant_id,
    )


def _provenance(
    evidence_id: str = _EVIDENCE_ID,
    tenant_id: str = _TENANT,
    source_tenant: str = _TENANT,
) -> EvidenceProvenance:
    return EvidenceProvenance(
        provenance_id=str(uuid.uuid4()),
        evidence_id=evidence_id,
        tenant_id=tenant_id,
        source=_source(tenant_id=source_tenant),
        provenance_version="1.0",
        assessment_id=_ASSESSMENT_ID,
        control_ids=("ctrl-1", "ctrl-2"),
        framework_id="fw-001",
    )


def _hash_record(hash_value: str = "") -> EvidenceHashRecord:
    rec = compute_evidence_hash(
        evidence_id=_EVIDENCE_ID,
        assessment_id=_ASSESSMENT_ID,
        tenant_id=_TENANT,
        evidence_type="document",
        evidence_title="Policy doc",
        submitted_by="actor-x",
        control_ids=["ctrl-1", "ctrl-2"],
        evidence_classification="internal",
    )
    if hash_value:
        # Return a record with a tampered hash_value for negative tests
        return EvidenceHashRecord(
            evidence_id=rec.evidence_id,
            algorithm=rec.algorithm,
            hash_value=hash_value,
            inputs_canonical=rec.inputs_canonical,
            inputs_description=rec.inputs_description,
            computed_at=rec.computed_at,
            is_replay_safe=rec.is_replay_safe,
        )
    return rec


def _integrity_record(
    hash_value: str = "",
    tenant_id: str = _TENANT,
    algorithm: str = "sha256",
) -> EvidenceIntegrityRecord:
    hr = _hash_record(hash_value=hash_value)
    if algorithm != "sha256":
        hr = EvidenceHashRecord(
            evidence_id=hr.evidence_id,
            algorithm=algorithm,
            hash_value=hr.hash_value,
            inputs_canonical=hr.inputs_canonical,
            inputs_description=hr.inputs_description,
            computed_at=hr.computed_at,
            is_replay_safe=hr.is_replay_safe,
        )
    return EvidenceIntegrityRecord(
        integrity_id=str(uuid.uuid4()),
        evidence_id=_EVIDENCE_ID,
        tenant_id=tenant_id,
        hash_record=hr,
        is_verified=False,
    )


# ---------------------------------------------------------------------------
# Hash determinism and stability
# ---------------------------------------------------------------------------


def test_hash_is_deterministic():
    h1 = compute_evidence_hash(
        evidence_id="ev-1",
        assessment_id="a-1",
        tenant_id="t-1",
        evidence_type="document",
        evidence_title="Title",
        submitted_by="actor",
        control_ids=["c1", "c2"],
        evidence_classification="internal",
    )
    h2 = compute_evidence_hash(
        evidence_id="ev-1",
        assessment_id="a-1",
        tenant_id="t-1",
        evidence_type="document",
        evidence_title="Title",
        submitted_by="actor",
        control_ids=["c1", "c2"],
        evidence_classification="internal",
    )
    assert h1.hash_value == h2.hash_value


def test_hash_stable_across_control_id_ordering():
    # control_ids ordering must not affect hash
    h1 = compute_evidence_hash(
        evidence_id="ev-1",
        assessment_id="a-1",
        tenant_id="t-1",
        evidence_type="document",
        evidence_title="Title",
        submitted_by="actor",
        control_ids=["c2", "c1"],
        evidence_classification="internal",
    )
    h2 = compute_evidence_hash(
        evidence_id="ev-1",
        assessment_id="a-1",
        tenant_id="t-1",
        evidence_type="document",
        evidence_title="Title",
        submitted_by="actor",
        control_ids=["c1", "c2"],
        evidence_classification="internal",
    )
    assert h1.hash_value == h2.hash_value


def test_hash_changes_on_evidence_id_change():
    h1 = compute_evidence_hash(
        evidence_id="ev-A",
        assessment_id="a-1",
        tenant_id="t-1",
        evidence_type="document",
        evidence_title="Title",
        submitted_by="actor",
        control_ids=["c1"],
        evidence_classification="internal",
    )
    h2 = compute_evidence_hash(
        evidence_id="ev-B",
        assessment_id="a-1",
        tenant_id="t-1",
        evidence_type="document",
        evidence_title="Title",
        submitted_by="actor",
        control_ids=["c1"],
        evidence_classification="internal",
    )
    assert h1.hash_value != h2.hash_value


def test_hash_changes_on_title_change():
    h1 = compute_evidence_hash(
        evidence_id="ev-1",
        assessment_id="a-1",
        tenant_id="t-1",
        evidence_type="document",
        evidence_title="Original title",
        submitted_by="actor",
        control_ids=["c1"],
        evidence_classification="internal",
    )
    h2 = compute_evidence_hash(
        evidence_id="ev-1",
        assessment_id="a-1",
        tenant_id="t-1",
        evidence_type="document",
        evidence_title="Tampered title",
        submitted_by="actor",
        control_ids=["c1"],
        evidence_classification="internal",
    )
    assert h1.hash_value != h2.hash_value


def test_hash_changes_on_tenant_change():
    h1 = compute_evidence_hash(
        evidence_id="ev-1",
        assessment_id="a-1",
        tenant_id="tenant-A",
        evidence_type="document",
        evidence_title="Title",
        submitted_by="actor",
        control_ids=["c1"],
        evidence_classification="internal",
    )
    h2 = compute_evidence_hash(
        evidence_id="ev-1",
        assessment_id="a-1",
        tenant_id="tenant-B",
        evidence_type="document",
        evidence_title="Title",
        submitted_by="actor",
        control_ids=["c1"],
        evidence_classification="internal",
    )
    assert h1.hash_value != h2.hash_value


def test_hash_is_replay_safe():
    record = compute_evidence_hash(
        evidence_id="ev-1",
        assessment_id="a-1",
        tenant_id="t-1",
        evidence_type="document",
        evidence_title="Title",
        submitted_by="actor",
        control_ids=["c1"],
        evidence_classification="confidential",
    )
    assert record.is_replay_safe is True
    replayed = replay_hash_from_canonical(record.inputs_canonical)
    assert replayed == record.hash_value


def test_inputs_canonical_is_deterministic_json():
    record = compute_evidence_hash(
        evidence_id="ev-1",
        assessment_id="a-1",
        tenant_id="t-1",
        evidence_type="document",
        evidence_title="Title",
        submitted_by="actor",
        control_ids=["c1"],
        evidence_classification="internal",
    )
    # inputs_canonical must be valid JSON without whitespace
    import json

    parsed = json.loads(record.inputs_canonical)
    assert parsed["evidence_id"] == "ev-1"
    assert parsed["tenant_id"] == "t-1"
    assert " " not in record.inputs_canonical  # compact separators


def test_hash_unsupported_algorithm_raises():
    with pytest.raises(ValueError, match="Unsupported hash algorithm"):
        compute_evidence_hash(
            evidence_id="ev-1",
            assessment_id="a-1",
            tenant_id="t-1",
            evidence_type="document",
            evidence_title="Title",
            submitted_by="actor",
            control_ids=[],
            evidence_classification=None,
            algorithm="md5",
        )


def test_verify_evidence_hash_pass():
    record = compute_evidence_hash(
        evidence_id="ev-1",
        assessment_id="a-1",
        tenant_id="t-1",
        evidence_type="document",
        evidence_title="Title",
        submitted_by="actor",
        control_ids=["c1"],
        evidence_classification="internal",
    )
    assert verify_evidence_hash(
        evidence_id="ev-1",
        assessment_id="a-1",
        tenant_id="t-1",
        evidence_type="document",
        evidence_title="Title",
        submitted_by="actor",
        control_ids=["c1"],
        evidence_classification="internal",
        expected_hash=record.hash_value,
    )


def test_verify_evidence_hash_fail():
    assert not verify_evidence_hash(
        evidence_id="ev-1",
        assessment_id="a-1",
        tenant_id="t-1",
        evidence_type="document",
        evidence_title="Title",
        submitted_by="actor",
        control_ids=["c1"],
        evidence_classification="internal",
        expected_hash="0000000000000000000000000000000000000000000000000000000000000000",
    )


# ---------------------------------------------------------------------------
# Immutability — frozen dataclasses
# ---------------------------------------------------------------------------


def test_evidence_source_is_frozen():
    src = _source()
    with pytest.raises((AttributeError, TypeError)):
        src.source_system = "tampered"  # type: ignore[misc]


def test_evidence_provenance_is_frozen():
    prov = _provenance()
    with pytest.raises((AttributeError, TypeError)):
        prov.assessment_id = "tampered"  # type: ignore[misc]


def test_evidence_hash_record_is_frozen():
    record = compute_evidence_hash(
        evidence_id="ev-1",
        assessment_id="a-1",
        tenant_id="t-1",
        evidence_type="document",
        evidence_title="Title",
        submitted_by="actor",
        control_ids=[],
        evidence_classification=None,
    )
    with pytest.raises((AttributeError, TypeError)):
        record.hash_value = "tampered"  # type: ignore[misc]


def test_evidence_integrity_record_is_frozen():
    ir = _integrity_record()
    with pytest.raises((AttributeError, TypeError)):
        ir.is_verified = True  # type: ignore[misc]


def test_evidence_link_is_frozen():
    link = EvidenceLink(
        link_id="lk-1",
        evidence_id=_EVIDENCE_ID,
        tenant_id=_TENANT,
        link_type=EvidenceLinkType.CONTROL,
        target_id="ctrl-1",
        target_type="control",
        created_at=_NOW,
    )
    with pytest.raises((AttributeError, TypeError)):
        link.target_id = "tampered"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Lifecycle state machine
# ---------------------------------------------------------------------------


def test_lifecycle_pending_to_active():
    validate_evidence_lifecycle_transition(
        EvidenceLifecycleState.PENDING, EvidenceLifecycleState.ACTIVE
    )


def test_lifecycle_pending_to_invalidated():
    validate_evidence_lifecycle_transition(
        EvidenceLifecycleState.PENDING, EvidenceLifecycleState.INVALIDATED
    )


def test_lifecycle_active_to_superseded():
    validate_evidence_lifecycle_transition(
        EvidenceLifecycleState.ACTIVE, EvidenceLifecycleState.SUPERSEDED
    )


def test_lifecycle_active_to_archived():
    validate_evidence_lifecycle_transition(
        EvidenceLifecycleState.ACTIVE, EvidenceLifecycleState.ARCHIVED
    )


def test_lifecycle_invalidated_is_terminal():
    with pytest.raises(ValueError):
        validate_evidence_lifecycle_transition(
            EvidenceLifecycleState.INVALIDATED, EvidenceLifecycleState.ACTIVE
        )


def test_lifecycle_archived_is_semi_terminal():
    with pytest.raises(ValueError):
        validate_evidence_lifecycle_transition(
            EvidenceLifecycleState.ARCHIVED, EvidenceLifecycleState.ACTIVE
        )


def test_immutable_states_set():
    assert EvidenceLifecycleState.INVALIDATED in IMMUTABLE_EVIDENCE_STATES
    assert EvidenceLifecycleState.ARCHIVED in IMMUTABLE_EVIDENCE_STATES
    assert EvidenceLifecycleState.ACTIVE not in IMMUTABLE_EVIDENCE_STATES


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


def test_tenant_isolation_pass():
    result = validate_tenant_isolation(
        evidence_tenant_id=_TENANT,
        caller_tenant_id=_TENANT,
        validation_id="v-1",
        evidence_id=_EVIDENCE_ID,
    )
    assert result.is_valid is True
    assert result.failure_reasons == ()


def test_tenant_isolation_cross_tenant_fail():
    result = validate_tenant_isolation(
        evidence_tenant_id=_TENANT,
        caller_tenant_id=_OTHER_TENANT,
        validation_id="v-1",
        evidence_id=_EVIDENCE_ID,
    )
    assert result.is_valid is False
    assert REASON_TENANT_MISMATCH in result.failure_reasons


def test_tenant_isolation_missing_tenant_fail():
    result = validate_tenant_isolation(
        evidence_tenant_id="",
        caller_tenant_id=_TENANT,
        validation_id="v-1",
        evidence_id=_EVIDENCE_ID,
    )
    assert result.is_valid is False
    assert REASON_TENANT_MISSING in result.failure_reasons


def test_tenant_isolation_validation_type():
    result = validate_tenant_isolation(
        evidence_tenant_id=_TENANT,
        caller_tenant_id=_OTHER_TENANT,
        validation_id="v-1",
        evidence_id=_EVIDENCE_ID,
    )
    assert result.validation_type == EvidenceValidationType.TENANT_ISOLATION


# ---------------------------------------------------------------------------
# Classification validation
# ---------------------------------------------------------------------------


def test_classification_valid_levels():
    for level in EvidenceClassificationLevel:
        result = validate_evidence_classification(
            evidence_id=_EVIDENCE_ID,
            tenant_id=_TENANT,
            classification=level.value,
            validation_id="v-1",
        )
        assert result.is_valid is True, f"Expected {level.value} to be valid"


def test_classification_unknown_value_fails():
    result = validate_evidence_classification(
        evidence_id=_EVIDENCE_ID,
        tenant_id=_TENANT,
        classification="top_secret",
        validation_id="v-1",
    )
    assert result.is_valid is False
    assert REASON_CLASSIFICATION_INVALID in result.failure_reasons


def test_classification_none_optional_passes():
    result = validate_evidence_classification(
        evidence_id=_EVIDENCE_ID,
        tenant_id=_TENANT,
        classification=None,
        require_explicit=False,
        validation_id="v-1",
    )
    assert result.is_valid is True


def test_classification_none_required_fails():
    result = validate_evidence_classification(
        evidence_id=_EVIDENCE_ID,
        tenant_id=_TENANT,
        classification=None,
        require_explicit=True,
        validation_id="v-1",
    )
    assert result.is_valid is False
    assert REASON_CLASSIFICATION_MISSING in result.failure_reasons


# ---------------------------------------------------------------------------
# Integrity validation
# ---------------------------------------------------------------------------


def test_integrity_valid_hash_passes():
    ir = _integrity_record()
    recomputed = replay_hash_from_canonical(ir.hash_record.inputs_canonical)
    result = validate_evidence_integrity(
        integrity_record=ir,
        recomputed_hash=recomputed,
        validation_id="v-1",
    )
    assert result.is_valid is True
    assert result.failure_reasons == ()


def test_integrity_tampered_hash_fails():
    ir = _integrity_record(hash_value="deadbeef" * 8)
    recomputed = replay_hash_from_canonical(ir.hash_record.inputs_canonical)
    result = validate_evidence_integrity(
        integrity_record=ir,
        recomputed_hash=recomputed,
        validation_id="v-1",
    )
    assert result.is_valid is False
    assert REASON_HASH_MISMATCH in result.failure_reasons


def test_integrity_unsupported_algorithm_fails():
    ir = _integrity_record(algorithm="md5")
    result = validate_evidence_integrity(
        integrity_record=ir,
        recomputed_hash="irrelevant",
        validation_id="v-1",
    )
    assert result.is_valid is False
    assert REASON_HASH_ALGORITHM_UNSUPPORTED in result.failure_reasons


# ---------------------------------------------------------------------------
# Provenance validation
# ---------------------------------------------------------------------------


def test_provenance_valid():
    prov = _provenance()
    result = validate_evidence_provenance(
        provenance=prov,
        evidence_tenant_id=_TENANT,
        validation_id="v-1",
    )
    assert result.is_valid is True
    assert result.failure_reasons == ()


def test_provenance_tenant_mismatch_fails():
    prov = _provenance(tenant_id=_OTHER_TENANT)
    result = validate_evidence_provenance(
        provenance=prov,
        evidence_tenant_id=_TENANT,
        validation_id="v-1",
    )
    assert result.is_valid is False
    assert REASON_PROVENANCE_TENANT_MISMATCH in result.failure_reasons


def test_provenance_source_tenant_mismatch_fails():
    prov = _provenance(source_tenant=_OTHER_TENANT)
    result = validate_evidence_provenance(
        provenance=prov,
        evidence_tenant_id=_TENANT,
        validation_id="v-1",
    )
    assert result.is_valid is False
    assert REASON_PROVENANCE_SOURCE_TENANT_MISMATCH in result.failure_reasons


def test_provenance_missing_source_fails():
    # Build provenance manually with None source
    prov = EvidenceProvenance(
        provenance_id="prov-1",
        evidence_id=_EVIDENCE_ID,
        tenant_id=_TENANT,
        source=None,  # type: ignore[arg-type]
        provenance_version="1.0",
    )
    result = validate_evidence_provenance(
        provenance=prov,
        evidence_tenant_id=_TENANT,
        validation_id="v-1",
    )
    assert result.is_valid is False
    assert REASON_PROVENANCE_SOURCE_MISSING in result.failure_reasons


# ---------------------------------------------------------------------------
# Lifecycle eligibility validation
# ---------------------------------------------------------------------------


def test_lifecycle_active_is_eligible():
    result = validate_evidence_lifecycle(
        evidence_id=_EVIDENCE_ID,
        tenant_id=_TENANT,
        lifecycle_state=EvidenceLifecycleState.ACTIVE,
        validation_id="v-1",
    )
    assert result.is_valid is True


def test_lifecycle_pending_is_eligible():
    result = validate_evidence_lifecycle(
        evidence_id=_EVIDENCE_ID,
        tenant_id=_TENANT,
        lifecycle_state=EvidenceLifecycleState.PENDING,
        validation_id="v-1",
    )
    assert result.is_valid is True


def test_lifecycle_invalidated_is_not_eligible():
    result = validate_evidence_lifecycle(
        evidence_id=_EVIDENCE_ID,
        tenant_id=_TENANT,
        lifecycle_state=EvidenceLifecycleState.INVALIDATED,
        validation_id="v-1",
    )
    assert result.is_valid is False
    assert REASON_STATE_INVALIDATED in result.failure_reasons


def test_lifecycle_superseded_is_not_eligible():
    result = validate_evidence_lifecycle(
        evidence_id=_EVIDENCE_ID,
        tenant_id=_TENANT,
        lifecycle_state=EvidenceLifecycleState.SUPERSEDED,
        validation_id="v-1",
    )
    assert result.is_valid is False
    assert REASON_STATE_SUPERSEDED in result.failure_reasons


def test_lifecycle_expired_is_not_eligible():
    result = validate_evidence_lifecycle(
        evidence_id=_EVIDENCE_ID,
        tenant_id=_TENANT,
        lifecycle_state=EvidenceLifecycleState.EXPIRED,
        validation_id="v-1",
    )
    assert result.is_valid is False
    assert REASON_STATE_EXPIRED in result.failure_reasons


# ---------------------------------------------------------------------------
# Linkage validation
# ---------------------------------------------------------------------------


def test_linkage_valid_with_controls():
    result = validate_evidence_linkage(
        evidence_id=_EVIDENCE_ID,
        tenant_id=_TENANT,
        control_ids=["ctrl-1", "ctrl-2"],
        link_tenant_ids=[_TENANT],
        validation_id="v-1",
    )
    assert result.is_valid is True


def test_linkage_empty_control_ids_fails():
    result = validate_evidence_linkage(
        evidence_id=_EVIDENCE_ID,
        tenant_id=_TENANT,
        control_ids=[],
        link_tenant_ids=[],
        validation_id="v-1",
    )
    assert result.is_valid is False
    assert REASON_LINKAGE_EMPTY in result.failure_reasons


def test_linkage_cross_tenant_target_fails():
    result = validate_evidence_linkage(
        evidence_id=_EVIDENCE_ID,
        tenant_id=_TENANT,
        control_ids=["ctrl-1"],
        link_tenant_ids=[_OTHER_TENANT],
        validation_id="v-1",
    )
    assert result.is_valid is False
    assert REASON_LINKAGE_TENANT_MISMATCH in result.failure_reasons


# ---------------------------------------------------------------------------
# EvidenceLink immutability and type safety
# ---------------------------------------------------------------------------


def test_evidence_link_default_metadata():
    link = EvidenceLink(
        link_id="lk-1",
        evidence_id=_EVIDENCE_ID,
        tenant_id=_TENANT,
        link_type=EvidenceLinkType.ASSESSMENT_RESULT,
        target_id="result-1",
        target_type="assessment_result",
        created_at=_NOW,
    )
    assert link.link_metadata == {}


def test_evidence_link_all_types_constructible():
    for link_type in EvidenceLinkType:
        link = EvidenceLink(
            link_id=str(uuid.uuid4()),
            evidence_id=_EVIDENCE_ID,
            tenant_id=_TENANT,
            link_type=link_type,
            target_id="target-1",
            target_type=link_type.value,
            created_at=_NOW,
        )
        assert link.link_type == link_type


# ---------------------------------------------------------------------------
# Category and classification enum completeness
# ---------------------------------------------------------------------------


def test_all_evidence_categories_valid():
    for cat in EvidenceCategory:
        assert isinstance(cat.value, str)
        assert cat.value  # non-empty


def test_all_classification_levels_valid():
    for level in EvidenceClassificationLevel:
        assert isinstance(level.value, str)


# ---------------------------------------------------------------------------
# Provenance chain linkage
# ---------------------------------------------------------------------------


def test_provenance_control_linkage():
    prov = _provenance()
    assert "ctrl-1" in prov.control_ids
    assert "ctrl-2" in prov.control_ids


def test_provenance_assessment_linkage():
    prov = _provenance()
    assert prov.assessment_id == _ASSESSMENT_ID


def test_provenance_source_metadata():
    src = _source()
    assert src.source_metadata == {}
    assert src.source_system == "manual"
    assert src.tenant_id == _TENANT


def test_provenance_reconstructable():
    prov = _provenance()
    # All fields needed for forensic reconstruction are present
    assert prov.provenance_id
    assert prov.evidence_id
    assert prov.tenant_id
    assert prov.source is not None
    assert prov.provenance_version


# ---------------------------------------------------------------------------
# Validator version is stable
# ---------------------------------------------------------------------------


def test_validation_record_has_version():
    result = validate_tenant_isolation(
        evidence_tenant_id=_TENANT,
        caller_tenant_id=_TENANT,
        validation_id="v-1",
        evidence_id=_EVIDENCE_ID,
    )
    assert result.validator_version == "1.0.0"
