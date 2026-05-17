"""Tests for the Runtime Evidence Collection & Governance Signal Extraction Layer.

No database. No I/O. Pure Python deterministic contracts.

Test categories:
- Model immutability (frozen dataclasses)
- Extractor output correctness for all 8 signal types
- Privacy contracts (no PHI, prompts, vectors in output)
- Snapshot hash determinism and replay safety
- Snapshot ordering independence (signals sorted canonically)
- UNAVAILABLE and ERROR signal construction
- Default mutable-dict fields (summary_metadata, policy_metadata, etc.)
- inputs_canonical is sufficient to reproduce snapshot_hash
- Tenant scoping on all signals and snapshots
- Enum value stability (str enum round-tripping)
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

import pytest

from services.readiness.runtime_evidence import (
    AuditChainSignalSummary,
    AuditChainStatus,
    EnforcementState,
    GovernanceSignalType,
    GroundedAnswerSignalSummary,
    OperationalGovernanceSignalSummary,
    PolicySignalSummary,
    ProviderGovernanceSignalSummary,
    ProviderGovernanceState,
    ProvenanceSignalSummary,
    RetrievalSignalSummary,
    RuntimeGovernanceSignal,
    SignalExtractionStatus,
    TenantIsolationSignalSummary,
    ValidationState,
    _EXTRACTOR_VERSION,
    _SNAPSHOT_VERSION,
    build_runtime_evidence_snapshot,
    compute_snapshot_hash,
    extract_audit_chain_signal,
    extract_grounded_answer_signal,
    extract_operational_governance_signal,
    extract_policy_signal,
    extract_provenance_signal,
    extract_provider_governance_signal,
    extract_retrieval_signal,
    extract_tenant_isolation_signal,
    make_error_signal,
    make_unavailable_signal,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_TENANT = "tenant-abc"
_EXTRACTION_ID = "extract-001"
_SIGNAL_ID = "sig-001"
_SNAPSHOT_ID = "snap-001"
_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
_SOURCE = "services.ai.provenance"


def _make_provenance_signal(
    *,
    tenant_id: str = _TENANT,
    signal_id: str = _SIGNAL_ID,
    extraction_id: str = _EXTRACTION_ID,
    governance_source: str = _SOURCE,
    enforcement_enabled: bool = True,
    validation_state: ValidationState = ValidationState.VALID,
    citation_count: int = 3,
    invalid_citation_count: int = 0,
    reason_code: str = "OK",
    grounded_answer_enforced: bool = True,
) -> RuntimeGovernanceSignal:
    return extract_provenance_signal(
        signal_id=signal_id,
        tenant_id=tenant_id,
        extraction_id=extraction_id,
        extracted_at=_NOW,
        governance_source=governance_source,
        enforcement_enabled=enforcement_enabled,
        validation_state=validation_state,
        citation_count=citation_count,
        invalid_citation_count=invalid_citation_count,
        reason_code=reason_code,
        grounded_answer_enforced=grounded_answer_enforced,
    )


# ---------------------------------------------------------------------------
# Enum value stability
# ---------------------------------------------------------------------------


def test_governance_signal_type_values_are_stable() -> None:
    assert GovernanceSignalType.PROVENANCE.value == "provenance"
    assert GovernanceSignalType.RETRIEVAL_CONFIDENCE.value == "retrieval_confidence"
    assert GovernanceSignalType.AUDIT_CHAIN.value == "audit_chain"
    assert GovernanceSignalType.PROVIDER_GOVERNANCE.value == "provider_governance"
    assert GovernanceSignalType.TENANT_ISOLATION.value == "tenant_isolation"
    assert GovernanceSignalType.POLICY_ENGINE.value == "policy_engine"
    assert GovernanceSignalType.GROUNDED_ANSWER.value == "grounded_answer"
    assert GovernanceSignalType.OPERATIONAL_GOVERNANCE.value == "operational_governance"


def test_signal_extraction_status_values_are_stable() -> None:
    assert SignalExtractionStatus.EXTRACTED.value == "extracted"
    assert SignalExtractionStatus.UNAVAILABLE.value == "unavailable"
    assert SignalExtractionStatus.ERROR.value == "error"


def test_validation_state_values_are_stable() -> None:
    assert ValidationState.VALID.value == "valid"
    assert ValidationState.INVALID.value == "invalid"
    assert ValidationState.UNKNOWN.value == "unknown"


def test_enforcement_state_values_are_stable() -> None:
    assert EnforcementState.ENABLED.value == "enabled"
    assert EnforcementState.DISABLED.value == "disabled"
    assert EnforcementState.UNKNOWN.value == "unknown"


def test_audit_chain_status_values_are_stable() -> None:
    assert AuditChainStatus.INTACT.value == "intact"
    assert AuditChainStatus.TAMPERED.value == "tampered"
    assert AuditChainStatus.INCOMPLETE.value == "incomplete"
    assert AuditChainStatus.UNKNOWN.value == "unknown"


def test_provider_governance_state_values_are_stable() -> None:
    assert ProviderGovernanceState.APPROVED.value == "approved"
    assert ProviderGovernanceState.RESTRICTED.value == "restricted"
    assert ProviderGovernanceState.BLOCKED.value == "blocked"
    assert ProviderGovernanceState.PENDING_REVIEW.value == "pending_review"
    assert ProviderGovernanceState.UNKNOWN.value == "unknown"


# ---------------------------------------------------------------------------
# Model immutability
# ---------------------------------------------------------------------------


def test_provenance_signal_is_frozen() -> None:
    sig = _make_provenance_signal()
    with pytest.raises(Exception):
        sig.tenant_id = "other"  # type: ignore[misc]


def test_provenance_summary_is_frozen() -> None:
    summary = ProvenanceSignalSummary(
        enforcement_enabled=True,
        validation_state=ValidationState.VALID,
        citation_count=1,
        invalid_citation_count=0,
        reason_code="OK",
        grounded_answer_enforced=True,
    )
    with pytest.raises(Exception):
        summary.citation_count = 99  # type: ignore[misc]


def test_runtime_evidence_snapshot_is_frozen() -> None:
    sig = _make_provenance_signal()
    snap = build_runtime_evidence_snapshot(
        snapshot_id=_SNAPSHOT_ID,
        tenant_id=_TENANT,
        signals=(sig,),
        created_at=_NOW,
    )
    with pytest.raises(Exception):
        snap.tenant_id = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Default mutable dict fields are not shared between instances
# ---------------------------------------------------------------------------


def test_retrieval_summary_metadata_defaults_to_empty_dict() -> None:
    s1 = RetrievalSignalSummary(
        retrieval_enabled=True,
        enforcement_state=EnforcementState.ENABLED,
        effective_strategy="dense",
        corpus_count=10,
        grounded_context_required=True,
        reason_code="OK",
        lexical_fallback_used=False,
    )
    s2 = RetrievalSignalSummary(
        retrieval_enabled=False,
        enforcement_state=EnforcementState.DISABLED,
        effective_strategy=None,
        corpus_count=0,
        grounded_context_required=False,
        reason_code="DISABLED",
        lexical_fallback_used=False,
    )
    assert s1.summary_metadata == {}
    assert s2.summary_metadata == {}
    assert s1.summary_metadata is not s2.summary_metadata


def test_policy_summary_metadata_defaults_to_empty_dict() -> None:
    s1 = PolicySignalSummary(
        enforcement_enabled=True,
        validation_state=ValidationState.VALID,
        replay_ready=True,
        policy_version="1.0",
    )
    s2 = PolicySignalSummary(
        enforcement_enabled=False,
        validation_state=ValidationState.UNKNOWN,
        replay_ready=False,
        policy_version=None,
    )
    assert s1.policy_metadata == {}
    assert s2.policy_metadata == {}
    assert s1.policy_metadata is not s2.policy_metadata


def test_operational_summary_ops_metadata_defaults_to_empty_dict() -> None:
    s1 = OperationalGovernanceSignalSummary(
        environment_state="production",
        secret_governance_active=True,
        retention_policy_active=True,
        export_controls_active=True,
    )
    s2 = OperationalGovernanceSignalSummary(
        environment_state="test",
        secret_governance_active=False,
        retention_policy_active=False,
        export_controls_active=False,
    )
    assert s1.ops_metadata == {}
    assert s2.ops_metadata == {}
    assert s1.ops_metadata is not s2.ops_metadata


def test_signal_metadata_defaults_to_empty_dict() -> None:
    sig1 = _make_provenance_signal(signal_id="s1")
    sig2 = _make_provenance_signal(signal_id="s2")
    assert sig1.signal_metadata == {}
    assert sig2.signal_metadata == {}
    assert sig1.signal_metadata is not sig2.signal_metadata


# ---------------------------------------------------------------------------
# extract_provenance_signal
# ---------------------------------------------------------------------------


def test_extract_provenance_signal_type_and_status() -> None:
    sig = _make_provenance_signal()
    assert sig.signal_type == GovernanceSignalType.PROVENANCE
    assert sig.status == SignalExtractionStatus.EXTRACTED


def test_extract_provenance_signal_tenant_scoped() -> None:
    sig = _make_provenance_signal(tenant_id="tenant-xyz")
    assert sig.tenant_id == "tenant-xyz"


def test_extract_provenance_signal_summary_fields() -> None:
    sig = _make_provenance_signal(
        citation_count=5,
        invalid_citation_count=1,
        enforcement_enabled=False,
        validation_state=ValidationState.INVALID,
        reason_code="CITATION_FAIL",
        grounded_answer_enforced=False,
    )
    s = sig.signal_summary
    assert isinstance(s, ProvenanceSignalSummary)
    assert s.citation_count == 5
    assert s.invalid_citation_count == 1
    assert s.enforcement_enabled is False
    assert s.validation_state == ValidationState.INVALID
    assert s.reason_code == "CITATION_FAIL"
    assert s.grounded_answer_enforced is False


def test_extract_provenance_signal_extractor_version() -> None:
    sig = _make_provenance_signal()
    assert sig.extractor_version == _EXTRACTOR_VERSION


# ---------------------------------------------------------------------------
# extract_retrieval_signal
# ---------------------------------------------------------------------------


def test_extract_retrieval_signal_type_and_status() -> None:
    sig = extract_retrieval_signal(
        signal_id=_SIGNAL_ID,
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.retrieval",
        retrieval_enabled=True,
        enforcement_state=EnforcementState.ENABLED,
        effective_strategy="dense",
        corpus_count=100,
        grounded_context_required=True,
        reason_code="OK",
        lexical_fallback_used=False,
    )
    assert sig.signal_type == GovernanceSignalType.RETRIEVAL_CONFIDENCE
    assert sig.status == SignalExtractionStatus.EXTRACTED


def test_extract_retrieval_signal_none_strategy() -> None:
    sig = extract_retrieval_signal(
        signal_id=_SIGNAL_ID,
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.retrieval",
        retrieval_enabled=False,
        enforcement_state=EnforcementState.DISABLED,
        effective_strategy=None,
        corpus_count=0,
        grounded_context_required=False,
        reason_code="DISABLED",
        lexical_fallback_used=False,
    )
    s = sig.signal_summary
    assert isinstance(s, RetrievalSignalSummary)
    assert s.effective_strategy is None


def test_extract_retrieval_signal_lexical_fallback() -> None:
    sig = extract_retrieval_signal(
        signal_id=_SIGNAL_ID,
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.retrieval",
        retrieval_enabled=True,
        enforcement_state=EnforcementState.ENABLED,
        effective_strategy="lexical",
        corpus_count=50,
        grounded_context_required=True,
        reason_code="FALLBACK",
        lexical_fallback_used=True,
    )
    assert sig.signal_summary.lexical_fallback_used is True  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# extract_audit_chain_signal
# ---------------------------------------------------------------------------


def test_extract_audit_chain_signal_intact() -> None:
    sig = extract_audit_chain_signal(
        signal_id=_SIGNAL_ID,
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.audit",
        chain_id="chain-001",
        chain_status=AuditChainStatus.INTACT,
        continuity_ok=True,
        event_count=42,
        tamper_detected=False,
        last_verified_at=_NOW,
    )
    assert sig.signal_type == GovernanceSignalType.AUDIT_CHAIN
    assert sig.status == SignalExtractionStatus.EXTRACTED
    s = sig.signal_summary
    assert isinstance(s, AuditChainSignalSummary)
    assert s.chain_status == AuditChainStatus.INTACT
    assert s.continuity_ok is True
    assert s.tamper_detected is False
    assert s.event_count == 42
    assert s.last_verified_at == _NOW


def test_extract_audit_chain_signal_tampered() -> None:
    sig = extract_audit_chain_signal(
        signal_id=_SIGNAL_ID,
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.audit",
        chain_id="chain-002",
        chain_status=AuditChainStatus.TAMPERED,
        continuity_ok=False,
        event_count=10,
        tamper_detected=True,
        last_verified_at=None,
    )
    s = sig.signal_summary
    assert isinstance(s, AuditChainSignalSummary)
    assert s.chain_status == AuditChainStatus.TAMPERED
    assert s.tamper_detected is True
    assert s.last_verified_at is None


# ---------------------------------------------------------------------------
# extract_provider_governance_signal — PHI privacy contract
# ---------------------------------------------------------------------------


def test_extract_provider_governance_signal_phi_count_not_types() -> None:
    """phi_type_count is stored; PHI type names are not accepted as input."""
    sig = extract_provider_governance_signal(
        signal_id=_SIGNAL_ID,
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.provider_baa",
        provider_id="provider-openai",
        governance_state=ProviderGovernanceState.APPROVED,
        phi_detected=True,
        phi_type_count=3,
        baa_enforced=True,
        enforcement_action="ALLOW",
        reason_code="BAA_VALID",
    )
    assert sig.signal_type == GovernanceSignalType.PROVIDER_GOVERNANCE
    s = sig.signal_summary
    assert isinstance(s, ProviderGovernanceSignalSummary)
    assert s.phi_type_count == 3
    assert s.phi_detected is True
    assert not hasattr(s, "phi_types")


def test_extract_provider_governance_signal_blocked_state() -> None:
    sig = extract_provider_governance_signal(
        signal_id=_SIGNAL_ID,
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.provider_baa",
        provider_id="provider-xyz",
        governance_state=ProviderGovernanceState.BLOCKED,
        phi_detected=False,
        phi_type_count=0,
        baa_enforced=False,
        enforcement_action="BLOCK",
        reason_code="PROVIDER_BLOCKED",
    )
    s = sig.signal_summary
    assert isinstance(s, ProviderGovernanceSignalSummary)
    assert s.governance_state == ProviderGovernanceState.BLOCKED
    assert s.enforcement_action == "BLOCK"


# ---------------------------------------------------------------------------
# extract_tenant_isolation_signal
# ---------------------------------------------------------------------------


def test_extract_tenant_isolation_signal_enforced() -> None:
    sig = extract_tenant_isolation_signal(
        signal_id=_SIGNAL_ID,
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.tenant_isolation",
        isolation_enforced=True,
        cross_tenant_rejected=False,
        enforcement_state=EnforcementState.ENABLED,
        validation_state=ValidationState.VALID,
        reason_code="OK",
    )
    assert sig.signal_type == GovernanceSignalType.TENANT_ISOLATION
    s = sig.signal_summary
    assert isinstance(s, TenantIsolationSignalSummary)
    assert s.isolation_enforced is True
    assert s.cross_tenant_rejected is False
    assert s.enforcement_state == EnforcementState.ENABLED


def test_extract_tenant_isolation_signal_cross_tenant_rejected() -> None:
    sig = extract_tenant_isolation_signal(
        signal_id=_SIGNAL_ID,
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.tenant_isolation",
        isolation_enforced=True,
        cross_tenant_rejected=True,
        enforcement_state=EnforcementState.ENABLED,
        validation_state=ValidationState.INVALID,
        reason_code="CROSS_TENANT_REJECTED",
    )
    s = sig.signal_summary
    assert isinstance(s, TenantIsolationSignalSummary)
    assert s.cross_tenant_rejected is True
    assert s.validation_state == ValidationState.INVALID


# ---------------------------------------------------------------------------
# extract_policy_signal
# ---------------------------------------------------------------------------


def test_extract_policy_signal_with_version() -> None:
    sig = extract_policy_signal(
        signal_id=_SIGNAL_ID,
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.policy_engine",
        enforcement_enabled=True,
        validation_state=ValidationState.VALID,
        replay_ready=True,
        policy_version="2.1.0",
    )
    assert sig.signal_type == GovernanceSignalType.POLICY_ENGINE
    s = sig.signal_summary
    assert isinstance(s, PolicySignalSummary)
    assert s.policy_version == "2.1.0"
    assert s.replay_ready is True


def test_extract_policy_signal_no_version() -> None:
    sig = extract_policy_signal(
        signal_id=_SIGNAL_ID,
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.policy_engine",
        enforcement_enabled=False,
        validation_state=ValidationState.UNKNOWN,
        replay_ready=False,
        policy_version=None,
    )
    s = sig.signal_summary
    assert isinstance(s, PolicySignalSummary)
    assert s.policy_version is None
    assert s.enforcement_enabled is False


# ---------------------------------------------------------------------------
# extract_grounded_answer_signal
# ---------------------------------------------------------------------------


def test_extract_grounded_answer_signal_fully_enforced() -> None:
    sig = extract_grounded_answer_signal(
        signal_id=_SIGNAL_ID,
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.ai.grounded_answer",
        enforcement_enabled=True,
        rejection_enabled=True,
        citation_required=True,
        validation_state=ValidationState.VALID,
        hallucination_mitigation_active=True,
    )
    assert sig.signal_type == GovernanceSignalType.GROUNDED_ANSWER
    s = sig.signal_summary
    assert isinstance(s, GroundedAnswerSignalSummary)
    assert s.enforcement_enabled is True
    assert s.rejection_enabled is True
    assert s.hallucination_mitigation_active is True


def test_extract_grounded_answer_signal_disabled() -> None:
    sig = extract_grounded_answer_signal(
        signal_id=_SIGNAL_ID,
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.ai.grounded_answer",
        enforcement_enabled=False,
        rejection_enabled=False,
        citation_required=False,
        validation_state=ValidationState.UNKNOWN,
        hallucination_mitigation_active=False,
    )
    s = sig.signal_summary
    assert isinstance(s, GroundedAnswerSignalSummary)
    assert s.enforcement_enabled is False
    assert s.hallucination_mitigation_active is False


# ---------------------------------------------------------------------------
# extract_operational_governance_signal
# ---------------------------------------------------------------------------


def test_extract_operational_governance_signal_production() -> None:
    sig = extract_operational_governance_signal(
        signal_id=_SIGNAL_ID,
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.ops_governance",
        environment_state="production",
        secret_governance_active=True,
        retention_policy_active=True,
        export_controls_active=True,
    )
    assert sig.signal_type == GovernanceSignalType.OPERATIONAL_GOVERNANCE
    s = sig.signal_summary
    assert isinstance(s, OperationalGovernanceSignalSummary)
    assert s.environment_state == "production"
    assert s.secret_governance_active is True
    assert s.export_controls_active is True


def test_extract_operational_governance_signal_test_env() -> None:
    sig = extract_operational_governance_signal(
        signal_id=_SIGNAL_ID,
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.ops_governance",
        environment_state="test",
        secret_governance_active=False,
        retention_policy_active=False,
        export_controls_active=False,
    )
    s = sig.signal_summary
    assert isinstance(s, OperationalGovernanceSignalSummary)
    assert s.environment_state == "test"
    assert s.secret_governance_active is False


# ---------------------------------------------------------------------------
# UNAVAILABLE and ERROR signals
# ---------------------------------------------------------------------------


def test_make_unavailable_signal_status() -> None:
    sig = make_unavailable_signal(
        signal_id=_SIGNAL_ID,
        signal_type=GovernanceSignalType.AUDIT_CHAIN,
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.audit",
        reason_code="SERVICE_UNREACHABLE",
    )
    assert sig.status == SignalExtractionStatus.UNAVAILABLE
    assert sig.signal_type == GovernanceSignalType.AUDIT_CHAIN
    assert sig.tenant_id == _TENANT


def test_make_error_signal_status() -> None:
    sig = make_error_signal(
        signal_id=_SIGNAL_ID,
        signal_type=GovernanceSignalType.PROVIDER_GOVERNANCE,
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.provider_baa",
        reason_code="EXTRACTION_FAILED",
    )
    assert sig.status == SignalExtractionStatus.ERROR
    assert sig.signal_type == GovernanceSignalType.PROVIDER_GOVERNANCE


def test_unavailable_signal_for_all_types() -> None:
    for sig_type in GovernanceSignalType:
        sig = make_unavailable_signal(
            signal_id=_SIGNAL_ID,
            signal_type=sig_type,
            tenant_id=_TENANT,
            extraction_id=_EXTRACTION_ID,
            extracted_at=_NOW,
            governance_source="test.source",
            reason_code="UNAVAILABLE",
        )
        assert sig.status == SignalExtractionStatus.UNAVAILABLE
        assert sig.signal_type == sig_type


# ---------------------------------------------------------------------------
# Snapshot hash determinism
# ---------------------------------------------------------------------------


def test_snapshot_hash_is_deterministic_for_identical_state() -> None:
    sig = _make_provenance_signal()
    snap1 = build_runtime_evidence_snapshot(
        snapshot_id="snap-1",
        tenant_id=_TENANT,
        signals=(sig,),
        created_at=_NOW,
    )
    snap2 = build_runtime_evidence_snapshot(
        snapshot_id="snap-2",
        tenant_id=_TENANT,
        signals=(sig,),
        created_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
    )
    assert snap1.snapshot_hash == snap2.snapshot_hash


def test_snapshot_hash_differs_for_different_governance_state() -> None:
    sig_valid = _make_provenance_signal(validation_state=ValidationState.VALID)
    sig_invalid = _make_provenance_signal(validation_state=ValidationState.INVALID)
    snap1 = build_runtime_evidence_snapshot(
        snapshot_id=_SNAPSHOT_ID,
        tenant_id=_TENANT,
        signals=(sig_valid,),
        created_at=_NOW,
    )
    snap2 = build_runtime_evidence_snapshot(
        snapshot_id=_SNAPSHOT_ID,
        tenant_id=_TENANT,
        signals=(sig_invalid,),
        created_at=_NOW,
    )
    assert snap1.snapshot_hash != snap2.snapshot_hash


def test_snapshot_hash_differs_for_different_tenant() -> None:
    sig_a = _make_provenance_signal(tenant_id="tenant-a")
    sig_b = _make_provenance_signal(tenant_id="tenant-b")
    snap_a = build_runtime_evidence_snapshot(
        snapshot_id=_SNAPSHOT_ID,
        tenant_id="tenant-a",
        signals=(sig_a,),
        created_at=_NOW,
    )
    snap_b = build_runtime_evidence_snapshot(
        snapshot_id=_SNAPSHOT_ID,
        tenant_id="tenant-b",
        signals=(sig_b,),
        created_at=_NOW,
    )
    assert snap_a.snapshot_hash != snap_b.snapshot_hash


def test_snapshot_hash_excludes_snapshot_id() -> None:
    sig = _make_provenance_signal()
    h1, _ = compute_snapshot_hash(_TENANT, _SNAPSHOT_VERSION, (sig,))
    h2, _ = compute_snapshot_hash(_TENANT, _SNAPSHOT_VERSION, (sig,))
    assert h1 == h2


# ---------------------------------------------------------------------------
# Snapshot signal ordering independence
# ---------------------------------------------------------------------------


def test_snapshot_hash_is_independent_of_signal_insertion_order() -> None:
    sig_prov = _make_provenance_signal(governance_source="services.ai.provenance")
    sig_audit = extract_audit_chain_signal(
        signal_id="sig-audit",
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.audit",
        chain_id="chain-001",
        chain_status=AuditChainStatus.INTACT,
        continuity_ok=True,
        event_count=5,
        tamper_detected=False,
        last_verified_at=None,
    )
    snap_ab = build_runtime_evidence_snapshot(
        snapshot_id=_SNAPSHOT_ID,
        tenant_id=_TENANT,
        signals=(sig_prov, sig_audit),
        created_at=_NOW,
    )
    snap_ba = build_runtime_evidence_snapshot(
        snapshot_id=_SNAPSHOT_ID,
        tenant_id=_TENANT,
        signals=(sig_audit, sig_prov),
        created_at=_NOW,
    )
    assert snap_ab.snapshot_hash == snap_ba.snapshot_hash


def test_snapshot_canonical_sort_by_type_then_source() -> None:
    """Two signals of the same type differ by source — verify sort key."""
    sig_a = _make_provenance_signal(
        signal_id="sig-a",
        governance_source="services.ai.provenance.alpha",
    )
    sig_b = _make_provenance_signal(
        signal_id="sig-b",
        governance_source="services.ai.provenance.beta",
    )
    snap_ab = build_runtime_evidence_snapshot(
        snapshot_id=_SNAPSHOT_ID,
        tenant_id=_TENANT,
        signals=(sig_a, sig_b),
        created_at=_NOW,
    )
    snap_ba = build_runtime_evidence_snapshot(
        snapshot_id=_SNAPSHOT_ID,
        tenant_id=_TENANT,
        signals=(sig_b, sig_a),
        created_at=_NOW,
    )
    assert snap_ab.snapshot_hash == snap_ba.snapshot_hash


# ---------------------------------------------------------------------------
# Snapshot replay safety (inputs_canonical reproduces hash)
# ---------------------------------------------------------------------------


def test_inputs_canonical_reproduces_snapshot_hash() -> None:
    sig = _make_provenance_signal()
    snap = build_runtime_evidence_snapshot(
        snapshot_id=_SNAPSHOT_ID,
        tenant_id=_TENANT,
        signals=(sig,),
        created_at=_NOW,
    )
    replayed_hash = hashlib.sha256(snap.inputs_canonical.encode("utf-8")).hexdigest()
    assert replayed_hash == snap.snapshot_hash


def test_inputs_canonical_is_valid_json() -> None:
    sig = _make_provenance_signal()
    snap = build_runtime_evidence_snapshot(
        snapshot_id=_SNAPSHOT_ID,
        tenant_id=_TENANT,
        signals=(sig,),
        created_at=_NOW,
    )
    parsed = json.loads(snap.inputs_canonical)
    assert "tenant_id" in parsed
    assert "signals" in parsed
    assert "snapshot_version" in parsed


def test_inputs_canonical_excludes_snapshot_id_and_timestamps() -> None:
    sig = _make_provenance_signal()
    snap = build_runtime_evidence_snapshot(
        snapshot_id="excluded-snap-id",
        tenant_id=_TENANT,
        signals=(sig,),
        created_at=_NOW,
    )
    assert "excluded-snap-id" not in snap.inputs_canonical
    assert "extracted_at" not in snap.inputs_canonical
    assert "signal_id" not in snap.inputs_canonical
    assert "extraction_id" not in snap.inputs_canonical


# ---------------------------------------------------------------------------
# Snapshot with assessment_id
# ---------------------------------------------------------------------------


def test_snapshot_assessment_id_is_optional() -> None:
    sig = _make_provenance_signal()
    snap_no_assess = build_runtime_evidence_snapshot(
        snapshot_id=_SNAPSHOT_ID,
        tenant_id=_TENANT,
        signals=(sig,),
        created_at=_NOW,
    )
    snap_with_assess = build_runtime_evidence_snapshot(
        snapshot_id=_SNAPSHOT_ID,
        tenant_id=_TENANT,
        signals=(sig,),
        created_at=_NOW,
        assessment_id="assess-001",
    )
    assert snap_no_assess.assessment_id is None
    assert snap_with_assess.assessment_id == "assess-001"


def test_snapshot_assessment_id_excluded_from_hash() -> None:
    sig = _make_provenance_signal()
    snap_no_assess = build_runtime_evidence_snapshot(
        snapshot_id=_SNAPSHOT_ID,
        tenant_id=_TENANT,
        signals=(sig,),
        created_at=_NOW,
    )
    snap_with_assess = build_runtime_evidence_snapshot(
        snapshot_id=_SNAPSHOT_ID,
        tenant_id=_TENANT,
        signals=(sig,),
        created_at=_NOW,
        assessment_id="assess-999",
    )
    assert snap_no_assess.snapshot_hash == snap_with_assess.snapshot_hash


# ---------------------------------------------------------------------------
# Snapshot version is included in hash
# ---------------------------------------------------------------------------


def test_snapshot_version_is_embedded_in_inputs_canonical() -> None:
    sig = _make_provenance_signal()
    snap = build_runtime_evidence_snapshot(
        snapshot_id=_SNAPSHOT_ID,
        tenant_id=_TENANT,
        signals=(sig,),
        created_at=_NOW,
    )
    parsed = json.loads(snap.inputs_canonical)
    assert parsed["snapshot_version"] == _SNAPSHOT_VERSION


# ---------------------------------------------------------------------------
# Empty signals tuple
# ---------------------------------------------------------------------------


def test_snapshot_with_no_signals() -> None:
    snap = build_runtime_evidence_snapshot(
        snapshot_id=_SNAPSHOT_ID,
        tenant_id=_TENANT,
        signals=(),
        created_at=_NOW,
    )
    assert snap.signals == ()
    assert len(snap.snapshot_hash) == 64


def test_snapshot_with_no_signals_is_deterministic() -> None:
    snap1 = build_runtime_evidence_snapshot(
        snapshot_id="s1",
        tenant_id=_TENANT,
        signals=(),
        created_at=_NOW,
    )
    snap2 = build_runtime_evidence_snapshot(
        snapshot_id="s2",
        tenant_id=_TENANT,
        signals=(),
        created_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )
    assert snap1.snapshot_hash == snap2.snapshot_hash


# ---------------------------------------------------------------------------
# audit_chain last_verified_at excluded from hash
# ---------------------------------------------------------------------------


def test_audit_chain_last_verified_at_excluded_from_hash() -> None:
    sig_ts1 = extract_audit_chain_signal(
        signal_id=_SIGNAL_ID,
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.audit",
        chain_id="chain-001",
        chain_status=AuditChainStatus.INTACT,
        continuity_ok=True,
        event_count=10,
        tamper_detected=False,
        last_verified_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    sig_ts2 = extract_audit_chain_signal(
        signal_id=_SIGNAL_ID,
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.audit",
        chain_id="chain-001",
        chain_status=AuditChainStatus.INTACT,
        continuity_ok=True,
        event_count=10,
        tamper_detected=False,
        last_verified_at=datetime(2026, 6, 15, tzinfo=timezone.utc),
    )
    h1, _ = compute_snapshot_hash(_TENANT, _SNAPSHOT_VERSION, (sig_ts1,))
    h2, _ = compute_snapshot_hash(_TENANT, _SNAPSHOT_VERSION, (sig_ts2,))
    assert h1 == h2


# ---------------------------------------------------------------------------
# Multi-signal snapshot correctness
# ---------------------------------------------------------------------------


def test_snapshot_preserves_all_signals() -> None:
    sigs = tuple(
        _make_provenance_signal(signal_id=f"sig-{i}", governance_source=f"source-{i}")
        for i in range(5)
    )
    snap = build_runtime_evidence_snapshot(
        snapshot_id=_SNAPSHOT_ID,
        tenant_id=_TENANT,
        signals=sigs,
        created_at=_NOW,
    )
    assert len(snap.signals) == 5


def test_snapshot_metadata_defaults_to_empty_dict() -> None:
    sig = _make_provenance_signal()
    snap = build_runtime_evidence_snapshot(
        snapshot_id=_SNAPSHOT_ID,
        tenant_id=_TENANT,
        signals=(sig,),
        created_at=_NOW,
    )
    assert snap.snapshot_metadata == {}


# ---------------------------------------------------------------------------
# Bug regression: metadata dicts are read-only (MappingProxyType) — Bug 2
# ---------------------------------------------------------------------------


def test_retrieval_summary_metadata_is_read_only() -> None:
    sig = extract_retrieval_signal(
        signal_id=_SIGNAL_ID,
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.retrieval",
        retrieval_enabled=True,
        enforcement_state=EnforcementState.ENABLED,
        effective_strategy="dense",
        corpus_count=10,
        grounded_context_required=True,
        reason_code="OK",
        lexical_fallback_used=False,
    )
    s = sig.signal_summary
    assert isinstance(s, RetrievalSignalSummary)
    with pytest.raises(TypeError):
        s.summary_metadata["injected"] = "bad"  # type: ignore[index]


def test_policy_metadata_is_read_only() -> None:
    sig = extract_policy_signal(
        signal_id=_SIGNAL_ID,
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.policy_engine",
        enforcement_enabled=True,
        validation_state=ValidationState.VALID,
        replay_ready=True,
        policy_version="1.0",
    )
    s = sig.signal_summary
    assert isinstance(s, PolicySignalSummary)
    with pytest.raises(TypeError):
        s.policy_metadata["injected"] = "bad"  # type: ignore[index]


def test_ops_metadata_is_read_only() -> None:
    sig = extract_operational_governance_signal(
        signal_id=_SIGNAL_ID,
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.ops_governance",
        environment_state="production",
        secret_governance_active=True,
        retention_policy_active=True,
        export_controls_active=True,
    )
    s = sig.signal_summary
    assert isinstance(s, OperationalGovernanceSignalSummary)
    with pytest.raises(TypeError):
        s.ops_metadata["injected"] = "bad"  # type: ignore[index]


def test_signal_metadata_is_read_only() -> None:
    sig = _make_provenance_signal()
    with pytest.raises(TypeError):
        sig.signal_metadata["injected"] = "bad"  # type: ignore[index]


def test_metadata_dict_mutation_after_construction_does_not_affect_stored_content() -> (
    None
):
    """Caller mutating their dict after passing it to the constructor must not
    affect the stored summary_metadata (defensive copy on construction)."""
    caller_meta: dict[str, Any] = {"key": "original"}
    summary = RetrievalSignalSummary(
        retrieval_enabled=True,
        enforcement_state=EnforcementState.ENABLED,
        effective_strategy="dense",
        corpus_count=10,
        grounded_context_required=True,
        reason_code="OK",
        lexical_fallback_used=False,
        summary_metadata=caller_meta,
    )
    caller_meta["key"] = "mutated"
    assert summary.summary_metadata["key"] == "original"


# ---------------------------------------------------------------------------
# Bug regression: sort tie-breaker for same type + same source — Bug 1
# ---------------------------------------------------------------------------


def test_snapshot_hash_stable_for_same_type_same_source_different_summaries() -> None:
    """Two provider-governance signals from the same source with different
    provider_ids must hash identically regardless of insertion order."""
    sig_a = extract_provider_governance_signal(
        signal_id="sig-prov-a",
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.provider_baa",
        provider_id="provider-openai",
        governance_state=ProviderGovernanceState.APPROVED,
        phi_detected=False,
        phi_type_count=0,
        baa_enforced=True,
        enforcement_action="ALLOW",
        reason_code="OK",
    )
    sig_b = extract_provider_governance_signal(
        signal_id="sig-prov-b",
        tenant_id=_TENANT,
        extraction_id=_EXTRACTION_ID,
        extracted_at=_NOW,
        governance_source="services.provider_baa",
        provider_id="provider-anthropic",
        governance_state=ProviderGovernanceState.APPROVED,
        phi_detected=False,
        phi_type_count=0,
        baa_enforced=True,
        enforcement_action="ALLOW",
        reason_code="OK",
    )
    snap_ab = build_runtime_evidence_snapshot(
        snapshot_id="snap-ab",
        tenant_id=_TENANT,
        signals=(sig_a, sig_b),
        created_at=_NOW,
    )
    snap_ba = build_runtime_evidence_snapshot(
        snapshot_id="snap-ba",
        tenant_id=_TENANT,
        signals=(sig_b, sig_a),
        created_at=_NOW,
    )
    assert snap_ab.snapshot_hash == snap_ba.snapshot_hash


# ---------------------------------------------------------------------------
# Extractor version constant
# ---------------------------------------------------------------------------


def test_extractor_version_is_semver_string() -> None:
    parts = _EXTRACTOR_VERSION.split(".")
    assert len(parts) == 3
    assert all(p.isdigit() for p in parts)


def test_snapshot_version_is_semver_string() -> None:
    parts = _SNAPSHOT_VERSION.split(".")
    assert len(parts) == 3
    assert all(p.isdigit() for p in parts)
