"""Runtime Evidence Collection & Governance Signal Extraction Layer — extractors.

All extraction functions in this module are:
  - Pure Python. No I/O. No side effects. No randomness.
  - Decoupled from provider domain objects — accept primitive typed parameters
    to avoid tight coupling with services.ai, services.provider_baa, etc.
  - Privacy-safe: no raw prompts, PHI values, vectors, embeddings, or provider
    credentials appear in the returned signals.
  - Fail-closed: any extraction error returns UNAVAILABLE or ERROR status.
  - Deterministic: identical inputs → identical signal_summary content.

Extractor contract:
  - Each function returns a RuntimeGovernanceSignal.
  - signal_id is caller-assigned and stable for the signal domain.
  - extraction_id is a session-level UUID provided by the caller.
  - extracted_at is provided by the caller (not generated internally) so that
    the caller controls the timestamp and tests are fully deterministic.
  - status=UNAVAILABLE when the governance system is not configured/reachable.
  - status=ERROR when extraction fails with a recoverable error.
  - status=EXTRACTED when state was read and normalized successfully.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from .models import (
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
)

_EXTRACTOR_VERSION = "1.0.0"


def extract_provenance_signal(
    *,
    signal_id: str,
    tenant_id: str,
    extraction_id: str,
    extracted_at: datetime,
    governance_source: str,
    enforcement_enabled: bool,
    validation_state: ValidationState,
    citation_count: int,
    invalid_citation_count: int,
    reason_code: str,
    grounded_answer_enforced: bool,
) -> RuntimeGovernanceSignal:
    """Extract a normalized provenance governance signal.

    No raw prompts, answer text, or retrieved chunk content are accepted
    or stored — only enforcement state and citation count metadata.
    """
    summary = ProvenanceSignalSummary(
        enforcement_enabled=enforcement_enabled,
        validation_state=validation_state,
        citation_count=citation_count,
        invalid_citation_count=invalid_citation_count,
        reason_code=reason_code,
        grounded_answer_enforced=grounded_answer_enforced,
    )
    return RuntimeGovernanceSignal(
        signal_id=signal_id,
        signal_type=GovernanceSignalType.PROVENANCE,
        tenant_id=tenant_id,
        extraction_id=extraction_id,
        extracted_at=extracted_at,
        status=SignalExtractionStatus.EXTRACTED,
        governance_source=governance_source,
        signal_summary=summary,
        extractor_version=_EXTRACTOR_VERSION,
    )


def extract_retrieval_signal(
    *,
    signal_id: str,
    tenant_id: str,
    extraction_id: str,
    extracted_at: datetime,
    governance_source: str,
    retrieval_enabled: bool,
    enforcement_state: EnforcementState,
    effective_strategy: Optional[str],
    corpus_count: int,
    grounded_context_required: bool,
    reason_code: str,
    lexical_fallback_used: bool,
) -> RuntimeGovernanceSignal:
    """Extract a normalized retrieval confidence governance signal.

    No embeddings, vectors, raw chunk payloads, or retrieval text are
    accepted or stored.
    """
    summary = RetrievalSignalSummary(
        retrieval_enabled=retrieval_enabled,
        enforcement_state=enforcement_state,
        effective_strategy=effective_strategy,
        corpus_count=corpus_count,
        grounded_context_required=grounded_context_required,
        reason_code=reason_code,
        lexical_fallback_used=lexical_fallback_used,
    )
    return RuntimeGovernanceSignal(
        signal_id=signal_id,
        signal_type=GovernanceSignalType.RETRIEVAL_CONFIDENCE,
        tenant_id=tenant_id,
        extraction_id=extraction_id,
        extracted_at=extracted_at,
        status=SignalExtractionStatus.EXTRACTED,
        governance_source=governance_source,
        signal_summary=summary,
        extractor_version=_EXTRACTOR_VERSION,
    )


def extract_audit_chain_signal(
    *,
    signal_id: str,
    tenant_id: str,
    extraction_id: str,
    extracted_at: datetime,
    governance_source: str,
    chain_id: str,
    chain_status: AuditChainStatus,
    continuity_ok: bool,
    event_count: int,
    tamper_detected: bool,
    last_verified_at: Optional[datetime],
) -> RuntimeGovernanceSignal:
    """Extract a normalized audit chain integrity signal.

    chain_id enables future forensic replay linkage.
    last_verified_at is preserved but excluded from canonical hash.
    """
    summary = AuditChainSignalSummary(
        chain_id=chain_id,
        chain_status=chain_status,
        continuity_ok=continuity_ok,
        event_count=event_count,
        tamper_detected=tamper_detected,
        last_verified_at=last_verified_at,
    )
    return RuntimeGovernanceSignal(
        signal_id=signal_id,
        signal_type=GovernanceSignalType.AUDIT_CHAIN,
        tenant_id=tenant_id,
        extraction_id=extraction_id,
        extracted_at=extracted_at,
        status=SignalExtractionStatus.EXTRACTED,
        governance_source=governance_source,
        signal_summary=summary,
        extractor_version=_EXTRACTOR_VERSION,
    )


def extract_provider_governance_signal(
    *,
    signal_id: str,
    tenant_id: str,
    extraction_id: str,
    extracted_at: datetime,
    governance_source: str,
    provider_id: str,
    governance_state: ProviderGovernanceState,
    phi_detected: bool,
    phi_type_count: int,
    baa_enforced: bool,
    enforcement_action: str,
    reason_code: str,
) -> RuntimeGovernanceSignal:
    """Extract a normalized provider governance and BAA enforcement signal.

    phi_type_count is an integer count of PHI category types detected.
    PHI type names are NOT accepted or stored — only the count is preserved
    to enable governance reporting without exposing PHI category metadata.
    No provider credentials or auth headers are accepted or stored.
    """
    summary = ProviderGovernanceSignalSummary(
        provider_id=provider_id,
        governance_state=governance_state,
        phi_detected=phi_detected,
        phi_type_count=phi_type_count,
        baa_enforced=baa_enforced,
        enforcement_action=enforcement_action,
        reason_code=reason_code,
    )
    return RuntimeGovernanceSignal(
        signal_id=signal_id,
        signal_type=GovernanceSignalType.PROVIDER_GOVERNANCE,
        tenant_id=tenant_id,
        extraction_id=extraction_id,
        extracted_at=extracted_at,
        status=SignalExtractionStatus.EXTRACTED,
        governance_source=governance_source,
        signal_summary=summary,
        extractor_version=_EXTRACTOR_VERSION,
    )


def extract_tenant_isolation_signal(
    *,
    signal_id: str,
    tenant_id: str,
    extraction_id: str,
    extracted_at: datetime,
    governance_source: str,
    isolation_enforced: bool,
    cross_tenant_rejected: bool,
    enforcement_state: EnforcementState,
    validation_state: ValidationState,
    reason_code: str,
) -> RuntimeGovernanceSignal:
    """Extract a normalized tenant isolation enforcement signal.

    Only the enforcement state for the scoped tenant is reported.
    No unrelated tenant identifiers or cross-tenant metadata are stored.
    """
    summary = TenantIsolationSignalSummary(
        isolation_enforced=isolation_enforced,
        cross_tenant_rejected=cross_tenant_rejected,
        enforcement_state=enforcement_state,
        validation_state=validation_state,
        reason_code=reason_code,
    )
    return RuntimeGovernanceSignal(
        signal_id=signal_id,
        signal_type=GovernanceSignalType.TENANT_ISOLATION,
        tenant_id=tenant_id,
        extraction_id=extraction_id,
        extracted_at=extracted_at,
        status=SignalExtractionStatus.EXTRACTED,
        governance_source=governance_source,
        signal_summary=summary,
        extractor_version=_EXTRACTOR_VERSION,
    )


def extract_policy_signal(
    *,
    signal_id: str,
    tenant_id: str,
    extraction_id: str,
    extracted_at: datetime,
    governance_source: str,
    enforcement_enabled: bool,
    validation_state: ValidationState,
    replay_ready: bool,
    policy_version: Optional[str],
) -> RuntimeGovernanceSignal:
    """Extract a normalized policy engine operational signal."""
    summary = PolicySignalSummary(
        enforcement_enabled=enforcement_enabled,
        validation_state=validation_state,
        replay_ready=replay_ready,
        policy_version=policy_version,
    )
    return RuntimeGovernanceSignal(
        signal_id=signal_id,
        signal_type=GovernanceSignalType.POLICY_ENGINE,
        tenant_id=tenant_id,
        extraction_id=extraction_id,
        extracted_at=extracted_at,
        status=SignalExtractionStatus.EXTRACTED,
        governance_source=governance_source,
        signal_summary=summary,
        extractor_version=_EXTRACTOR_VERSION,
    )


def extract_grounded_answer_signal(
    *,
    signal_id: str,
    tenant_id: str,
    extraction_id: str,
    extracted_at: datetime,
    governance_source: str,
    enforcement_enabled: bool,
    rejection_enabled: bool,
    citation_required: bool,
    validation_state: ValidationState,
    hallucination_mitigation_active: bool,
) -> RuntimeGovernanceSignal:
    """Extract a normalized grounded-answer enforcement signal.

    No raw prompts, model completions, user conversations, raw answers,
    or sensitive retrieval data are accepted or stored.
    """
    summary = GroundedAnswerSignalSummary(
        enforcement_enabled=enforcement_enabled,
        rejection_enabled=rejection_enabled,
        citation_required=citation_required,
        validation_state=validation_state,
        hallucination_mitigation_active=hallucination_mitigation_active,
    )
    return RuntimeGovernanceSignal(
        signal_id=signal_id,
        signal_type=GovernanceSignalType.GROUNDED_ANSWER,
        tenant_id=tenant_id,
        extraction_id=extraction_id,
        extracted_at=extracted_at,
        status=SignalExtractionStatus.EXTRACTED,
        governance_source=governance_source,
        signal_summary=summary,
        extractor_version=_EXTRACTOR_VERSION,
    )


def extract_operational_governance_signal(
    *,
    signal_id: str,
    tenant_id: str,
    extraction_id: str,
    extracted_at: datetime,
    governance_source: str,
    environment_state: str,
    secret_governance_active: bool,
    retention_policy_active: bool,
    export_controls_active: bool,
) -> RuntimeGovernanceSignal:
    """Extract a normalized operational governance signal."""
    summary = OperationalGovernanceSignalSummary(
        environment_state=environment_state,
        secret_governance_active=secret_governance_active,
        retention_policy_active=retention_policy_active,
        export_controls_active=export_controls_active,
    )
    return RuntimeGovernanceSignal(
        signal_id=signal_id,
        signal_type=GovernanceSignalType.OPERATIONAL_GOVERNANCE,
        tenant_id=tenant_id,
        extraction_id=extraction_id,
        extracted_at=extracted_at,
        status=SignalExtractionStatus.EXTRACTED,
        governance_source=governance_source,
        signal_summary=summary,
        extractor_version=_EXTRACTOR_VERSION,
    )


def make_unavailable_signal(
    *,
    signal_id: str,
    signal_type: GovernanceSignalType,
    tenant_id: str,
    extraction_id: str,
    extracted_at: datetime,
    governance_source: str,
    reason_code: str,
) -> RuntimeGovernanceSignal:
    """Return a signal with UNAVAILABLE status when a governance system is unreachable.

    The signal_summary is a ProvenanceSignalSummary stub with UNKNOWN state
    and the provided reason_code. The stub is typed as ProvenanceSignalSummary
    only because GovernanceSignalBody requires a concrete type; callers should
    treat UNAVAILABLE signals as opaque and not inspect signal_summary content.
    """
    stub = ProvenanceSignalSummary(
        enforcement_enabled=False,
        validation_state=ValidationState.UNKNOWN,
        citation_count=0,
        invalid_citation_count=0,
        reason_code=reason_code,
        grounded_answer_enforced=False,
    )
    return RuntimeGovernanceSignal(
        signal_id=signal_id,
        signal_type=signal_type,
        tenant_id=tenant_id,
        extraction_id=extraction_id,
        extracted_at=extracted_at,
        status=SignalExtractionStatus.UNAVAILABLE,
        governance_source=governance_source,
        signal_summary=stub,
        extractor_version=_EXTRACTOR_VERSION,
    )


def make_error_signal(
    *,
    signal_id: str,
    signal_type: GovernanceSignalType,
    tenant_id: str,
    extraction_id: str,
    extracted_at: datetime,
    governance_source: str,
    reason_code: str,
) -> RuntimeGovernanceSignal:
    """Return a signal with ERROR status when extraction fails with a recoverable error."""
    stub = ProvenanceSignalSummary(
        enforcement_enabled=False,
        validation_state=ValidationState.UNKNOWN,
        citation_count=0,
        invalid_citation_count=0,
        reason_code=reason_code,
        grounded_answer_enforced=False,
    )
    return RuntimeGovernanceSignal(
        signal_id=signal_id,
        signal_type=signal_type,
        tenant_id=tenant_id,
        extraction_id=extraction_id,
        extracted_at=extracted_at,
        status=SignalExtractionStatus.ERROR,
        governance_source=governance_source,
        signal_summary=stub,
        extractor_version=_EXTRACTOR_VERSION,
    )
