"""Runtime Evidence Collection & Governance Signal Extraction Layer.

Public API surface — all stable exports from this package.

Consumers import from this package, not from submodules, to allow
internal refactoring without breaking callers.
"""

from .extractors import (
    _EXTRACTOR_VERSION,
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
from .models import (
    AuditChainSignalSummary,
    AuditChainStatus,
    EnforcementState,
    GovernanceSignalBody,
    GovernanceSignalType,
    GroundedAnswerSignalSummary,
    OperationalGovernanceSignalSummary,
    PolicySignalSummary,
    ProviderGovernanceSignalSummary,
    ProviderGovernanceState,
    ProvenanceSignalSummary,
    RetrievalSignalSummary,
    RuntimeEvidenceSnapshot,
    RuntimeGovernanceSignal,
    SignalExtractionStatus,
    TenantIsolationSignalSummary,
    ValidationState,
)
from .snapshot import (
    _SNAPSHOT_VERSION,
    build_runtime_evidence_snapshot,
    compute_snapshot_hash,
)

__all__ = [
    # Enumerations
    "GovernanceSignalType",
    "SignalExtractionStatus",
    "ValidationState",
    "EnforcementState",
    "ProviderGovernanceState",
    "AuditChainStatus",
    # Signal summaries
    "ProvenanceSignalSummary",
    "RetrievalSignalSummary",
    "AuditChainSignalSummary",
    "ProviderGovernanceSignalSummary",
    "TenantIsolationSignalSummary",
    "PolicySignalSummary",
    "GroundedAnswerSignalSummary",
    "OperationalGovernanceSignalSummary",
    # Union type
    "GovernanceSignalBody",
    # Core signal and snapshot types
    "RuntimeGovernanceSignal",
    "RuntimeEvidenceSnapshot",
    # Extractors
    "extract_provenance_signal",
    "extract_retrieval_signal",
    "extract_audit_chain_signal",
    "extract_provider_governance_signal",
    "extract_tenant_isolation_signal",
    "extract_policy_signal",
    "extract_grounded_answer_signal",
    "extract_operational_governance_signal",
    "make_unavailable_signal",
    "make_error_signal",
    # Snapshot builder
    "build_runtime_evidence_snapshot",
    "compute_snapshot_hash",
    # Version constants
    "_EXTRACTOR_VERSION",
    "_SNAPSHOT_VERSION",
]
