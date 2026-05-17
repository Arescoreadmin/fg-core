"""Runtime Evidence Collection & Governance Signal Extraction Layer — models.

All types in this module are:
  - Pure Python. No I/O. No randomness.
  - Frozen after construction (immutable).
  - Deterministic: identical governance state → identical canonical form.
  - Privacy-safe: no raw prompts, PHI, vectors, embeddings, or provider payloads.
  - Tenant-safe: all signals are scoped to a single tenant_id.
  - Replay-safe: inputs_canonical in RuntimeEvidenceSnapshot is sufficient to
    reproduce snapshot_hash without rerunning extraction.
  - Export-safe: no secrets, credentials, internal topology, or signed URLs.

Governance signal types correspond to existing runtime governance systems.
This layer reads from those systems — it does NOT mutate them.

Field-level hash exclusion contract:
  - Timestamps (extracted_at, last_verified_at, created_at) are EXCLUDED from
    canonical hashes — they are nondeterministic and mutable across extraction runs.
  - Identifiers (signal_id, extraction_id, snapshot_id) are EXCLUDED — they are
    session-level UUIDs that vary between extractions of identical state.
  - All governance state fields (enforcement_enabled, validation_state, reason_codes,
    counts, chain_status, etc.) are INCLUDED — they define the observable state.

Future extension hooks (not implemented):
  - signal_metadata: deployment governance evidence, RAG trace linkage, legal hold.
  - snapshot_metadata: export lineage, regulator attestation, signed snapshot chains.
  - GovernanceSignalType extensions: DEPLOYMENT_GOVERNANCE, RETENTION_GOVERNANCE,
    EXPORT_GOVERNANCE, RECOVERY_GOVERNANCE, RAG_INTEGRITY without redesign.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from types import MappingProxyType
from typing import Any, Optional, Union


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class GovernanceSignalType(str, Enum):
    """Runtime governance signal domain — what system produced the signal.

    Future extensions append new values; existing values are stable and
    never change meaning once published.
    """

    PROVENANCE = "provenance"
    RETRIEVAL_CONFIDENCE = "retrieval_confidence"
    AUDIT_CHAIN = "audit_chain"
    PROVIDER_GOVERNANCE = "provider_governance"
    TENANT_ISOLATION = "tenant_isolation"
    POLICY_ENGINE = "policy_engine"
    GROUNDED_ANSWER = "grounded_answer"
    OPERATIONAL_GOVERNANCE = "operational_governance"


class SignalExtractionStatus(str, Enum):
    """Status of a single signal extraction attempt.

    EXTRACTED:   Signal state was read and normalized successfully.
    UNAVAILABLE: Governance system is not reachable or not configured.
    ERROR:       Extraction attempted but failed due to a recoverable error.
    """

    EXTRACTED = "extracted"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class ValidationState(str, Enum):
    """Normalized validation outcome for a governance check."""

    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"


class EnforcementState(str, Enum):
    """Whether enforcement is currently active for a governance control."""

    ENABLED = "enabled"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


class ProviderGovernanceState(str, Enum):
    """Normalized provider governance lifecycle state.

    Mirrors the provider governance operational states but as a stable
    evidence-layer enum decoupled from provider service internals.
    """

    APPROVED = "approved"
    RESTRICTED = "restricted"
    BLOCKED = "blocked"
    PENDING_REVIEW = "pending_review"
    UNKNOWN = "unknown"


class AuditChainStatus(str, Enum):
    """Integrity status of an observed audit chain."""

    INTACT = "intact"
    TAMPERED = "tampered"
    INCOMPLETE = "incomplete"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Per-domain signal summaries (frozen, privacy-safe)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProvenanceSignalSummary:
    """Audit-safe summary of provenance enforcement state.

    No raw prompts, no answer text, no retrieved chunk content.
    Only governance enforcement state and citation count metadata.
    """

    enforcement_enabled: bool
    validation_state: ValidationState
    citation_count: int
    invalid_citation_count: int
    reason_code: str
    grounded_answer_enforced: bool


@dataclass(frozen=True)
class RetrievalSignalSummary:
    """Audit-safe summary of retrieval confidence and policy enforcement.

    No embeddings, no vectors, no raw chunk payloads, no retrieval text.
    Only policy state and enforcement configuration metadata.

    Extension hook: summary_metadata for future reranker governance and
    RAG integrity evidence without redesign.
    """

    retrieval_enabled: bool
    enforcement_state: EnforcementState
    effective_strategy: Optional[str]
    corpus_count: int
    grounded_context_required: bool
    reason_code: str
    lexical_fallback_used: bool
    summary_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        meta = self.summary_metadata
        object.__setattr__(
            self,
            "summary_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )


@dataclass(frozen=True)
class AuditChainSignalSummary:
    """Audit-safe summary of audit chain health and continuity.

    Supports future forensic replay without redesign via chain_id linkage.

    last_verified_at is NOT part of the canonical hash (it is a timestamp).
    chain_status, continuity_ok, tamper_detected, and event_count ARE hashed.
    """

    chain_id: str
    chain_status: AuditChainStatus
    continuity_ok: bool
    event_count: int
    tamper_detected: bool
    last_verified_at: Optional[datetime]


@dataclass(frozen=True)
class ProviderGovernanceSignalSummary:
    """Audit-safe summary of provider governance and BAA enforcement state.

    No provider credentials, auth headers, or PHI values.
    phi_detected is a boolean; phi_type_count is a count (not the type names),
    preserving privacy while enabling governance reporting.
    """

    provider_id: str
    governance_state: ProviderGovernanceState
    phi_detected: bool
    phi_type_count: int
    baa_enforced: bool
    enforcement_action: str
    reason_code: str


@dataclass(frozen=True)
class TenantIsolationSignalSummary:
    """Audit-safe summary of tenant isolation enforcement state.

    Does NOT expose unrelated tenant identifiers or cross-tenant metadata.
    Only the enforcement state for the scoped tenant is reported.
    """

    isolation_enforced: bool
    cross_tenant_rejected: bool
    enforcement_state: EnforcementState
    validation_state: ValidationState
    reason_code: str


@dataclass(frozen=True)
class PolicySignalSummary:
    """Audit-safe summary of policy engine operational state.

    Extension hook: policy_metadata for future OPA evidence and signed
    policy lineage without redesign.
    """

    enforcement_enabled: bool
    validation_state: ValidationState
    replay_ready: bool
    policy_version: Optional[str]
    policy_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        meta = self.policy_metadata
        object.__setattr__(
            self,
            "policy_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )


@dataclass(frozen=True)
class GroundedAnswerSignalSummary:
    """Audit-safe summary of grounded-answer enforcement state.

    No raw prompts, no model completions, no user conversations,
    no raw answers, no sensitive retrieval data.
    """

    enforcement_enabled: bool
    rejection_enabled: bool
    citation_required: bool
    validation_state: ValidationState
    hallucination_mitigation_active: bool


@dataclass(frozen=True)
class OperationalGovernanceSignalSummary:
    """Audit-safe summary of operational governance state.

    Extension hook: ops_metadata for future retention, export, and recovery
    governance evidence without redesign.
    """

    environment_state: str
    secret_governance_active: bool
    retention_policy_active: bool
    export_controls_active: bool
    ops_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        meta = self.ops_metadata
        object.__setattr__(
            self,
            "ops_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )


# Union type for all signal body types — exhaustive by design.
GovernanceSignalBody = Union[
    ProvenanceSignalSummary,
    RetrievalSignalSummary,
    AuditChainSignalSummary,
    ProviderGovernanceSignalSummary,
    TenantIsolationSignalSummary,
    PolicySignalSummary,
    GroundedAnswerSignalSummary,
    OperationalGovernanceSignalSummary,
]


# ---------------------------------------------------------------------------
# Runtime governance signal
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuntimeGovernanceSignal:
    """A single extracted, normalized governance signal.

    Immutability contract: frozen after construction.
    Privacy contract: signal_summary contains only audit-safe summary fields.
    Determinism contract: identical governance state → identical signal_summary.
    Replay contract: signal_id and extracted_at are NOT part of canonical hash.

    signal_id: caller-assigned stable identifier for this signal.
    extraction_id: session-level identifier for the extraction run.
    governance_source: human-readable identifier for the source system
        (e.g. "services.ai.provenance", "services.provider_baa.gate").
    extractor_version: version of the extraction logic that produced this signal.
    signal_metadata: extension hook for future chain-of-custody and
        attestation metadata — not validated here.
    """

    signal_id: str
    signal_type: GovernanceSignalType
    tenant_id: str
    extraction_id: str
    extracted_at: datetime
    status: SignalExtractionStatus
    governance_source: str
    signal_summary: GovernanceSignalBody
    extractor_version: str
    signal_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        meta = self.signal_metadata
        object.__setattr__(
            self,
            "signal_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )


# ---------------------------------------------------------------------------
# Runtime evidence snapshot
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuntimeEvidenceSnapshot:
    """Deterministic, immutable snapshot of all extracted governance signals.

    snapshot_hash covers only stable signal content — not timestamps,
    snapshot_id, or extraction_id. It is deterministic: identical governance
    state across different extraction runs produces the same snapshot_hash.

    inputs_canonical is the exact JSON string that was hashed — preserved for
    independent forensic replay without rerunning extraction.

    created_at is NOT part of the hash — it is a nondeterministic timestamp.
    assessment_id is NOT part of the hash — it can vary between assessments
    covering the same governance state.

    Extension hook: snapshot_metadata for future regulator export lineage and
    signed snapshot chain attestation without redesign.
    """

    snapshot_id: str
    tenant_id: str
    snapshot_version: str
    signals: tuple[RuntimeGovernanceSignal, ...]
    snapshot_hash: str
    inputs_canonical: str
    created_at: datetime
    assessment_id: Optional[str] = None
    snapshot_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        meta = self.snapshot_metadata
        object.__setattr__(
            self,
            "snapshot_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )
