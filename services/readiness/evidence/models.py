"""Enterprise Evidence Contract & Provenance Governance Layer — pure Python models.

Frozen dataclasses and enums only. No I/O. No SQLAlchemy. No scoring logic.
No ingestion automation. No OCR. No document AI. No provider calls.
No raw document bodies. No secrets.

These models provide structured, typed, hashable governance contracts for
evidence provenance, classification, integrity, and linkage. They are the
normalized form of what the EvidenceReference source/ownership/integrity
metadata dicts contain at runtime.

Immutability contract:
  - All output types are frozen after construction.
  - Evidence corrections MUST create new records rather than mutating existing ones.
  - EvidenceIntegrityRecord.hash_value MUST NOT change after creation.

Serialization contract:
  - All fields are export-safe: no secrets, credentials, raw document bodies,
    OCR text, embeddings, signed URLs, internal storage paths, or provider payloads.
  - Unknown fields are never silently accepted; callers must explicitly pass known fields.

Hashing contract:
  - Hash inputs are explicitly enumerated in EvidenceHashRecord.inputs_description.
  - Hash generation is deterministic, ordering-stable, and replay-safe.
  - Hash functions must not depend on nondeterministic timestamps, dict ordering
    instability, ORM ordering, or serialization randomness.

Future extension hooks:
  - EvidenceLink.link_metadata: chain-of-custody, attestation, signer metadata.
  - EvidenceProvenance.lineage_metadata: export lineage, forensic handling.
  - EvidenceIntegrityRecord: Merkle verification, signed evidence chains.
  - EvidenceClassification: residency restrictions, sovereign restrictions, legal hold.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class EvidenceCategory(str, Enum):
    """Normalized evidence category — purpose-oriented classification.

    Distinct from EvidenceType (which is the submission medium). Category
    describes the governance purpose of the evidence in a readiness context.
    """

    AUDIT_LOG = "audit_log"
    CONFIGURATION = "configuration"
    POLICY = "policy"
    RETRIEVAL_TRACE = "retrieval_trace"
    SCREENSHOT = "screenshot"
    EXPORTED_REPORT = "exported_report"
    RUNTIME_TELEMETRY = "runtime_telemetry"
    ATTESTATION = "attestation"
    EXTERNAL_CERTIFICATION = "external_certification"
    OTHER = "other"


class EvidenceLifecycleState(str, Enum):
    """Evidence lifecycle state — immutable once terminal.

    PENDING:     Submitted, awaiting integrity/provenance validation.
    ACTIVE:      Validated; eligible for scoring and audit use.
    SUPERSEDED:  Replaced by a newer evidence record (create new, not mutate).
    EXPIRED:     Past evidence expiration_date; excluded from active scoring.
    ARCHIVED:    Preserved for audit replay; excluded from active scoring.
    INVALIDATED: Failed integrity or provenance validation; excluded from all use.

    Terminal states: INVALIDATED. No transitions out.
    ARCHIVED is semi-terminal: no forward transitions except forensic re-activation
    via break-glass (not implemented in this layer).
    """

    PENDING = "pending"
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    EXPIRED = "expired"
    ARCHIVED = "archived"
    INVALIDATED = "invalidated"


class EvidenceClassificationLevel(str, Enum):
    """Evidence classification level for export and access control.

    Governs which principals may access, export, or reference evidence.
    Default-deny: unknown classification blocks export.

    Extension hooks (not implemented):
    - residency restrictions (data sovereignty)
    - sovereign cloud restrictions
    - legal hold classification
    - retention governance tiers
    - export restrictions by jurisdiction
    """

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    REGULATED = "regulated"
    EXPORT_CONTROLLED = "export_controlled"


class EvidenceCollectionMethod(str, Enum):
    """How the evidence was collected from the source system."""

    MANUAL_UPLOAD = "manual_upload"
    AUTOMATED_EXPORT = "automated_export"
    API_PULL = "api_pull"
    AGENT_COLLECT = "agent_collect"
    ATTESTATION_SUBMISSION = "attestation_submission"
    EXTERNAL_CONNECTOR = "external_connector"


class EvidenceLinkType(str, Enum):
    """The type of relationship described by an EvidenceLink."""

    ASSESSMENT_RESULT = "assessment_result"
    CONTROL = "control"
    FRAMEWORK = "framework"
    RETRIEVAL_TRACE = "retrieval_trace"
    TELEMETRY_RECORD = "telemetry_record"
    AUDIT_EVENT = "audit_event"
    EXPORT_RUN = "export_run"
    OPERATIONAL_GOVERNANCE = "operational_governance"


class EvidenceValidationType(str, Enum):
    """What dimension was validated."""

    INTEGRITY = "integrity"
    PROVENANCE = "provenance"
    CLASSIFICATION = "classification"
    SCHEMA = "schema"
    TENANT_ISOLATION = "tenant_isolation"
    LINKAGE = "linkage"
    LIFECYCLE = "lifecycle"


# ---------------------------------------------------------------------------
# Valid lifecycle transitions
# ---------------------------------------------------------------------------

VALID_EVIDENCE_TRANSITIONS: dict[
    EvidenceLifecycleState, frozenset[EvidenceLifecycleState]
] = {
    EvidenceLifecycleState.PENDING: frozenset(
        {
            EvidenceLifecycleState.ACTIVE,
            EvidenceLifecycleState.INVALIDATED,
        }
    ),
    EvidenceLifecycleState.ACTIVE: frozenset(
        {
            EvidenceLifecycleState.SUPERSEDED,
            EvidenceLifecycleState.EXPIRED,
            EvidenceLifecycleState.ARCHIVED,
            EvidenceLifecycleState.INVALIDATED,
        }
    ),
    EvidenceLifecycleState.SUPERSEDED: frozenset(
        {
            EvidenceLifecycleState.ARCHIVED,
        }
    ),
    EvidenceLifecycleState.EXPIRED: frozenset(
        {
            EvidenceLifecycleState.ARCHIVED,
        }
    ),
    EvidenceLifecycleState.ARCHIVED: frozenset(),  # semi-terminal
    EvidenceLifecycleState.INVALIDATED: frozenset(),  # terminal
}

IMMUTABLE_EVIDENCE_STATES: frozenset[EvidenceLifecycleState] = frozenset(
    {
        EvidenceLifecycleState.INVALIDATED,
        EvidenceLifecycleState.ARCHIVED,
    }
)


def validate_evidence_lifecycle_transition(
    from_state: EvidenceLifecycleState,
    to_state: EvidenceLifecycleState,
) -> None:
    """Raise ValueError if the evidence lifecycle transition is not permitted."""
    allowed = VALID_EVIDENCE_TRANSITIONS.get(from_state, frozenset())
    if to_state not in allowed:
        raise ValueError(
            f"Invalid evidence lifecycle transition: {from_state!r} → {to_state!r}. "
            f"Allowed: {sorted(s.value for s in allowed) or 'none (terminal state)'}"
        )


# ---------------------------------------------------------------------------
# Component dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceSource:
    """Normalized evidence source descriptor.

    Describes the system and actor that produced or exported the evidence.
    No raw credentials, auth headers, or internal storage paths.

    Extension hook: source_metadata for future connector-specific fields.
    Chain-of-custody: custody_metadata (not implemented) would extend here.
    """

    source_id: str
    source_system: str
    collection_method: EvidenceCollectionMethod
    collection_actor: str
    collected_at: datetime
    tenant_id: str
    source_version: Optional[str] = None
    source_metadata: dict[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.source_metadata is None:
            object.__setattr__(self, "source_metadata", {})


@dataclass(frozen=True)
class EvidenceProvenance:
    """Immutable provenance record for a piece of evidence.

    Links evidence to the assessment, controls, framework, and operational
    context under which it was collected. Deterministic and reconstructable.

    lineage_metadata is the extension hook for future chain-of-custody,
    export lineage, and forensic handling metadata — not validated here.

    All IDs are stable identifiers from the corresponding domain model.
    No raw content, no secrets, no provider payloads.
    """

    provenance_id: str
    evidence_id: str
    tenant_id: str
    source: EvidenceSource
    provenance_version: str  # schema version for replay, e.g. "1.0"
    actor_metadata: dict[str, Any] = None  # type: ignore[assignment]
    lineage_metadata: dict[str, Any] = None  # type: ignore[assignment]
    assessment_id: Optional[str] = None
    control_ids: tuple[str, ...] = ()
    framework_id: Optional[str] = None
    environment_id: Optional[str] = None
    retrieval_trace_id: Optional[str] = None
    export_id: Optional[str] = None
    audit_event_id: Optional[str] = None

    def __post_init__(self) -> None:
        if self.actor_metadata is None:
            object.__setattr__(self, "actor_metadata", {})
        if self.lineage_metadata is None:
            object.__setattr__(self, "lineage_metadata", {})


@dataclass(frozen=True)
class EvidenceHashRecord:
    """Deterministic hash of a normalized evidence payload.

    hash_value: SHA-256 hex digest of the canonical payload.
    inputs_description: human-readable documentation of exactly what was hashed.
    inputs_canonical: the deterministic JSON string that was hashed (for replay).

    Replay contract:
      - inputs_canonical is sort-keyed JSON with no whitespace.
      - The same inputs_canonical ALWAYS produces the same hash_value.
      - computed_at is NOT part of hash inputs (timestamps are nondeterministic).

    Future extensions:
      - algorithm field enables migration to SHA-3 or stronger without redesign.
      - Merkle tree construction: hash_value becomes a leaf node.
      - Signed chains: hash_value becomes the signing target.
    """

    evidence_id: str
    algorithm: str  # always "sha256" in v1
    hash_value: str  # hex digest
    inputs_canonical: str  # the exact JSON string hashed
    inputs_description: str  # human-readable documentation of what was hashed
    computed_at: datetime
    is_replay_safe: bool  # True if inputs_canonical is sufficient to reproduce


@dataclass(frozen=True)
class EvidenceIntegrityRecord:
    """Full integrity record: hash + verification state.

    Once persisted, hash_value MUST NOT mutate. Corrections require a new
    EvidenceIntegrityRecord for the corrected evidence record.

    Verification chain:
      - is_verified=False: hash computed but not yet verified against source.
      - is_verified=True: hash was independently validated by verification_actor.
      - verification_actor/verified_at: required when is_verified=True.
    """

    integrity_id: str
    evidence_id: str
    tenant_id: str
    hash_record: EvidenceHashRecord
    is_verified: bool
    verification_actor: Optional[str] = None
    verified_at: Optional[datetime] = None


@dataclass(frozen=True)
class EvidenceLink:
    """Immutable directional link from evidence to a governed resource.

    Enables bidirectional traceability: given evidence → find all controls,
    assessment results, and audit events; given a control → find all evidence.

    link_metadata: extension hook for future attestation and signer metadata.
    No raw content, secrets, or provider payloads in link_metadata.
    """

    link_id: str
    evidence_id: str
    tenant_id: str
    link_type: EvidenceLinkType
    target_id: str
    target_type: str
    created_at: datetime
    link_metadata: dict[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.link_metadata is None:
            object.__setattr__(self, "link_metadata", {})


@dataclass(frozen=True)
class EvidenceValidationRecord:
    """Deterministic validation result for one validation dimension.

    Validation is fail-closed: is_valid=False means the evidence MUST NOT be
    used for scoring, export, or audit until the failure is resolved.

    failure_reasons is an ordered tuple of deterministic, testable reason codes
    (not narrative text). Callers can assert specific failure codes in tests.
    """

    validation_id: str
    evidence_id: str
    tenant_id: str
    validation_type: EvidenceValidationType
    is_valid: bool
    failure_reasons: tuple[str, ...]
    validated_at: datetime
    validator_version: str  # e.g. "1.0.0"
