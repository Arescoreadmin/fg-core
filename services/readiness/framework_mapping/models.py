"""Enterprise Framework Mapping & Crosswalk Governance Engine — models.

All types in this module are:
  - Pure Python. No I/O. No randomness.
  - Frozen after construction (immutable).
  - Deterministic: identical mapping state → identical canonical form.
  - Tenant-safe: tenant-scoped mappings are isolated from other tenants.
  - Export-safe: no secrets, credentials, internal topology, or provider payloads.
  - Additive: new frameworks integrate through explicit mapping contracts only.

Framework isolation contract:
  - Frameworks are identified by framework_id (string, UUID-backed) and
    framework_version (string tag). No framework semantics are hardcoded here.
  - Well-known framework slug constants are informational only — they are NOT
    enforced by this module. Framework identity is determined by the store layer.
  - Mappings are relational metadata only. Framework definitions remain
    authoritative within their own framework boundaries.

Namespace isolation contract:
  - Frameworks frequently reuse control identifiers across different specifications
    (e.g. "AC-1", "GV-2", "PR.3" appear in multiple frameworks with distinct
    meanings). Control identity is ALWAYS the combination of (control_id,
    framework_id). Bare control_id lookups are prohibited by design.
  - FrameworkNamespace provides an explicit namespace layer for future
    enforcement — a control's canonical identity is
    (namespace_prefix, control_id, framework_version).

Metadata field immutability contract:
  - All *_metadata dict fields are wrapped in MappingProxyType on construction.
  - A defensive copy is taken of the caller's dict at construction time.
  - Callers cannot mutate stored metadata content after construction.

History immutability contract:
  - Mapping history is append-only. Supersession creates a new record; it does
    not mutate prior mapping version records.
  - Historical mappings remain reconstructable even after framework evolution.
  - Supersession lineage: supersedes_relationship_id on MappingRelationship
    carries the explicit lineage pointer for replay and audit reconstruction.

Provenance contract:
  - Every MappingRelationship and ControlInheritance carries a MappingProvenance.
  - source_authority and mapping_rationale must be non-empty for valid mappings.
  - Governance approval and attestation metadata are extension hooks for future
    regulatory review and signed mapping workflows.

Confidence and authority contract:
  - mapping_confidence (0.0–1.0) declares how certain the mapping author is
    about the relationship. Validation rejects values outside [0.0, 1.0].
  - mapping_authority_level classifies the trustworthiness of the mapping source.
    Audits and regulator exports SHOULD filter on authority level.
  - mapping_review_status tracks the governance lifecycle of the mapping claim.

Tenant isolation contract:
  - scope=PLATFORM mappings have tenant_id=None and are globally readable.
  - scope=TENANT mappings have a non-None tenant_id and are isolated.
  - Validation enforces scope-tenant consistency.

Mapping integrity contract:
  - MappingHashRecord carries a deterministic SHA-256 hash of stable relationship
    content, enabling replay verification and future signed mapping support.
  - inputs_canonical is the exact JSON string that was hashed — preserved for
    independent forensic replay without rerunning the relationship construction.
  - Excluded from hash: created_at (timestamp), tenant_id, mapping_status,
    mapping_review_status, mapping_metadata (extension dict), jurisdiction,
    control_scope, supersedes_relationship_id, namespace IDs.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from types import MappingProxyType
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Well-known framework slug constants (informational — not enforced)
# ---------------------------------------------------------------------------
# Frameworks are identified by framework_id (UUID) in the store layer.
# These slug strings are canonical human-readable references for documentation
# and provenance metadata. Adding a new framework does NOT require changing
# this file — these constants are a convenience, not a requirement.

FRAMEWORK_SLUG_NIST_AI_RMF = "nist-ai-rmf"
FRAMEWORK_SLUG_ISO_42001 = "iso-42001"
FRAMEWORK_SLUG_SOC2_AI = "soc2-ai-overlay"
FRAMEWORK_SLUG_HIPAA_AI = "hipaa-ai-safeguards"
FRAMEWORK_SLUG_FROSTGATE = "frostgate"
# Future (not yet implemented — extend here when onboarding):
# FRAMEWORK_SLUG_EU_AI_ACT = "eu-ai-act"
# FRAMEWORK_SLUG_NIST_CSF = "nist-csf"
# FRAMEWORK_SLUG_ISO_27001 = "iso-27001"
# FRAMEWORK_SLUG_PCI_DSS_AI = "pci-dss-ai-overlay"
# FRAMEWORK_SLUG_FEDRAMP_AI = "fedramp-ai-overlay"

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class MappingRelationshipType(str, Enum):
    """Explicit relationship semantics between a source and target control.

    Relationship types are directional: source → target.
    Bidirectionality must be declared explicitly (is_bidirectional=True on
    MappingRelationship) — it is NEVER silently inferred.

    Future extensions append new values; existing values are stable and never
    change meaning once published.
    """

    EQUIVALENT = "equivalent"
    PARTIALLY_EQUIVALENT = "partially_equivalent"
    INHERITED = "inherited"
    DERIVED = "derived"
    SUPPLEMENTAL = "supplemental"
    DEPENDENT = "dependent"
    OVERLAPPING = "overlapping"
    BROADER_THAN = "broader_than"
    NARROWER_THAN = "narrower_than"


class MappingStatus(str, Enum):
    """Lifecycle status of a mapping record or mapping version.

    DRAFT:      Mapping is in preparation, not yet governance-approved.
    ACTIVE:     Mapping is current and governance-approved.
    DEPRECATED: Mapping remains reconstructable but is no longer recommended.
    SUPERSEDED: Mapping has been replaced by a newer version.
    """

    DRAFT = "draft"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    SUPERSEDED = "superseded"


class MappingScope(str, Enum):
    """Scope of a framework mapping set.

    PLATFORM: Globally readable; tenant_id must be None.
    TENANT:   Tenant-isolated; tenant_id must be set.
    """

    PLATFORM = "platform"
    TENANT = "tenant"


class MappingValidationType(str, Enum):
    """Type of validation performed on a mapping artifact."""

    RELATIONSHIP = "relationship"
    INHERITANCE = "inheritance"
    FRAMEWORK = "framework"
    VERSION = "version"
    DUPLICATE = "duplicate"
    CYCLE = "cycle"


class MappingGapType(str, Enum):
    """Classification of a detected mapping gap.

    UNMAPPED:                  Control has zero outbound relationships to any target.
    PARTIALLY_MAPPED:          Control has relationships but not to all target frameworks.
    ORPHANED:                  Relationship references a control or framework not in
                               the known registry.
    MISSING_INHERITANCE_TARGET: Inheritance references a parent control not in the
                               known registry.
    UNSUPPORTED_FRAMEWORK:     Control belongs to a framework not yet onboarded into
                               the mapping engine.
    """

    UNMAPPED = "unmapped"
    PARTIALLY_MAPPED = "partially_mapped"
    ORPHANED = "orphaned"
    MISSING_INHERITANCE_TARGET = "missing_inheritance_target"
    UNSUPPORTED_FRAMEWORK = "unsupported_framework"


class MappingAuthorityLevel(str, Enum):
    """Trustworthiness classification of the mapping source.

    CANONICAL:           Authoritative mapping from the framework body (e.g. NIST, ISO).
    REGULATOR_REVIEWED:  Reviewed and approved by a regulatory body.
    INTERNAL:            Produced by the platform or an internal governance team.
    CUSTOMER_DEFINED:    Produced by a customer tenant for their own context.
    PROVISIONAL:         Preliminary; not yet through full governance review.
    DEPRECATED:          Authority level no longer in use for new mappings.
    """

    CANONICAL = "canonical"
    REGULATOR_REVIEWED = "regulator_reviewed"
    INTERNAL = "internal"
    CUSTOMER_DEFINED = "customer_defined"
    PROVISIONAL = "provisional"
    DEPRECATED = "deprecated"


class MappingReviewStatus(str, Enum):
    """Governance lifecycle status of a mapping claim.

    PENDING:    Not yet submitted for review.
    IN_REVIEW:  Under active governance review.
    APPROVED:   Review passed; mapping is governance-approved.
    REJECTED:   Review failed; mapping must be revised before resubmission.
    SUPERSEDED: Mapping has been replaced by a newer reviewed version.
    """

    PENDING = "pending"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"


class MappingGranularity(str, Enum):
    """Granularity level of the mapping relationship.

    Describes what governance unit each side of the relationship represents.
    """

    CONTROL_TO_CONTROL = "control_to_control"
    CONTROL_TO_SUBCONTROL = "control_to_subcontrol"
    SUBCONTROL_TO_CONTROL = "subcontrol_to_control"
    DOMAIN_TO_DOMAIN = "domain_to_domain"
    POLICY_TO_CONTROL = "policy_to_control"
    CONTROL_TO_POLICY = "control_to_policy"


# ---------------------------------------------------------------------------
# Provenance and compatibility metadata
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MappingProvenance:
    """Immutable provenance record for a mapping relationship or inheritance.

    source_authority: Organization or body that produced the mapping
        (e.g. "NIST", "ISO", "FrostGate", "customer-tenant-123").
    mapping_rationale: Non-empty human-readable justification for the mapping.
    mapping_origin: How the mapping was produced
        (e.g. "manual", "regulatory_review", "vendor_supplied").
    mapping_version: Version of this provenance record (e.g. "1.0.0").
    author_metadata: Extension hook for author identity (future signing).
    governance_metadata: Extension hook for approval/attestation metadata
        (future regulator-reviewed, legal-reviewed, or signed mappings).
    framework_source_metadata: Extension hook for framework specification
        references (future: section numbers, annex references, etc.).
    """

    provenance_id: str
    source_authority: str
    mapping_rationale: str
    mapping_origin: str
    mapping_version: str
    author_metadata: Mapping[str, Any] = None  # type: ignore[assignment]
    governance_metadata: Mapping[str, Any] = None  # type: ignore[assignment]
    framework_source_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        for field_name in (
            "author_metadata",
            "governance_metadata",
            "framework_source_metadata",
        ):
            val = getattr(self, field_name)
            object.__setattr__(
                self,
                field_name,
                MappingProxyType(dict(val) if val is not None else {}),
            )


@dataclass(frozen=True)
class MappingCompatibilityRecord:
    """Version-pinned compatibility declaration between two framework versions.

    Asserts whether mappings between a specific pair of framework versions are
    considered compatible. Compatibility is explicit — never inferred.

    source_framework_id / target_framework_id: UUID-backed framework identifiers.
    source_version_tag / target_version_tag: The exact framework version tags
        for which this compatibility assertion holds.
    is_compatible: Whether the two versions are compatible for mapping purposes.
    compatibility_notes: Human-readable compatibility rationale.
    compatibility_metadata: Extension hook for future compatibility governance.
    """

    source_framework_id: str
    source_version_tag: str
    target_framework_id: str
    target_version_tag: str
    is_compatible: bool
    compatibility_notes: str
    compatibility_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        meta = self.compatibility_metadata
        object.__setattr__(
            self,
            "compatibility_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )


@dataclass(frozen=True)
class JurisdictionApplicability:
    """Jurisdiction scope declaration for a mapping relationship.

    jurisdiction_ids: Explicit jurisdiction codes (e.g. "EU", "US-CA", "UK").
    regional_restrictions: Regions where the mapping does NOT apply.
    sovereign_applicability: Sovereign or national contexts where it applies.
    sector_applicability: Industry sectors (e.g. "healthcare", "financial").
    jurisdiction_metadata: Extension hook for regulatory overlay details.
    """

    jurisdiction_ids: tuple[str, ...]
    regional_restrictions: tuple[str, ...]
    sovereign_applicability: tuple[str, ...]
    sector_applicability: tuple[str, ...]
    jurisdiction_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        meta = self.jurisdiction_metadata
        object.__setattr__(
            self,
            "jurisdiction_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )


@dataclass(frozen=True)
class MappingControlScope:
    """Scope dimension declaration for a mapping relationship.

    Each field describes an applicability boundary of the mapping.
    """

    control_scope: str
    organizational_scope: str
    operational_scope: str
    technical_scope: str
    scope_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        meta = self.scope_metadata
        object.__setattr__(
            self,
            "scope_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )


@dataclass(frozen=True)
class FrameworkNamespace:
    """Explicit namespace record for a framework's control identifier space.

    Provides an additional isolation layer for frameworks that reuse control
    identifier strings across different specifications.

    namespace_prefix: Short prefix for this namespace (e.g. "NIST-AI:", "ISO-42:").
    namespace_version: Version of this namespace declaration.
    namespace_metadata: Extension hook for namespace governance details.
    """

    namespace_id: str
    framework_id: str
    namespace_prefix: str
    namespace_version: str
    namespace_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        meta = self.namespace_metadata
        object.__setattr__(
            self,
            "namespace_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )


# ---------------------------------------------------------------------------
# Core mapping types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MappingRelationship:
    """A single directional governance relationship between two controls.

    Relationships are directional: source_control_id → target_control_id.
    Bidirectionality must be declared explicitly via is_bidirectional=True —
    it is NEVER inferred from a single relationship record.

    relationship_type explicitly declares the semantic meaning of the mapping.
    No equivalence is assumed: EQUIVALENT must be declared, not inferred.

    tenant_id=None means the relationship is platform-level (globally readable).
    tenant_id set means the relationship is tenant-scoped and isolated.

    mapping_metadata: extension hook for future chain-of-custody, attestation,
    and regulatory export metadata.
    """

    relationship_id: str
    source_control_id: str
    source_framework_id: str
    source_framework_version: str
    target_control_id: str
    target_framework_id: str
    target_framework_version: str
    relationship_type: MappingRelationshipType
    mapping_status: MappingStatus
    provenance: MappingProvenance
    compatibility: MappingCompatibilityRecord
    is_bidirectional: bool
    created_by: str
    created_at: datetime
    tenant_id: Optional[str]
    mapping_metadata: Mapping[str, Any] = None  # type: ignore[assignment]
    mapping_confidence: float = 1.0
    mapping_authority_level: MappingAuthorityLevel = MappingAuthorityLevel.INTERNAL
    mapping_review_status: MappingReviewStatus = MappingReviewStatus.PENDING
    mapping_granularity: MappingGranularity = MappingGranularity.CONTROL_TO_CONTROL
    jurisdiction: Optional[JurisdictionApplicability] = None
    control_scope: Optional[MappingControlScope] = None
    supersedes_relationship_id: Optional[str] = None
    source_namespace_id: Optional[str] = None
    target_namespace_id: Optional[str] = None

    def __post_init__(self) -> None:
        meta = self.mapping_metadata
        object.__setattr__(
            self,
            "mapping_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )


@dataclass(frozen=True)
class ControlInheritance:
    """Explicit control inheritance record between a parent and child control.

    Inheritance semantics are explicit: each inherited dimension is declared
    individually via its boolean field. Hidden inheritance logic is prohibited.

    Architecture supports future extension for:
    - Layered inheritance (grandparent → parent → child chains)
    - Conditional inheritance (inheritance with applicability conditions)
    - Framework overlays (tenant-specific inheritance modifications)
    - Inheritance exceptions (explicit opt-out of inherited obligations)

    These future patterns extend this record without redesign by using
    inheritance_metadata and adding new versioned record types.
    """

    inheritance_id: str
    parent_control_id: str
    parent_framework_id: str
    parent_framework_version: str
    child_control_id: str
    child_framework_id: str
    child_framework_version: str
    inherited_obligations: bool
    inherited_maturity_semantics: bool
    inherited_evidence_expectations: bool
    inherited_applicability_metadata: bool
    inheritance_rationale: str
    provenance: MappingProvenance
    created_by: str
    created_at: datetime
    tenant_id: Optional[str]
    inheritance_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        meta = self.inheritance_metadata
        object.__setattr__(
            self,
            "inheritance_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )


@dataclass(frozen=True)
class FrameworkMappingVersion:
    """Versioned record of a mapping set between two framework versions.

    A FrameworkMappingVersion pins the mapping set to specific versions of both
    the source and target framework. When either framework releases a new version,
    a new FrameworkMappingVersion is created. Historical versions remain
    reconstructable and immutable.

    Supersession creates a new record and sets superseded_by on the prior record.
    It never mutates the prior record's content.

    mapping_version_tag: Semantic version of this mapping set (e.g. "1.0.0").
    superseded_by: mapping_version_id of the newer version, if superseded.
    version_metadata: Extension hook for future governance approval and
        signed version chains.
    """

    mapping_version_id: str
    source_framework_id: str
    source_framework_version: str
    target_framework_id: str
    target_framework_version: str
    mapping_version_tag: str
    mapping_status: MappingStatus
    superseded_by: Optional[str]
    created_by: str
    created_at: datetime
    deprecation_note: Optional[str]
    version_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        meta = self.version_metadata
        object.__setattr__(
            self,
            "version_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )


@dataclass(frozen=True)
class FrameworkMapping:
    """An immutable, versioned collection of governance mappings between two frameworks.

    A FrameworkMapping aggregates all MappingRelationship and ControlInheritance
    records for a specific source/target framework pair at a declared mapping version.

    Relationships and inheritances are stored as tuples — append-only; corrections
    create new records rather than mutating existing ones.

    scope=PLATFORM mappings have tenant_id=None.
    scope=TENANT mappings have a non-None tenant_id.

    mapping_metadata: Extension hook for future regulator export lineage and
    signed mapping chain attestation.
    """

    framework_mapping_id: str
    source_framework_id: str
    target_framework_id: str
    mapping_version: FrameworkMappingVersion
    relationships: tuple[MappingRelationship, ...]
    inheritances: tuple[ControlInheritance, ...]
    scope: MappingScope
    tenant_id: Optional[str]
    created_by: str
    created_at: datetime
    mapping_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        meta = self.mapping_metadata
        object.__setattr__(
            self,
            "mapping_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )


# ---------------------------------------------------------------------------
# Validation and gap detection output types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MappingValidationRecord:
    """Deterministic result of a mapping validation operation.

    failure_reasons is a tuple of stable, version-safe reason codes.
    is_valid=False with empty failure_reasons MUST NOT occur.
    validator_version enables future schema evolution detection.
    """

    validation_id: str
    subject_id: str
    validation_type: MappingValidationType
    is_valid: bool
    failure_reasons: tuple[str, ...]
    validated_at: datetime
    validator_version: str


@dataclass(frozen=True)
class MappingHashRecord:
    """Deterministic SHA-256 integrity record for a mapping relationship.

    relationship_id: ID of the relationship this hash covers.
    algorithm: Hash algorithm used (always "sha256" for current records).
    hash_value: Hex-encoded SHA-256 digest of inputs_canonical.
    inputs_canonical: Exact JSON string hashed — preserved for forensic replay.
    computed_at: Timestamp when the hash was computed.
    is_replay_safe: True if inputs_canonical is complete for independent replay.
    """

    relationship_id: str
    algorithm: str
    hash_value: str
    inputs_canonical: str
    computed_at: datetime
    is_replay_safe: bool


@dataclass(frozen=True)
class MappingGapRecord:
    """A detected gap in framework control coverage.

    gap_type classifies the nature of the gap.
    gap_metadata is an extension hook for future gap remediation planning
    and gap severity classification without redesign.
    """

    gap_id: str
    control_id: str
    framework_id: str
    framework_version: str
    gap_type: MappingGapType
    detected_at: datetime
    gap_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        meta = self.gap_metadata
        object.__setattr__(
            self,
            "gap_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )


@dataclass(frozen=True)
class CrosswalkEntry:
    """A single entry in a framework crosswalk for one source control.

    outbound_relationships: mappings where this control is the source.
    inbound_relationships: mappings where this control is the target.
    inheritances: inheritance records where this control is the child.
    gap_status: None means the control is fully mapped on at least one dimension.
    crosswalk_metadata: extension hook for future regulator export crosswalk
    formatting and attestation metadata.
    """

    source_control_id: str
    source_framework_id: str
    source_framework_version: str
    outbound_relationships: tuple[MappingRelationship, ...]
    inbound_relationships: tuple[MappingRelationship, ...]
    inheritances: tuple[ControlInheritance, ...]
    gap_status: Optional[MappingGapType]
    crosswalk_metadata: Mapping[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        meta = self.crosswalk_metadata
        object.__setattr__(
            self,
            "crosswalk_metadata",
            MappingProxyType(dict(meta) if meta is not None else {}),
        )
