"""services/evidence_authority/models.py — Domain models for Canonical Evidence Authority.

Pure Python. No I/O. No SQLAlchemy. No scoring logic. No provider calls.

All enums and state machines are defined here as the authoritative contract.
Changing a transition map or adding a state is a breaking change — update
schema_version and add a migration note.

Design principles:
  - Fail-closed: unknown states or invalid transitions raise immediately.
  - Immutability: terminal states cannot transition out.
  - AGI-forward: actor_type supports human|service|agent|autonomous_system.
  - Extensible: classification_labels is an open set for future regulatory labels.
  - Deterministic: all transition logic is pure and testable without I/O.
"""

from __future__ import annotations

from enum import Enum
from typing import FrozenSet


# ---------------------------------------------------------------------------
# Evidence Lifecycle
# ---------------------------------------------------------------------------


class EvidenceLifecycleState(str, Enum):
    """Ten-state enterprise evidence lifecycle.

    DRAFT:          Created but not yet submitted for review.
    COLLECTED:      Raw evidence captured from source; not yet formally submitted.
    SUBMITTED:      Formally submitted for review; awaiting review assignment.
    UNDER_REVIEW:   Assigned to a reviewer; review in progress.
    VERIFIED:       Review completed positively; evidence is authoritative.
    REJECTED:       Review completed negatively; evidence is disqualified.
    SUPERSEDED:     Replaced by a newer evidence record; preserved for lineage.
    EXPIRED:        Past expires_at threshold; excluded from active use.
    REVOKED:        Administratively revoked (e.g., discovered tampered).
    ARCHIVED:       Long-term preservation; excluded from active scoring.

    Terminal states: REVOKED (no forward transition allowed).
    Semi-terminal: ARCHIVED (break-glass reactivation not implemented here).
    """

    DRAFT = "DRAFT"
    COLLECTED = "COLLECTED"
    SUBMITTED = "SUBMITTED"
    UNDER_REVIEW = "UNDER_REVIEW"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    SUPERSEDED = "SUPERSEDED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    ARCHIVED = "ARCHIVED"


# Authoritative lifecycle transition map.
# Changing this is a breaking change — bump LIFECYCLE_SCHEMA_VERSION.
LIFECYCLE_SCHEMA_VERSION = "1.0"

VALID_LIFECYCLE_TRANSITIONS: dict[
    EvidenceLifecycleState, FrozenSet[EvidenceLifecycleState]
] = {
    EvidenceLifecycleState.DRAFT: frozenset(
        {
            EvidenceLifecycleState.COLLECTED,
            EvidenceLifecycleState.SUBMITTED,
            EvidenceLifecycleState.REVOKED,
        }
    ),
    EvidenceLifecycleState.COLLECTED: frozenset(
        {
            EvidenceLifecycleState.SUBMITTED,
            EvidenceLifecycleState.EXPIRED,
            EvidenceLifecycleState.REVOKED,
            EvidenceLifecycleState.ARCHIVED,
        }
    ),
    EvidenceLifecycleState.SUBMITTED: frozenset(
        {
            EvidenceLifecycleState.UNDER_REVIEW,
            EvidenceLifecycleState.COLLECTED,  # retract submission
            EvidenceLifecycleState.EXPIRED,
            EvidenceLifecycleState.REVOKED,
        }
    ),
    EvidenceLifecycleState.UNDER_REVIEW: frozenset(
        {
            EvidenceLifecycleState.VERIFIED,
            EvidenceLifecycleState.REJECTED,
            EvidenceLifecycleState.REVOKED,
        }
    ),
    EvidenceLifecycleState.VERIFIED: frozenset(
        {
            EvidenceLifecycleState.SUPERSEDED,
            EvidenceLifecycleState.EXPIRED,
            EvidenceLifecycleState.ARCHIVED,
            EvidenceLifecycleState.REVOKED,
        }
    ),
    EvidenceLifecycleState.REJECTED: frozenset(
        {
            EvidenceLifecycleState.SUBMITTED,  # resubmit after correction
            EvidenceLifecycleState.ARCHIVED,
            EvidenceLifecycleState.REVOKED,
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
            EvidenceLifecycleState.REVOKED,
        }
    ),
    EvidenceLifecycleState.REVOKED: frozenset(),  # terminal — no outbound
    EvidenceLifecycleState.ARCHIVED: frozenset(),  # semi-terminal
}

# States where evidence is eligible for active use (scoring, reporting, governance)
ACTIVE_ELIGIBLE_STATES: FrozenSet[EvidenceLifecycleState] = frozenset(
    {
        EvidenceLifecycleState.VERIFIED,
    }
)

# States where evidence is eligible for read (viewing, audit trail)
READ_ELIGIBLE_STATES: FrozenSet[EvidenceLifecycleState] = frozenset(
    {
        EvidenceLifecycleState.DRAFT,
        EvidenceLifecycleState.COLLECTED,
        EvidenceLifecycleState.SUBMITTED,
        EvidenceLifecycleState.UNDER_REVIEW,
        EvidenceLifecycleState.VERIFIED,
        EvidenceLifecycleState.REJECTED,
        EvidenceLifecycleState.SUPERSEDED,
        EvidenceLifecycleState.EXPIRED,
        EvidenceLifecycleState.ARCHIVED,
        # REVOKED is readable for audit purposes
        EvidenceLifecycleState.REVOKED,
    }
)

# Terminal states — no transitions out
TERMINAL_LIFECYCLE_STATES: FrozenSet[EvidenceLifecycleState] = frozenset(
    {
        EvidenceLifecycleState.REVOKED,
    }
)

# States that block mutation of evidence metadata
IMMUTABLE_LIFECYCLE_STATES: FrozenSet[EvidenceLifecycleState] = frozenset(
    {
        EvidenceLifecycleState.VERIFIED,
        EvidenceLifecycleState.REVOKED,
        EvidenceLifecycleState.ARCHIVED,
    }
)


def validate_lifecycle_transition(
    from_state: EvidenceLifecycleState,
    to_state: EvidenceLifecycleState,
) -> None:
    """Raise ValueError if the transition is not permitted."""
    allowed = VALID_LIFECYCLE_TRANSITIONS.get(from_state, frozenset())
    if to_state not in allowed:
        allowed_str = sorted(s.value for s in allowed) or ["none (terminal)"]
        raise ValueError(
            f"Invalid lifecycle transition: {from_state.value!r} → {to_state.value!r}. "
            f"Allowed: {allowed_str}"
        )


# ---------------------------------------------------------------------------
# Evidence Classification
# ---------------------------------------------------------------------------


class EvidenceClassification(str, Enum):
    """Base classification tier — governs access, export, and display."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    REGULATED = "REGULATED"


# Extended classification labels (additive, open set).
# These are stored as JSON array on fa_evidence.classification_labels.
# Adding new values here requires no schema migration.
KNOWN_CLASSIFICATION_LABELS: frozenset[str] = frozenset(
    {
        "PII",
        "PHI",
        "PCI",
        "CJIS",
        "ITAR",
        "EXPORT_CONTROLLED",
        "LEGAL_HOLD",
        "CUI",
        "FEDRAMP",
        "GLBA",
        "SOX",
    }
)

# Tier ordering for export gate logic: higher index = more restrictive
CLASSIFICATION_TIER_ORDER = [
    EvidenceClassification.PUBLIC,
    EvidenceClassification.INTERNAL,
    EvidenceClassification.CONFIDENTIAL,
    EvidenceClassification.RESTRICTED,
    EvidenceClassification.REGULATED,
]


def is_classification_export_blocked(classification: EvidenceClassification) -> bool:
    """REGULATED evidence is export-blocked by default (default-deny)."""
    return classification == EvidenceClassification.REGULATED


# ---------------------------------------------------------------------------
# Evidence Source Type
# ---------------------------------------------------------------------------


class EvidenceSourceType(str, Enum):
    """How the evidence originated — unlimited extension without migration."""

    INTERVIEW = "INTERVIEW"
    DOCUMENT = "DOCUMENT"
    SCREENSHOT = "SCREENSHOT"
    SYSTEM_EXPORT = "SYSTEM_EXPORT"
    CONNECTOR = "CONNECTOR"
    SCAN = "SCAN"
    POLICY = "POLICY"
    ATTESTATION = "ATTESTATION"
    CONTROL_VERIFICATION = "CONTROL_VERIFICATION"
    REMEDIATION_VERIFICATION = "REMEDIATION_VERIFICATION"
    MANUAL_UPLOAD = "MANUAL_UPLOAD"


class EvidenceCollectionMethod(str, Enum):
    """How the evidence was collected from the source."""

    MANUAL_UPLOAD = "MANUAL_UPLOAD"
    AUTOMATED_EXPORT = "AUTOMATED_EXPORT"
    API_PULL = "API_PULL"
    AGENT_COLLECT = "AGENT_COLLECT"
    ATTESTATION_SUBMISSION = "ATTESTATION_SUBMISSION"
    EXTERNAL_CONNECTOR = "EXTERNAL_CONNECTOR"


# ---------------------------------------------------------------------------
# Evidence Trust State
# ---------------------------------------------------------------------------


class EvidenceTrustState(str, Enum):
    """Trust state independent of lifecycle state.

    A piece of evidence can be VERIFIED (lifecycle) but DISPUTED (trust) if
    subsequent information calls its accuracy into question.
    """

    UNVERIFIED = "UNVERIFIED"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    VERIFIED = "VERIFIED"
    HIGH_CONFIDENCE = "HIGH_CONFIDENCE"
    DISPUTED = "DISPUTED"
    INVALIDATED = "INVALIDATED"


VALID_TRUST_TRANSITIONS: dict[EvidenceTrustState, FrozenSet[EvidenceTrustState]] = {
    EvidenceTrustState.UNVERIFIED: frozenset(
        {
            EvidenceTrustState.PARTIALLY_VERIFIED,
            EvidenceTrustState.VERIFIED,
            EvidenceTrustState.DISPUTED,
            EvidenceTrustState.INVALIDATED,
        }
    ),
    EvidenceTrustState.PARTIALLY_VERIFIED: frozenset(
        {
            EvidenceTrustState.VERIFIED,
            EvidenceTrustState.HIGH_CONFIDENCE,
            EvidenceTrustState.DISPUTED,
            EvidenceTrustState.INVALIDATED,
        }
    ),
    EvidenceTrustState.VERIFIED: frozenset(
        {
            EvidenceTrustState.HIGH_CONFIDENCE,
            EvidenceTrustState.DISPUTED,
            EvidenceTrustState.INVALIDATED,
            EvidenceTrustState.PARTIALLY_VERIFIED,  # downgrade if new evidence contradicts
        }
    ),
    EvidenceTrustState.HIGH_CONFIDENCE: frozenset(
        {
            EvidenceTrustState.DISPUTED,
            EvidenceTrustState.INVALIDATED,
            EvidenceTrustState.VERIFIED,  # downgrade if confidence evidence removed
        }
    ),
    EvidenceTrustState.DISPUTED: frozenset(
        {
            EvidenceTrustState.PARTIALLY_VERIFIED,  # dispute resolved partially
            EvidenceTrustState.VERIFIED,  # dispute resolved fully
            EvidenceTrustState.INVALIDATED,  # dispute proves invalidity
        }
    ),
    EvidenceTrustState.INVALIDATED: frozenset(),  # terminal
}

TERMINAL_TRUST_STATES: FrozenSet[EvidenceTrustState] = frozenset(
    {
        EvidenceTrustState.INVALIDATED,
    }
)

# Minimum trust score by state (for trust scoring engine)
TRUST_STATE_SCORE_FLOOR: dict[EvidenceTrustState, int] = {
    EvidenceTrustState.UNVERIFIED: 0,
    EvidenceTrustState.PARTIALLY_VERIFIED: 25,
    EvidenceTrustState.VERIFIED: 60,
    EvidenceTrustState.HIGH_CONFIDENCE: 85,
    EvidenceTrustState.DISPUTED: 0,
    EvidenceTrustState.INVALIDATED: 0,
}


def validate_trust_transition(
    from_state: EvidenceTrustState,
    to_state: EvidenceTrustState,
) -> None:
    """Raise ValueError if the trust transition is not permitted."""
    allowed = VALID_TRUST_TRANSITIONS.get(from_state, frozenset())
    if to_state not in allowed:
        allowed_str = sorted(s.value for s in allowed) or ["none (terminal)"]
        raise ValueError(
            f"Invalid trust transition: {from_state.value!r} → {to_state.value!r}. "
            f"Allowed: {allowed_str}"
        )


# ---------------------------------------------------------------------------
# Ownership Role
# ---------------------------------------------------------------------------


class EvidenceOwnershipRole(str, Enum):
    """Ownership roles for evidence — AGI-forward."""

    OWNER = "OWNER"
    REVIEWER = "REVIEWER"
    VERIFIER = "VERIFIER"
    APPROVER = "APPROVER"
    CUSTODIAN = "CUSTODIAN"


class ActorType(str, Enum):
    """Actor type classification — supports autonomous systems."""

    HUMAN = "human"
    SERVICE = "service"
    AGENT = "agent"
    AUTONOMOUS_SYSTEM = "autonomous_system"


# ---------------------------------------------------------------------------
# Relationship Types
# ---------------------------------------------------------------------------


class EvidenceRelatedEntityType(str, Enum):
    """Entity types that evidence can relate to."""

    ASSESSMENT = "assessment"
    FINDING = "finding"
    CONTROL = "control"
    RISK_ACCEPTANCE = "risk_acceptance"
    REVIEW = "review"
    GOVERNANCE_DECISION = "governance_decision"
    REMEDIATION = "remediation"
    REPORT = "report"
    TIMELINE_EVENT = "timeline_event"


class EvidenceRelationshipType(str, Enum):
    """Type of relationship between evidence and a governed resource."""

    SUPPORTS = "SUPPORTS"
    PROVES = "PROVES"
    REFUTES = "REFUTES"
    SUPERSEDES = "SUPERSEDES"
    LINKED_TO = "LINKED_TO"


# ---------------------------------------------------------------------------
# Verification Source
# ---------------------------------------------------------------------------


class VerificationSource(str, Enum):
    """Who or what performed the verification."""

    HUMAN = "HUMAN"
    AI = "AI"
    CONNECTOR = "CONNECTOR"
    THIRD_PARTY = "THIRD_PARTY"
    AUTOMATED = "AUTOMATED"
    SYSTEM = "SYSTEM"


# ---------------------------------------------------------------------------
# Audit Event Types
# ---------------------------------------------------------------------------


class EvidenceAuditEventType(str, Enum):
    """Stable audit event type codes — never change; only add."""

    EVIDENCE_CREATED = "evidence_created"
    LIFECYCLE_TRANSITIONED = "lifecycle_transitioned"
    OWNERSHIP_ASSIGNED = "ownership_assigned"
    OWNERSHIP_REVOKED = "ownership_revoked"
    RELATIONSHIP_LINKED = "relationship_linked"
    METADATA_UPDATED = "metadata_updated"
    TRUST_STATE_CHANGED = "trust_state_changed"
    CLASSIFICATION_CHANGED = "classification_changed"
    EVIDENCE_EXPIRED = "evidence_expired"
    EVIDENCE_REVOKED = "evidence_revoked"
    EVIDENCE_ARCHIVED = "evidence_archived"
    EVIDENCE_SUPERSEDED = "evidence_superseded"
