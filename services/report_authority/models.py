"""services/report_authority/models.py — Domain models for Report Authority.

Pure Python. No I/O. No SQLAlchemy. No Pydantic.

All enums and state machines are defined here as the authoritative contract.
Changing a transition map or adding a state is a breaking change — update
REPORT_SCHEMA_VERSION and add a migration note.

Design principles:
  - Fail-closed: unknown states or invalid transitions raise immediately.
  - Immutability: published/signed/superseded states block metadata mutation.
  - AGI-forward: ActorType supports human|service|agent|autonomous_system.
  - Deterministic: all transition logic is pure and testable without I/O.
"""

from __future__ import annotations

from enum import Enum
from typing import FrozenSet


# ---------------------------------------------------------------------------
# Schema version constants
# ---------------------------------------------------------------------------

REPORT_SCHEMA_VERSION = "1.0"
MANIFEST_SCHEMA_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Quality score thresholds (0.0 – 1.0 range)
# ---------------------------------------------------------------------------

QUALITY_EXCELLENT_THRESHOLD: float = 0.90
QUALITY_GOOD_THRESHOLD: float = 0.75
QUALITY_ACCEPTABLE_THRESHOLD: float = 0.60
QUALITY_POOR_THRESHOLD: float = 0.40
# Below QUALITY_POOR_THRESHOLD → INCOMPLETE


# ---------------------------------------------------------------------------
# Report Lifecycle
# ---------------------------------------------------------------------------


class ReportLifecycleState(str, Enum):
    """Nine-state enterprise report lifecycle.

    DRAFT:       Created but generation not started.
    GENERATING:  Report generation pipeline is running.
    GENERATED:   Generation complete; awaiting review / signing.
    SIGNING:     In the signing pipeline.
    SIGNED:      Cryptographically signed; awaiting publication approval.
    PUBLISHED:   Officially published and accessible to consumers.
    SUPERSEDED:  Replaced by a newer report; preserved for audit lineage.
    ARCHIVED:    Long-term preservation; excluded from active distribution.
    FAILED:      Generation or signing pipeline failed unrecoverably.

    Terminal states: SUPERSEDED, ARCHIVED, FAILED (with exceptions noted below).
    SUPERSEDED allows → ARCHIVED for housekeeping.
    """

    DRAFT = "DRAFT"
    GENERATING = "GENERATING"
    GENERATED = "GENERATED"
    SIGNING = "SIGNING"
    SIGNED = "SIGNED"
    PUBLISHED = "PUBLISHED"
    SUPERSEDED = "SUPERSEDED"
    ARCHIVED = "ARCHIVED"
    FAILED = "FAILED"


VALID_LIFECYCLE_TRANSITIONS: dict[
    ReportLifecycleState, FrozenSet[ReportLifecycleState]
] = {
    ReportLifecycleState.DRAFT: frozenset(
        {
            ReportLifecycleState.GENERATING,
            ReportLifecycleState.FAILED,
        }
    ),
    ReportLifecycleState.GENERATING: frozenset(
        {
            ReportLifecycleState.GENERATED,
            ReportLifecycleState.FAILED,
        }
    ),
    ReportLifecycleState.GENERATED: frozenset(
        {
            ReportLifecycleState.SIGNING,
            ReportLifecycleState.PUBLISHED,  # skip signing for non-regulated types
            ReportLifecycleState.FAILED,
            ReportLifecycleState.ARCHIVED,
        }
    ),
    ReportLifecycleState.SIGNING: frozenset(
        {
            ReportLifecycleState.SIGNED,
            ReportLifecycleState.FAILED,
        }
    ),
    ReportLifecycleState.SIGNED: frozenset(
        {
            ReportLifecycleState.PUBLISHED,
            ReportLifecycleState.ARCHIVED,
        }
    ),
    ReportLifecycleState.PUBLISHED: frozenset(
        {
            ReportLifecycleState.SUPERSEDED,
            ReportLifecycleState.ARCHIVED,
        }
    ),
    ReportLifecycleState.SUPERSEDED: frozenset(
        {
            ReportLifecycleState.ARCHIVED,
        }
    ),
    ReportLifecycleState.ARCHIVED: frozenset(),  # terminal
    ReportLifecycleState.FAILED: frozenset(
        {
            ReportLifecycleState.DRAFT,  # allow retry from failed
        }
    ),
}

# States from which no meaningful forward transition is expected
TERMINAL_LIFECYCLE_STATES: FrozenSet[ReportLifecycleState] = frozenset(
    {
        ReportLifecycleState.ARCHIVED,
        ReportLifecycleState.SUPERSEDED,
    }
)

# States that block mutation of report metadata / content
IMMUTABLE_LIFECYCLE_STATES: FrozenSet[ReportLifecycleState] = frozenset(
    {
        ReportLifecycleState.SIGNED,
        ReportLifecycleState.PUBLISHED,
        ReportLifecycleState.SUPERSEDED,
        ReportLifecycleState.ARCHIVED,
    }
)


def validate_lifecycle_transition(
    from_state: ReportLifecycleState,
    to_state: ReportLifecycleState,
) -> None:
    """Raise ValueError if the lifecycle transition is not permitted."""
    allowed = VALID_LIFECYCLE_TRANSITIONS.get(from_state, frozenset())
    if to_state not in allowed:
        allowed_str = sorted(s.value for s in allowed) or ["none (terminal)"]
        raise ValueError(
            f"Invalid lifecycle transition: {from_state.value!r} → {to_state.value!r}. "
            f"Allowed: {allowed_str}"
        )


# ---------------------------------------------------------------------------
# Report Type
# ---------------------------------------------------------------------------


class ReportType(str, Enum):
    """Classification of the report audience and regulatory context."""

    EXECUTIVE = "EXECUTIVE"
    TECHNICAL = "TECHNICAL"
    BOARD = "BOARD"
    REGULATORY_HEALTHCARE = "REGULATORY_HEALTHCARE"
    REGULATORY_FINANCE = "REGULATORY_FINANCE"
    REGULATORY_LEGAL = "REGULATORY_LEGAL"
    REGULATORY_GOVERNMENT = "REGULATORY_GOVERNMENT"
    REGULATORY_MANUFACTURING = "REGULATORY_MANUFACTURING"


# ---------------------------------------------------------------------------
# Report Format
# ---------------------------------------------------------------------------


class ReportFormat(str, Enum):
    """Output formats supported by the report generation pipeline."""

    PDF = "PDF"
    HTML = "HTML"
    JSON = "JSON"


# ---------------------------------------------------------------------------
# Report Section Type
# ---------------------------------------------------------------------------


class ReportSectionType(str, Enum):
    """Canonical section identifiers within a generated report."""

    EXECUTIVE_SUMMARY = "EXECUTIVE_SUMMARY"
    ASSESSMENT_OVERVIEW = "ASSESSMENT_OVERVIEW"
    ENVIRONMENT_SUMMARY = "ENVIRONMENT_SUMMARY"
    FINDINGS = "FINDINGS"
    EVIDENCE_APPENDIX = "EVIDENCE_APPENDIX"
    CONTROL_APPENDIX = "CONTROL_APPENDIX"
    REMEDIATION_APPENDIX = "REMEDIATION_APPENDIX"
    VERIFICATION_APPENDIX = "VERIFICATION_APPENDIX"
    TRUST_APPENDIX = "TRUST_APPENDIX"
    TRANSPARENCY_APPENDIX = "TRANSPARENCY_APPENDIX"
    MANIFEST = "MANIFEST"


# ---------------------------------------------------------------------------
# Export Bundle State
# ---------------------------------------------------------------------------


class ExportBundleState(str, Enum):
    """Lifecycle of a report export bundle."""

    PENDING = "PENDING"
    BUILDING = "BUILDING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


# ---------------------------------------------------------------------------
# Finding Severity
# ---------------------------------------------------------------------------


class FindingSeverity(str, Enum):
    """Standard severity classification for findings in a report."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


# ---------------------------------------------------------------------------
# Report Quality Grade
# ---------------------------------------------------------------------------


class ReportQualityGrade(str, Enum):
    """Human-readable quality grade derived from composite quality score."""

    EXCELLENT = "EXCELLENT"
    GOOD = "GOOD"
    ACCEPTABLE = "ACCEPTABLE"
    POOR = "POOR"
    INCOMPLETE = "INCOMPLETE"


# ---------------------------------------------------------------------------
# Actor Type
# ---------------------------------------------------------------------------


class ActorType(str, Enum):
    """Actor type classification — supports autonomous systems."""

    HUMAN = "human"
    SERVICE = "service"
    AGENT = "agent"
    AUTONOMOUS_SYSTEM = "autonomous_system"
