"""Readiness scoring engine I/O contracts.

Pure Python frozen dataclasses — export-safe, serialization-safe.
No I/O. No SQLAlchemy. No scoring logic.

All output types are frozen. Mutating a ScoreOutput after construction
is not possible at the attribute level; callers must not mutate the
contained dicts (domain_scores, control_scores) at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional

from services.readiness.models import (
    Assessment,
    AssessmentOutcome,
    Control,
    Domain,
    EvidenceReference,
    Framework,
    MaturityTier,
    ScoringContract,
    AssessmentResult,
)


# ---------------------------------------------------------------------------
# Output enumerations
# ---------------------------------------------------------------------------


class RiskLevel(str, Enum):
    """Deterministic risk classification output.

    Derived from overall score, completion state, and critical/required
    control failures. Incomplete assessments are never classified as MINIMAL
    or LOW unless all applicable controls are fully evaluated.
    """

    UNKNOWN = "unknown"  # no controls defined or all N/A
    MINIMAL = "minimal"  # score >= 90, complete
    LOW = "low"  # score >= 75, complete
    MODERATE = "moderate"  # score >= 50
    HIGH = "high"  # score >= 25, or incomplete with fails
    CRITICAL = "critical"  # score < 25, or critical controls failed


class RemediationPriority(str, Enum):
    """Structured remediation urgency classification.

    Derived from risk classification, critical/required control failures,
    and maturity blockers. Not a narrative recommendation.
    """

    CRITICAL_IMMEDIATE = (
        "critical_immediate"  # risk CRITICAL or critical controls failed
    )
    HIGH_PRIORITY = "high_priority"  # risk HIGH or required controls missing
    MEDIUM_PRIORITY = "medium_priority"  # risk MODERATE
    LOW_PRIORITY = "low_priority"  # risk LOW
    NOT_REQUIRED = "not_required"  # risk MINIMAL and complete


class CompletionState(str, Enum):
    """Assessment completion state derived from evaluated vs. applicable controls."""

    COMPLETE = "complete"  # all applicable controls evaluated
    PARTIAL = "partial"  # >= 50% evaluated, some missing
    INCOMPLETE = "incomplete"  # < 50% evaluated
    EMPTY = "empty"  # no controls evaluated at all


# ---------------------------------------------------------------------------
# Component-level output types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ControlScore:
    """Per-control scoring output component."""

    control_id: str
    control_identifier: str
    domain_id: str
    outcome: AssessmentOutcome
    raw_score: float  # 0.0–100.0; NOT_APPLICABLE yields 0.0 but excluded
    weight: float  # validated weight >= 0.0
    is_evaluated: bool  # True if an AssessmentResult exists for this control
    is_applicable: bool  # False only when outcome == NOT_APPLICABLE
    evidence_count: int  # number of evidence references linked to this control


@dataclass(frozen=True)
class DomainScore:
    """Per-domain scoring output component — weighted aggregate of control scores."""

    domain_id: str
    domain_name: str
    raw_score: float  # weighted average of applicable control scores, 0.0–100.0
    normalized_score: float  # raw_score / 100.0
    weight: float  # domain weight in overall aggregation
    completion_percentage: float  # % of applicable controls that have been evaluated
    missing_control_count: int  # controls with no result
    incomplete_control_count: int  # PARTIALLY_COMPLIANT or NOT_EVALUATED results
    failed_control_count: int  # NON_COMPLIANT results
    risk_classification: RiskLevel
    threshold_failed: bool  # True if domain score is below a contract minimum


@dataclass(frozen=True)
class ThresholdFailure:
    """A named threshold that was not met."""

    threshold_type: (
        str  # "overall_pass" | "domain_minimum" | "maturity_gate" | "required_control"
    )
    threshold_name: str  # human-readable name or control_id
    required_value: float
    actual_value: float
    message: str


@dataclass(frozen=True)
class RemediationFactor:
    """A contributing factor to the remediation priority classification.

    Structured and explainable — no narrative generation.
    """

    factor_type: str  # "failed_critical_control" | "missing_required_control" |
    #                     "low_domain_score" | "maturity_blocked" | "incomplete_assessment"
    description: str
    severity: str  # "critical" | "high" | "medium" | "low"


# ---------------------------------------------------------------------------
# Engine I/O contracts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScoringInput:
    """All data required to score an assessment.

    The caller is responsible for loading all fields from the store before
    constructing this object. The engine performs no I/O.

    Tenant isolation: assessment.tenant_id must match the tenant that loaded
    the results and evidence_refs. The engine validates this internally.
    """

    assessment: Assessment
    framework: Framework
    controls: tuple[Control, ...]
    domains: tuple[Domain, ...]
    maturity_tiers: tuple[MaturityTier, ...]
    results: tuple[AssessmentResult, ...]
    evidence_refs: tuple[EvidenceReference, ...]
    scoring_contract: Optional[ScoringContract] = None


@dataclass(frozen=True)
class ScoreOutput:
    """Deterministic scoring result. Frozen after construction.

    Produced by ReadinessScoreEngine.score(). Never mutated.
    All fields are export-safe — no secrets, credentials, raw evidence,
    provider payloads, storage paths, or internal topology.

    domain_scores: keyed by domain_id
    control_scores: keyed by control_id
    """

    assessment_id: str
    tenant_id: str
    framework_id: str
    framework_version_tag: str
    overall_score: float  # 0.0–100.0, 4 decimal places
    normalized_score: float  # 0.0–1.0, 6 decimal places
    domain_scores: dict[str, DomainScore]  # domain_id → DomainScore
    control_scores: dict[str, ControlScore]  # control_id → ControlScore
    maturity_tier: Optional[str]  # tier_identifier of highest achieved tier
    maturity_tier_id: Optional[str]  # tier_id of highest achieved tier
    risk_classification: RiskLevel
    remediation_priority: RemediationPriority
    remediation_factors: tuple[RemediationFactor, ...]
    missing_controls: tuple[str, ...]  # control_ids with no result
    incomplete_controls: tuple[str, ...]  # control_ids with partial result
    failed_controls: tuple[str, ...]  # control_ids non-compliant
    not_applicable_controls: tuple[str, ...]  # control_ids excluded from scoring
    threshold_failures: tuple[ThresholdFailure, ...]
    scoring_warnings: tuple[str, ...]
    completion_state: CompletionState
    completion_percentage: float  # 0.0–100.0
    is_complete: bool  # all applicable controls evaluated
    computed_at: datetime
    score_version: str  # engine version, e.g. "1.0.0"
    scoring_contract_id: Optional[str] = None
    scoring_contract_version: Optional[str] = None
