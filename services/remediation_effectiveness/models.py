"""services/remediation_effectiveness/models.py

Pure Python domain models, classifiers, and computation logic.
No I/O. No SQLAlchemy.

PR 17.5 — Remediation Effectiveness Analytics Authority
"""

from __future__ import annotations

from enum import Enum

REMEDIATION_EFFECTIVENESS_VERSION = "1.0"

# Outcome classification thresholds
OUTCOME_SUCCESS_THRESHOLD = 10.0  # delta >= 10 → SUCCESS
OUTCOME_PARTIAL_THRESHOLD = 3.0  # delta >= 3 → PARTIAL_SUCCESS
OUTCOME_NO_CHANGE_FLOOR = -3.0  # delta >= -3 → NO_CHANGE
OUTCOME_REGRESSION_FLOOR = -10.0  # delta >= -10 → REGRESSION (else FAILURE)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class RemediationStatus(str, Enum):
    PENDING = "PENDING"
    MEASURING = "MEASURING"
    COMPLETE = "COMPLETE"
    INVALIDATED = "INVALIDATED"


class OutcomeClassification(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    NO_CHANGE = "NO_CHANGE"
    REGRESSION = "REGRESSION"
    FAILURE = "FAILURE"


class RemediationEffectivenessLevel(str, Enum):
    HIGHLY_EFFECTIVE = "HIGHLY_EFFECTIVE"
    EFFECTIVE = "EFFECTIVE"
    ADEQUATE = "ADEQUATE"
    WEAK = "WEAK"
    INEFFECTIVE = "INEFFECTIVE"


class PersistenceClassification(str, Enum):
    SUSTAINED = "SUSTAINED"
    HOLDING = "HOLDING"
    DECLINING = "DECLINING"
    LOST = "LOST"
    NOT_YET_MEASURABLE = "NOT_YET_MEASURABLE"


class PatternType(str, Enum):
    REPEATED_FAILURE = "REPEATED_FAILURE"
    RECURRING_DEGRADATION = "RECURRING_DEGRADATION"
    NO_IMPROVEMENT = "NO_IMPROVEMENT"
    ROLLBACK_PATTERN = "ROLLBACK_PATTERN"
    CONSISTENT_IMPROVEMENT = "CONSISTENT_IMPROVEMENT"
    RAPID_REGRESSION = "RAPID_REGRESSION"


class PatternSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RemediationCategory(str, Enum):
    VERIFICATION = "VERIFICATION"
    FRESHNESS = "FRESHNESS"
    COVERAGE = "COVERAGE"
    TREND = "TREND"
    FORECAST = "FORECAST"
    EVIDENCE = "EVIDENCE"
    EXCEPTION = "EXCEPTION"
    GOVERNANCE = "GOVERNANCE"
    OTHER = "OTHER"


class ROIClassification(str, Enum):
    EXCELLENT = "EXCELLENT"
    GOOD = "GOOD"
    ACCEPTABLE = "ACCEPTABLE"
    POOR = "POOR"
    NEGATIVE = "NEGATIVE"


# ---------------------------------------------------------------------------
# Pure functions
# ---------------------------------------------------------------------------


def classify_outcome(score_delta: float) -> OutcomeClassification:
    """Classify the outcome of a remediation based on score delta."""
    if score_delta >= OUTCOME_SUCCESS_THRESHOLD:
        return OutcomeClassification.SUCCESS
    if score_delta >= OUTCOME_PARTIAL_THRESHOLD:
        return OutcomeClassification.PARTIAL_SUCCESS
    if score_delta >= OUTCOME_NO_CHANGE_FLOOR:
        return OutcomeClassification.NO_CHANGE
    if score_delta >= OUTCOME_REGRESSION_FLOOR:
        return OutcomeClassification.REGRESSION
    return OutcomeClassification.FAILURE


def compute_remediation_effectiveness_score(
    before_score: float, after_score: float
) -> float:
    """Compute remediation effectiveness score in 0-100 range.

    Formula: clamp(50 + (delta * 2.5), 0, 100)
    where delta = after - before.
    So +20 delta → 100, 0 delta → 50, -20 delta → 0.
    """
    delta = after_score - before_score
    raw = 50.0 + (delta * 2.5)
    return max(0.0, min(100.0, raw))


def classify_effectiveness_level(res: float) -> RemediationEffectivenessLevel:
    """Classify remediation effectiveness score into a level."""
    if res >= 75.0:
        return RemediationEffectivenessLevel.HIGHLY_EFFECTIVE
    if res >= 60.0:
        return RemediationEffectivenessLevel.EFFECTIVE
    if res >= 45.0:
        return RemediationEffectivenessLevel.ADEQUATE
    if res >= 30.0:
        return RemediationEffectivenessLevel.WEAK
    return RemediationEffectivenessLevel.INEFFECTIVE


def compute_roi_score(before_score: float, score_delta: float) -> float:
    """Compute ROI score in 0-100 range.

    improvement headroom = 100 - before_score
    roi = delta / (headroom + 1) * 100
    clamp to -100..100, normalize to 0..100 via (roi + 100) / 2
    """
    headroom = 100.0 - before_score
    roi = score_delta / (headroom + 1.0) * 100.0
    roi_clamped = max(-100.0, min(100.0, roi))
    return (roi_clamped + 100.0) / 2.0


def classify_roi(roi_score: float) -> ROIClassification:
    """Classify ROI score into a classification."""
    if roi_score >= 70.0:
        return ROIClassification.EXCELLENT
    if roi_score >= 55.0:
        return ROIClassification.GOOD
    if roi_score >= 40.0:
        return ROIClassification.ACCEPTABLE
    if roi_score >= 30.0:
        return ROIClassification.POOR
    return ROIClassification.NEGATIVE


def classify_persistence(
    close_score: float, current_score: float
) -> PersistenceClassification:
    """Classify persistence of remediation gains.

    delta = current - close_score
    >= -2 → SUSTAINED; >= -5 → HOLDING; >= -10 → DECLINING; else LOST
    """
    delta = current_score - close_score
    if delta >= -2.0:
        return PersistenceClassification.SUSTAINED
    if delta >= -5.0:
        return PersistenceClassification.HOLDING
    if delta >= -10.0:
        return PersistenceClassification.DECLINING
    return PersistenceClassification.LOST


def classify_category_from_string(category_str: str | None) -> RemediationCategory:
    """Map a string to RemediationCategory enum, defaulting to OTHER."""
    if category_str is None:
        return RemediationCategory.OTHER
    try:
        return RemediationCategory(category_str.upper())
    except ValueError:
        return RemediationCategory.OTHER
