"""services/report_authority/statistics.py — Pure report quality and statistics functions.

All functions operate on plain Python values (no database access, no I/O).
The engine calls these and persists results via the repository.

Quality scoring uses a weighted composite of five sub-scores:
  evidence_coverage     — weight 0.30
  verification_coverage — weight 0.25
  freshness             — weight 0.20
  confidence            — weight 0.15
  completeness          — weight 0.10

All sub-scores and the composite score are floats in [0.0, 1.0].
"""

from __future__ import annotations

from services.report_authority.models import (
    QUALITY_ACCEPTABLE_THRESHOLD,
    QUALITY_EXCELLENT_THRESHOLD,
    QUALITY_GOOD_THRESHOLD,
    QUALITY_POOR_THRESHOLD,
    ReportQualityGrade,
)

# Weights must sum to 1.0
_WEIGHT_EVIDENCE_COVERAGE: float = 0.30
_WEIGHT_VERIFICATION_COVERAGE: float = 0.25
_WEIGHT_FRESHNESS: float = 0.20
_WEIGHT_CONFIDENCE: float = 0.15
_WEIGHT_COMPLETENESS: float = 0.10


def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    """Clamp *value* to [*lo*, *hi*]."""
    return max(lo, min(hi, value))


def compute_quality_score(
    evidence_coverage: float,
    verification_coverage: float,
    freshness_score: float,
    confidence_score: float,
    completeness_score: float,
) -> tuple[float, str]:
    """Compute a composite quality score and derive the quality grade.

    All inputs must be in [0.0, 1.0]; out-of-range values are clamped silently
    to protect against upstream rounding errors.

    Returns:
        (score, grade) where score is in [0.0, 1.0] and grade is one of
        the ReportQualityGrade enum values as a string.
    """
    ec = _clamp(evidence_coverage)
    vc = _clamp(verification_coverage)
    fs = _clamp(freshness_score)
    cs = _clamp(confidence_score)
    cms = _clamp(completeness_score)

    score = (
        ec * _WEIGHT_EVIDENCE_COVERAGE
        + vc * _WEIGHT_VERIFICATION_COVERAGE
        + fs * _WEIGHT_FRESHNESS
        + cs * _WEIGHT_CONFIDENCE
        + cms * _WEIGHT_COMPLETENESS
    )
    score = _clamp(round(score, 6))

    if score >= QUALITY_EXCELLENT_THRESHOLD:
        grade = ReportQualityGrade.EXCELLENT.value
    elif score >= QUALITY_GOOD_THRESHOLD:
        grade = ReportQualityGrade.GOOD.value
    elif score >= QUALITY_ACCEPTABLE_THRESHOLD:
        grade = ReportQualityGrade.ACCEPTABLE.value
    elif score >= QUALITY_POOR_THRESHOLD:
        grade = ReportQualityGrade.POOR.value
    else:
        grade = ReportQualityGrade.INCOMPLETE.value

    return score, grade


def aggregate_by_field(
    records: list[dict[str, object]],
    field: str,
) -> dict[str, int]:
    """Return a count map for *field* across *records*.

    Records where the field is missing or None are grouped under the key
    '__unknown__'. This is used to build the by_type, by_lifecycle_state, and
    by_quality_grade breakdowns in ReportStatisticsResponse.
    """
    result: dict[str, int] = {}
    for record in records:
        value = record.get(field)
        key = str(value) if value is not None else "__unknown__"
        result[key] = result.get(key, 0) + 1
    return result
