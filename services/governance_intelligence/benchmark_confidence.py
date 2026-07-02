"""Benchmark Confidence Engine (PR 18.5A).

Pure functions only.  No DB I/O.
"""

from __future__ import annotations

import math
from typing import Any

from services.governance_intelligence.schemas import (
    GovernanceIntelligenceValidationError,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MINIMUM_SAMPLE_SIZE = 10
MINIMUM_COHORT_SIZE = 5

_Z95 = 1.96  # z-score for 95% confidence interval


# ---------------------------------------------------------------------------
# Confidence interval
# ---------------------------------------------------------------------------


def compute_confidence_interval(
    values: list[float], confidence_level: float = 0.95
) -> tuple[float, float]:
    """Compute a normal-approximation confidence interval.

    Returns (lower, upper).  Falls back to (mean, mean) for n < 2.
    """
    n = len(values)
    if n == 0:
        return (0.0, 0.0)
    mean = sum(values) / n
    if n < 2:
        return (mean, mean)
    variance = sum((x - mean) ** 2 for x in values) / (n - 1)
    std = math.sqrt(variance)
    # Select z based on confidence level
    if confidence_level >= 0.99:
        z = 2.576
    elif confidence_level >= 0.95:
        z = 1.96
    elif confidence_level >= 0.90:
        z = 1.645
    else:
        z = 1.28
    margin = z * std / math.sqrt(n)
    return (mean - margin, mean + margin)


# ---------------------------------------------------------------------------
# Benchmark confidence
# ---------------------------------------------------------------------------


def compute_benchmark_confidence(
    sample_size: int,
    cohort_size: int,
    data_recency_days: int,
    values: list[float],
) -> dict[str, Any]:
    """Compute benchmark confidence from sample and cohort metadata.

    Returns a result dict with confidence_grade, meets_threshold, etc.
    """
    # Freshness bucket
    if data_recency_days < 30:
        freshness = "FRESH"
    elif data_recency_days < 90:
        freshness = "STALE"
    else:
        freshness = "EXPIRED"

    # Insufficient conditions
    if sample_size < MINIMUM_SAMPLE_SIZE or cohort_size < MINIMUM_COHORT_SIZE:
        ci = compute_confidence_interval(values)
        return {
            "sample_size": sample_size,
            "cohort_size": cohort_size,
            "data_recency_days": data_recency_days,
            "confidence_interval": [round(ci[0], 6), round(ci[1], 6)],
            "confidence_grade": "INSUFFICIENT",
            "meets_threshold": False,
            "min_sample_threshold": MINIMUM_SAMPLE_SIZE,
            "benchmark_freshness": freshness,
        }

    ci = compute_confidence_interval(values)

    # Grade based on sample size, cohort size, and freshness
    if (
        sample_size >= MINIMUM_SAMPLE_SIZE * 5
        and cohort_size >= MINIMUM_COHORT_SIZE * 4
        and freshness == "FRESH"
    ):
        grade = "A"
    elif (
        sample_size >= MINIMUM_SAMPLE_SIZE * 2
        and cohort_size >= MINIMUM_COHORT_SIZE * 2
        and freshness in ("FRESH", "STALE")
    ):
        grade = "B"
    elif sample_size >= MINIMUM_SAMPLE_SIZE and cohort_size >= MINIMUM_COHORT_SIZE:
        grade = "C"
    else:
        grade = "INSUFFICIENT"

    meets = grade in ("A", "B")

    return {
        "sample_size": sample_size,
        "cohort_size": cohort_size,
        "data_recency_days": data_recency_days,
        "confidence_interval": [round(ci[0], 6), round(ci[1], 6)],
        "confidence_grade": grade,
        "meets_threshold": meets,
        "min_sample_threshold": MINIMUM_SAMPLE_SIZE,
        "benchmark_freshness": freshness,
    }


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_benchmark_confidence(result: dict[str, Any]) -> None:
    """Raise GovernanceIntelligenceValidationError if meets_threshold is False."""
    if not result.get("meets_threshold", False):
        grade = result.get("confidence_grade", "UNKNOWN")
        raise GovernanceIntelligenceValidationError(
            f"Benchmark confidence does not meet threshold (grade={grade}). "
            "Increase sample size or cohort size."
        )
