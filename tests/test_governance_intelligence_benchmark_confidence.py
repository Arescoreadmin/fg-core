"""Tests for PR 18.5A — Benchmark Confidence Engine.

Pure-function tests. No DB required.
"""

from __future__ import annotations

import pytest

from services.governance_intelligence.benchmark_confidence import (
    MINIMUM_COHORT_SIZE,
    MINIMUM_SAMPLE_SIZE,
    compute_benchmark_confidence,
    compute_confidence_interval,
    validate_benchmark_confidence,
)
from services.governance_intelligence.schemas import (
    GovernanceIntelligenceValidationError,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class TestConstants:
    def test_minimum_sample_size_is_10(self):
        assert MINIMUM_SAMPLE_SIZE == 10

    def test_minimum_cohort_size_is_5(self):
        assert MINIMUM_COHORT_SIZE == 5


# ---------------------------------------------------------------------------
# compute_confidence_interval
# ---------------------------------------------------------------------------


class TestComputeConfidenceInterval:
    def test_empty_list_returns_zeros(self):
        lo, hi = compute_confidence_interval([])
        assert lo == 0.0
        assert hi == 0.0

    def test_single_value_returns_mean_mean(self):
        lo, hi = compute_confidence_interval([0.5])
        assert lo == hi == 0.5

    def test_returns_tuple_of_two(self):
        result = compute_confidence_interval([0.5, 0.6, 0.7])
        assert len(result) == 2

    def test_lower_le_upper(self):
        lo, hi = compute_confidence_interval([0.3, 0.5, 0.7, 0.9])
        assert lo <= hi

    def test_interval_contains_mean(self):
        values = [0.4, 0.5, 0.6]
        lo, hi = compute_confidence_interval(values)
        mean = sum(values) / len(values)
        assert lo <= mean <= hi

    def test_larger_spread_wider_interval(self):
        narrow = compute_confidence_interval([0.5, 0.5, 0.5, 0.5, 0.5])
        wide = compute_confidence_interval([0.0, 0.25, 0.5, 0.75, 1.0])
        narrow_width = narrow[1] - narrow[0]
        wide_width = wide[1] - wide[0]
        assert wide_width > narrow_width

    def test_99_confidence_wider_than_95(self):
        values = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
        lo95, hi95 = compute_confidence_interval(values, 0.95)
        lo99, hi99 = compute_confidence_interval(values, 0.99)
        assert (hi99 - lo99) >= (hi95 - lo95)

    def test_90_confidence_narrower_than_95(self):
        values = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
        lo90, hi90 = compute_confidence_interval(values, 0.90)
        lo95, hi95 = compute_confidence_interval(values, 0.95)
        assert (hi95 - lo95) >= (hi90 - lo90)

    def test_uniform_values_zero_interval(self):
        values = [0.5] * 10
        lo, hi = compute_confidence_interval(values)
        assert abs(lo - 0.5) < 1e-9
        assert abs(hi - 0.5) < 1e-9


# ---------------------------------------------------------------------------
# Insufficient conditions
# ---------------------------------------------------------------------------


class TestInsufficientConditions:
    def test_sample_below_10_is_insufficient(self):
        result = compute_benchmark_confidence(9, 10, 15, [0.5] * 9)
        assert result["confidence_grade"] == "INSUFFICIENT"
        assert result["meets_threshold"] is False

    def test_sample_0_is_insufficient(self):
        result = compute_benchmark_confidence(0, 10, 15, [])
        assert result["confidence_grade"] == "INSUFFICIENT"

    def test_cohort_below_5_is_insufficient(self):
        result = compute_benchmark_confidence(15, 4, 15, [0.5] * 15)
        assert result["confidence_grade"] == "INSUFFICIENT"

    def test_cohort_0_is_insufficient(self):
        result = compute_benchmark_confidence(15, 0, 15, [0.5] * 15)
        assert result["confidence_grade"] == "INSUFFICIENT"

    def test_insufficient_has_meets_threshold_false(self):
        result = compute_benchmark_confidence(1, 1, 15, [0.5])
        assert result["meets_threshold"] is False

    def test_insufficient_still_has_confidence_interval(self):
        result = compute_benchmark_confidence(5, 3, 15, [0.4, 0.5, 0.6, 0.7, 0.8])
        assert "confidence_interval" in result
        assert len(result["confidence_interval"]) == 2


# ---------------------------------------------------------------------------
# Freshness
# ---------------------------------------------------------------------------


class TestFreshness:
    def _grade(self, recency: int) -> str:
        r = compute_benchmark_confidence(50, 20, recency, [0.5] * 50)
        return r["benchmark_freshness"]

    def test_recency_0_is_fresh(self):
        assert self._grade(0) == "FRESH"

    def test_recency_29_is_fresh(self):
        assert self._grade(29) == "FRESH"

    def test_recency_30_is_stale(self):
        assert self._grade(30) == "STALE"

    def test_recency_89_is_stale(self):
        assert self._grade(89) == "STALE"

    def test_recency_90_is_expired(self):
        assert self._grade(90) == "EXPIRED"

    def test_recency_365_is_expired(self):
        assert self._grade(365) == "EXPIRED"


# ---------------------------------------------------------------------------
# Grade computation
# ---------------------------------------------------------------------------


class TestGradeComputation:
    def test_large_sample_fresh_is_grade_a(self):
        result = compute_benchmark_confidence(
            MINIMUM_SAMPLE_SIZE * 5,
            MINIMUM_COHORT_SIZE * 4,
            15,  # FRESH
            [0.5] * (MINIMUM_SAMPLE_SIZE * 5),
        )
        assert result["confidence_grade"] == "A"
        assert result["meets_threshold"] is True

    def test_moderate_sample_fresh_is_grade_b(self):
        result = compute_benchmark_confidence(
            MINIMUM_SAMPLE_SIZE * 2,
            MINIMUM_COHORT_SIZE * 2,
            20,  # FRESH
            [0.5] * (MINIMUM_SAMPLE_SIZE * 2),
        )
        assert result["confidence_grade"] == "B"
        assert result["meets_threshold"] is True

    def test_minimum_thresholds_is_grade_c(self):
        result = compute_benchmark_confidence(
            MINIMUM_SAMPLE_SIZE,
            MINIMUM_COHORT_SIZE,
            15,
            [0.5] * MINIMUM_SAMPLE_SIZE,
        )
        assert result["confidence_grade"] == "C"
        assert result["meets_threshold"] is False

    def test_result_has_required_keys(self):
        result = compute_benchmark_confidence(10, 5, 15, [0.5] * 10)
        required = {
            "sample_size",
            "cohort_size",
            "data_recency_days",
            "confidence_interval",
            "confidence_grade",
            "meets_threshold",
            "min_sample_threshold",
            "benchmark_freshness",
        }
        for k in required:
            assert k in result, f"Missing key: {k}"

    def test_min_sample_threshold_reported(self):
        result = compute_benchmark_confidence(10, 5, 15, [0.5] * 10)
        assert result["min_sample_threshold"] == MINIMUM_SAMPLE_SIZE

    def test_meets_threshold_false_for_grade_c(self):
        result = compute_benchmark_confidence(
            MINIMUM_SAMPLE_SIZE, MINIMUM_COHORT_SIZE, 15, [0.5] * MINIMUM_SAMPLE_SIZE
        )
        assert result["meets_threshold"] is False

    def test_large_stale_is_grade_b(self):
        result = compute_benchmark_confidence(
            MINIMUM_SAMPLE_SIZE * 2,
            MINIMUM_COHORT_SIZE * 2,
            60,  # STALE
            [0.5] * (MINIMUM_SAMPLE_SIZE * 2),
        )
        assert result["confidence_grade"] == "B"


# ---------------------------------------------------------------------------
# validate_benchmark_confidence
# ---------------------------------------------------------------------------


class TestValidateBenchmarkConfidence:
    def test_meets_threshold_true_does_not_raise(self):
        result = compute_benchmark_confidence(
            MINIMUM_SAMPLE_SIZE * 5, MINIMUM_COHORT_SIZE * 4, 15, [0.5] * 50
        )
        validate_benchmark_confidence(result)

    def test_meets_threshold_false_raises(self):
        result = compute_benchmark_confidence(5, 3, 15, [0.5] * 5)
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_benchmark_confidence(result)

    def test_error_message_contains_grade(self):
        result = compute_benchmark_confidence(5, 3, 15, [0.5] * 5)
        with pytest.raises(GovernanceIntelligenceValidationError, match="INSUFFICIENT"):
            validate_benchmark_confidence(result)
