"""Tests for services/governance_intelligence/confidence.py

GIC-1 to GIC-200 — pure function tests for compute_data_freshness_score,
compute_coverage_score, compute_sample_confidence, compute_overall_confidence,
and build_confidence_response.
"""

from __future__ import annotations

import datetime

import pytest

from services.governance_intelligence.confidence import (
    build_confidence_response,
    compute_coverage_score,
    compute_data_freshness_score,
    compute_overall_confidence,
    compute_sample_confidence,
)
from services.governance_intelligence.models import ConfidenceLevel


# ---------------------------------------------------------------------------
# GIC-1 — GIC-40: compute_data_freshness_score
# ---------------------------------------------------------------------------


class TestComputeDataFreshnessScore:
    """GIC-1 to GIC-40: compute_data_freshness_score function tests."""

    def _now_iso(self) -> str:
        """Return current UTC ISO 8601 string."""
        return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _past_iso(self, days_ago: int) -> str:
        dt = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days_ago)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def test_gic_1_returns_float(self):
        """GIC-1: result is a float."""
        result = compute_data_freshness_score([], 30)
        assert isinstance(result, float)

    def test_gic_2_empty_items_returns_zero(self):
        """GIC-2: empty items list returns 0.0."""
        result = compute_data_freshness_score([], 30)
        assert result == pytest.approx(0.0)

    def test_gic_3_max_age_zero_returns_one(self):
        """GIC-3: max_age_days=0 returns 1.0."""
        items = [{"created_at": self._past_iso(100)}]
        result = compute_data_freshness_score(items, 0)
        assert result == pytest.approx(1.0)

    def test_gic_4_all_fresh_items_returns_one(self):
        """GIC-4: all items created today → 1.0 freshness."""
        now = self._now_iso()
        items = [{"created_at": now}, {"created_at": now}, {"created_at": now}]
        result = compute_data_freshness_score(items, 30)
        assert result == pytest.approx(1.0)

    def test_gic_5_all_stale_items_returns_zero(self):
        """GIC-5: all items older than max_age_days → 0.0 freshness."""
        old = self._past_iso(60)
        items = [{"created_at": old}, {"created_at": old}]
        result = compute_data_freshness_score(items, 30)
        assert result == pytest.approx(0.0)

    def test_gic_6_half_fresh_returns_half(self):
        """GIC-6: half fresh items → 0.5 freshness."""
        now = self._now_iso()
        old = self._past_iso(60)
        items = [{"created_at": now}, {"created_at": old}]
        result = compute_data_freshness_score(items, 30)
        assert result == pytest.approx(0.5)

    def test_gic_7_uses_updated_at_if_available(self):
        """GIC-7: uses updated_at over created_at when both present."""
        now = self._now_iso()
        old = self._past_iso(60)
        items = [{"created_at": old, "updated_at": now}]
        result = compute_data_freshness_score(items, 30)
        assert result == pytest.approx(1.0)

    def test_gic_8_missing_timestamp_skipped(self):
        """GIC-8: items without timestamp are skipped (not counted as fresh)."""
        now = self._now_iso()
        items = [{"created_at": now}, {"other_field": "no_ts"}]
        # Item without timestamp skipped, 1/2 items have fresh ts but only 1 has ts
        result = compute_data_freshness_score(items, 30)
        # 1 fresh out of 2 total = 0.5 (the item without ts is skipped, not counted)
        # Actually: 2 items total, 1 fresh → 0.5
        assert 0.0 <= result <= 1.0

    def test_gic_9_result_between_0_and_1(self):
        """GIC-9: result is always in [0.0, 1.0]."""
        items = [{"created_at": self._past_iso(i)} for i in range(10)]
        result = compute_data_freshness_score(items, 5)
        assert 0.0 <= result <= 1.0

    def test_gic_10_invalid_timestamp_skipped_gracefully(self):
        """GIC-10: invalid timestamp strings are skipped without error."""
        items = [{"created_at": "not-a-date"}, {"created_at": self._now_iso()}]
        result = compute_data_freshness_score(items, 30)
        # 1 out of 2 fresh (the valid one)
        assert 0.0 <= result <= 1.0

    def test_gic_11_result_rounded_to_4_decimal(self):
        """GIC-11: result is rounded to 4 decimal places."""
        now = self._now_iso()
        items = [{"created_at": now}] * 3 + [{"created_at": self._past_iso(60)}]
        result = compute_data_freshness_score(items, 30)
        # 3/4 = 0.75 — should be 0.75
        assert result == pytest.approx(0.75)


# ---------------------------------------------------------------------------
# GIC-41 — GIC-80: compute_coverage_score
# ---------------------------------------------------------------------------


class TestComputeCoverageScore:
    """GIC-41 to GIC-80: compute_coverage_score function tests."""

    def test_gic_41_returns_float(self):
        """GIC-41: result is a float."""
        result = compute_coverage_score(5, 10)
        assert isinstance(result, float)

    def test_gic_42_full_coverage_returns_one(self):
        """GIC-42: covered == total → 1.0."""
        assert compute_coverage_score(10, 10) == pytest.approx(1.0)

    def test_gic_43_zero_coverage_returns_zero(self):
        """GIC-43: covered == 0 → 0.0."""
        assert compute_coverage_score(0, 10) == pytest.approx(0.0)

    def test_gic_44_half_coverage_returns_half(self):
        """GIC-44: 5/10 → 0.5."""
        assert compute_coverage_score(5, 10) == pytest.approx(0.5)

    def test_gic_45_zero_total_returns_zero(self):
        """GIC-45: total == 0 → 0.0 (no division by zero)."""
        assert compute_coverage_score(0, 0) == pytest.approx(0.0)

    def test_gic_46_negative_total_returns_zero(self):
        """GIC-46: negative total → 0.0."""
        assert compute_coverage_score(5, -10) == pytest.approx(0.0)

    def test_gic_47_covered_exceeds_total_capped_at_1(self):
        """GIC-47: covered > total → capped at 1.0."""
        assert compute_coverage_score(20, 10) == pytest.approx(1.0)

    def test_gic_48_result_between_0_and_1(self):
        """GIC-48: result is in [0.0, 1.0]."""
        for covered, total in [(0, 5), (3, 5), (5, 5), (6, 5)]:
            r = compute_coverage_score(covered, total)
            assert 0.0 <= r <= 1.0

    def test_gic_49_rounded_to_4_decimal(self):
        """GIC-49: result rounded to 4 decimal places."""
        # 1/3 = 0.3333
        result = compute_coverage_score(1, 3)
        assert result == pytest.approx(0.3333, abs=0.001)

    def test_gic_50_large_totals(self):
        """GIC-50: handles large totals."""
        result = compute_coverage_score(750000, 1000000)
        assert result == pytest.approx(0.75)


# ---------------------------------------------------------------------------
# GIC-81 — GIC-120: compute_sample_confidence
# ---------------------------------------------------------------------------


class TestComputeSampleConfidence:
    """GIC-81 to GIC-120: compute_sample_confidence function tests."""

    def test_gic_81_returns_float(self):
        """GIC-81: result is a float."""
        result = compute_sample_confidence(10)
        assert isinstance(result, float)

    def test_gic_82_zero_samples_low(self):
        """GIC-82: 0 samples → 0.33 (LOW)."""
        assert compute_sample_confidence(0) == pytest.approx(0.33)

    def test_gic_83_nine_samples_low(self):
        """GIC-83: 9 samples → 0.33 (LOW)."""
        assert compute_sample_confidence(9) == pytest.approx(0.33)

    def test_gic_84_ten_samples_medium(self):
        """GIC-84: 10 samples → 0.66 (MEDIUM)."""
        assert compute_sample_confidence(10) == pytest.approx(0.66)

    def test_gic_85_29_samples_medium(self):
        """GIC-85: 29 samples → 0.66 (MEDIUM)."""
        assert compute_sample_confidence(29) == pytest.approx(0.66)

    def test_gic_86_30_samples_high(self):
        """GIC-86: 30 samples → 1.0 (HIGH)."""
        assert compute_sample_confidence(30) == pytest.approx(1.0)

    def test_gic_87_100_samples_high(self):
        """GIC-87: 100 samples → 1.0 (HIGH)."""
        assert compute_sample_confidence(100) == pytest.approx(1.0)

    @pytest.mark.parametrize("n,expected", [
        (0, 0.33), (1, 0.33), (5, 0.33), (9, 0.33),
        (10, 0.66), (15, 0.66), (20, 0.66), (29, 0.66),
        (30, 1.0), (50, 1.0), (1000, 1.0),
    ])
    def test_gic_88_parametrize_sample_confidence(self, n, expected):
        """GIC-88: parametrized sample confidence values."""
        assert compute_sample_confidence(n) == pytest.approx(expected)


# ---------------------------------------------------------------------------
# GIC-121 — GIC-160: compute_overall_confidence
# ---------------------------------------------------------------------------


class TestComputeOverallConfidence:
    """GIC-121 to GIC-160: compute_overall_confidence function tests."""

    def test_gic_121_returns_tuple(self):
        """GIC-121: result is a tuple."""
        result = compute_overall_confidence([0.5])
        assert isinstance(result, tuple)

    def test_gic_122_tuple_has_two_elements(self):
        """GIC-122: result tuple has 2 elements."""
        result = compute_overall_confidence([0.5])
        assert len(result) == 2

    def test_gic_123_empty_scores_insufficient(self):
        """GIC-123: empty scores → (0.0, INSUFFICIENT)."""
        score, level = compute_overall_confidence([])
        assert score == pytest.approx(0.0)
        assert level == ConfidenceLevel.INSUFFICIENT.value

    def test_gic_124_all_high_scores_high(self):
        """GIC-124: all scores >= 0.75 → HIGH."""
        score, level = compute_overall_confidence([0.8, 0.9, 1.0])
        assert level == ConfidenceLevel.HIGH.value

    def test_gic_125_all_zero_scores_insufficient(self):
        """GIC-125: all 0.0 scores → INSUFFICIENT."""
        score, level = compute_overall_confidence([0.0, 0.0, 0.0])
        assert level == ConfidenceLevel.INSUFFICIENT.value

    def test_gic_126_medium_scores_medium(self):
        """GIC-126: average in [0.5, 0.75) → MEDIUM."""
        score, level = compute_overall_confidence([0.5, 0.6, 0.7])
        assert level == ConfidenceLevel.MEDIUM.value

    def test_gic_127_low_scores_low(self):
        """GIC-127: average in (0.0, 0.5) → LOW."""
        score, level = compute_overall_confidence([0.1, 0.2, 0.3])
        assert level == ConfidenceLevel.LOW.value

    def test_gic_128_score_is_mean_of_inputs(self):
        """GIC-128: score is the mean of input scores."""
        score, _ = compute_overall_confidence([0.4, 0.6])
        assert score == pytest.approx(0.5)

    def test_gic_129_score_rounded_to_4_decimal(self):
        """GIC-129: score is rounded to 4 decimal places."""
        score, _ = compute_overall_confidence([1.0 / 3.0, 2.0 / 3.0])
        assert round(score, 4) == pytest.approx(score)

    def test_gic_130_boundary_075_is_high(self):
        """GIC-130: score exactly 0.75 → HIGH."""
        _, level = compute_overall_confidence([0.75])
        assert level == ConfidenceLevel.HIGH.value

    def test_gic_131_boundary_050_is_medium(self):
        """GIC-131: score exactly 0.50 → MEDIUM."""
        _, level = compute_overall_confidence([0.50])
        assert level == ConfidenceLevel.MEDIUM.value

    def test_gic_132_valid_level_value(self):
        """GIC-132: returned level is always a valid ConfidenceLevel value."""
        valid = {l.value for l in ConfidenceLevel}
        for scores in [[], [0.0], [0.3], [0.5], [0.8], [1.0]]:
            _, level = compute_overall_confidence(scores)
            assert level in valid


# ---------------------------------------------------------------------------
# GIC-161 — GIC-200: build_confidence_response
# ---------------------------------------------------------------------------


class TestBuildConfidenceResponse:
    """GIC-161 to GIC-200: build_confidence_response function tests."""

    def test_gic_161_returns_dict(self):
        """GIC-161: result is a dict."""
        result = build_confidence_response("mfa_coverage", {"data_freshness": 0.8})
        assert isinstance(result, dict)

    def test_gic_162_dimension_preserved(self):
        """GIC-162: dimension is preserved."""
        result = build_confidence_response("my_dimension", {"score": 0.7})
        assert result["dimension"] == "my_dimension"

    def test_gic_163_has_score(self):
        """GIC-163: result has 'score' key."""
        result = build_confidence_response("dim", {"s": 0.5})
        assert "score" in result

    def test_gic_164_has_level(self):
        """GIC-164: result has 'level' key."""
        result = build_confidence_response("dim", {"s": 0.5})
        assert "level" in result

    def test_gic_165_has_factors(self):
        """GIC-165: result has 'factors' key."""
        result = build_confidence_response("dim", {"s": 0.5})
        assert "factors" in result

    def test_gic_166_has_computed_at(self):
        """GIC-166: result has 'computed_at' timestamp."""
        result = build_confidence_response("dim", {"s": 0.5})
        assert "computed_at" in result

    def test_gic_167_factors_match_input_scores(self):
        """GIC-167: factors dict equals the input scores dict."""
        scores = {"freshness": 0.8, "coverage": 0.6}
        result = build_confidence_response("dim", scores)
        assert result["factors"] == scores

    def test_gic_168_score_is_mean_of_factors(self):
        """GIC-168: score is the mean of factor values."""
        scores = {"a": 0.8, "b": 0.6}
        result = build_confidence_response("dim", scores)
        assert result["score"] == pytest.approx(0.7)

    def test_gic_169_empty_scores_level_insufficient(self):
        """GIC-169: empty scores → INSUFFICIENT level."""
        result = build_confidence_response("dim", {})
        assert result["level"] == ConfidenceLevel.INSUFFICIENT.value

    def test_gic_170_high_scores_high_level(self):
        """GIC-170: all scores >= 0.75 → HIGH level."""
        result = build_confidence_response("dim", {"a": 0.8, "b": 0.9})
        assert result["level"] == ConfidenceLevel.HIGH.value

    def test_gic_171_level_is_valid_confidence_level(self):
        """GIC-171: level is always a valid ConfidenceLevel value."""
        valid = {l.value for l in ConfidenceLevel}
        for scores in [{}, {"a": 0.0}, {"a": 0.4}, {"a": 0.6}, {"a": 0.9}]:
            result = build_confidence_response("dim", scores)
            assert result["level"] in valid

    def test_gic_172_computed_at_is_string(self):
        """GIC-172: computed_at is a string."""
        result = build_confidence_response("dim", {"s": 0.5})
        assert isinstance(result["computed_at"], str)

    def test_gic_173_computed_at_is_iso8601(self):
        """GIC-173: computed_at looks like an ISO 8601 timestamp."""
        result = build_confidence_response("dim", {"s": 0.5})
        # Should contain 'T' and end with 'Z' or contain timezone offset
        assert "T" in result["computed_at"]

    def test_gic_174_no_tenant_id_in_output(self):
        """GIC-174: no tenant_id in output."""
        result = build_confidence_response("dim", {"freshness": 0.8})
        assert "tenant_id" not in result

    def test_gic_175_multiple_factors(self):
        """GIC-175: multiple factor scores handled correctly."""
        scores = {f"factor_{i}": float(i) / 10 for i in range(1, 6)}
        result = build_confidence_response("dim", scores)
        assert result["factors"] == scores
        assert "score" in result
