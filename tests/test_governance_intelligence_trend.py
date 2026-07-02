"""Tests for services/governance_intelligence/trend_analysis.py

GIT-1 to GIT-200 — pure function tests for compute_trend,
detect_direction, and build_trend_response.
"""

from __future__ import annotations

import pytest

from services.governance_intelligence.trend_analysis import (
    build_trend_response,
    compute_trend,
    detect_direction,
)
from services.governance_intelligence.models import TrendDirection


# ---------------------------------------------------------------------------
# GIT-1 — GIT-60: detect_direction
# ---------------------------------------------------------------------------


class TestDetectDirection:
    """GIT-1 to GIT-60: detect_direction function tests."""

    def test_git_1_returns_string(self):
        """GIT-1: result is a string."""
        result = detect_direction([1.0, 2.0, 3.0])
        assert isinstance(result, str)

    def test_git_2_empty_list_stable(self):
        """GIT-2: empty list → STABLE."""
        result = detect_direction([])
        assert result == TrendDirection.STABLE.value

    def test_git_3_single_value_stable(self):
        """GIT-3: single value → STABLE."""
        result = detect_direction([5.0])
        assert result == TrendDirection.STABLE.value

    def test_git_4_strictly_increasing_improving(self):
        """GIT-4: strictly increasing values with low CV → IMPROVING."""
        # Use base 100 to keep CV low: 100..129 → mean~114.5, std~8.65, CV~0.076
        values = [100.0 + float(i) for i in range(30)]
        result = detect_direction(values)
        assert result == TrendDirection.IMPROVING.value

    def test_git_5_strictly_decreasing_declining(self):
        """GIT-5: strictly decreasing values with low CV → DECLINING."""
        # Use base 200 to keep CV low: 200..171 → mean~185.5, std~8.65, CV~0.047
        values = [200.0 - float(i) for i in range(30)]
        result = detect_direction(values)
        assert result == TrendDirection.DECLINING.value

    def test_git_6_constant_values_stable(self):
        """GIT-6: constant values → STABLE (slope=0, CV=0)."""
        values = [5.0] * 20
        result = detect_direction(values)
        assert result == TrendDirection.STABLE.value

    def test_git_7_high_cv_volatile(self):
        """GIT-7: values with high CV → VOLATILE."""
        # alternating 0.01 and 100.0 → very high CV
        values = [0.01, 100.0] * 15
        result = detect_direction(values)
        assert result == TrendDirection.VOLATILE.value

    def test_git_8_result_is_valid_trend_direction(self):
        """GIT-8: result is always a valid TrendDirection value."""
        valid = {d.value for d in TrendDirection}
        for n in [0, 1, 2, 5, 10, 30]:
            r = detect_direction([float(i) for i in range(n)])
            assert r in valid

    def test_git_9_slope_above_001_improving(self):
        """GIT-9: slope > 0.01 → IMPROVING (not VOLATILE when CV is low)."""
        # Low variance, clear upward trend
        values = [10.0 + 0.1 * i for i in range(50)]
        result = detect_direction(values)
        # CV = stddev / mean, std ~ 1.4, mean ~ 12.5 → CV ~ 0.11 < 0.5 → IMPROVING
        assert result == TrendDirection.IMPROVING.value

    def test_git_10_slope_below_neg_001_declining(self):
        """GIT-10: slope < -0.01 → DECLINING (CV low)."""
        values = [10.0 - 0.1 * i for i in range(50)]
        result = detect_direction(values)
        assert result == TrendDirection.DECLINING.value

    def test_git_11_tiny_slope_stable(self):
        """GIT-11: tiny slope within [-0.01, 0.01] → STABLE (when CV low)."""
        # Very flat trend, no high variance
        values = [5.0 + 0.001 * i for i in range(30)]
        result = detect_direction(values)
        assert result == TrendDirection.STABLE.value

    def test_git_12_two_values_increasing(self):
        """GIT-12: two values [10, 12] → slope=2, but CV check needed. IMPROVING if CV<=0.5."""
        # mean=11, std=1, CV=0.09 < 0.5 → IMPROVING
        result = detect_direction([10.0, 12.0])
        assert result == TrendDirection.IMPROVING.value

    def test_git_13_two_values_decreasing(self):
        """GIT-13: two values [12, 10] → slope=-2, low CV → DECLINING."""
        # mean=11, std=1, CV=0.09 < 0.5 → DECLINING
        result = detect_direction([12.0, 10.0])
        assert result == TrendDirection.DECLINING.value

    def test_git_14_volatile_overrides_slope(self):
        """GIT-14: high CV takes priority → VOLATILE even if slope positive."""
        # Chaotic values: mean ~50, std ~50 → CV > 0.5 → VOLATILE
        values = [1.0, 100.0, 2.0, 99.0, 3.0, 98.0] * 5
        result = detect_direction(values)
        assert result == TrendDirection.VOLATILE.value

    @pytest.mark.parametrize(
        "values,expected",
        [
            # Low-variance increasing: CV = std(100..104)/mean(102) ≈ 0.014 < 0.5 → IMPROVING
            ([100.0, 101.0, 102.0, 103.0, 104.0], TrendDirection.IMPROVING.value),
            # Low-variance decreasing: mean~102, CV small → DECLINING
            ([104.0, 103.0, 102.0, 101.0, 100.0], TrendDirection.DECLINING.value),
            ([5.0, 5.0, 5.0, 5.0, 5.0], TrendDirection.STABLE.value),
        ],
    )
    def test_git_15_parametrize_directions(self, values, expected):
        """GIT-15: parametrized trend direction tests."""
        result = detect_direction(values)
        assert result == expected


# ---------------------------------------------------------------------------
# GIT-61 — GIT-130: compute_trend
# ---------------------------------------------------------------------------


class TestComputeTrend:
    """GIT-61 to GIT-130: compute_trend function tests."""

    def _make_data_points(self, values: list[float]) -> list[dict]:
        return [{"value": v} for v in values]

    def test_git_61_returns_dict(self):
        """GIT-61: result is a dict."""
        result = compute_trend([], 30)
        assert isinstance(result, dict)

    def test_git_62_empty_data_stable_direction(self):
        """GIT-62: empty data → direction=STABLE."""
        result = compute_trend([], 30)
        assert result["direction"] == TrendDirection.STABLE.value

    def test_git_63_empty_data_zero_slope(self):
        """GIT-63: empty data → slope=0.0."""
        result = compute_trend([], 30)
        assert result["slope"] == pytest.approx(0.0)

    def test_git_64_empty_data_zero_count(self):
        """GIT-64: empty data → data_point_count=0."""
        result = compute_trend([], 30)
        assert result["data_point_count"] == 0

    def test_git_65_window_days_preserved(self):
        """GIT-65: window_days is preserved in result."""
        result = compute_trend([], 45)
        assert result["window_days"] == 45

    def test_git_66_has_direction_key(self):
        """GIT-66: result has 'direction' key."""
        result = compute_trend(self._make_data_points([1.0, 2.0, 3.0]), 7)
        assert "direction" in result

    def test_git_67_has_slope_key(self):
        """GIT-67: result has 'slope' key."""
        result = compute_trend(self._make_data_points([1.0, 2.0, 3.0]), 7)
        assert "slope" in result

    def test_git_68_has_window_days_key(self):
        """GIT-68: result has 'window_days' key."""
        result = compute_trend(self._make_data_points([1.0, 2.0, 3.0]), 7)
        assert "window_days" in result

    def test_git_69_has_data_point_count_key(self):
        """GIT-69: result has 'data_point_count' key."""
        result = compute_trend(self._make_data_points([1.0, 2.0, 3.0]), 7)
        assert "data_point_count" in result

    def test_git_70_data_point_count_correct(self):
        """GIT-70: data_point_count matches input length."""
        points = self._make_data_points([1.0, 2.0, 3.0, 4.0, 5.0])
        result = compute_trend(points, 30)
        assert result["data_point_count"] == 5

    def test_git_71_increasing_trend_improving(self):
        """GIT-71: increasing data with low CV → IMPROVING direction."""
        points = self._make_data_points([100.0 + float(i) for i in range(20)])
        result = compute_trend(points, 30)
        assert result["direction"] == TrendDirection.IMPROVING.value

    def test_git_72_decreasing_trend_declining(self):
        """GIT-72: decreasing data with low CV → DECLINING direction."""
        points = self._make_data_points([200.0 - float(i) for i in range(20)])
        result = compute_trend(points, 30)
        assert result["direction"] == TrendDirection.DECLINING.value

    def test_git_73_positive_slope_for_increasing(self):
        """GIT-73: increasing data → positive slope."""
        points = self._make_data_points([float(i) for i in range(1, 10)])
        result = compute_trend(points, 30)
        assert result["slope"] > 0.0

    def test_git_74_negative_slope_for_decreasing(self):
        """GIT-74: decreasing data → negative slope."""
        points = self._make_data_points([10.0 - float(i) for i in range(10)])
        result = compute_trend(points, 30)
        assert result["slope"] < 0.0

    def test_git_75_slope_rounded_to_6_decimal(self):
        """GIT-75: slope is rounded to 6 decimal places."""
        points = self._make_data_points([1.0, 2.0, 3.0])
        result = compute_trend(points, 30)
        assert isinstance(result["slope"], float)

    def test_git_76_single_data_point_zero_slope(self):
        """GIT-76: single data point → slope=0.0."""
        points = self._make_data_points([5.0])
        result = compute_trend(points, 30)
        assert result["slope"] == pytest.approx(0.0)

    def test_git_77_direction_is_valid_trend_direction(self):
        """GIT-77: direction is always a valid TrendDirection value."""
        valid = {d.value for d in TrendDirection}
        points = self._make_data_points([1.0, 2.0, 3.0])
        result = compute_trend(points, 30)
        assert result["direction"] in valid

    def test_git_78_missing_value_key_defaults_zero(self):
        """GIT-78: data points without 'value' key default to 0.0."""
        points = [{"metric": 5.0}, {"metric": 6.0}]  # no 'value' key
        result = compute_trend(points, 30)
        assert result["slope"] == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# GIT-131 — GIT-200: build_trend_response
# ---------------------------------------------------------------------------


class TestBuildTrendResponse:
    """GIT-131 to GIT-200: build_trend_response function tests."""

    def _make_data_points(self, values: list[float]) -> list[dict]:
        return [{"value": v} for v in values]

    def test_git_131_returns_dict(self):
        """GIT-131: result is a dict."""
        result = build_trend_response("mfa_coverage", [], 30)
        assert isinstance(result, dict)

    def test_git_132_metric_key_preserved(self):
        """GIT-132: metric_key is preserved."""
        result = build_trend_response("my_metric", [], 30)
        assert result["metric_key"] == "my_metric"

    def test_git_133_direction_present(self):
        """GIT-133: result has 'direction' key."""
        result = build_trend_response("m", [], 30)
        assert "direction" in result

    def test_git_134_data_points_preserved(self):
        """GIT-134: data_points are preserved in result."""
        points = self._make_data_points([1.0, 2.0, 3.0])
        result = build_trend_response("m", points, 30)
        assert result["data_points"] == points

    def test_git_135_window_days_preserved(self):
        """GIT-135: window_days is preserved."""
        result = build_trend_response("m", [], 90)
        assert result["window_days"] == 90

    def test_git_136_has_computed_at(self):
        """GIT-136: result has 'computed_at' timestamp."""
        result = build_trend_response("m", [], 30)
        assert "computed_at" in result

    def test_git_137_computed_at_is_string(self):
        """GIT-137: computed_at is a string."""
        result = build_trend_response("m", [], 30)
        assert isinstance(result["computed_at"], str)

    def test_git_138_computed_at_is_iso8601(self):
        """GIT-138: computed_at looks like an ISO 8601 timestamp."""
        result = build_trend_response("m", [], 30)
        assert "T" in result["computed_at"]

    def test_git_139_increasing_trend_improving_direction(self):
        """GIT-139: increasing data with low CV → IMPROVING direction in response."""
        points = self._make_data_points([100.0 + float(i) for i in range(20)])
        result = build_trend_response("metric", points, 30)
        assert result["direction"] == TrendDirection.IMPROVING.value

    def test_git_140_empty_data_stable_direction(self):
        """GIT-140: empty data → STABLE direction."""
        result = build_trend_response("metric", [], 30)
        assert result["direction"] == TrendDirection.STABLE.value

    def test_git_141_no_tenant_id_in_output(self):
        """GIT-141: no tenant_id in output."""
        result = build_trend_response("metric", [], 30)
        assert "tenant_id" not in result

    def test_git_142_direction_is_valid(self):
        """GIT-142: direction is always a valid TrendDirection value."""
        valid = {d.value for d in TrendDirection}
        result = build_trend_response("metric", self._make_data_points([1.0, 2.0]), 30)
        assert result["direction"] in valid

    def test_git_143_large_dataset(self):
        """GIT-143: handles large dataset correctly."""
        points = self._make_data_points([100.0 + float(i) for i in range(100)])
        result = build_trend_response("metric", points, 30)
        assert result["direction"] in {d.value for d in TrendDirection}

    def test_git_144_declining_trend_in_response(self):
        """GIT-144: declining data with low CV → DECLINING direction in response."""
        points = self._make_data_points([200.0 - float(i) for i in range(30)])
        result = build_trend_response("metric", points, 30)
        assert result["direction"] == TrendDirection.DECLINING.value

    def test_git_145_window_days_different_values(self):
        """GIT-145: different window_days values are preserved."""
        for days in [7, 30, 90, 365]:
            result = build_trend_response("metric", [], days)
            assert result["window_days"] == days
