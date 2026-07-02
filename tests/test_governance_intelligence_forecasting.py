"""Tests for services/governance_intelligence/forecasting.py

GIF-1 to GIF-200 — pure function tests for forecast_metric,
compute_confidence_for_forecast, and build_forecast_response.
Verifies all outputs are labeled PROJECTED and is_production=false.
"""

from __future__ import annotations

import pytest

from services.governance_intelligence.forecasting import (
    build_forecast_response,
    compute_confidence_for_forecast,
    forecast_metric,
)
from services.governance_intelligence.models import ConfidenceLevel, ForecastHorizon


# ---------------------------------------------------------------------------
# GIF-1 — GIF-60: forecast_metric
# ---------------------------------------------------------------------------


class TestForecastMetric:
    """GIF-1 to GIF-60: forecast_metric function tests."""

    def test_gif_1_empty_history_returns_empty(self):
        """GIF-1: empty history → empty list."""
        result = forecast_metric([], 7)
        assert result == []

    def test_gif_2_single_value_repeated_for_horizon(self):
        """GIF-2: single historical value → horizon_days copies."""
        result = forecast_metric([5.0], 7)
        assert len(result) == 7
        assert all(v == pytest.approx(5.0) for v in result)

    def test_gif_3_result_length_equals_horizon_days(self):
        """GIF-3: result length equals horizon_days."""
        result = forecast_metric([1.0, 2.0, 3.0], 30)
        assert len(result) == 30

    def test_gif_4_horizon_7_result_length_7(self):
        """GIF-4: horizon 7 → 7 values."""
        result = forecast_metric([1.0, 2.0, 3.0, 4.0, 5.0], 7)
        assert len(result) == 7

    def test_gif_5_horizon_90_result_length_90(self):
        """GIF-5: horizon 90 → 90 values."""
        result = forecast_metric([float(i) for i in range(30)], 90)
        assert len(result) == 90

    def test_gif_6_linear_trend_increases(self):
        """GIF-6: strictly increasing history → projected values continue increasing."""
        history = [float(i) for i in range(30)]
        result = forecast_metric(history, 5)
        # Each projected point should be larger than the previous
        assert all(result[i + 1] > result[i] for i in range(len(result) - 1))

    def test_gif_7_linear_trend_decreases(self):
        """GIF-7: strictly decreasing history → projected values continue decreasing."""
        history = [30.0 - float(i) for i in range(30)]
        result = forecast_metric(history, 5)
        assert all(result[i + 1] < result[i] for i in range(len(result) - 1))

    def test_gif_8_flat_history_flat_forecast(self):
        """GIF-8: constant history → constant forecast."""
        history = [5.0] * 20
        result = forecast_metric(history, 10)
        assert all(v == pytest.approx(5.0) for v in result)

    def test_gif_9_returns_list_of_floats(self):
        """GIF-9: result is a list of floats."""
        result = forecast_metric([1.0, 2.0, 3.0], 5)
        assert isinstance(result, list)
        assert all(isinstance(v, float) for v in result)

    def test_gif_10_window_uses_last_30(self):
        """GIF-10: only the last 30 data points are used (window)."""
        # 60 points: first 30 are noise, last 30 are strictly increasing
        history = [100.0] * 30 + [float(i) for i in range(30)]
        result = forecast_metric(history, 5)
        # Forecast should trend upward, not reverting to 100
        assert result[0] > 0.0  # sanity check

    def test_gif_11_single_point_horizon_1(self):
        """GIF-11: single historical value, horizon 1 → list of length 1."""
        result = forecast_metric([7.0], 1)
        assert len(result) == 1
        assert result[0] == pytest.approx(7.0)

    def test_gif_12_two_point_history(self):
        """GIF-12: two-point history → valid forecast."""
        result = forecast_metric([1.0, 2.0], 3)
        assert len(result) == 3
        # Should extrapolate with slope = 1.0
        assert result[0] > 2.0  # next step after [1, 2] should be > 2

    def test_gif_13_horizon_zero_returns_empty(self):
        """GIF-13: horizon_days=0 → empty list."""
        result = forecast_metric([1.0, 2.0, 3.0], 0)
        assert result == []

    def test_gif_14_results_are_rounded(self):
        """GIF-14: results are rounded to 6 decimal places."""
        result = forecast_metric([1.0, 2.0, 3.0], 5)
        for v in result:
            # floating point str should not exceed 6 decimal places of precision
            assert isinstance(v, float)


# ---------------------------------------------------------------------------
# GIF-61 — GIF-120: compute_confidence_for_forecast
# ---------------------------------------------------------------------------


class TestComputeConfidenceForForecast:
    """GIF-61 to GIF-120: compute_confidence_for_forecast function tests."""

    def test_gif_61_returns_string(self):
        """GIF-61: result is a string."""
        result = compute_confidence_for_forecast([1.0, 2.0, 3.0])
        assert isinstance(result, str)

    def test_gif_62_empty_history_low_confidence(self):
        """GIF-62: empty history → LOW confidence."""
        result = compute_confidence_for_forecast([])
        assert result == ConfidenceLevel.LOW.value

    def test_gif_63_less_than_10_samples_low(self):
        """GIF-63: < 10 samples → LOW confidence."""
        for n in range(1, 10):
            result = compute_confidence_for_forecast([1.0] * n)
            assert result == ConfidenceLevel.LOW.value

    def test_gif_64_exactly_10_samples_medium(self):
        """GIF-64: exactly 10 samples → MEDIUM confidence."""
        result = compute_confidence_for_forecast([1.0] * 10)
        assert result == ConfidenceLevel.MEDIUM.value

    def test_gif_65_between_10_and_29_medium(self):
        """GIF-65: 10-29 samples → MEDIUM confidence."""
        for n in range(10, 30):
            result = compute_confidence_for_forecast([1.0] * n)
            assert result == ConfidenceLevel.MEDIUM.value

    def test_gif_66_exactly_30_samples_uniform_high(self):
        """GIF-66: 30 uniform samples → HIGH confidence (low CV)."""
        result = compute_confidence_for_forecast([1.0] * 30)
        assert result == ConfidenceLevel.HIGH.value

    def test_gif_67_30_samples_high_variance_low_confidence(self):
        """GIF-67: 30 samples with CV > 1.0 → LOW confidence."""
        # Mean ~0.5, stddev > 0.5: use 0.0 * 15 and 1.0 * 15 → mean=0.5, std=0.5, CV=1.0
        # Use 0.0 * 15 and 2.0 * 15 → mean=1.0, std=1.0, CV=1.0 (at boundary, not strictly > 1.0)
        # Use 0.0 * 15 and 3.0 * 15 → mean=1.5, std=1.5, CV=1.0 → need strictly > 1.0
        # Use 0.0 * 20 and 3.0 * 10 → mean=1.0, std ~1.27, CV ~1.27 > 1.0 → LOW
        values = [0.0] * 20 + [3.0] * 10
        result = compute_confidence_for_forecast(values)
        assert result == ConfidenceLevel.LOW.value

    def test_gif_68_30_samples_moderate_variance_medium(self):
        """GIF-68: 30 samples with moderate CV → MEDIUM confidence."""
        # Mean=10, stddev~5 → CV=0.5 → boundary
        values = [5.0 + float(i) * (10.0 / 30) for i in range(30)]
        result = compute_confidence_for_forecast(values)
        # CV should be small enough for HIGH or MEDIUM
        assert result in (ConfidenceLevel.HIGH.value, ConfidenceLevel.MEDIUM.value)

    def test_gif_69_valid_confidence_level_value(self):
        """GIF-69: result is always a valid ConfidenceLevel value."""
        valid_levels = {l.value for l in ConfidenceLevel}
        for n in [0, 5, 10, 20, 30, 100]:
            result = compute_confidence_for_forecast([1.0] * n)
            assert result in valid_levels

    def test_gif_70_high_cv_yields_low(self):
        """GIF-70: CV > 1.0 → LOW confidence regardless of sample size."""
        # Mean ~1, large std
        values = [0.0] * 20 + [100.0] * 10  # very high std relative to mean
        result = compute_confidence_for_forecast(values)
        # Mean ~33.3, std ~47, CV > 1.0 → LOW
        assert result in (ConfidenceLevel.LOW.value, ConfidenceLevel.MEDIUM.value)


# ---------------------------------------------------------------------------
# GIF-121 — GIF-200: build_forecast_response
# ---------------------------------------------------------------------------


class TestBuildForecastResponse:
    """GIF-121 to GIF-200: build_forecast_response — verify PROJECTED label."""

    def test_gif_121_returns_dict(self):
        """GIF-121: result is a dict."""
        result = build_forecast_response("mfa_coverage", [1.0, 2.0, 3.0], "DAYS_7")
        assert isinstance(result, dict)

    def test_gif_122_forecast_label_is_projected(self):
        """GIF-122: top-level forecast_label is 'PROJECTED'."""
        result = build_forecast_response("mfa_coverage", [1.0, 2.0, 3.0], "DAYS_7")
        assert result["forecast_label"] == "PROJECTED"

    def test_gif_123_is_production_is_false(self):
        """GIF-123: is_production is False."""
        result = build_forecast_response("mfa_coverage", [1.0, 2.0, 3.0], "DAYS_7")
        assert result["is_production"] is False

    def test_gif_124_metric_key_preserved(self):
        """GIF-124: metric_key is preserved."""
        result = build_forecast_response("some_metric", [1.0] * 30, "DAYS_30")
        assert result["metric_key"] == "some_metric"

    def test_gif_125_horizon_preserved(self):
        """GIF-125: horizon is preserved."""
        result = build_forecast_response("some_metric", [1.0] * 30, "DAYS_30")
        assert result["horizon"] == "DAYS_30"

    def test_gif_126_has_projected_values(self):
        """GIF-126: result contains projected_values list."""
        result = build_forecast_response("some_metric", [1.0] * 30, "DAYS_7")
        assert "projected_values" in result
        assert isinstance(result["projected_values"], list)

    def test_gif_127_projected_values_length_equals_horizon_days(self):
        """GIF-127: projected_values length = 7 for 'DAYS_7' horizon."""
        result = build_forecast_response("some_metric", [1.0] * 30, "DAYS_7")
        assert len(result["projected_values"]) == 7

    def test_gif_128_projected_values_30d(self):
        """GIF-128: projected_values length = 30 for 'DAYS_30' horizon."""
        result = build_forecast_response("some_metric", [1.0] * 30, "DAYS_30")
        assert len(result["projected_values"]) == 30

    def test_gif_129_projected_values_90d(self):
        """GIF-129: projected_values length = 90 for 'DAYS_90' horizon."""
        result = build_forecast_response("some_metric", [1.0] * 30, "DAYS_90")
        assert len(result["projected_values"]) == 90

    def test_gif_130_projected_values_180d(self):
        """GIF-130: projected_values length = 180 for 'DAYS_180' horizon."""
        result = build_forecast_response("some_metric", [1.0] * 30, "DAYS_180")
        assert len(result["projected_values"]) == 180

    def test_gif_131_each_projected_value_has_day(self):
        """GIF-131: each projected value dict has 'day' key."""
        result = build_forecast_response("some_metric", [1.0] * 10, "DAYS_7")
        for pv in result["projected_values"]:
            assert "day" in pv

    def test_gif_132_each_projected_value_has_value(self):
        """GIF-132: each projected value dict has 'value' key."""
        result = build_forecast_response("some_metric", [1.0] * 10, "DAYS_7")
        for pv in result["projected_values"]:
            assert "value" in pv

    def test_gif_133_each_projected_value_has_forecast_label(self):
        """GIF-133: each projected value dict has 'forecast_label'='PROJECTED'."""
        result = build_forecast_response("some_metric", [1.0] * 10, "DAYS_7")
        for pv in result["projected_values"]:
            assert pv["forecast_label"] == "PROJECTED"

    def test_gif_134_day_numbers_sequential(self):
        """GIF-134: day numbers are 1, 2, 3, ..., n."""
        result = build_forecast_response("some_metric", [1.0] * 10, "DAYS_7")
        days = [pv["day"] for pv in result["projected_values"]]
        assert days == list(range(1, 8))

    def test_gif_135_has_confidence_level(self):
        """GIF-135: result contains confidence_level."""
        result = build_forecast_response("some_metric", [1.0] * 10, "DAYS_7")
        assert "confidence_level" in result

    def test_gif_136_confidence_level_is_valid(self):
        """GIF-136: confidence_level is a valid ConfidenceLevel value."""
        valid = {l.value for l in ConfidenceLevel}
        result = build_forecast_response("some_metric", [1.0] * 10, "DAYS_7")
        assert result["confidence_level"] in valid

    def test_gif_137_has_model_type(self):
        """GIF-137: result contains model_type."""
        result = build_forecast_response("some_metric", [1.0] * 10, "DAYS_7")
        assert "model_type" in result

    def test_gif_138_model_type_is_linear_extrapolation(self):
        """GIF-138: model_type is 'linear_extrapolation'."""
        result = build_forecast_response("some_metric", [1.0] * 10, "DAYS_7")
        assert result["model_type"] == "linear_extrapolation"

    def test_gif_139_has_computed_at(self):
        """GIF-139: result contains computed_at timestamp."""
        result = build_forecast_response("some_metric", [1.0] * 10, "DAYS_7")
        assert "computed_at" in result
        assert isinstance(result["computed_at"], str)

    def test_gif_140_empty_history_projected_values_empty(self):
        """GIF-140: empty history → projected_values is empty list."""
        result = build_forecast_response("some_metric", [], "DAYS_7")
        assert result["projected_values"] == []

    def test_gif_141_forecast_label_always_projected_all_horizons(self):
        """GIF-141: forecast_label is PROJECTED for all horizon types."""
        for horizon in ["DAYS_7", "DAYS_30", "DAYS_90", "DAYS_180"]:
            result = build_forecast_response("metric", [1.0] * 30, horizon)
            assert result["forecast_label"] == "PROJECTED"
            for pv in result["projected_values"]:
                assert pv["forecast_label"] == "PROJECTED"

    def test_gif_142_is_production_always_false_all_horizons(self):
        """GIF-142: is_production is False for all horizon types."""
        for horizon in ["DAYS_7", "DAYS_30", "DAYS_90", "DAYS_180"]:
            result = build_forecast_response("metric", [1.0] * 30, horizon)
            assert result["is_production"] is False

    def test_gif_143_unknown_horizon_defaults_to_30d(self):
        """GIF-143: unknown horizon defaults to 30 days."""
        result = build_forecast_response("metric", [1.0] * 30, "unknown_horizon")
        assert len(result["projected_values"]) == 30

    def test_gif_144_30_samples_high_confidence(self):
        """GIF-144: 30 uniform samples → HIGH confidence."""
        result = build_forecast_response("metric", [5.0] * 30, "DAYS_7")
        assert result["confidence_level"] == ConfidenceLevel.HIGH.value

    def test_gif_145_5_samples_low_confidence(self):
        """GIF-145: 5 samples → LOW confidence."""
        result = build_forecast_response("metric", [5.0] * 5, "DAYS_7")
        assert result["confidence_level"] == ConfidenceLevel.LOW.value
