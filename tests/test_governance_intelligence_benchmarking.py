"""Tests for services/governance_intelligence/benchmarking.py

GIB-1 to GIB-200 — pure function tests for compute_percentile, assign_tier,
anonymize_benchmark (verify tenant_id stripped), and compute_benchmark_summary.
"""

from __future__ import annotations

import pytest

from services.governance_intelligence.benchmarking import (
    anonymize_benchmark,
    assign_tier,
    compute_benchmark_summary,
    compute_percentile,
)
from services.governance_intelligence.models import BenchmarkTier


# ---------------------------------------------------------------------------
# GIB-1 — GIB-40: compute_percentile
# ---------------------------------------------------------------------------


class TestComputePercentile:
    """GIB-1 to GIB-40: compute_percentile function tests."""

    def test_gib_1_returns_float(self):
        """GIB-1: result is a float."""
        result = compute_percentile([1.0, 2.0, 3.0], 2.0)
        assert isinstance(result, float)

    def test_gib_2_empty_values_returns_zero(self):
        """GIB-2: empty values list returns 0.0."""
        result = compute_percentile([], 5.0)
        assert result == pytest.approx(0.0)

    def test_gib_3_target_at_median(self):
        """GIB-3: target at median of [1,2,3,4,5] is 50.0 (midpoint formula: (2+0.5)/5*100)."""
        result = compute_percentile([1.0, 2.0, 3.0, 4.0, 5.0], 3.0)
        assert result == pytest.approx(50.0)

    def test_gib_4_target_at_max_returns_90(self):
        """GIB-4: target at max of [1-5] returns 90.0 (midpoint formula: 4+0.5*1)/5*100)."""
        result = compute_percentile([1.0, 2.0, 3.0, 4.0, 5.0], 5.0)
        assert result == pytest.approx(90.0)

    def test_gib_5_target_at_min_returns_10(self):
        """GIB-5: target at min of [1-5] returns 10.0 (midpoint formula: (0+0.5*1)/5*100)."""
        result = compute_percentile([1.0, 2.0, 3.0, 4.0, 5.0], 1.0)
        assert result == pytest.approx(10.0)

    def test_gib_6_single_value_equals_target_50(self):
        """GIB-6: single value equal to target → 50.0 (midpoint formula)."""
        result = compute_percentile([5.0], 5.0)
        assert result == pytest.approx(50.0)

    def test_gib_7_target_exceeds_all_values(self):
        """GIB-7: target > all values → 100.0."""
        result = compute_percentile([1.0, 2.0, 3.0], 10.0)
        assert result == pytest.approx(100.0)

    def test_gib_8_target_below_all_values(self):
        """GIB-8: target < all values → some low percentile > 0."""
        result = compute_percentile([5.0, 6.0, 7.0], 0.0)
        assert 0.0 <= result <= 100.0

    def test_gib_9_result_between_0_and_100(self):
        """GIB-9: result is always in [0, 100]."""
        for target in [-10.0, 0.0, 2.5, 5.0, 100.0]:
            r = compute_percentile([1.0, 2.0, 3.0, 4.0, 5.0], target)
            assert 0.0 <= r <= 100.0

    def test_gib_10_large_list(self):
        """GIB-10: handles large list correctly."""
        values = [float(i) for i in range(1000)]
        result = compute_percentile(values, 500.0)
        assert 0.0 <= result <= 100.0

    def test_gib_11_duplicate_values(self):
        """GIB-11: handles duplicate values (midpoint: all equal → 50th percentile)."""
        result = compute_percentile([5.0, 5.0, 5.0, 5.0], 5.0)
        assert result == pytest.approx(50.0)


# ---------------------------------------------------------------------------
# GIB-41 — GIB-80: assign_tier
# ---------------------------------------------------------------------------


class TestAssignTier:
    """GIB-41 to GIB-80: assign_tier function tests."""

    def test_gib_41_returns_string(self):
        """GIB-41: result is a string."""
        result = assign_tier(80.0)
        assert isinstance(result, str)

    def test_gib_42_100_percentile_is_p95(self):
        """GIB-42: 100.0 → PERCENTILE_95 tier."""
        result = assign_tier(100.0)
        assert result == BenchmarkTier.PERCENTILE_95.value

    def test_gib_43_95_percentile_is_p95(self):
        """GIB-43: exactly 95.0 → PERCENTILE_95 tier."""
        result = assign_tier(95.0)
        assert result == BenchmarkTier.PERCENTILE_95.value

    def test_gib_44_94_percentile_is_p90(self):
        """GIB-44: 94.0 → PERCENTILE_90 tier."""
        result = assign_tier(94.0)
        assert result == BenchmarkTier.PERCENTILE_90.value

    def test_gib_45_90_percentile_is_p90(self):
        """GIB-45: exactly 90.0 → PERCENTILE_90 tier."""
        result = assign_tier(90.0)
        assert result == BenchmarkTier.PERCENTILE_90.value

    def test_gib_46_89_percentile_is_p75(self):
        """GIB-46: 89.0 → PERCENTILE_75 tier."""
        result = assign_tier(89.0)
        assert result == BenchmarkTier.PERCENTILE_75.value

    def test_gib_47_75_percentile_is_p75(self):
        """GIB-47: exactly 75.0 → PERCENTILE_75 tier."""
        result = assign_tier(75.0)
        assert result == BenchmarkTier.PERCENTILE_75.value

    def test_gib_48_74_percentile_is_p50(self):
        """GIB-48: 74.0 → PERCENTILE_50 tier."""
        result = assign_tier(74.0)
        assert result == BenchmarkTier.PERCENTILE_50.value

    def test_gib_49_50_percentile_is_p50(self):
        """GIB-49: exactly 50.0 → PERCENTILE_50 tier."""
        result = assign_tier(50.0)
        assert result == BenchmarkTier.PERCENTILE_50.value

    def test_gib_50_49_percentile_is_p25(self):
        """GIB-50: 49.0 → PERCENTILE_25 tier."""
        result = assign_tier(49.0)
        assert result == BenchmarkTier.PERCENTILE_25.value

    def test_gib_51_zero_percentile_is_p25(self):
        """GIB-51: 0.0 → PERCENTILE_25 tier."""
        result = assign_tier(0.0)
        assert result == BenchmarkTier.PERCENTILE_25.value

    def test_gib_52_boundary_95_inclusive(self):
        """GIB-52: 95.0 is inclusive boundary for PERCENTILE_95."""
        result = assign_tier(95.0)
        assert result == BenchmarkTier.PERCENTILE_95.value

    def test_gib_53_boundary_90_inclusive(self):
        """GIB-53: 90.0 is inclusive boundary for PERCENTILE_90."""
        result = assign_tier(90.0)
        assert result == BenchmarkTier.PERCENTILE_90.value

    def test_gib_54_boundary_75_inclusive(self):
        """GIB-54: 75.0 is inclusive boundary for PERCENTILE_75."""
        result = assign_tier(75.0)
        assert result == BenchmarkTier.PERCENTILE_75.value

    def test_gib_55_boundary_50_inclusive(self):
        """GIB-55: 50.0 is inclusive boundary for PERCENTILE_50."""
        result = assign_tier(50.0)
        assert result == BenchmarkTier.PERCENTILE_50.value

    @pytest.mark.parametrize(
        "percentile,expected_tier",
        [
            (100.0, BenchmarkTier.PERCENTILE_95.value),
            (97.5, BenchmarkTier.PERCENTILE_95.value),
            (92.0, BenchmarkTier.PERCENTILE_90.value),
            (80.0, BenchmarkTier.PERCENTILE_75.value),
            (60.0, BenchmarkTier.PERCENTILE_50.value),
            (25.0, BenchmarkTier.PERCENTILE_25.value),
            (0.0, BenchmarkTier.PERCENTILE_25.value),
        ],
    )
    def test_gib_56_parametrize_tiers(self, percentile, expected_tier):
        """GIB-56: parametrized tier assignments."""
        assert assign_tier(percentile) == expected_tier


# ---------------------------------------------------------------------------
# GIB-81 — GIB-140: anonymize_benchmark
# ---------------------------------------------------------------------------


class TestAnonymizeBenchmark:
    """GIB-81 to GIB-140: anonymize_benchmark — verify tenant_id is NEVER in output."""

    def _sample_record(self) -> dict:
        return {
            "id": "bench-001",
            "tenant_id": "tenant-abc-secret",
            "framework": "PCI_DSS",
            "category": "access_control",
            "metric_key": "mfa_coverage",
            "value": 0.95,
            "percentile": 88.0,
            "tier": "PERCENTILE_90",
            "metadata": "some internal data",
            "created_at": "2026-01-01T00:00:00Z",
        }

    def test_gib_81_returns_dict(self):
        """GIB-81: result is a dict."""
        result = anonymize_benchmark(self._sample_record())
        assert isinstance(result, dict)

    def test_gib_82_tenant_id_not_in_output(self):
        """GIB-82: tenant_id is NOT in the output dict."""
        result = anonymize_benchmark(self._sample_record())
        assert "tenant_id" not in result

    def test_gib_83_tenant_id_value_not_in_output(self):
        """GIB-83: tenant_id value 'tenant-abc-secret' not present in output values."""
        result = anonymize_benchmark(self._sample_record())
        assert "tenant-abc-secret" not in result.values()

    def test_gib_84_framework_preserved(self):
        """GIB-84: framework is preserved."""
        result = anonymize_benchmark(self._sample_record())
        assert result["framework"] == "PCI_DSS"

    def test_gib_85_category_preserved(self):
        """GIB-85: category is preserved."""
        result = anonymize_benchmark(self._sample_record())
        assert result["category"] == "access_control"

    def test_gib_86_metric_key_preserved(self):
        """GIB-86: metric_key is preserved."""
        result = anonymize_benchmark(self._sample_record())
        assert result["metric_key"] == "mfa_coverage"

    def test_gib_87_value_preserved(self):
        """GIB-87: value is preserved."""
        result = anonymize_benchmark(self._sample_record())
        assert result["value"] == pytest.approx(0.95)

    def test_gib_88_percentile_preserved(self):
        """GIB-88: percentile is preserved."""
        result = anonymize_benchmark(self._sample_record())
        assert result["percentile"] == pytest.approx(88.0)

    def test_gib_89_tier_preserved(self):
        """GIB-89: tier is preserved."""
        result = anonymize_benchmark(self._sample_record())
        assert result["tier"] == "PERCENTILE_90"

    def test_gib_90_id_stripped(self):
        """GIB-90: id field (PII) is stripped."""
        result = anonymize_benchmark(self._sample_record())
        assert "id" not in result

    def test_gib_91_metadata_stripped(self):
        """GIB-91: metadata field is stripped."""
        result = anonymize_benchmark(self._sample_record())
        assert "metadata" not in result

    def test_gib_92_created_at_stripped(self):
        """GIB-92: created_at is stripped."""
        result = anonymize_benchmark(self._sample_record())
        assert "created_at" not in result

    def test_gib_93_only_expected_keys(self):
        """GIB-93: output contains only the expected keys."""
        result = anonymize_benchmark(self._sample_record())
        expected_keys = {"framework", "category", "metric_key", "value", "percentile", "tier"}
        assert set(result.keys()) == expected_keys

    def test_gib_94_empty_input_ok(self):
        """GIB-94: empty input yields all None values."""
        result = anonymize_benchmark({})
        assert result.get("framework") is None
        assert "tenant_id" not in result

    def test_gib_95_no_tenant_id_in_empty_input(self):
        """GIB-95: empty input also has no tenant_id in output."""
        result = anonymize_benchmark({})
        assert "tenant_id" not in result

    def test_gib_96_different_tenant_ids_stripped(self):
        """GIB-96: any tenant_id value is stripped."""
        for tenant in ["tenant-X", "org-abc", "t1", "ffffffff"]:
            record = self._sample_record()
            record["tenant_id"] = tenant
            result = anonymize_benchmark(record)
            assert "tenant_id" not in result
            assert tenant not in result.values()

    def test_gib_97_multiple_calls_consistent(self):
        """GIB-97: multiple calls yield same result."""
        record = self._sample_record()
        r1 = anonymize_benchmark(record)
        r2 = anonymize_benchmark(record)
        assert r1 == r2

    def test_gib_98_does_not_mutate_input(self):
        """GIB-98: anonymize_benchmark does not mutate the input dict."""
        record = self._sample_record()
        original_keys = set(record.keys())
        anonymize_benchmark(record)
        assert set(record.keys()) == original_keys

    def test_gib_99_none_value_preserved(self):
        """GIB-99: None value in the record is preserved in output."""
        record = self._sample_record()
        record["value"] = None
        result = anonymize_benchmark(record)
        assert result["value"] is None

    def test_gib_100_zero_value_preserved(self):
        """GIB-100: zero value is preserved."""
        record = self._sample_record()
        record["value"] = 0.0
        result = anonymize_benchmark(record)
        assert result["value"] == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# GIB-141 — GIB-200: compute_benchmark_summary
# ---------------------------------------------------------------------------


class TestComputeBenchmarkSummary:
    """GIB-141 to GIB-200: compute_benchmark_summary function tests."""

    def test_gib_141_returns_dict(self):
        """GIB-141: result is a dict."""
        result = compute_benchmark_summary([{"value": 1.0}])
        assert isinstance(result, dict)

    def test_gib_142_empty_records_count_zero(self):
        """GIB-142: empty records → count=0."""
        result = compute_benchmark_summary([])
        assert result["count"] == 0

    def test_gib_143_empty_records_none_mean(self):
        """GIB-143: empty records → mean=None."""
        result = compute_benchmark_summary([])
        assert result["mean"] is None

    def test_gib_144_empty_records_none_min_max(self):
        """GIB-144: empty records → min=None, max=None."""
        result = compute_benchmark_summary([])
        assert result["min"] is None
        assert result["max"] is None

    def test_gib_145_single_record_count_one(self):
        """GIB-145: single record → count=1."""
        result = compute_benchmark_summary([{"value": 5.0}])
        assert result["count"] == 1

    def test_gib_146_single_record_mean_correct(self):
        """GIB-146: single record → mean=that value."""
        result = compute_benchmark_summary([{"value": 5.0}])
        assert result["mean"] == pytest.approx(5.0)

    def test_gib_147_single_record_min_max_same(self):
        """GIB-147: single record → min=max=value."""
        result = compute_benchmark_summary([{"value": 5.0}])
        assert result["min"] == pytest.approx(5.0)
        assert result["max"] == pytest.approx(5.0)

    def test_gib_148_multiple_records_count(self):
        """GIB-148: 5 records → count=5."""
        records = [{"value": float(i)} for i in range(5)]
        result = compute_benchmark_summary(records)
        assert result["count"] == 5

    def test_gib_149_mean_correct(self):
        """GIB-149: mean of [1,2,3,4,5] = 3.0."""
        records = [{"value": float(i)} for i in range(1, 6)]
        result = compute_benchmark_summary(records)
        assert result["mean"] == pytest.approx(3.0)

    def test_gib_150_min_correct(self):
        """GIB-150: min of [1,2,3,4,5] = 1.0."""
        records = [{"value": float(i)} for i in range(1, 6)]
        result = compute_benchmark_summary(records)
        assert result["min"] == pytest.approx(1.0)

    def test_gib_151_max_correct(self):
        """GIB-151: max of [1,2,3,4,5] = 5.0."""
        records = [{"value": float(i)} for i in range(1, 6)]
        result = compute_benchmark_summary(records)
        assert result["max"] == pytest.approx(5.0)

    def test_gib_152_has_stddev(self):
        """GIB-152: result includes stddev."""
        records = [{"value": float(i)} for i in range(1, 6)]
        result = compute_benchmark_summary(records)
        assert "stddev" in result

    def test_gib_153_has_percentiles(self):
        """GIB-153: result includes percentiles dict."""
        records = [{"value": float(i)} for i in range(1, 6)]
        result = compute_benchmark_summary(records)
        assert "percentiles" in result
        assert isinstance(result["percentiles"], dict)

    def test_gib_154_has_p25_p50_p75(self):
        """GIB-154: percentiles dict has p25, p50, p75 keys."""
        records = [{"value": float(i)} for i in range(1, 6)]
        result = compute_benchmark_summary(records)
        assert "p25" in result["percentiles"]
        assert "p50" in result["percentiles"]
        assert "p75" in result["percentiles"]

    def test_gib_155_none_value_records_excluded(self):
        """GIB-155: records with None value are excluded from computations."""
        records = [{"value": 5.0}, {"value": None}, {"value": 10.0}]
        result = compute_benchmark_summary(records)
        # Only 2 valid values
        assert result["count"] == 2

    def test_gib_156_single_value_stddev_is_zero_or_small(self):
        """GIB-156: single value → stddev is 0 or near 0."""
        result = compute_benchmark_summary([{"value": 5.0}])
        assert result["stddev"] is not None
        assert result["stddev"] == pytest.approx(0.0)

    def test_gib_157_no_tenant_id_in_output(self):
        """GIB-157: output of compute_benchmark_summary has no tenant_id."""
        records = [{"value": 5.0, "tenant_id": "t1"}]
        result = compute_benchmark_summary(records)
        assert "tenant_id" not in result

    def test_gib_158_large_dataset(self):
        """GIB-158: handles 1000 records."""
        records = [{"value": float(i)} for i in range(1000)]
        result = compute_benchmark_summary(records)
        assert result["count"] == 1000
        assert result["mean"] == pytest.approx(499.5)
