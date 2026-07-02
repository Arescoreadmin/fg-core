"""Benchmarking utilities for the Governance Intelligence Authority.

Pure functions. No I/O. No SQLAlchemy. No Pydantic.
"""

from __future__ import annotations

from typing import Any

from services.governance_intelligence.models import BenchmarkTier
from services.governance_intelligence.statistics import (
    compute_mean,
    compute_percentile_rank,
    compute_stddev,
)


def compute_percentile(values: list[float], target: float) -> float:
    """Return the percentile rank (0-100) of target in values."""
    if not values:
        return 0.0
    return compute_percentile_rank(values, target)


def assign_tier(percentile: float) -> str:
    """Assign a BenchmarkTier based on percentile rank (0-100)."""
    if percentile >= 95.0:
        return BenchmarkTier.PERCENTILE_95.value
    if percentile >= 90.0:
        return BenchmarkTier.PERCENTILE_90.value
    if percentile >= 75.0:
        return BenchmarkTier.PERCENTILE_75.value
    if percentile >= 50.0:
        return BenchmarkTier.PERCENTILE_50.value
    return BenchmarkTier.PERCENTILE_25.value


def anonymize_benchmark(record: dict[str, Any]) -> dict[str, Any]:
    """Strip tenant_id and PII, keeping only framework/category/metric_key/value/percentile."""
    return {
        "framework": record.get("framework"),
        "category": record.get("category"),
        "metric_key": record.get("metric_key"),
        "value": record.get("value"),
        "percentile": record.get("percentile"),
        "tier": record.get("tier"),
    }


def compute_benchmark_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate benchmark data across a list of anonymized records."""
    if not records:
        return {
            "count": 0,
            "mean": None,
            "stddev": None,
            "min": None,
            "max": None,
            "percentiles": {},
        }

    values = [float(r["value"]) for r in records if r.get("value") is not None]
    if not values:
        return {
            "count": len(records),
            "mean": None,
            "stddev": None,
            "min": None,
            "max": None,
            "percentiles": {},
        }

    return {
        "count": len(values),
        "mean": compute_mean(values),
        "stddev": compute_stddev(values),
        "min": min(values),
        "max": max(values),
        "percentiles": {
            "p25": compute_percentile(
                values, sorted(values)[max(0, len(values) // 4 - 1)]
            ),
            "p50": compute_percentile(
                values, sorted(values)[max(0, len(values) // 2 - 1)]
            ),
            "p75": compute_percentile(
                values, sorted(values)[max(0, 3 * len(values) // 4 - 1)]
            ),
        },
    }
