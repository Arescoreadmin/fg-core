"""Statistical utilities for the Governance Intelligence Authority.

Pure functions. No I/O. No SQLAlchemy. No Pydantic.
"""

from __future__ import annotations

import math
from typing import Any


def compute_mean(values: list[float]) -> float:
    """Compute arithmetic mean of a list of floats."""
    if not values:
        return 0.0
    return sum(values) / len(values)


def compute_stddev(values: list[float]) -> float:
    """Compute population standard deviation of a list of floats."""
    if len(values) < 2:
        return 0.0
    mean = compute_mean(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance)


def compute_percentile_rank(values: list[float], target: float) -> float:
    """Return the percentile rank (0-100) of target within values."""
    if not values:
        return 0.0
    count_below = sum(1 for v in values if v < target)
    count_equal = sum(1 for v in values if v == target)
    rank = (count_below + 0.5 * count_equal) / len(values) * 100.0
    return round(min(100.0, max(0.0, rank)), 4)


def compute_moving_average(values: list[float], window: int) -> list[float]:
    """Compute a simple moving average with the given window size."""
    if not values or window < 1:
        return []
    result: list[float] = []
    for i in range(len(values)):
        start = max(0, i - window + 1)
        window_vals = values[start : i + 1]
        result.append(compute_mean(window_vals))
    return result


def aggregate_stats(records: list[dict[str, Any]], metric_key: str) -> dict[str, Any]:
    """Return aggregated statistics for a metric across a list of records."""
    values = [
        float(r[metric_key])
        for r in records
        if metric_key in r and r[metric_key] is not None
    ]
    if not values:
        return {
            "metric_key": metric_key,
            "count": 0,
            "min": None,
            "max": None,
            "mean": None,
            "stddev": None,
            "percentiles": {},
        }
    sorted_vals = sorted(values)
    n = len(sorted_vals)

    def _p(pct: float) -> float:
        idx = int(pct / 100.0 * n)
        idx = min(idx, n - 1)
        return sorted_vals[idx]

    return {
        "metric_key": metric_key,
        "count": n,
        "min": min(values),
        "max": max(values),
        "mean": compute_mean(values),
        "stddev": compute_stddev(values),
        "percentiles": {
            "p25": _p(25),
            "p50": _p(50),
            "p75": _p(75),
            "p90": _p(90),
            "p95": _p(95),
        },
    }
