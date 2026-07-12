"""Pure-function statistics. No external dependencies (stdlib only)."""

from __future__ import annotations

import math

from .models import RollingStats


def percentile(values: list[float], p: float) -> float:
    """Linear interpolation percentile. p in [0, 100]."""
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    idx = (p / 100.0) * (n - 1)
    lo = int(idx)
    hi = lo + 1
    if hi >= n:
        return sorted_vals[-1]
    frac = idx - lo
    return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac


def compute_rolling_stats(values: list[float]) -> RollingStats:
    if not values:
        return RollingStats(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    n = len(values)
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / n
    std_dev = math.sqrt(variance)
    return RollingStats(
        count=n,
        mean=round(mean, 3),
        median=round(percentile(values, 50), 3),
        p90=round(percentile(values, 90), 3),
        p95=round(percentile(values, 95), 3),
        minimum=round(min(values), 3),
        maximum=round(max(values), 3),
        std_dev=round(std_dev, 3),
    )
