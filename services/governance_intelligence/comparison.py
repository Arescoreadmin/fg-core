"""Comparison utilities for the Governance Intelligence Authority.

Pure functions. No I/O. No SQLAlchemy. No Pydantic.
"""

from __future__ import annotations

from typing import Any

from services.governance_intelligence.statistics import compute_mean, compute_stddev


def compare_periods(
    period_a: list[dict[str, Any]],
    period_b: list[dict[str, Any]],
    metric_key: str,
) -> dict[str, Any]:
    """Statistical comparison between two time windows for a given metric."""
    vals_a = [
        float(r[metric_key])
        for r in period_a
        if metric_key in r and r[metric_key] is not None
    ]
    vals_b = [
        float(r[metric_key])
        for r in period_b
        if metric_key in r and r[metric_key] is not None
    ]

    mean_a = compute_mean(vals_a)
    mean_b = compute_mean(vals_b)
    delta = compute_delta(mean_a, mean_b)

    return {
        "metric_key": metric_key,
        "period_a": {
            "count": len(vals_a),
            "mean": mean_a,
            "stddev": compute_stddev(vals_a),
            "min": min(vals_a) if vals_a else None,
            "max": max(vals_a) if vals_a else None,
        },
        "period_b": {
            "count": len(vals_b),
            "mean": mean_b,
            "stddev": compute_stddev(vals_b),
            "min": min(vals_b) if vals_b else None,
            "max": max(vals_b) if vals_b else None,
        },
        "delta": delta,
    }


def compute_delta(a: float, b: float) -> dict[str, Any]:
    """Return absolute and percentage delta with direction."""
    absolute_delta = round(b - a, 6)
    pct_delta = round((b - a) / abs(a) * 100.0, 4) if a != 0.0 else None
    if absolute_delta > 0:
        direction = "INCREASED"
    elif absolute_delta < 0:
        direction = "DECREASED"
    else:
        direction = "UNCHANGED"
    return {
        "from": a,
        "to": b,
        "absolute_delta": absolute_delta,
        "pct_delta": pct_delta,
        "direction": direction,
    }
