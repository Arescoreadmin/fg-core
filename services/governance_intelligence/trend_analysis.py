"""Trend analysis utilities for the Governance Intelligence Authority.

Pure functions. No I/O. No SQLAlchemy. No Pydantic.
"""

from __future__ import annotations

from typing import Any

from services.governance_intelligence.models import TrendDirection
from services.governance_intelligence.statistics import compute_mean, compute_stddev
from services.canonical import utc_iso8601_z_now


def compute_trend(
    data_points: list[dict[str, Any]], window_days: int
) -> dict[str, Any]:
    """Compute trend direction and slope from a list of data points."""
    if not data_points:
        return {
            "direction": TrendDirection.STABLE.value,
            "slope": 0.0,
            "window_days": window_days,
            "data_point_count": 0,
        }
    values = [float(dp.get("value", 0.0)) for dp in data_points]
    direction = detect_direction(values)
    # Simple linear regression slope
    n = len(values)
    if n < 2:
        slope = 0.0
    else:
        x_vals = list(range(n))
        x_mean = compute_mean([float(x) for x in x_vals])
        y_mean = compute_mean(values)
        num = sum((x_vals[i] - x_mean) * (values[i] - y_mean) for i in range(n))
        denom = sum((x_vals[i] - x_mean) ** 2 for i in range(n))
        slope = num / denom if denom != 0.0 else 0.0

    return {
        "direction": direction,
        "slope": round(slope, 6),
        "window_days": window_days,
        "data_point_count": n,
    }


def detect_direction(values: list[float]) -> str:
    """Return TrendDirection value based on simple linear regression slope.

    Rules:
      - slope > 0.01  → IMPROVING
      - slope < -0.01 → DECLINING
      - stddev high relative to mean (CV > 0.5) → VOLATILE
      - else → STABLE
    """
    if not values or len(values) < 2:
        return TrendDirection.STABLE.value

    n = len(values)
    x_vals = list(range(n))
    x_mean = sum(x_vals) / n
    y_mean = sum(values) / n
    num = sum((x_vals[i] - x_mean) * (values[i] - y_mean) for i in range(n))
    denom = sum((x_vals[i] - x_mean) ** 2 for i in range(n))
    slope = num / denom if denom != 0.0 else 0.0

    stddev = compute_stddev(values)
    mean_abs = abs(y_mean)
    cv = stddev / mean_abs if mean_abs > 0.0 else 0.0

    if cv > 0.5:
        return TrendDirection.VOLATILE.value
    if slope > 0.01:
        return TrendDirection.IMPROVING.value
    if slope < -0.01:
        return TrendDirection.DECLINING.value
    return TrendDirection.STABLE.value


def build_trend_response(
    metric_key: str,
    data_points: list[dict[str, Any]],
    window_days: int,
) -> dict[str, Any]:
    """Build a complete trend response dict."""
    trend = compute_trend(data_points, window_days)
    return {
        "metric_key": metric_key,
        "direction": trend["direction"],
        "data_points": data_points,
        "window_days": window_days,
        "computed_at": utc_iso8601_z_now(),
    }
