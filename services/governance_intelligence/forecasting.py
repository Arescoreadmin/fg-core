"""Forecasting utilities for the Governance Intelligence Authority.

Pure functions. No I/O. No SQLAlchemy. No Pydantic.

All outputs are labeled PROJECTED and is_production=false.
"""

from __future__ import annotations

from typing import Any

from services.governance_intelligence.models import ConfidenceLevel, ForecastHorizon
from services.governance_intelligence.statistics import compute_mean, compute_stddev
from services.canonical import utc_iso8601_z_now


_HORIZON_DAYS: dict[str, int] = {
    ForecastHorizon.DAYS_7.value: 7,
    ForecastHorizon.DAYS_30.value: 30,
    ForecastHorizon.DAYS_90.value: 90,
    ForecastHorizon.DAYS_180.value: 180,
}


def forecast_metric(historical_values: list[float], horizon_days: int) -> list[float]:
    """Simple linear extrapolation from last 30 data points.

    All outputs are PROJECTED values.
    """
    if not historical_values:
        return []

    window = historical_values[-30:]
    n = len(window)

    if n == 1:
        return [window[0]] * horizon_days

    # Linear regression
    x_vals = list(range(n))
    x_mean = sum(x_vals) / n
    y_mean = sum(window) / n
    num = sum((x_vals[i] - x_mean) * (window[i] - y_mean) for i in range(n))
    denom = sum((x_vals[i] - x_mean) ** 2 for i in range(n))
    slope = num / denom if denom != 0.0 else 0.0
    intercept = y_mean - slope * x_mean

    return [round(intercept + slope * (n + d), 6) for d in range(horizon_days)]


def compute_confidence_for_forecast(historical_values: list[float]) -> str:
    """Return ConfidenceLevel based on sample size and variance."""
    n = len(historical_values)
    if n < 10:
        return ConfidenceLevel.LOW.value
    if n < 30:
        return ConfidenceLevel.MEDIUM.value

    mean = compute_mean(historical_values)
    stddev = compute_stddev(historical_values)
    cv = stddev / abs(mean) if abs(mean) > 0.0 else float("inf")

    if cv > 1.0:
        return ConfidenceLevel.LOW.value
    if cv > 0.5:
        return ConfidenceLevel.MEDIUM.value
    return ConfidenceLevel.HIGH.value


def build_forecast_response(
    metric_key: str, historical: list[float], horizon: str
) -> dict[str, Any]:
    """Build a forecast dict. Includes forecast_label=PROJECTED, is_production=false."""
    horizon_days = _HORIZON_DAYS.get(horizon, 30)
    projected = forecast_metric(historical, horizon_days)
    confidence = compute_confidence_for_forecast(historical)

    projected_values = [
        {"day": d + 1, "value": projected[d], "forecast_label": "PROJECTED"}
        for d in range(len(projected))
    ]

    return {
        "metric_key": metric_key,
        "horizon": horizon,
        "projected_values": projected_values,
        "confidence_level": confidence,
        "model_type": "linear_extrapolation",
        "forecast_label": "PROJECTED",
        "is_production": False,
        "computed_at": utc_iso8601_z_now(),
    }
