"""Severity-driven regression detection. Advisory mode (doesn't fail builds)."""

from __future__ import annotations

from .models import Regression, RollingStats

# Severity thresholds (% increase over baseline)
_THRESHOLDS = {
    "critical": 100.0,  # doubled
    "high": 50.0,  # 50% increase
    "medium": 25.0,  # 25% increase
    "low": 10.0,  # 10% increase
}


def _severity(pct_change: float) -> str:
    if pct_change >= _THRESHOLDS["critical"]:
        return "critical"
    if pct_change >= _THRESHOLDS["high"]:
        return "high"
    if pct_change >= _THRESHOLDS["medium"]:
        return "medium"
    if pct_change >= _THRESHOLDS["low"]:
        return "low"
    return "none"


# Public name used by __init__.py
RegressionSeverity = _THRESHOLDS


def detect_regressions(
    gate: str,
    current_duration: float,
    current_collected: int,
    baseline_stats: RollingStats,
    baseline_collected: int | None = None,
) -> list[Regression]:
    regressions: list[Regression] = []
    if baseline_stats.count == 0 or baseline_stats.median == 0:
        return regressions

    # Check duration regression vs median
    pct = ((current_duration - baseline_stats.median) / baseline_stats.median) * 100
    sev = _severity(pct)
    if sev != "none":
        regressions.append(
            Regression(
                gate=gate,
                field="duration_seconds",
                current_value=round(current_duration, 1),
                baseline_value=round(baseline_stats.median, 1),
                pct_change=round(pct, 1),
                severity=sev,
                message=(
                    f"{gate} duration {current_duration:.0f}s is {pct:.0f}% above "
                    f"median {baseline_stats.median:.0f}s"
                ),
            )
        )

    # Check test count regression (reduction in collected = possible missing tests)
    if (
        baseline_collected is not None
        and baseline_collected > 0
        and current_collected < baseline_collected
    ):
        drop_pct = ((baseline_collected - current_collected) / baseline_collected) * 100
        sev = _severity(drop_pct)
        if sev != "none":
            regressions.append(
                Regression(
                    gate=gate,
                    field="collected",
                    current_value=float(current_collected),
                    baseline_value=float(baseline_collected),
                    pct_change=round(-drop_pct, 1),
                    severity=sev,
                    message=(
                        f"{gate} collected {current_collected} tests "
                        f"(was {baseline_collected}, -{drop_pct:.0f}%)"
                    ),
                )
            )

    return regressions
