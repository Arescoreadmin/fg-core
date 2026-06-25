"""services/freshness_score_history/models.py — Domain models for Freshness Score History.

Pure Python. No I/O. No SQLAlchemy.

PR 14.6.8 — Freshness Score History & Governance Trend Intelligence
"""

from __future__ import annotations

from enum import Enum


class SnapshotPeriod(str, Enum):
    DAILY = "DAILY"
    WEEKLY = "WEEKLY"
    MONTHLY = "MONTHLY"


class TrendDirection(str, Enum):
    IMPROVING = "IMPROVING"
    STABLE = "STABLE"
    DEGRADING = "DEGRADING"
    CRITICAL = "CRITICAL"


def compute_trend_direction(score_delta: float) -> TrendDirection:
    if score_delta > 5:
        return TrendDirection.IMPROVING
    if score_delta < -15:
        return TrendDirection.CRITICAL
    if score_delta < -5:
        return TrendDirection.DEGRADING
    return TrendDirection.STABLE


def compute_score_delta(current: float, baseline: float) -> float:
    return float(round(current - baseline, 2))
