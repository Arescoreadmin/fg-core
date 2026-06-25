"""services/control_effectiveness/models.py — Domain models for the Control Effectiveness Engine.

Pure Python. No I/O. No SQLAlchemy.

SCORING MODEL v1 (calculation_version="1.0"):
  Coverage          20%  — evidence linked, coverage completeness, verified evidence ratio
  Verification      20%  — success rate, age, failure count
  Freshness         15%  — average freshness score across linked evidence
  Trend             15%  — 7d/30d/90d effectiveness trajectory
  Forecast          10%  — projected freshness trajectory for linked evidence
  Evidence Density  10%  — count, quality scores, source diversity
  Exception         10%  — open exceptions vs. compensating controls

Classification:
  90-100 → HIGHLY_EFFECTIVE
  75-89  → EFFECTIVE
  60-74  → ADEQUATE
  40-59  → WEAK
  0-39   → INEFFECTIVE

Risk:
  HIGHLY_EFFECTIVE / EFFECTIVE → LOW
  ADEQUATE                     → MEDIUM
  WEAK                         → HIGH
  INEFFECTIVE                  → CRITICAL

PR 16.5 — Control Effectiveness Engine
"""

from __future__ import annotations

from enum import Enum

SCORING_MODEL_VERSION = "1.0"

# Scoring weights — must sum to 1.0
WEIGHT_COVERAGE = 0.20
WEIGHT_VERIFICATION = 0.20
WEIGHT_FRESHNESS = 0.15
WEIGHT_TREND = 0.15
WEIGHT_FORECAST = 0.10
WEIGHT_EVIDENCE_DENSITY = 0.10
WEIGHT_EXCEPTION = 0.10


class EffectivenessLevel(str, Enum):
    INEFFECTIVE = "INEFFECTIVE"
    WEAK = "WEAK"
    ADEQUATE = "ADEQUATE"
    EFFECTIVE = "EFFECTIVE"
    HIGHLY_EFFECTIVE = "HIGHLY_EFFECTIVE"


class EffectivenessRisk(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TrendDirection(str, Enum):
    IMPROVING = "IMPROVING"
    STABLE = "STABLE"
    DEGRADING = "DEGRADING"
    CRITICAL = "CRITICAL"


def classify_effectiveness(score: float) -> EffectivenessLevel:
    if score >= 90:
        return EffectivenessLevel.HIGHLY_EFFECTIVE
    if score >= 75:
        return EffectivenessLevel.EFFECTIVE
    if score >= 60:
        return EffectivenessLevel.ADEQUATE
    if score >= 40:
        return EffectivenessLevel.WEAK
    return EffectivenessLevel.INEFFECTIVE


def classify_risk(level: EffectivenessLevel) -> EffectivenessRisk:
    if level in (EffectivenessLevel.HIGHLY_EFFECTIVE, EffectivenessLevel.EFFECTIVE):
        return EffectivenessRisk.LOW
    if level == EffectivenessLevel.ADEQUATE:
        return EffectivenessRisk.MEDIUM
    if level == EffectivenessLevel.WEAK:
        return EffectivenessRisk.HIGH
    return EffectivenessRisk.CRITICAL


def classify_trend(delta: float) -> TrendDirection:
    if delta > 5:
        return TrendDirection.IMPROVING
    if delta < -15:
        return TrendDirection.CRITICAL
    if delta < -5:
        return TrendDirection.DEGRADING
    return TrendDirection.STABLE


def compute_effectiveness_score(
    coverage_score: float,
    verification_score: float,
    freshness_score: float,
    trend_score: float,
    forecast_score: float,
    evidence_density_score: float,
    exception_score: float,
) -> float:
    """Weighted sum of all component scores. Result is clamped to [0, 100]."""
    raw = (
        coverage_score * WEIGHT_COVERAGE
        + verification_score * WEIGHT_VERIFICATION
        + freshness_score * WEIGHT_FRESHNESS
        + trend_score * WEIGHT_TREND
        + forecast_score * WEIGHT_FORECAST
        + evidence_density_score * WEIGHT_EVIDENCE_DENSITY
        + exception_score * WEIGHT_EXCEPTION
    )
    return round(max(0.0, min(100.0, raw)), 2)
