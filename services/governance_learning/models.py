"""services/governance_learning/models.py

Pure Python domain models, classifiers, and computation logic.
No I/O. No SQLAlchemy. No AI. No LLMs. All outputs are deterministic and auditable.

PR 17.6B — Governance Learning Loop Authority
"""

from __future__ import annotations

import math
from enum import Enum
from typing import Optional

GOVERNANCE_LEARNING_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class LearningCategory(str, Enum):
    REMEDIATION = "REMEDIATION"
    VERIFICATION = "VERIFICATION"
    FRESHNESS = "FRESHNESS"
    EFFECTIVENESS = "EFFECTIVENESS"
    HEALTH = "HEALTH"
    FORECAST = "FORECAST"


class LearningSignal(str, Enum):
    IMPROVES_EFFECTIVENESS = "IMPROVES_EFFECTIVENESS"
    IMPROVES_FRESHNESS = "IMPROVES_FRESHNESS"
    IMPROVES_VERIFICATION = "IMPROVES_VERIFICATION"
    IMPROVES_FORECAST = "IMPROVES_FORECAST"
    IMPROVES_HEALTH = "IMPROVES_HEALTH"
    HIGH_SUCCESS_RATE = "HIGH_SUCCESS_RATE"
    HIGH_FAILURE_RATE = "HIGH_FAILURE_RATE"
    REPEATED_FAILURE = "REPEATED_FAILURE"
    FASTEST_IMPROVEMENT = "FASTEST_IMPROVEMENT"
    MOST_RELIABLE_REMEDIATION = "MOST_RELIABLE_REMEDIATION"
    MOST_EFFECTIVE_ACTION = "MOST_EFFECTIVE_ACTION"


class MomentumClass(str, Enum):
    ACCELERATING = "ACCELERATING"
    STABLE = "STABLE"
    DECELERATING = "DECELERATING"
    REGRESSING = "REGRESSING"


class StabilityClass(str, Enum):
    VERY_STABLE = "VERY_STABLE"
    STABLE = "STABLE"
    VARIABLE = "VARIABLE"
    UNSTABLE = "UNSTABLE"


class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# Pure deterministic functions
# ---------------------------------------------------------------------------


def compute_success_score(outcome_classification: str, score_delta: float) -> float:
    """0-100 success score based on outcome classification plus delta bonus.

    Base scores: SUCCESS=100, PARTIAL_SUCCESS=60, NO_CHANGE=40, REGRESSION=20, FAILURE=0.
    Delta bonus: clamped to [-10, +10] via score_delta * 0.5.
    """
    base = {
        "SUCCESS": 100.0,
        "PARTIAL_SUCCESS": 60.0,
        "NO_CHANGE": 40.0,
        "REGRESSION": 20.0,
        "FAILURE": 0.0,
    }.get(outcome_classification, 40.0)
    bonus = min(10.0, max(-10.0, score_delta * 0.5))
    return round(min(100.0, max(0.0, base + bonus)), 2)


def compute_confidence_score(sample_count: int) -> float:
    """Confidence score based on sample size.

    >=20 samples → HIGH (90), >=10 → MEDIUM (70), >=3 → LOW (50), <3 → UNKNOWN (20).
    """
    if sample_count >= 20:
        return 90.0
    if sample_count >= 10:
        return 70.0
    if sample_count >= 3:
        return 50.0
    return 20.0


def classify_confidence(sample_count: int) -> ConfidenceLevel:
    """Classify confidence level from sample count."""
    if sample_count >= 20:
        return ConfidenceLevel.HIGH
    if sample_count >= 10:
        return ConfidenceLevel.MEDIUM
    if sample_count >= 3:
        return ConfidenceLevel.LOW
    return ConfidenceLevel.UNKNOWN


def classify_momentum(
    avg_health_delta_30d: Optional[float],
    avg_effectiveness_delta_30d: Optional[float],
) -> MomentumClass:
    """Classify momentum from 30d average health and effectiveness deltas."""
    if avg_health_delta_30d is None and avg_effectiveness_delta_30d is None:
        return MomentumClass.STABLE
    deltas = [
        d for d in [avg_health_delta_30d, avg_effectiveness_delta_30d] if d is not None
    ]
    avg = sum(deltas) / len(deltas)
    if avg >= 5.0:
        return MomentumClass.ACCELERATING
    if avg >= 0.0:
        return MomentumClass.STABLE
    if avg >= -5.0:
        return MomentumClass.DECELERATING
    return MomentumClass.REGRESSING


def classify_stability(health_deltas: list[float]) -> StabilityClass:
    """Classify stability from the variance of health deltas.

    stddev <=2 → VERY_STABLE, <=5 → STABLE, <=10 → VARIABLE, >10 → UNSTABLE.
    """
    if len(health_deltas) < 2:
        return StabilityClass.STABLE
    mean = sum(health_deltas) / len(health_deltas)
    variance = sum((d - mean) ** 2 for d in health_deltas) / len(health_deltas)
    stddev = math.sqrt(variance)
    if stddev <= 2.0:
        return StabilityClass.VERY_STABLE
    if stddev <= 5.0:
        return StabilityClass.STABLE
    if stddev <= 10.0:
        return StabilityClass.VARIABLE
    return StabilityClass.UNSTABLE


def detect_signals(
    avg_effectiveness_delta: Optional[float],
    avg_health_delta: Optional[float],
    avg_freshness_delta: Optional[float],
    avg_verification_delta: Optional[float],
    avg_forecast_delta: Optional[float],
    success_rate: float,
    failure_rate: float,
    total_count: int,
) -> list[str]:
    """Deterministic signal detection from aggregate statistics."""
    signals: list[str] = []
    if avg_effectiveness_delta is not None and avg_effectiveness_delta > 5.0:
        signals.append(LearningSignal.IMPROVES_EFFECTIVENESS.value)
    if avg_freshness_delta is not None and avg_freshness_delta > 5.0:
        signals.append(LearningSignal.IMPROVES_FRESHNESS.value)
    if avg_verification_delta is not None and avg_verification_delta > 5.0:
        signals.append(LearningSignal.IMPROVES_VERIFICATION.value)
    if avg_forecast_delta is not None and avg_forecast_delta > 5.0:
        signals.append(LearningSignal.IMPROVES_FORECAST.value)
    if avg_health_delta is not None and avg_health_delta > 5.0:
        signals.append(LearningSignal.IMPROVES_HEALTH.value)
    if success_rate >= 0.8:
        signals.append(LearningSignal.HIGH_SUCCESS_RATE.value)
    if failure_rate >= 0.5:
        signals.append(LearningSignal.HIGH_FAILURE_RATE.value)
    if failure_rate >= 0.7 and total_count >= 3:
        signals.append(LearningSignal.REPEATED_FAILURE.value)
    return signals
