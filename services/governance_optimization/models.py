"""services/governance_optimization/models.py

Pure Python domain models, classifiers, and computation logic.
No I/O. No SQLAlchemy. No AI. No LLMs. All outputs are deterministic and auditable.

PR 17.6D — Governance Optimization Engine
"""

from __future__ import annotations

from enum import Enum

GOVERNANCE_OPTIMIZATION_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class OptimizationType(str, Enum):
    RECOMMENDATION_RANKING = "RECOMMENDATION_RANKING"
    CONTROL_PRIORITIZATION = "CONTROL_PRIORITIZATION"
    REMEDIATION_PRIORITIZATION = "REMEDIATION_PRIORITIZATION"
    BRIDGE_PRIORITIZATION = "BRIDGE_PRIORITIZATION"
    STRATEGY_WEIGHTING = "STRATEGY_WEIGHTING"


class TargetType(str, Enum):
    RECOMMENDATION = "RECOMMENDATION"
    CONTROL = "CONTROL"
    REMEDIATION = "REMEDIATION"
    BRIDGE = "BRIDGE"
    STRATEGY = "STRATEGY"


class OptimizationConfidence(str, Enum):
    HIGH = "HIGH"  # >= 5 samples, score >= 70
    MEDIUM = "MEDIUM"  # >= 3 samples or score >= 50
    LOW = "LOW"  # < 3 samples or score < 50
    INSUFFICIENT = "INSUFFICIENT"  # 0 samples


# ---------------------------------------------------------------------------
# Pure computation functions
# ---------------------------------------------------------------------------


def clamp(value: float, lo: float, hi: float) -> float:
    """Clamp value between lo and hi."""
    return max(lo, min(hi, value))


def compute_priority_score(
    accuracy_score: float,
    avg_health_delta: float | None,
    avg_effectiveness_delta: float | None,
    failure_penalty: float,
    sample_size: int,
    deprioritize: bool = False,
) -> float:
    """Compute a 0.0–100.0 priority score for an optimization target.

    Transparent formula:
      base = accuracy_score * 60.0                    # accuracy drives 60%
      health_bonus = clamp(avg_health_delta * 2, -20, 20) if not None else 0
      eff_bonus = clamp(avg_effectiveness_delta * 1, -10, 10) if not None else 0
      size_bonus = min(sample_size / 10.0, 10.0)     # up to +10 for large samples
      penalty = failure_penalty * 20.0               # up to -20 for failure rate
      deprioritize_penalty = 15.0 if deprioritize else 0.0
      raw = base + health_bonus + eff_bonus + size_bonus - penalty - deprioritize_penalty
      return clamp(raw, 0.0, 100.0)
    """
    base = accuracy_score * 60.0
    health_bonus = (
        clamp(avg_health_delta * 2.0, -20.0, 20.0)
        if avg_health_delta is not None
        else 0.0
    )
    eff_bonus = (
        clamp(avg_effectiveness_delta * 1.0, -10.0, 10.0)
        if avg_effectiveness_delta is not None
        else 0.0
    )
    size_bonus = min(sample_size / 10.0, 10.0)
    penalty = failure_penalty * 20.0
    deprioritize_penalty = 15.0 if deprioritize else 0.0
    raw = base + health_bonus + eff_bonus + size_bonus - penalty - deprioritize_penalty
    return clamp(raw, 0.0, 100.0)


def classify_optimization_confidence(
    score: float, sample_size: int
) -> OptimizationConfidence:
    """Classify optimization confidence level based on score and sample size."""
    if sample_size == 0:
        return OptimizationConfidence.INSUFFICIENT
    if sample_size >= 5 and score >= 70.0:
        return OptimizationConfidence.HIGH
    if sample_size >= 3 or score >= 50.0:
        return OptimizationConfidence.MEDIUM
    return OptimizationConfidence.LOW
