"""services/governance_adaptive_intelligence/models.py

Pure Python domain models, classifiers, and computation logic.
No I/O. No SQLAlchemy. No AI. No LLMs. All outputs are deterministic and auditable.

PR 17.6C — Governance Adaptive Intelligence Authority
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

GOVERNANCE_ADAPTIVE_INTELLIGENCE_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class RecommendationStatus(str, Enum):
    PENDING = "PENDING"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    CLOSED = "CLOSED"


class RecommendationType(str, Enum):
    PRIORITIZE_BEST_CATEGORY = "PRIORITIZE_BEST_CATEGORY"
    ESCALATE_WORST_CATEGORY = "ESCALATE_WORST_CATEGORY"
    GOVERNANCE_REVIEW = "GOVERNANCE_REVIEW"
    IMPROVE_EFFECTIVENESS = "IMPROVE_EFFECTIVENESS"
    IMPROVE_VERIFICATION = "IMPROVE_VERIFICATION"
    IMPROVE_FRESHNESS = "IMPROVE_FRESHNESS"
    IMPROVE_FORECAST = "IMPROVE_FORECAST"


class PlaybookType(str, Enum):
    REMEDIATION = "REMEDIATION"
    VERIFICATION = "VERIFICATION"
    FRESHNESS_RECOVERY = "FRESHNESS_RECOVERY"
    CONTROL_IMPROVEMENT = "CONTROL_IMPROVEMENT"


class CalibratedConfidence(str, Enum):
    CALIBRATED_HIGH = "CALIBRATED_HIGH"
    CALIBRATED_MEDIUM = "CALIBRATED_MEDIUM"
    CALIBRATED_LOW = "CALIBRATED_LOW"
    CALIBRATED_UNKNOWN = "CALIBRATED_UNKNOWN"


class StrategyProfile(str, Enum):
    HEALTHCARE = "HEALTHCARE"
    FINANCIAL = "FINANCIAL"
    INSURANCE = "INSURANCE"
    GOVERNMENT = "GOVERNMENT"
    LEGAL = "LEGAL"
    MSP = "MSP"
    GENERAL = "GENERAL"


# ---------------------------------------------------------------------------
# Pure deterministic functions
# ---------------------------------------------------------------------------


def compute_accuracy_score(successful: int, executed: int) -> float:
    """Accuracy score = successful / executed if executed > 0 else 0.0."""
    if executed <= 0:
        return 0.0
    return round(successful / executed, 4)


def classify_calibrated_confidence(
    accuracy_score: float, total_executed: int
) -> CalibratedConfidence:
    """Classify calibrated confidence from accuracy score and sample size.

    CALIBRATED_UNKNOWN if total_executed < 3 (insufficient data).
    CALIBRATED_HIGH    if accuracy_score >= 0.75
    CALIBRATED_MEDIUM  if accuracy_score >= 0.50
    CALIBRATED_LOW     if accuracy_score >= 0.25
    CALIBRATED_UNKNOWN if accuracy_score < 0.25
    """
    if total_executed < 3:
        return CalibratedConfidence.CALIBRATED_UNKNOWN
    if accuracy_score >= 0.75:
        return CalibratedConfidence.CALIBRATED_HIGH
    if accuracy_score >= 0.50:
        return CalibratedConfidence.CALIBRATED_MEDIUM
    if accuracy_score >= 0.25:
        return CalibratedConfidence.CALIBRATED_LOW
    return CalibratedConfidence.CALIBRATED_UNKNOWN


def compute_avg_delta(values: list[Optional[float]]) -> Optional[float]:
    """Average of non-None values. Returns None if all are None."""
    valid = [v for v in values if v is not None]
    if not valid:
        return None
    return round(sum(valid) / len(valid), 4)


_INDUSTRY_MAP: dict[str, StrategyProfile] = {
    "health": StrategyProfile.HEALTHCARE,
    "medical": StrategyProfile.HEALTHCARE,
    "hospital": StrategyProfile.HEALTHCARE,
    "clinic": StrategyProfile.HEALTHCARE,
    "finance": StrategyProfile.FINANCIAL,
    "financial": StrategyProfile.FINANCIAL,
    "bank": StrategyProfile.FINANCIAL,
    "banking": StrategyProfile.FINANCIAL,
    "investment": StrategyProfile.FINANCIAL,
    "insurance": StrategyProfile.INSURANCE,
    "insurer": StrategyProfile.INSURANCE,
    "government": StrategyProfile.GOVERNMENT,
    "gov": StrategyProfile.GOVERNMENT,
    "federal": StrategyProfile.GOVERNMENT,
    "state": StrategyProfile.GOVERNMENT,
    "legal": StrategyProfile.LEGAL,
    "law": StrategyProfile.LEGAL,
    "attorney": StrategyProfile.LEGAL,
    "msp": StrategyProfile.MSP,
    "managed service": StrategyProfile.MSP,
}


def classify_strategy_profile(industry_hint: Optional[str]) -> StrategyProfile:
    """Map an industry hint string to a StrategyProfile enum value."""
    if industry_hint is None:
        return StrategyProfile.GENERAL
    hint_lower = industry_hint.lower()
    for keyword, profile in _INDUSTRY_MAP.items():
        if keyword in hint_lower:
            return profile
    return StrategyProfile.GENERAL
