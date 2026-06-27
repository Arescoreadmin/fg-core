"""services/governance_chain/models.py — Domain models for Governance Chain Authority.

All computation is deterministic. No AI. No heuristics without documentation.

PR 17.6 — Canonical Governance Chain Authority
PR 17.6A — Governance Chain Completion
"""

from __future__ import annotations

import math
from enum import Enum
from typing import Optional

GOVERNANCE_CHAIN_VERSION = "2.0"


# ---------------------------------------------------------------------------
# Event types emitted by the governance chain
# ---------------------------------------------------------------------------


class ChainEventType(str, Enum):
    EVIDENCE_REGISTERED = "EVIDENCE_REGISTERED"
    VERIFICATION_CREATED = "VERIFICATION_CREATED"
    VERIFICATION_COMPLETED = "VERIFICATION_COMPLETED"
    FRESHNESS_UPDATED = "FRESHNESS_UPDATED"
    EFFECTIVENESS_RECALCULATED = "EFFECTIVENESS_RECALCULATED"
    EXPLANATION_REGENERATED = "EXPLANATION_REGENERATED"
    ACTION_CREATED = "ACTION_CREATED"
    ACTION_ACCEPTED = "ACTION_ACCEPTED"
    REMEDIATION_CREATED = "REMEDIATION_CREATED"
    REMEDIATION_COMPLETED = "REMEDIATION_COMPLETED"
    OUTCOME_RECORDED = "OUTCOME_RECORDED"
    REPORT_GENERATED = "REPORT_GENERATED"


# ---------------------------------------------------------------------------
# Bridge types — each bridge connects two adjacent authorities
# ---------------------------------------------------------------------------


class BridgeType(str, Enum):
    ASSESSMENT_TO_EVIDENCE = "ASSESSMENT_TO_EVIDENCE"
    EVIDENCE_TO_VERIFICATION = "EVIDENCE_TO_VERIFICATION"
    VERIFICATION_TO_FRESHNESS = "VERIFICATION_TO_FRESHNESS"
    FRESHNESS_TO_EFFECTIVENESS = "FRESHNESS_TO_EFFECTIVENESS"
    EFFECTIVENESS_TO_EXPLAINABILITY = "EFFECTIVENESS_TO_EXPLAINABILITY"
    ACTION_TO_REMEDIATION = "ACTION_TO_REMEDIATION"
    REMEDIATION_TO_OUTCOME = "REMEDIATION_TO_OUTCOME"
    ALL_TO_REPORTING = "ALL_TO_REPORTING"


# Maps bridge type → (source_authority, target_authority)
BRIDGE_AUTHORITIES: dict[str, tuple[str, str]] = {
    BridgeType.ASSESSMENT_TO_EVIDENCE.value: (
        "field_assessment",
        "evidence_authority",
    ),
    BridgeType.EVIDENCE_TO_VERIFICATION.value: (
        "evidence_authority",
        "verification_authority",
    ),
    BridgeType.VERIFICATION_TO_FRESHNESS.value: (
        "verification_authority",
        "evidence_freshness_authority",
    ),
    BridgeType.FRESHNESS_TO_EFFECTIVENESS.value: (
        "evidence_freshness_authority",
        "control_effectiveness",
    ),
    BridgeType.EFFECTIVENESS_TO_EXPLAINABILITY.value: (
        "control_effectiveness",
        "control_effectiveness_explainability",
    ),
    BridgeType.ACTION_TO_REMEDIATION.value: (
        "control_effectiveness_explainability",
        "remediation",
    ),
    BridgeType.REMEDIATION_TO_OUTCOME.value: (
        "remediation",
        "remediation_effectiveness",
    ),
    BridgeType.ALL_TO_REPORTING.value: (
        "governance_chain",
        "governance_reporting",
    ),
}


# ---------------------------------------------------------------------------
# Execution results
# ---------------------------------------------------------------------------


class ChainExecutionResult(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILURE = "FAILURE"
    SKIPPED_UNAVAILABLE = "SKIPPED_UNAVAILABLE"
    NOOP_SAFE = "NOOP_SAFE"


# ---------------------------------------------------------------------------
# Governance health
# ---------------------------------------------------------------------------


class GovernanceHealthRating(str, Enum):
    EXCELLENT = "EXCELLENT"
    GOOD = "GOOD"
    ADEQUATE = "ADEQUATE"
    WEAK = "WEAK"
    CRITICAL = "CRITICAL"


# Health component weights — must sum to 1.0
HEALTH_WEIGHT_VERIFICATION: float = 0.25
HEALTH_WEIGHT_FRESHNESS: float = 0.25
HEALTH_WEIGHT_EFFECTIVENESS: float = 0.25
HEALTH_WEIGHT_REMEDIATION: float = 0.15
HEALTH_WEIGHT_FORECAST: float = 0.10


def compute_governance_health_score(
    verification_health: float,
    freshness_health: float,
    effectiveness_health: float,
    remediation_health: float,
    forecast_health: float,
) -> float:
    """Compute weighted governance health score in [0, 100]."""
    raw = (
        verification_health * HEALTH_WEIGHT_VERIFICATION
        + freshness_health * HEALTH_WEIGHT_FRESHNESS
        + effectiveness_health * HEALTH_WEIGHT_EFFECTIVENESS
        + remediation_health * HEALTH_WEIGHT_REMEDIATION
        + forecast_health * HEALTH_WEIGHT_FORECAST
    )
    return round(min(100.0, max(0.0, raw)), 2)


def classify_governance_health(score: float) -> GovernanceHealthRating:
    """Classify a health score into a rating tier."""
    if score >= 85.0:
        return GovernanceHealthRating.EXCELLENT
    elif score >= 70.0:
        return GovernanceHealthRating.GOOD
    elif score >= 55.0:
        return GovernanceHealthRating.ADEQUATE
    elif score >= 40.0:
        return GovernanceHealthRating.WEAK
    else:
        return GovernanceHealthRating.CRITICAL


# Default health when no data is available (not zero — absence ≠ failure)
HEALTH_DEFAULT_NO_DATA: float = 75.0


# ---------------------------------------------------------------------------
# Governance chain v2: momentum, stability, confidence
# ---------------------------------------------------------------------------


def compute_governance_momentum(
    current_score: float,
    previous_score: Optional[float],
) -> float:
    """Momentum: direction of health score change. 50=neutral, >50=improving."""
    if previous_score is None:
        return 50.0
    delta = current_score - previous_score
    # Map [-100, +100] delta to [0, 100] momentum
    return round(min(100.0, max(0.0, 50.0 + delta)), 2)


def compute_governance_stability(scores: list[float]) -> float:
    """Stability: inverse of score variance across recent snapshots."""
    if len(scores) < 2:
        return 50.0
    mean = sum(scores) / len(scores)
    variance = sum((s - mean) ** 2 for s in scores) / len(scores)
    stddev = math.sqrt(variance)
    # Higher stddev = lower stability; clamp to [0, 100]
    return round(min(100.0, max(0.0, 100.0 - stddev * 2.0)), 2)


def compute_governance_confidence(
    missing_input_count: int,
    total_executions: int,
    failed_executions: int,
    skipped_executions: int,
) -> float:
    """Confidence: starts at 100, reduced by missing inputs and execution failures."""
    score = 100.0
    # Each missing input deducts 10, capped at 50
    score -= min(50.0, missing_input_count * 10.0)
    if total_executions > 0:
        fail_ratio = failed_executions / total_executions
        skip_ratio = skipped_executions / total_executions
        score -= fail_ratio * 30.0
        score -= skip_ratio * 10.0
    return round(min(100.0, max(0.0, score)), 2)
