"""services/control_effectiveness_explainability/models.py

Pure Python domain models, classifiers, and computation logic.
No I/O. No SQLAlchemy.

PR 16.5.1 — Control Effectiveness Explainability & Governance Action Engine
"""

from __future__ import annotations

from enum import Enum
from typing import NamedTuple

from services.control_effectiveness.models import (
    WEIGHT_COVERAGE,
    WEIGHT_EVIDENCE_DENSITY,
    WEIGHT_EXCEPTION,
    WEIGHT_FORECAST,
    WEIGHT_FRESHNESS,
    WEIGHT_TREND,
    WEIGHT_VERIFICATION,
)

EXPLAINABILITY_VERSION = "1.0"

IMPACT_POSITIVE_THRESHOLD = 70.0
IMPACT_NEGATIVE_THRESHOLD = 50.0


class SignalImpact(str, Enum):
    POSITIVE = "POSITIVE"
    NEGATIVE = "NEGATIVE"
    NEUTRAL = "NEUTRAL"


class GovernancePriority(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RootCauseType(str, Enum):
    VERIFICATION_FAILURES = "VERIFICATION_FAILURES"
    FRESHNESS_DECLINE = "FRESHNESS_DECLINE"
    COVERAGE_GAPS = "COVERAGE_GAPS"
    DECLINING_TREND = "DECLINING_TREND"
    CRITICAL_TREND = "CRITICAL_TREND"
    ACTIVE_EXCEPTIONS = "ACTIVE_EXCEPTIONS"
    LOW_EVIDENCE_DENSITY = "LOW_EVIDENCE_DENSITY"
    GOVERNANCE_HEALTH_RISK = "GOVERNANCE_HEALTH_RISK"
    NEGATIVE_FORECAST = "NEGATIVE_FORECAST"
    STRONG_VERIFICATION = "STRONG_VERIFICATION"
    HIGH_FRESHNESS = "HIGH_FRESHNESS"
    STRONG_COVERAGE = "STRONG_COVERAGE"
    IMPROVING_TREND = "IMPROVING_TREND"
    CLEAN_EXCEPTION_RECORD = "CLEAN_EXCEPTION_RECORD"
    HIGH_EVIDENCE_DENSITY = "HIGH_EVIDENCE_DENSITY"
    POSITIVE_FORECAST = "POSITIVE_FORECAST"


class ActionType(str, Enum):
    REVIEW_VERIFICATION_WORKFLOW = "REVIEW_VERIFICATION_WORKFLOW"
    REFRESH_EVIDENCE = "REFRESH_EVIDENCE"
    COLLECT_ADDITIONAL_EVIDENCE = "COLLECT_ADDITIONAL_EVIDENCE"
    RESOLVE_ACTIVE_EXCEPTIONS = "RESOLVE_ACTIVE_EXCEPTIONS"
    REVIEW_GOVERNANCE_HEALTH = "REVIEW_GOVERNANCE_HEALTH"
    INVESTIGATE_DECLINING_TREND = "INVESTIGATE_DECLINING_TREND"
    ADDRESS_FORECAST_RISK = "ADDRESS_FORECAST_RISK"
    MONITOR_TREND = "MONITOR_TREND"


class RankType(str, Enum):
    TOP = "TOP"
    WEAKEST = "WEAKEST"
    FASTEST_IMPROVING = "FASTEST_IMPROVING"
    FASTEST_DECLINING = "FASTEST_DECLINING"
    HIGHEST_RISK = "HIGHEST_RISK"
    MOST_FRAGILE = "MOST_FRAGILE"
    MOST_VALUABLE = "MOST_VALUABLE"


class ComponentWeight(NamedTuple):
    name: str
    weight: float


COMPONENT_WEIGHTS: list[ComponentWeight] = [
    ComponentWeight("coverage", WEIGHT_COVERAGE),
    ComponentWeight("verification", WEIGHT_VERIFICATION),
    ComponentWeight("freshness", WEIGHT_FRESHNESS),
    ComponentWeight("trend", WEIGHT_TREND),
    ComponentWeight("forecast", WEIGHT_FORECAST),
    ComponentWeight("evidence_density", WEIGHT_EVIDENCE_DENSITY),
    ComponentWeight("exception", WEIGHT_EXCEPTION),
]

PRIORITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
}

RISK_SEVERITY: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
}


def _score(val: float | None, default: float = 50.0) -> float:
    return val if val is not None else default


# ---------------------------------------------------------------------------
# Priority classification
# ---------------------------------------------------------------------------


def classify_priority(
    effectiveness_score: float,
    effectiveness_level: str,
    trend_direction: str | None,
    forecast_score: float | None,
    exception_score: float | None,
) -> GovernancePriority:
    """Deterministic governance priority. Same inputs → same output."""
    if effectiveness_level == "INEFFECTIVE":
        return GovernancePriority.CRITICAL
    if effectiveness_score < 40:
        return GovernancePriority.CRITICAL
    if effectiveness_level == "WEAK" and trend_direction == "CRITICAL":
        return GovernancePriority.CRITICAL
    if effectiveness_score < 60:
        return GovernancePriority.HIGH
    if effectiveness_score < 75 and trend_direction in ("DEGRADING", "CRITICAL"):
        return GovernancePriority.HIGH
    if exception_score is not None and exception_score < 60:
        return GovernancePriority.HIGH
    if effectiveness_score < 75:
        return GovernancePriority.MEDIUM
    if trend_direction == "CRITICAL":
        return GovernancePriority.HIGH
    if trend_direction == "DEGRADING":
        return GovernancePriority.MEDIUM
    if forecast_score is not None and forecast_score < 50:
        return GovernancePriority.MEDIUM
    return GovernancePriority.LOW


# ---------------------------------------------------------------------------
# Score contributions
# ---------------------------------------------------------------------------


def compute_contributions(
    coverage_score: float | None,
    verification_score: float | None,
    freshness_score: float | None,
    trend_score: float | None,
    forecast_score: float | None,
    evidence_density_score: float | None,
    exception_score: float | None,
) -> list[dict]:
    """Compute per-component contribution breakdown. Returns list of dicts."""
    raw_scores = [
        _score(coverage_score, 0.0),
        _score(verification_score, 0.0),
        _score(freshness_score, 50.0),
        _score(trend_score, 50.0),
        _score(forecast_score, 65.0),
        _score(evidence_density_score, 0.0),
        _score(exception_score, 100.0),
    ]
    weighted = [rs * cw.weight for rs, cw in zip(raw_scores, COMPONENT_WEIGHTS)]
    total_weighted = sum(weighted)

    results = []
    for i, cw in enumerate(COMPONENT_WEIGHTS):
        rs = raw_scores[i]
        ws = weighted[i]
        pct = round(ws / total_weighted * 100.0, 2) if total_weighted > 0 else 0.0
        if rs >= IMPACT_POSITIVE_THRESHOLD:
            impact = SignalImpact.POSITIVE.value
        elif rs < IMPACT_NEGATIVE_THRESHOLD:
            impact = SignalImpact.NEGATIVE.value
        else:
            impact = SignalImpact.NEUTRAL.value
        results.append(
            {
                "component_name": cw.name,
                "raw_score": round(rs, 2),
                "weight": cw.weight,
                "weighted_score": round(ws, 2),
                "contribution_percentage": pct,
                "impact": impact,
            }
        )
    return results


# ---------------------------------------------------------------------------
# Root cause analysis
# ---------------------------------------------------------------------------

_SIGNAL_DESCRIPTIONS: dict[str, str] = {
    "VERIFICATION_FAILURES": "Repeated or frequent verification failures detected.",
    "FRESHNESS_DECLINE": "Evidence freshness is below acceptable threshold.",
    "COVERAGE_GAPS": "Evidence coverage is insufficient for this control.",
    "DECLINING_TREND": "Control effectiveness is on a declining trend.",
    "CRITICAL_TREND": "Control effectiveness trend is in critical decline.",
    "ACTIVE_EXCEPTIONS": "Active governance exceptions are reducing control strength.",
    "LOW_EVIDENCE_DENSITY": "Evidence density is insufficient for reliable assurance.",
    "GOVERNANCE_HEALTH_RISK": "Governance health indicators show elevated risk.",
    "NEGATIVE_FORECAST": "Forward-looking indicators suggest continued decline.",
    "STRONG_VERIFICATION": "Verification SLA is being met consistently.",
    "HIGH_FRESHNESS": "Evidence freshness is at a healthy level.",
    "STRONG_COVERAGE": "Evidence coverage exceeds requirements.",
    "IMPROVING_TREND": "Control effectiveness is on an improving trend.",
    "CLEAN_EXCEPTION_RECORD": "No active governance exceptions.",
    "HIGH_EVIDENCE_DENSITY": "Evidence density provides strong assurance depth.",
    "POSITIVE_FORECAST": "Forward-looking indicators suggest continued improvement.",
}

_SIGNAL_SEVERITY: dict[str, str] = {
    "CRITICAL_TREND": "CRITICAL",
    "VERIFICATION_FAILURES": "HIGH",
    "FRESHNESS_DECLINE": "HIGH",
    "COVERAGE_GAPS": "HIGH",
    "GOVERNANCE_HEALTH_RISK": "HIGH",
    "DECLINING_TREND": "MEDIUM",
    "ACTIVE_EXCEPTIONS": "MEDIUM",
    "LOW_EVIDENCE_DENSITY": "MEDIUM",
    "NEGATIVE_FORECAST": "MEDIUM",
    "STRONG_VERIFICATION": "INFORMATIONAL",
    "HIGH_FRESHNESS": "INFORMATIONAL",
    "STRONG_COVERAGE": "INFORMATIONAL",
    "IMPROVING_TREND": "INFORMATIONAL",
    "CLEAN_EXCEPTION_RECORD": "INFORMATIONAL",
    "HIGH_EVIDENCE_DENSITY": "INFORMATIONAL",
    "POSITIVE_FORECAST": "INFORMATIONAL",
}


def compute_root_causes(
    verification_score: float | None,
    freshness_score: float | None,
    coverage_score: float | None,
    trend_direction: str | None,
    exception_score: float | None,
    evidence_density_score: float | None,
    governance_health_score: float | None,
    forecast_score: float | None,
) -> list[dict]:
    """Rules-based root cause signal generation. Returns list of dicts."""
    signals: list[dict] = []

    def _add(rct: str, impact: str, impact_score: float) -> None:
        signals.append(
            {
                "root_cause_type": rct,
                "impact": impact,
                "severity": _SIGNAL_SEVERITY.get(rct, "MEDIUM"),
                "impact_score": round(impact_score, 2),
                "description": _SIGNAL_DESCRIPTIONS.get(rct, rct),
            }
        )

    vs = _score(verification_score, 0.0)
    if vs < 60:
        _add("VERIFICATION_FAILURES", "NEGATIVE", (60 - vs) * 0.5)
    elif vs >= 80:
        _add("STRONG_VERIFICATION", "POSITIVE", (vs - 80) * 0.5)

    fs = _score(freshness_score, 50.0)
    if fs < 60:
        _add("FRESHNESS_DECLINE", "NEGATIVE", (60 - fs) * 0.4)
    elif fs >= 85:
        _add("HIGH_FRESHNESS", "POSITIVE", (fs - 85) * 0.4)

    cs = _score(coverage_score, 0.0)
    if cs < 60:
        _add("COVERAGE_GAPS", "NEGATIVE", (60 - cs) * 0.3)
    elif cs >= 80:
        _add("STRONG_COVERAGE", "POSITIVE", (cs - 80) * 0.3)

    if trend_direction == "CRITICAL":
        _add("CRITICAL_TREND", "NEGATIVE", 30.0)
    elif trend_direction == "DEGRADING":
        _add("DECLINING_TREND", "NEGATIVE", 15.0)
    elif trend_direction == "IMPROVING":
        _add("IMPROVING_TREND", "POSITIVE", 15.0)

    es = _score(exception_score, 100.0)
    if es < 70:
        _add("ACTIVE_EXCEPTIONS", "NEGATIVE", (70 - es) * 0.4)
    elif es >= 95:
        _add("CLEAN_EXCEPTION_RECORD", "POSITIVE", 10.0)

    eds = _score(evidence_density_score, 0.0)
    if eds < 50:
        _add("LOW_EVIDENCE_DENSITY", "NEGATIVE", (50 - eds) * 0.3)
    elif eds >= 80:
        _add("HIGH_EVIDENCE_DENSITY", "POSITIVE", (eds - 80) * 0.3)

    ghs = _score(governance_health_score, 50.0)
    if ghs < 60:
        _add("GOVERNANCE_HEALTH_RISK", "NEGATIVE", (60 - ghs) * 0.5)

    fcs = _score(forecast_score, 65.0)
    if fcs < 50:
        _add("NEGATIVE_FORECAST", "NEGATIVE", (50 - fcs) * 0.3)
    elif fcs >= 80:
        _add("POSITIVE_FORECAST", "POSITIVE", (fcs - 80) * 0.3)

    negatives = sorted(
        [s for s in signals if s["impact"] == "NEGATIVE"],
        key=lambda x: x["impact_score"],
        reverse=True,
    )
    positives = sorted(
        [s for s in signals if s["impact"] == "POSITIVE"],
        key=lambda x: x["impact_score"],
        reverse=True,
    )
    return negatives + positives


# ---------------------------------------------------------------------------
# Governance actions
# ---------------------------------------------------------------------------

_ACTION_DESCRIPTIONS: dict[str, str] = {
    "REVIEW_VERIFICATION_WORKFLOW": "Review and remediate verification workflow to reduce failure rate.",
    "REFRESH_EVIDENCE": "Refresh stale evidence artifacts to improve freshness score.",
    "COLLECT_ADDITIONAL_EVIDENCE": "Collect additional evidence to close coverage gaps.",
    "RESOLVE_ACTIVE_EXCEPTIONS": "Resolve active governance exceptions to restore control strength.",
    "REVIEW_GOVERNANCE_HEALTH": "Review governance health indicators and address overdue items.",
    "INVESTIGATE_DECLINING_TREND": "Investigate the root cause of the declining effectiveness trend.",
    "ADDRESS_FORECAST_RISK": "Address leading indicators suggesting future effectiveness decline.",
    "MONITOR_TREND": "Continue monitoring trend indicators for early warning signals.",
}

_ACTION_RATIONALE: dict[str, str] = {
    "REVIEW_VERIFICATION_WORKFLOW": "Verification score is below threshold, indicating repeated failures that reduce control assurance.",
    "REFRESH_EVIDENCE": "Freshness score is below threshold, indicating evidence is becoming stale and less reliable.",
    "COLLECT_ADDITIONAL_EVIDENCE": "Coverage score is below threshold, indicating insufficient evidence for this control.",
    "RESOLVE_ACTIVE_EXCEPTIONS": "Exception score is below threshold, indicating active governance exceptions that weaken control effectiveness.",
    "REVIEW_GOVERNANCE_HEALTH": "Governance health score is below threshold, indicating overdue reviews or open compliance items.",
    "INVESTIGATE_DECLINING_TREND": "Trend direction is declining or critical, indicating systemic deterioration.",
    "ADDRESS_FORECAST_RISK": "Forecast score is below threshold, indicating projected future decline.",
    "MONITOR_TREND": "Trend shows early warning signals that may indicate future deterioration.",
}


def compute_governance_actions(
    verification_score: float | None,
    freshness_score: float | None,
    coverage_score: float | None,
    exception_score: float | None,
    governance_health_score: float | None,
    trend_direction: str | None,
    forecast_score: float | None,
) -> list[dict]:
    """Deterministic governance action generation. Returns list sorted by priority."""
    actions: list[dict] = []

    def _add(at: str, priority: str) -> None:
        actions.append(
            {
                "action_type": at,
                "priority": priority,
                "description": _ACTION_DESCRIPTIONS[at],
                "rationale": _ACTION_RATIONALE[at],
            }
        )

    vs = _score(verification_score, 0.0)
    if vs < 40:
        _add("REVIEW_VERIFICATION_WORKFLOW", "CRITICAL")
    elif vs < 60:
        _add("REVIEW_VERIFICATION_WORKFLOW", "HIGH")

    fs = _score(freshness_score, 50.0)
    if fs < 40:
        _add("REFRESH_EVIDENCE", "CRITICAL")
    elif fs < 60:
        _add("REFRESH_EVIDENCE", "HIGH")

    cs = _score(coverage_score, 0.0)
    if cs < 50:
        _add("COLLECT_ADDITIONAL_EVIDENCE", "HIGH")
    elif cs < 70:
        _add("COLLECT_ADDITIONAL_EVIDENCE", "MEDIUM")

    es = _score(exception_score, 100.0)
    if es < 60:
        _add("RESOLVE_ACTIVE_EXCEPTIONS", "HIGH")
    elif es < 80:
        _add("RESOLVE_ACTIVE_EXCEPTIONS", "MEDIUM")

    ghs = _score(governance_health_score, 50.0)
    if ghs < 50:
        _add("REVIEW_GOVERNANCE_HEALTH", "HIGH")
    elif ghs < 70:
        _add("REVIEW_GOVERNANCE_HEALTH", "MEDIUM")

    if trend_direction == "CRITICAL":
        _add("INVESTIGATE_DECLINING_TREND", "CRITICAL")
    elif trend_direction == "DEGRADING":
        _add("INVESTIGATE_DECLINING_TREND", "HIGH")

    fcs = _score(forecast_score, 65.0)
    if fcs < 40:
        _add("ADDRESS_FORECAST_RISK", "HIGH")
    elif fcs < 50:
        _add("ADDRESS_FORECAST_RISK", "MEDIUM")

    if not actions and trend_direction == "STABLE" and fcs < 65:
        _add("MONITOR_TREND", "LOW")

    actions.sort(key=lambda x: PRIORITY_ORDER[x["priority"]])
    return actions


# ---------------------------------------------------------------------------
# Narrative generation
# ---------------------------------------------------------------------------

_LEVEL_PHRASES: dict[str, str] = {
    "HIGHLY_EFFECTIVE": "highly effective",
    "EFFECTIVE": "effective",
    "ADEQUATE": "adequate",
    "WEAK": "weak",
    "INEFFECTIVE": "ineffective",
}

_TREND_PHRASES: dict[str, str] = {
    "IMPROVING": "Control effectiveness has been improving over the past 30 days.",
    "STABLE": "Control effectiveness has remained stable.",
    "DEGRADING": "Control effectiveness has been declining over the past 30 days.",
    "CRITICAL": "Control effectiveness is in critical decline and requires immediate attention.",
}


def generate_narrative(
    effectiveness_score: float,
    effectiveness_level: str,
    trend_direction: str | None,
    root_causes: list[dict],
    actions: list[dict],
) -> str:
    """Template-driven, auditable control health narrative. No generative AI."""
    level_phrase = _LEVEL_PHRASES.get(effectiveness_level, effectiveness_level.lower())
    parts = [
        f"This control is {level_phrase} with a score of {int(effectiveness_score)}."
    ]

    if trend_direction and trend_direction in _TREND_PHRASES:
        parts.append(_TREND_PHRASES[trend_direction])

    positives = [rc for rc in root_causes if rc["impact"] == "POSITIVE"][:2]
    negatives = [rc for rc in root_causes if rc["impact"] == "NEGATIVE"][:2]

    if positives:
        descs = " and ".join(p["description"].rstrip(".").lower() for p in positives)
        parts.append(f"Positive factors include {descs}.")

    if negatives:
        descs = " and ".join(n["description"].rstrip(".").lower() for n in negatives)
        parts.append(f"Risk factors include {descs}.")

    if actions:
        top = actions[0]
        parts.append(
            f"Recommended action: {top['description'].rstrip('.')}"
            f" (priority: {top['priority'].lower()})."
        )

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Change detection
# ---------------------------------------------------------------------------


def detect_change(
    score_delta_7d: float | None,
    score_delta_30d: float | None,
    score_delta_90d: float | None,
) -> dict:
    """Produce a change detection summary from score deltas."""
    primary = score_delta_30d if score_delta_30d is not None else score_delta_7d

    if primary is None:
        return {
            "status": "STABLE",
            "explanation": "Insufficient history to determine trend.",
            "delta_7d": score_delta_7d,
            "delta_30d": score_delta_30d,
            "delta_90d": score_delta_90d,
        }

    if primary > 10:
        status = "IMPROVED"
        explanation = f"Score improved by {primary:+.1f} points over the measurement period."
    elif primary > 3:
        status = "IMPROVING"
        explanation = f"Score has shown moderate improvement of {primary:+.1f} points."
    elif primary < -10:
        status = "CRITICAL"
        explanation = (
            f"Score declined by {abs(primary):.1f} points — immediate attention required."
        )
    elif primary < -3:
        status = "DECLINING"
        explanation = f"Score has declined by {abs(primary):.1f} points over the measurement period."
    else:
        status = "STABLE"
        explanation = "Score has remained stable."

    return {
        "status": status,
        "explanation": explanation,
        "delta_7d": score_delta_7d,
        "delta_30d": score_delta_30d,
        "delta_90d": score_delta_90d,
    }
