"""Governance impact analysis — pure deterministic projections."""

from __future__ import annotations

from typing import Any

from services.governance_orchestration.models import ChangeType, ImpactLevel


_IMPACT_WEIGHTS: dict[str, float] = {
    ChangeType.EVIDENCE_CHANGE.value: 15.0,
    ChangeType.CONTROL_CHANGE.value: 25.0,
    ChangeType.RISK_CHANGE.value: 30.0,
    ChangeType.POLICY_CHANGE.value: 10.0,
    ChangeType.FRAMEWORK_CHANGE.value: 20.0,
    ChangeType.TRUST_CHANGE.value: 20.0,
}


def analyze_impact(
    db: Any, tenant_id: str, change_type: str, change_data: dict[str, Any]
) -> dict[str, Any]:
    """Return an impact analysis dict for a proposed change.

    Deterministic — no DB writes, safe cross-authority reads only.
    """
    if not isinstance(change_data, dict):
        change_data = {}
    weight = _IMPACT_WEIGHTS.get(change_type, 5.0)
    magnitude = float(change_data.get("magnitude") or 1.0)
    magnitude = max(0.0, min(magnitude, 3.0))
    score_delta = round(-weight * magnitude, 2)
    control_delta = estimate_control_effectiveness_delta(change_data)
    risk_reduction = estimate_risk_reduction(change_data)
    if score_delta <= -30:
        impact_level = ImpactLevel.CRITICAL.value
    elif score_delta <= -15:
        impact_level = ImpactLevel.HIGH.value
    elif score_delta <= -5:
        impact_level = ImpactLevel.MEDIUM.value
    elif score_delta < 0:
        impact_level = ImpactLevel.LOW.value
    else:
        impact_level = ImpactLevel.NONE.value
    return {
        "tenant_id": tenant_id,
        "change_type": change_type,
        "impact_level": impact_level,
        "governance_score_delta": score_delta,
        "control_effectiveness_delta": control_delta,
        "risk_reduction": risk_reduction,
        "affected_controls": int(change_data.get("affected_controls") or 0),
        "affected_evidence": int(change_data.get("affected_evidence") or 0),
        "recommendations": _recommendations(impact_level, change_type),
    }


def compute_governance_score_delta(
    current: dict[str, Any], projected: dict[str, Any]
) -> float:
    """Return projected − current."""
    if not isinstance(current, dict) or not isinstance(projected, dict):
        return 0.0
    try:
        return round(float(projected.get("score", 0)) - float(current.get("score", 0)), 2)
    except (TypeError, ValueError):
        return 0.0


def estimate_control_effectiveness_delta(change_data: dict[str, Any]) -> float:
    if not isinstance(change_data, dict):
        return 0.0
    try:
        return round(float(change_data.get("control_delta") or 0.0), 2)
    except (TypeError, ValueError):
        return 0.0


def estimate_risk_reduction(change_data: dict[str, Any]) -> float:
    if not isinstance(change_data, dict):
        return 0.0
    try:
        return round(float(change_data.get("risk_reduction") or 0.0), 2)
    except (TypeError, ValueError):
        return 0.0


def _recommendations(impact_level: str, change_type: str) -> list[str]:
    recs: list[str] = []
    if impact_level in {ImpactLevel.CRITICAL.value, ImpactLevel.HIGH.value}:
        recs.append("Trigger executive review")
        recs.append("Initiate reassessment")
    if change_type == ChangeType.CONTROL_CHANGE.value:
        recs.append("Recompute control effectiveness")
    if change_type == ChangeType.EVIDENCE_CHANGE.value:
        recs.append("Refresh evidence sufficiency")
    if change_type == ChangeType.TRUST_CHANGE.value:
        recs.append("Verify transparency ledger consistency")
    if not recs:
        recs.append("Monitor")
    return recs
