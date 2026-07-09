"""Policy-as-code evaluation for the Governance Orchestration Authority.

Pure functions. No DB. No I/O. Determinism required.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from services.governance_orchestration.models import PolicyRiskLevel


_REASSESSMENT_INTERVAL_DAYS: dict[str, int] = {
    PolicyRiskLevel.CRITICAL.value: 30,
    PolicyRiskLevel.HIGH.value: 60,
    PolicyRiskLevel.MEDIUM.value: 90,
    PolicyRiskLevel.LOW.value: 180,
}


_ALLOWED_ACTIONS = {
    "REASSESS",
    "APPROVE_REQUIRED",
    "ESCALATE",
    "NO_ACTION",
    "SUSPEND",
    "REMEDIATE",
}


def evaluate_policy(
    policy_data: dict[str, Any], context: dict[str, Any]
) -> dict[str, Any]:
    """Deterministic policy evaluation.

    Returns a dict with the shape:
        {decision, risk_level, actions, reason}
    """
    if not isinstance(policy_data, dict):
        policy_data = {}
    if not isinstance(context, dict):
        context = {}
    risk_level = str(policy_data.get("risk_level") or PolicyRiskLevel.MEDIUM.value)
    if risk_level not in _REASSESSMENT_INTERVAL_DAYS:
        risk_level = PolicyRiskLevel.MEDIUM.value

    triggers = context.get("triggers") or []
    if not isinstance(triggers, list):
        triggers = []

    try:
        score = float(context.get("governance_score", 100))
    except (TypeError, ValueError):
        score = 100.0
    try:
        control_health = float(context.get("control_health_pct", 100))
    except (TypeError, ValueError):
        control_health = 100.0
    try:
        evidence_pct = float(context.get("evidence_sufficiency_pct", 100))
    except (TypeError, ValueError):
        evidence_pct = 100.0

    reason_parts: list[str] = []
    actions: list[str] = []
    decision = "ALLOW"

    if risk_level == PolicyRiskLevel.CRITICAL.value:
        actions.append("APPROVE_REQUIRED")
        actions.append("ESCALATE")
        decision = "APPROVE_REQUIRED"
        reason_parts.append("CRITICAL risk level requires approval and escalation")
    elif risk_level == PolicyRiskLevel.HIGH.value:
        actions.append("APPROVE_REQUIRED")
        decision = "APPROVE_REQUIRED"
        reason_parts.append("HIGH risk level requires approval")

    if score < 60:
        actions.append("REASSESS")
        decision = "REASSESS" if decision == "ALLOW" else decision
        reason_parts.append("governance score below reassessment threshold")
    if control_health < 60:
        actions.append("REMEDIATE")
        reason_parts.append("control health degraded")
    if evidence_pct < 60:
        actions.append("REASSESS")
        reason_parts.append("evidence sufficiency degraded")

    if triggers:
        actions.append("REASSESS")
        reason_parts.append(f"{len(triggers)} active trigger(s)")

    if not actions:
        actions.append("NO_ACTION")

    # De-dupe while preserving order and filter allowed
    seen: set[str] = set()
    normalized: list[str] = []
    for a in actions:
        if a in _ALLOWED_ACTIONS and a not in seen:
            seen.add(a)
            normalized.append(a)

    return {
        "decision": decision,
        "risk_level": risk_level,
        "actions": normalized,
        "reason": "; ".join(reason_parts) if reason_parts else "policy evaluated",
    }


def compute_reassessment_schedule(
    policy_data: dict[str, Any], risk_level: str
) -> dict[str, Any]:
    """Compute the next reassessment schedule for a policy + risk level.

    Returns {next_reassessment_date, interval_days, approval_required}.
    """
    if risk_level not in _REASSESSMENT_INTERVAL_DAYS:
        risk_level = PolicyRiskLevel.MEDIUM.value
    interval = int(
        (policy_data or {}).get("reassessment_interval_days")
        or _REASSESSMENT_INTERVAL_DAYS[risk_level]
    )
    if interval < 1:
        interval = _REASSESSMENT_INTERVAL_DAYS[risk_level]
    approval_required = risk_level in {
        PolicyRiskLevel.CRITICAL.value,
        PolicyRiskLevel.HIGH.value,
    }
    # Deterministic: base off UTC "midnight today" + interval
    now = datetime.now(timezone.utc)
    base = now.replace(hour=0, minute=0, second=0, microsecond=0)
    next_dt = base + timedelta(days=interval)
    return {
        "next_reassessment_date": next_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "interval_days": interval,
        "approval_required": approval_required,
    }


def validate_policy_schema(policy_data: dict[str, Any]) -> list[str]:
    """Return list of validation errors. Empty means valid."""
    errors: list[str] = []
    if not isinstance(policy_data, dict):
        return ["policy_data must be an object"]
    risk = policy_data.get("risk_level")
    if risk is not None and risk not in _REASSESSMENT_INTERVAL_DAYS:
        errors.append(f"risk_level {risk!r} invalid")
    interval = policy_data.get("reassessment_interval_days")
    if interval is not None:
        if not isinstance(interval, int) or interval < 1 or interval > 3650:
            errors.append("reassessment_interval_days must be int 1..3650")
    for key in ("name", "description"):
        value = policy_data.get(key)
        if value is not None and not isinstance(value, str):
            errors.append(f"{key} must be a string")
    return errors
