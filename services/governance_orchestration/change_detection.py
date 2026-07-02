"""Change-detection logic for governance orchestration.

Deterministic. Callers wrap in try/except when reading from other authorities.
"""

from __future__ import annotations

from typing import Any

from services.governance_orchestration.models import ChangeType, ImpactLevel
from services.governance_orchestration.repository import (
    GovernanceOrchestrationRepository,
)


def detect_changes(db: Any, tenant_id: str, context: dict[str, Any]) -> list[dict[str, Any]]:
    """Detect changes from a context dict.

    The context is expected to be produced by the engine (which collects
    signals from other authorities behind try/except). Returns a list of
    change dicts (not persisted).
    """
    if not isinstance(context, dict):
        return []
    changes: list[dict[str, Any]] = []
    if context.get("evidence_delta"):
        changes.append(
            {
                "change_type": ChangeType.EVIDENCE_CHANGE.value,
                "source_id": context.get("evidence_id"),
                "change_data": context.get("evidence_delta") or {},
            }
        )
    if context.get("control_delta"):
        changes.append(
            {
                "change_type": ChangeType.CONTROL_CHANGE.value,
                "source_id": context.get("control_id"),
                "change_data": context.get("control_delta") or {},
            }
        )
    if context.get("risk_delta"):
        changes.append(
            {
                "change_type": ChangeType.RISK_CHANGE.value,
                "source_id": context.get("risk_id"),
                "change_data": context.get("risk_delta") or {},
            }
        )
    if context.get("policy_delta"):
        changes.append(
            {
                "change_type": ChangeType.POLICY_CHANGE.value,
                "source_id": context.get("policy_id"),
                "change_data": context.get("policy_delta") or {},
            }
        )
    if context.get("framework_delta"):
        changes.append(
            {
                "change_type": ChangeType.FRAMEWORK_CHANGE.value,
                "source_id": context.get("framework_id"),
                "change_data": context.get("framework_delta") or {},
            }
        )
    if context.get("trust_delta"):
        changes.append(
            {
                "change_type": ChangeType.TRUST_CHANGE.value,
                "source_id": context.get("trust_id"),
                "change_data": context.get("trust_delta") or {},
            }
        )
    for c in changes:
        c["impact_level"] = assess_change_significance(c)
    return changes


def classify_change(change: dict[str, Any]) -> str:
    if not isinstance(change, dict):
        return ChangeType.POLICY_CHANGE.value
    ct = change.get("change_type")
    if isinstance(ct, str) and ct in {m.value for m in ChangeType}:
        return ct
    return ChangeType.POLICY_CHANGE.value


def assess_change_significance(change: dict[str, Any]) -> str:
    """Return an impact level for a change dict."""
    if not isinstance(change, dict):
        return ImpactLevel.LOW.value
    data = change.get("change_data") or {}
    if not isinstance(data, dict):
        return ImpactLevel.LOW.value
    delta = data.get("severity_delta") or data.get("delta") or 0
    try:
        delta_val = float(delta)
    except (TypeError, ValueError):
        delta_val = 0.0
    if delta_val >= 40:
        return ImpactLevel.CRITICAL.value
    if delta_val >= 20:
        return ImpactLevel.HIGH.value
    if delta_val >= 10:
        return ImpactLevel.MEDIUM.value
    if delta_val > 0:
        return ImpactLevel.LOW.value
    return ImpactLevel.NONE.value


def record_change_event(db: Any, tenant_id: str, change: dict[str, Any]) -> dict[str, Any]:
    """Persist a detected change. Returns the persisted change dict."""
    repo = GovernanceOrchestrationRepository(db, tenant_id)
    row = repo.create_change_detection(
        change_type=classify_change(change),
        source_id=change.get("source_id"),
        impact_level=change.get("impact_level") or assess_change_significance(change),
        change_data=change.get("change_data") or {},
    )
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "change_type": row.change_type,
        "source_id": row.source_id,
        "impact_level": row.impact_level,
        "created_at": row.created_at,
    }
