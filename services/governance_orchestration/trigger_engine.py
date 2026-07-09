"""Trigger detection and recording for the Governance Orchestration Authority.

Deterministic — no side effects beyond the requested DB writes.
"""

from __future__ import annotations

from typing import Any

from services.governance_orchestration.models import TriggerType
from services.governance_orchestration.repository import (
    GovernanceOrchestrationRepository,
)


def evaluate_triggers(
    db: Any, tenant_id: str, context: dict[str, Any]
) -> list[dict[str, Any]]:
    """Evaluate trigger conditions for a tenant given a context dict.

    Deterministic. Returns a list of trigger dicts (not persisted).
    """
    if not isinstance(context, dict):
        context = {}
    detected: list[dict[str, Any]] = []

    if context.get("evidence_expired"):
        detected.append(
            {
                "trigger_type": TriggerType.EVIDENCE_EXPIRED.value,
                "reason": "evidence expiry detected",
                "confidence": 1.0,
            }
        )
    if context.get("verification_failures", 0) > 0:
        detected.append(
            {
                "trigger_type": TriggerType.VERIFICATION_FAILED.value,
                "reason": f"{context['verification_failures']} verification failure(s)",
                "confidence": 0.9,
            }
        )
    if context.get("control_health_pct") is not None:
        try:
            hp = float(context["control_health_pct"])
            if hp < 60.0:
                detected.append(
                    {
                        "trigger_type": TriggerType.CONTROL_DEGRADED.value,
                        "reason": f"control health {hp:.1f}%",
                        "confidence": 0.85,
                    }
                )
        except (TypeError, ValueError):
            pass
    if context.get("risk_score") is not None:
        try:
            rs = float(context["risk_score"])
            if rs >= 0.75:
                detected.append(
                    {
                        "trigger_type": TriggerType.RISK_THRESHOLD_EXCEEDED.value,
                        "reason": f"risk score {rs:.2f} exceeds threshold",
                        "confidence": 1.0,
                    }
                )
        except (TypeError, ValueError):
            pass
    if context.get("remediation_completed"):
        detected.append(
            {
                "trigger_type": TriggerType.REMEDIATION_COMPLETED.value,
                "reason": "remediation completed",
                "confidence": 1.0,
            }
        )
    if context.get("framework_revised"):
        detected.append(
            {
                "trigger_type": TriggerType.FRAMEWORK_REVISION.value,
                "reason": "framework revised",
                "confidence": 1.0,
            }
        )
    return detected


def record_trigger(
    db: Any,
    tenant_id: str,
    trigger_type: str,
    source_id: str | None,
    reason: str | None,
    confidence: float,
    policy_version: str = "1.0",
) -> dict[str, Any]:
    """Persist a trigger record. Returns the resulting trigger dict."""
    repo = GovernanceOrchestrationRepository(db, tenant_id)
    row = repo.create_trigger(
        trigger_type=trigger_type,
        source_id=source_id,
        reason=reason,
        confidence=confidence,
        policy_version=policy_version,
    )
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "trigger_type": row.trigger_type,
        "source_id": row.source_id,
        "reason": row.reason,
        "confidence": row.confidence,
        "policy_version": row.policy_version,
        "created_at": row.created_at,
    }


def is_trigger_active_for_tenant(db: Any, tenant_id: str, trigger_type: str) -> bool:
    """Return True if any active maintenance window suppresses this trigger.

    A trigger is 'suppressed' while a maintenance window is ACTIVE for the
    tenant. This helper never raises.
    """
    from services.governance_orchestration.maintenance_windows import (
        is_in_maintenance_window,
    )

    try:
        return not is_in_maintenance_window(db, tenant_id)
    except Exception:
        return True
