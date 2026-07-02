"""Core continuous evaluation loop for the Governance Orchestration Authority.

All functions are deterministic. Reads from other authorities are wrapped
in try/except so the loop degrades gracefully.
"""

from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import text as sa_text

from services.governance_orchestration.models import GovernanceOrchestrationState
from services.governance_orchestration.trigger_engine import evaluate_triggers


def evaluate_governance_state(
    db: Any, tenant_id: str, context: Optional[dict[str, Any]] = None
) -> dict[str, Any]:
    """Evaluate the continuous governance state for a tenant.

    Returns:
        {state, triggers_detected, actions_required, evidence_sufficiency,
         next_evaluation_hint}
    Deterministic; safe on failure.
    """
    ctx = dict(context or {})
    triggers = evaluate_triggers(db, tenant_id, ctx)

    evidence = compute_evidence_sufficiency(db, tenant_id)
    control = evaluate_control_health(db, tenant_id)
    posture = evaluate_governance_posture(db, tenant_id)

    actions_required: list[str] = []
    if triggers:
        actions_required.append("PROCESS_TRIGGERS")
    if evidence.get("coverage_pct", 100) < 60:
        actions_required.append("REFRESH_EVIDENCE")
    if control.get("health_pct", 100) < 60:
        actions_required.append("REVIEW_CONTROLS")
    if posture.get("score", 100) < 60:
        actions_required.append("REASSESS")

    if triggers or actions_required:
        state = GovernanceOrchestrationState.EVALUATING.value
    else:
        state = GovernanceOrchestrationState.IDLE.value

    return {
        "state": state,
        "triggers_detected": triggers,
        "actions_required": actions_required,
        "evidence_sufficiency": evidence,
        "control_health": control,
        "posture": posture,
        "next_evaluation_hint": "24h" if state == GovernanceOrchestrationState.IDLE.value else "1h",
    }


def compute_evidence_sufficiency(db: Any, tenant_id: str) -> dict[str, Any]:
    """Compute evidence-sufficiency stats.

    Best-effort cross-authority read; returns defaults on any failure.
    """
    try:
        total = _count(
            db,
            "SELECT COUNT(1) FROM fa_evidence WHERE tenant_id = :t",
            {"t": tenant_id},
        )
        verified = _count(
            db,
            "SELECT COUNT(1) FROM fa_evidence WHERE tenant_id = :t "
            "AND trust_state IN ('VERIFIED', 'HIGH_CONFIDENCE', 'ATTESTED')",
            {"t": tenant_id},
        )
        fresh = _count(
            db,
            "SELECT COUNT(1) FROM fa_evidence WHERE tenant_id = :t "
            "AND lifecycle_state IN ('COLLECTED', 'SUBMITTED', 'UNDER_REVIEW', 'VERIFIED')",
            {"t": tenant_id},
        )
    except Exception:
        total = 0
        verified = 0
        fresh = 0
    coverage_pct = 0.0
    if total > 0:
        coverage_pct = round(100.0 * verified / total, 2)
    return {
        "required": total,
        "collected": total,
        "verified": verified,
        "fresh": fresh,
        "coverage_pct": coverage_pct,
        "missing_items": max(0, total - verified),
    }


def evaluate_control_health(db: Any, tenant_id: str) -> dict[str, Any]:
    """Return control health stats. Best-effort read; safe on failure."""
    try:
        total = _count(
            db,
            "SELECT COUNT(1) FROM control_registry WHERE tenant_id = :t",
            {"t": tenant_id},
        )
        verified = _count(
            db,
            "SELECT COUNT(1) FROM control_registry WHERE tenant_id = :t "
            "AND verification_status = 'verified'",
            {"t": tenant_id},
        )
    except Exception:
        total = 0
        verified = 0
    healthy = verified
    failed = 0
    degraded = max(0, total - verified)
    health_pct = 0.0
    if total > 0:
        health_pct = round(100.0 * healthy / total, 2)
    return {
        "healthy": healthy,
        "degraded": degraded,
        "failed": failed,
        "total": total,
        "health_pct": health_pct,
    }


def evaluate_governance_posture(db: Any, tenant_id: str) -> dict[str, Any]:
    """Return posture metrics. Best-effort read; safe on failure."""
    score = 75.0
    try:
        row = db.execute(
            sa_text(
                "SELECT governance_health_score FROM fa_governance_health_snapshots "
                "WHERE tenant_id = :t ORDER BY snapshot_at DESC LIMIT 1"
            ),
            {"t": tenant_id},
        ).first()
        if row is not None and row[0] is not None:
            score = float(row[0])
    except Exception:
        pass
    if score >= 80:
        risk = "LOW"
    elif score >= 60:
        risk = "MEDIUM"
    elif score >= 40:
        risk = "HIGH"
    else:
        risk = "CRITICAL"
    return {
        "score": score,
        "trend": "STABLE",
        "risk_level": risk,
        "framework_coverage": {},
    }


def _count(db: Any, sql: str, params: dict[str, Any]) -> int:
    row = db.execute(sa_text(sql), params).first()
    return int(row[0]) if row is not None and row[0] is not None else 0
