"""Deterministic scheduler for governance orchestration.

There are no live timers. This module records schedules and evaluates
what is due on demand. Callers persist the results themselves.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from services.canonical import utc_iso8601_z_now
from services.governance_orchestration.models import (
    ApprovalState,
    MaintenanceWindowState,
    ReassessmentState,
)
from services.governance_orchestration.repository import (
    GovernanceOrchestrationRepository,
)


def compute_next_run(policy_data: dict[str, Any], last_run_at: str | None) -> str:
    """Compute the next run timestamp (ISO-8601 Z) for a policy.

    Deterministic — driven by `interval_days` in the policy data (default 30).
    """
    interval_days = 30
    if isinstance(policy_data, dict):
        raw = policy_data.get("interval_days")
        if isinstance(raw, int) and 1 <= raw <= 3650:
            interval_days = raw
    if last_run_at:
        try:
            base = datetime.strptime(last_run_at, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc
            )
        except (TypeError, ValueError):
            base = datetime.now(timezone.utc)
    else:
        base = datetime.now(timezone.utc)
    next_dt = base + timedelta(days=interval_days)
    return next_dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def get_due_reassessments(db: Any, tenant_id: str) -> list[dict[str, Any]]:
    """Return reassessments whose ``scheduled_at`` is <= now."""
    repo = GovernanceOrchestrationRepository(db, tenant_id)
    rows, _ = repo.list_reassessments(
        reassessment_state=ReassessmentState.SCHEDULED.value,
        offset=0,
        limit=500,
    )
    now = utc_iso8601_z_now()
    due: list[dict[str, Any]] = []
    for r in rows:
        if r.scheduled_at and r.scheduled_at <= now:
            due.append(
                {
                    "id": r.id,
                    "assessment_id": r.assessment_id,
                    "scheduled_at": r.scheduled_at,
                }
            )
    return due


def get_overdue_approvals(db: Any, tenant_id: str) -> list[dict[str, Any]]:
    """Return approvals that have been PENDING for more than 7 days."""
    repo = GovernanceOrchestrationRepository(db, tenant_id)
    rows = repo.list_approvals(approval_state=ApprovalState.PENDING.value)
    if not rows:
        return []
    threshold = (datetime.now(timezone.utc) - timedelta(days=7)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    overdue: list[dict[str, Any]] = []
    for r in rows:
        if r.created_at and r.created_at <= threshold:
            overdue.append(
                {
                    "id": r.id,
                    "workflow_id": r.workflow_id,
                    "stage": r.stage,
                    "created_at": r.created_at,
                }
            )
    return overdue


def get_expiring_maintenance_windows(db: Any, tenant_id: str) -> list[dict[str, Any]]:
    """Return maintenance windows whose ``ends_at`` is within the next 24h."""
    repo = GovernanceOrchestrationRepository(db, tenant_id)
    rows = repo.list_maintenance_windows(
        window_state=MaintenanceWindowState.ACTIVE.value
    )
    if not rows:
        return []
    now = datetime.now(timezone.utc)
    horizon = (now + timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    expiring: list[dict[str, Any]] = []
    for r in rows:
        if r.ends_at and now_iso <= r.ends_at <= horizon:
            expiring.append(
                {
                    "id": r.id,
                    "name": r.name,
                    "ends_at": r.ends_at,
                }
            )
    return expiring
