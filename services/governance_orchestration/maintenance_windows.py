"""Maintenance window management for governance orchestration."""

from __future__ import annotations

from typing import Any, Optional

from services.canonical import utc_iso8601_z_now
from services.governance_orchestration.models import MaintenanceWindowState
from services.governance_orchestration.repository import (
    GovernanceOrchestrationRepository,
)
from services.governance_orchestration.schemas import (
    GovernanceOrchestrationInvalidTransition,
    GovernanceOrchestrationNotFound,
)


def is_in_maintenance_window(
    db: Any, tenant_id: str, check_time: Optional[str] = None
) -> bool:
    """True if the tenant has any ACTIVE maintenance window covering the time."""
    repo = GovernanceOrchestrationRepository(db, tenant_id)
    rows = repo.list_maintenance_windows(
        window_state=MaintenanceWindowState.ACTIVE.value
    )
    if not rows:
        return False
    check = check_time or utc_iso8601_z_now()
    for r in rows:
        if r.starts_at <= check <= r.ends_at:
            return True
    return False


def get_active_window(db: Any, tenant_id: str) -> Optional[dict[str, Any]]:
    repo = GovernanceOrchestrationRepository(db, tenant_id)
    rows = repo.list_maintenance_windows(
        window_state=MaintenanceWindowState.ACTIVE.value
    )
    if not rows:
        return None
    now = utc_iso8601_z_now()
    for r in rows:
        if r.starts_at <= now <= r.ends_at:
            return {
                "id": r.id,
                "name": r.name,
                "starts_at": r.starts_at,
                "ends_at": r.ends_at,
                "window_state": r.window_state,
            }
    return None


def open_maintenance_window(db: Any, tenant_id: str, window_id: str) -> dict[str, Any]:
    repo = GovernanceOrchestrationRepository(db, tenant_id)
    row = repo.get_maintenance_window(window_id)
    if row is None:
        raise GovernanceOrchestrationNotFound(
            f"Maintenance window {window_id!r} not found"
        )
    state = MaintenanceWindowState(row.window_state)
    if state != MaintenanceWindowState.SCHEDULED:
        raise GovernanceOrchestrationInvalidTransition(
            f"Cannot open window from state {state.value!r}"
        )
    row.window_state = MaintenanceWindowState.ACTIVE.value
    repo.update_maintenance_window(row)
    return _to_dict(row)


def close_maintenance_window(db: Any, tenant_id: str, window_id: str) -> dict[str, Any]:
    repo = GovernanceOrchestrationRepository(db, tenant_id)
    row = repo.get_maintenance_window(window_id)
    if row is None:
        raise GovernanceOrchestrationNotFound(
            f"Maintenance window {window_id!r} not found"
        )
    state = MaintenanceWindowState(row.window_state)
    if state not in {MaintenanceWindowState.ACTIVE, MaintenanceWindowState.SCHEDULED}:
        raise GovernanceOrchestrationInvalidTransition(
            f"Cannot close window from state {state.value!r}"
        )
    row.window_state = MaintenanceWindowState.COMPLETED.value
    repo.update_maintenance_window(row)
    return _to_dict(row)


def check_blackout_period(tenant_id: str, check_time: str) -> bool:
    """Pure helper: return True if ``check_time`` falls in a global blackout.

    Deterministic — this default implementation returns False (no global
    blackouts defined at the platform level). Tenant-scoped windows are
    checked via ``is_in_maintenance_window``.
    """
    if not isinstance(check_time, str) or not check_time:
        return False
    if not isinstance(tenant_id, str) or not tenant_id:
        return False
    return False


def _to_dict(row: Any) -> dict[str, Any]:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "name": row.name,
        "window_state": row.window_state,
        "starts_at": row.starts_at,
        "ends_at": row.ends_at,
        "reason": row.reason,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }
