"""SLA computation for remediation tasks.

Compares target_date to now (or to the completed_at timestamp) and returns
one of the SlaStatus values. Pure Python.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from services.remediation_authority.models import SlaStatus


AT_RISK_DAYS: int = 3


def _parse(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        cleaned = ts.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(cleaned)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (ValueError, TypeError):
        return None


def compute_sla_status(
    target_date: Optional[str],
    task_state: str,
    completed_at: Optional[str] = None,
    now: Optional[datetime] = None,
) -> SlaStatus:
    """Return the SLA status for the given task."""
    if not target_date:
        return SlaStatus.UNSCHEDULED
    target = _parse(target_date)
    if target is None:
        return SlaStatus.UNSCHEDULED
    if task_state == "COMPLETED":
        # If completed on/before target, ON_TRACK; otherwise BREACHED.
        completion = _parse(completed_at)
        if completion is None:
            return SlaStatus.ON_TRACK
        if completion <= target:
            return SlaStatus.ON_TRACK
        return SlaStatus.BREACHED
    if task_state == "CANCELLED":
        return SlaStatus.UNSCHEDULED
    reference = now or datetime.now(tz=timezone.utc)
    if reference > target:
        return SlaStatus.BREACHED
    if reference + timedelta(days=AT_RISK_DAYS) >= target:
        return SlaStatus.AT_RISK
    return SlaStatus.ON_TRACK


def is_breached(status: SlaStatus) -> bool:
    """Return True if the status is BREACHED."""
    return status == SlaStatus.BREACHED
