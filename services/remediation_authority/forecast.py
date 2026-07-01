"""Deterministic forecasting helpers.

Reads from `services.governance_learning` when available; otherwise falls
back to a straightforward velocity-based projection.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional


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


def compute_forecast(
    tasks: list[Any],
    horizon_days: int,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    """Return a deterministic forecast summary.

    ``tasks`` is expected to be a list of ORM rows with attributes
    ``task_state``, ``completed_at``, ``target_date``.
    """
    reference = now or datetime.now(tz=timezone.utc)
    horizon_end = reference + timedelta(days=horizon_days)

    open_tasks = 0
    completed_recent = 0
    predicted_breaches = 0

    velocity_window_days = 30
    window_start = reference - timedelta(days=velocity_window_days)

    for task in tasks:
        state = getattr(task, "task_state", "OPEN")
        if state == "COMPLETED":
            completed_at = _parse(getattr(task, "completed_at", None))
            if completed_at is not None and completed_at >= window_start:
                completed_recent += 1
            continue
        if state == "CANCELLED":
            continue
        open_tasks += 1
        target = _parse(getattr(task, "target_date", None))
        if target is not None and target <= horizon_end and target < reference:
            predicted_breaches += 1

    velocity = 0.0
    if velocity_window_days > 0:
        velocity = round(completed_recent / velocity_window_days, 6)
    predicted_completions = min(open_tasks, int(velocity * horizon_days))
    return {
        "horizon_days": horizon_days,
        "open_task_count": open_tasks,
        "predicted_completions": predicted_completions,
        "predicted_breaches": predicted_breaches,
        "average_velocity_per_day": velocity,
    }


def read_governance_learning_signal(db: Any, tenant_id: str) -> Optional[float]:
    """Return a governance-learning signal (if available), else None.

    Wrapped in try/except so the authority degrades gracefully when the
    learning authority is not populated for this tenant.
    """
    try:
        from api.db_models_governance_learning import (
            FaGovernanceLearningAggregate,
        )

        row = (
            db.query(FaGovernanceLearningAggregate)
            .filter(FaGovernanceLearningAggregate.tenant_id == tenant_id)
            .order_by(FaGovernanceLearningAggregate.last_updated_at.desc())
            .first()
        )
        if row is None:
            return None
        return float(getattr(row, "confidence_score", 0.0) or 0.0)
    except Exception:
        return None
