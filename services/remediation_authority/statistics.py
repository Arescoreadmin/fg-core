"""Aggregation helpers for remediation authority statistics.

All functions are pure and operate on lists of ORM rows or already-summarized
counts. They do NOT touch the DB directly — the repository does that.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _parse(ts: str | None) -> datetime | None:
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


def bucket_by(rows: list[Any], attr: str) -> dict[str, int]:
    """Return a count of rows grouped by the given attribute (as string)."""
    buckets: dict[str, int] = {}
    for row in rows:
        value = getattr(row, attr, None)
        key = str(value) if value is not None else "__unknown__"
        buckets[key] = buckets.get(key, 0) + 1
    return buckets


def average_completion_days(rows: list[Any]) -> float | None:
    """Compute the average completion time in days for completed tasks."""
    diffs: list[float] = []
    for row in rows:
        state = getattr(row, "task_state", None)
        if state != "COMPLETED":
            continue
        created = _parse(getattr(row, "created_at", None))
        completed = _parse(getattr(row, "completed_at", None))
        if created is None or completed is None:
            continue
        delta = (completed - created).total_seconds() / 86400.0
        if delta >= 0:
            diffs.append(delta)
    if not diffs:
        return None
    return round(sum(diffs) / len(diffs), 4)


def count_by_sla(rows: list[Any]) -> dict[str, int]:
    """Return the count of tasks by their computed SLA status."""
    return bucket_by(rows, "sla_status")
