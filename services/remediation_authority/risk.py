"""Risk reduction helpers.

Computes portfolio-level open vs. mitigated risk from task risk_score values.
Deterministic. No I/O of its own — callers supply the task rows.
"""

from __future__ import annotations

from typing import Any


TERMINAL_STATES = frozenset({"COMPLETED", "CANCELLED"})


def _score(row: Any) -> float:
    value = getattr(row, "risk_score", None)
    if value is None:
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def compute_risk_summary(rows: list[Any]) -> dict[str, Any]:
    """Return risk aggregates keyed by priority and status."""
    total = 0.0
    open_total = 0.0
    mitigated = 0.0
    by_priority: dict[str, float] = {}
    for row in rows:
        score = _score(row)
        total += score
        state = getattr(row, "task_state", None) or "OPEN"
        priority = getattr(row, "priority", None) or "MEDIUM"
        by_priority[priority] = round(by_priority.get(priority, 0.0) + score, 6)
        if state == "COMPLETED":
            mitigated += score
        elif state not in TERMINAL_STATES:
            open_total += score
    reduction_pct = 0.0
    if total > 0:
        reduction_pct = round((mitigated / total) * 100.0, 4)
    return {
        "total_risk_score": round(total, 6),
        "open_risk_score": round(open_total, 6),
        "mitigated_risk_score": round(mitigated, 6),
        "risk_reduction_pct": reduction_pct,
        "by_priority": by_priority,
    }
