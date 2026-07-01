"""Effectiveness helpers.

Reads from ``services/remediation_effectiveness`` when available; falls
back to deterministic no-op values so the authority degrades gracefully.
"""

from __future__ import annotations

from typing import Any


def read_effectiveness_summary(db: Any, tenant_id: str) -> dict[str, float]:
    """Return an effectiveness summary for the tenant.

    Falls back to zero-values if the effectiveness authority is not
    populated for this tenant.
    """
    summary: dict[str, float] = {
        "effectiveness_score": 0.0,
        "sustained_ratio": 0.0,
        "persistence_score": 0.0,
    }
    try:
        from api.db_models_remediation_effectiveness import (
            FaRemediationOutcome,
        )

        q = db.query(FaRemediationOutcome).filter(
            FaRemediationOutcome.tenant_id == tenant_id
        )
        rows = q.all()
        if not rows:
            return summary
        total = 0.0
        sustained = 0
        for row in rows:
            score = float(getattr(row, "effectiveness_score", 0.0) or 0.0)
            total += score
            if getattr(row, "sustained", False):
                sustained += 1
        count = len(rows)
        summary["effectiveness_score"] = round(total / count, 6) if count else 0.0
        summary["sustained_ratio"] = round(sustained / count, 6) if count else 0.0
        summary["persistence_score"] = summary["sustained_ratio"]
    except Exception:
        return summary
    return summary
