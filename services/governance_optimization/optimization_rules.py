"""services/governance_optimization/optimization_rules.py

Deterministic optimization surfacing and ranking rules.
No AI. No LLMs.

PR 17.6D — Governance Optimization Engine
"""

from __future__ import annotations

from services.governance_optimization.ranking import RankedItem


def should_surface_as_optimization_target(
    target_type: str, score: float, sample_size: int
) -> bool:
    """Return True if this item deserves to appear in the optimization output."""
    if sample_size == 0:
        return False
    return True  # all types with data surface; rank determines priority


def apply_optimization_context(
    ranked_items: list[RankedItem],
    optimization_type: str,
) -> list[RankedItem]:
    """Sort items by priority_score descending and assign ranks 1..N."""
    sorted_items = sorted(ranked_items, key=lambda x: x.priority_score, reverse=True)
    for i, item in enumerate(sorted_items):
        item.rank = i + 1
    return sorted_items
