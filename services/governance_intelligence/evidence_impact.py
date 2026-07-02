"""Evidence Impact Graph (PR 18.5A).

Pure functions only.  No DB I/O.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Impact chain constant (10 stages)
# ---------------------------------------------------------------------------

IMPACT_CHAIN: list[str] = [
    "evidence",
    "verification",
    "finding",
    "control",
    "policy",
    "report",
    "recommendation",
    "simulation",
    "dashboard",
    "executive_summary",
]

assert len(IMPACT_CHAIN) == 10, "IMPACT_CHAIN must have exactly 10 entries"


# ---------------------------------------------------------------------------
# Blast radius labels
# ---------------------------------------------------------------------------


def _blast_radius_label(total: int) -> str:
    if total < 5:
        return "LOW"
    if total < 20:
        return "MEDIUM"
    if total < 50:
        return "HIGH"
    return "CRITICAL"


# ---------------------------------------------------------------------------
# Impact computation
# ---------------------------------------------------------------------------


def compute_evidence_impact(
    evidence_id: str,
    evidence_data: dict[str, Any],
    downstream_data: dict[str, list[str]],
) -> dict[str, Any]:
    """Trace the blast radius of a single piece of evidence.

    downstream_data maps stage names → list of affected object IDs.
    Only stages that appear in IMPACT_CHAIN (after "evidence") are used.

    Returns a dict with impact_chain, total_affected, and blast_radius_label.
    """
    impact_chain: list[dict[str, Any]] = []
    total_affected = 0

    for stage in IMPACT_CHAIN:
        if stage == "evidence":
            # The evidence itself — always 1
            impact_chain.append(
                {
                    "stage": stage,
                    "affected_ids": [evidence_id],
                    "impact_count": 1,
                }
            )
        else:
            affected_ids = list(downstream_data.get(stage, []))
            count = len(affected_ids)
            total_affected += count
            impact_chain.append(
                {
                    "stage": stage,
                    "affected_ids": sorted(affected_ids),
                    "impact_count": count,
                }
            )

    label = _blast_radius_label(total_affected)

    return {
        "evidence_id": evidence_id,
        "impact_chain": impact_chain,
        "total_affected": total_affected,
        "blast_radius_label": label,
    }


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def summarize_impact(impact: dict[str, Any]) -> str:
    """Return a short human-readable summary of an evidence impact result."""
    eid = impact.get("evidence_id", "unknown")
    total = impact.get("total_affected", 0)
    label = impact.get("blast_radius_label", "UNKNOWN")
    return (
        f"Evidence '{eid}' — blast radius {label} "
        f"({total} downstream objects affected across {len(IMPACT_CHAIN) - 1} stages)"
    )
