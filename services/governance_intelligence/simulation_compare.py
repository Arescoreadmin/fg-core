"""Simulation Comparison Studio (PR 18.5A).

Pure functions only.  No DB I/O.  Every comparison output is labeled
DETERMINISTIC_COMPARISON with is_production=false.
"""

from __future__ import annotations

from typing import Any

from services.governance_intelligence.schemas import (
    GovernanceIntelligenceValidationError,
)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_comparison_inputs(
    baseline: dict[str, Any], proposed: dict[str, Any]
) -> None:
    """Raise GovernanceIntelligenceValidationError on invalid inputs."""
    if not isinstance(baseline, dict):
        raise GovernanceIntelligenceValidationError("baseline must be a dict")
    if not isinstance(proposed, dict):
        raise GovernanceIntelligenceValidationError("proposed must be a dict")


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


def _safe_float(d: dict[str, Any], key: str, default: float = 0.0) -> float:
    try:
        return float(d.get(key, default))
    except (TypeError, ValueError):
        return default


def compare_simulations(
    baseline: dict[str, Any],
    proposed: dict[str, Any],
) -> dict[str, Any]:
    """Side-by-side deterministic comparison of two simulation results.

    comparison_label is always "DETERMINISTIC_COMPARISON".
    is_production is always False.
    """
    validate_comparison_inputs(baseline, proposed)

    baseline_id = str(baseline.get("id", baseline.get("name", "baseline")))
    proposed_id = str(proposed.get("id", proposed.get("name", "proposed")))

    risk_b = _safe_float(
        baseline, "risk_score", _safe_float(baseline, "projected_risk")
    )
    risk_p = _safe_float(
        proposed, "risk_score", _safe_float(proposed, "projected_risk")
    )

    gov_b = _safe_float(
        baseline, "governance_score", _safe_float(baseline, "projected_score")
    )
    gov_p = _safe_float(
        proposed, "governance_score", _safe_float(proposed, "projected_score")
    )

    comp_b = _safe_float(
        baseline,
        "compliance_score",
        _safe_float(baseline, "projected_compliance_delta"),
    )
    comp_p = _safe_float(
        proposed,
        "compliance_score",
        _safe_float(proposed, "projected_compliance_delta"),
    )

    work_b = _safe_float(
        baseline,
        "workload",
        _safe_float(baseline, "projected_remediation_load"),
    )
    work_p = _safe_float(
        proposed,
        "workload",
        _safe_float(proposed, "projected_remediation_load"),
    )

    approval_b = _safe_float(baseline, "approval_rate")
    approval_p = _safe_float(proposed, "approval_rate")

    cost_b = _safe_float(baseline, "cost")
    cost_p = _safe_float(proposed, "cost")

    auto_b = _safe_float(
        baseline,
        "automation_savings",
        _safe_float(baseline, "projected_automation_savings"),
    )
    auto_p = _safe_float(
        proposed,
        "automation_savings",
        _safe_float(proposed, "projected_automation_savings"),
    )

    risk_diff = round(risk_p - risk_b, 4)
    gov_diff = round(gov_p - gov_b, 4)
    comp_diff = round(comp_p - comp_b, 4)
    work_diff = round(work_p - work_b, 4)
    approval_diff = round(approval_p - approval_b, 4)
    cost_diff = round(cost_p - cost_b, 4)
    auto_diff = round(auto_p - auto_b, 4)

    # Narrative summary
    direction = (
        "improves" if gov_diff > 0 else "reduces" if gov_diff < 0 else "maintains"
    )
    summary = (
        f"Proposed scenario {direction} governance score by "
        f"{abs(gov_diff):.4f} vs baseline."
    )

    return {
        "baseline_id": baseline_id,
        "proposed_id": proposed_id,
        "risk_difference": risk_diff,
        "governance_difference": gov_diff,
        "compliance_difference": comp_diff,
        "workload_difference": work_diff,
        "approval_difference": approval_diff,
        "cost_difference": cost_diff,
        "automation_difference": auto_diff,
        "summary": summary,
        "comparison_label": "DETERMINISTIC_COMPARISON",
        "is_production": False,
    }


# ---------------------------------------------------------------------------
# Ranking
# ---------------------------------------------------------------------------


def rank_simulations(
    simulations: list[dict[str, Any]], metric: str
) -> list[dict[str, Any]]:
    """Rank simulation dicts by a given metric key (descending)."""

    def _key(sim: dict[str, Any]) -> float:
        return _safe_float(sim, metric)

    return sorted(simulations, key=_key, reverse=True)
