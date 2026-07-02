"""Counterfactual Governance Engine (PR 18.5A).

Pure functions only.  No DB I/O.  Every output is labeled PROJECTED with
is_production=false so it is never confusable with measured production values.
"""

from __future__ import annotations

from typing import Any

from services.governance_intelligence.schemas import (
    GovernanceIntelligenceSimulationError,
    GovernanceIntelligenceValidationError,
)


# ---------------------------------------------------------------------------
# Supported scenarios
# ---------------------------------------------------------------------------

SUPPORTED_SCENARIOS: frozenset[str] = frozenset(
    {
        "POLICY_ROLLBACK",
        "REMEDIATION_DELAY",
        "APPROVAL_FAILURE",
        "EVIDENCE_EXPIRY",
        "VERIFICATION_SUCCESS",
        "VERIFICATION_FAILURE",
        "TRUST_ROTATION",
        "CONFIDENCE_THRESHOLD_CHANGE",
        "BENCHMARK_COHORT_CHANGE",
    }
)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_counterfactual(scenario: str, parameters: dict[str, Any]) -> None:
    """Raise GovernanceIntelligenceSimulationError if scenario is invalid."""
    if scenario not in SUPPORTED_SCENARIOS:
        raise GovernanceIntelligenceSimulationError(
            f"Unsupported counterfactual scenario '{scenario}'. "
            f"Supported: {sorted(SUPPORTED_SCENARIOS)}"
        )
    if not isinstance(parameters, dict):
        raise GovernanceIntelligenceValidationError("parameters must be a dict")


# ---------------------------------------------------------------------------
# Scenario delta functions
# ---------------------------------------------------------------------------

_SCORE_KEY = "governance_score"
_RISK_KEY = "risk_score"
_REMEDIATION_KEY = "remediation_load"
_VERIFICATION_KEY = "verification_load"
_COMPLIANCE_KEY = "compliance_score"
_AUTOMATION_KEY = "automation_savings"
_SLA_KEY = "sla_health"


def _safe_float(baseline: dict[str, Any], key: str, default: float = 0.5) -> float:
    val = baseline.get(key, default)
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


def _apply_policy_rollback(
    baseline: dict[str, Any], parameters: dict[str, Any]
) -> dict[str, Any]:
    rollback_severity = _safe_float(parameters, "rollback_severity", 0.3)
    score = _clamp(_safe_float(baseline, _SCORE_KEY) - rollback_severity * 0.4)
    risk = _clamp(_safe_float(baseline, _RISK_KEY) + rollback_severity * 0.3)
    compliance = _clamp(
        _safe_float(baseline, _COMPLIANCE_KEY) - rollback_severity * 0.35
    )
    return {
        "projected_score": round(score, 4),
        "projected_risk": round(risk, 4),
        "projected_remediation_load": round(
            _clamp(_safe_float(baseline, _REMEDIATION_KEY) + rollback_severity * 0.2), 4
        ),
        "projected_verification_load": round(
            _clamp(_safe_float(baseline, _VERIFICATION_KEY)), 4
        ),
        "projected_compliance_delta": round(
            compliance - _safe_float(baseline, _COMPLIANCE_KEY), 4
        ),
        "projected_automation_savings": round(
            _clamp(_safe_float(baseline, _AUTOMATION_KEY) - rollback_severity * 0.1), 4
        ),
        "projected_sla_impact": round(
            _clamp(_safe_float(baseline, _SLA_KEY) - rollback_severity * 0.15), 4
        ),
    }


def _apply_remediation_delay(
    baseline: dict[str, Any], parameters: dict[str, Any]
) -> dict[str, Any]:
    delay_days = max(0, int(parameters.get("delay_days", 30)))
    penalty = min(0.5, delay_days / 180.0)
    score = _clamp(_safe_float(baseline, _SCORE_KEY) - penalty * 0.35)
    risk = _clamp(_safe_float(baseline, _RISK_KEY) + penalty * 0.4)
    compliance = _clamp(_safe_float(baseline, _COMPLIANCE_KEY) - penalty * 0.25)
    return {
        "projected_score": round(score, 4),
        "projected_risk": round(risk, 4),
        "projected_remediation_load": round(
            _clamp(_safe_float(baseline, _REMEDIATION_KEY) + penalty * 0.5), 4
        ),
        "projected_verification_load": round(
            _clamp(_safe_float(baseline, _VERIFICATION_KEY) + penalty * 0.1), 4
        ),
        "projected_compliance_delta": round(
            compliance - _safe_float(baseline, _COMPLIANCE_KEY), 4
        ),
        "projected_automation_savings": round(
            _clamp(_safe_float(baseline, _AUTOMATION_KEY)), 4
        ),
        "projected_sla_impact": round(
            _clamp(_safe_float(baseline, _SLA_KEY) - penalty * 0.25), 4
        ),
    }


def _apply_approval_failure(
    baseline: dict[str, Any], parameters: dict[str, Any]
) -> dict[str, Any]:
    failure_rate = _clamp(_safe_float(parameters, "failure_rate", 0.2))
    score = _clamp(_safe_float(baseline, _SCORE_KEY) - failure_rate * 0.3)
    risk = _clamp(_safe_float(baseline, _RISK_KEY) + failure_rate * 0.25)
    compliance = _clamp(_safe_float(baseline, _COMPLIANCE_KEY) - failure_rate * 0.2)
    return {
        "projected_score": round(score, 4),
        "projected_risk": round(risk, 4),
        "projected_remediation_load": round(
            _clamp(_safe_float(baseline, _REMEDIATION_KEY) + failure_rate * 0.15), 4
        ),
        "projected_verification_load": round(
            _clamp(_safe_float(baseline, _VERIFICATION_KEY) + failure_rate * 0.2), 4
        ),
        "projected_compliance_delta": round(
            compliance - _safe_float(baseline, _COMPLIANCE_KEY), 4
        ),
        "projected_automation_savings": round(
            _clamp(_safe_float(baseline, _AUTOMATION_KEY) - failure_rate * 0.05), 4
        ),
        "projected_sla_impact": round(
            _clamp(_safe_float(baseline, _SLA_KEY) - failure_rate * 0.1), 4
        ),
    }


def _apply_evidence_expiry(
    baseline: dict[str, Any], parameters: dict[str, Any]
) -> dict[str, Any]:
    expiry_fraction = _clamp(_safe_float(parameters, "expiry_fraction", 0.3))
    score = _clamp(_safe_float(baseline, _SCORE_KEY) - expiry_fraction * 0.45)
    risk = _clamp(_safe_float(baseline, _RISK_KEY) + expiry_fraction * 0.35)
    compliance = _clamp(_safe_float(baseline, _COMPLIANCE_KEY) - expiry_fraction * 0.4)
    return {
        "projected_score": round(score, 4),
        "projected_risk": round(risk, 4),
        "projected_remediation_load": round(
            _clamp(_safe_float(baseline, _REMEDIATION_KEY) + expiry_fraction * 0.3), 4
        ),
        "projected_verification_load": round(
            _clamp(_safe_float(baseline, _VERIFICATION_KEY) + expiry_fraction * 0.4), 4
        ),
        "projected_compliance_delta": round(
            compliance - _safe_float(baseline, _COMPLIANCE_KEY), 4
        ),
        "projected_automation_savings": round(
            _clamp(_safe_float(baseline, _AUTOMATION_KEY) - expiry_fraction * 0.1), 4
        ),
        "projected_sla_impact": round(
            _clamp(_safe_float(baseline, _SLA_KEY) - expiry_fraction * 0.2), 4
        ),
    }


def _apply_verification_success(
    baseline: dict[str, Any], parameters: dict[str, Any]
) -> dict[str, Any]:
    coverage_gain = _clamp(_safe_float(parameters, "coverage_gain", 0.2))
    score = _clamp(_safe_float(baseline, _SCORE_KEY) + coverage_gain * 0.3)
    risk = _clamp(_safe_float(baseline, _RISK_KEY) - coverage_gain * 0.25)
    compliance = _clamp(_safe_float(baseline, _COMPLIANCE_KEY) + coverage_gain * 0.2)
    return {
        "projected_score": round(score, 4),
        "projected_risk": round(risk, 4),
        "projected_remediation_load": round(
            _clamp(_safe_float(baseline, _REMEDIATION_KEY) - coverage_gain * 0.1), 4
        ),
        "projected_verification_load": round(
            _clamp(_safe_float(baseline, _VERIFICATION_KEY) - coverage_gain * 0.15), 4
        ),
        "projected_compliance_delta": round(
            compliance - _safe_float(baseline, _COMPLIANCE_KEY), 4
        ),
        "projected_automation_savings": round(
            _clamp(_safe_float(baseline, _AUTOMATION_KEY) + coverage_gain * 0.1), 4
        ),
        "projected_sla_impact": round(
            _clamp(_safe_float(baseline, _SLA_KEY) + coverage_gain * 0.1), 4
        ),
    }


def _apply_verification_failure(
    baseline: dict[str, Any], parameters: dict[str, Any]
) -> dict[str, Any]:
    failure_fraction = _clamp(_safe_float(parameters, "failure_fraction", 0.25))
    score = _clamp(_safe_float(baseline, _SCORE_KEY) - failure_fraction * 0.4)
    risk = _clamp(_safe_float(baseline, _RISK_KEY) + failure_fraction * 0.35)
    compliance = _clamp(_safe_float(baseline, _COMPLIANCE_KEY) - failure_fraction * 0.3)
    return {
        "projected_score": round(score, 4),
        "projected_risk": round(risk, 4),
        "projected_remediation_load": round(
            _clamp(_safe_float(baseline, _REMEDIATION_KEY) + failure_fraction * 0.25), 4
        ),
        "projected_verification_load": round(
            _clamp(_safe_float(baseline, _VERIFICATION_KEY) + failure_fraction * 0.35),
            4,
        ),
        "projected_compliance_delta": round(
            compliance - _safe_float(baseline, _COMPLIANCE_KEY), 4
        ),
        "projected_automation_savings": round(
            _clamp(_safe_float(baseline, _AUTOMATION_KEY) - failure_fraction * 0.05), 4
        ),
        "projected_sla_impact": round(
            _clamp(_safe_float(baseline, _SLA_KEY) - failure_fraction * 0.2), 4
        ),
    }


def _apply_trust_rotation(
    baseline: dict[str, Any], parameters: dict[str, Any]
) -> dict[str, Any]:
    rotation_cost = _clamp(_safe_float(parameters, "rotation_cost", 0.15))
    score = _clamp(_safe_float(baseline, _SCORE_KEY) - rotation_cost * 0.1)
    risk = _clamp(_safe_float(baseline, _RISK_KEY) + rotation_cost * 0.05)
    return {
        "projected_score": round(score, 4),
        "projected_risk": round(risk, 4),
        "projected_remediation_load": round(
            _clamp(_safe_float(baseline, _REMEDIATION_KEY) + rotation_cost * 0.1), 4
        ),
        "projected_verification_load": round(
            _clamp(_safe_float(baseline, _VERIFICATION_KEY) + rotation_cost * 0.2), 4
        ),
        "projected_compliance_delta": round(0.0, 4),
        "projected_automation_savings": round(
            _clamp(_safe_float(baseline, _AUTOMATION_KEY) - rotation_cost * 0.05), 4
        ),
        "projected_sla_impact": round(
            _clamp(_safe_float(baseline, _SLA_KEY) - rotation_cost * 0.1), 4
        ),
    }


def _apply_confidence_threshold_change(
    baseline: dict[str, Any], parameters: dict[str, Any]
) -> dict[str, Any]:
    threshold_delta = _safe_float(parameters, "threshold_delta", 0.0)
    score_delta = (
        -abs(threshold_delta) * 0.2
        if threshold_delta > 0
        else abs(threshold_delta) * 0.1
    )
    score = _clamp(_safe_float(baseline, _SCORE_KEY) + score_delta)
    risk = _clamp(_safe_float(baseline, _RISK_KEY) - score_delta * 0.5)
    compliance = _clamp(_safe_float(baseline, _COMPLIANCE_KEY) + score_delta * 0.5)
    return {
        "projected_score": round(score, 4),
        "projected_risk": round(risk, 4),
        "projected_remediation_load": round(
            _clamp(_safe_float(baseline, _REMEDIATION_KEY)), 4
        ),
        "projected_verification_load": round(
            _clamp(
                _safe_float(baseline, _VERIFICATION_KEY) + abs(threshold_delta) * 0.1
            ),
            4,
        ),
        "projected_compliance_delta": round(
            compliance - _safe_float(baseline, _COMPLIANCE_KEY), 4
        ),
        "projected_automation_savings": round(
            _clamp(_safe_float(baseline, _AUTOMATION_KEY)), 4
        ),
        "projected_sla_impact": round(_clamp(_safe_float(baseline, _SLA_KEY)), 4),
    }


def _apply_benchmark_cohort_change(
    baseline: dict[str, Any], parameters: dict[str, Any]
) -> dict[str, Any]:
    cohort_size_delta = int(parameters.get("cohort_size_delta", 0))
    cohort_factor = max(-0.3, min(0.3, cohort_size_delta / 100.0))
    score = _clamp(_safe_float(baseline, _SCORE_KEY) + cohort_factor * 0.15)
    risk = _clamp(_safe_float(baseline, _RISK_KEY) - cohort_factor * 0.1)
    return {
        "projected_score": round(score, 4),
        "projected_risk": round(risk, 4),
        "projected_remediation_load": round(
            _clamp(_safe_float(baseline, _REMEDIATION_KEY)), 4
        ),
        "projected_verification_load": round(
            _clamp(_safe_float(baseline, _VERIFICATION_KEY)), 4
        ),
        "projected_compliance_delta": round(0.0, 4),
        "projected_automation_savings": round(
            _clamp(_safe_float(baseline, _AUTOMATION_KEY) + cohort_factor * 0.05), 4
        ),
        "projected_sla_impact": round(_clamp(_safe_float(baseline, _SLA_KEY)), 4),
    }


_SCENARIO_DISPATCH = {
    "POLICY_ROLLBACK": _apply_policy_rollback,
    "REMEDIATION_DELAY": _apply_remediation_delay,
    "APPROVAL_FAILURE": _apply_approval_failure,
    "EVIDENCE_EXPIRY": _apply_evidence_expiry,
    "VERIFICATION_SUCCESS": _apply_verification_success,
    "VERIFICATION_FAILURE": _apply_verification_failure,
    "TRUST_ROTATION": _apply_trust_rotation,
    "CONFIDENCE_THRESHOLD_CHANGE": _apply_confidence_threshold_change,
    "BENCHMARK_COHORT_CHANGE": _apply_benchmark_cohort_change,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_counterfactual(
    scenario: str,
    baseline: dict[str, Any],
    parameters: dict[str, Any],
) -> dict[str, Any]:
    """Run a single counterfactual scenario.

    Returns a dict with all projected metrics plus invariant labels.
    result_label is always "PROJECTED".
    is_production is always False.
    """
    validate_counterfactual(scenario, parameters)
    fn = _SCENARIO_DISPATCH[scenario]
    projected = fn(baseline, parameters)
    baseline_score = round(_safe_float(baseline, _SCORE_KEY), 4)
    return {
        "scenario": scenario,
        "baseline_score": baseline_score,
        **projected,
        "result_label": "PROJECTED",
        "is_production": False,
    }


def compare_counterfactuals(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare multiple counterfactual results.

    Returns a summary dict sorted by projected_score descending.
    """
    if not results:
        return {
            "count": 0,
            "ranked": [],
            "best_scenario": None,
            "worst_scenario": None,
        }

    ranked = sorted(
        results,
        key=lambda r: r.get("projected_score", 0.0),
        reverse=True,
    )
    return {
        "count": len(ranked),
        "ranked": ranked,
        "best_scenario": ranked[0].get("scenario"),
        "worst_scenario": ranked[-1].get("scenario"),
    }
