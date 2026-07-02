"""Simulation engine for the Governance Intelligence Authority.

Pure functions. No I/O. No SQLAlchemy. No Pydantic.

All outputs are clearly labeled as PROJECTED. Never confuse with measured values.
"""

from __future__ import annotations

from typing import Any

from services.governance_intelligence.schemas import GovernanceIntelligenceSimulationError


SUPPORTED_SCENARIO_TYPES: frozenset[str] = frozenset(
    {
        "policy_change",
        "approval_chain",
        "sla_change",
        "maintenance_window",
        "risk_threshold",
        "reassessment_cadence",
        "playbook_selection",
    }
)


def validate_simulation_parameters(
    scenario_type: str, parameters: dict[str, Any]
) -> None:
    """Raise GovernanceIntelligenceSimulationError if parameters are invalid."""
    if scenario_type not in SUPPORTED_SCENARIO_TYPES:
        raise GovernanceIntelligenceSimulationError(
            f"Unsupported scenario_type '{scenario_type}'. "
            f"Supported: {sorted(SUPPORTED_SCENARIO_TYPES)}"
        )
    if not isinstance(parameters, dict):
        raise GovernanceIntelligenceSimulationError(
            "parameters must be a dict"
        )


def run_simulation(
    scenario_type: str, parameters: dict[str, Any]
) -> dict[str, Any]:
    """Run a deterministic simulation and return projected results.

    All outputs are labeled PROJECTED and is_production=false.
    """
    validate_simulation_parameters(scenario_type, parameters)

    base: dict[str, Any] = {
        "scenario_type": scenario_type,
        "simulation_label": "PROJECTED",
        "is_production": False,
        "parameters_used": parameters,
    }

    if scenario_type == "policy_change":
        severity = parameters.get("severity", "MEDIUM")
        # Deterministic mappings by severity
        delta_map = {"CRITICAL": -0.15, "HIGH": -0.08, "MEDIUM": -0.03, "LOW": -0.01}
        workload_map = {"CRITICAL": 0.40, "HIGH": 0.25, "MEDIUM": 0.10, "LOW": 0.02}
        base.update(
            {
                "projected_governance_delta": delta_map.get(severity, -0.03),
                "projected_workload_change": workload_map.get(severity, 0.10),
                "projected_reassessments": max(1, len(parameters.get("controls_affected", [])) * 2),
                "projected_evidence_volume": max(0, len(parameters.get("controls_affected", [])) * 5),
                "projected_verification_demand": max(1, len(parameters.get("controls_affected", [])) * 3),
                "projected_remediation_demand": max(0, len(parameters.get("controls_affected", [])) * 1),
            }
        )

    elif scenario_type == "approval_chain":
        stages = int(parameters.get("stages", 1))
        base.update(
            {
                "projected_governance_delta": round(stages * 0.02, 3),
                "projected_workload_change": round(stages * 0.05, 3),
                "projected_reassessments": stages,
                "projected_evidence_volume": stages * 2,
                "projected_verification_demand": stages * 2,
                "projected_remediation_demand": 0,
            }
        )

    elif scenario_type == "sla_change":
        days_reduction = int(parameters.get("days_reduction", 0))
        base.update(
            {
                "projected_governance_delta": round(min(0.10, days_reduction * 0.005), 3),
                "projected_workload_change": round(days_reduction * 0.02, 3),
                "projected_reassessments": max(1, days_reduction // 7),
                "projected_evidence_volume": max(0, days_reduction * 2),
                "projected_verification_demand": max(1, days_reduction // 5),
                "projected_remediation_demand": max(0, days_reduction // 10),
            }
        )

    elif scenario_type == "maintenance_window":
        duration_hours = float(parameters.get("duration_hours", 1.0))
        base.update(
            {
                "projected_governance_delta": round(-0.01 * duration_hours, 4),
                "projected_workload_change": round(0.05 * duration_hours, 4),
                "projected_reassessments": max(1, int(duration_hours // 4)),
                "projected_evidence_volume": max(0, int(duration_hours * 2)),
                "projected_verification_demand": max(1, int(duration_hours)),
                "projected_remediation_demand": 0,
            }
        )

    elif scenario_type == "risk_threshold":
        threshold_change = float(parameters.get("threshold_change", 0.0))
        direction = 1 if threshold_change >= 0 else -1
        base.update(
            {
                "projected_governance_delta": round(direction * abs(threshold_change) * 0.1, 4),
                "projected_workload_change": round(abs(threshold_change) * 0.15, 4),
                "projected_reassessments": max(1, int(abs(threshold_change) * 5)),
                "projected_evidence_volume": max(0, int(abs(threshold_change) * 10)),
                "projected_verification_demand": max(1, int(abs(threshold_change) * 3)),
                "projected_remediation_demand": max(0, int(abs(threshold_change) * 2)),
            }
        )

    elif scenario_type == "reassessment_cadence":
        frequency_days = int(parameters.get("frequency_days", 30))
        annual_count = max(1, 365 // max(1, frequency_days))
        base.update(
            {
                "projected_governance_delta": round(min(0.20, annual_count * 0.005), 3),
                "projected_workload_change": round(annual_count * 0.02, 3),
                "projected_reassessments": annual_count,
                "projected_evidence_volume": annual_count * 10,
                "projected_verification_demand": annual_count * 5,
                "projected_remediation_demand": max(0, annual_count // 4),
            }
        )

    elif scenario_type == "playbook_selection":
        playbook_type = parameters.get("playbook_type", "GENERIC")
        complexity_map = {
            "PCI_DSS": 0.12,
            "HIPAA": 0.10,
            "NIST_CSF": 0.08,
            "ISO_27001": 0.09,
            "SOC2": 0.07,
            "GENERIC": 0.05,
        }
        complexity = complexity_map.get(playbook_type, 0.05)
        base.update(
            {
                "projected_governance_delta": round(complexity * 1.5, 3),
                "projected_workload_change": complexity,
                "projected_reassessments": max(1, int(complexity * 20)),
                "projected_evidence_volume": max(5, int(complexity * 100)),
                "projected_verification_demand": max(2, int(complexity * 30)),
                "projected_remediation_demand": max(1, int(complexity * 10)),
            }
        )

    return base


def compute_simulation_diff(
    baseline: dict[str, Any], simulation: dict[str, Any]
) -> dict[str, Any]:
    """Compute delta between baseline and simulation result dicts."""
    numeric_keys = [
        "projected_governance_delta",
        "projected_workload_change",
        "projected_reassessments",
        "projected_evidence_volume",
        "projected_verification_demand",
        "projected_remediation_demand",
    ]
    delta: dict[str, Any] = {
        "baseline_scenario": baseline.get("scenario_type"),
        "simulation_scenario": simulation.get("scenario_type"),
        "simulation_label": "PROJECTED",
        "is_production": False,
    }
    for key in numeric_keys:
        base_val = baseline.get(key, 0.0)
        sim_val = simulation.get(key, 0.0)
        if isinstance(base_val, (int, float)) and isinstance(sim_val, (int, float)):
            delta[f"{key}_delta"] = round(float(sim_val) - float(base_val), 6)
    return delta
