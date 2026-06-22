"""Export-safe deterministic serialization for simulation outputs.

All functions are pure Python: no I/O, no side effects.

Serialization contract:
  - Output is deterministic: identical SimulationProjection → identical serialized form.
  - All dicts use sort_keys=True for canonical ordering.
  - No secrets, vectors, prompts, raw evidence bodies, PHI, or internal topology.
  - All export-safe fields are preserved; no additional scrubbing needed downstream.
  - Historical projections remain deserializable by future consumers that are version-aware.

# signed_attestation_seam: cryptographic signing of the canonical JSON goes here.
# The output of json.dumps(..., sort_keys=True) is the canonical byte sequence
# to sign. A detached signature record (key_id, algorithm, signature_b64)
# stored alongside projection_json enables regulator/auditor/legal attestation
# without modifying the projection payload itself.

# sovereignty_simulation_seam: residency-aware simulation projections for sovereign
# AI deployments extend from this serialization boundary. A SovereigntyProjection
# sub-record (region, export_boundary, residency_compliance) can be added as an
# optional field in the serialized output without breaking existing consumers.
# This boundary is the anchor for EU AI Act residency projection scenarios and
# govcon boundary enforcement simulations.
"""

from __future__ import annotations

import json

from .models import (
    SimulationBlastRadius,
    SimulationBoundedAuthorityModel,
    SimulationCapabilityProjection,
    SimulationComplianceProjection,
    SimulationDiffRecord,
    SimulationGovernanceTrajectory,
    SimulationImpactRecord,
    SimulationMultiAgentCascadeProjection,
    SimulationProjection,
    SimulationReadinessProjection,
    SimulationRiskProjection,
    SimulationWarning,
)


def _serialize_readiness_projection(r: SimulationReadinessProjection) -> dict:
    return {
        "baseline_completion_pct": r.baseline_completion_pct,
        "projected_completion_pct": r.projected_completion_pct,
        "delta_pct": r.delta_pct,
        "direction": r.direction.value,
        "impacted_control_ids": sorted(r.impacted_control_ids),
        "newly_failing_control_ids": sorted(r.newly_failing_control_ids),
        "newly_passing_control_ids": sorted(r.newly_passing_control_ids),
        "uncertainty": r.uncertainty.value,
        "basis": r.basis,
    }


def _serialize_risk_projection(r: SimulationRiskProjection) -> dict:
    return {
        "baseline_risk_score": r.baseline_risk_score,
        "projected_risk_score": r.projected_risk_score,
        "delta": r.delta,
        "direction": r.direction.value,
        "risk_factors": {k: v for k, v in r.risk_factors},
        "uncertainty": r.uncertainty.value,
    }


def _serialize_compliance_projection(c: SimulationComplianceProjection) -> dict:
    return {
        "baseline_framework_coverage": c.baseline_framework_coverage,
        "projected_framework_coverage": c.projected_framework_coverage,
        "delta": c.delta,
        "direction": c.direction.value,
        "newly_missing_required_controls": sorted(c.newly_missing_required_controls),
        "newly_covered_controls": sorted(c.newly_covered_controls),
        "maturity_regression": c.maturity_regression,
        "compliance_risk_increase": c.compliance_risk_increase,
        "uncertainty": c.uncertainty.value,
    }


def _serialize_blast_radius(b: SimulationBlastRadius) -> dict:
    return {
        "total_affected_controls": b.total_affected_controls,
        "total_affected_evidence": b.total_affected_evidence,
        "total_affected_frameworks": b.total_affected_frameworks,
        "cascading_risk": b.cascading_risk.value,
        "dependency_chains_impacted": b.dependency_chains_impacted,
        "description": b.description,
        "uncertainty": b.uncertainty.value,
    }


def _serialize_impact_record(i: SimulationImpactRecord) -> dict:
    return {
        "impact_id": i.impact_id,
        "impact_domain": i.impact_domain,
        "impact_description": i.impact_description,
        "severity": i.severity.value,
        "affected_scope": i.affected_scope,
        "affected_ids": sorted(i.affected_ids),
        "direction": i.direction.value,
        "uncertainty": i.uncertainty.value,
    }


def _serialize_diff_record(d: SimulationDiffRecord) -> dict:
    return {
        "diff_id": d.diff_id,
        "diff_type": d.diff_type,
        "before_value": d.before_value,
        "after_value": d.after_value,
        "affected_scope": d.affected_scope,
        "severity": d.severity.value,
        "direction": d.direction.value,
    }


def _serialize_warning(w: SimulationWarning) -> dict:
    return {
        "warning_id": w.warning_id,
        "warning_type": w.warning_type,
        "description": w.description,
        "severity": w.severity.value,
        "affected_scope": w.affected_scope,
        "affected_control_ids": sorted(w.affected_control_ids),
        "uncertainty": w.uncertainty.value,
    }


def _serialize_bounded_authority_model(
    b: SimulationBoundedAuthorityModel | None,
) -> dict | None:
    if b is None:
        return None
    return {
        "authority_scope": b.authority_scope,
        "max_delegation_depth": b.max_delegation_depth,
        "current_delegation_depth": b.current_delegation_depth,
        "delegation_depth_exceeded": b.delegation_depth_exceeded,
        "authority_boundary_violated": b.authority_boundary_violated,
        "execution_envelope_breached": b.execution_envelope_breached,
        "containment_state": b.containment_state,
        "uncertainty": b.uncertainty.value,
    }


def _serialize_multi_agent_cascade(
    m: SimulationMultiAgentCascadeProjection | None,
) -> dict | None:
    if m is None:
        return None
    return {
        "cascade_id": m.cascade_id,
        "affected_agent_count": m.affected_agent_count,
        "cascade_severity": m.cascade_severity.value,
        "propagation_risk": m.propagation_risk.value,
        "isolation_failure_projected": m.isolation_failure_projected,
        "uncertainty": m.uncertainty.value,
        "basis": m.basis,
    }


def _serialize_capability_projection(
    c: SimulationCapabilityProjection | None,
) -> dict | None:
    if c is None:
        return None
    return {
        "capability_scope": c.capability_scope,
        "authority_degradation": c.authority_degradation,
        "escalation_risk_increase": c.escalation_risk_increase,
        "auditability_degradation": c.auditability_degradation,
        "bounded_authority_degradation": c.bounded_authority_degradation,
        "uncertainty": c.uncertainty.value,
        "basis": c.basis,
        "bounded_authority_model": _serialize_bounded_authority_model(
            c.bounded_authority_model
        ),
        "multi_agent_cascade_projection": _serialize_multi_agent_cascade(
            c.multi_agent_cascade_projection
        ),
    }


def _serialize_governance_trajectory(
    t: SimulationGovernanceTrajectory | None,
) -> dict | None:
    if t is None:
        return None
    return {
        "trajectory_id": t.trajectory_id,
        "scenario_type": t.scenario_type.value,
        "projected_drift_events": t.projected_drift_events,
        "projected_critical_events": t.projected_critical_events,
        "governance_stability": t.governance_stability.value,
        "maturity_trajectory": t.maturity_trajectory.value,
        "uncertainty": t.uncertainty.value,
    }


def serialize_projection(projection: SimulationProjection) -> dict:
    """Serialize a SimulationProjection to an export-safe dict.

    Deterministic: identical projection → identical serialized form.
    No secrets, vectors, prompts, PHI, or internal topology.
    """
    return {
        "simulation_id": projection.simulation_id,
        "simulation_snapshot_id": projection.simulation_snapshot_id,
        "tenant_id": projection.tenant_id,
        "assessment_id": projection.assessment_id,
        "framework_id": projection.framework_id,
        "scenario_type": projection.scenario_type.value,
        "readiness_projection": _serialize_readiness_projection(
            projection.readiness_projection
        ),
        "risk_projection": _serialize_risk_projection(projection.risk_projection),
        "compliance_projection": _serialize_compliance_projection(
            projection.compliance_projection
        ),
        "blast_radius": _serialize_blast_radius(projection.blast_radius),
        "impact_records": [
            _serialize_impact_record(i) for i in projection.impact_records
        ],
        "diff_records": [_serialize_diff_record(d) for d in projection.diff_records],
        "warnings": [_serialize_warning(w) for w in projection.warnings],
        "constraints": [
            {
                "constraint_id": c.constraint_id,
                "constraint_type": c.constraint_type,
                "description": c.description,
                "severity": c.severity.value,
                "blocks_simulation": c.blocks_simulation,
            }
            for c in projection.constraints
        ],
        "capability_projection": _serialize_capability_projection(
            projection.capability_projection
        ),
        "governance_trajectory": _serialize_governance_trajectory(
            projection.governance_trajectory
        ),
        "simulation_contract_version": projection.simulation_contract_version,
        "simulation_engine_version": projection.simulation_engine_version,
        "framework_version_tag": projection.framework_version_tag,
        "simulated_at_iso": projection.simulated_at_iso,
        "uncertainty": projection.uncertainty.value,
        "replay_contract_metadata": {
            k: v for k, v in projection.replay_contract_metadata
        },
    }


def projection_to_json(projection: SimulationProjection) -> str:
    """Serialize a projection to canonical JSON.

    # signed_attestation_seam: the output of json.dumps(..., sort_keys=True) is
    # the canonical byte sequence to sign. A detached Ed25519 or ECDSA-P256 signature
    # over SHA-256(canonical_bytes) produces a self-verifying governance artifact.
    # A verification endpoint would accept {projection_json, signature_b64, key_id}
    # and return pass/fail without re-running the simulation.

    # sovereignty_simulation_seam: canonical JSON is the anchor for sovereignty
    # projection signing and residency attestation in sovereign deployments.
    """
    return json.dumps(serialize_projection(projection), sort_keys=True)


def projection_from_json(raw: str) -> dict:
    """Deserialize a stored projection JSON string. Returns a plain dict for API use."""
    return json.loads(raw)
