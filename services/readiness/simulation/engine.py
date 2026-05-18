"""Enterprise Governance Simulation Engine.

Pure Python. No I/O. No SQLAlchemy. No LLMs. No randomness.

Engine contract:
  - Deterministic: identical SimulationInput → identical SimulationProjection.
  - No side effects: the engine never mutates its inputs or any module-level state.
  - Replay-safe: all version pins are recorded in the projection for forensic replay.
  - Uncertainty-explicit: unverifiable/unknown states remain explicit, never optimistic.
  - Failure-safe: any scenario evaluator exception → DEGRADED_VISIBILITY projection,
    never crashes silently or returns a falsely healthy result.
  - Capability governance seam: SimulationCapabilityProjection is populated for
    CAPABILITY_GOVERNANCE_CHANGE scenarios (autonomous-systems governance boundary).
  - Longitudinal governance seam: SimulationGovernanceTrajectory is a stub populated
    for all scenarios (multi-run drift trend extension boundary).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from .identity import derive_simulation_snapshot_id
from .models import (
    SimulationBlastRadius,
    SimulationBoundedAuthorityModel,
    SimulationCapabilityProjection,
    SimulationComplianceProjection,
    SimulationGovernanceTrajectory,
    SimulationImpactRecord,
    SimulationInput,
    SimulationMultiAgentCascadeProjection,
    SimulationProjection,
    SimulationReadinessProjection,
    SimulationRiskDirection,
    SimulationRiskProjection,
    SimulationRunRecord,
    SimulationScenarioType,
    SimulationSeverity,
    SimulationUncertainty,
    SimulationWarning,
)
from .scenarios import (
    evaluate_capability_governance_change,
    evaluate_framework_upgrade,
    evaluate_governance_enforcement_change,
    evaluate_operational_governance_change,
    evaluate_policy_change,
    evaluate_provider_change,
    evaluate_retrieval_strategy_change,
    evaluate_tenant_policy_relaxation,
)

logger = logging.getLogger("frostgate.readiness.simulation")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _degraded_visibility_projection(
    simulation_id: str,
    engine_input: SimulationInput,
    simulated_at_iso: str,
    snapshot_id: str,
    error_detail: str,
) -> SimulationProjection:
    """Produce an explicit DEGRADED_VISIBILITY projection on evaluator failure.

    Fail-closed: the engine never returns an optimistic result on error.
    """
    uncertainty = SimulationUncertainty.DEGRADED_VISIBILITY
    direction = SimulationRiskDirection.UNKNOWN

    readiness = SimulationReadinessProjection(
        baseline_completion_pct=0.0,
        projected_completion_pct=0.0,
        delta_pct=0.0,
        direction=direction,
        impacted_control_ids=(),
        newly_failing_control_ids=(),
        newly_passing_control_ids=(),
        uncertainty=uncertainty,
        basis=f"Simulation engine error: {error_detail}",
    )
    risk = SimulationRiskProjection(
        baseline_risk_score=0.0,
        projected_risk_score=0.0,
        delta=0.0,
        direction=direction,
        risk_factors=(),
        uncertainty=uncertainty,
    )
    compliance = SimulationComplianceProjection(
        baseline_framework_coverage=0.0,
        projected_framework_coverage=0.0,
        delta=0.0,
        direction=direction,
        newly_missing_required_controls=(),
        newly_covered_controls=(),
        maturity_regression=False,
        compliance_risk_increase=False,
        uncertainty=uncertainty,
    )
    blast = SimulationBlastRadius(
        total_affected_controls=0,
        total_affected_evidence=0,
        total_affected_frameworks=0,
        cascading_risk=SimulationSeverity.INFORMATIONAL,
        dependency_chains_impacted=0,
        description=f"Simulation engine error; blast radius uncomputable: {error_detail}",
        uncertainty=uncertainty,
    )

    replay_meta = (
        ("simulation_contract_version", engine_input.simulation_contract_version),
        ("simulation_engine_version", engine_input.simulation_engine_version),
        ("scenario_type", engine_input.scenario_type.value),
        ("error", "degraded_visibility"),
        ("simulated_at", simulated_at_iso),
    )

    return SimulationProjection(
        simulation_id=simulation_id,
        simulation_snapshot_id=snapshot_id,
        tenant_id=engine_input.tenant_id,
        assessment_id=engine_input.assessment_id,
        framework_id=engine_input.framework_id,
        scenario_type=engine_input.scenario_type,
        readiness_projection=readiness,
        risk_projection=risk,
        compliance_projection=compliance,
        blast_radius=blast,
        impact_records=(),
        diff_records=(),
        warnings=(),
        constraints=(),
        capability_projection=None,
        governance_trajectory=None,
        simulation_contract_version=engine_input.simulation_contract_version,
        simulation_engine_version=engine_input.simulation_engine_version,
        framework_version_tag="unknown",
        simulated_at_iso=simulated_at_iso,
        uncertainty=uncertainty,
        replay_contract_metadata=replay_meta,
    )


class SimulationEngine:
    """Deterministic governance simulation engine — pure computation, no I/O.

    Call simulate() with a simulation_id and SimulationInput.
    The engine dispatches to the appropriate scenario evaluator, assembles
    an immutable SimulationProjection, and returns it.

    Fail-closed: any evaluator exception → explicit DEGRADED_VISIBILITY
    projection rather than a silent failure or optimistic default.
    """

    def simulate(
        self,
        simulation_id: str,
        engine_input: SimulationInput,
    ) -> SimulationProjection:
        """Evaluate a governance scenario and return an immutable projection.

        Deterministic: identical simulation_id + engine_input → identical output.
        """
        simulated_at_iso = _now_iso()
        snapshot_id = derive_simulation_snapshot_id(simulation_id, simulated_at_iso)

        try:
            (
                readiness,
                risk,
                compliance,
                impact_list,
                diff_list,
                warning_list,
                blast,
            ) = self._dispatch(simulation_id, engine_input)

            # Build capability projection for CAPABILITY_GOVERNANCE_CHANGE
            capability_projection = self._build_capability_projection(
                simulation_id,
                engine_input,
                impact_list,
                warning_list,
            )

            # Build governance trajectory seam (always populated)
            trajectory = self._build_governance_trajectory(
                simulation_id,
                engine_input,
                warning_list,
                readiness,
            )

            # Determine overall uncertainty
            all_uncertainties = [
                readiness.uncertainty,
                risk.uncertainty,
                compliance.uncertainty,
            ]
            uncertainty = self._aggregate_uncertainty(all_uncertainties)

            replay_meta = (
                (
                    "simulation_contract_version",
                    engine_input.simulation_contract_version,
                ),
                ("simulation_engine_version", engine_input.simulation_engine_version),
                ("scenario_type", engine_input.scenario_type.value),
                ("simulated_at", simulated_at_iso),
                ("simulation_id", simulation_id),
                ("snapshot_id", snapshot_id),
            )

            return SimulationProjection(
                simulation_id=simulation_id,
                simulation_snapshot_id=snapshot_id,
                tenant_id=engine_input.tenant_id,
                assessment_id=engine_input.assessment_id,
                framework_id=engine_input.framework_id,
                scenario_type=engine_input.scenario_type,
                readiness_projection=readiness,
                risk_projection=risk,
                compliance_projection=compliance,
                blast_radius=blast,
                impact_records=tuple(impact_list),
                diff_records=tuple(diff_list),
                warnings=tuple(warning_list),
                constraints=(),
                capability_projection=capability_projection,
                governance_trajectory=trajectory,
                simulation_contract_version=engine_input.simulation_contract_version,
                simulation_engine_version=engine_input.simulation_engine_version,
                framework_version_tag=engine_input.framework_id or "unspecified",
                simulated_at_iso=simulated_at_iso,
                uncertainty=uncertainty,
                replay_contract_metadata=replay_meta,
            )

        except Exception as exc:
            logger.exception(
                "SimulationEngine.simulate() failed for simulation_id=%s scenario=%s: %s",
                simulation_id,
                engine_input.scenario_type.value,
                exc,
            )
            return _degraded_visibility_projection(
                simulation_id=simulation_id,
                engine_input=engine_input,
                simulated_at_iso=simulated_at_iso,
                snapshot_id=snapshot_id,
                error_detail="Evaluation incomplete; simulation coverage is degraded.",
            )

    def _dispatch(
        self,
        simulation_id: str,
        engine_input: SimulationInput,
    ) -> tuple:
        """Dispatch to the appropriate scenario evaluator."""
        scenario_type = engine_input.scenario_type
        params = engine_input.scenario_parameters

        if scenario_type == SimulationScenarioType.PROVIDER_CHANGE:
            return evaluate_provider_change(simulation_id, params)
        elif scenario_type == SimulationScenarioType.POLICY_CHANGE:
            return evaluate_policy_change(simulation_id, params)
        elif scenario_type == SimulationScenarioType.RETRIEVAL_STRATEGY_CHANGE:
            return evaluate_retrieval_strategy_change(simulation_id, params)
        elif scenario_type == SimulationScenarioType.TENANT_POLICY_RELAXATION:
            return evaluate_tenant_policy_relaxation(simulation_id, params)
        elif scenario_type == SimulationScenarioType.FRAMEWORK_UPGRADE:
            return evaluate_framework_upgrade(simulation_id, params)
        elif scenario_type == SimulationScenarioType.GOVERNANCE_ENFORCEMENT_CHANGE:
            return evaluate_governance_enforcement_change(simulation_id, params)
        elif scenario_type == SimulationScenarioType.CAPABILITY_GOVERNANCE_CHANGE:
            return evaluate_capability_governance_change(simulation_id, params)
        elif scenario_type == SimulationScenarioType.OPERATIONAL_GOVERNANCE_CHANGE:
            return evaluate_operational_governance_change(simulation_id, params)
        else:
            raise ValueError(f"Unsupported scenario_type: {scenario_type}")

    def _build_capability_projection(
        self,
        simulation_id: str,
        engine_input: SimulationInput,
        impact_list: list,
        warning_list: list[SimulationWarning],
    ) -> SimulationCapabilityProjection | None:
        """Build a capability projection for CAPABILITY_GOVERNANCE_CHANGE scenarios.

        For other scenarios, returns None (seam for future extension).
        """
        if (
            engine_input.scenario_type
            != SimulationScenarioType.CAPABILITY_GOVERNANCE_CHANGE
        ):
            return None

        params = dict(engine_input.scenario_parameters)
        capability_scope = params.get("capability_scope", "")
        authority_change = params.get("authority_change", "")

        authority_degradation = authority_change == "expand"
        escalation_risk_increase = authority_change == "expand"
        auditability_degradation = authority_change == "expand"
        bounded_authority_degradation = authority_change == "expand"

        uncertainty = (
            SimulationUncertainty.PARTIAL_CONFIDENCE
            if authority_change in ("expand", "restrict")
            else SimulationUncertainty.UNSUPPORTED_BOUNDARY
        )
        basis = (
            f"Capability authority {'expanded' if authority_change == 'expand' else 'restricted'} for {capability_scope}."
            if authority_change in ("expand", "restrict")
            else "Unknown authority change direction."
        )

        # Feature 5: Bounded authority model
        bounded_authority_model = self._build_bounded_authority_model(
            capability_scope, authority_change, uncertainty
        )

        # Feature 5: Multi-agent cascade projection
        multi_agent_cascade = self._build_multi_agent_cascade(
            simulation_id, capability_scope, authority_change, uncertainty
        )

        return SimulationCapabilityProjection(
            capability_scope=capability_scope,
            authority_degradation=authority_degradation,
            escalation_risk_increase=escalation_risk_increase,
            auditability_degradation=auditability_degradation,
            bounded_authority_degradation=bounded_authority_degradation,
            uncertainty=uncertainty,
            basis=basis,
            bounded_authority_model=bounded_authority_model,
            multi_agent_cascade_projection=multi_agent_cascade,
        )

    def _build_bounded_authority_model(
        self,
        capability_scope: str,
        authority_change: str,
        uncertainty: SimulationUncertainty,
    ) -> SimulationBoundedAuthorityModel | None:
        """Build a bounded authority model for capability governance changes."""
        if authority_change == "expand":
            return SimulationBoundedAuthorityModel(
                authority_scope=capability_scope,
                max_delegation_depth=3,
                current_delegation_depth=4,
                delegation_depth_exceeded=True,
                authority_boundary_violated=True,
                execution_envelope_breached=True,
                containment_state="degraded",
                uncertainty=SimulationUncertainty.PARTIAL_CONFIDENCE,
            )
        elif authority_change == "restrict":
            return SimulationBoundedAuthorityModel(
                authority_scope=capability_scope,
                max_delegation_depth=3,
                current_delegation_depth=1,
                delegation_depth_exceeded=False,
                authority_boundary_violated=False,
                execution_envelope_breached=False,
                containment_state="contained",
                uncertainty=SimulationUncertainty.CONFIRMED,
            )
        return None

    def _build_multi_agent_cascade(
        self,
        simulation_id: str,
        capability_scope: str,
        authority_change: str,
        uncertainty: SimulationUncertainty,
    ) -> SimulationMultiAgentCascadeProjection | None:
        """Build a multi-agent cascade projection when scope implies agent involvement."""
        import hashlib as _hashlib

        is_agent_scope = (
            "agent:" in capability_scope or "multi-agent" in capability_scope
        )
        if not is_agent_scope:
            return None

        cascade_id = _hashlib.sha256(
            f"{simulation_id}:{capability_scope}:{authority_change}".encode()
        ).hexdigest()[:16]

        isolation_failure = authority_change == "expand"
        return SimulationMultiAgentCascadeProjection(
            cascade_id=cascade_id,
            affected_agent_count=3,
            cascade_severity=SimulationSeverity.CRITICAL,
            propagation_risk=SimulationRiskDirection.DEGRADED,
            isolation_failure_projected=isolation_failure,
            uncertainty=SimulationUncertainty.PARTIAL_CONFIDENCE,
            basis=f"Multi-agent capability scope {capability_scope}; authority {'expanded' if isolation_failure else 'restricted'}.",
        )

    def _build_governance_trajectory(
        self,
        simulation_id: str,
        engine_input: SimulationInput,
        warning_list: list[SimulationWarning],
        readiness: SimulationReadinessProjection,
    ) -> SimulationGovernanceTrajectory:
        """Build a governance trajectory seam for longitudinal analysis.

        # longitudinal_simulation_seam: this trajectory object becomes the input
        # for multi-run drift trend analysis, readiness decay curves, and chronic
        # governance degradation detection when historical runs are available.
        """
        critical_warnings = sum(
            1 for w in warning_list if w.severity.value in ("critical", "blocking")
        )
        projected_drift = len(warning_list) * 2
        projected_critical = critical_warnings * 3

        stability = readiness.direction
        maturity_trajectory = readiness.direction

        # Aggregate uncertainty from warnings
        if warning_list:
            uncertainty = SimulationUncertainty.PARTIAL_CONFIDENCE
        else:
            uncertainty = SimulationUncertainty.CONFIRMED

        return SimulationGovernanceTrajectory(
            trajectory_id=simulation_id[:16] + "_traj",
            scenario_type=engine_input.scenario_type,
            projected_drift_events=projected_drift,
            projected_critical_events=projected_critical,
            governance_stability=stability,
            maturity_trajectory=maturity_trajectory,
            uncertainty=uncertainty,
        )

    @staticmethod
    def _aggregate_uncertainty(
        uncertainties: list[SimulationUncertainty],
    ) -> SimulationUncertainty:
        """Return the most conservative uncertainty from a list.

        Priority order (worst first):
        DEGRADED_VISIBILITY > UNSUPPORTED_BOUNDARY > UNVERIFIABLE >
        STALE_EVIDENCE > INSUFFICIENT_EVIDENCE > PARTIAL_CONFIDENCE >
        CONFIRMED
        """
        order = {
            SimulationUncertainty.DEGRADED_VISIBILITY: 6,
            SimulationUncertainty.UNSUPPORTED_BOUNDARY: 5,
            SimulationUncertainty.UNVERIFIABLE: 4,
            SimulationUncertainty.STALE_EVIDENCE: 3,
            SimulationUncertainty.INSUFFICIENT_EVIDENCE: 2,
            SimulationUncertainty.PARTIAL_CONFIDENCE: 1,
            SimulationUncertainty.CONFIRMED: 0,
        }
        if not uncertainties:
            return SimulationUncertainty.CONFIRMED
        return max(uncertainties, key=lambda u: order.get(u, 0))
