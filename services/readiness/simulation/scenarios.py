"""Deterministic scenario evaluators for governance simulation.

All functions are pure Python: no I/O, no side effects, no randomness.
Each evaluator is called by SimulationEngine with a parsed parameter dict.

Scenario evaluator contract:
  - Each function receives a simulation_id and a dict of scenario parameters.
  - Unknown or missing parameters → UNSUPPORTED_BOUNDARY uncertainty, not an error.
  - All projections are deterministic given the same parameters.
  - No evaluator calls DB, HTTP, or file I/O.
  - Each evaluator returns:
      (SimulationReadinessProjection, SimulationRiskProjection,
       SimulationComplianceProjection, list[SimulationImpactRecord],
       list[SimulationDiffRecord], list[SimulationWarning], SimulationBlastRadius)

Severity mapping (for deterministic projections):
  - Provider blocked → CRITICAL impact, DEGRADED risk/compliance
  - Policy disabled (provenance) → CRITICAL warning, BLOCKING for audit
  - Tenant policy relaxation → always HIGH or CRITICAL warning
  - Framework upgrade with new controls → MODERATE readiness regression
  - Capability governance expand → CRITICAL warning, authority_degradation=True
  - Governance enforcement disabled → BLOCKING warning, DEGRADED

Parameter parsing:
  - Parameters are passed as dict[str, str] (converted from tuple of pairs).
  - Missing parameters produce UNSUPPORTED_BOUNDARY uncertainty but not exceptions.
  - Unknown enforcement modes produce UNSUPPORTED_BOUNDARY uncertainty.
"""

from __future__ import annotations


from .identity import derive_diff_id, derive_impact_id, derive_warning_id
from .models import (
    SimulationBlastRadius,
    SimulationComplianceProjection,
    SimulationDiffRecord,
    SimulationImpactRecord,
    SimulationReadinessProjection,
    SimulationRiskDirection,
    SimulationRiskProjection,
    SimulationSeverity,
    SimulationUncertainty,
    SimulationWarning,
)

# ---------------------------------------------------------------------------
# Type alias for evaluator return
# ---------------------------------------------------------------------------

_EvalResult = tuple[
    SimulationReadinessProjection,
    SimulationRiskProjection,
    SimulationComplianceProjection,
    list[SimulationImpactRecord],
    list[SimulationDiffRecord],
    list[SimulationWarning],
    SimulationBlastRadius,
]

# ---------------------------------------------------------------------------
# Projection defaults (honest about unknowns)
# ---------------------------------------------------------------------------

_BASELINE_COMPLETION = 0.75
_BASELINE_RISK_SCORE = 0.30
_BASELINE_COVERAGE = 0.80


def _degraded_readiness(
    simulation_id: str,
    delta: float,
    impacted_controls: tuple[str, ...],
    newly_failing: tuple[str, ...],
    uncertainty: SimulationUncertainty,
    basis: str,
) -> SimulationReadinessProjection:
    projected = max(0.0, _BASELINE_COMPLETION + delta)
    direction = (
        SimulationRiskDirection.DEGRADED
        if delta < 0
        else (
            SimulationRiskDirection.IMPROVED
            if delta > 0
            else SimulationRiskDirection.UNCHANGED
        )
    )
    return SimulationReadinessProjection(
        baseline_completion_pct=_BASELINE_COMPLETION,
        projected_completion_pct=projected,
        delta_pct=delta,
        direction=direction,
        impacted_control_ids=impacted_controls,
        newly_failing_control_ids=newly_failing,
        newly_passing_control_ids=(),
        uncertainty=uncertainty,
        basis=basis,
    )


def _improved_readiness(
    simulation_id: str,
    delta: float,
    uncertainty: SimulationUncertainty,
    basis: str,
) -> SimulationReadinessProjection:
    projected = min(1.0, _BASELINE_COMPLETION + delta)
    direction = (
        SimulationRiskDirection.IMPROVED
        if delta > 0
        else SimulationRiskDirection.UNCHANGED
    )
    return SimulationReadinessProjection(
        baseline_completion_pct=_BASELINE_COMPLETION,
        projected_completion_pct=projected,
        delta_pct=delta,
        direction=direction,
        impacted_control_ids=(),
        newly_failing_control_ids=(),
        newly_passing_control_ids=(),
        uncertainty=uncertainty,
        basis=basis,
    )


def _unchanged_readiness(
    uncertainty: SimulationUncertainty, basis: str
) -> SimulationReadinessProjection:
    return SimulationReadinessProjection(
        baseline_completion_pct=_BASELINE_COMPLETION,
        projected_completion_pct=_BASELINE_COMPLETION,
        delta_pct=0.0,
        direction=SimulationRiskDirection.UNCHANGED,
        impacted_control_ids=(),
        newly_failing_control_ids=(),
        newly_passing_control_ids=(),
        uncertainty=uncertainty,
        basis=basis,
    )


def _risk_projection(
    delta: float,
    direction: SimulationRiskDirection,
    risk_factors: tuple[tuple[str, str], ...],
    uncertainty: SimulationUncertainty,
) -> SimulationRiskProjection:
    projected = max(0.0, min(1.0, _BASELINE_RISK_SCORE + delta))
    return SimulationRiskProjection(
        baseline_risk_score=_BASELINE_RISK_SCORE,
        projected_risk_score=projected,
        delta=delta,
        direction=direction,
        risk_factors=risk_factors,
        uncertainty=uncertainty,
    )


def _compliance_projection(
    delta: float,
    direction: SimulationRiskDirection,
    newly_missing: tuple[str, ...],
    newly_covered: tuple[str, ...],
    maturity_regression: bool,
    compliance_risk_increase: bool,
    uncertainty: SimulationUncertainty,
) -> SimulationComplianceProjection:
    projected = max(0.0, min(1.0, _BASELINE_COVERAGE + delta))
    return SimulationComplianceProjection(
        baseline_framework_coverage=_BASELINE_COVERAGE,
        projected_framework_coverage=projected,
        delta=delta,
        direction=direction,
        newly_missing_required_controls=newly_missing,
        newly_covered_controls=newly_covered,
        maturity_regression=maturity_regression,
        compliance_risk_increase=compliance_risk_increase,
        uncertainty=uncertainty,
    )


def _blast_radius(
    affected_controls: int,
    cascading_risk: SimulationSeverity,
    description: str,
    uncertainty: SimulationUncertainty,
    affected_evidence: int = 0,
    affected_frameworks: int = 1,
    dependency_chains: int = 1,
) -> SimulationBlastRadius:
    return SimulationBlastRadius(
        total_affected_controls=affected_controls,
        total_affected_evidence=affected_evidence,
        total_affected_frameworks=affected_frameworks,
        cascading_risk=cascading_risk,
        dependency_chains_impacted=dependency_chains,
        description=description,
        uncertainty=uncertainty,
    )


def _make_warning(
    simulation_id: str,
    warning_type: str,
    description: str,
    severity: SimulationSeverity,
    affected_scope: str,
    uncertainty: SimulationUncertainty,
    affected_controls: tuple[str, ...] = (),
) -> SimulationWarning:
    wid = derive_warning_id(simulation_id, warning_type, affected_scope)
    return SimulationWarning(
        warning_id=wid,
        warning_type=warning_type,
        description=description,
        severity=severity,
        affected_scope=affected_scope,
        affected_control_ids=affected_controls,
        uncertainty=uncertainty,
    )


def _make_impact(
    simulation_id: str,
    domain: str,
    description: str,
    severity: SimulationSeverity,
    affected_scope: str,
    direction: SimulationRiskDirection,
    uncertainty: SimulationUncertainty,
    affected_ids: tuple[str, ...] = (),
) -> SimulationImpactRecord:
    iid = derive_impact_id(simulation_id, domain, affected_scope)
    return SimulationImpactRecord(
        impact_id=iid,
        impact_domain=domain,
        impact_description=description,
        severity=severity,
        affected_scope=affected_scope,
        affected_ids=affected_ids,
        direction=direction,
        uncertainty=uncertainty,
    )


def _make_diff(
    simulation_id: str,
    diff_type: str,
    before_value: str,
    after_value: str,
    affected_scope: str,
    severity: SimulationSeverity,
    direction: SimulationRiskDirection,
) -> SimulationDiffRecord:
    did = derive_diff_id(simulation_id, diff_type, before_value, after_value)
    return SimulationDiffRecord(
        diff_id=did,
        diff_type=diff_type,
        before_value=before_value,
        after_value=after_value,
        affected_scope=affected_scope,
        severity=severity,
        direction=direction,
    )


def _params_to_dict(params: tuple[tuple[str, str], ...]) -> dict[str, str]:
    return dict(params)


# ---------------------------------------------------------------------------
# Scenario evaluators
# ---------------------------------------------------------------------------


def evaluate_provider_change(
    simulation_id: str,
    params: tuple[tuple[str, str], ...],
) -> _EvalResult:
    """Evaluate PROVIDER_CHANGE scenario.

    Parameters:
      - provider_id: identifier of the provider being changed
      - new_status: allowed | blocked | restricted (default: unknown)
      - new_governance_classification: new classification label
      - new_region: new provider region
    """
    p = _params_to_dict(params)
    provider_id = p.get("provider_id", "")
    new_status = p.get("new_status", "")

    if not provider_id or not new_status:
        uncertainty = SimulationUncertainty.UNSUPPORTED_BOUNDARY
        readiness = _unchanged_readiness(
            uncertainty, "Missing provider_id or new_status parameters."
        )
        risk = _risk_projection(0.0, SimulationRiskDirection.UNKNOWN, (), uncertainty)
        compliance = _compliance_projection(
            0.0, SimulationRiskDirection.UNKNOWN, (), (), False, False, uncertainty
        )
        blast = _blast_radius(
            0,
            SimulationSeverity.INFORMATIONAL,
            "Insufficient parameters to compute blast radius.",
            uncertainty,
        )
        return readiness, risk, compliance, [], [], [], blast

    if new_status == "blocked":
        uncertainty = SimulationUncertainty.CONFIRMED
        readiness = _degraded_readiness(
            simulation_id,
            delta=-0.10,
            impacted_controls=(),
            newly_failing=(),
            uncertainty=uncertainty,
            basis=f"Provider {provider_id} blocked; affected controls lose evidence linkage.",
        )
        risk = _risk_projection(
            0.20,
            SimulationRiskDirection.DEGRADED,
            (
                (
                    "provider_blocked",
                    f"Provider {provider_id} moved to blocked status.",
                ),
                (
                    "compliance_coverage_loss",
                    "Provider-dependent controls lose evidence.",
                ),
            ),
            uncertainty,
        )
        compliance = _compliance_projection(
            -0.12,
            SimulationRiskDirection.DEGRADED,
            (),
            (),
            maturity_regression=True,
            compliance_risk_increase=True,
            uncertainty=uncertainty,
        )
        impacts = [
            _make_impact(
                simulation_id,
                "provider_governance",
                f"Provider {provider_id} will be blocked; all dependent controls affected.",
                SimulationSeverity.CRITICAL,
                f"provider:{provider_id}",
                SimulationRiskDirection.DEGRADED,
                uncertainty,
            )
        ]
        diffs = [
            _make_diff(
                simulation_id,
                "provider_status",
                "allowed",
                "blocked",
                f"provider:{provider_id}",
                SimulationSeverity.CRITICAL,
                SimulationRiskDirection.DEGRADED,
            )
        ]
        warnings = [
            _make_warning(
                simulation_id,
                "provider_blocked_governance",
                f"Provider {provider_id} blocked status will degrade compliance coverage and readiness.",
                SimulationSeverity.CRITICAL,
                f"provider:{provider_id}",
                uncertainty,
            )
        ]
        blast = _blast_radius(
            5,
            SimulationSeverity.CRITICAL,
            f"Provider {provider_id} blocked; estimated 5 controls lose evidence linkage.",
            uncertainty,
            affected_evidence=3,
            affected_frameworks=1,
            dependency_chains=2,
        )
        return readiness, risk, compliance, impacts, diffs, warnings, blast

    elif new_status == "restricted":
        uncertainty = SimulationUncertainty.PARTIAL_CONFIDENCE
        readiness = _degraded_readiness(
            simulation_id,
            delta=-0.04,
            impacted_controls=(),
            newly_failing=(),
            uncertainty=uncertainty,
            basis=f"Provider {provider_id} restricted; partial compliance coverage loss.",
        )
        risk = _risk_projection(
            0.08,
            SimulationRiskDirection.DEGRADED,
            (("provider_restricted", f"Provider {provider_id} restricted."),),
            uncertainty,
        )
        compliance = _compliance_projection(
            -0.04,
            SimulationRiskDirection.DEGRADED,
            (),
            (),
            maturity_regression=False,
            compliance_risk_increase=True,
            uncertainty=uncertainty,
        )
        impacts = [
            _make_impact(
                simulation_id,
                "provider_governance",
                f"Provider {provider_id} restricted; partial coverage reduction projected.",
                SimulationSeverity.HIGH,
                f"provider:{provider_id}",
                SimulationRiskDirection.DEGRADED,
                uncertainty,
            )
        ]
        diffs = [
            _make_diff(
                simulation_id,
                "provider_status",
                "allowed",
                "restricted",
                f"provider:{provider_id}",
                SimulationSeverity.HIGH,
                SimulationRiskDirection.DEGRADED,
            )
        ]
        warnings = [
            _make_warning(
                simulation_id,
                "provider_restricted_governance",
                f"Provider {provider_id} restricted; review compliance dependencies.",
                SimulationSeverity.HIGH,
                f"provider:{provider_id}",
                uncertainty,
            )
        ]
        blast = _blast_radius(
            2,
            SimulationSeverity.HIGH,
            f"Provider {provider_id} restricted; estimated 2 controls affected.",
            uncertainty,
        )
        return readiness, risk, compliance, impacts, diffs, warnings, blast

    elif new_status == "allowed":
        uncertainty = SimulationUncertainty.CONFIRMED
        readiness = _improved_readiness(
            simulation_id,
            delta=0.03,
            uncertainty=uncertainty,
            basis=f"Provider {provider_id} allowed; governance coverage expected to improve.",
        )
        risk = _risk_projection(
            -0.05,
            SimulationRiskDirection.IMPROVED,
            (("provider_approved", f"Provider {provider_id} approved for use."),),
            uncertainty,
        )
        compliance = _compliance_projection(
            0.04,
            SimulationRiskDirection.IMPROVED,
            (),
            (),
            maturity_regression=False,
            compliance_risk_increase=False,
            uncertainty=uncertainty,
        )
        impacts = [
            _make_impact(
                simulation_id,
                "provider_governance",
                f"Provider {provider_id} allowed; governance coverage improves.",
                SimulationSeverity.INFORMATIONAL,
                f"provider:{provider_id}",
                SimulationRiskDirection.IMPROVED,
                uncertainty,
            )
        ]
        diffs = [
            _make_diff(
                simulation_id,
                "provider_status",
                "blocked",
                "allowed",
                f"provider:{provider_id}",
                SimulationSeverity.LOW,
                SimulationRiskDirection.IMPROVED,
            )
        ]
        blast = _blast_radius(
            0,
            SimulationSeverity.INFORMATIONAL,
            f"Provider {provider_id} approved; no cascading risk projected.",
            uncertainty,
        )
        return readiness, risk, compliance, impacts, diffs, [], blast

    else:
        # Unknown status
        uncertainty = SimulationUncertainty.UNSUPPORTED_BOUNDARY
        readiness = _unchanged_readiness(
            uncertainty, f"Unknown provider status '{new_status}'."
        )
        risk = _risk_projection(0.0, SimulationRiskDirection.UNKNOWN, (), uncertainty)
        compliance = _compliance_projection(
            0.0, SimulationRiskDirection.UNKNOWN, (), (), False, False, uncertainty
        )
        warnings = [
            _make_warning(
                simulation_id,
                "unknown_provider_status",
                f"Provider status '{new_status}' is not a recognized governance state.",
                SimulationSeverity.MODERATE,
                f"provider:{provider_id}",
                uncertainty,
            )
        ]
        blast = _blast_radius(
            0,
            SimulationSeverity.INFORMATIONAL,
            "Unknown status; blast radius uncomputable.",
            uncertainty,
        )
        return readiness, risk, compliance, [], [], warnings, blast


def evaluate_policy_change(
    simulation_id: str,
    params: tuple[tuple[str, str], ...],
) -> _EvalResult:
    """Evaluate POLICY_CHANGE scenario.

    Parameters:
      - policy_id: identifier of the policy being changed
      - new_enabled: true | false
      - new_enforcement_mode: strict | permissive | disabled
    """
    p = _params_to_dict(params)
    policy_id = p.get("policy_id", "")
    new_enabled_raw = p.get("new_enabled", "")
    new_enforcement = p.get("new_enforcement_mode", "")

    if not policy_id:
        uncertainty = SimulationUncertainty.UNSUPPORTED_BOUNDARY
        readiness = _unchanged_readiness(uncertainty, "Missing policy_id parameter.")
        risk = _risk_projection(0.0, SimulationRiskDirection.UNKNOWN, (), uncertainty)
        compliance = _compliance_projection(
            0.0, SimulationRiskDirection.UNKNOWN, (), (), False, False, uncertainty
        )
        blast = _blast_radius(
            0, SimulationSeverity.INFORMATIONAL, "Insufficient parameters.", uncertainty
        )
        return readiness, risk, compliance, [], [], [], blast

    new_enabled = new_enabled_raw.lower() != "false" if new_enabled_raw else True
    is_provenance = "provenance" in policy_id.lower()
    is_audit = "audit" in policy_id.lower()

    if not new_enabled:
        # Policy disabled
        if is_provenance:
            uncertainty = SimulationUncertainty.CONFIRMED
            readiness = _degraded_readiness(
                simulation_id,
                delta=-0.15,
                impacted_controls=(),
                newly_failing=(),
                uncertainty=uncertainty,
                basis=f"Policy {policy_id} disabled; provenance enforcement gap introduced.",
            )
            risk = _risk_projection(
                0.25,
                SimulationRiskDirection.DEGRADED,
                (
                    (
                        "provenance_enforcement_disabled",
                        f"Policy {policy_id} disabled.",
                    ),
                    ("attestation_gap", "Provenance attestation no longer enforced."),
                ),
                uncertainty,
            )
            compliance = _compliance_projection(
                -0.18,
                SimulationRiskDirection.DEGRADED,
                (),
                (),
                maturity_regression=True,
                compliance_risk_increase=True,
                uncertainty=uncertainty,
            )
            impacts = [
                _make_impact(
                    simulation_id,
                    "policy_governance",
                    f"Provenance policy {policy_id} disabled; attestation enforcement gap.",
                    SimulationSeverity.CRITICAL,
                    f"policy:{policy_id}",
                    SimulationRiskDirection.DEGRADED,
                    uncertainty,
                )
            ]
            diffs = [
                _make_diff(
                    simulation_id,
                    "policy_enabled",
                    "true",
                    "false",
                    f"policy:{policy_id}",
                    SimulationSeverity.CRITICAL,
                    SimulationRiskDirection.DEGRADED,
                )
            ]
            warnings = [
                _make_warning(
                    simulation_id,
                    "provenance_policy_disabled",
                    f"Policy {policy_id} (provenance) disabled. This is a CRITICAL governance exposure.",
                    SimulationSeverity.CRITICAL,
                    f"policy:{policy_id}",
                    uncertainty,
                )
            ]
            blast = _blast_radius(
                8,
                SimulationSeverity.CRITICAL,
                f"Provenance policy {policy_id} disabled; 8 controls lose provenance enforcement.",
                uncertainty,
                affected_evidence=5,
                dependency_chains=3,
            )
            return readiness, risk, compliance, impacts, diffs, warnings, blast

        elif is_audit:
            uncertainty = SimulationUncertainty.CONFIRMED
            readiness = _degraded_readiness(
                simulation_id,
                delta=-0.12,
                impacted_controls=(),
                newly_failing=(),
                uncertainty=uncertainty,
                basis=f"Audit policy {policy_id} disabled; audit chain integrity at risk.",
            )
            risk = _risk_projection(
                0.20,
                SimulationRiskDirection.DEGRADED,
                (("audit_policy_disabled", f"Audit policy {policy_id} disabled."),),
                uncertainty,
            )
            compliance = _compliance_projection(
                -0.15,
                SimulationRiskDirection.DEGRADED,
                (),
                (),
                maturity_regression=True,
                compliance_risk_increase=True,
                uncertainty=uncertainty,
            )
            impacts = [
                _make_impact(
                    simulation_id,
                    "audit_governance",
                    f"Audit policy {policy_id} disabled; audit chain integrity at risk.",
                    SimulationSeverity.BLOCKING,
                    f"policy:{policy_id}",
                    SimulationRiskDirection.DEGRADED,
                    uncertainty,
                )
            ]
            diffs = [
                _make_diff(
                    simulation_id,
                    "policy_enabled",
                    "true",
                    "false",
                    f"policy:{policy_id}",
                    SimulationSeverity.BLOCKING,
                    SimulationRiskDirection.DEGRADED,
                )
            ]
            warnings = [
                _make_warning(
                    simulation_id,
                    "audit_policy_disabled",
                    f"Policy {policy_id} (audit) disabled. This is a BLOCKING governance violation.",
                    SimulationSeverity.BLOCKING,
                    f"policy:{policy_id}",
                    uncertainty,
                )
            ]
            blast = _blast_radius(
                10,
                SimulationSeverity.BLOCKING,
                f"Audit policy {policy_id} disabled; full audit chain integrity at risk.",
                uncertainty,
                affected_evidence=8,
                dependency_chains=4,
            )
            return readiness, risk, compliance, impacts, diffs, warnings, blast

        else:
            uncertainty = SimulationUncertainty.CONFIRMED
            readiness = _degraded_readiness(
                simulation_id,
                delta=-0.06,
                impacted_controls=(),
                newly_failing=(),
                uncertainty=uncertainty,
                basis=f"Policy {policy_id} disabled; governance coverage reduced.",
            )
            risk = _risk_projection(
                0.10,
                SimulationRiskDirection.DEGRADED,
                (("policy_disabled", f"Policy {policy_id} disabled."),),
                uncertainty,
            )
            compliance = _compliance_projection(
                -0.06,
                SimulationRiskDirection.DEGRADED,
                (),
                (),
                maturity_regression=False,
                compliance_risk_increase=True,
                uncertainty=uncertainty,
            )
            impacts = [
                _make_impact(
                    simulation_id,
                    "policy_governance",
                    f"Policy {policy_id} disabled; moderate governance coverage loss.",
                    SimulationSeverity.MODERATE,
                    f"policy:{policy_id}",
                    SimulationRiskDirection.DEGRADED,
                    uncertainty,
                )
            ]
            diffs = [
                _make_diff(
                    simulation_id,
                    "policy_enabled",
                    "true",
                    "false",
                    f"policy:{policy_id}",
                    SimulationSeverity.MODERATE,
                    SimulationRiskDirection.DEGRADED,
                )
            ]
            warnings = [
                _make_warning(
                    simulation_id,
                    "policy_disabled",
                    f"Policy {policy_id} disabled; governance coverage reduced.",
                    SimulationSeverity.MODERATE,
                    f"policy:{policy_id}",
                    uncertainty,
                )
            ]
            blast = _blast_radius(
                3,
                SimulationSeverity.MODERATE,
                f"Policy {policy_id} disabled; 3 controls affected.",
                uncertainty,
            )
            return readiness, risk, compliance, impacts, diffs, warnings, blast

    else:
        # Policy enabled — check enforcement mode
        if new_enforcement == "strict":
            uncertainty = SimulationUncertainty.CONFIRMED
            readiness = _improved_readiness(
                simulation_id,
                delta=0.05,
                uncertainty=uncertainty,
                basis=f"Policy {policy_id} enabled with strict enforcement.",
            )
            risk = _risk_projection(
                -0.08,
                SimulationRiskDirection.IMPROVED,
                (
                    (
                        "strict_enforcement",
                        f"Policy {policy_id} strict enforcement active.",
                    ),
                ),
                uncertainty,
            )
            compliance = _compliance_projection(
                0.06,
                SimulationRiskDirection.IMPROVED,
                (),
                (),
                maturity_regression=False,
                compliance_risk_increase=False,
                uncertainty=uncertainty,
            )
            blast = _blast_radius(
                0,
                SimulationSeverity.INFORMATIONAL,
                f"Policy {policy_id} strict enforcement; no cascading risk.",
                uncertainty,
            )
            return readiness, risk, compliance, [], [], [], blast

        elif new_enforcement == "permissive":
            uncertainty = SimulationUncertainty.PARTIAL_CONFIDENCE
            readiness = _unchanged_readiness(
                uncertainty, f"Policy {policy_id} enabled permissive; minimal change."
            )
            risk = _risk_projection(
                0.03,
                SimulationRiskDirection.DEGRADED,
                (
                    (
                        "permissive_enforcement",
                        f"Policy {policy_id} permissive mode reduces enforcement strength.",
                    ),
                ),
                uncertainty,
            )
            compliance = _compliance_projection(
                -0.02,
                SimulationRiskDirection.DEGRADED,
                (),
                (),
                maturity_regression=False,
                compliance_risk_increase=False,
                uncertainty=uncertainty,
            )
            blast = _blast_radius(
                0,
                SimulationSeverity.LOW,
                f"Policy {policy_id} permissive; minimal blast radius.",
                uncertainty,
            )
            return readiness, risk, compliance, [], [], [], blast

        elif new_enforcement == "disabled":
            # Enforcement mode disabled even though enabled=true is unusual
            uncertainty = SimulationUncertainty.UNSUPPORTED_BOUNDARY
            readiness = _unchanged_readiness(
                uncertainty,
                f"Policy {policy_id} enabled but enforcement disabled — unusual state.",
            )
            risk = _risk_projection(
                0.05, SimulationRiskDirection.DEGRADED, (), uncertainty
            )
            compliance = _compliance_projection(
                -0.05,
                SimulationRiskDirection.DEGRADED,
                (),
                (),
                False,
                True,
                uncertainty,
            )
            warnings = [
                _make_warning(
                    simulation_id,
                    "policy_enforcement_disabled",
                    f"Policy {policy_id} enabled but enforcement_mode=disabled; governance inconsistency.",
                    SimulationSeverity.HIGH,
                    f"policy:{policy_id}",
                    uncertainty,
                )
            ]
            blast = _blast_radius(
                1,
                SimulationSeverity.HIGH,
                f"Policy {policy_id} inconsistent state; uncertain blast radius.",
                uncertainty,
            )
            return readiness, risk, compliance, [], [], warnings, blast

        elif not new_enforcement:
            uncertainty = SimulationUncertainty.UNSUPPORTED_BOUNDARY
            readiness = _unchanged_readiness(
                uncertainty, f"Policy {policy_id} enabled; enforcement mode unknown."
            )
            risk = _risk_projection(
                0.0, SimulationRiskDirection.UNKNOWN, (), uncertainty
            )
            compliance = _compliance_projection(
                0.0, SimulationRiskDirection.UNKNOWN, (), (), False, False, uncertainty
            )
            blast = _blast_radius(
                0,
                SimulationSeverity.INFORMATIONAL,
                "Unknown enforcement mode.",
                uncertainty,
            )
            return readiness, risk, compliance, [], [], [], blast

        else:
            uncertainty = SimulationUncertainty.UNSUPPORTED_BOUNDARY
            readiness = _unchanged_readiness(
                uncertainty, f"Unknown enforcement mode '{new_enforcement}'."
            )
            risk = _risk_projection(
                0.0, SimulationRiskDirection.UNKNOWN, (), uncertainty
            )
            compliance = _compliance_projection(
                0.0, SimulationRiskDirection.UNKNOWN, (), (), False, False, uncertainty
            )
            warnings = [
                _make_warning(
                    simulation_id,
                    "unknown_enforcement_mode",
                    f"Enforcement mode '{new_enforcement}' is not a recognized governance state.",
                    SimulationSeverity.MODERATE,
                    f"policy:{policy_id}",
                    uncertainty,
                )
            ]
            blast = _blast_radius(
                0,
                SimulationSeverity.INFORMATIONAL,
                "Unknown enforcement mode.",
                uncertainty,
            )
            return readiness, risk, compliance, [], [], warnings, blast


def evaluate_retrieval_strategy_change(
    simulation_id: str,
    params: tuple[tuple[str, str], ...],
) -> _EvalResult:
    """Evaluate RETRIEVAL_STRATEGY_CHANGE scenario.

    Parameters:
      - policy_id: retrieval policy identifier
      - new_enabled: true | false
      - new_reranker_state: active | degraded | disabled
    """
    p = _params_to_dict(params)
    policy_id = p.get("policy_id", "")
    new_enabled_raw = p.get("new_enabled", "")
    reranker_state = p.get("new_reranker_state", "")

    if not policy_id:
        uncertainty = SimulationUncertainty.UNSUPPORTED_BOUNDARY
        readiness = _unchanged_readiness(
            uncertainty, "Missing policy_id for retrieval strategy."
        )
        risk = _risk_projection(0.0, SimulationRiskDirection.UNKNOWN, (), uncertainty)
        compliance = _compliance_projection(
            0.0, SimulationRiskDirection.UNKNOWN, (), (), False, False, uncertainty
        )
        blast = _blast_radius(
            0, SimulationSeverity.INFORMATIONAL, "Missing policy_id.", uncertainty
        )
        return readiness, risk, compliance, [], [], [], blast

    new_enabled = new_enabled_raw.lower() != "false" if new_enabled_raw else True

    if not new_enabled:
        uncertainty = SimulationUncertainty.CONFIRMED
        readiness = _degraded_readiness(
            simulation_id,
            delta=-0.08,
            impacted_controls=(),
            newly_failing=(),
            uncertainty=uncertainty,
            basis=f"Retrieval policy {policy_id} disabled; evidence retrieval governance degraded.",
        )
        risk = _risk_projection(
            0.15,
            SimulationRiskDirection.DEGRADED,
            (
                (
                    "retrieval_policy_disabled",
                    f"Retrieval policy {policy_id} disabled.",
                ),
                ("evidence_gap", "Evidence retrieval governance coverage reduced."),
            ),
            uncertainty,
        )
        compliance = _compliance_projection(
            -0.09,
            SimulationRiskDirection.DEGRADED,
            (),
            (),
            maturity_regression=False,
            compliance_risk_increase=True,
            uncertainty=uncertainty,
        )
        impacts = [
            _make_impact(
                simulation_id,
                "retrieval_governance",
                f"Retrieval policy {policy_id} disabled; evidence retrieval governance degraded.",
                SimulationSeverity.HIGH,
                f"retrieval_policy:{policy_id}",
                SimulationRiskDirection.DEGRADED,
                uncertainty,
            )
        ]
        diffs = [
            _make_diff(
                simulation_id,
                "retrieval_policy_enabled",
                "true",
                "false",
                f"retrieval_policy:{policy_id}",
                SimulationSeverity.HIGH,
                SimulationRiskDirection.DEGRADED,
            )
        ]
        warnings = [
            _make_warning(
                simulation_id,
                "retrieval_policy_disabled",
                f"Retrieval policy {policy_id} disabled; evidence coverage at risk.",
                SimulationSeverity.HIGH,
                f"retrieval_policy:{policy_id}",
                uncertainty,
            )
        ]
        blast = _blast_radius(
            4,
            SimulationSeverity.HIGH,
            f"Retrieval policy {policy_id} disabled; 4 controls lose evidence retrieval.",
            uncertainty,
            affected_evidence=6,
        )
        return readiness, risk, compliance, impacts, diffs, warnings, blast

    # Policy enabled — check reranker state
    if reranker_state == "disabled":
        uncertainty = SimulationUncertainty.PARTIAL_CONFIDENCE
        readiness = _degraded_readiness(
            simulation_id,
            delta=-0.03,
            impacted_controls=(),
            newly_failing=(),
            uncertainty=uncertainty,
            basis=f"Reranker disabled for {policy_id}; evidence quality governance reduced.",
        )
        risk = _risk_projection(
            0.06,
            SimulationRiskDirection.DEGRADED,
            (
                (
                    "reranker_disabled",
                    f"Reranker for {policy_id} disabled; quality degraded.",
                ),
            ),
            uncertainty,
        )
        compliance = _compliance_projection(
            -0.03,
            SimulationRiskDirection.DEGRADED,
            (),
            (),
            maturity_regression=False,
            compliance_risk_increase=False,
            uncertainty=uncertainty,
        )
        warnings = [
            _make_warning(
                simulation_id,
                "reranker_disabled",
                f"Reranker disabled for retrieval policy {policy_id}; evidence quality governance reduced.",
                SimulationSeverity.MODERATE,
                f"retrieval_policy:{policy_id}",
                uncertainty,
            )
        ]
        blast = _blast_radius(
            1,
            SimulationSeverity.MODERATE,
            f"Reranker disabled for {policy_id}; quality degradation projected.",
            uncertainty,
        )
        return readiness, risk, compliance, [], [], warnings, blast

    elif reranker_state == "active" or reranker_state == "":
        uncertainty = SimulationUncertainty.CONFIRMED
        readiness = _improved_readiness(
            simulation_id,
            delta=0.04,
            uncertainty=uncertainty,
            basis=f"Retrieval policy {policy_id} enabled with active reranker.",
        )
        risk = _risk_projection(
            -0.06,
            SimulationRiskDirection.IMPROVED,
            (
                (
                    "retrieval_active",
                    f"Retrieval policy {policy_id} active with reranker.",
                ),
            ),
            uncertainty,
        )
        compliance = _compliance_projection(
            0.04,
            SimulationRiskDirection.IMPROVED,
            (),
            (),
            maturity_regression=False,
            compliance_risk_increase=False,
            uncertainty=uncertainty,
        )
        blast = _blast_radius(
            0,
            SimulationSeverity.INFORMATIONAL,
            f"Retrieval policy {policy_id} active; no cascading risk.",
            uncertainty,
        )
        return readiness, risk, compliance, [], [], [], blast

    elif reranker_state == "degraded":
        uncertainty = SimulationUncertainty.PARTIAL_CONFIDENCE
        readiness = _unchanged_readiness(
            uncertainty, f"Retrieval policy {policy_id} enabled; reranker degraded."
        )
        risk = _risk_projection(
            0.04,
            SimulationRiskDirection.DEGRADED,
            (("reranker_degraded", f"Reranker degraded for {policy_id}."),),
            uncertainty,
        )
        compliance = _compliance_projection(
            -0.02,
            SimulationRiskDirection.DEGRADED,
            (),
            (),
            maturity_regression=False,
            compliance_risk_increase=False,
            uncertainty=uncertainty,
        )
        blast = _blast_radius(
            0,
            SimulationSeverity.LOW,
            f"Reranker degraded for {policy_id}; minimal impact.",
            uncertainty,
        )
        return readiness, risk, compliance, [], [], [], blast

    else:
        uncertainty = SimulationUncertainty.UNSUPPORTED_BOUNDARY
        readiness = _unchanged_readiness(
            uncertainty, f"Unknown reranker state '{reranker_state}'."
        )
        risk = _risk_projection(0.0, SimulationRiskDirection.UNKNOWN, (), uncertainty)
        compliance = _compliance_projection(
            0.0, SimulationRiskDirection.UNKNOWN, (), (), False, False, uncertainty
        )
        blast = _blast_radius(
            0, SimulationSeverity.INFORMATIONAL, "Unknown reranker state.", uncertainty
        )
        return readiness, risk, compliance, [], [], [], blast


def evaluate_tenant_policy_relaxation(
    simulation_id: str,
    params: tuple[tuple[str, str], ...],
) -> _EvalResult:
    """Evaluate TENANT_POLICY_RELAXATION scenario.

    Parameters:
      - relaxation_type: evidence | provenance | audit | retrieval | escalation
      - new_threshold: new threshold value (informational)

    Always generates HIGH or CRITICAL governance exposure warning.
    """
    p = _params_to_dict(params)
    relaxation_type = p.get("relaxation_type", "")
    new_threshold = p.get("new_threshold", "unknown")

    if not relaxation_type:
        uncertainty = SimulationUncertainty.UNSUPPORTED_BOUNDARY
        readiness = _unchanged_readiness(
            uncertainty, "Missing relaxation_type parameter."
        )
        risk = _risk_projection(0.0, SimulationRiskDirection.UNKNOWN, (), uncertainty)
        compliance = _compliance_projection(
            0.0, SimulationRiskDirection.UNKNOWN, (), (), False, False, uncertainty
        )
        blast = _blast_radius(
            0, SimulationSeverity.INFORMATIONAL, "Missing relaxation_type.", uncertainty
        )
        return readiness, risk, compliance, [], [], [], blast

    is_provenance = relaxation_type == "provenance"
    is_audit = relaxation_type == "audit"
    is_escalation = relaxation_type == "escalation"

    if is_provenance:
        uncertainty = SimulationUncertainty.PARTIAL_CONFIDENCE
        severity = SimulationSeverity.CRITICAL
        delta_readiness = -0.10
        delta_risk = 0.20
    elif is_audit:
        uncertainty = SimulationUncertainty.PARTIAL_CONFIDENCE
        severity = SimulationSeverity.CRITICAL
        delta_readiness = -0.08
        delta_risk = 0.18
    elif is_escalation:
        uncertainty = SimulationUncertainty.PARTIAL_CONFIDENCE
        severity = SimulationSeverity.HIGH
        delta_readiness = -0.05
        delta_risk = 0.12
    else:
        uncertainty = SimulationUncertainty.PARTIAL_CONFIDENCE
        severity = SimulationSeverity.HIGH
        delta_readiness = -0.04
        delta_risk = 0.08

    readiness = _degraded_readiness(
        simulation_id,
        delta=delta_readiness,
        impacted_controls=(),
        newly_failing=(),
        uncertainty=uncertainty,
        basis=f"Tenant policy relaxation on {relaxation_type}; governance exposure increases.",
    )
    risk = _risk_projection(
        delta_risk,
        SimulationRiskDirection.DEGRADED,
        (
            (
                "policy_relaxation",
                f"Tenant {relaxation_type} policy relaxed to {new_threshold}.",
            ),
            (
                "governance_exposure",
                "Relaxed policy increases governance risk exposure.",
            ),
        ),
        uncertainty,
    )
    compliance = _compliance_projection(
        -abs(delta_readiness),
        SimulationRiskDirection.DEGRADED,
        (),
        (),
        maturity_regression=is_provenance or is_audit,
        compliance_risk_increase=True,
        uncertainty=uncertainty,
    )
    impacts = [
        _make_impact(
            simulation_id,
            "tenant_policy_governance",
            f"Tenant {relaxation_type} policy relaxed; governance exposure increases.",
            severity,
            f"tenant_policy:{relaxation_type}",
            SimulationRiskDirection.DEGRADED,
            uncertainty,
        )
    ]
    diffs = [
        _make_diff(
            simulation_id,
            "tenant_policy_threshold",
            "original",
            new_threshold,
            f"tenant_policy:{relaxation_type}",
            severity,
            SimulationRiskDirection.DEGRADED,
        )
    ]
    warnings = [
        _make_warning(
            simulation_id,
            f"tenant_policy_relaxation_{relaxation_type}",
            (
                f"Tenant policy relaxation on {relaxation_type} (new_threshold={new_threshold}) "
                f"introduces governance exposure. This change MUST be reviewed by compliance."
            ),
            severity,
            f"tenant_policy:{relaxation_type}",
            uncertainty,
        )
    ]
    blast = _blast_radius(
        3,
        severity,
        f"Tenant {relaxation_type} policy relaxed; 3 controls affected.",
        uncertainty,
        affected_evidence=2,
    )
    return readiness, risk, compliance, impacts, diffs, warnings, blast


def evaluate_framework_upgrade(
    simulation_id: str,
    params: tuple[tuple[str, str], ...],
) -> _EvalResult:
    """Evaluate FRAMEWORK_UPGRADE scenario.

    Parameters:
      - target_framework_version_tag: new version tag
      - added_control_count: number of new controls added
      - removed_control_count: number of controls removed
    """
    p = _params_to_dict(params)
    version_tag = p.get("target_framework_version_tag", "unknown")

    try:
        added = int(p.get("added_control_count", "0"))
    except (ValueError, TypeError):
        added = 0

    try:
        removed = int(p.get("removed_control_count", "0"))
    except (ValueError, TypeError):
        removed = 0

    net = added - removed

    if net == 0 and added == 0:
        uncertainty = SimulationUncertainty.CONFIRMED
        readiness = _unchanged_readiness(
            uncertainty, f"Framework upgrade to {version_tag}; no control delta."
        )
        risk = _risk_projection(0.0, SimulationRiskDirection.UNCHANGED, (), uncertainty)
        compliance = _compliance_projection(
            0.0, SimulationRiskDirection.UNCHANGED, (), (), False, False, uncertainty
        )
        blast = _blast_radius(
            0,
            SimulationSeverity.INFORMATIONAL,
            f"Framework upgrade to {version_tag}; no control changes.",
            uncertainty,
        )
        return readiness, risk, compliance, [], [], [], blast

    if added > 0:
        # New controls must be evidenced — readiness will drop
        uncertainty = SimulationUncertainty.CONFIRMED
        # Each added control reduces completion by ~1/total_controls fraction
        # Approximating: assume ~50 total controls
        completion_delta = -(added / 50.0)
        newly_missing = tuple(f"new_control_{i}" for i in range(min(added, 10)))

        readiness = _degraded_readiness(
            simulation_id,
            delta=completion_delta,
            impacted_controls=newly_missing,
            newly_failing=newly_missing,
            uncertainty=uncertainty,
            basis=f"Framework {version_tag} adds {added} controls requiring new evidence.",
        )
        risk = _risk_projection(
            added * 0.01,
            SimulationRiskDirection.DEGRADED,
            (
                ("new_controls_unevidenced", f"{added} new controls require evidence."),
                (
                    "framework_upgrade_gap",
                    f"Framework version gap: upgrading to {version_tag}.",
                ),
            ),
            uncertainty,
        )
        compliance = _compliance_projection(
            completion_delta,
            SimulationRiskDirection.DEGRADED,
            newly_missing,
            tuple(f"removed_control_{i}" for i in range(min(removed, 5))),
            maturity_regression=added > 3,
            compliance_risk_increase=True,
            uncertainty=uncertainty,
        )
        impacts = [
            _make_impact(
                simulation_id,
                "framework_compliance",
                f"Framework upgrade to {version_tag}: {added} new controls unevidenced.",
                SimulationSeverity.MODERATE if added <= 5 else SimulationSeverity.HIGH,
                f"framework:{version_tag}",
                SimulationRiskDirection.DEGRADED,
                uncertainty,
            )
        ]
        diffs = [
            _make_diff(
                simulation_id,
                "framework_version",
                "current",
                version_tag,
                "framework",
                SimulationSeverity.MODERATE,
                SimulationRiskDirection.DEGRADED,
            ),
            _make_diff(
                simulation_id,
                "control_count_added",
                "0",
                str(added),
                "framework_controls",
                SimulationSeverity.MODERATE,
                SimulationRiskDirection.DEGRADED,
            ),
        ]
        warnings = [
            _make_warning(
                simulation_id,
                "framework_upgrade_readiness_regression",
                f"Framework upgrade to {version_tag}: {added} new controls will cause readiness regression until evidenced.",
                SimulationSeverity.MODERATE,
                f"framework:{version_tag}",
                uncertainty,
            )
        ]
        blast = _blast_radius(
            added,
            SimulationSeverity.MODERATE if added <= 5 else SimulationSeverity.HIGH,
            f"Framework upgrade adds {added} controls; each requires new evidence.",
            uncertainty,
            dependency_chains=max(1, added // 3),
        )
        return readiness, risk, compliance, impacts, diffs, warnings, blast

    else:
        # Only controls removed — compliance can improve
        uncertainty = SimulationUncertainty.CONFIRMED
        completion_delta = removed / 50.0
        readiness = _improved_readiness(
            simulation_id,
            delta=completion_delta,
            uncertainty=uncertainty,
            basis=f"Framework {version_tag} removes {removed} controls; coverage improves.",
        )
        risk = _risk_projection(
            -removed * 0.005,
            SimulationRiskDirection.IMPROVED,
            (
                (
                    "controls_removed",
                    f"{removed} controls removed from framework {version_tag}.",
                ),
            ),
            uncertainty,
        )
        compliance = _compliance_projection(
            removed / 50.0,
            SimulationRiskDirection.IMPROVED,
            (),
            (),
            maturity_regression=False,
            compliance_risk_increase=False,
            uncertainty=uncertainty,
        )
        blast = _blast_radius(
            0,
            SimulationSeverity.INFORMATIONAL,
            f"Framework {version_tag}: {removed} controls removed; no new evidence required.",
            uncertainty,
        )
        return readiness, risk, compliance, [], [], [], blast


def evaluate_governance_enforcement_change(
    simulation_id: str,
    params: tuple[tuple[str, str], ...],
) -> _EvalResult:
    """Evaluate GOVERNANCE_ENFORCEMENT_CHANGE scenario.

    Parameters:
      - enforcement_mode: strict | permissive | disabled
    """
    p = _params_to_dict(params)
    enforcement_mode = p.get("enforcement_mode", "")

    if not enforcement_mode:
        uncertainty = SimulationUncertainty.UNSUPPORTED_BOUNDARY
        readiness = _unchanged_readiness(
            uncertainty, "Missing enforcement_mode parameter."
        )
        risk = _risk_projection(0.0, SimulationRiskDirection.UNKNOWN, (), uncertainty)
        compliance = _compliance_projection(
            0.0, SimulationRiskDirection.UNKNOWN, (), (), False, False, uncertainty
        )
        blast = _blast_radius(
            0,
            SimulationSeverity.INFORMATIONAL,
            "Missing enforcement_mode.",
            uncertainty,
        )
        return readiness, risk, compliance, [], [], [], blast

    if enforcement_mode == "disabled":
        uncertainty = SimulationUncertainty.CONFIRMED
        readiness = _degraded_readiness(
            simulation_id,
            delta=-0.20,
            impacted_controls=(),
            newly_failing=(),
            uncertainty=uncertainty,
            basis="Governance enforcement disabled; all enforcement controls become ineffective.",
        )
        risk = _risk_projection(
            0.35,
            SimulationRiskDirection.DEGRADED,
            (
                ("enforcement_disabled", "Global governance enforcement disabled."),
                (
                    "controls_ineffective",
                    "All enforcement-dependent controls become ineffective.",
                ),
                (
                    "compliance_exposure",
                    "Full governance compliance exposure introduced.",
                ),
            ),
            uncertainty,
        )
        compliance = _compliance_projection(
            -0.25,
            SimulationRiskDirection.DEGRADED,
            (),
            (),
            maturity_regression=True,
            compliance_risk_increase=True,
            uncertainty=uncertainty,
        )
        impacts = [
            _make_impact(
                simulation_id,
                "governance_enforcement",
                "Global governance enforcement disabled; all enforcement controls ineffective.",
                SimulationSeverity.BLOCKING,
                "governance:enforcement",
                SimulationRiskDirection.DEGRADED,
                uncertainty,
            )
        ]
        diffs = [
            _make_diff(
                simulation_id,
                "enforcement_mode",
                "strict",
                "disabled",
                "governance:enforcement",
                SimulationSeverity.BLOCKING,
                SimulationRiskDirection.DEGRADED,
            )
        ]
        warnings = [
            _make_warning(
                simulation_id,
                "governance_enforcement_disabled",
                "Global governance enforcement disabled. This is a BLOCKING governance violation and will prevent all readiness milestones.",
                SimulationSeverity.BLOCKING,
                "governance:enforcement",
                uncertainty,
            )
        ]
        blast = _blast_radius(
            20,
            SimulationSeverity.BLOCKING,
            "Governance enforcement disabled; all enforcement-dependent controls affected across all frameworks.",
            uncertainty,
            affected_evidence=15,
            affected_frameworks=3,
            dependency_chains=8,
        )
        return readiness, risk, compliance, impacts, diffs, warnings, blast

    elif enforcement_mode == "permissive":
        uncertainty = SimulationUncertainty.PARTIAL_CONFIDENCE
        readiness = _degraded_readiness(
            simulation_id,
            delta=-0.08,
            impacted_controls=(),
            newly_failing=(),
            uncertainty=uncertainty,
            basis="Governance enforcement set to permissive; enforcement strength reduced.",
        )
        risk = _risk_projection(
            0.12,
            SimulationRiskDirection.DEGRADED,
            (("permissive_enforcement", "Governance enforcement mode is permissive."),),
            uncertainty,
        )
        compliance = _compliance_projection(
            -0.08,
            SimulationRiskDirection.DEGRADED,
            (),
            (),
            maturity_regression=False,
            compliance_risk_increase=True,
            uncertainty=uncertainty,
        )
        impacts = [
            _make_impact(
                simulation_id,
                "governance_enforcement",
                "Governance enforcement permissive; enforcement strength reduced.",
                SimulationSeverity.HIGH,
                "governance:enforcement",
                SimulationRiskDirection.DEGRADED,
                uncertainty,
            )
        ]
        diffs = [
            _make_diff(
                simulation_id,
                "enforcement_mode",
                "strict",
                "permissive",
                "governance:enforcement",
                SimulationSeverity.HIGH,
                SimulationRiskDirection.DEGRADED,
            )
        ]
        warnings = [
            _make_warning(
                simulation_id,
                "governance_enforcement_permissive",
                "Governance enforcement mode set to permissive; compliance risk increases.",
                SimulationSeverity.HIGH,
                "governance:enforcement",
                uncertainty,
            )
        ]
        blast = _blast_radius(
            8,
            SimulationSeverity.HIGH,
            "Permissive enforcement; 8 controls at risk of non-compliance.",
            uncertainty,
            dependency_chains=3,
        )
        return readiness, risk, compliance, impacts, diffs, warnings, blast

    elif enforcement_mode == "strict":
        uncertainty = SimulationUncertainty.CONFIRMED
        readiness = _improved_readiness(
            simulation_id,
            delta=0.05,
            uncertainty=uncertainty,
            basis="Governance enforcement set to strict; all controls fully enforced.",
        )
        risk = _risk_projection(
            -0.10,
            SimulationRiskDirection.IMPROVED,
            (("strict_enforcement", "Governance enforcement mode is strict."),),
            uncertainty,
        )
        compliance = _compliance_projection(
            0.06,
            SimulationRiskDirection.IMPROVED,
            (),
            (),
            maturity_regression=False,
            compliance_risk_increase=False,
            uncertainty=uncertainty,
        )
        blast = _blast_radius(
            0,
            SimulationSeverity.INFORMATIONAL,
            "Strict governance enforcement; no cascading risk.",
            uncertainty,
        )
        return readiness, risk, compliance, [], [], [], blast

    else:
        uncertainty = SimulationUncertainty.UNSUPPORTED_BOUNDARY
        readiness = _unchanged_readiness(
            uncertainty, f"Unknown enforcement mode '{enforcement_mode}'."
        )
        risk = _risk_projection(0.0, SimulationRiskDirection.UNKNOWN, (), uncertainty)
        compliance = _compliance_projection(
            0.0, SimulationRiskDirection.UNKNOWN, (), (), False, False, uncertainty
        )
        warnings = [
            _make_warning(
                simulation_id,
                "unknown_enforcement_mode",
                f"Enforcement mode '{enforcement_mode}' is not a recognized governance state.",
                SimulationSeverity.MODERATE,
                "governance:enforcement",
                uncertainty,
            )
        ]
        blast = _blast_radius(
            0,
            SimulationSeverity.INFORMATIONAL,
            "Unknown enforcement mode.",
            uncertainty,
        )
        return readiness, risk, compliance, [], [], warnings, blast


def evaluate_capability_governance_change(
    simulation_id: str,
    params: tuple[tuple[str, str], ...],
) -> _EvalResult:
    """Evaluate CAPABILITY_GOVERNANCE_CHANGE scenario.

    Parameters:
      - capability_scope: scope identifier of the capability
      - authority_change: expand | restrict

    # capability_governance_seam: capability scope governance, autonomous-systems
    # authority delegation, and bounded-authority enforcement extend from here.
    # multi_agent_governance_seam: multi-agent capability attestation and delegation
    # chain integrity extend from authority_change=expand scenarios.
    """
    p = _params_to_dict(params)
    capability_scope = p.get("capability_scope", "")
    authority_change = p.get("authority_change", "")

    if not capability_scope or not authority_change:
        uncertainty = SimulationUncertainty.UNSUPPORTED_BOUNDARY
        readiness = _unchanged_readiness(
            uncertainty, "Missing capability_scope or authority_change."
        )
        risk = _risk_projection(0.0, SimulationRiskDirection.UNKNOWN, (), uncertainty)
        compliance = _compliance_projection(
            0.0, SimulationRiskDirection.UNKNOWN, (), (), False, False, uncertainty
        )
        blast = _blast_radius(
            0, SimulationSeverity.INFORMATIONAL, "Missing parameters.", uncertainty
        )
        return readiness, risk, compliance, [], [], [], blast

    if authority_change == "expand":
        uncertainty = SimulationUncertainty.PARTIAL_CONFIDENCE
        readiness = _degraded_readiness(
            simulation_id,
            delta=-0.08,
            impacted_controls=(),
            newly_failing=(),
            uncertainty=uncertainty,
            basis=f"Capability authority expansion for {capability_scope}; escalation risk increases.",
        )
        risk = _risk_projection(
            0.20,
            SimulationRiskDirection.DEGRADED,
            (
                (
                    "authority_expansion",
                    f"Capability {capability_scope} authority expanded.",
                ),
                (
                    "escalation_risk",
                    "Expanded authority increases uncontrolled escalation risk.",
                ),
                (
                    "bounded_authority_violation",
                    "Principle of least privilege potentially violated.",
                ),
            ),
            uncertainty,
        )
        compliance = _compliance_projection(
            -0.08,
            SimulationRiskDirection.DEGRADED,
            (),
            (),
            maturity_regression=False,
            compliance_risk_increase=True,
            uncertainty=uncertainty,
        )
        impacts = [
            _make_impact(
                simulation_id,
                "capability_governance",
                f"Capability {capability_scope} authority expanded; escalation risk increases.",
                SimulationSeverity.CRITICAL,
                f"capability:{capability_scope}",
                SimulationRiskDirection.DEGRADED,
                uncertainty,
            )
        ]
        diffs = [
            _make_diff(
                simulation_id,
                "capability_authority",
                "restricted",
                "expanded",
                f"capability:{capability_scope}",
                SimulationSeverity.CRITICAL,
                SimulationRiskDirection.DEGRADED,
            )
        ]
        warnings = [
            _make_warning(
                simulation_id,
                "capability_authority_expansion",
                (
                    f"Capability {capability_scope} authority expanded. This introduces escalation risk "
                    f"and may violate bounded-authority governance principles. Review required."
                ),
                SimulationSeverity.CRITICAL,
                f"capability:{capability_scope}",
                uncertainty,
            )
        ]
        blast = _blast_radius(
            5,
            SimulationSeverity.CRITICAL,
            f"Capability {capability_scope} authority expanded; 5 controls may need revalidation.",
            uncertainty,
            dependency_chains=2,
        )
        return readiness, risk, compliance, impacts, diffs, warnings, blast

    elif authority_change == "restrict":
        uncertainty = SimulationUncertainty.CONFIRMED
        readiness = _improved_readiness(
            simulation_id,
            delta=0.04,
            uncertainty=uncertainty,
            basis=f"Capability {capability_scope} authority restricted; bounded-authority improved.",
        )
        risk = _risk_projection(
            -0.10,
            SimulationRiskDirection.IMPROVED,
            (
                ("authority_restriction", f"Capability {capability_scope} restricted."),
                (
                    "bounded_authority_improved",
                    "Principle of least privilege enforced.",
                ),
            ),
            uncertainty,
        )
        compliance = _compliance_projection(
            0.04,
            SimulationRiskDirection.IMPROVED,
            (),
            (),
            maturity_regression=False,
            compliance_risk_increase=False,
            uncertainty=uncertainty,
        )
        blast = _blast_radius(
            0,
            SimulationSeverity.INFORMATIONAL,
            f"Capability {capability_scope} restricted; no cascading risk.",
            uncertainty,
        )
        return readiness, risk, compliance, [], [], [], blast

    else:
        uncertainty = SimulationUncertainty.UNSUPPORTED_BOUNDARY
        readiness = _unchanged_readiness(
            uncertainty, f"Unknown authority_change '{authority_change}'."
        )
        risk = _risk_projection(0.0, SimulationRiskDirection.UNKNOWN, (), uncertainty)
        compliance = _compliance_projection(
            0.0, SimulationRiskDirection.UNKNOWN, (), (), False, False, uncertainty
        )
        warnings = [
            _make_warning(
                simulation_id,
                "unknown_authority_change",
                f"Authority change '{authority_change}' is not a recognized governance state.",
                SimulationSeverity.MODERATE,
                f"capability:{capability_scope}",
                uncertainty,
            )
        ]
        blast = _blast_radius(
            0,
            SimulationSeverity.INFORMATIONAL,
            "Unknown authority change.",
            uncertainty,
        )
        return readiness, risk, compliance, [], [], warnings, blast


def evaluate_operational_governance_change(
    simulation_id: str,
    params: tuple[tuple[str, str], ...],
) -> _EvalResult:
    """Evaluate OPERATIONAL_GOVERNANCE_CHANGE scenario.

    Parameters:
      - governance_signal_failure_rate: float string (0.0 to 1.0)
      - enforcement_mode: strict | permissive | disabled
    """
    p = _params_to_dict(params)
    enforcement_mode = p.get("enforcement_mode", "strict")

    try:
        failure_rate = float(p.get("governance_signal_failure_rate", "0.0"))
    except (ValueError, TypeError):
        failure_rate = 0.0

    if enforcement_mode == "disabled" or failure_rate >= 0.5:
        uncertainty = SimulationUncertainty.CONFIRMED
        severity = (
            SimulationSeverity.CRITICAL
            if failure_rate >= 0.5
            else SimulationSeverity.HIGH
        )
        readiness = _degraded_readiness(
            simulation_id,
            delta=-0.12 - (failure_rate * 0.10),
            impacted_controls=(),
            newly_failing=(),
            uncertainty=uncertainty,
            basis=f"Operational governance degraded (failure_rate={failure_rate:.2f}, mode={enforcement_mode}).",
        )
        risk = _risk_projection(
            0.20 + failure_rate * 0.15,
            SimulationRiskDirection.DEGRADED,
            (
                (
                    "operational_governance_degraded",
                    f"Failure rate {failure_rate:.2f}; mode {enforcement_mode}.",
                ),
                ("signal_failure", "Governance signals failing at elevated rate."),
            ),
            uncertainty,
        )
        compliance = _compliance_projection(
            -0.12,
            SimulationRiskDirection.DEGRADED,
            (),
            (),
            maturity_regression=True,
            compliance_risk_increase=True,
            uncertainty=uncertainty,
        )
        impacts = [
            _make_impact(
                simulation_id,
                "operational_governance",
                f"Operational governance degraded: failure_rate={failure_rate:.2f}, mode={enforcement_mode}.",
                severity,
                "operational_governance:signals",
                SimulationRiskDirection.DEGRADED,
                uncertainty,
            )
        ]
        diffs = [
            _make_diff(
                simulation_id,
                "governance_signal_failure_rate",
                "0.0",
                str(failure_rate),
                "operational_governance:signals",
                severity,
                SimulationRiskDirection.DEGRADED,
            )
        ]
        warnings = [
            _make_warning(
                simulation_id,
                "operational_governance_degraded",
                f"Operational governance failure rate {failure_rate:.2f} with mode {enforcement_mode}; readiness at risk.",
                severity,
                "operational_governance:signals",
                uncertainty,
            )
        ]
        blast = _blast_radius(
            int(failure_rate * 10),
            severity,
            f"Operational governance failure rate {failure_rate:.2f}; cascading signal failures.",
            uncertainty,
            dependency_chains=2,
        )
        return readiness, risk, compliance, impacts, diffs, warnings, blast

    elif enforcement_mode == "permissive" or failure_rate > 0.0:
        uncertainty = SimulationUncertainty.PARTIAL_CONFIDENCE
        readiness = _degraded_readiness(
            simulation_id,
            delta=-0.05,
            impacted_controls=(),
            newly_failing=(),
            uncertainty=uncertainty,
            basis=f"Operational governance permissive (failure_rate={failure_rate:.2f}).",
        )
        risk = _risk_projection(
            0.08,
            SimulationRiskDirection.DEGRADED,
            (
                (
                    "operational_governance_permissive",
                    f"Mode {enforcement_mode}; rate {failure_rate:.2f}.",
                ),
            ),
            uncertainty,
        )
        compliance = _compliance_projection(
            -0.05,
            SimulationRiskDirection.DEGRADED,
            (),
            (),
            maturity_regression=False,
            compliance_risk_increase=True,
            uncertainty=uncertainty,
        )
        blast = _blast_radius(
            2,
            SimulationSeverity.MODERATE,
            "Operational governance permissive; 2 controls at risk.",
            uncertainty,
        )
        return readiness, risk, compliance, [], [], [], blast

    else:
        uncertainty = SimulationUncertainty.CONFIRMED
        readiness = _unchanged_readiness(
            uncertainty, "Operational governance strict with 0 failures."
        )
        risk = _risk_projection(0.0, SimulationRiskDirection.UNCHANGED, (), uncertainty)
        compliance = _compliance_projection(
            0.0, SimulationRiskDirection.UNCHANGED, (), (), False, False, uncertainty
        )
        blast = _blast_radius(
            0,
            SimulationSeverity.INFORMATIONAL,
            "Strict governance; no blast radius.",
            uncertainty,
        )
        return readiness, risk, compliance, [], [], [], blast
