"""Converts SimulationResult → ExecutionPlan."""

from __future__ import annotations

import hashlib

from services.canonical import utc_iso8601_z_now
from services.governance_execution.models import (
    GOVERNANCE_EXECUTION_PLANNER_VERSION,
    GOVERNANCE_EXECUTION_SCHEMA_VERSION,
    ExecutionApprovalRequirement,
    ExecutionAuthority,
    ExecutionGate,
    ExecutionPlan,
    ExecutionRollbackPlan,
    ExecutionRollbackStep,
    ExecutionStep,
)
from services.governance_execution.registry import (
    GOVERNANCE_GATES,
    get_required_approvers,
)
from services.governance_simulation.models import SimulationResult


_DOMAIN_PRIORITY: dict[str, int] = {
    "authority": 0,
    "governance": 1,
    "control": 2,
    "evidence": 3,
    "framework": 4,
    "compliance": 5,
    "risk": 6,
    "readiness": 7,
    "operational": 8,
    "executive": 9,
}


def _sha256_prefix(s: str, length: int = 20) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:length]


def plan_execution(
    simulation_result: SimulationResult,
    plan_name: str,
    authority: str,
    *,
    approval_type: str = "SingleApprover",
    created_by: str = "system:governance_execution_planner",
) -> ExecutionPlan:
    """Convert a SimulationResult into a governed ExecutionPlan."""
    from services.governance_execution.fingerprint import compute_plan_fingerprint

    tenant_id: str = simulation_result.scenario.tenant_id
    scenario_id: str = simulation_result.scenario.scenario_id
    category: str = simulation_result.scenario.category
    created_at: str = utc_iso8601_z_now()

    plan_id: str = _sha256_prefix(
        f"PLAN:{tenant_id}:{scenario_id}:{simulation_result.simulation_fingerprint}:{plan_name}:{authority}:{approval_type}",
        length=24,
    )

    # Sort diff entries by domain priority, then stable secondary key
    entries = list(simulation_result.diff.entries)
    entries.sort(
        key=lambda e: (
            _DOMAIN_PRIORITY.get(e.domain, 99),
            e.diff_id,
        )
    )

    # Build ExecutionSteps
    steps: list[ExecutionStep] = []
    for i, entry in enumerate(entries, start=1):
        step_id = _sha256_prefix(
            f"STEP:{plan_id}:{entry.diff_id}:{i}",
            length=20,
        )
        step_authority = entry.authority if entry.authority else authority
        step = ExecutionStep(
            step_id=step_id,
            plan_id=plan_id,
            tenant_id=tenant_id,
            sequence=i,
            name=f"Execute {entry.operation} on {entry.domain} [{entry.entity_id or entry.relationship_id or 'unknown'}]",
            description=entry.reason,
            state="Pending",
            preconditions=(),
            postconditions=(),
            dependencies=(),
            authority_required=step_authority,
            evidence_required=(),
            verification_required=True,
            rollback_step_id=None,
        )
        steps.append(step)

    steps_tuple = tuple(steps)

    # Build rollback steps (reverse sequence)
    rollback_steps: list[ExecutionRollbackStep] = []
    for rev_seq, step in enumerate(reversed(steps), start=1):
        rb_step = ExecutionRollbackStep(
            step_id=_sha256_prefix(f"RBSTEP:{plan_id}:{step.step_id}", length=20),
            name=f"Rollback: {step.name}",
            sequence=rev_seq,
            authority_required=step.authority_required,
            reverses_step_id=step.step_id,
        )
        rollback_steps.append(rb_step)

    rollback_plan = ExecutionRollbackPlan(
        rollback_id=_sha256_prefix(f"ROLLBACK:{plan_id}", length=20),
        plan_id=plan_id,
        tenant_id=tenant_id,
        rollback_steps=tuple(rollback_steps),
        rollback_dependencies=(),
        rollback_evidence=(),
        rollback_authority=authority,
        rollback_verification=True,
        rollback_ready=True,
        created_at=created_at,
    )

    # Build governance gates (all Pending)
    gates: list[ExecutionGate] = []
    for gate_name in GOVERNANCE_GATES:
        gate = ExecutionGate(
            gate_id=_sha256_prefix(f"GATE:{plan_id}:{gate_name}", length=20),
            name=gate_name,
            condition=gate_name,
            authority_required=authority,
            evidence_required=(),
            blocking=True,
            result="Pending",
        )
        gates.append(gate)

    # Build approval requirement
    min_approvers = get_required_approvers(approval_type)
    approval_req = ExecutionApprovalRequirement(
        requirement_id=_sha256_prefix(
            f"APPROVALREQ:{plan_id}:{approval_type}", length=20
        ),
        plan_id=plan_id,
        approval_type=approval_type,
        min_approvers=min_approvers,
        authority_required=authority,
        policy_refs=(),
    )

    # Build authority
    exec_authority = ExecutionAuthority(
        authority_id=_sha256_prefix(f"AUTH:{plan_id}:{authority}", length=20),
        name=authority,
        scope="execution",
        permission_level="execute",
        tenant_id=tenant_id,
    )

    lineage = (
        f"exec:{plan_id}"
        f":sim:{simulation_result.scenario.scenario_id}"
        f":snap:{simulation_result.scenario.parent_snapshot_id}"
    )

    # Build plan stub for fingerprint computation
    plan_stub = ExecutionPlan(
        plan_id=plan_id,
        tenant_id=tenant_id,
        simulation_id=scenario_id,
        simulation_fingerprint=simulation_result.simulation_fingerprint,
        digital_twin_fingerprint=simulation_result.scenario.source_snapshot_fingerprint,
        plan_name=plan_name,
        category=category,
        state="Draft",
        created_at=created_at,
        created_by=created_by,
        steps=steps_tuple,
        approval_requirements=(approval_req,),
        rollback_plan=rollback_plan,
        gates=tuple(gates),
        policies=(),
        authorities=(exec_authority,),
        evidence_requirements=(),
        planner_version=GOVERNANCE_EXECUTION_PLANNER_VERSION,
        schema_version=GOVERNANCE_EXECUTION_SCHEMA_VERSION,
        plan_fingerprint="",
        lineage=lineage,
    )

    fingerprint = compute_plan_fingerprint(plan_stub)

    import dataclasses

    plan = dataclasses.replace(plan_stub, plan_fingerprint=fingerprint)
    return plan
