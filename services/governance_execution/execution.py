"""Execution lifecycle state machine for the Governance Execution Engine."""

from __future__ import annotations

import dataclasses
import hashlib

from services.canonical import utc_iso8601_z_now
from services.governance_execution.approvals import check_approval_requirements
from services.governance_execution.fingerprint import (
    compute_audit_fingerprint,
    compute_run_fingerprint,
)
from services.governance_execution.models import (
    ExecutionApproval,
    ExecutionAuditRecord,
    ExecutionPlan,
    ExecutionRun,
)
from services.governance_execution.registry import is_valid_transition
from services.governance_execution.validator import ExecutionValidationError


def create_run(
    plan: ExecutionPlan,
    approvals: tuple[ExecutionApproval, ...],
) -> ExecutionRun:
    """Create an ExecutionRun for the given plan after validating approvals.

    Raises ExecutionValidationError if approvals are not satisfied.
    """
    satisfied, unmet = check_approval_requirements(plan, approvals)
    if not satisfied:
        raise ExecutionValidationError(
            "Approval requirements not satisfied: " + "; ".join(unmet)
        )

    started_at = utc_iso8601_z_now()
    run_id = hashlib.sha256(
        f"RUN:{plan.plan_id}:{started_at}:{plan.plan_fingerprint}".encode("utf-8")
    ).hexdigest()[:24]

    run_stub = ExecutionRun(
        run_id=run_id,
        plan_id=plan.plan_id,
        tenant_id=plan.tenant_id,
        state="Draft",
        started_at=started_at,
        completed_at=None,
        failed_at=None,
        simulation_id=plan.simulation_id,
        simulation_fingerprint=plan.simulation_fingerprint,
        executed_steps=(),
        skipped_steps=(),
        failed_steps=(),
        verification_ids=(),
        measurement_ids=(),
        approvals=approvals,
        rollback_reference=None,
        run_fingerprint="",
    )

    fingerprint = compute_run_fingerprint(run_stub)
    return dataclasses.replace(run_stub, run_fingerprint=fingerprint)


def advance_state(
    run: ExecutionRun,
    new_state: str,
    *,
    actor: str = "system:governance_execution",
    reason: str = "",
) -> tuple[ExecutionRun, ExecutionAuditRecord]:
    """Advance run state via the state machine.

    Raises ExecutionValidationError on invalid transition.
    Returns (updated_run, audit_record).
    """
    if not is_valid_transition(run.state, new_state):
        raise ExecutionValidationError(
            f"Invalid state transition: {run.state!r} → {new_state!r}"
        )

    event_at = utc_iso8601_z_now()
    audit_id = hashlib.sha256(
        f"AUDIT:{run.run_id}:{run.state}:{new_state}:{event_at}".encode("utf-8")
    ).hexdigest()[:20]

    audit_stub = ExecutionAuditRecord(
        audit_id=audit_id,
        plan_id=run.plan_id,
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        event_type="state_transition",
        event_at=event_at,
        actor=actor,
        authority=actor,
        before_state=run.state,
        after_state=new_state,
        reason=reason,
        fingerprint="",
    )
    audit_fingerprint = compute_audit_fingerprint(audit_stub)
    audit_record = dataclasses.replace(audit_stub, fingerprint=audit_fingerprint)

    updated_run = dataclasses.replace(run, state=new_state)
    return updated_run, audit_record


def complete_step(
    run: ExecutionRun,
    step_id: str,
) -> ExecutionRun:
    """Mark a step as completed by adding it to executed_steps."""
    return dataclasses.replace(
        run,
        executed_steps=run.executed_steps + (step_id,),
    )


def fail_step(
    run: ExecutionRun,
    step_id: str,
) -> ExecutionRun:
    """Mark a step as failed by adding it to failed_steps."""
    return dataclasses.replace(
        run,
        failed_steps=run.failed_steps + (step_id,),
    )
