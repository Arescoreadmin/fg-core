"""Rollback planning and execution for the Governance Execution Engine."""

from __future__ import annotations

import dataclasses
import hashlib

from services.canonical import utc_iso8601_z_now
from services.governance_execution.fingerprint import compute_audit_fingerprint
from services.governance_execution.models import (
    ExecutionAuditRecord,
    ExecutionPlan,
    ExecutionRollbackPlan,
    ExecutionRollbackStep,
    ExecutionRun,
)
from services.governance_execution.validator import ExecutionValidationError


def plan_rollback(
    plan: ExecutionPlan,
    run: ExecutionRun,
    *,
    authority: str,
) -> ExecutionRollbackPlan:
    """Build a rollback plan based on currently executed steps (in reverse).

    rollback_ready = True if authority is non-empty and at least one executed step exists.
    """
    created_at = utc_iso8601_z_now()
    rollback_id = hashlib.sha256(
        f"ROLLBACK:{plan.plan_id}:{run.run_id}:{created_at}".encode("utf-8")
    ).hexdigest()[:20]

    # Build rollback steps for executed steps in reverse order
    step_map = {s.step_id: s for s in plan.steps}
    executed = list(run.executed_steps)
    rollback_steps: list[ExecutionRollbackStep] = []
    for rev_seq, step_id in enumerate(reversed(executed), start=1):
        original = step_map.get(step_id)
        rb_step = ExecutionRollbackStep(
            step_id=hashlib.sha256(
                f"RBSTEP:{rollback_id}:{step_id}".encode("utf-8")
            ).hexdigest()[:20],
            name=f"Rollback: {original.name if original else step_id}",
            sequence=rev_seq,
            authority_required=original.authority_required if original else authority,
            reverses_step_id=step_id,
        )
        rollback_steps.append(rb_step)

    rollback_ready = bool(authority and executed)

    return ExecutionRollbackPlan(
        rollback_id=rollback_id,
        plan_id=plan.plan_id,
        tenant_id=plan.tenant_id,
        rollback_steps=tuple(rollback_steps),
        rollback_dependencies=(),
        rollback_evidence=(),
        rollback_authority=authority,
        rollback_verification=True,
        rollback_ready=rollback_ready,
        created_at=created_at,
    )


def execute_rollback(
    rollback_plan: ExecutionRollbackPlan,
    run: ExecutionRun,
) -> tuple[ExecutionRun, ExecutionAuditRecord]:
    """Initiate rollback execution against the run.

    Raises ExecutionValidationError if rollback_plan.rollback_ready is False.
    Returns (run with rollback_reference set, audit_record).
    """
    if not rollback_plan.rollback_ready:
        raise ExecutionValidationError(
            "Cannot execute rollback: rollback_plan.rollback_ready is False"
        )

    event_at = utc_iso8601_z_now()
    audit_id = hashlib.sha256(
        f"AUDIT:{run.run_id}:rollback:{rollback_plan.rollback_id}:{event_at}".encode(
            "utf-8"
        )
    ).hexdigest()[:20]

    audit_stub = ExecutionAuditRecord(
        audit_id=audit_id,
        plan_id=run.plan_id,
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        event_type="rollback_initiated",
        event_at=event_at,
        actor=rollback_plan.rollback_authority,
        authority=rollback_plan.rollback_authority,
        before_state=run.state,
        after_state="Rollback",
        reason=f"Rollback plan {rollback_plan.rollback_id} initiated",
        fingerprint="",
    )
    audit_fingerprint = compute_audit_fingerprint(audit_stub)
    audit_record = dataclasses.replace(audit_stub, fingerprint=audit_fingerprint)

    updated_run = dataclasses.replace(
        run,
        rollback_reference=rollback_plan.rollback_id,
    )
    return updated_run, audit_record
