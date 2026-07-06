"""Approval workflow engine for the Governance Execution Engine."""

from __future__ import annotations

import hashlib

from services.canonical import canonical_json_bytes, utc_iso8601_z_now
from services.governance_execution.models import (
    ExecutionApproval,
    ExecutionPlan,
)
from services.governance_execution.validator import ExecutionValidationError


def create_approval(
    plan: ExecutionPlan,
    approver_id: str,
    approver_authority: str,
    reason: str,
    *,
    evidence_refs: tuple[str, ...] = (),
    policy_refs: tuple[str, ...] = (),
) -> ExecutionApproval:
    """Create an ExecutionApproval for the given plan.

    Raises ExecutionValidationError if approver_authority is empty.
    """
    if not approver_authority:
        raise ExecutionValidationError("approver_authority must not be empty")

    approved_at = utc_iso8601_z_now()
    approval_id = hashlib.sha256(
        f"APPROVAL:{plan.plan_id}:{approver_id}:{approved_at}".encode("utf-8")
    ).hexdigest()[:20]

    fingerprint_payload = {
        "approval_id": approval_id,
        "plan_id": plan.plan_id,
        "approver_authority": approver_authority,
        "reason": reason,
        "evidence_refs": list(evidence_refs),
        "policy_refs": list(policy_refs),
    }
    fingerprint = hashlib.sha256(canonical_json_bytes(fingerprint_payload)).hexdigest()

    # Determine approval_type from the plan's first approval requirement
    approval_type = "SingleApprover"
    if plan.approval_requirements:
        approval_type = plan.approval_requirements[0].approval_type

    return ExecutionApproval(
        approval_id=approval_id,
        plan_id=plan.plan_id,
        tenant_id=plan.tenant_id,
        approval_type=approval_type,
        approver_id=approver_id,
        approver_authority=approver_authority,
        approved_at=approved_at,
        reason=reason,
        evidence_refs=evidence_refs,
        policy_refs=policy_refs,
        fingerprint=fingerprint,
    )


def check_approval_requirements(
    plan: ExecutionPlan,
    approvals: tuple[ExecutionApproval, ...],
) -> tuple[bool, list[str]]:
    """Check whether approval requirements are satisfied.

    Returns (satisfied, list_of_unmet_reasons).
    """
    unmet: list[str] = []
    plan_approvals = [a for a in approvals if a.plan_id == plan.plan_id]

    for req in plan.approval_requirements:
        distinct_approvers = len(
            {
                a.approver_id
                for a in plan_approvals
                if a.approval_type == req.approval_type
            }
        )
        if distinct_approvers < req.min_approvers:
            unmet.append(
                f"Requirement {req.requirement_id} ({req.approval_type}) needs "
                f"{req.min_approvers} distinct approver(s), got {distinct_approvers}"
            )

    return (len(unmet) == 0, unmet)
