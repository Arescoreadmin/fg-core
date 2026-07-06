"""Step verification engine for the Governance Execution Engine."""

from __future__ import annotations

import hashlib

from services.canonical import utc_iso8601_z_now
from services.governance_execution.models import (
    ExecutionRun,
    ExecutionVerification,
)


def verify_step(
    run: ExecutionRun,
    step_id: str,
    *,
    verified_by: str = "system:governance_verification",
    evidence_collected: tuple[str, ...] = (),
    authority_confirmed: str = "",
    policy_satisfied: bool = False,
    expected_outcome_achieved: bool | None = None,
    unexpected_outcome_detected: bool = False,
    manual_review_required: bool = False,
    limitations: tuple[str, ...] = (),
) -> ExecutionVerification:
    """Produce an ExecutionVerification record for the given step.

    Confidence:
      PROVEN   — evidence_collected non-empty AND policy_satisfied
      INFERRED — authority_confirmed non-empty
      UNKNOWN  — otherwise

    Outcome:
      "success" — expected_outcome_achieved is True
      "failure" — expected_outcome_achieved is False
      "unknown" — expected_outcome_achieved is None
    """
    verified_at = utc_iso8601_z_now()
    verification_id = hashlib.sha256(
        f"VERIFY:{run.run_id}:{step_id}:{verified_at}".encode("utf-8")
    ).hexdigest()[:20]

    if evidence_collected and policy_satisfied:
        confidence = "PROVEN"
    elif authority_confirmed:
        confidence = "INFERRED"
    else:
        confidence = "UNKNOWN"

    if expected_outcome_achieved is True:
        outcome = "success"
    elif expected_outcome_achieved is False:
        outcome = "failure"
    else:
        outcome = "unknown"

    return ExecutionVerification(
        verification_id=verification_id,
        run_id=run.run_id,
        step_id=step_id,
        tenant_id=run.tenant_id,
        verified_at=verified_at,
        verified_by=verified_by,
        outcome=outcome,
        evidence_collected=evidence_collected,
        authority_confirmed=authority_confirmed,
        policy_satisfied=policy_satisfied,
        expected_outcome_achieved=expected_outcome_achieved,
        unexpected_outcome_detected=unexpected_outcome_detected,
        manual_review_required=manual_review_required,
        confidence=confidence,
        limitations=limitations,
    )
