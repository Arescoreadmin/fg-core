"""Outcome measurement engine for the Governance Execution Engine."""

from __future__ import annotations

import hashlib

from services.canonical import utc_iso8601_z_now
from services.governance_execution.models import (
    ExecutionMeasurement,
    ExecutionRun,
    ExecutionVerification,
)


def measure_outcome(
    run: ExecutionRun,
    verifications: tuple[ExecutionVerification, ...],
    *,
    governance_delta: int | None = None,
    control_delta: int | None = None,
    evidence_delta: int | None = None,
    compliance_delta: int | None = None,
    risk_delta: int | None = None,
    trust_delta: int | None = None,
    readiness_delta: int | None = None,
    policy_impact: str | None = None,
    framework_impact: str | None = None,
    supporting_evidence_ids: tuple[str, ...] = (),
) -> ExecutionMeasurement:
    """Produce an ExecutionMeasurement for the run.

    execution_quality / verification_quality:
      PROVEN   — any verification has PROVEN confidence
      INFERRED — any verification has INFERRED confidence (and none PROVEN)
      UNKNOWN  — all UNKNOWN or no verifications
    """
    measured_at = utc_iso8601_z_now()
    measurement_id = hashlib.sha256(
        f"MEASURE:{run.run_id}:{measured_at}".encode("utf-8")
    ).hexdigest()[:20]

    limitations: list[str] = []
    if not verifications:
        limitations.append("no verifications provided")

    confidences = {v.confidence for v in verifications}

    if "PROVEN" in confidences:
        quality = "PROVEN"
    elif "INFERRED" in confidences:
        quality = "INFERRED"
    else:
        quality = "UNKNOWN"

    execution_quality = quality
    verification_quality = quality

    return ExecutionMeasurement(
        measurement_id=measurement_id,
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        measured_at=measured_at,
        governance_delta=governance_delta,
        control_delta=control_delta,
        evidence_delta=evidence_delta,
        compliance_delta=compliance_delta,
        risk_delta=risk_delta,
        trust_delta=trust_delta,
        readiness_delta=readiness_delta,
        policy_impact=policy_impact,
        framework_impact=framework_impact,
        execution_quality=execution_quality,
        verification_quality=verification_quality,
        limitations=tuple(limitations),
        supporting_evidence_ids=supporting_evidence_ids,
    )
