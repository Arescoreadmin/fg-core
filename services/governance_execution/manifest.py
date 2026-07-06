"""Manifest builder for the Governance Execution Engine."""

from __future__ import annotations

from services.governance_execution.models import (
    GOVERNANCE_EXECUTION_MANIFEST_VERSION,
    GOVERNANCE_EXECUTION_MCIM_VERSION,
    GOVERNANCE_EXECUTION_PLANNER_VERSION,
    GOVERNANCE_EXECUTION_SCHEMA_VERSION,
    GOVERNANCE_EXECUTION_VERSION,
    GOVERNANCE_EXECUTION_VALIDATOR_VERSION,
    ExecutionManifest,
    ExecutionMeasurement,
    ExecutionPlan,
    ExecutionRun,
    ExecutionVerification,
)


def build_execution_manifest(
    plan: ExecutionPlan,
    run: ExecutionRun,
    verifications: tuple[ExecutionVerification, ...],
    measurements: tuple[ExecutionMeasurement, ...],
    execution_fingerprint: str,
    *,
    validation_duration_ms: int | None = None,
    execution_duration_ms: int | None = None,
    generation: int = 1,
) -> ExecutionManifest:
    """Build an ExecutionManifest summarising the execution."""
    return ExecutionManifest(
        manifest_schema_version=GOVERNANCE_EXECUTION_SCHEMA_VERSION,
        plan_id=plan.plan_id,
        tenant_id=plan.tenant_id,
        execution_version=GOVERNANCE_EXECUTION_VERSION,
        planner_version=GOVERNANCE_EXECUTION_PLANNER_VERSION,
        validator_version=GOVERNANCE_EXECUTION_VALIDATOR_VERSION,
        mcim_version=GOVERNANCE_EXECUTION_MCIM_VERSION,
        manifest_version=GOVERNANCE_EXECUTION_MANIFEST_VERSION,
        fingerprint=execution_fingerprint,
        step_count=len(plan.steps),
        approval_count=len(run.approvals),
        verification_count=len(verifications),
        measurement_count=len(measurements),
        rollback_ready=plan.rollback_plan.rollback_ready,
        execution_duration_ms=execution_duration_ms,
        validation_duration_ms=validation_duration_ms,
        lineage=plan.lineage,
        generation=generation,
    )
