"""Execution replay package builder for the Governance Execution Engine."""

from __future__ import annotations

import hashlib

from services.canonical import utc_iso8601_z_now
from services.governance_execution.fingerprint import (
    compute_execution_fingerprint,
    compute_replay_fingerprint,
)
from services.governance_execution.manifest import build_execution_manifest
from services.governance_execution.models import (
    GOVERNANCE_EXECUTION_MCIM_VERSION,
    GOVERNANCE_EXECUTION_REPLAY_VERSION,
    GOVERNANCE_EXECUTION_SCHEMA_VERSION,
    GOVERNANCE_EXECUTION_VERSION,
    ExecutionDecisionLedger,
    ExecutionMeasurement,
    ExecutionPlan,
    ExecutionReplayPackage,
    ExecutionRun,
    ExecutionValidationReport,
    ExecutionVerification,
)


def build_execution_replay_package(
    plan: ExecutionPlan,
    run: ExecutionRun,
    verifications: tuple[ExecutionVerification, ...],
    measurements: tuple[ExecutionMeasurement, ...],
    decision_ledger: ExecutionDecisionLedger,
    validation_report: ExecutionValidationReport,
    digital_twin_fingerprint: str,
    simulation_fingerprint: str,
) -> ExecutionReplayPackage:
    """Build a self-contained ExecutionReplayPackage."""
    execution_fingerprint = compute_execution_fingerprint(
        plan,
        run,
        verifications,
        measurements,
        builder_version=GOVERNANCE_EXECUTION_VERSION,
        schema_version=GOVERNANCE_EXECUTION_SCHEMA_VERSION,
    )

    package_id = hashlib.sha256(
        f"EXEC_REPLAY:{plan.plan_id}:{run.run_id}:{execution_fingerprint}".encode(
            "utf-8"
        )
    ).hexdigest()[:24]

    fingerprint = compute_replay_fingerprint(
        package_id=package_id,
        plan_id=plan.plan_id,
        run_id=run.run_id,
        execution_fingerprint=execution_fingerprint,
        tenant_id=plan.tenant_id,
    )

    manifest = build_execution_manifest(
        plan=plan,
        run=run,
        verifications=verifications,
        measurements=measurements,
        execution_fingerprint=execution_fingerprint,
    )

    created_at = utc_iso8601_z_now()

    return ExecutionReplayPackage(
        package_id=package_id,
        plan_id=plan.plan_id,
        run_id=run.run_id,
        tenant_id=plan.tenant_id,
        digital_twin_fingerprint=digital_twin_fingerprint,
        simulation_fingerprint=simulation_fingerprint,
        execution_fingerprint=execution_fingerprint,
        manifest=manifest,
        plan=plan,
        run=run,
        verifications=verifications,
        measurements=measurements,
        decision_ledger=decision_ledger,
        validation_report=validation_report,
        fingerprint=fingerprint,
        created_at=created_at,
        mcim_version=GOVERNANCE_EXECUTION_MCIM_VERSION,
        schema_version=GOVERNANCE_EXECUTION_SCHEMA_VERSION,
        replay_version=GOVERNANCE_EXECUTION_REPLAY_VERSION,
        lineage=plan.lineage,
    )
