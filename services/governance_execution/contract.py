"""Protocol + concrete service class for the Governance Execution Engine."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from services.governance_execution.approvals import (
    create_approval,
)
from services.governance_execution.execution import create_run
from services.governance_execution.exporter import export_execution_replay_package
from services.governance_execution.fingerprint import compute_execution_fingerprint
from services.governance_execution.measurement import measure_outcome
from services.governance_execution.models import (
    GOVERNANCE_EXECUTION_SCHEMA_VERSION,
    GOVERNANCE_EXECUTION_VERSION,
    ExecutionApproval,
    ExecutionMeasurement,
    ExecutionPlan,
    ExecutionReplayPackage,
    ExecutionRollbackPlan,
    ExecutionRun,
    ExecutionValidationReport,
    ExecutionVerification,
)
from services.governance_execution.planner import plan_execution
from services.governance_execution.rollback import plan_rollback
from services.governance_execution.validator import validate_execution_plan
from services.governance_execution.verification import verify_step
from services.governance_simulation.models import SimulationResult


@runtime_checkable
class GovernanceExecutionServiceContract(Protocol):
    def plan(
        self,
        simulation_result: SimulationResult,
        plan_name: str,
        authority: str,
        *,
        approval_type: str,
        created_by: str,
    ) -> ExecutionPlan: ...

    def validate(self, plan: ExecutionPlan) -> ExecutionValidationReport: ...

    def approve(
        self,
        plan: ExecutionPlan,
        approver_id: str,
        approver_authority: str,
        reason: str,
        *,
        evidence_refs: tuple[str, ...],
        policy_refs: tuple[str, ...],
    ) -> ExecutionApproval: ...

    def execute(
        self,
        plan: ExecutionPlan,
        approvals: tuple[ExecutionApproval, ...],
    ) -> ExecutionRun: ...

    def verify(
        self,
        run: ExecutionRun,
        step_id: str,
        *,
        verified_by: str,
        evidence_collected: tuple[str, ...],
        authority_confirmed: str,
        policy_satisfied: bool,
        expected_outcome_achieved: bool | None,
        unexpected_outcome_detected: bool,
        manual_review_required: bool,
        limitations: tuple[str, ...],
    ) -> ExecutionVerification: ...

    def measure(
        self,
        run: ExecutionRun,
        verifications: tuple[ExecutionVerification, ...],
        *,
        governance_delta: int | None,
        control_delta: int | None,
        evidence_delta: int | None,
        compliance_delta: int | None,
        risk_delta: int | None,
        trust_delta: int | None,
        readiness_delta: int | None,
        policy_impact: str | None,
        framework_impact: str | None,
        supporting_evidence_ids: tuple[str, ...],
    ) -> ExecutionMeasurement: ...

    def rollback(
        self,
        plan: ExecutionPlan,
        run: ExecutionRun,
        authority: str,
    ) -> ExecutionRollbackPlan: ...

    def export(self, package: ExecutionReplayPackage) -> Mapping[str, Any]: ...

    def replay(self, package: ExecutionReplayPackage) -> ExecutionReplayPackage: ...

    def fingerprint(
        self,
        plan: ExecutionPlan,
        run: ExecutionRun,
        verifications: tuple[ExecutionVerification, ...],
        measurements: tuple[ExecutionMeasurement, ...],
    ) -> str: ...


class GovernanceExecutionService:
    """Concrete service implementation delegating to module functions."""

    def plan(
        self,
        simulation_result: SimulationResult,
        plan_name: str,
        authority: str,
        *,
        approval_type: str = "SingleApprover",
        created_by: str = "system:governance_execution_planner",
    ) -> ExecutionPlan:
        return plan_execution(
            simulation_result,
            plan_name,
            authority,
            approval_type=approval_type,
            created_by=created_by,
        )

    def validate(self, plan: ExecutionPlan) -> ExecutionValidationReport:
        return validate_execution_plan(plan)

    def approve(
        self,
        plan: ExecutionPlan,
        approver_id: str,
        approver_authority: str,
        reason: str,
        *,
        evidence_refs: tuple[str, ...] = (),
        policy_refs: tuple[str, ...] = (),
    ) -> ExecutionApproval:
        return create_approval(
            plan,
            approver_id,
            approver_authority,
            reason,
            evidence_refs=evidence_refs,
            policy_refs=policy_refs,
        )

    def execute(
        self,
        plan: ExecutionPlan,
        approvals: tuple[ExecutionApproval, ...],
    ) -> ExecutionRun:
        return create_run(plan, approvals)

    def verify(
        self,
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
        return verify_step(
            run,
            step_id,
            verified_by=verified_by,
            evidence_collected=evidence_collected,
            authority_confirmed=authority_confirmed,
            policy_satisfied=policy_satisfied,
            expected_outcome_achieved=expected_outcome_achieved,
            unexpected_outcome_detected=unexpected_outcome_detected,
            manual_review_required=manual_review_required,
            limitations=limitations,
        )

    def measure(
        self,
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
        return measure_outcome(
            run,
            verifications,
            governance_delta=governance_delta,
            control_delta=control_delta,
            evidence_delta=evidence_delta,
            compliance_delta=compliance_delta,
            risk_delta=risk_delta,
            trust_delta=trust_delta,
            readiness_delta=readiness_delta,
            policy_impact=policy_impact,
            framework_impact=framework_impact,
            supporting_evidence_ids=supporting_evidence_ids,
        )

    def rollback(
        self,
        plan: ExecutionPlan,
        run: ExecutionRun,
        authority: str,
    ) -> ExecutionRollbackPlan:
        return plan_rollback(plan, run, authority=authority)

    def export(self, package: ExecutionReplayPackage) -> Mapping[str, Any]:
        return export_execution_replay_package(package)

    def replay(self, package: ExecutionReplayPackage) -> ExecutionReplayPackage:
        raise NotImplementedError(
            "replay() requires the original SimulationResult snapshot — "
            "call plan_execution() with the original inputs to reproduce."
        )

    def fingerprint(
        self,
        plan: ExecutionPlan,
        run: ExecutionRun,
        verifications: tuple[ExecutionVerification, ...],
        measurements: tuple[ExecutionMeasurement, ...],
    ) -> str:
        return compute_execution_fingerprint(
            plan,
            run,
            verifications,
            measurements,
            builder_version=GOVERNANCE_EXECUTION_VERSION,
            schema_version=GOVERNANCE_EXECUTION_SCHEMA_VERSION,
        )
