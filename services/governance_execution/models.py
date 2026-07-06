"""Pure data models for the Governance Execution Engine."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from enum import Enum


GOVERNANCE_EXECUTION_VERSION = "18.8.3"
GOVERNANCE_EXECUTION_PLANNER_VERSION = "1.0.0"
GOVERNANCE_EXECUTION_VALIDATOR_VERSION = "1.0.0"
GOVERNANCE_EXECUTION_SCHEMA_VERSION = "1.0"
GOVERNANCE_EXECUTION_REPLAY_VERSION = "1.0"
GOVERNANCE_EXECUTION_MANIFEST_VERSION = "1.0"
GOVERNANCE_EXECUTION_FINGERPRINT_DOMAIN = "FG_GOVERNANCE_EXECUTION_V1"
GOVERNANCE_EXECUTION_MCIM_VERSION = "MCIM-18.8.3-GOVERNANCE-EXECUTION"


class ExecutionState(str, Enum):
    Draft = "Draft"
    Validated = "Validated"
    AwaitingApproval = "AwaitingApproval"
    Approved = "Approved"
    Scheduled = "Scheduled"
    Executing = "Executing"
    Verifying = "Verifying"
    Completed = "Completed"
    Measured = "Measured"
    Archived = "Archived"
    Failed = "Failed"
    Rollback = "Rollback"
    Verification = "Verification"
    Closed = "Closed"


class ApprovalType(str, Enum):
    SingleApprover = "SingleApprover"
    DualApproval = "DualApproval"
    MajorityApproval = "MajorityApproval"
    RiskBased = "RiskBased"
    Emergency = "Emergency"
    Executive = "Executive"
    Compliance = "Compliance"
    Security = "Security"
    Authority = "Authority"


class ExecutionOutcomeConfidence(str, Enum):
    PROVEN = "PROVEN"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class ExecutionGateResult(str, Enum):
    Passed = "Passed"
    Failed = "Failed"
    Pending = "Pending"
    Skipped = "Skipped"


class ExecutionStepState(str, Enum):
    Pending = "Pending"
    InProgress = "InProgress"
    Completed = "Completed"
    Failed = "Failed"
    Skipped = "Skipped"
    RolledBack = "RolledBack"


@dataclass(frozen=True)
class ExecutionAuthority:
    authority_id: str
    name: str
    scope: str
    permission_level: str
    tenant_id: str


@dataclass(frozen=True)
class ExecutionPolicy:
    policy_id: str
    name: str
    authority: str
    rule: str
    enforcement: str  # "block" | "warn" | "log"


@dataclass(frozen=True)
class ExecutionGate:
    gate_id: str
    name: str
    condition: str
    authority_required: str
    evidence_required: tuple[str, ...]
    blocking: bool
    result: str = dataclasses.field(default="Pending")  # ExecutionGateResult value


@dataclass(frozen=True)
class ExecutionStep:
    step_id: str
    plan_id: str
    tenant_id: str
    sequence: int
    name: str
    description: str
    state: str  # ExecutionStepState value
    preconditions: tuple[str, ...]
    postconditions: tuple[str, ...]
    dependencies: tuple[str, ...]  # other step_ids
    authority_required: str
    evidence_required: tuple[str, ...]
    verification_required: bool
    rollback_step_id: str | None


@dataclass(frozen=True)
class ExecutionApprovalRequirement:
    requirement_id: str
    plan_id: str
    approval_type: str
    min_approvers: int
    authority_required: str
    policy_refs: tuple[str, ...]


@dataclass(frozen=True)
class ExecutionApproval:
    approval_id: str
    plan_id: str
    tenant_id: str
    approval_type: str
    approver_id: str
    approver_authority: str
    approved_at: str
    reason: str
    evidence_refs: tuple[str, ...]
    policy_refs: tuple[str, ...]
    fingerprint: str


@dataclass(frozen=True)
class ExecutionRollbackStep:
    step_id: str
    name: str
    sequence: int
    authority_required: str
    reverses_step_id: str


@dataclass(frozen=True)
class ExecutionRollbackPlan:
    rollback_id: str
    plan_id: str
    tenant_id: str
    rollback_steps: tuple[ExecutionRollbackStep, ...]
    rollback_dependencies: tuple[str, ...]
    rollback_evidence: tuple[str, ...]
    rollback_authority: str
    rollback_verification: bool
    rollback_ready: bool
    created_at: str


@dataclass(frozen=True)
class ExecutionPlan:
    plan_id: str
    tenant_id: str
    simulation_id: str  # scenario_id from SimulationResult
    simulation_fingerprint: str
    digital_twin_fingerprint: str  # source_snapshot_fingerprint
    plan_name: str
    category: str
    state: str  # ExecutionState value, starts "Draft"
    created_at: str
    created_by: str
    steps: tuple[ExecutionStep, ...]
    approval_requirements: tuple[ExecutionApprovalRequirement, ...]
    rollback_plan: ExecutionRollbackPlan
    gates: tuple[ExecutionGate, ...]
    policies: tuple[ExecutionPolicy, ...]
    authorities: tuple[ExecutionAuthority, ...]
    evidence_requirements: tuple[str, ...]
    planner_version: str
    schema_version: str
    plan_fingerprint: str
    lineage: str


@dataclass(frozen=True)
class ExecutionVerification:
    verification_id: str
    run_id: str
    step_id: str
    tenant_id: str
    verified_at: str
    verified_by: str
    outcome: str  # "success" | "failure" | "unknown"
    evidence_collected: tuple[str, ...]
    authority_confirmed: str
    policy_satisfied: bool
    expected_outcome_achieved: bool | None
    unexpected_outcome_detected: bool
    manual_review_required: bool
    confidence: str  # ExecutionOutcomeConfidence value
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class ExecutionMeasurement:
    measurement_id: str
    run_id: str
    tenant_id: str
    measured_at: str
    governance_delta: int | None
    control_delta: int | None
    evidence_delta: int | None
    compliance_delta: int | None
    risk_delta: int | None
    trust_delta: int | None
    readiness_delta: int | None
    policy_impact: str | None
    framework_impact: str | None
    execution_quality: str  # ExecutionOutcomeConfidence value
    verification_quality: str
    limitations: tuple[str, ...]
    supporting_evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class ExecutionDecisionRecord:
    record_id: str
    plan_id: str
    run_id: str
    tenant_id: str
    decided_at: str
    decided_by: str
    decision: str  # "approved" | "rejected" | "deferred"
    authority: str
    policy: str
    supporting_evidence_ids: tuple[str, ...]
    simulation_reference: str
    execution_reference: str
    verification_reference: str
    outcome: str | None
    fingerprint: str


@dataclass(frozen=True)
class ExecutionDecisionLedger:
    ledger_id: str
    plan_id: str
    tenant_id: str
    records: tuple[ExecutionDecisionRecord, ...]
    ledger_hash: str


@dataclass(frozen=True)
class ExecutionRun:
    run_id: str
    plan_id: str
    tenant_id: str
    state: str  # ExecutionState value
    started_at: str
    completed_at: str | None
    failed_at: str | None
    simulation_id: str
    simulation_fingerprint: str
    executed_steps: tuple[str, ...]
    skipped_steps: tuple[str, ...]
    failed_steps: tuple[str, ...]
    verification_ids: tuple[str, ...]
    measurement_ids: tuple[str, ...]
    approvals: tuple[ExecutionApproval, ...]
    rollback_reference: str | None
    run_fingerprint: str


@dataclass(frozen=True)
class ExecutionAuditRecord:
    audit_id: str
    plan_id: str
    run_id: str
    tenant_id: str
    event_type: str
    event_at: str
    actor: str
    authority: str
    before_state: str | None
    after_state: str | None
    reason: str
    fingerprint: str


@dataclass(frozen=True)
class ExecutionValidationFinding:
    severity: str
    code: str
    message: str


@dataclass(frozen=True)
class ExecutionValidationReport:
    valid: bool
    findings: tuple[ExecutionValidationFinding, ...]
    highest_severity: str
    violations: tuple[str, ...]
    checked_invariants: tuple[str, ...]


@dataclass(frozen=True)
class ExecutionManifest:
    manifest_schema_version: str
    plan_id: str
    tenant_id: str
    execution_version: str
    planner_version: str
    validator_version: str
    mcim_version: str
    manifest_version: str
    fingerprint: str
    step_count: int
    approval_count: int
    verification_count: int
    measurement_count: int
    rollback_ready: bool
    execution_duration_ms: int | None
    validation_duration_ms: int | None
    lineage: str
    generation: int


@dataclass(frozen=True)
class ExecutionSummary:
    summary_id: str
    plan_id: str
    run_id: str
    tenant_id: str
    final_state: str
    total_steps: int
    completed_steps: int
    failed_steps: int
    skipped_steps: int
    total_verifications: int
    successful_verifications: int
    failed_verifications: int
    total_measurements: int
    rollback_triggered: bool
    execution_duration_ms: int | None
    outcome_confidence: str
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class ExecutionReplayPackage:
    package_id: str
    plan_id: str
    run_id: str
    tenant_id: str
    digital_twin_fingerprint: str
    simulation_fingerprint: str
    execution_fingerprint: str
    manifest: ExecutionManifest
    plan: ExecutionPlan
    run: ExecutionRun
    verifications: tuple[ExecutionVerification, ...]
    measurements: tuple[ExecutionMeasurement, ...]
    decision_ledger: ExecutionDecisionLedger
    validation_report: ExecutionValidationReport
    fingerprint: str
    created_at: str
    mcim_version: str
    schema_version: str
    replay_version: str
    lineage: str
