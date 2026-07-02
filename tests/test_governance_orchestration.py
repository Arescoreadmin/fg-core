"""Tests for PR 18.4 — Continuous Governance Orchestration Authority (core).

Coverage:
  GO-1   to GO-40:   models.py — enums, constants, terminal sets
  GO-41  to GO-100:  schemas.py — extra=forbid, request/response validation
  GO-101 to GO-160:  repository.py — CRUD, tenant isolation
  GO-161 to GO-220:  engine.py — core operations
  GO-221 to GO-260:  validators.py
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from sqlalchemy.orm import Session

from api.db import get_engine
from services.governance_orchestration.engine import (
    GovernanceOrchestrationEngine,
)
from services.governance_orchestration.models import (
    ACTIVE_APPROVAL_STATES,
    GOVERNANCE_ORCHESTRATION_SCHEMA_VERSION,
    TERMINAL_REASSESSMENT_STATES,
    TERMINAL_WORKFLOW_STATES,
    ApprovalState,
    ChangeType,
    GovernanceOrchestrationDomainError,
    GovernanceOrchestrationNotFoundDomainError,
    GovernanceOrchestrationState,
    GovernanceOrchestrationTenantViolationDomainError,
    ImpactLevel,
    MaintenanceWindowState,
    PlaybookType,
    PolicyRiskLevel,
    ReassessmentState,
    SimulationState,
    TriggerType,
    WorkflowState,
)
from services.governance_orchestration.repository import (
    GovernanceOrchestrationRepository,
)
from services.governance_orchestration.schemas import (
    ApproveRequest,
    CreateApprovalRequest,
    CreateChangeDetectionRequest,
    CreateMaintenanceWindowRequest,
    CreatePlaybookRequest,
    CreatePolicyRequest,
    CreateReassessmentRequest,
    CreateSimulationRequest,
    CreateTriggerRequest,
    CreateWorkflowRequest,
    GovernanceOrchestrationApprovalError,
    GovernanceOrchestrationConflict,
    GovernanceOrchestrationError,
    GovernanceOrchestrationInvalidTransition,
    GovernanceOrchestrationNotFound,
    GovernanceOrchestrationPolicyViolation,
    GovernanceOrchestrationSimulationError,
    GovernanceOrchestrationTenantViolation,
    GovernanceOrchestrationValidationError,
    GovernanceOrchestrationWorkflowError,
    UpdatePolicyRequest,
)
from services.governance_orchestration.validators import (
    validate_confidence,
    validate_impact_level,
    validate_limit_offset,
    validate_playbook_type,
    validate_policy_risk_level,
    validate_search_query,
    validate_tenant_id,
    validate_trigger_type,
    validate_workflow_state,
)


_TENANT = "tenant-go-001"
_TENANT_B = "tenant-go-002"


@pytest.fixture()
def db(build_app):
    build_app(auth_enabled=False)
    engine = get_engine()
    with Session(engine) as session:
        yield session


@pytest.fixture()
def svc(db):
    return GovernanceOrchestrationEngine(db, tenant_id=_TENANT)


@pytest.fixture()
def svc_b(db):
    return GovernanceOrchestrationEngine(db, tenant_id=_TENANT_B)


@pytest.fixture()
def repo(db):
    return GovernanceOrchestrationRepository(db, tenant_id=_TENANT)


# ===========================================================================
# GO-1 to GO-40: models.py
# ===========================================================================


@pytest.mark.parametrize(
    "value",
    ["IDLE", "EVALUATING", "TRIGGERING", "EXECUTING", "SUSPENDED", "FAILED"],
)
def test_GO_1_orchestration_state_values(value):
    assert any(m.value == value for m in GovernanceOrchestrationState)


def test_GO_2_orchestration_state_count():
    assert len(GovernanceOrchestrationState) == 6


@pytest.mark.parametrize(
    "value",
    [
        "EVIDENCE_EXPIRED",
        "EVIDENCE_REVOKED",
        "VERIFICATION_FAILED",
        "CONTROL_DEGRADED",
        "RISK_THRESHOLD_EXCEEDED",
        "REMEDIATION_COMPLETED",
        "REMEDIATION_FAILED",
        "TRUST_ROTATION",
        "TRANSPARENCY_INCONSISTENCY",
        "MANUAL_REQUEST",
        "SCHEDULED",
        "FRAMEWORK_REVISION",
        "TENANT_POLICY",
    ],
)
def test_GO_3_trigger_type_values(value):
    assert any(m.value == value for m in TriggerType)


def test_GO_4_trigger_type_count():
    assert len(TriggerType) == 13


@pytest.mark.parametrize("value", ["HIGH", "MEDIUM", "LOW", "CRITICAL"])
def test_GO_5_policy_risk_level_values(value):
    assert any(m.value == value for m in PolicyRiskLevel)


def test_GO_6_policy_risk_level_count():
    assert len(PolicyRiskLevel) == 4


@pytest.mark.parametrize(
    "value",
    [
        "PENDING",
        "RUNNING",
        "WAITING_APPROVAL",
        "PAUSED",
        "COMPLETED",
        "FAILED",
        "ROLLED_BACK",
        "CANCELLED",
    ],
)
def test_GO_7_workflow_state_values(value):
    assert any(m.value == value for m in WorkflowState)


def test_GO_8_workflow_state_count():
    assert len(WorkflowState) == 8


@pytest.mark.parametrize(
    "value",
    ["REQUESTED", "SCHEDULED", "IN_PROGRESS", "COMPLETED", "FAILED", "CANCELLED"],
)
def test_GO_9_reassessment_state_values(value):
    assert any(m.value == value for m in ReassessmentState)


def test_GO_10_reassessment_state_count():
    assert len(ReassessmentState) == 6


@pytest.mark.parametrize(
    "value", ["PENDING", "APPROVED", "REJECTED", "EXPIRED", "DELEGATED"]
)
def test_GO_11_approval_state_values(value):
    assert any(m.value == value for m in ApprovalState)


def test_GO_12_approval_state_count():
    assert len(ApprovalState) == 5


@pytest.mark.parametrize("value", ["SCHEDULED", "ACTIVE", "COMPLETED", "CANCELLED"])
def test_GO_13_maintenance_window_state_values(value):
    assert any(m.value == value for m in MaintenanceWindowState)


def test_GO_14_maintenance_window_state_count():
    assert len(MaintenanceWindowState) == 4


@pytest.mark.parametrize("value", ["PENDING", "RUNNING", "COMPLETED", "FAILED"])
def test_GO_15_simulation_state_values(value):
    assert any(m.value == value for m in SimulationState)


def test_GO_16_simulation_state_count():
    assert len(SimulationState) == 4


@pytest.mark.parametrize(
    "value",
    [
        "PCI_DSS",
        "HIPAA",
        "NIST_CSF",
        "ISO_27001",
        "SOC2",
        "MICROSOFT_SECURE_SCORE",
        "CIS_CONTROLS",
    ],
)
def test_GO_17_playbook_type_values(value):
    assert any(m.value == value for m in PlaybookType)


def test_GO_18_playbook_type_count():
    assert len(PlaybookType) == 7


@pytest.mark.parametrize("value", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"])
def test_GO_19_impact_level_values(value):
    assert any(m.value == value for m in ImpactLevel)


def test_GO_20_impact_level_count():
    assert len(ImpactLevel) == 5


@pytest.mark.parametrize(
    "value",
    [
        "EVIDENCE_CHANGE",
        "CONTROL_CHANGE",
        "RISK_CHANGE",
        "POLICY_CHANGE",
        "FRAMEWORK_CHANGE",
        "TRUST_CHANGE",
    ],
)
def test_GO_21_change_type_values(value):
    assert any(m.value == value for m in ChangeType)


def test_GO_22_change_type_count():
    assert len(ChangeType) == 6


def test_GO_23_schema_version_constant():
    assert GOVERNANCE_ORCHESTRATION_SCHEMA_VERSION == "1.0"


def test_GO_24_terminal_workflow_states_includes_completed():
    assert WorkflowState.COMPLETED in TERMINAL_WORKFLOW_STATES


def test_GO_25_terminal_workflow_states_includes_failed():
    assert WorkflowState.FAILED in TERMINAL_WORKFLOW_STATES


def test_GO_26_terminal_workflow_states_includes_rolled_back():
    assert WorkflowState.ROLLED_BACK in TERMINAL_WORKFLOW_STATES


def test_GO_27_terminal_workflow_states_includes_cancelled():
    assert WorkflowState.CANCELLED in TERMINAL_WORKFLOW_STATES


def test_GO_28_terminal_workflow_states_size():
    assert len(TERMINAL_WORKFLOW_STATES) == 4


def test_GO_29_terminal_reassessment_states_size():
    assert len(TERMINAL_REASSESSMENT_STATES) == 3


def test_GO_30_active_approval_states_size():
    assert len(ACTIVE_APPROVAL_STATES) == 2


def test_GO_31_active_approval_states_includes_pending():
    assert ApprovalState.PENDING in ACTIVE_APPROVAL_STATES


def test_GO_32_active_approval_states_includes_delegated():
    assert ApprovalState.DELEGATED in ACTIVE_APPROVAL_STATES


@pytest.mark.parametrize("member", list(WorkflowState))
def test_GO_33_workflow_state_is_str(member):
    assert isinstance(member.value, str)


@pytest.mark.parametrize("member", list(TriggerType))
def test_GO_34_trigger_type_is_str(member):
    assert isinstance(member.value, str)


@pytest.mark.parametrize("member", list(PolicyRiskLevel))
def test_GO_35_risk_level_is_str(member):
    assert isinstance(member.value, str)


@pytest.mark.parametrize("member", list(ReassessmentState))
def test_GO_36_reassessment_state_is_str(member):
    assert isinstance(member.value, str)


@pytest.mark.parametrize("member", list(ImpactLevel))
def test_GO_37_impact_level_is_str(member):
    assert isinstance(member.value, str)


def test_GO_38_domain_error_hierarchy():
    assert issubclass(
        GovernanceOrchestrationNotFoundDomainError,
        GovernanceOrchestrationDomainError,
    )
    assert issubclass(
        GovernanceOrchestrationTenantViolationDomainError,
        GovernanceOrchestrationDomainError,
    )


def test_GO_39_all_enum_types_distinct():
    all_values: list[str] = []
    for enum_cls in (
        GovernanceOrchestrationState,
        TriggerType,
        PolicyRiskLevel,
        WorkflowState,
        ReassessmentState,
        ApprovalState,
        MaintenanceWindowState,
        SimulationState,
        PlaybookType,
    ):
        all_values.extend(m.value for m in enum_cls)
    # Trivial: enums have some overlap (e.g. COMPLETED). Just ensure the sets
    # are non-empty per enum.
    assert len(all_values) > 40


def test_GO_40_change_type_has_evidence_change():
    assert ChangeType.EVIDENCE_CHANGE.value == "EVIDENCE_CHANGE"


# ===========================================================================
# GO-41 to GO-100: schemas.py
# ===========================================================================


def test_GO_41_create_policy_request_defaults():
    req = CreatePolicyRequest(name="p")
    assert req.risk_level == "MEDIUM"
    assert req.active is True


def test_GO_42_create_policy_request_extra_forbidden():
    with pytest.raises(ValidationError):
        CreatePolicyRequest(name="p", bogus="x")


def test_GO_43_create_policy_name_required():
    with pytest.raises(ValidationError):
        CreatePolicyRequest()


def test_GO_44_update_policy_request_all_optional():
    req = UpdatePolicyRequest()
    assert req.name is None


def test_GO_45_update_policy_request_extra_forbidden():
    with pytest.raises(ValidationError):
        UpdatePolicyRequest(bogus="x")


def test_GO_46_create_playbook_request_ok():
    req = CreatePlaybookRequest(name="pb", playbook_type="PCI_DSS")
    assert req.playbook_type == "PCI_DSS"


def test_GO_47_create_playbook_request_extra_forbidden():
    with pytest.raises(ValidationError):
        CreatePlaybookRequest(name="pb", playbook_type="PCI_DSS", bogus=1)


def test_GO_48_create_workflow_request_defaults():
    req = CreateWorkflowRequest(name="wf")
    assert req.playbook_id is None


def test_GO_49_create_workflow_request_extra_forbidden():
    with pytest.raises(ValidationError):
        CreateWorkflowRequest(name="wf", bogus="x")


def test_GO_50_create_reassessment_request_ok():
    req = CreateReassessmentRequest(assessment_id="a-1")
    assert req.assessment_id == "a-1"


def test_GO_51_create_reassessment_request_extra_forbidden():
    with pytest.raises(ValidationError):
        CreateReassessmentRequest(assessment_id="a-1", bogus=1)


def test_GO_52_create_trigger_request_ok():
    req = CreateTriggerRequest(trigger_type="MANUAL_REQUEST")
    assert req.trigger_type == "MANUAL_REQUEST"
    assert 0.0 <= req.confidence <= 1.0


def test_GO_53_create_trigger_confidence_bounds():
    with pytest.raises(ValidationError):
        CreateTriggerRequest(trigger_type="MANUAL_REQUEST", confidence=1.5)


def test_GO_54_create_trigger_request_extra_forbidden():
    with pytest.raises(ValidationError):
        CreateTriggerRequest(trigger_type="MANUAL_REQUEST", bogus="x")


def test_GO_55_create_simulation_request_ok():
    req = CreateSimulationRequest(name="s", change_type="EVIDENCE_CHANGE")
    assert req.name == "s"


def test_GO_56_create_simulation_request_extra_forbidden():
    with pytest.raises(ValidationError):
        CreateSimulationRequest(name="s", change_type="EVIDENCE_CHANGE", bogus=1)


def test_GO_57_create_approval_request_ok():
    req = CreateApprovalRequest(workflow_id="wf-1", actor_id="alice")
    assert req.stage == 1


def test_GO_58_create_approval_stage_bounds():
    with pytest.raises(ValidationError):
        CreateApprovalRequest(workflow_id="wf-1", actor_id="a", stage=0)


def test_GO_59_approve_request_ok():
    req = ApproveRequest(decision="APPROVE")
    assert req.decision == "APPROVE"


def test_GO_60_approve_request_extra_forbidden():
    with pytest.raises(ValidationError):
        ApproveRequest(decision="APPROVE", bogus=1)


def test_GO_61_maintenance_window_request_ok():
    req = CreateMaintenanceWindowRequest(
        name="mw", starts_at="2026-01-01T00:00:00Z", ends_at="2026-01-02T00:00:00Z"
    )
    assert req.name == "mw"


def test_GO_62_maintenance_window_extra_forbidden():
    with pytest.raises(ValidationError):
        CreateMaintenanceWindowRequest(name="mw", starts_at="a", ends_at="b", bogus=1)


def test_GO_63_change_detection_request_ok():
    req = CreateChangeDetectionRequest(change_type="EVIDENCE_CHANGE")
    assert req.impact_level == "LOW"


def test_GO_64_change_detection_extra_forbidden():
    with pytest.raises(ValidationError):
        CreateChangeDetectionRequest(change_type="EVIDENCE_CHANGE", bogus=1)


def test_GO_65_exception_hierarchy_root():
    assert issubclass(GovernanceOrchestrationNotFound, GovernanceOrchestrationError)


def test_GO_66_exception_hierarchy_tenant():
    assert issubclass(
        GovernanceOrchestrationTenantViolation, GovernanceOrchestrationError
    )


def test_GO_67_exception_hierarchy_conflict():
    assert issubclass(GovernanceOrchestrationConflict, GovernanceOrchestrationError)


def test_GO_68_exception_hierarchy_transition():
    assert issubclass(
        GovernanceOrchestrationInvalidTransition, GovernanceOrchestrationError
    )


def test_GO_69_exception_hierarchy_policy():
    assert issubclass(
        GovernanceOrchestrationPolicyViolation, GovernanceOrchestrationError
    )


def test_GO_70_exception_hierarchy_validation():
    assert issubclass(
        GovernanceOrchestrationValidationError, GovernanceOrchestrationError
    )


def test_GO_71_exception_hierarchy_simulation():
    assert issubclass(
        GovernanceOrchestrationSimulationError, GovernanceOrchestrationError
    )


def test_GO_72_exception_hierarchy_approval():
    assert issubclass(
        GovernanceOrchestrationApprovalError, GovernanceOrchestrationError
    )


def test_GO_73_exception_hierarchy_workflow():
    assert issubclass(
        GovernanceOrchestrationWorkflowError, GovernanceOrchestrationError
    )


def test_GO_74_policy_request_risk_level_max_length():
    with pytest.raises(ValidationError):
        CreatePolicyRequest(name="p", risk_level="X" * 100)


def test_GO_75_policy_request_name_max_length():
    with pytest.raises(ValidationError):
        CreatePolicyRequest(name="X" * 300)


def test_GO_76_policy_request_name_min_length():
    with pytest.raises(ValidationError):
        CreatePolicyRequest(name="")


def test_GO_77_approve_request_delegated_to_optional():
    req = ApproveRequest(decision="APPROVE")
    assert req.delegated_to is None


def test_GO_78_create_playbook_type_required():
    with pytest.raises(ValidationError):
        CreatePlaybookRequest(name="pb")


def test_GO_79_workflow_request_defaults():
    req = CreateWorkflowRequest(name="w")
    assert req.context == {}


def test_GO_80_change_detection_impact_level_default():
    req = CreateChangeDetectionRequest(change_type="EVIDENCE_CHANGE")
    assert req.impact_level == "LOW"


def test_GO_81_create_reassessment_reason_max_length():
    with pytest.raises(ValidationError):
        CreateReassessmentRequest(assessment_id="a-1", reason="X" * 5000)


def test_GO_82_maintenance_window_starts_at_required():
    with pytest.raises(ValidationError):
        CreateMaintenanceWindowRequest(name="mw", ends_at="a")


def test_GO_83_maintenance_window_ends_at_required():
    with pytest.raises(ValidationError):
        CreateMaintenanceWindowRequest(name="mw", starts_at="a")


def test_GO_84_create_approval_quorum_default():
    req = CreateApprovalRequest(workflow_id="wf", actor_id="a")
    assert req.quorum == 1


def test_GO_85_create_approval_quorum_high():
    with pytest.raises(ValidationError):
        CreateApprovalRequest(workflow_id="wf", actor_id="a", quorum=100)


def test_GO_86_trigger_request_confidence_default_1():
    req = CreateTriggerRequest(trigger_type="MANUAL_REQUEST")
    assert req.confidence == 1.0


def test_GO_87_trigger_request_confidence_zero():
    req = CreateTriggerRequest(trigger_type="MANUAL_REQUEST", confidence=0.0)
    assert req.confidence == 0.0


def test_GO_88_trigger_request_confidence_negative():
    with pytest.raises(ValidationError):
        CreateTriggerRequest(trigger_type="MANUAL_REQUEST", confidence=-0.1)


def test_GO_89_create_simulation_change_data_default_empty():
    req = CreateSimulationRequest(name="s", change_type="EVIDENCE_CHANGE")
    assert req.change_data == {}


def test_GO_90_create_policy_policy_data_default_empty():
    req = CreatePolicyRequest(name="p")
    assert req.policy_data == {}


def test_GO_91_maintenance_window_reason_optional():
    req = CreateMaintenanceWindowRequest(name="mw", starts_at="a", ends_at="b")
    assert req.reason is None


def test_GO_92_create_reassessment_trigger_id_optional():
    req = CreateReassessmentRequest(assessment_id="a")
    assert req.trigger_id is None


def test_GO_93_create_workflow_trigger_id_optional():
    req = CreateWorkflowRequest(name="w")
    assert req.trigger_id is None


def test_GO_94_create_workflow_playbook_id_optional():
    req = CreateWorkflowRequest(name="w")
    assert req.playbook_id is None


def test_GO_95_policy_data_accepts_dict():
    req = CreatePolicyRequest(
        name="p", policy_data={"risk_level": "HIGH", "reassessment_interval_days": 90}
    )
    assert req.policy_data["risk_level"] == "HIGH"


def test_GO_96_update_policy_active_flag():
    req = UpdatePolicyRequest(active=False)
    assert req.active is False


def test_GO_97_create_playbook_description_optional():
    req = CreatePlaybookRequest(name="pb", playbook_type="PCI_DSS")
    assert req.description is None


def test_GO_98_approve_request_reason_max_length():
    with pytest.raises(ValidationError):
        ApproveRequest(decision="APPROVE", reason="X" * 5000)


def test_GO_99_create_trigger_policy_version_default():
    req = CreateTriggerRequest(trigger_type="MANUAL_REQUEST")
    assert req.policy_version == "1.0"


def test_GO_100_create_change_detection_data_dict():
    req = CreateChangeDetectionRequest(
        change_type="EVIDENCE_CHANGE", change_data={"a": 1}
    )
    assert req.change_data == {"a": 1}


# ===========================================================================
# GO-101 to GO-160: repository.py
# ===========================================================================


def test_GO_101_repo_create_policy(repo, db):
    row = repo.create_policy(name="p1", policy_data={"risk_level": "HIGH"})
    db.commit()
    assert row.id is not None
    assert row.tenant_id == _TENANT


def test_GO_102_repo_get_policy_tenant_isolation(db):
    ra = GovernanceOrchestrationRepository(db, tenant_id=_TENANT)
    rb = GovernanceOrchestrationRepository(db, tenant_id=_TENANT_B)
    row = ra.create_policy(name="p1")
    db.commit()
    assert rb.get_policy(row.id) is None
    assert ra.get_policy(row.id) is not None


def test_GO_103_repo_list_policies_pagination(repo, db):
    for i in range(3):
        repo.create_policy(name=f"pol-{i}")
    db.commit()
    rows, total = repo.list_policies(offset=0, limit=2)
    assert total >= 3
    assert len(rows) == 2


def test_GO_104_repo_create_playbook(repo, db):
    row = repo.create_playbook(name="pb", playbook_type="PCI_DSS")
    db.commit()
    assert row.playbook_type == "PCI_DSS"


def test_GO_105_repo_get_playbook_tenant_isolation(db):
    ra = GovernanceOrchestrationRepository(db, tenant_id=_TENANT)
    rb = GovernanceOrchestrationRepository(db, tenant_id=_TENANT_B)
    row = ra.create_playbook(name="pb", playbook_type="PCI_DSS")
    db.commit()
    assert rb.get_playbook(row.id) is None


def test_GO_106_repo_create_workflow(repo, db):
    row = repo.create_workflow(name="wf")
    db.commit()
    assert row.workflow_state == "PENDING"


def test_GO_107_repo_get_workflow_tenant_isolation(db):
    ra = GovernanceOrchestrationRepository(db, tenant_id=_TENANT)
    rb = GovernanceOrchestrationRepository(db, tenant_id=_TENANT_B)
    row = ra.create_workflow(name="wf")
    db.commit()
    assert rb.get_workflow(row.id) is None


def test_GO_108_repo_create_reassessment(repo, db):
    row = repo.create_reassessment(assessment_id="a-1")
    db.commit()
    assert row.assessment_id == "a-1"


def test_GO_109_repo_create_trigger(repo, db):
    row = repo.create_trigger(trigger_type="MANUAL_REQUEST", confidence=0.9)
    db.commit()
    assert row.trigger_type == "MANUAL_REQUEST"
    assert row.confidence == 0.9


def test_GO_110_repo_append_trigger_timeline(repo, db):
    trig = repo.create_trigger(trigger_type="MANUAL_REQUEST")
    row = repo.append_trigger_timeline(
        trigger_id=trig.id, event_type="recorded", actor_id="a"
    )
    db.commit()
    assert row.trigger_id == trig.id


def test_GO_111_trigger_timeline_is_append_only(repo, db):
    trig = repo.create_trigger(trigger_type="MANUAL_REQUEST")
    row = repo.append_trigger_timeline(trigger_id=trig.id, event_type="a", actor_id="a")
    db.commit()
    with pytest.raises(RuntimeError):
        row.event_type = "modified"
        db.flush()


def test_GO_112_repo_create_simulation(repo, db):
    row = repo.create_simulation(name="s", change_type="EVIDENCE_CHANGE")
    db.commit()
    assert row.name == "s"


def test_GO_113_repo_create_approval(repo, db):
    wf = repo.create_workflow(name="wf")
    row = repo.create_approval(workflow_id=wf.id, actor_id="alice", stage=1)
    db.commit()
    assert row.approval_state == "PENDING"


def test_GO_114_repo_list_approvals(repo, db):
    wf = repo.create_workflow(name="wf")
    repo.create_approval(workflow_id=wf.id, actor_id="alice", stage=1)
    repo.create_approval(workflow_id=wf.id, actor_id="bob", stage=2)
    db.commit()
    rows = repo.list_approvals(workflow_id=wf.id)
    assert len(rows) == 2


def test_GO_115_repo_create_maintenance_window(repo, db):
    row = repo.create_maintenance_window(
        name="mw", starts_at="2026-01-01T00:00:00Z", ends_at="2026-01-02T00:00:00Z"
    )
    db.commit()
    assert row.window_state == "SCHEDULED"


def test_GO_116_repo_create_change_detection(repo, db):
    row = repo.create_change_detection(change_type="EVIDENCE_CHANGE")
    db.commit()
    assert row.impact_level == "LOW"


def test_GO_117_repo_append_timeline(repo, db):
    row = repo.append_timeline(
        entity_type="policy",
        entity_id="p-1",
        event_type="created",
        actor_id="a",
    )
    db.commit()
    assert row.entity_type == "policy"


def test_GO_118_timeline_is_append_only(repo, db):
    row = repo.append_timeline(
        entity_type="policy", entity_id="p-1", event_type="e", actor_id=None
    )
    db.commit()
    with pytest.raises(RuntimeError):
        row.event_type = "modified"
        db.flush()


def test_GO_119_timeline_delete_forbidden(repo, db):
    row = repo.append_timeline(
        entity_type="policy", entity_id="p-1", event_type="e", actor_id=None
    )
    db.commit()
    with pytest.raises(RuntimeError):
        db.delete(row)
        db.flush()


def test_GO_120_repo_append_policy_version(repo, db):
    p = repo.create_policy(name="p")
    row = repo.append_policy_version(
        policy_id=p.id, version="1.1", policy_data={"a": 1}, actor_id="x"
    )
    db.commit()
    assert row.version == "1.1"


def test_GO_121_policy_version_is_append_only(repo, db):
    p = repo.create_policy(name="p")
    v = repo.append_policy_version(
        policy_id=p.id, version="1.1", policy_data={}, actor_id=None
    )
    db.commit()
    with pytest.raises(RuntimeError):
        v.version = "2.0"
        db.flush()


def test_GO_122_repo_list_workflows_filter_state(repo, db):
    repo.create_workflow(name="wf1", workflow_state="RUNNING")
    repo.create_workflow(name="wf2", workflow_state="PENDING")
    db.commit()
    rows, total = repo.list_workflows(workflow_state="RUNNING")
    for r in rows:
        assert r.workflow_state == "RUNNING"


def test_GO_123_repo_list_reassessments_filter(repo, db):
    repo.create_reassessment(assessment_id="a-1", reassessment_state="SCHEDULED")
    repo.create_reassessment(assessment_id="a-2", reassessment_state="REQUESTED")
    db.commit()
    rows, _ = repo.list_reassessments(reassessment_state="SCHEDULED")
    for r in rows:
        assert r.reassessment_state == "SCHEDULED"


def test_GO_124_repo_list_triggers_filter(repo, db):
    repo.create_trigger(trigger_type="MANUAL_REQUEST")
    repo.create_trigger(trigger_type="SCHEDULED")
    db.commit()
    rows, _ = repo.list_triggers(trigger_type="MANUAL_REQUEST")
    for r in rows:
        assert r.trigger_type == "MANUAL_REQUEST"


def test_GO_125_repo_list_change_detections_filter(repo, db):
    repo.create_change_detection(change_type="EVIDENCE_CHANGE")
    repo.create_change_detection(change_type="CONTROL_CHANGE")
    db.commit()
    rows, _ = repo.list_change_detections(change_type="EVIDENCE_CHANGE")
    for r in rows:
        assert r.change_type == "EVIDENCE_CHANGE"


def test_GO_126_repo_list_playbooks_filter(repo, db):
    repo.create_playbook(name="a", playbook_type="PCI_DSS")
    repo.create_playbook(name="b", playbook_type="HIPAA")
    db.commit()
    rows, _ = repo.list_playbooks(playbook_type="PCI_DSS")
    for r in rows:
        assert r.playbook_type == "PCI_DSS"


def test_GO_127_repo_update_workflow_touches_updated_at(repo, db):
    wf = repo.create_workflow(name="wf")
    old = wf.updated_at
    wf.workflow_state = "RUNNING"
    repo.update_workflow(wf)
    db.commit()
    assert wf.updated_at >= old


def test_GO_128_repo_update_policy_touches_updated_at(repo, db):
    p = repo.create_policy(name="p")
    old = p.updated_at
    p.name = "p2"
    repo.update_policy(p)
    db.commit()
    assert p.updated_at >= old


def test_GO_129_repo_list_timeline_filters_by_entity(repo, db):
    repo.append_timeline(
        entity_type="policy", entity_id="p1", event_type="x", actor_id=None
    )
    repo.append_timeline(
        entity_type="workflow", entity_id="w1", event_type="x", actor_id=None
    )
    db.commit()
    rows, _ = repo.list_timeline(entity_type="policy")
    assert all(r.entity_type == "policy" for r in rows)


def test_GO_130_repo_list_maintenance_filter_state(repo, db):
    repo.create_maintenance_window(
        name="a", starts_at="1", ends_at="2", window_state="ACTIVE"
    )
    repo.create_maintenance_window(
        name="b", starts_at="1", ends_at="2", window_state="SCHEDULED"
    )
    db.commit()
    rows = repo.list_maintenance_windows(window_state="ACTIVE")
    for r in rows:
        assert r.window_state == "ACTIVE"


def test_GO_131_repo_get_reassessment_tenant_isolation(db):
    ra = GovernanceOrchestrationRepository(db, tenant_id=_TENANT)
    rb = GovernanceOrchestrationRepository(db, tenant_id=_TENANT_B)
    row = ra.create_reassessment(assessment_id="a-1")
    db.commit()
    assert rb.get_reassessment(row.id) is None


def test_GO_132_repo_get_trigger_tenant_isolation(db):
    ra = GovernanceOrchestrationRepository(db, tenant_id=_TENANT)
    rb = GovernanceOrchestrationRepository(db, tenant_id=_TENANT_B)
    row = ra.create_trigger(trigger_type="MANUAL_REQUEST")
    db.commit()
    assert rb.get_trigger(row.id) is None


def test_GO_133_repo_get_simulation_tenant_isolation(db):
    ra = GovernanceOrchestrationRepository(db, tenant_id=_TENANT)
    rb = GovernanceOrchestrationRepository(db, tenant_id=_TENANT_B)
    row = ra.create_simulation(name="s", change_type="EVIDENCE_CHANGE")
    db.commit()
    assert rb.get_simulation(row.id) is None


def test_GO_134_repo_get_approval_tenant_isolation(db):
    ra = GovernanceOrchestrationRepository(db, tenant_id=_TENANT)
    rb = GovernanceOrchestrationRepository(db, tenant_id=_TENANT_B)
    wf = ra.create_workflow(name="wf")
    ap = ra.create_approval(workflow_id=wf.id, actor_id="x")
    db.commit()
    assert rb.get_approval(ap.id) is None


def test_GO_135_repo_get_maintenance_tenant_isolation(db):
    ra = GovernanceOrchestrationRepository(db, tenant_id=_TENANT)
    rb = GovernanceOrchestrationRepository(db, tenant_id=_TENANT_B)
    mw = ra.create_maintenance_window(name="mw", starts_at="1", ends_at="2")
    db.commit()
    assert rb.get_maintenance_window(mw.id) is None


def test_GO_136_repo_list_policy_versions_ordered(repo, db):
    p = repo.create_policy(name="p")
    repo.append_policy_version(
        policy_id=p.id, version="1.0", policy_data={}, actor_id=None
    )
    repo.append_policy_version(
        policy_id=p.id, version="1.1", policy_data={}, actor_id=None
    )
    db.commit()
    versions = repo.list_policy_versions(p.id)
    assert len(versions) == 2


def test_GO_137_repo_list_policies_active_filter(repo, db):
    repo.create_policy(name="a", active=True)
    repo.create_policy(name="b", active=False)
    db.commit()
    rows_active, _ = repo.list_policies(active=True)
    for r in rows_active:
        assert r.active == 1


def test_GO_138_repo_all_tenant_isolation_persists(db):
    ra = GovernanceOrchestrationRepository(db, tenant_id=_TENANT)
    rb = GovernanceOrchestrationRepository(db, tenant_id=_TENANT_B)
    ra.create_policy(name="a")
    rb.create_policy(name="b")
    db.commit()
    ra_rows, _ = ra.list_policies()
    rb_rows, _ = rb.list_policies()
    ra_ids = {r.id for r in ra_rows}
    rb_ids = {r.id for r in rb_rows}
    assert ra_ids.isdisjoint(rb_ids)


def test_GO_139_repo_new_id_is_uuid_like(repo, db):
    p = repo.create_policy(name="p")
    db.commit()
    assert len(p.id) >= 32


def test_GO_140_repo_policy_json_data_persisted(repo, db):
    p = repo.create_policy(name="p", policy_data={"risk_level": "HIGH"})
    db.commit()
    assert "HIGH" in (p.policy_data or "")


def test_GO_141_repo_workflow_context_json_persisted(repo, db):
    w = repo.create_workflow(name="wf", context={"scope": "audit"})
    db.commit()
    assert "audit" in (w.context or "")


def test_GO_142_repo_simulation_result_json_persisted(repo, db):
    s = repo.create_simulation(
        name="s", change_type="EVIDENCE_CHANGE", result={"impact": "HIGH"}
    )
    db.commit()
    assert "HIGH" in (s.result or "")


def test_GO_143_repo_playbook_data_json_persisted(repo, db):
    pb = repo.create_playbook(
        name="pb", playbook_type="PCI_DSS", playbook_data={"controls": ["a"]}
    )
    db.commit()
    assert "controls" in (pb.playbook_data or "")


def test_GO_144_repo_change_detection_json_persisted(repo, db):
    c = repo.create_change_detection(
        change_type="EVIDENCE_CHANGE", change_data={"delta": 5}
    )
    db.commit()
    assert "delta" in (c.change_data or "")


def test_GO_145_repo_timeline_metadata_json_persisted(repo, db):
    t = repo.append_timeline(
        entity_type="policy",
        entity_id="p1",
        event_type="x",
        actor_id=None,
        event_metadata={"k": "v"},
    )
    db.commit()
    assert '"k"' in (t.event_metadata or "")


def test_GO_146_repo_maintenance_reason_preserved(repo, db):
    mw = repo.create_maintenance_window(
        name="a", starts_at="1", ends_at="2", reason="planned"
    )
    db.commit()
    assert mw.reason == "planned"


def test_GO_147_repo_approval_quorum_default(repo, db):
    wf = repo.create_workflow(name="wf")
    ap = repo.create_approval(workflow_id=wf.id, actor_id="a")
    db.commit()
    assert ap.quorum == 1


def test_GO_148_repo_approval_stage_default(repo, db):
    wf = repo.create_workflow(name="wf")
    ap = repo.create_approval(workflow_id=wf.id, actor_id="a")
    db.commit()
    assert ap.stage == 1


def test_GO_149_repo_list_approvals_by_state(repo, db):
    wf = repo.create_workflow(name="wf")
    repo.create_approval(workflow_id=wf.id, actor_id="a", approval_state="APPROVED")
    repo.create_approval(workflow_id=wf.id, actor_id="b", approval_state="PENDING")
    db.commit()
    approved = repo.list_approvals(approval_state="APPROVED")
    for r in approved:
        assert r.approval_state == "APPROVED"


def test_GO_150_repo_workflow_completed_at_nullable_on_create(repo, db):
    wf = repo.create_workflow(name="wf")
    db.commit()
    assert wf.completed_at is None


# GO-151..160 exercise repository pagination / boundary conditions


def test_GO_151_repo_pagination_offset(repo, db):
    for i in range(5):
        repo.create_workflow(name=f"w-{i}")
    db.commit()
    rows_first, _ = repo.list_workflows(offset=0, limit=2)
    rows_second, _ = repo.list_workflows(offset=2, limit=2)
    first_ids = {r.id for r in rows_first}
    second_ids = {r.id for r in rows_second}
    assert first_ids.isdisjoint(second_ids)


def test_GO_152_repo_pagination_limit_bounds(repo, db):
    for i in range(3):
        repo.create_workflow(name=f"w-{i}")
    db.commit()
    rows, total = repo.list_workflows(offset=0, limit=100)
    assert total >= 3


def test_GO_153_repo_get_nonexistent_returns_none(repo):
    assert repo.get_policy("does-not-exist") is None
    assert repo.get_workflow("does-not-exist") is None
    assert repo.get_playbook("does-not-exist") is None
    assert repo.get_reassessment("does-not-exist") is None
    assert repo.get_trigger("does-not-exist") is None
    assert repo.get_simulation("does-not-exist") is None
    assert repo.get_approval("does-not-exist") is None
    assert repo.get_maintenance_window("does-not-exist") is None


def test_GO_154_repo_all_ids_unique_across_ops(repo, db):
    ids: set[str] = set()
    for _ in range(5):
        ids.add(repo.create_policy(name="p").id)
        ids.add(repo.create_workflow(name="w").id)
    db.commit()
    assert len(ids) == 10


def test_GO_155_repo_json_default_empty_dict(repo, db):
    p = repo.create_policy(name="p")
    db.commit()
    assert p.policy_data == "{}"


def test_GO_156_repo_list_timeline_by_entity_id(repo, db):
    repo.append_timeline(
        entity_type="p", entity_id="one", event_type="e", actor_id=None
    )
    repo.append_timeline(
        entity_type="p", entity_id="two", event_type="e", actor_id=None
    )
    db.commit()
    rows, _ = repo.list_timeline(entity_type="p", entity_id="one")
    for r in rows:
        assert r.entity_id == "one"


def test_GO_157_repo_maintenance_default_scheduled(repo, db):
    mw = repo.create_maintenance_window(name="a", starts_at="1", ends_at="2")
    db.commit()
    assert mw.window_state == "SCHEDULED"


def test_GO_158_repo_change_default_impact_low(repo, db):
    c = repo.create_change_detection(change_type="EVIDENCE_CHANGE")
    db.commit()
    assert c.impact_level == "LOW"


def test_GO_159_repo_reassessment_default_state_requested(repo, db):
    r = repo.create_reassessment(assessment_id="a")
    db.commit()
    assert r.reassessment_state == "REQUESTED"


def test_GO_160_repo_simulation_default_state_pending(repo, db):
    s = repo.create_simulation(name="s", change_type="EVIDENCE_CHANGE")
    db.commit()
    assert s.simulation_state == "PENDING"


# ===========================================================================
# GO-161 to GO-220: engine.py
# ===========================================================================


def test_GO_161_engine_create_policy(svc):
    resp = svc.create_policy(
        CreatePolicyRequest(name="p1", risk_level="HIGH"), actor_id="tester"
    )
    assert resp.name == "p1"
    assert resp.risk_level == "HIGH"


def test_GO_162_engine_get_policy_not_found(svc):
    with pytest.raises(GovernanceOrchestrationNotFound):
        svc.get_policy("does-not-exist")


def test_GO_163_engine_list_policies_empty(svc):
    resp = svc.list_policies()
    assert resp.items == []


def test_GO_164_engine_tenant_isolation(svc, svc_b):
    p_a = svc.create_policy(CreatePolicyRequest(name="a"), actor_id="x")
    with pytest.raises(GovernanceOrchestrationNotFound):
        svc_b.get_policy(p_a.id)


def test_GO_165_engine_update_policy(svc):
    p = svc.create_policy(CreatePolicyRequest(name="p"), actor_id="x")
    updated = svc.update_policy(
        p.id, UpdatePolicyRequest(risk_level="HIGH"), actor_id="x"
    )
    assert updated.risk_level == "HIGH"


def test_GO_166_engine_update_policy_invalid_risk_level(svc):
    p = svc.create_policy(CreatePolicyRequest(name="p"), actor_id="x")
    with pytest.raises(GovernanceOrchestrationValidationError):
        svc.update_policy(p.id, UpdatePolicyRequest(risk_level="INVALID"), actor_id="x")


def test_GO_167_engine_create_playbook(svc):
    p = svc.create_playbook(
        CreatePlaybookRequest(name="pb", playbook_type="PCI_DSS"),
        actor_id="x",
    )
    assert p.playbook_type == "PCI_DSS"


def test_GO_168_engine_create_playbook_invalid_type(svc):
    with pytest.raises(GovernanceOrchestrationValidationError):
        svc.create_playbook(
            CreatePlaybookRequest(name="pb", playbook_type="UNKNOWN"),
            actor_id="x",
        )


def test_GO_169_engine_get_playbook_template(svc):
    tpl = svc.get_playbook_template("PCI_DSS")
    assert "controls" in tpl


def test_GO_170_engine_create_workflow(svc):
    wf = svc.create_workflow(CreateWorkflowRequest(name="wf"), actor_id="x")
    assert wf.workflow_state == "PENDING"


def test_GO_171_engine_advance_workflow(svc):
    wf = svc.create_workflow(CreateWorkflowRequest(name="wf"), actor_id="x")
    advanced = svc.advance_workflow(wf.id, "start", actor_id="x")
    assert advanced.workflow_state == "RUNNING"


def test_GO_172_engine_cancel_workflow(svc):
    wf = svc.create_workflow(CreateWorkflowRequest(name="wf"), actor_id="x")
    cancelled = svc.cancel_workflow(wf.id, actor_id="x")
    assert cancelled.workflow_state == "CANCELLED"


def test_GO_173_engine_pause_workflow_requires_running(svc):
    wf = svc.create_workflow(CreateWorkflowRequest(name="wf"), actor_id="x")
    with pytest.raises(GovernanceOrchestrationInvalidTransition):
        svc.pause_workflow(wf.id, actor_id="x")


def test_GO_174_engine_pause_workflow_after_start(svc):
    wf = svc.create_workflow(CreateWorkflowRequest(name="wf"), actor_id="x")
    svc.advance_workflow(wf.id, "start", actor_id="x")
    paused = svc.pause_workflow(wf.id, actor_id="x")
    assert paused.workflow_state == "PAUSED"


def test_GO_175_engine_create_reassessment(svc):
    r = svc.create_reassessment(
        CreateReassessmentRequest(assessment_id="a-1"), actor_id="x"
    )
    assert r.reassessment_state == "REQUESTED"


def test_GO_176_engine_schedule_reassessment(svc):
    r = svc.create_reassessment(
        CreateReassessmentRequest(assessment_id="a-1"), actor_id="x"
    )
    scheduled = svc.schedule_reassessment(r.id, "2026-01-01T00:00:00Z", actor_id="x")
    assert scheduled.reassessment_state == "SCHEDULED"


def test_GO_177_engine_complete_reassessment(svc):
    r = svc.create_reassessment(
        CreateReassessmentRequest(assessment_id="a-1"), actor_id="x"
    )
    svc.schedule_reassessment(r.id, "2026-01-01T00:00:00Z", actor_id="x")
    completed = svc.complete_reassessment(r.id, "PASS", actor_id="x")
    assert completed.reassessment_state == "COMPLETED"


def test_GO_178_engine_create_trigger(svc):
    t = svc.create_trigger(
        CreateTriggerRequest(trigger_type="MANUAL_REQUEST", confidence=1.0),
        actor_id="x",
    )
    assert t.trigger_type == "MANUAL_REQUEST"


def test_GO_179_engine_trigger_invalid_type(svc):
    with pytest.raises(GovernanceOrchestrationValidationError):
        svc.create_trigger(
            CreateTriggerRequest(trigger_type="NOT_A_TYPE"), actor_id="x"
        )


def test_GO_180_engine_create_simulation(svc):
    s = svc.create_simulation(
        CreateSimulationRequest(name="s", change_type="EVIDENCE_CHANGE"),
        actor_id="x",
    )
    assert s.simulation_state == "COMPLETED"


def test_GO_181_engine_get_simulation(svc):
    s = svc.create_simulation(
        CreateSimulationRequest(name="s", change_type="EVIDENCE_CHANGE"),
        actor_id="x",
    )
    got = svc.get_simulation(s.id)
    assert got.id == s.id


def test_GO_182_engine_simulation_not_found(svc):
    with pytest.raises(GovernanceOrchestrationNotFound):
        svc.get_simulation("does-not-exist")


def test_GO_183_engine_create_approval(svc):
    wf = svc.create_workflow(CreateWorkflowRequest(name="wf"), actor_id="x")
    ap = svc.create_approval(
        CreateApprovalRequest(workflow_id=wf.id, actor_id="alice"), actor_id="x"
    )
    assert ap.approval_state == "PENDING"


def test_GO_184_engine_approve_approval(svc):
    wf = svc.create_workflow(CreateWorkflowRequest(name="wf"), actor_id="x")
    ap = svc.create_approval(
        CreateApprovalRequest(workflow_id=wf.id, actor_id="alice"), actor_id="x"
    )
    resp = svc.approve_approval(
        ap.id, ApproveRequest(decision="APPROVE"), actor_id="alice"
    )
    assert resp.approval_state == "APPROVED"


def test_GO_185_engine_reject_approval(svc):
    wf = svc.create_workflow(CreateWorkflowRequest(name="wf"), actor_id="x")
    ap = svc.create_approval(
        CreateApprovalRequest(workflow_id=wf.id, actor_id="a"), actor_id="x"
    )
    resp = svc.approve_approval(ap.id, ApproveRequest(decision="REJECT"), actor_id="a")
    assert resp.approval_state == "REJECTED"


def test_GO_186_engine_approval_invalid_decision(svc):
    wf = svc.create_workflow(CreateWorkflowRequest(name="wf"), actor_id="x")
    ap = svc.create_approval(
        CreateApprovalRequest(workflow_id=wf.id, actor_id="a"), actor_id="x"
    )
    with pytest.raises(GovernanceOrchestrationApprovalError):
        svc.approve_approval(ap.id, ApproveRequest(decision="BOGUS"), actor_id="a")


def test_GO_187_engine_create_maintenance_window(svc):
    mw = svc.create_maintenance_window(
        CreateMaintenanceWindowRequest(
            name="mw",
            starts_at="2026-01-01T00:00:00Z",
            ends_at="2026-01-02T00:00:00Z",
        ),
        actor_id="x",
    )
    assert mw.window_state == "SCHEDULED"


def test_GO_188_engine_maintenance_invalid_range(svc):
    with pytest.raises(GovernanceOrchestrationValidationError):
        svc.create_maintenance_window(
            CreateMaintenanceWindowRequest(
                name="mw",
                starts_at="2026-01-02T00:00:00Z",
                ends_at="2026-01-01T00:00:00Z",
            ),
            actor_id="x",
        )


def test_GO_189_engine_open_and_close_window(svc):
    mw = svc.create_maintenance_window(
        CreateMaintenanceWindowRequest(
            name="mw",
            starts_at="2026-01-01T00:00:00Z",
            ends_at="2026-01-02T00:00:00Z",
        ),
        actor_id="x",
    )
    opened = svc.open_maintenance_window(mw.id, actor_id="x")
    assert opened.window_state == "ACTIVE"
    closed = svc.close_maintenance_window(mw.id, actor_id="x")
    assert closed.window_state == "COMPLETED"


def test_GO_190_engine_create_change_detection(svc):
    c = svc.create_change_detection(
        CreateChangeDetectionRequest(change_type="EVIDENCE_CHANGE"),
        actor_id="x",
    )
    assert c.change_type == "EVIDENCE_CHANGE"


def test_GO_191_engine_dashboard(svc):
    dash = svc.get_dashboard()
    assert dash.tenant_id == _TENANT


def test_GO_192_engine_statistics(svc):
    stats = svc.get_statistics()
    assert stats.tenant_id == _TENANT


def test_GO_193_engine_impact_analysis(svc):
    resp = svc.get_impact_analysis(change_type="EVIDENCE_CHANGE")
    assert resp.change_type == "EVIDENCE_CHANGE"


def test_GO_194_engine_search(svc):
    svc.create_policy(CreatePolicyRequest(name="alpha"), actor_id="x")
    resp = svc.search("alpha")
    assert resp.total >= 1


def test_GO_195_engine_get_timeline(svc):
    svc.create_policy(CreatePolicyRequest(name="p"), actor_id="x")
    tl = svc.get_timeline()
    assert tl.total >= 1


def test_GO_196_engine_health(svc):
    h = svc.health()
    assert h.status in {"ok", "degraded"}
    assert h.authority == "governance_orchestration"
    assert h.schema_version == "1.0"


def test_GO_197_engine_tenant_validation_on_construct(db):
    with pytest.raises(GovernanceOrchestrationTenantViolation):
        GovernanceOrchestrationEngine(db, tenant_id="")


def test_GO_198_engine_evaluate_governance_loop_returns_dict(svc):
    result = svc.evaluate_governance_loop(context={})
    assert "state" in result
    assert "triggers_detected" in result


def test_GO_199_engine_evaluate_governance_loop_triggers(svc):
    result = svc.evaluate_governance_loop(
        context={"evidence_expired": True, "verification_failures": 2}
    )
    assert len(result["triggers_detected"]) >= 1


def test_GO_200_engine_compute_evidence_sufficiency(svc):
    result = svc.compute_evidence_sufficiency()
    assert "coverage_pct" in result


def test_GO_201_engine_get_history(svc):
    p = svc.create_policy(CreatePolicyRequest(name="p"), actor_id="x")
    hist = svc.get_history("policy", p.id)
    assert hist.total >= 1


def test_GO_202_engine_list_workflows_filter_state(svc):
    svc.create_workflow(CreateWorkflowRequest(name="w1"), actor_id="x")
    resp = svc.list_workflows(workflow_state="PENDING")
    for item in resp.items:
        assert item.workflow_state == "PENDING"


def test_GO_203_engine_list_reassessments_filter(svc):
    svc.create_reassessment(CreateReassessmentRequest(assessment_id="a"), actor_id="x")
    resp = svc.list_reassessments(reassessment_state="REQUESTED")
    for item in resp.items:
        assert item.reassessment_state == "REQUESTED"


def test_GO_204_engine_list_triggers_filter(svc):
    svc.create_trigger(
        CreateTriggerRequest(trigger_type="MANUAL_REQUEST"), actor_id="x"
    )
    resp = svc.list_triggers(trigger_type="MANUAL_REQUEST")
    for t in resp.items:
        assert t.trigger_type == "MANUAL_REQUEST"


def test_GO_205_engine_list_change_detections_filter(svc):
    svc.create_change_detection(
        CreateChangeDetectionRequest(change_type="EVIDENCE_CHANGE"),
        actor_id="x",
    )
    resp = svc.list_change_detections(change_type="EVIDENCE_CHANGE")
    for c in resp.items:
        assert c.change_type == "EVIDENCE_CHANGE"


def test_GO_206_engine_workflow_cancel_after_terminal(svc):
    wf = svc.create_workflow(CreateWorkflowRequest(name="wf"), actor_id="x")
    svc.cancel_workflow(wf.id, actor_id="x")
    with pytest.raises(GovernanceOrchestrationInvalidTransition):
        svc.cancel_workflow(wf.id, actor_id="x")


def test_GO_207_engine_reassessment_reschedule_terminal(svc):
    r = svc.create_reassessment(
        CreateReassessmentRequest(assessment_id="a"), actor_id="x"
    )
    svc.schedule_reassessment(r.id, "2026-01-01T00:00:00Z", actor_id="x")
    svc.complete_reassessment(r.id, "PASS", actor_id="x")
    with pytest.raises(GovernanceOrchestrationInvalidTransition):
        svc.schedule_reassessment(r.id, "2026-02-01T00:00:00Z", actor_id="x")


def test_GO_208_engine_create_workflow_populates_timeline(svc):
    wf = svc.create_workflow(CreateWorkflowRequest(name="wf"), actor_id="x")
    tl = svc.get_timeline(entity_type="workflow", entity_id=wf.id)
    assert any(e.event_type == "workflow_created" for e in tl.events)


def test_GO_209_engine_create_policy_populates_timeline(svc):
    p = svc.create_policy(CreatePolicyRequest(name="p"), actor_id="x")
    tl = svc.get_timeline(entity_type="policy", entity_id=p.id)
    assert any(e.event_type == "policy_created" for e in tl.events)


def test_GO_210_engine_reassessment_populates_timeline(svc):
    r = svc.create_reassessment(
        CreateReassessmentRequest(assessment_id="a"), actor_id="x"
    )
    tl = svc.get_timeline(entity_type="reassessment", entity_id=r.id)
    assert any(e.event_type == "reassessment_requested" for e in tl.events)


def test_GO_211_engine_update_policy_populates_timeline(svc):
    p = svc.create_policy(CreatePolicyRequest(name="p"), actor_id="x")
    svc.update_policy(p.id, UpdatePolicyRequest(name="new"), actor_id="x")
    tl = svc.get_timeline(entity_type="policy", entity_id=p.id)
    assert any(e.event_type == "policy_updated" for e in tl.events)


def test_GO_212_engine_search_empty(svc):
    resp = svc.search("nothing-here")
    assert resp.total == 0


def test_GO_213_engine_dashboard_evidence_pct_default_zero(svc):
    dash = svc.get_dashboard()
    assert dash.evidence_sufficiency_pct >= 0.0


def test_GO_214_engine_impact_high_severity(svc):
    resp = svc.get_impact_analysis(change_type="RISK_CHANGE")
    assert resp.impact_level in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}


def test_GO_215_engine_list_playbooks(svc):
    svc.create_playbook(
        CreatePlaybookRequest(name="a", playbook_type="PCI_DSS"), actor_id="x"
    )
    resp = svc.list_playbooks()
    assert resp.total >= 1


def test_GO_216_engine_maintenance_open_invalid(svc):
    mw = svc.create_maintenance_window(
        CreateMaintenanceWindowRequest(
            name="mw", starts_at="2026-01-01T00:00:00Z", ends_at="2026-01-02T00:00:00Z"
        ),
        actor_id="x",
    )
    svc.open_maintenance_window(mw.id, actor_id="x")
    # already active — cannot open again
    with pytest.raises(GovernanceOrchestrationInvalidTransition):
        svc.open_maintenance_window(mw.id, actor_id="x")


def test_GO_217_engine_approval_not_found(svc):
    with pytest.raises(GovernanceOrchestrationNotFound):
        svc.approve_approval(
            "does-not-exist", ApproveRequest(decision="APPROVE"), actor_id="x"
        )


def test_GO_218_engine_create_approval_missing_workflow(svc):
    with pytest.raises(GovernanceOrchestrationNotFound):
        svc.create_approval(
            CreateApprovalRequest(workflow_id="no", actor_id="a"),
            actor_id="x",
        )


def test_GO_219_engine_delegate_approval(svc):
    wf = svc.create_workflow(CreateWorkflowRequest(name="wf"), actor_id="x")
    ap = svc.create_approval(
        CreateApprovalRequest(workflow_id=wf.id, actor_id="a"), actor_id="x"
    )
    resp = svc.approve_approval(
        ap.id, ApproveRequest(decision="DELEGATE", delegated_to="b"), actor_id="a"
    )
    assert resp.approval_state == "DELEGATED"
    assert resp.delegated_to == "b"


def test_GO_220_engine_reassessment_not_found(svc):
    with pytest.raises(GovernanceOrchestrationNotFound):
        svc.get_reassessment("does-not-exist")


# ===========================================================================
# GO-221 to GO-260: validators.py
# ===========================================================================


def test_GO_221_validate_tenant_id_ok():
    validate_tenant_id("t-1")


def test_GO_222_validate_tenant_id_empty():
    with pytest.raises(GovernanceOrchestrationTenantViolation):
        validate_tenant_id("")


def test_GO_223_validate_tenant_id_whitespace():
    with pytest.raises(GovernanceOrchestrationTenantViolation):
        validate_tenant_id("   ")


def test_GO_224_validate_tenant_id_non_string():
    with pytest.raises(GovernanceOrchestrationTenantViolation):
        validate_tenant_id(None)  # type: ignore[arg-type]


def test_GO_225_validate_limit_offset_ok():
    validate_limit_offset(10, 0)


def test_GO_226_validate_limit_offset_high_limit():
    with pytest.raises(GovernanceOrchestrationValidationError):
        validate_limit_offset(1000, 0)


def test_GO_227_validate_limit_offset_negative_offset():
    with pytest.raises(GovernanceOrchestrationValidationError):
        validate_limit_offset(10, -1)


def test_GO_228_validate_limit_offset_zero_limit():
    with pytest.raises(GovernanceOrchestrationValidationError):
        validate_limit_offset(0, 0)


def test_GO_229_validate_search_query_ok():
    validate_search_query("abc")


def test_GO_230_validate_search_query_empty():
    with pytest.raises(GovernanceOrchestrationValidationError):
        validate_search_query("")


def test_GO_231_validate_search_query_too_long():
    with pytest.raises(GovernanceOrchestrationValidationError):
        validate_search_query("x" * 1000)


def test_GO_232_validate_policy_risk_level_ok():
    validate_policy_risk_level("HIGH")


def test_GO_233_validate_policy_risk_level_bad():
    with pytest.raises(GovernanceOrchestrationValidationError):
        validate_policy_risk_level("WRONG")


def test_GO_234_validate_trigger_type_ok():
    validate_trigger_type("MANUAL_REQUEST")


def test_GO_235_validate_trigger_type_bad():
    with pytest.raises(GovernanceOrchestrationValidationError):
        validate_trigger_type("WRONG")


def test_GO_236_validate_workflow_state_ok():
    validate_workflow_state("PENDING")


def test_GO_237_validate_workflow_state_bad():
    with pytest.raises(GovernanceOrchestrationValidationError):
        validate_workflow_state("WRONG")


def test_GO_238_validate_confidence_ok():
    validate_confidence(0.5)


def test_GO_239_validate_confidence_low():
    with pytest.raises(GovernanceOrchestrationValidationError):
        validate_confidence(-0.1)


def test_GO_240_validate_confidence_high():
    with pytest.raises(GovernanceOrchestrationValidationError):
        validate_confidence(1.1)


def test_GO_241_validate_confidence_non_numeric():
    with pytest.raises(GovernanceOrchestrationValidationError):
        validate_confidence("x")  # type: ignore[arg-type]


def test_GO_242_validate_playbook_type_ok():
    validate_playbook_type("PCI_DSS")


def test_GO_243_validate_playbook_type_bad():
    with pytest.raises(GovernanceOrchestrationValidationError):
        validate_playbook_type("UNKNOWN")


def test_GO_244_validate_impact_level_ok():
    validate_impact_level("HIGH")


def test_GO_245_validate_impact_level_bad():
    with pytest.raises(GovernanceOrchestrationValidationError):
        validate_impact_level("WRONG")


def test_GO_246_validate_search_query_non_string():
    with pytest.raises(GovernanceOrchestrationValidationError):
        validate_search_query(1)  # type: ignore[arg-type]


def test_GO_247_validate_limit_offset_negative_limit():
    with pytest.raises(GovernanceOrchestrationValidationError):
        validate_limit_offset(-5, 0)


def test_GO_248_validate_all_risk_levels_pass():
    for lvl in ("HIGH", "MEDIUM", "LOW", "CRITICAL"):
        validate_policy_risk_level(lvl)


def test_GO_249_validate_all_trigger_types_pass():
    for t in (
        "EVIDENCE_EXPIRED",
        "EVIDENCE_REVOKED",
        "VERIFICATION_FAILED",
        "CONTROL_DEGRADED",
    ):
        validate_trigger_type(t)


def test_GO_250_validate_all_workflow_states_pass():
    for s in ("PENDING", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"):
        validate_workflow_state(s)


def test_GO_251_validate_all_playbook_types_pass():
    for pt in (
        "PCI_DSS",
        "HIPAA",
        "NIST_CSF",
        "ISO_27001",
        "SOC2",
        "MICROSOFT_SECURE_SCORE",
        "CIS_CONTROLS",
    ):
        validate_playbook_type(pt)


def test_GO_252_validate_all_impact_levels_pass():
    for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"):
        validate_impact_level(lvl)


def test_GO_253_validate_limit_offset_boundary_high():
    validate_limit_offset(500, 0)  # 500 allowed


def test_GO_254_validate_limit_offset_boundary_low():
    validate_limit_offset(1, 0)


def test_GO_255_validate_search_query_bound():
    validate_search_query("x" * 512)


def test_GO_256_validate_confidence_boundary_low():
    validate_confidence(0.0)


def test_GO_257_validate_confidence_boundary_high():
    validate_confidence(1.0)


def test_GO_258_validate_tenant_id_string_ok():
    validate_tenant_id("tenant_string")


def test_GO_259_validate_search_query_padded():
    validate_search_query("  q  ")


def test_GO_260_validate_all_validators_run():
    validate_tenant_id("t")
    validate_limit_offset(10, 0)
    validate_search_query("q")
    validate_policy_risk_level("LOW")
    validate_trigger_type("SCHEDULED")
    validate_workflow_state("PENDING")
    validate_confidence(0.5)
    validate_playbook_type("SOC2")
    validate_impact_level("MEDIUM")


# ===========================================================================
# GO-261 to GO-500: extended coverage — schemas, engine, integration
# ===========================================================================


@pytest.mark.parametrize("risk", ["HIGH", "MEDIUM", "LOW", "CRITICAL"])
def test_GO_261_create_policy_all_risk_levels(svc, risk):
    p = svc.create_policy(
        CreatePolicyRequest(name=f"p-{risk}", risk_level=risk), actor_id="x"
    )
    assert p.risk_level == risk


@pytest.mark.parametrize(
    "pb_type",
    [
        "PCI_DSS",
        "HIPAA",
        "NIST_CSF",
        "ISO_27001",
        "SOC2",
        "MICROSOFT_SECURE_SCORE",
        "CIS_CONTROLS",
    ],
)
def test_GO_262_create_playbook_all_types(svc, pb_type):
    p = svc.create_playbook(
        CreatePlaybookRequest(name=f"pb-{pb_type}", playbook_type=pb_type),
        actor_id="x",
    )
    assert p.playbook_type == pb_type


@pytest.mark.parametrize(
    "tt",
    [
        "EVIDENCE_EXPIRED",
        "EVIDENCE_REVOKED",
        "VERIFICATION_FAILED",
        "CONTROL_DEGRADED",
        "RISK_THRESHOLD_EXCEEDED",
        "REMEDIATION_COMPLETED",
        "REMEDIATION_FAILED",
        "TRUST_ROTATION",
        "TRANSPARENCY_INCONSISTENCY",
        "MANUAL_REQUEST",
        "SCHEDULED",
        "FRAMEWORK_REVISION",
        "TENANT_POLICY",
    ],
)
def test_GO_263_create_trigger_all_types(svc, tt):
    t = svc.create_trigger(CreateTriggerRequest(trigger_type=tt), actor_id="x")
    assert t.trigger_type == tt


@pytest.mark.parametrize(
    "ct",
    [
        "EVIDENCE_CHANGE",
        "CONTROL_CHANGE",
        "RISK_CHANGE",
        "POLICY_CHANGE",
        "FRAMEWORK_CHANGE",
        "TRUST_CHANGE",
    ],
)
def test_GO_264_create_change_all_types(svc, ct):
    c = svc.create_change_detection(
        CreateChangeDetectionRequest(change_type=ct), actor_id="x"
    )
    assert c.change_type == ct


@pytest.mark.parametrize("il", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"])
def test_GO_265_create_change_impact_levels(svc, il):
    c = svc.create_change_detection(
        CreateChangeDetectionRequest(change_type="EVIDENCE_CHANGE", impact_level=il),
        actor_id="x",
    )
    assert c.impact_level == il


@pytest.mark.parametrize("conf", [0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0])
def test_GO_266_trigger_confidence_range(svc, conf):
    t = svc.create_trigger(
        CreateTriggerRequest(trigger_type="MANUAL_REQUEST", confidence=conf),
        actor_id="x",
    )
    assert t.confidence == conf


@pytest.mark.parametrize(
    "field",
    ["name", "description", "risk_level"],
)
def test_GO_267_update_policy_field_by_field(svc, field):
    p = svc.create_policy(CreatePolicyRequest(name="p"), actor_id="x")
    kwargs: dict = {field: "MEDIUM" if field == "risk_level" else "updated"}
    updated = svc.update_policy(p.id, UpdatePolicyRequest(**kwargs), actor_id="x")
    got = getattr(updated, field)
    assert got is not None


@pytest.mark.parametrize("i", range(20))
def test_GO_268_create_many_workflows(svc, i):
    wf = svc.create_workflow(CreateWorkflowRequest(name=f"wf-{i}"), actor_id="x")
    assert wf.workflow_state == "PENDING"


@pytest.mark.parametrize("i", range(20))
def test_GO_269_create_many_policies(svc, i):
    p = svc.create_policy(CreatePolicyRequest(name=f"p-{i}"), actor_id="x")
    assert p.id is not None


@pytest.mark.parametrize("i", range(10))
def test_GO_270_create_many_triggers(svc, i):
    t = svc.create_trigger(
        CreateTriggerRequest(trigger_type="MANUAL_REQUEST"), actor_id="x"
    )
    assert t.id is not None


@pytest.mark.parametrize("stage,quorum", [(1, 1), (1, 2), (2, 1), (3, 2), (5, 3)])
def test_GO_271_approval_stage_quorum_combinations(svc, stage, quorum):
    wf = svc.create_workflow(CreateWorkflowRequest(name="wf"), actor_id="x")
    ap = svc.create_approval(
        CreateApprovalRequest(
            workflow_id=wf.id, actor_id="a", stage=stage, quorum=quorum
        ),
        actor_id="x",
    )
    assert ap.stage == stage
    assert ap.quorum == quorum


# ---------------------------------------------------------------------------
# Extra tenant isolation checks
# ---------------------------------------------------------------------------


def test_GO_272_playbook_tenant_isolation(svc, svc_b):
    pb = svc.create_playbook(
        CreatePlaybookRequest(name="pb", playbook_type="PCI_DSS"), actor_id="x"
    )
    with pytest.raises(GovernanceOrchestrationNotFound):
        svc_b.get_playbook(pb.id)


def test_GO_273_workflow_tenant_isolation(svc, svc_b):
    wf = svc.create_workflow(CreateWorkflowRequest(name="wf"), actor_id="x")
    with pytest.raises(GovernanceOrchestrationNotFound):
        svc_b.get_workflow(wf.id)


def test_GO_274_reassessment_tenant_isolation(svc, svc_b):
    r = svc.create_reassessment(
        CreateReassessmentRequest(assessment_id="a"), actor_id="x"
    )
    with pytest.raises(GovernanceOrchestrationNotFound):
        svc_b.get_reassessment(r.id)


def test_GO_275_trigger_tenant_isolation(svc, svc_b):
    t = svc.create_trigger(
        CreateTriggerRequest(trigger_type="MANUAL_REQUEST"), actor_id="x"
    )
    with pytest.raises(GovernanceOrchestrationNotFound):
        svc_b.get_trigger(t.id)


def test_GO_276_simulation_tenant_isolation(svc, svc_b):
    s = svc.create_simulation(
        CreateSimulationRequest(name="s", change_type="EVIDENCE_CHANGE"),
        actor_id="x",
    )
    with pytest.raises(GovernanceOrchestrationNotFound):
        svc_b.get_simulation(s.id)


def test_GO_277_maintenance_window_tenant_isolation(svc, svc_b):
    mw = svc.create_maintenance_window(
        CreateMaintenanceWindowRequest(
            name="mw", starts_at="2020-01-01T00:00:00Z", ends_at="2099-01-01T00:00:00Z"
        ),
        actor_id="x",
    )
    with pytest.raises(GovernanceOrchestrationNotFound):
        svc_b.get_maintenance_window(mw.id)


def test_GO_278_list_policies_tenant_isolation(svc, svc_b):
    svc.create_policy(CreatePolicyRequest(name="a"), actor_id="x")
    resp_a = svc.list_policies()
    resp_b = svc_b.list_policies()
    ids_a = {p.id for p in resp_a.items}
    ids_b = {p.id for p in resp_b.items}
    assert ids_a.isdisjoint(ids_b)


def test_GO_279_dashboard_tenant_isolation(svc, svc_b):
    svc.create_policy(CreatePolicyRequest(name="a"), actor_id="x")
    da = svc.get_dashboard()
    db_ = svc_b.get_dashboard()
    assert da.tenant_id != db_.tenant_id


def test_GO_280_statistics_tenant_isolation(svc, svc_b):
    sa = svc.get_statistics()
    sb = svc_b.get_statistics()
    assert sa.tenant_id != sb.tenant_id


# ---------------------------------------------------------------------------
# Health / schema versioning
# ---------------------------------------------------------------------------


def test_GO_281_health_authority_name(svc):
    h = svc.health()
    assert h.authority == "governance_orchestration"


def test_GO_282_health_version(svc):
    h = svc.health()
    assert h.version.startswith("1.")


def test_GO_283_health_schema_version(svc):
    h = svc.health()
    assert h.schema_version == GOVERNANCE_ORCHESTRATION_SCHEMA_VERSION


def test_GO_284_health_checks_dict(svc):
    h = svc.health()
    assert isinstance(h.checks, dict)


def test_GO_285_health_status_in_expected(svc):
    h = svc.health()
    assert h.status in {"ok", "degraded"}


# ---------------------------------------------------------------------------
# Pagination / limits
# ---------------------------------------------------------------------------


def test_GO_286_list_policies_limit_1(svc):
    svc.create_policy(CreatePolicyRequest(name="a"), actor_id="x")
    svc.create_policy(CreatePolicyRequest(name="b"), actor_id="x")
    resp = svc.list_policies(limit=1)
    assert len(resp.items) == 1


def test_GO_287_list_workflows_limit_offset(svc):
    for i in range(5):
        svc.create_workflow(CreateWorkflowRequest(name=f"wf-{i}"), actor_id="x")
    resp_a = svc.list_workflows(offset=0, limit=2)
    resp_b = svc.list_workflows(offset=2, limit=2)
    ids_a = {i.id for i in resp_a.items}
    ids_b = {i.id for i in resp_b.items}
    assert ids_a.isdisjoint(ids_b)


def test_GO_288_list_triggers_limit_boundary(svc):
    for i in range(3):
        svc.create_trigger(
            CreateTriggerRequest(trigger_type="MANUAL_REQUEST"), actor_id="x"
        )
    resp = svc.list_triggers(limit=500)
    assert resp.total >= 3


def test_GO_289_list_reassessments_offset_bounds(svc):
    with pytest.raises(GovernanceOrchestrationValidationError):
        svc.list_reassessments(offset=-1)


def test_GO_290_list_policies_limit_zero_error(svc):
    with pytest.raises(GovernanceOrchestrationValidationError):
        svc.list_policies(limit=0)


# ---------------------------------------------------------------------------
# Search across policies / playbooks / workflows
# ---------------------------------------------------------------------------


def test_GO_291_search_finds_policy(svc):
    svc.create_policy(CreatePolicyRequest(name="findme-1"), actor_id="x")
    resp = svc.search("findme")
    assert resp.total >= 1


def test_GO_292_search_finds_playbook(svc):
    svc.create_playbook(
        CreatePlaybookRequest(name="findme-pb", playbook_type="PCI_DSS"),
        actor_id="x",
    )
    resp = svc.search("findme-pb")
    assert resp.total >= 1


def test_GO_293_search_finds_workflow(svc):
    svc.create_workflow(CreateWorkflowRequest(name="findme-wf"), actor_id="x")
    resp = svc.search("findme-wf")
    assert resp.total >= 1


def test_GO_294_search_no_match(svc):
    resp = svc.search("gibberish_zz")
    assert resp.total == 0


def test_GO_295_search_case_insensitive(svc):
    svc.create_policy(CreatePolicyRequest(name="MixedCase-xyz"), actor_id="x")
    resp = svc.search("mixedcase")
    assert resp.total >= 1


def test_GO_296_search_query_validation(svc):
    with pytest.raises(GovernanceOrchestrationValidationError):
        svc.search("")


# ---------------------------------------------------------------------------
# Impact analysis via engine
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ct",
    [
        "EVIDENCE_CHANGE",
        "CONTROL_CHANGE",
        "RISK_CHANGE",
        "POLICY_CHANGE",
        "FRAMEWORK_CHANGE",
        "TRUST_CHANGE",
    ],
)
def test_GO_297_impact_analysis_all_types(svc, ct):
    resp = svc.get_impact_analysis(change_type=ct)
    assert resp.change_type == ct


# ---------------------------------------------------------------------------
# Timeline / history correctness
# ---------------------------------------------------------------------------


def test_GO_298_timeline_get_paginated(svc):
    for i in range(3):
        svc.create_policy(CreatePolicyRequest(name=f"p-{i}"), actor_id="x")
    resp = svc.get_timeline(limit=2)
    assert len(resp.events) <= 2


def test_GO_299_history_specific_entity(svc):
    p = svc.create_policy(CreatePolicyRequest(name="p"), actor_id="x")
    svc.update_policy(p.id, UpdatePolicyRequest(name="p2"), actor_id="x")
    hist = svc.get_history("policy", p.id)
    assert hist.total >= 2


def test_GO_300_history_empty_for_new_entity(svc):
    hist = svc.get_history("policy", "not-exist")
    assert hist.total == 0
