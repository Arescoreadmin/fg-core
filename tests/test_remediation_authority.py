"""Tests for PR 18.3 — Enterprise Remediation Authority (core).

Coverage:
  RA-1   to RA-40:   models.py — enums, constants, immutability sets
  RA-41  to RA-100:  schemas.py — extra=forbid, request/response validation
  RA-101 to RA-160:  repository.py — CRUD, tenant isolation, append-only guards
  RA-161 to RA-220:  engine.py — plans/tasks/statistics/health
  RA-221 to RA-260:  validators.py — input validation
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from sqlalchemy.orm import Session

from api.db import get_engine
from api.db_models_remediation_authority import (
    RemAuthAssignment,
    RemAuthDependency,
    RemAuthEvidenceLink,
    RemAuthPlan,
    RemAuthTask,
    RemAuthTimeline,
    RemAuthVerification,
)
from services.remediation_authority.engine import RemediationAuthorityEngine
from services.remediation_authority.health import build_health
from services.remediation_authority.models import (
    IMMUTABLE_PLAN_STATES,
    IMMUTABLE_TASK_STATES,
    REMEDIATION_AUTHORITY_SCHEMA_VERSION,
    TERMINAL_TASK_STATES,
    AssignmentRole,
    DependencyType,
    RemediationAuthorityDomainError,
    RemediationNotFoundDomainError,
    RemediationPlanState,
    RemediationPriority,
    RemediationTaskState,
    RemediationTenantViolationDomainError,
    RemediationVerificationState,
    SlaStatus,
)
from services.remediation_authority.repository import (
    RemediationAuthorityRepository,
)
from services.remediation_authority.schemas import (
    CreateAssignmentRequest,
    CreateDependencyRequest,
    CreatePlanRequest,
    CreateTaskRequest,
    CreateVerificationRequest,
    DashboardResponse,
    ForecastResponse,
    HealthResponse,
    PlanListResponse,
    PlanResponse,
    RemediationAssignmentError,
    RemediationAuthorityError,
    RemediationConflict,
    RemediationDependencyError,
    RemediationImmutableState,
    RemediationInvalidTransition,
    RemediationNotFound,
    RemediationTenantViolation,
    RemediationValidationError,
    RemediationVerificationError,
    RiskResponse,
    SearchResponse,
    StatisticsResponse,
    TaskListResponse,
    TaskResponse,
    TransitionTaskRequest,
    UpdatePlanRequest,
    UpdateTaskRequest,
)
from services.remediation_authority.validators import (
    validate_horizon_days,
    validate_limit_offset,
    validate_search_query,
    validate_task_id,
    validate_tenant_id,
)


_TENANT = "tenant-ra-001"
_TENANT_B = "tenant-ra-002"


@pytest.fixture()
def db(build_app):
    build_app(auth_enabled=False)
    engine = get_engine()
    with Session(engine) as session:
        yield session


@pytest.fixture()
def svc(db):
    return RemediationAuthorityEngine(db, tenant_id=_TENANT)


@pytest.fixture()
def svc_b(db):
    return RemediationAuthorityEngine(db, tenant_id=_TENANT_B)


@pytest.fixture()
def repo(db):
    return RemediationAuthorityRepository(db, tenant_id=_TENANT)


# ===========================================================================
# RA-1 to RA-40: models.py
# ===========================================================================


@pytest.mark.parametrize(
    "value",
    ["DRAFT", "ACTIVE", "ON_HOLD", "COMPLETED", "CANCELLED", "ARCHIVED"],
)
def test_RA_1_plan_state_values(value):
    assert any(m.value == value for m in RemediationPlanState)


def test_RA_2_plan_state_count():
    assert len(RemediationPlanState) == 6


@pytest.mark.parametrize(
    "value",
    [
        "OPEN",
        "ASSIGNED",
        "IN_PROGRESS",
        "BLOCKED",
        "READY_FOR_REVIEW",
        "VERIFYING",
        "APPROVED",
        "COMPLETED",
        "CANCELLED",
        "REOPENED",
    ],
)
def test_RA_3_task_state_values(value):
    assert any(m.value == value for m in RemediationTaskState)


def test_RA_4_task_state_count():
    assert len(RemediationTaskState) == 10


@pytest.mark.parametrize(
    "value", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
)
def test_RA_5_priority_values(value):
    assert any(m.value == value for m in RemediationPriority)


def test_RA_6_priority_count():
    assert len(RemediationPriority) == 5


@pytest.mark.parametrize(
    "value", ["PENDING", "IN_REVIEW", "APPROVED", "REJECTED", "EXPIRED"]
)
def test_RA_7_verification_state_values(value):
    assert any(m.value == value for m in RemediationVerificationState)


def test_RA_8_verification_state_count():
    assert len(RemediationVerificationState) == 5


@pytest.mark.parametrize("value", ["OWNER", "REVIEWER", "APPROVER", "CONTRIBUTOR"])
def test_RA_9_assignment_role_values(value):
    assert any(m.value == value for m in AssignmentRole)


def test_RA_10_assignment_role_count():
    assert len(AssignmentRole) == 4


@pytest.mark.parametrize("value", ["ON_TRACK", "AT_RISK", "BREACHED", "UNSCHEDULED"])
def test_RA_11_sla_status_values(value):
    assert any(m.value == value for m in SlaStatus)


def test_RA_12_sla_status_count():
    assert len(SlaStatus) == 4


@pytest.mark.parametrize("value", ["BLOCKS", "REQUIRES", "RELATED"])
def test_RA_13_dependency_type_values(value):
    assert any(m.value == value for m in DependencyType)


def test_RA_14_dependency_type_count():
    assert len(DependencyType) == 3


def test_RA_15_schema_version_constant():
    assert REMEDIATION_AUTHORITY_SCHEMA_VERSION == "1.0"


def test_RA_16_immutable_task_states_includes_completed():
    assert RemediationTaskState.COMPLETED in IMMUTABLE_TASK_STATES


def test_RA_17_immutable_task_states_includes_cancelled():
    assert RemediationTaskState.CANCELLED in IMMUTABLE_TASK_STATES


def test_RA_18_terminal_task_states_size():
    assert len(TERMINAL_TASK_STATES) == 2


def test_RA_19_immutable_plan_states_includes_completed():
    assert RemediationPlanState.COMPLETED in IMMUTABLE_PLAN_STATES


def test_RA_20_immutable_plan_states_includes_archived():
    assert RemediationPlanState.ARCHIVED in IMMUTABLE_PLAN_STATES


@pytest.mark.parametrize("member", list(RemediationTaskState))
def test_RA_21_task_state_is_str(member):
    assert isinstance(member.value, str)


@pytest.mark.parametrize("member", list(RemediationPlanState))
def test_RA_22_plan_state_is_str(member):
    assert isinstance(member.value, str)


@pytest.mark.parametrize("member", list(RemediationPriority))
def test_RA_23_priority_is_str(member):
    assert isinstance(member.value, str)


@pytest.mark.parametrize("member", list(AssignmentRole))
def test_RA_24_role_is_str(member):
    assert isinstance(member.value, str)


@pytest.mark.parametrize("member", list(SlaStatus))
def test_RA_25_sla_is_str(member):
    assert isinstance(member.value, str)


@pytest.mark.parametrize("member", list(DependencyType))
def test_RA_26_dependency_type_is_str(member):
    assert isinstance(member.value, str)


def test_RA_27_task_state_enum_lookup_by_value():
    assert RemediationTaskState("OPEN") is RemediationTaskState.OPEN


def test_RA_28_plan_state_enum_lookup_by_value():
    assert RemediationPlanState("DRAFT") is RemediationPlanState.DRAFT


def test_RA_29_task_state_iteration_deterministic():
    assert [m.value for m in RemediationTaskState] == [
        m.value for m in RemediationTaskState
    ]


def test_RA_30_priority_iteration_deterministic():
    assert [m.value for m in RemediationPriority] == [
        m.value for m in RemediationPriority
    ]


def test_RA_31_domain_error_base():
    assert issubclass(RemediationAuthorityDomainError, Exception)


def test_RA_32_domain_not_found_subclass():
    assert issubclass(RemediationNotFoundDomainError, RemediationAuthorityDomainError)


def test_RA_33_domain_tenant_violation_subclass():
    assert issubclass(
        RemediationTenantViolationDomainError, RemediationAuthorityDomainError
    )


def test_RA_34_authority_error_base():
    assert issubclass(RemediationAuthorityError, Exception)


@pytest.mark.parametrize(
    "exc_cls",
    [
        RemediationNotFound,
        RemediationTenantViolation,
        RemediationConflict,
        RemediationInvalidTransition,
        RemediationImmutableState,
        RemediationDependencyError,
        RemediationAssignmentError,
        RemediationVerificationError,
        RemediationValidationError,
    ],
)
def test_RA_35_exception_subclasses(exc_cls):
    assert issubclass(exc_cls, RemediationAuthorityError)


def test_RA_36_completed_is_terminal():
    assert RemediationTaskState.COMPLETED in TERMINAL_TASK_STATES


def test_RA_37_cancelled_is_terminal():
    assert RemediationTaskState.CANCELLED in TERMINAL_TASK_STATES


def test_RA_38_open_is_not_terminal():
    assert RemediationTaskState.OPEN not in TERMINAL_TASK_STATES


def test_RA_39_active_plan_is_mutable():
    assert RemediationPlanState.ACTIVE not in IMMUTABLE_PLAN_STATES


def test_RA_40_draft_plan_is_mutable():
    assert RemediationPlanState.DRAFT not in IMMUTABLE_PLAN_STATES


# ===========================================================================
# RA-41 to RA-100: schemas.py — extra=forbid + request/response
# ===========================================================================


def test_RA_41_create_plan_request_valid():
    req = CreatePlanRequest(title="Plan")
    assert req.title == "Plan"


def test_RA_42_create_plan_request_extra_forbid():
    with pytest.raises(ValidationError):
        CreatePlanRequest(title="P", unknown="x")  # type: ignore[call-arg]


def test_RA_43_create_plan_request_empty_title_rejected():
    with pytest.raises(ValidationError):
        CreatePlanRequest(title="")


def test_RA_44_create_plan_request_long_title_rejected():
    with pytest.raises(ValidationError):
        CreatePlanRequest(title="x" * 513)


def test_RA_45_update_plan_request_partial_ok():
    req = UpdatePlanRequest(title="new title")
    assert req.title == "new title"


def test_RA_46_update_plan_request_extra_forbid():
    with pytest.raises(ValidationError):
        UpdatePlanRequest(title="t", bogus="x")  # type: ignore[call-arg]


def test_RA_47_update_plan_request_plan_state_enum():
    req = UpdatePlanRequest(plan_state=RemediationPlanState.ACTIVE)
    assert req.plan_state == RemediationPlanState.ACTIVE


def test_RA_48_create_task_request_defaults():
    req = CreateTaskRequest(title="T")
    assert req.priority == RemediationPriority.MEDIUM


def test_RA_49_create_task_request_extra_forbid():
    with pytest.raises(ValidationError):
        CreateTaskRequest(title="T", bogus=1)  # type: ignore[call-arg]


def test_RA_50_create_task_request_empty_title_rejected():
    with pytest.raises(ValidationError):
        CreateTaskRequest(title="")


def test_RA_51_create_task_risk_score_lower_bound():
    with pytest.raises(ValidationError):
        CreateTaskRequest(title="T", risk_score=-0.01)


def test_RA_52_create_task_risk_score_upper_bound():
    with pytest.raises(ValidationError):
        CreateTaskRequest(title="T", risk_score=1.5)


def test_RA_53_create_task_risk_score_valid():
    req = CreateTaskRequest(title="T", risk_score=0.5)
    assert req.risk_score == 0.5


def test_RA_54_update_task_extra_forbid():
    with pytest.raises(ValidationError):
        UpdateTaskRequest(title="T", x=1)  # type: ignore[call-arg]


def test_RA_55_update_task_priority_valid():
    req = UpdateTaskRequest(priority=RemediationPriority.HIGH)
    assert req.priority == RemediationPriority.HIGH


def test_RA_56_transition_task_request_extra_forbid():
    with pytest.raises(ValidationError):
        TransitionTaskRequest(to_state=RemediationTaskState.IN_PROGRESS, extra="x")  # type: ignore[call-arg]


def test_RA_57_transition_task_request_missing_state():
    with pytest.raises(ValidationError):
        TransitionTaskRequest()  # type: ignore[call-arg]


def test_RA_58_create_assignment_request_missing_fields():
    with pytest.raises(ValidationError):
        CreateAssignmentRequest(task_id="t")  # type: ignore[call-arg]


def test_RA_59_create_assignment_request_role_enum():
    req = CreateAssignmentRequest(task_id="t", actor_id="a", role=AssignmentRole.OWNER)
    assert req.role == AssignmentRole.OWNER


def test_RA_60_create_dependency_request_default_type():
    req = CreateDependencyRequest(source_task_id="s", target_task_id="t")
    assert req.dependency_type == DependencyType.BLOCKS


def test_RA_61_create_dependency_request_extra_forbid():
    with pytest.raises(ValidationError):
        CreateDependencyRequest(source_task_id="s", target_task_id="t", extra="x")  # type: ignore[call-arg]


def test_RA_62_create_verification_request_default_state():
    req = CreateVerificationRequest(task_id="t", verifier_id="v")
    assert req.verification_state == RemediationVerificationState.IN_REVIEW


def test_RA_63_create_verification_request_extra_forbid():
    with pytest.raises(ValidationError):
        CreateVerificationRequest(task_id="t", verifier_id="v", nope=True)  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "cls",
    [
        CreatePlanRequest,
        UpdatePlanRequest,
        CreateTaskRequest,
        UpdateTaskRequest,
        TransitionTaskRequest,
        CreateAssignmentRequest,
        CreateDependencyRequest,
        CreateVerificationRequest,
    ],
)
def test_RA_64_schemas_extra_forbid_flag(cls):
    assert cls.model_config.get("extra") == "forbid"


@pytest.mark.parametrize(
    "cls",
    [
        PlanResponse,
        PlanListResponse,
        TaskResponse,
        TaskListResponse,
        StatisticsResponse,
        ForecastResponse,
        RiskResponse,
        SearchResponse,
        DashboardResponse,
        HealthResponse,
    ],
)
def test_RA_65_response_schemas_extra_forbid_flag(cls):
    assert cls.model_config.get("extra") == "forbid"


def test_RA_66_plan_response_has_id():
    resp = PlanResponse(
        id="p-1",
        tenant_id=_TENANT,
        title="t",
        description=None,
        plan_state="DRAFT",
        assessment_id=None,
        target_date=None,
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
        completed_at=None,
    )
    assert resp.id == "p-1"


def test_RA_67_plan_list_response_defaults():
    resp = PlanListResponse(items=[], total=0, offset=0, limit=50)
    assert resp.total == 0


def test_RA_68_task_list_response_defaults():
    resp = TaskListResponse(items=[], total=0, offset=0, limit=50)
    assert resp.limit == 50


def test_RA_69_health_response_str_status():
    resp = HealthResponse(
        status="ok",
        authority="x",
        version="v",
        schema_version="1.0",
        checks={},
    )
    assert resp.status == "ok"


def test_RA_70_statistics_response_shape():
    resp = StatisticsResponse(
        tenant_id=_TENANT,
        total_plans=0,
        total_tasks=0,
        by_state={},
        by_priority={},
        by_sla_status={},
        verifications_pending=0,
        verifications_approved=0,
        average_completion_days=None,
        computed_at="2026-01-01T00:00:00Z",
    )
    assert resp.total_plans == 0


def test_RA_71_forecast_response_shape():
    resp = ForecastResponse(
        tenant_id=_TENANT,
        horizon_days=30,
        predicted_completions=0,
        predicted_breaches=0,
        open_task_count=0,
        average_velocity_per_day=0.0,
        computed_at="2026-01-01T00:00:00Z",
    )
    assert resp.horizon_days == 30


def test_RA_72_risk_response_shape():
    resp = RiskResponse(
        tenant_id=_TENANT,
        total_risk_score=1.0,
        open_risk_score=0.5,
        mitigated_risk_score=0.5,
        risk_reduction_pct=50.0,
        by_priority={"HIGH": 1.0},
        computed_at="2026-01-01T00:00:00Z",
    )
    assert resp.risk_reduction_pct == 50.0


def test_RA_73_dashboard_response_shape():
    resp = DashboardResponse(
        tenant_id=_TENANT,
        open_tasks=1,
        in_progress_tasks=0,
        blocked_tasks=0,
        ready_for_review=0,
        completed_tasks=0,
        breached_sla=0,
        at_risk_sla=0,
        upcoming_deadlines=[],
        priority_breakdown={},
        computed_at="2026-01-01T00:00:00Z",
    )
    assert resp.open_tasks == 1


def test_RA_74_search_response_shape():
    resp = SearchResponse(query="q", items=[], total=0)
    assert resp.query == "q"


@pytest.mark.parametrize("title", [""])
def test_RA_75_plan_request_empty_rejected(title):
    with pytest.raises(ValidationError):
        CreatePlanRequest(title=title)


@pytest.mark.parametrize("priority", list(RemediationPriority))
def test_RA_76_task_all_priorities_valid(priority):
    req = CreateTaskRequest(title="T", priority=priority)
    assert req.priority == priority


@pytest.mark.parametrize("role", list(AssignmentRole))
def test_RA_77_assignment_all_roles_valid(role):
    req = CreateAssignmentRequest(task_id="t", actor_id="a", role=role)
    assert req.role == role


@pytest.mark.parametrize("dep_type", list(DependencyType))
def test_RA_78_dependency_all_types_valid(dep_type):
    req = CreateDependencyRequest(
        source_task_id="s", target_task_id="t", dependency_type=dep_type
    )
    assert req.dependency_type == dep_type


@pytest.mark.parametrize("state", list(RemediationTaskState))
def test_RA_79_transition_all_states(state):
    req = TransitionTaskRequest(to_state=state)
    assert req.to_state == state


@pytest.mark.parametrize("state", list(RemediationVerificationState))
def test_RA_80_verification_all_states(state):
    req = CreateVerificationRequest(
        task_id="t", verifier_id="v", verification_state=state
    )
    assert req.verification_state == state


def test_RA_81_update_task_all_none_ok():
    req = UpdateTaskRequest()
    assert req.title is None


def test_RA_82_update_plan_all_none_ok():
    req = UpdatePlanRequest()
    assert req.title is None


def test_RA_83_create_task_finding_id_max_length():
    with pytest.raises(ValidationError):
        CreateTaskRequest(title="t", finding_id="x" * 65)


def test_RA_84_create_task_control_id_max_length():
    with pytest.raises(ValidationError):
        CreateTaskRequest(title="t", control_id="x" * 65)


def test_RA_85_create_task_evidence_id_max_length():
    with pytest.raises(ValidationError):
        CreateTaskRequest(title="t", evidence_id="x" * 65)


def test_RA_86_create_task_owner_id_max_length():
    with pytest.raises(ValidationError):
        CreateTaskRequest(title="t", owner_id="x" * 256)


def test_RA_87_create_task_description_max_length():
    with pytest.raises(ValidationError):
        CreateTaskRequest(title="t", description="x" * 4097)


def test_RA_88_create_plan_description_max_length():
    with pytest.raises(ValidationError):
        CreatePlanRequest(title="t", description="x" * 4097)


def test_RA_89_transition_reason_max_length():
    with pytest.raises(ValidationError):
        TransitionTaskRequest(
            to_state=RemediationTaskState.IN_PROGRESS, reason="x" * 1025
        )


def test_RA_90_verification_notes_max_length():
    with pytest.raises(ValidationError):
        CreateVerificationRequest(task_id="t", verifier_id="v", notes="x" * 2049)


def test_RA_91_plan_response_completed_at_optional():
    resp = PlanResponse(
        id="p",
        tenant_id=_TENANT,
        title="t",
        description=None,
        plan_state="DRAFT",
        assessment_id=None,
        target_date=None,
        created_at="2026-01-01",
        updated_at="2026-01-01",
        completed_at=None,
    )
    assert resp.completed_at is None


def test_RA_92_task_response_risk_score_optional():
    resp = TaskResponse(
        id="t",
        tenant_id=_TENANT,
        plan_id=None,
        title="t",
        description=None,
        task_state="OPEN",
        priority="MEDIUM",
        owner_id=None,
        reviewer_id=None,
        approver_id=None,
        finding_id=None,
        control_id=None,
        evidence_id=None,
        target_date=None,
        risk_score=None,
        sla_status="UNSCHEDULED",
        created_at="2026-01-01",
        updated_at="2026-01-01",
        completed_at=None,
    )
    assert resp.risk_score is None


def test_RA_93_create_assignment_missing_actor_rejected():
    with pytest.raises(ValidationError):
        CreateAssignmentRequest(task_id="t", actor_id="", role=AssignmentRole.OWNER)


def test_RA_94_create_verification_empty_verifier_rejected():
    with pytest.raises(ValidationError):
        CreateVerificationRequest(task_id="t", verifier_id="")


def test_RA_95_create_dependency_empty_source_rejected():
    with pytest.raises(ValidationError):
        CreateDependencyRequest(source_task_id="", target_task_id="t")


def test_RA_96_create_dependency_empty_target_rejected():
    with pytest.raises(ValidationError):
        CreateDependencyRequest(source_task_id="s", target_task_id="")


def test_RA_97_health_response_authority_str():
    resp = build_health(db_ok=True)
    assert resp.authority == "remediation_authority"


def test_RA_98_health_response_ok():
    assert build_health(db_ok=True).status == "ok"


def test_RA_99_health_response_degraded():
    assert build_health(db_ok=False).status == "degraded"


def test_RA_100_health_response_schema_version():
    assert build_health(db_ok=True).schema_version == "1.0"


# ===========================================================================
# RA-101 to RA-160: repository.py — CRUD + tenant isolation
# ===========================================================================


def test_RA_101_create_plan_persists(db, repo):
    row = repo.create_plan(title="P1")
    db.commit()
    assert row.tenant_id == _TENANT
    assert row.plan_state == "DRAFT"


def test_RA_102_get_plan_none_when_missing(repo):
    assert repo.get_plan("missing-id") is None


def test_RA_103_get_plan_returns_row(db, repo):
    row = repo.create_plan(title="P")
    db.commit()
    got = repo.get_plan(row.id)
    assert got is not None and got.id == row.id


def test_RA_104_plan_tenant_isolation(db):
    repo_a = RemediationAuthorityRepository(db, tenant_id=_TENANT)
    repo_b = RemediationAuthorityRepository(db, tenant_id=_TENANT_B)
    row = repo_a.create_plan(title="P")
    db.commit()
    assert repo_a.get_plan(row.id) is not None
    assert repo_b.get_plan(row.id) is None


def test_RA_105_list_plans_default(db, repo):
    for i in range(3):
        repo.create_plan(title=f"P-{i}")
    db.commit()
    items, total = repo.list_plans(offset=0, limit=50)
    assert total >= 3


def test_RA_106_list_plans_pagination(db, repo):
    for i in range(5):
        repo.create_plan(title=f"P-{i}")
    db.commit()
    items, total = repo.list_plans(offset=0, limit=2)
    assert len(items) == 2


def test_RA_107_list_plans_filter_state(db, repo):
    repo.create_plan(title="A", plan_state="ACTIVE")
    repo.create_plan(title="B", plan_state="DRAFT")
    db.commit()
    items, total = repo.list_plans(plan_state="ACTIVE", offset=0, limit=10)
    assert all(i.plan_state == "ACTIVE" for i in items)


def test_RA_108_create_task_persists(db, repo):
    task = repo.create_task(title="T")
    db.commit()
    assert task.tenant_id == _TENANT
    assert task.task_state == "OPEN"


def test_RA_109_create_task_with_plan(db, repo):
    plan = repo.create_plan(title="P")
    db.commit()
    task = repo.create_task(title="T", plan_id=plan.id)
    db.commit()
    assert task.plan_id == plan.id


def test_RA_110_task_tenant_isolation(db):
    repo_a = RemediationAuthorityRepository(db, tenant_id=_TENANT)
    repo_b = RemediationAuthorityRepository(db, tenant_id=_TENANT_B)
    task = repo_a.create_task(title="T")
    db.commit()
    assert repo_a.get_task(task.id) is not None
    assert repo_b.get_task(task.id) is None


def test_RA_111_list_tasks_filter_state(db, repo):
    repo.create_task(title="A", task_state="OPEN")
    repo.create_task(title="B", task_state="IN_PROGRESS")
    db.commit()
    items, _ = repo.list_tasks(task_state="OPEN", offset=0, limit=50)
    assert all(t.task_state == "OPEN" for t in items)


def test_RA_112_list_tasks_filter_priority(db, repo):
    repo.create_task(title="A", priority="HIGH")
    repo.create_task(title="B", priority="LOW")
    db.commit()
    items, _ = repo.list_tasks(priority="HIGH", offset=0, limit=50)
    assert all(t.priority == "HIGH" for t in items)


def test_RA_113_list_tasks_filter_owner(db, repo):
    repo.create_task(title="A", owner_id="alice")
    repo.create_task(title="B", owner_id="bob")
    db.commit()
    items, _ = repo.list_tasks(owner_id="alice", offset=0, limit=50)
    assert all(t.owner_id == "alice" for t in items)


def test_RA_114_append_timeline_persists(db, repo):
    task = repo.create_task(title="T")
    db.commit()
    row = repo.append_timeline(
        task_id=task.id,
        event_type="task_created",
        from_state=None,
        to_state="OPEN",
        actor_id="u",
        reason=None,
    )
    db.commit()
    assert row.event_type == "task_created"


def test_RA_115_list_timeline_ordered_by_created(db, repo):
    task = repo.create_task(title="T")
    db.commit()
    for et in ("e1", "e2", "e3"):
        repo.append_timeline(
            task_id=task.id,
            event_type=et,
            from_state=None,
            to_state=None,
            actor_id=None,
            reason=None,
        )
    db.commit()
    rows = repo.list_timeline(task.id)
    assert [r.event_type for r in rows] == ["e1", "e2", "e3"]


def test_RA_116_timeline_update_blocked(db, repo):
    task = repo.create_task(title="T")
    db.commit()
    row = repo.append_timeline(
        task_id=task.id,
        event_type="e",
        from_state=None,
        to_state=None,
        actor_id=None,
        reason=None,
    )
    db.commit()
    row.event_type = "hacked"
    with pytest.raises(RuntimeError, match="append-only"):
        db.commit()
    db.rollback()


def test_RA_117_timeline_delete_blocked(db, repo):
    task = repo.create_task(title="T")
    db.commit()
    row = repo.append_timeline(
        task_id=task.id,
        event_type="e",
        from_state=None,
        to_state=None,
        actor_id=None,
        reason=None,
    )
    db.commit()
    db.delete(row)
    with pytest.raises(RuntimeError, match="append-only"):
        db.commit()
    db.rollback()


def test_RA_118_create_assignment_persists(db, repo):
    task = repo.create_task(title="T")
    db.commit()
    row = repo.create_assignment(task_id=task.id, actor_id="u1", role="OWNER")
    db.commit()
    assert row.role == "OWNER"


def test_RA_119_list_assignments_filter_task(db, repo):
    t1 = repo.create_task(title="A")
    t2 = repo.create_task(title="B")
    db.commit()
    repo.create_assignment(task_id=t1.id, actor_id="u", role="OWNER")
    repo.create_assignment(task_id=t2.id, actor_id="u", role="OWNER")
    db.commit()
    rows = repo.list_assignments(task_id=t1.id)
    assert all(a.task_id == t1.id for a in rows)


def test_RA_120_create_dependency_persists(db, repo):
    t1 = repo.create_task(title="A")
    t2 = repo.create_task(title="B")
    db.commit()
    row = repo.create_dependency(
        source_task_id=t1.id, target_task_id=t2.id, dependency_type="BLOCKS"
    )
    db.commit()
    assert row.dependency_type == "BLOCKS"


def test_RA_121_list_dependencies_returns_all(db, repo):
    t1 = repo.create_task(title="A")
    t2 = repo.create_task(title="B")
    t3 = repo.create_task(title="C")
    db.commit()
    repo.create_dependency(
        source_task_id=t1.id, target_task_id=t2.id, dependency_type="BLOCKS"
    )
    repo.create_dependency(
        source_task_id=t2.id, target_task_id=t3.id, dependency_type="BLOCKS"
    )
    db.commit()
    assert len(repo.list_dependencies()) >= 2


def test_RA_122_delete_dependency(db, repo):
    t1 = repo.create_task(title="A")
    t2 = repo.create_task(title="B")
    db.commit()
    dep = repo.create_dependency(
        source_task_id=t1.id, target_task_id=t2.id, dependency_type="BLOCKS"
    )
    db.commit()
    assert repo.delete_dependency(dep.id) is True
    db.commit()
    assert repo.get_dependency(dep.id) is None


def test_RA_123_delete_dependency_missing_returns_false(repo):
    assert repo.delete_dependency("missing") is False


def test_RA_124_create_verification_persists(db, repo):
    t = repo.create_task(title="A")
    db.commit()
    row = repo.create_verification(
        task_id=t.id,
        verifier_id="v",
        verification_state="APPROVED",
        evidence_id=None,
        notes=None,
    )
    db.commit()
    assert row.verification_state == "APPROVED"


def test_RA_125_list_verifications_filter_task(db, repo):
    t1 = repo.create_task(title="A")
    t2 = repo.create_task(title="B")
    db.commit()
    repo.create_verification(
        task_id=t1.id,
        verifier_id="v",
        verification_state="APPROVED",
        evidence_id=None,
        notes=None,
    )
    repo.create_verification(
        task_id=t2.id,
        verifier_id="v",
        verification_state="APPROVED",
        evidence_id=None,
        notes=None,
    )
    db.commit()
    rows = repo.list_verifications(task_id=t1.id)
    assert all(v.task_id == t1.id for v in rows)


def test_RA_126_create_evidence_link_persists(db, repo):
    t = repo.create_task(title="A")
    db.commit()
    row = repo.create_evidence_link(task_id=t.id, evidence_id="e1")
    db.commit()
    assert row.evidence_id == "e1"


def test_RA_127_update_plan_touches_updated_at(db, repo):
    plan = repo.create_plan(title="P")
    db.commit()
    old = plan.updated_at
    plan.title = "P2"
    repo.update_plan(plan)
    db.commit()
    assert plan.updated_at >= old


def test_RA_128_update_task_touches_updated_at(db, repo):
    task = repo.create_task(title="T")
    db.commit()
    old = task.updated_at
    task.title = "T2"
    repo.update_task(task)
    db.commit()
    assert task.updated_at >= old


def test_RA_129_all_tasks_returns_only_tenant_rows(db):
    repo_a = RemediationAuthorityRepository(db, tenant_id=_TENANT)
    repo_b = RemediationAuthorityRepository(db, tenant_id=_TENANT_B)
    repo_a.create_task(title="A1")
    repo_b.create_task(title="B1")
    db.commit()
    a_rows = repo_a.all_tasks()
    b_rows = repo_b.all_tasks()
    assert all(r.tenant_id == _TENANT for r in a_rows)
    assert all(r.tenant_id == _TENANT_B for r in b_rows)


def test_RA_130_search_tasks_matches_title(db, repo):
    repo.create_task(title="widget audit")
    repo.create_task(title="other")
    db.commit()
    items, total = repo.search_tasks("widget", offset=0, limit=10)
    assert all("widget" in (t.title or "").lower() for t in items)


@pytest.mark.parametrize("i", range(1, 21))
def test_RA_131_bulk_plans_persist(db, repo, i):
    row = repo.create_plan(title=f"BulkPlan-{i}")
    db.commit()
    assert row.title == f"BulkPlan-{i}"


@pytest.mark.parametrize("i", range(1, 21))
def test_RA_132_bulk_tasks_persist(db, repo, i):
    row = repo.create_task(title=f"BulkTask-{i}")
    db.commit()
    assert row.title == f"BulkTask-{i}"


def test_RA_133_repository_never_leaks_other_tenants_plans(db):
    a = RemediationAuthorityRepository(db, tenant_id="t-r-1")
    b = RemediationAuthorityRepository(db, tenant_id="t-r-2")
    a.create_plan(title="A1")
    b.create_plan(title="B1")
    db.commit()
    a_items, _ = a.list_plans(offset=0, limit=50)
    b_items, _ = b.list_plans(offset=0, limit=50)
    assert all(r.tenant_id == "t-r-1" for r in a_items)
    assert all(r.tenant_id == "t-r-2" for r in b_items)


def test_RA_134_repository_never_leaks_other_tenants_tasks(db):
    a = RemediationAuthorityRepository(db, tenant_id="t-r-3")
    b = RemediationAuthorityRepository(db, tenant_id="t-r-4")
    a.create_task(title="A1")
    b.create_task(title="B1")
    db.commit()
    a_items, _ = a.list_tasks(offset=0, limit=50)
    b_items, _ = b.list_tasks(offset=0, limit=50)
    assert all(r.tenant_id == "t-r-3" for r in a_items)
    assert all(r.tenant_id == "t-r-4" for r in b_items)


def test_RA_135_repository_never_leaks_dependencies(db):
    a = RemediationAuthorityRepository(db, tenant_id="t-r-5")
    b = RemediationAuthorityRepository(db, tenant_id="t-r-6")
    t1 = a.create_task(title="A1")
    t2 = a.create_task(title="A2")
    db.commit()
    a.create_dependency(
        source_task_id=t1.id, target_task_id=t2.id, dependency_type="BLOCKS"
    )
    db.commit()
    assert b.list_dependencies() == []


def test_RA_136_repository_never_leaks_verifications(db):
    a = RemediationAuthorityRepository(db, tenant_id="t-r-7")
    b = RemediationAuthorityRepository(db, tenant_id="t-r-8")
    t = a.create_task(title="A")
    db.commit()
    a.create_verification(
        task_id=t.id,
        verifier_id="v",
        verification_state="APPROVED",
        evidence_id=None,
        notes=None,
    )
    db.commit()
    assert b.list_verifications() == []


def test_RA_137_orm_plan_has_tenant_index():
    assert "tenant_id" in {c.name for c in RemAuthPlan.__table__.columns}


def test_RA_138_orm_task_has_tenant_index():
    assert "tenant_id" in {c.name for c in RemAuthTask.__table__.columns}


def test_RA_139_orm_timeline_has_tenant_index():
    assert "tenant_id" in {c.name for c in RemAuthTimeline.__table__.columns}


def test_RA_140_orm_assignment_has_tenant():
    assert "tenant_id" in {c.name for c in RemAuthAssignment.__table__.columns}


def test_RA_141_orm_dependency_has_tenant():
    assert "tenant_id" in {c.name for c in RemAuthDependency.__table__.columns}


def test_RA_142_orm_verification_has_tenant():
    assert "tenant_id" in {c.name for c in RemAuthVerification.__table__.columns}


def test_RA_143_orm_evidence_link_has_tenant():
    assert "tenant_id" in {c.name for c in RemAuthEvidenceLink.__table__.columns}


def test_RA_144_orm_task_state_default_open():
    assert RemAuthTask.__table__.c.task_state.default.arg == "OPEN"


def test_RA_145_orm_plan_state_default_draft():
    assert RemAuthPlan.__table__.c.plan_state.default.arg == "DRAFT"


def test_RA_146_orm_priority_default_medium():
    assert RemAuthTask.__table__.c.priority.default.arg == "MEDIUM"


def test_RA_147_orm_verification_state_default_pending():
    assert RemAuthVerification.__table__.c.verification_state.default.arg == "PENDING"


def test_RA_148_orm_dependency_type_default_blocks():
    assert RemAuthDependency.__table__.c.dependency_type.default.arg == "BLOCKS"


def test_RA_149_orm_sla_status_default_unscheduled():
    assert RemAuthTask.__table__.c.sla_status.default.arg == "UNSCHEDULED"


def test_RA_150_orm_task_id_primary():
    assert RemAuthTask.__table__.c.id.primary_key is True


def test_RA_151_orm_plan_id_primary():
    assert RemAuthPlan.__table__.c.id.primary_key is True


def test_RA_152_orm_timeline_id_primary():
    assert RemAuthTimeline.__table__.c.id.primary_key is True


def test_RA_153_orm_assignment_id_primary():
    assert RemAuthAssignment.__table__.c.id.primary_key is True


def test_RA_154_orm_dependency_id_primary():
    assert RemAuthDependency.__table__.c.id.primary_key is True


def test_RA_155_orm_verification_id_primary():
    assert RemAuthVerification.__table__.c.id.primary_key is True


def test_RA_156_orm_evidence_link_id_primary():
    assert RemAuthEvidenceLink.__table__.c.id.primary_key is True


def test_RA_157_orm_tenant_not_nullable():
    assert RemAuthTask.__table__.c.tenant_id.nullable is False


def test_RA_158_orm_task_title_not_nullable():
    assert RemAuthTask.__table__.c.title.nullable is False


def test_RA_159_orm_plan_title_not_nullable():
    assert RemAuthPlan.__table__.c.title.nullable is False


def test_RA_160_orm_timeline_task_id_not_nullable():
    assert RemAuthTimeline.__table__.c.task_id.nullable is False


# ===========================================================================
# RA-161 to RA-220: engine.py — plans, tasks, statistics, health
# ===========================================================================


def test_RA_161_engine_health_ok(svc):
    r = svc.health()
    assert r.status == "ok"


def test_RA_162_engine_health_returns_schema(svc):
    r = svc.health()
    assert isinstance(r, HealthResponse)


def test_RA_163_engine_create_plan(svc):
    r = svc.create_plan(CreatePlanRequest(title="P"), actor_id="u")
    assert r.title == "P"
    assert r.plan_state == "DRAFT"


def test_RA_164_engine_get_plan_missing(svc):
    with pytest.raises(RemediationNotFound):
        svc.get_plan("missing")


def test_RA_165_engine_get_plan_found(svc, db):
    p = svc.create_plan(CreatePlanRequest(title="P"), actor_id="u")
    db.commit()
    assert svc.get_plan(p.id).id == p.id


def test_RA_166_engine_list_plans_empty(svc):
    r = svc.list_plans()
    assert isinstance(r, PlanListResponse)


def test_RA_167_engine_list_plans_populated(svc, db):
    for i in range(3):
        svc.create_plan(CreatePlanRequest(title=f"P-{i}"), actor_id="u")
    db.commit()
    r = svc.list_plans(limit=50, offset=0)
    assert r.total >= 3


def test_RA_168_engine_update_plan_title(svc, db):
    p = svc.create_plan(CreatePlanRequest(title="P"), actor_id="u")
    db.commit()
    r = svc.update_plan(p.id, UpdatePlanRequest(title="P2"), actor_id="u")
    assert r.title == "P2"


def test_RA_169_engine_update_plan_state_transition(svc, db):
    p = svc.create_plan(CreatePlanRequest(title="P"), actor_id="u")
    db.commit()
    r = svc.update_plan(
        p.id,
        UpdatePlanRequest(plan_state=RemediationPlanState.ACTIVE),
        actor_id="u",
    )
    assert r.plan_state == RemediationPlanState.ACTIVE.value


def test_RA_170_engine_update_plan_invalid_transition(svc, db):
    p = svc.create_plan(CreatePlanRequest(title="P"), actor_id="u")
    db.commit()
    with pytest.raises(RemediationInvalidTransition):
        svc.update_plan(
            p.id,
            UpdatePlanRequest(plan_state=RemediationPlanState.ARCHIVED),
            actor_id="u",
        )


def test_RA_171_engine_update_plan_immutable_after_completed(svc, db):
    p = svc.create_plan(CreatePlanRequest(title="P"), actor_id="u")
    svc.update_plan(
        p.id,
        UpdatePlanRequest(plan_state=RemediationPlanState.ACTIVE),
        actor_id="u",
    )
    svc.update_plan(
        p.id,
        UpdatePlanRequest(plan_state=RemediationPlanState.COMPLETED),
        actor_id="u",
    )
    db.commit()
    with pytest.raises(RemediationImmutableState):
        svc.update_plan(p.id, UpdatePlanRequest(title="X"), actor_id="u")


def test_RA_172_engine_update_plan_missing_raises(svc):
    with pytest.raises(RemediationNotFound):
        svc.update_plan("missing", UpdatePlanRequest(title="X"), actor_id="u")


def test_RA_173_engine_create_task(svc):
    r = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    assert r.title == "T"
    assert r.task_state == "OPEN"


def test_RA_174_engine_create_task_with_plan(svc, db):
    p = svc.create_plan(CreatePlanRequest(title="P"), actor_id="u")
    db.commit()
    r = svc.create_task(CreateTaskRequest(title="T", plan_id=p.id), actor_id="u")
    assert r.plan_id == p.id


def test_RA_175_engine_create_task_with_missing_plan_raises(svc):
    with pytest.raises(RemediationNotFound):
        svc.create_task(CreateTaskRequest(title="T", plan_id="missing"), actor_id="u")


def test_RA_176_engine_create_task_records_timeline(svc, db):
    t = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    db.commit()
    tl = svc.get_timeline(t.id)
    assert any(e.event_type == "task_created" for e in tl.events)


def test_RA_177_engine_get_task_missing(svc):
    with pytest.raises(RemediationNotFound):
        svc.get_task("missing")


def test_RA_178_engine_list_tasks_empty(svc):
    r = svc.list_tasks()
    assert isinstance(r, TaskListResponse)


def test_RA_179_engine_list_tasks_filter_priority(svc, db):
    svc.create_task(
        CreateTaskRequest(title="A", priority=RemediationPriority.HIGH),
        actor_id="u",
    )
    svc.create_task(
        CreateTaskRequest(title="B", priority=RemediationPriority.LOW),
        actor_id="u",
    )
    db.commit()
    r = svc.list_tasks(priority="HIGH")
    assert all(t.priority == "HIGH" for t in r.items)


def test_RA_180_engine_update_task_immutable_after_completed(svc, db):
    t = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    # OPEN -> IN_PROGRESS -> READY_FOR_REVIEW -> VERIFYING -> APPROVED -> COMPLETED
    for target in (
        RemediationTaskState.IN_PROGRESS,
        RemediationTaskState.READY_FOR_REVIEW,
        RemediationTaskState.VERIFYING,
        RemediationTaskState.APPROVED,
        RemediationTaskState.COMPLETED,
    ):
        svc.transition_task(t.id, TransitionTaskRequest(to_state=target), actor_id="u")
    db.commit()
    with pytest.raises(RemediationImmutableState):
        svc.update_task(t.id, UpdateTaskRequest(title="X"), actor_id="u")


def test_RA_181_engine_update_task_missing_raises(svc):
    with pytest.raises(RemediationNotFound):
        svc.update_task("missing", UpdateTaskRequest(title="X"), actor_id="u")


def test_RA_182_engine_update_task_changes_priority(svc, db):
    t = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    db.commit()
    r = svc.update_task(
        t.id, UpdateTaskRequest(priority=RemediationPriority.HIGH), actor_id="u"
    )
    assert r.priority == "HIGH"


def test_RA_183_engine_transition_task_open_to_in_progress(svc, db):
    t = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    db.commit()
    r = svc.transition_task(
        t.id,
        TransitionTaskRequest(to_state=RemediationTaskState.IN_PROGRESS),
        actor_id="u",
    )
    assert r.task_state == "IN_PROGRESS"


def test_RA_184_engine_transition_task_invalid_raises(svc, db):
    t = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    db.commit()
    with pytest.raises(RemediationInvalidTransition):
        svc.transition_task(
            t.id,
            TransitionTaskRequest(to_state=RemediationTaskState.APPROVED),
            actor_id="u",
        )


def test_RA_185_engine_transition_task_missing_raises(svc):
    with pytest.raises(RemediationNotFound):
        svc.transition_task(
            "missing",
            TransitionTaskRequest(to_state=RemediationTaskState.IN_PROGRESS),
            actor_id="u",
        )


def test_RA_186_engine_transition_task_completed_sets_completed_at(svc, db):
    t = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    for target in (
        RemediationTaskState.IN_PROGRESS,
        RemediationTaskState.READY_FOR_REVIEW,
        RemediationTaskState.VERIFYING,
        RemediationTaskState.APPROVED,
        RemediationTaskState.COMPLETED,
    ):
        t = svc.transition_task(
            t.id, TransitionTaskRequest(to_state=target), actor_id="u"
        )
    db.commit()
    assert t.completed_at is not None


def test_RA_187_engine_timeline_missing_task_raises(svc):
    with pytest.raises(RemediationNotFound):
        svc.get_timeline("missing")


def test_RA_188_engine_history_missing_task_raises(svc):
    with pytest.raises(RemediationNotFound):
        svc.get_history("missing")


def test_RA_189_engine_history_returns_events(svc, db):
    t = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    svc.transition_task(
        t.id,
        TransitionTaskRequest(to_state=RemediationTaskState.IN_PROGRESS),
        actor_id="u",
    )
    db.commit()
    r = svc.get_history(t.id)
    assert r.total >= 1


def test_RA_190_engine_get_statistics_shape(svc, db):
    svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    db.commit()
    r = svc.get_statistics()
    assert isinstance(r, StatisticsResponse)
    assert r.total_tasks >= 1


def test_RA_191_engine_get_forecast_horizon(svc):
    r = svc.get_forecast(horizon_days=30)
    assert r.horizon_days == 30


def test_RA_192_engine_get_forecast_invalid_horizon_raises(svc):
    with pytest.raises(RemediationValidationError):
        svc.get_forecast(horizon_days=0)


def test_RA_193_engine_get_risk_response(svc):
    r = svc.get_risk()
    assert isinstance(r, RiskResponse)
    assert 0 <= r.risk_reduction_pct <= 100


def test_RA_194_engine_get_dashboard(svc, db):
    svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    db.commit()
    r = svc.get_dashboard()
    assert isinstance(r, DashboardResponse)


def test_RA_195_engine_search_missing_query(svc):
    with pytest.raises(RemediationValidationError):
        svc.search_tasks("")


def test_RA_196_engine_search_ok(svc, db):
    svc.create_task(CreateTaskRequest(title="widget review"), actor_id="u")
    db.commit()
    r = svc.search_tasks("widget")
    assert isinstance(r, SearchResponse)


def test_RA_197_engine_tenant_isolation_reads(db):
    a = RemediationAuthorityEngine(db, tenant_id="t-r-9")
    b = RemediationAuthorityEngine(db, tenant_id="t-r-10")
    a.create_task(CreateTaskRequest(title="A"), actor_id="u")
    db.commit()
    r = b.list_tasks()
    assert r.total == 0


def test_RA_198_engine_empty_tenant_rejected(db):
    with pytest.raises(RemediationTenantViolation):
        RemediationAuthorityEngine(db, tenant_id="")


def test_RA_199_engine_whitespace_tenant_rejected(db):
    with pytest.raises(RemediationTenantViolation):
        RemediationAuthorityEngine(db, tenant_id="   ")


def test_RA_200_engine_valid_tenant_ok(db):
    e = RemediationAuthorityEngine(db, tenant_id="t-r-11")
    assert e is not None


@pytest.mark.parametrize("priority", list(RemediationPriority))
def test_RA_201_engine_task_all_priorities(svc, priority):
    r = svc.create_task(
        CreateTaskRequest(title=f"T-{priority.value}", priority=priority),
        actor_id="u",
    )
    assert r.priority == priority.value


def test_RA_202_engine_task_default_sla_unscheduled(svc):
    r = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    assert r.sla_status == "UNSCHEDULED"


def test_RA_203_engine_task_with_target_sla_on_track(svc):
    r = svc.create_task(
        CreateTaskRequest(title="T", target_date="2099-12-31T00:00:00Z"),
        actor_id="u",
    )
    assert r.sla_status in ("ON_TRACK", "AT_RISK")


def test_RA_204_engine_task_target_in_past_breached(svc):
    r = svc.create_task(
        CreateTaskRequest(title="T", target_date="2000-01-01T00:00:00Z"),
        actor_id="u",
    )
    assert r.sla_status == "BREACHED"


def test_RA_205_engine_update_task_target_date_recomputes_sla(svc, db):
    r = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    db.commit()
    updated = svc.update_task(
        r.id,
        UpdateTaskRequest(target_date="2099-12-31T00:00:00Z"),
        actor_id="u",
    )
    assert updated.sla_status in ("ON_TRACK", "AT_RISK")


@pytest.mark.parametrize("i", range(1, 21))
def test_RA_206_engine_bulk_plan_creation(svc, db, i):
    r = svc.create_plan(CreatePlanRequest(title=f"BP-{i}"), actor_id="u")
    db.commit()
    assert r.title == f"BP-{i}"


@pytest.mark.parametrize("i", range(1, 21))
def test_RA_207_engine_bulk_task_creation(svc, db, i):
    r = svc.create_task(CreateTaskRequest(title=f"BT-{i}"), actor_id="u")
    db.commit()
    assert r.title == f"BT-{i}"


def test_RA_208_engine_verification_missing_task_raises(svc):
    with pytest.raises(RemediationNotFound):
        svc.create_verification(
            CreateVerificationRequest(task_id="missing", verifier_id="v"),
            actor_id="u",
        )


def test_RA_209_engine_assignment_missing_task_raises(svc):
    with pytest.raises(RemediationNotFound):
        svc.create_assignment(
            CreateAssignmentRequest(
                task_id="missing", actor_id="a", role=AssignmentRole.OWNER
            ),
            actor_id="u",
        )


def test_RA_210_engine_dependency_missing_source_raises(svc, db):
    t = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    db.commit()
    with pytest.raises(RemediationNotFound):
        svc.create_dependency(
            CreateDependencyRequest(source_task_id="missing", target_task_id=t.id),
            actor_id="u",
        )


def test_RA_211_engine_dependency_missing_target_raises(svc, db):
    t = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    db.commit()
    with pytest.raises(RemediationNotFound):
        svc.create_dependency(
            CreateDependencyRequest(source_task_id=t.id, target_task_id="missing"),
            actor_id="u",
        )


def test_RA_212_engine_dependency_self_raises(svc, db):
    t = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    db.commit()
    with pytest.raises(RemediationDependencyError):
        svc.create_dependency(
            CreateDependencyRequest(source_task_id=t.id, target_task_id=t.id),
            actor_id="u",
        )


def test_RA_213_engine_delete_dependency_missing_raises(svc):
    with pytest.raises(RemediationNotFound):
        svc.delete_dependency("missing", actor_id="u")


def test_RA_214_engine_critical_path_empty(svc):
    assert svc.critical_path() == []


def test_RA_215_engine_dependents_of_empty(svc):
    assert svc.dependents_of("missing") == []


def test_RA_216_engine_forecast_shape(svc):
    r = svc.get_forecast(horizon_days=30)
    assert r.open_task_count >= 0


def test_RA_217_engine_risk_shape(svc):
    r = svc.get_risk()
    assert r.total_risk_score >= 0


def test_RA_218_engine_search_pagination(svc, db):
    for i in range(3):
        svc.create_task(CreateTaskRequest(title=f"searchme-{i}"), actor_id="u")
    db.commit()
    r = svc.search_tasks("searchme", limit=2, offset=0)
    assert len(r.items) <= 2


def test_RA_219_engine_dashboard_upcoming_limit(svc, db):
    for i in range(10):
        svc.create_task(
            CreateTaskRequest(title=f"T-{i}", target_date="2099-12-31T00:00:00Z"),
            actor_id="u",
        )
    db.commit()
    r = svc.get_dashboard()
    assert len(r.upcoming_deadlines) <= 5


def test_RA_220_engine_statistics_verifications_pending(svc, db):
    t = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    svc.create_verification(
        CreateVerificationRequest(
            task_id=t.id,
            verifier_id="v",
            verification_state=RemediationVerificationState.PENDING,
        ),
        actor_id="u",
    )
    db.commit()
    r = svc.get_statistics()
    assert r.verifications_pending >= 1


# ===========================================================================
# RA-221 to RA-260: validators
# ===========================================================================


@pytest.mark.parametrize("tid", ["", "   ", "\t"])
def test_RA_221_validate_tenant_id_rejects_empty(tid):
    with pytest.raises(RemediationTenantViolation):
        validate_tenant_id(tid)


@pytest.mark.parametrize("tid", ["t", "tenant-1", "abc-123"])
def test_RA_222_validate_tenant_id_accepts(tid):
    validate_tenant_id(tid)


@pytest.mark.parametrize("limit", [0, -1, 501, 1000])
def test_RA_223_validate_limit_offset_rejects_bad_limit(limit):
    with pytest.raises(RemediationValidationError):
        validate_limit_offset(limit, 0)


def test_RA_224_validate_limit_offset_rejects_negative_offset():
    with pytest.raises(RemediationValidationError):
        validate_limit_offset(50, -1)


@pytest.mark.parametrize("limit,offset", [(1, 0), (50, 0), (500, 1000)])
def test_RA_225_validate_limit_offset_accepts(limit, offset):
    validate_limit_offset(limit, offset)


@pytest.mark.parametrize("q", ["", "   "])
def test_RA_226_validate_search_query_rejects_empty(q):
    with pytest.raises(RemediationValidationError):
        validate_search_query(q)


def test_RA_227_validate_search_query_rejects_long():
    with pytest.raises(RemediationValidationError):
        validate_search_query("x" * 513)


def test_RA_228_validate_search_query_accepts():
    validate_search_query("q")


@pytest.mark.parametrize("h", [0, -1, 366, 1000])
def test_RA_229_validate_horizon_rejects_bad(h):
    with pytest.raises(RemediationValidationError):
        validate_horizon_days(h)


@pytest.mark.parametrize("h", [1, 30, 90, 365])
def test_RA_230_validate_horizon_accepts(h):
    validate_horizon_days(h)


@pytest.mark.parametrize("tid", ["", " "])
def test_RA_231_validate_task_id_rejects_empty(tid):
    with pytest.raises(RemediationValidationError):
        validate_task_id(tid)


def test_RA_232_validate_task_id_accepts():
    validate_task_id("t")


@pytest.mark.parametrize("q", ["a", "hello world", "x" * 512])
def test_RA_233_validate_search_query_valid_range(q):
    validate_search_query(q)


@pytest.mark.parametrize("lim", [1, 50, 100, 500])
def test_RA_234_validate_limit_all_valid(lim):
    validate_limit_offset(lim, 0)


@pytest.mark.parametrize("o", [0, 1, 100, 1000])
def test_RA_235_validate_offset_all_valid(o):
    validate_limit_offset(50, o)


def test_RA_236_validate_search_whitespace_only_rejected():
    with pytest.raises(RemediationValidationError):
        validate_search_query("    ")


def test_RA_237_validate_search_boundary_512():
    validate_search_query("x" * 512)


def test_RA_238_validate_search_513_rejected():
    with pytest.raises(RemediationValidationError):
        validate_search_query("x" * 513)


def test_RA_239_validate_horizon_1_accepted():
    validate_horizon_days(1)


def test_RA_240_validate_horizon_365_accepted():
    validate_horizon_days(365)


def test_RA_241_validate_horizon_366_rejected():
    with pytest.raises(RemediationValidationError):
        validate_horizon_days(366)


@pytest.mark.parametrize(
    "fn,args",
    [
        (validate_tenant_id, ("",)),
        (validate_search_query, ("",)),
        (validate_limit_offset, (-1, 0)),
        (validate_limit_offset, (50, -5)),
        (validate_horizon_days, (0,)),
        (validate_task_id, ("",)),
    ],
)
def test_RA_242_validator_failure_modes(fn, args):
    with pytest.raises(Exception):
        fn(*args)


def test_RA_243_health_response_authority_string(svc):
    assert svc.health().authority == "remediation_authority"


def test_RA_244_forecast_zero_tasks(svc):
    r = svc.get_forecast(horizon_days=30)
    assert r.predicted_completions == 0


def test_RA_245_risk_zero_tasks(svc):
    r = svc.get_risk()
    assert r.total_risk_score == 0.0


def test_RA_246_dashboard_zero_tasks(svc):
    r = svc.get_dashboard()
    assert r.open_tasks == 0


def test_RA_247_stats_zero_tasks(svc):
    r = svc.get_statistics()
    assert r.total_tasks == 0


def test_RA_248_search_no_matches(svc):
    r = svc.search_tasks("no-match-query-xyz")
    assert r.total == 0


def test_RA_249_list_plans_empty_response_type(svc):
    assert isinstance(svc.list_plans(), PlanListResponse)


def test_RA_250_list_tasks_empty_response_type(svc):
    assert isinstance(svc.list_tasks(), TaskListResponse)


def test_RA_251_list_assignments_empty(svc):
    r = svc.list_assignments()
    assert r.total == 0


def test_RA_252_list_dependencies_empty(svc):
    r = svc.list_dependencies()
    assert r.total == 0


def test_RA_253_list_verifications_empty(svc):
    r = svc.list_verifications()
    assert r.total == 0


def test_RA_254_health_authority_static():
    assert build_health(True).authority == "remediation_authority"


def test_RA_255_health_version_semver_ish():
    parts = build_health(True).version.split(".")
    assert len(parts) == 3


def test_RA_256_engine_all_tasks_returns_list(db):
    e = RemediationAuthorityEngine(db, tenant_id="t-r-all")
    e.create_task(CreateTaskRequest(title="X"), actor_id="u")
    db.commit()
    assert e.get_dashboard().tenant_id == "t-r-all"


def test_RA_257_engine_create_plan_records_timeline(svc, db):
    p = svc.create_plan(CreatePlanRequest(title="P"), actor_id="u")
    db.commit()
    # Plans use the plan.id as the timeline task_id (audit surface).
    tl = svc._repo.list_timeline(p.id)
    assert any(t.event_type == "plan_created" for t in tl)


def test_RA_258_engine_update_task_appends_timeline(svc, db):
    t = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    svc.update_task(t.id, UpdateTaskRequest(title="T2"), actor_id="u")
    db.commit()
    tl = svc.get_timeline(t.id)
    assert any(e.event_type == "task_updated" for e in tl.events)


def test_RA_259_engine_get_history_ignores_non_history_events(svc, db):
    t = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    svc.update_task(t.id, UpdateTaskRequest(title="T2"), actor_id="u")
    db.commit()
    r = svc.get_history(t.id)
    # task_updated is not in history event set
    event_types = {e.to_state for e in r.entries}
    assert "OPEN" in event_types or None in event_types


def test_RA_260_engine_forecast_open_count(svc, db):
    for _ in range(3):
        svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    db.commit()
    r = svc.get_forecast(horizon_days=30)
    assert r.open_task_count == 3
