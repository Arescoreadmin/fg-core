"""RemediationAuthorityEngine — single write authority for fa_rem_* tables.

Every mutating operation follows the standard pattern:
  1. Validate inputs (fail-closed).
  2. Enforce tenant isolation via the repository.
  3. Execute the state transition via the formal state machine.
  4. Append an audit / timeline event (always, never skipped).
  5. Return a schema object (never a raw ORM row).

The engine never touches other authorities' write surfaces. Cross-authority
reads (governance_learning, remediation_effectiveness) are wrapped in
``try/except`` so the engine degrades gracefully when those services are
not populated for the tenant.

Caller (API layer) owns ``db.commit()`` — the engine does not commit.
"""

from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import text as sa_text
from sqlalchemy.orm import Session

from services.canonical import utc_iso8601_z_now
from services.remediation_authority.dependencies import (
    check_no_cycle,
    critical_path,
    dependents_of,
)
from services.remediation_authority.effectiveness import read_effectiveness_summary
from services.remediation_authority.forecast import (
    compute_forecast,
    read_governance_learning_signal,
)
from services.remediation_authority.health import build_health
from services.remediation_authority.history import timeline_row_to_history
from services.remediation_authority.models import (
    IMMUTABLE_TASK_STATES,
    AssignmentRole,
    DependencyType,
    RemediationPlanState,
    RemediationPriority,
    RemediationTaskState,
    RemediationVerificationState,
)
from services.remediation_authority.repository import (
    RemediationAuthorityRepository,
)
from services.remediation_authority.risk import compute_risk_summary
from services.remediation_authority.schemas import (
    AssignmentListResponse,
    AssignmentResponse,
    CreateAssignmentRequest,
    CreateDependencyRequest,
    CreatePlanRequest,
    CreateTaskRequest,
    CreateVerificationRequest,
    DashboardResponse,
    DependencyListResponse,
    DependencyResponse,
    ForecastResponse,
    HealthResponse,
    HistoryResponse,
    PlanListResponse,
    PlanResponse,
    RemediationAssignmentError,
    RemediationDependencyError,
    RemediationImmutableState,
    RemediationInvalidTransition,
    RemediationNotFound,
    RemediationVerificationError,
    RiskResponse,
    SearchResponse,
    StatisticsResponse,
    TaskListResponse,
    TaskResponse,
    TimelineResponse,
    TransitionTaskRequest,
    UpdatePlanRequest,
    UpdateTaskRequest,
    VerificationListResponse,
    VerificationResponse,
)
from services.remediation_authority.sla import compute_sla_status
from services.remediation_authority.state_machine import (
    is_immutable_plan_state,
    validate_plan_transition,
    validate_transition,
)
from services.remediation_authority.statistics import (
    average_completion_days,
    bucket_by,
    count_by_sla,
)
from services.remediation_authority.timeline import timeline_row_to_event
from services.remediation_authority.validators import (
    validate_horizon_days,
    validate_limit_offset,
    validate_search_query,
    validate_task_id,
    validate_tenant_id,
)
from services.remediation_authority.verification import (
    approval_completes_task,
    normalize_state as normalize_verification_state,
)


def _now() -> str:
    return utc_iso8601_z_now()


# ---------------------------------------------------------------------------
# Mapping helpers (ORM row -> response schema)
# ---------------------------------------------------------------------------


def _plan_to_response(row: Any) -> PlanResponse:
    return PlanResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        title=row.title,
        description=row.description,
        plan_state=row.plan_state,
        assessment_id=row.assessment_id,
        target_date=row.target_date,
        created_at=row.created_at,
        updated_at=row.updated_at,
        completed_at=row.completed_at,
    )


def _task_to_response(row: Any) -> TaskResponse:
    return TaskResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        plan_id=row.plan_id,
        title=row.title,
        description=row.description,
        task_state=row.task_state,
        priority=row.priority,
        owner_id=row.owner_id,
        reviewer_id=row.reviewer_id,
        approver_id=row.approver_id,
        finding_id=row.finding_id,
        control_id=row.control_id,
        evidence_id=row.evidence_id,
        target_date=row.target_date,
        risk_score=row.risk_score,
        sla_status=row.sla_status,
        created_at=row.created_at,
        updated_at=row.updated_at,
        completed_at=row.completed_at,
    )


def _assignment_to_response(row: Any) -> AssignmentResponse:
    return AssignmentResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        task_id=row.task_id,
        actor_id=row.actor_id,
        role=row.role,
        created_at=row.created_at,
    )


def _dependency_to_response(row: Any) -> DependencyResponse:
    return DependencyResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        source_task_id=row.source_task_id,
        target_task_id=row.target_task_id,
        dependency_type=row.dependency_type,
        created_at=row.created_at,
    )


def _verification_to_response(row: Any) -> VerificationResponse:
    return VerificationResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        task_id=row.task_id,
        verifier_id=row.verifier_id,
        verification_state=row.verification_state,
        evidence_id=row.evidence_id,
        notes=row.notes,
        created_at=row.created_at,
    )


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class RemediationAuthorityEngine:
    """Single write authority for Remediation Authority tables."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        validate_tenant_id(tenant_id)
        self._db = db
        self._tenant_id = tenant_id
        self._repo = RemediationAuthorityRepository(db=db, tenant_id=tenant_id)

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health(self) -> HealthResponse:
        try:
            self._db.execute(sa_text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
        return build_health(db_ok=db_ok)

    # ------------------------------------------------------------------
    # Plans
    # ------------------------------------------------------------------

    def create_plan(self, req: CreatePlanRequest, *, actor_id: str) -> PlanResponse:
        row = self._repo.create_plan(
            title=req.title,
            description=req.description,
            plan_state=RemediationPlanState.DRAFT.value,
            assessment_id=req.assessment_id,
            target_date=req.target_date,
        )
        self._repo.append_timeline(
            task_id=row.id,
            event_type="plan_created",
            from_state=None,
            to_state=RemediationPlanState.DRAFT.value,
            actor_id=actor_id,
            reason=None,
            event_metadata={"plan_id": row.id},
        )
        return _plan_to_response(row)

    def get_plan(self, plan_id: str) -> PlanResponse:
        row = self._repo.get_plan(plan_id)
        if row is None:
            raise RemediationNotFound(
                f"Plan {plan_id!r} not found for tenant {self._tenant_id!r}"
            )
        return _plan_to_response(row)

    def list_plans(
        self,
        *,
        plan_state: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> PlanListResponse:
        validate_limit_offset(limit, offset)
        rows, total = self._repo.list_plans(
            plan_state=plan_state, offset=offset, limit=limit
        )
        return PlanListResponse(
            items=[_plan_to_response(r) for r in rows],
            total=total,
            offset=offset,
            limit=limit,
        )

    def update_plan(
        self, plan_id: str, req: UpdatePlanRequest, *, actor_id: str
    ) -> PlanResponse:
        row = self._repo.get_plan(plan_id)
        if row is None:
            raise RemediationNotFound(
                f"Plan {plan_id!r} not found for tenant {self._tenant_id!r}"
            )
        current_state = RemediationPlanState(row.plan_state)
        if is_immutable_plan_state(current_state):
            raise RemediationImmutableState(
                f"Plan {plan_id!r} in state {current_state.value!r} is immutable"
            )
        if req.plan_state is not None and req.plan_state != current_state:
            try:
                validate_plan_transition(current_state, req.plan_state)
            except ValueError as exc:
                raise RemediationInvalidTransition(str(exc)) from exc
            row.plan_state = req.plan_state.value
            if req.plan_state == RemediationPlanState.COMPLETED:
                row.completed_at = _now()
            self._repo.append_timeline(
                task_id=row.id,
                event_type="plan_state_changed",
                from_state=current_state.value,
                to_state=req.plan_state.value,
                actor_id=actor_id,
                reason=None,
                event_metadata={"plan_id": row.id},
            )
        if req.title is not None:
            row.title = req.title
        if req.description is not None:
            row.description = req.description
        if req.target_date is not None:
            row.target_date = req.target_date
        self._repo.update_plan(row)
        return _plan_to_response(row)

    # ------------------------------------------------------------------
    # Tasks
    # ------------------------------------------------------------------

    def create_task(self, req: CreateTaskRequest, *, actor_id: str) -> TaskResponse:
        if req.plan_id is not None and self._repo.get_plan(req.plan_id) is None:
            raise RemediationNotFound(
                f"Plan {req.plan_id!r} not found for tenant {self._tenant_id!r}"
            )
        initial_state = RemediationTaskState.OPEN
        priority = req.priority or RemediationPriority.MEDIUM
        sla_status = compute_sla_status(
            target_date=req.target_date,
            task_state=initial_state.value,
            completed_at=None,
        )
        row = self._repo.create_task(
            plan_id=req.plan_id,
            title=req.title,
            description=req.description,
            task_state=initial_state.value,
            priority=priority.value,
            owner_id=req.owner_id,
            reviewer_id=req.reviewer_id,
            approver_id=req.approver_id,
            finding_id=req.finding_id,
            control_id=req.control_id,
            evidence_id=req.evidence_id,
            target_date=req.target_date,
            risk_score=req.risk_score,
            sla_status=sla_status.value,
        )
        self._repo.append_timeline(
            task_id=row.id,
            event_type="task_created",
            from_state=None,
            to_state=initial_state.value,
            actor_id=actor_id,
            reason=None,
            event_metadata={"priority": priority.value},
        )
        return _task_to_response(row)

    def get_task(self, task_id: str) -> TaskResponse:
        validate_task_id(task_id)
        row = self._repo.get_task(task_id)
        if row is None:
            raise RemediationNotFound(
                f"Task {task_id!r} not found for tenant {self._tenant_id!r}"
            )
        return _task_to_response(row)

    def list_tasks(
        self,
        *,
        plan_id: Optional[str] = None,
        task_state: Optional[str] = None,
        priority: Optional[str] = None,
        owner_id: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> TaskListResponse:
        validate_limit_offset(limit, offset)
        rows, total = self._repo.list_tasks(
            plan_id=plan_id,
            task_state=task_state,
            priority=priority,
            owner_id=owner_id,
            offset=offset,
            limit=limit,
        )
        return TaskListResponse(
            items=[_task_to_response(r) for r in rows],
            total=total,
            offset=offset,
            limit=limit,
        )

    def update_task(
        self, task_id: str, req: UpdateTaskRequest, *, actor_id: str
    ) -> TaskResponse:
        row = self._repo.get_task(task_id)
        if row is None:
            raise RemediationNotFound(
                f"Task {task_id!r} not found for tenant {self._tenant_id!r}"
            )
        state = RemediationTaskState(row.task_state)
        if state in IMMUTABLE_TASK_STATES:
            raise RemediationImmutableState(
                f"Task {task_id!r} in state {state.value!r} is immutable"
            )
        changed: dict[str, Any] = {}
        if req.title is not None:
            row.title = req.title
            changed["title"] = req.title
        if req.description is not None:
            row.description = req.description
        if req.priority is not None:
            row.priority = req.priority.value
            changed["priority"] = req.priority.value
        if req.owner_id is not None:
            row.owner_id = req.owner_id
        if req.reviewer_id is not None:
            row.reviewer_id = req.reviewer_id
        if req.approver_id is not None:
            row.approver_id = req.approver_id
        if req.target_date is not None:
            row.target_date = req.target_date
            changed["target_date"] = req.target_date
        if req.risk_score is not None:
            row.risk_score = req.risk_score
        # Recompute SLA based on new target_date
        row.sla_status = compute_sla_status(
            target_date=row.target_date,
            task_state=row.task_state,
            completed_at=row.completed_at,
        ).value
        self._repo.update_task(row)
        if changed:
            self._repo.append_timeline(
                task_id=row.id,
                event_type="task_updated",
                from_state=state.value,
                to_state=state.value,
                actor_id=actor_id,
                reason=None,
                event_metadata=changed,
            )
        return _task_to_response(row)

    def transition_task(
        self, task_id: str, req: TransitionTaskRequest, *, actor_id: str
    ) -> TaskResponse:
        row = self._repo.get_task(task_id)
        if row is None:
            raise RemediationNotFound(
                f"Task {task_id!r} not found for tenant {self._tenant_id!r}"
            )
        current = RemediationTaskState(row.task_state)
        try:
            validate_transition(current, req.to_state)
        except ValueError as exc:
            raise RemediationInvalidTransition(str(exc)) from exc
        # Block transitions that would violate outstanding blockers
        if req.to_state in {
            RemediationTaskState.READY_FOR_REVIEW,
            RemediationTaskState.APPROVED,
            RemediationTaskState.COMPLETED,
        }:
            self._ensure_no_open_blockers(row.id)
        row.task_state = req.to_state.value
        if req.to_state == RemediationTaskState.COMPLETED:
            row.completed_at = _now()
        row.sla_status = compute_sla_status(
            target_date=row.target_date,
            task_state=row.task_state,
            completed_at=row.completed_at,
        ).value
        self._repo.update_task(row)
        self._repo.append_timeline(
            task_id=row.id,
            event_type="task_transition",
            from_state=current.value,
            to_state=req.to_state.value,
            actor_id=actor_id,
            reason=req.reason,
            event_metadata={},
        )
        return _task_to_response(row)

    def _ensure_no_open_blockers(self, task_id: str) -> None:
        edges = [
            (d.source_task_id, d.target_task_id) for d in self._repo.list_dependencies()
        ]
        blockers = [src for src, dst in edges if dst == task_id]
        for blocker_id in blockers:
            blocker = self._repo.get_task(blocker_id)
            if blocker is None:
                continue
            if blocker.task_state != RemediationTaskState.COMPLETED.value:
                raise RemediationInvalidTransition(
                    f"Task {task_id!r} is blocked by open task {blocker_id!r} "
                    f"(state={blocker.task_state})"
                )

    # ------------------------------------------------------------------
    # Timeline / history
    # ------------------------------------------------------------------

    def get_timeline(self, task_id: str) -> TimelineResponse:
        if self._repo.get_task(task_id) is None:
            raise RemediationNotFound(
                f"Task {task_id!r} not found for tenant {self._tenant_id!r}"
            )
        rows = self._repo.list_timeline(task_id)
        return TimelineResponse(
            task_id=task_id,
            events=[timeline_row_to_event(r) for r in rows],
            total=len(rows),
        )

    def get_history(self, task_id: str) -> HistoryResponse:
        if self._repo.get_task(task_id) is None:
            raise RemediationNotFound(
                f"Task {task_id!r} not found for tenant {self._tenant_id!r}"
            )
        rows = [
            r
            for r in self._repo.list_timeline(task_id)
            if r.event_type in {"task_transition", "task_created", "plan_state_changed"}
        ]
        return HistoryResponse(
            task_id=task_id,
            entries=[timeline_row_to_history(r) for r in rows],
            total=len(rows),
        )

    # ------------------------------------------------------------------
    # Assignments
    # ------------------------------------------------------------------

    def create_assignment(
        self, req: CreateAssignmentRequest, *, actor_id: str
    ) -> AssignmentResponse:
        task = self._repo.get_task(req.task_id)
        if task is None:
            raise RemediationNotFound(
                f"Task {req.task_id!r} not found for tenant {self._tenant_id!r}"
            )
        if not req.actor_id or not req.actor_id.strip():
            raise RemediationAssignmentError("actor_id must be non-empty")
        role_str = (
            req.role.value if isinstance(req.role, AssignmentRole) else str(req.role)
        )
        row = self._repo.create_assignment(
            task_id=req.task_id,
            actor_id=req.actor_id,
            role=role_str,
        )
        # Reflect owner/reviewer/approver on the task itself for convenience
        if role_str == AssignmentRole.OWNER.value:
            task.owner_id = req.actor_id
        elif role_str == AssignmentRole.REVIEWER.value:
            task.reviewer_id = req.actor_id
        elif role_str == AssignmentRole.APPROVER.value:
            task.approver_id = req.actor_id
        # Move OPEN tasks to ASSIGNED when an owner is set
        if (
            role_str == AssignmentRole.OWNER.value
            and task.task_state == RemediationTaskState.OPEN.value
        ):
            task.task_state = RemediationTaskState.ASSIGNED.value
            self._repo.append_timeline(
                task_id=task.id,
                event_type="task_transition",
                from_state=RemediationTaskState.OPEN.value,
                to_state=RemediationTaskState.ASSIGNED.value,
                actor_id=actor_id,
                reason="Owner assigned",
                event_metadata={"assignment_id": row.id},
            )
        self._repo.update_task(task)
        self._repo.append_timeline(
            task_id=task.id,
            event_type="assignment_created",
            from_state=None,
            to_state=None,
            actor_id=actor_id,
            reason=None,
            event_metadata={"role": role_str, "actor_id": req.actor_id},
        )
        return _assignment_to_response(row)

    def list_assignments(
        self, *, task_id: Optional[str] = None
    ) -> AssignmentListResponse:
        rows = self._repo.list_assignments(task_id=task_id)
        return AssignmentListResponse(
            items=[_assignment_to_response(r) for r in rows],
            total=len(rows),
        )

    # ------------------------------------------------------------------
    # Dependencies
    # ------------------------------------------------------------------

    def create_dependency(
        self, req: CreateDependencyRequest, *, actor_id: str
    ) -> DependencyResponse:
        if req.source_task_id == req.target_task_id:
            raise RemediationDependencyError("source and target tasks must differ")
        if self._repo.get_task(req.source_task_id) is None:
            raise RemediationNotFound(f"Source task {req.source_task_id!r} not found")
        if self._repo.get_task(req.target_task_id) is None:
            raise RemediationNotFound(f"Target task {req.target_task_id!r} not found")
        edges = [
            (d.source_task_id, d.target_task_id) for d in self._repo.list_dependencies()
        ]
        check_no_cycle(edges, (req.source_task_id, req.target_task_id))
        dep_type = (
            req.dependency_type.value
            if isinstance(req.dependency_type, DependencyType)
            else str(req.dependency_type)
        )
        row = self._repo.create_dependency(
            source_task_id=req.source_task_id,
            target_task_id=req.target_task_id,
            dependency_type=dep_type,
        )
        # If a BLOCKS dependency is added and source is not COMPLETED, mark
        # the target as BLOCKED (unless already in an incompatible state).
        if dep_type == DependencyType.BLOCKS.value:
            source = self._repo.get_task(req.source_task_id)
            target = self._repo.get_task(req.target_task_id)
            if (
                source is not None
                and target is not None
                and source.task_state != RemediationTaskState.COMPLETED.value
                and target.task_state
                in {
                    RemediationTaskState.OPEN.value,
                    RemediationTaskState.ASSIGNED.value,
                    RemediationTaskState.IN_PROGRESS.value,
                }
            ):
                prev = target.task_state
                target.task_state = RemediationTaskState.BLOCKED.value
                self._repo.update_task(target)
                self._repo.append_timeline(
                    task_id=target.id,
                    event_type="task_transition",
                    from_state=prev,
                    to_state=RemediationTaskState.BLOCKED.value,
                    actor_id=actor_id,
                    reason="Blocked by dependency",
                    event_metadata={"dependency_id": row.id},
                )
        self._repo.append_timeline(
            task_id=req.target_task_id,
            event_type="dependency_created",
            from_state=None,
            to_state=None,
            actor_id=actor_id,
            reason=None,
            event_metadata={
                "source_task_id": req.source_task_id,
                "target_task_id": req.target_task_id,
                "dependency_type": dep_type,
            },
        )
        return _dependency_to_response(row)

    def list_dependencies(self) -> DependencyListResponse:
        rows = self._repo.list_dependencies()
        return DependencyListResponse(
            items=[_dependency_to_response(r) for r in rows],
            total=len(rows),
        )

    def delete_dependency(self, dep_id: str, *, actor_id: str) -> bool:
        row = self._repo.get_dependency(dep_id)
        if row is None:
            raise RemediationNotFound(
                f"Dependency {dep_id!r} not found for tenant {self._tenant_id!r}"
            )
        target_id = row.target_task_id
        deleted = self._repo.delete_dependency(dep_id)
        if deleted:
            self._repo.append_timeline(
                task_id=target_id,
                event_type="dependency_deleted",
                from_state=None,
                to_state=None,
                actor_id=actor_id,
                reason=None,
                event_metadata={"dependency_id": dep_id},
            )
        return deleted

    def critical_path(self) -> list[str]:
        edges = [
            (d.source_task_id, d.target_task_id) for d in self._repo.list_dependencies()
        ]
        if not edges:
            return []
        sources = list({src for src, _ in edges})
        return critical_path(edges, sources)

    def dependents_of(self, task_id: str) -> list[str]:
        edges = [
            (d.source_task_id, d.target_task_id) for d in self._repo.list_dependencies()
        ]
        return dependents_of(task_id, edges)

    # ------------------------------------------------------------------
    # Verifications
    # ------------------------------------------------------------------

    def create_verification(
        self, req: CreateVerificationRequest, *, actor_id: str
    ) -> VerificationResponse:
        task = self._repo.get_task(req.task_id)
        if task is None:
            raise RemediationNotFound(
                f"Task {req.task_id!r} not found for tenant {self._tenant_id!r}"
            )
        state_str = (
            req.verification_state.value
            if isinstance(req.verification_state, RemediationVerificationState)
            else str(req.verification_state)
        )
        try:
            normalize_verification_state(state_str)
        except RemediationVerificationError as exc:
            raise RemediationVerificationError(str(exc)) from exc
        row = self._repo.create_verification(
            task_id=req.task_id,
            verifier_id=req.verifier_id,
            verification_state=state_str,
            evidence_id=req.evidence_id,
            notes=req.notes,
        )
        # Auto-move task states based on verification lifecycle
        if state_str == RemediationVerificationState.IN_REVIEW.value:
            if task.task_state == RemediationTaskState.READY_FOR_REVIEW.value:
                task.task_state = RemediationTaskState.VERIFYING.value
                self._repo.update_task(task)
                self._repo.append_timeline(
                    task_id=task.id,
                    event_type="task_transition",
                    from_state=RemediationTaskState.READY_FOR_REVIEW.value,
                    to_state=RemediationTaskState.VERIFYING.value,
                    actor_id=actor_id,
                    reason="Verification started",
                    event_metadata={"verification_id": row.id},
                )
        elif approval_completes_task(task.task_state, state_str):
            prev = task.task_state
            task.task_state = RemediationTaskState.APPROVED.value
            self._repo.update_task(task)
            self._repo.append_timeline(
                task_id=task.id,
                event_type="task_transition",
                from_state=prev,
                to_state=RemediationTaskState.APPROVED.value,
                actor_id=actor_id,
                reason="Verification approved",
                event_metadata={"verification_id": row.id},
            )
        elif state_str == RemediationVerificationState.REJECTED.value:
            if task.task_state == RemediationTaskState.VERIFYING.value:
                task.task_state = RemediationTaskState.IN_PROGRESS.value
                self._repo.update_task(task)
                self._repo.append_timeline(
                    task_id=task.id,
                    event_type="task_transition",
                    from_state=RemediationTaskState.VERIFYING.value,
                    to_state=RemediationTaskState.IN_PROGRESS.value,
                    actor_id=actor_id,
                    reason="Verification rejected",
                    event_metadata={"verification_id": row.id},
                )
        self._repo.append_timeline(
            task_id=req.task_id,
            event_type="verification_created",
            from_state=None,
            to_state=None,
            actor_id=actor_id,
            reason=None,
            event_metadata={
                "verifier_id": req.verifier_id,
                "verification_state": state_str,
                "evidence_id": req.evidence_id,
            },
        )
        return _verification_to_response(row)

    def list_verifications(
        self, *, task_id: Optional[str] = None
    ) -> VerificationListResponse:
        rows = self._repo.list_verifications(task_id=task_id)
        return VerificationListResponse(
            items=[_verification_to_response(r) for r in rows],
            total=len(rows),
        )

    # ------------------------------------------------------------------
    # Statistics / Forecast / Risk
    # ------------------------------------------------------------------

    def get_statistics(self) -> StatisticsResponse:
        rows = self._repo.all_tasks()
        plans, plans_total = self._repo.list_plans(offset=0, limit=1)
        del plans  # unused
        verifications = self._repo.list_verifications()
        by_state = bucket_by(rows, "task_state")
        by_priority = bucket_by(rows, "priority")
        by_sla = count_by_sla(rows)
        pending = sum(
            1
            for v in verifications
            if v.verification_state == RemediationVerificationState.PENDING.value
            or v.verification_state == RemediationVerificationState.IN_REVIEW.value
        )
        approved = sum(
            1
            for v in verifications
            if v.verification_state == RemediationVerificationState.APPROVED.value
        )
        return StatisticsResponse(
            tenant_id=self._tenant_id,
            total_plans=plans_total,
            total_tasks=len(rows),
            by_state=by_state,
            by_priority=by_priority,
            by_sla_status=by_sla,
            verifications_pending=pending,
            verifications_approved=approved,
            average_completion_days=average_completion_days(rows),
            computed_at=_now(),
        )

    def get_forecast(self, horizon_days: int = 30) -> ForecastResponse:
        validate_horizon_days(horizon_days)
        rows = self._repo.all_tasks()
        summary = compute_forecast(rows, horizon_days=horizon_days)
        # Governance-learning signal (optional) — currently unused in the
        # forecast math but preserved for future weighting decisions.
        _ = read_governance_learning_signal(self._db, self._tenant_id)
        return ForecastResponse(
            tenant_id=self._tenant_id,
            horizon_days=summary["horizon_days"],
            predicted_completions=summary["predicted_completions"],
            predicted_breaches=summary["predicted_breaches"],
            open_task_count=summary["open_task_count"],
            average_velocity_per_day=summary["average_velocity_per_day"],
            computed_at=_now(),
        )

    def get_risk(self) -> RiskResponse:
        rows = self._repo.all_tasks()
        summary = compute_risk_summary(rows)
        # Read effectiveness summary (currently informational — not blended
        # into the risk figures to preserve determinism until the contract
        # for the blended score is defined).
        _ = read_effectiveness_summary(self._db, self._tenant_id)
        return RiskResponse(
            tenant_id=self._tenant_id,
            total_risk_score=summary["total_risk_score"],
            open_risk_score=summary["open_risk_score"],
            mitigated_risk_score=summary["mitigated_risk_score"],
            risk_reduction_pct=summary["risk_reduction_pct"],
            by_priority=summary["by_priority"],
            computed_at=_now(),
        )

    # ------------------------------------------------------------------
    # Search / Dashboard
    # ------------------------------------------------------------------

    def search_tasks(
        self, query: str, *, offset: int = 0, limit: int = 50
    ) -> SearchResponse:
        validate_search_query(query)
        validate_limit_offset(limit, offset)
        rows, total = self._repo.search_tasks(query, offset=offset, limit=limit)
        return SearchResponse(
            query=query,
            items=[_task_to_response(r) for r in rows],
            total=total,
        )

    def get_dashboard(self) -> DashboardResponse:
        rows = self._repo.all_tasks()
        by_state = bucket_by(rows, "task_state")
        by_sla = count_by_sla(rows)
        by_priority = bucket_by(rows, "priority")

        def _target_date_or_max(row: Any) -> tuple[int, str]:
            td = getattr(row, "target_date", None) or ""
            # Rows without a target sort last (marker=1); others by ISO string.
            return (0 if td else 1, td)

        upcoming = [
            r
            for r in rows
            if r.task_state
            not in {
                RemediationTaskState.COMPLETED.value,
                RemediationTaskState.CANCELLED.value,
            }
        ]
        upcoming.sort(key=_target_date_or_max)
        upcoming_top = upcoming[:5]

        return DashboardResponse(
            tenant_id=self._tenant_id,
            open_tasks=by_state.get(RemediationTaskState.OPEN.value, 0),
            in_progress_tasks=by_state.get(RemediationTaskState.IN_PROGRESS.value, 0),
            blocked_tasks=by_state.get(RemediationTaskState.BLOCKED.value, 0),
            ready_for_review=by_state.get(
                RemediationTaskState.READY_FOR_REVIEW.value, 0
            ),
            completed_tasks=by_state.get(RemediationTaskState.COMPLETED.value, 0),
            breached_sla=by_sla.get("BREACHED", 0),
            at_risk_sla=by_sla.get("AT_RISK", 0),
            upcoming_deadlines=[_task_to_response(r) for r in upcoming_top],
            priority_breakdown=by_priority,
            computed_at=_now(),
        )
