"""GovernanceOrchestrationEngine — single write authority for fa_gov_orch_* tables.

Follows the standard pattern:
  1. Validate inputs (fail-closed).
  2. Enforce tenant isolation via the repository.
  3. Execute state transitions through helper modules.
  4. Append timeline events (never skipped for state changes).
  5. Return schema objects (never raw ORM rows).

Caller (API layer) owns ``db.commit()`` — the engine does not commit.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from sqlalchemy.orm import Session

from services.canonical import utc_iso8601_z_now
from services.governance_orchestration import governance_loop as _gov_loop
from services.governance_orchestration import statistics as _stats
from services.governance_orchestration.health import build_health
from services.governance_orchestration.impact_analysis import analyze_impact
from services.governance_orchestration.models import (
    ReassessmentState,
    SimulationState,
)
from services.governance_orchestration.playbooks import get_playbook_template
from services.governance_orchestration.policy_engine import (
    validate_policy_schema,
)
from services.governance_orchestration.repository import (
    GovernanceOrchestrationRepository,
)
from services.governance_orchestration.schemas import (
    ApprovalListResponse,
    ApprovalResponse,
    ApproveRequest,
    ChangeDetectionListResponse,
    ChangeDetectionResponse,
    CreateApprovalRequest,
    CreateChangeDetectionRequest,
    CreateMaintenanceWindowRequest,
    CreatePlaybookRequest,
    CreatePolicyRequest,
    CreateReassessmentRequest,
    CreateSimulationRequest,
    CreateTriggerRequest,
    CreateWorkflowRequest,
    DashboardResponse,
    GovernanceOrchestrationApprovalError,
    GovernanceOrchestrationNotFound,
    GovernanceOrchestrationSimulationError,
    GovernanceOrchestrationValidationError,
    HealthResponse,
    HistoryResponse,
    ImpactAnalysisResponse,
    MaintenanceWindowListResponse,
    MaintenanceWindowResponse,
    PlaybookListResponse,
    PlaybookResponse,
    PolicyListResponse,
    PolicyResponse,
    ReassessmentListResponse,
    ReassessmentResponse,
    SearchResponse,
    SimulationListResponse,
    SimulationResponse,
    StatisticsResponse,
    TimelineEventResponse,
    TimelineResponse,
    TriggerListResponse,
    TriggerResponse,
    UpdatePolicyRequest,
    WorkflowListResponse,
    WorkflowResponse,
)
from services.governance_orchestration.validators import (
    validate_confidence,
    validate_limit_offset,
    validate_playbook_type,
    validate_policy_risk_level,
    validate_search_query,
    validate_tenant_id,
    validate_trigger_type,
)


def _now() -> str:
    return utc_iso8601_z_now()


def _loads(raw: Any) -> dict[str, Any]:
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, ValueError):
        return {}


# ---------------------------------------------------------------------------
# Mapping helpers
# ---------------------------------------------------------------------------


def _policy_to_response(row: Any) -> PolicyResponse:
    return PolicyResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        name=row.name,
        description=row.description,
        risk_level=row.risk_level,
        policy_data=_loads(row.policy_data),
        active=bool(row.active),
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _playbook_to_response(row: Any) -> PlaybookResponse:
    return PlaybookResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        name=row.name,
        playbook_type=row.playbook_type,
        description=row.description,
        playbook_data=_loads(row.playbook_data),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _workflow_to_response(row: Any) -> WorkflowResponse:
    return WorkflowResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        name=row.name,
        workflow_state=row.workflow_state,
        playbook_id=row.playbook_id,
        trigger_id=row.trigger_id,
        context=_loads(row.context),
        created_at=row.created_at,
        updated_at=row.updated_at,
        completed_at=row.completed_at,
    )


def _reassessment_to_response(row: Any) -> ReassessmentResponse:
    return ReassessmentResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        assessment_id=row.assessment_id,
        trigger_id=row.trigger_id,
        reassessment_state=row.reassessment_state,
        reason=row.reason,
        scheduled_at=row.scheduled_at,
        completed_at=row.completed_at,
        outcome=row.outcome,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _trigger_to_response(row: Any) -> TriggerResponse:
    return TriggerResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        trigger_type=row.trigger_type,
        source_id=row.source_id,
        reason=row.reason,
        confidence=row.confidence,
        policy_version=row.policy_version,
        created_at=row.created_at,
    )


def _simulation_to_response(row: Any) -> SimulationResponse:
    return SimulationResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        name=row.name,
        change_type=row.change_type,
        change_data=_loads(row.change_data),
        simulation_state=row.simulation_state,
        result=_loads(row.result),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _approval_to_response(row: Any) -> ApprovalResponse:
    return ApprovalResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        workflow_id=row.workflow_id,
        actor_id=row.actor_id,
        stage=row.stage,
        quorum=row.quorum,
        approval_state=row.approval_state,
        decision=row.decision,
        reason=row.reason,
        delegated_to=row.delegated_to,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _window_to_response(row: Any) -> MaintenanceWindowResponse:
    return MaintenanceWindowResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        name=row.name,
        window_state=row.window_state,
        starts_at=row.starts_at,
        ends_at=row.ends_at,
        reason=row.reason,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _change_to_response(row: Any) -> ChangeDetectionResponse:
    return ChangeDetectionResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        change_type=row.change_type,
        source_id=row.source_id,
        impact_level=row.impact_level,
        change_data=_loads(row.change_data),
        created_at=row.created_at,
    )


def _timeline_to_response(row: Any) -> TimelineEventResponse:
    return TimelineEventResponse(
        id=row.id,
        entity_type=row.entity_type,
        entity_id=row.entity_id,
        event_type=row.event_type,
        actor_id=row.actor_id,
        event_metadata=_loads(row.event_metadata),
        created_at=row.created_at,
    )


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class GovernanceOrchestrationEngine:
    """Single write authority for Governance Orchestration Authority tables."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        validate_tenant_id(tenant_id)
        self._db = db
        self._tenant_id = tenant_id
        self._repo = GovernanceOrchestrationRepository(db=db, tenant_id=tenant_id)

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health(self) -> HealthResponse:
        payload = build_health(self._db, self._tenant_id)
        return HealthResponse(**payload)

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def create_policy(
        self, req: CreatePolicyRequest, *, actor_id: str
    ) -> PolicyResponse:
        validate_policy_risk_level(req.risk_level)
        errors = validate_policy_schema(req.policy_data or {})
        if errors:
            raise GovernanceOrchestrationValidationError("; ".join(errors))
        row = self._repo.create_policy(
            name=req.name,
            description=req.description,
            risk_level=req.risk_level,
            policy_data=req.policy_data or {},
            active=req.active,
        )
        self._repo.append_policy_version(
            policy_id=row.id,
            version=row.version,
            policy_data=req.policy_data or {},
            actor_id=actor_id,
        )
        self._repo.append_timeline(
            entity_type="policy",
            entity_id=row.id,
            event_type="policy_created",
            actor_id=actor_id,
            event_metadata={"risk_level": req.risk_level},
        )
        return _policy_to_response(row)

    def get_policy(self, policy_id: str) -> PolicyResponse:
        row = self._repo.get_policy(policy_id)
        if row is None:
            raise GovernanceOrchestrationNotFound(
                f"Policy {policy_id!r} not found for tenant {self._tenant_id!r}"
            )
        return _policy_to_response(row)

    def list_policies(
        self,
        *,
        active: Optional[bool] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> PolicyListResponse:
        validate_limit_offset(limit, offset)
        rows, total = self._repo.list_policies(
            active=active, offset=offset, limit=limit
        )
        return PolicyListResponse(
            items=[_policy_to_response(r) for r in rows],
            total=total,
            offset=offset,
            limit=limit,
        )

    def update_policy(
        self, policy_id: str, req: UpdatePolicyRequest, *, actor_id: str
    ) -> PolicyResponse:
        row = self._repo.get_policy(policy_id)
        if row is None:
            raise GovernanceOrchestrationNotFound(
                f"Policy {policy_id!r} not found for tenant {self._tenant_id!r}"
            )
        changed: dict[str, Any] = {}
        if req.name is not None:
            row.name = req.name
            changed["name"] = req.name
        if req.description is not None:
            row.description = req.description
            changed["description"] = req.description
        if req.risk_level is not None:
            validate_policy_risk_level(req.risk_level)
            row.risk_level = req.risk_level
            changed["risk_level"] = req.risk_level
        if req.policy_data is not None:
            errors = validate_policy_schema(req.policy_data)
            if errors:
                raise GovernanceOrchestrationValidationError("; ".join(errors))
            row.policy_data = json.dumps(req.policy_data, sort_keys=True)
            # Bump version and record in append-only policy_version table.
            try:
                major, minor = row.version.split(".", 1)
                row.version = f"{major}.{int(minor) + 1}"
            except Exception:
                row.version = row.version + ".1"
            self._repo.append_policy_version(
                policy_id=row.id,
                version=row.version,
                policy_data=req.policy_data,
                actor_id=actor_id,
            )
            changed["policy_data"] = True
            changed["version"] = row.version
        if req.active is not None:
            row.active = 1 if req.active else 0
            changed["active"] = req.active
        self._repo.update_policy(row)
        if changed:
            self._repo.append_timeline(
                entity_type="policy",
                entity_id=row.id,
                event_type="policy_updated",
                actor_id=actor_id,
                event_metadata=changed,
            )
        return _policy_to_response(row)

    # ------------------------------------------------------------------
    # Playbooks
    # ------------------------------------------------------------------

    def create_playbook(
        self, req: CreatePlaybookRequest, *, actor_id: str
    ) -> PlaybookResponse:
        validate_playbook_type(req.playbook_type)
        row = self._repo.create_playbook(
            name=req.name,
            playbook_type=req.playbook_type,
            description=req.description,
            playbook_data=req.playbook_data or {},
        )
        self._repo.append_timeline(
            entity_type="playbook",
            entity_id=row.id,
            event_type="playbook_created",
            actor_id=actor_id,
            event_metadata={"playbook_type": req.playbook_type},
        )
        return _playbook_to_response(row)

    def get_playbook(self, playbook_id: str) -> PlaybookResponse:
        row = self._repo.get_playbook(playbook_id)
        if row is None:
            raise GovernanceOrchestrationNotFound(
                f"Playbook {playbook_id!r} not found for tenant {self._tenant_id!r}"
            )
        return _playbook_to_response(row)

    def list_playbooks(
        self,
        *,
        playbook_type: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> PlaybookListResponse:
        validate_limit_offset(limit, offset)
        rows, total = self._repo.list_playbooks(
            playbook_type=playbook_type, offset=offset, limit=limit
        )
        return PlaybookListResponse(
            items=[_playbook_to_response(r) for r in rows],
            total=total,
            offset=offset,
            limit=limit,
        )

    def get_playbook_template(self, playbook_type: str) -> dict[str, Any]:
        validate_playbook_type(playbook_type)
        return get_playbook_template(playbook_type)

    # ------------------------------------------------------------------
    # Workflows
    # ------------------------------------------------------------------

    def create_workflow(
        self, req: CreateWorkflowRequest, *, actor_id: str
    ) -> WorkflowResponse:
        row = self._repo.create_workflow(
            name=req.name,
            playbook_id=req.playbook_id,
            trigger_id=req.trigger_id,
            context=req.context or {},
        )
        self._repo.append_timeline(
            entity_type="workflow",
            entity_id=row.id,
            event_type="workflow_created",
            actor_id=actor_id,
            event_metadata={"playbook_id": req.playbook_id},
        )
        return _workflow_to_response(row)

    def get_workflow(self, workflow_id: str) -> WorkflowResponse:
        row = self._repo.get_workflow(workflow_id)
        if row is None:
            raise GovernanceOrchestrationNotFound(
                f"Workflow {workflow_id!r} not found for tenant {self._tenant_id!r}"
            )
        return _workflow_to_response(row)

    def list_workflows(
        self,
        *,
        workflow_state: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> WorkflowListResponse:
        validate_limit_offset(limit, offset)
        rows, total = self._repo.list_workflows(
            workflow_state=workflow_state, offset=offset, limit=limit
        )
        return WorkflowListResponse(
            items=[_workflow_to_response(r) for r in rows],
            total=total,
            offset=offset,
            limit=limit,
        )

    def advance_workflow(
        self, workflow_id: str, event: str, *, actor_id: str
    ) -> WorkflowResponse:
        from services.governance_orchestration.workflow import WorkflowCoordinator

        WorkflowCoordinator().advance_workflow(
            self._db, self._tenant_id, workflow_id, event
        )
        self._repo.append_timeline(
            entity_type="workflow",
            entity_id=workflow_id,
            event_type=f"workflow_event_{event}",
            actor_id=actor_id,
            event_metadata={"event": event},
        )
        return self.get_workflow(workflow_id)

    def pause_workflow(self, workflow_id: str, *, actor_id: str) -> WorkflowResponse:
        return self.advance_workflow(workflow_id, "pause", actor_id=actor_id)

    def cancel_workflow(self, workflow_id: str, *, actor_id: str) -> WorkflowResponse:
        return self.advance_workflow(workflow_id, "cancel", actor_id=actor_id)

    # ------------------------------------------------------------------
    # Reassessments
    # ------------------------------------------------------------------

    def create_reassessment(
        self, req: CreateReassessmentRequest, *, actor_id: str
    ) -> ReassessmentResponse:
        row = self._repo.create_reassessment(
            assessment_id=req.assessment_id,
            trigger_id=req.trigger_id,
            reassessment_state=ReassessmentState.REQUESTED.value,
            reason=req.reason,
        )
        self._repo.append_timeline(
            entity_type="reassessment",
            entity_id=row.id,
            event_type="reassessment_requested",
            actor_id=actor_id,
            event_metadata={"assessment_id": req.assessment_id},
        )
        return _reassessment_to_response(row)

    def get_reassessment(self, reassessment_id: str) -> ReassessmentResponse:
        row = self._repo.get_reassessment(reassessment_id)
        if row is None:
            raise GovernanceOrchestrationNotFound(
                f"Reassessment {reassessment_id!r} not found"
            )
        return _reassessment_to_response(row)

    def list_reassessments(
        self,
        *,
        reassessment_state: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> ReassessmentListResponse:
        validate_limit_offset(limit, offset)
        rows, total = self._repo.list_reassessments(
            reassessment_state=reassessment_state, offset=offset, limit=limit
        )
        return ReassessmentListResponse(
            items=[_reassessment_to_response(r) for r in rows],
            total=total,
            offset=offset,
            limit=limit,
        )

    def schedule_reassessment(
        self, reassessment_id: str, scheduled_at: str, *, actor_id: str
    ) -> ReassessmentResponse:
        from services.governance_orchestration.reassessment import (
            schedule_reassessment as _sched,
        )

        _sched(self._db, self._tenant_id, reassessment_id, scheduled_at)
        self._repo.append_timeline(
            entity_type="reassessment",
            entity_id=reassessment_id,
            event_type="reassessment_scheduled",
            actor_id=actor_id,
            event_metadata={"scheduled_at": scheduled_at},
        )
        return self.get_reassessment(reassessment_id)

    def complete_reassessment(
        self, reassessment_id: str, outcome: str, *, actor_id: str
    ) -> ReassessmentResponse:
        from services.governance_orchestration.reassessment import (
            complete_reassessment as _complete,
        )

        _complete(self._db, self._tenant_id, reassessment_id, outcome)
        self._repo.append_timeline(
            entity_type="reassessment",
            entity_id=reassessment_id,
            event_type="reassessment_completed",
            actor_id=actor_id,
            event_metadata={"outcome": outcome},
        )
        return self.get_reassessment(reassessment_id)

    # ------------------------------------------------------------------
    # Triggers
    # ------------------------------------------------------------------

    def create_trigger(
        self, req: CreateTriggerRequest, *, actor_id: str
    ) -> TriggerResponse:
        validate_trigger_type(req.trigger_type)
        validate_confidence(req.confidence)
        row = self._repo.create_trigger(
            trigger_type=req.trigger_type,
            source_id=req.source_id,
            reason=req.reason,
            confidence=req.confidence,
            policy_version=req.policy_version,
        )
        self._repo.append_trigger_timeline(
            trigger_id=row.id,
            event_type="trigger_recorded",
            actor_id=actor_id,
            event_metadata={"trigger_type": req.trigger_type},
        )
        return _trigger_to_response(row)

    def get_trigger(self, trigger_id: str) -> TriggerResponse:
        row = self._repo.get_trigger(trigger_id)
        if row is None:
            raise GovernanceOrchestrationNotFound(
                f"Trigger {trigger_id!r} not found for tenant {self._tenant_id!r}"
            )
        return _trigger_to_response(row)

    def list_triggers(
        self,
        *,
        trigger_type: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> TriggerListResponse:
        validate_limit_offset(limit, offset)
        rows, total = self._repo.list_triggers(
            trigger_type=trigger_type, offset=offset, limit=limit
        )
        return TriggerListResponse(
            items=[_trigger_to_response(r) for r in rows],
            total=total,
            offset=offset,
            limit=limit,
        )

    # ------------------------------------------------------------------
    # Simulations
    # ------------------------------------------------------------------

    def create_simulation(
        self, req: CreateSimulationRequest, *, actor_id: str
    ) -> SimulationResponse:
        result = analyze_impact(
            self._db, self._tenant_id, req.change_type, req.change_data or {}
        )
        row = self._repo.create_simulation(
            name=req.name,
            change_type=req.change_type,
            change_data=req.change_data or {},
            simulation_state=SimulationState.COMPLETED.value,
            result=result,
        )
        self._repo.append_timeline(
            entity_type="simulation",
            entity_id=row.id,
            event_type="simulation_created",
            actor_id=actor_id,
            event_metadata={"change_type": req.change_type},
        )
        return _simulation_to_response(row)

    def get_simulation(self, simulation_id: str) -> SimulationResponse:
        row = self._repo.get_simulation(simulation_id)
        if row is None:
            raise GovernanceOrchestrationNotFound(
                f"Simulation {simulation_id!r} not found"
            )
        return _simulation_to_response(row)

    def list_simulations(
        self, *, offset: int = 0, limit: int = 50
    ) -> SimulationListResponse:
        validate_limit_offset(limit, offset)
        rows, total = self._repo.list_simulations(offset=offset, limit=limit)
        return SimulationListResponse(
            items=[_simulation_to_response(r) for r in rows],
            total=total,
            offset=offset,
            limit=limit,
        )

    def simulate_governance_impact(
        self, tenant_id: str, simulation_id: str
    ) -> SimulationResponse:
        row = self._repo.get_simulation(simulation_id)
        if row is None:
            raise GovernanceOrchestrationSimulationError(
                f"Simulation {simulation_id!r} not found"
            )
        return _simulation_to_response(row)

    # ------------------------------------------------------------------
    # Approvals
    # ------------------------------------------------------------------

    def create_approval(
        self, req: CreateApprovalRequest, *, actor_id: str
    ) -> ApprovalResponse:
        workflow = self._repo.get_workflow(req.workflow_id)
        if workflow is None:
            raise GovernanceOrchestrationNotFound(
                f"Workflow {req.workflow_id!r} not found"
            )
        row = self._repo.create_approval(
            workflow_id=req.workflow_id,
            actor_id=req.actor_id,
            stage=req.stage,
            quorum=req.quorum,
        )
        self._repo.append_timeline(
            entity_type="approval",
            entity_id=row.id,
            event_type="approval_created",
            actor_id=actor_id,
            event_metadata={"workflow_id": req.workflow_id, "stage": req.stage},
        )
        return _approval_to_response(row)

    def list_approvals(
        self,
        *,
        workflow_id: Optional[str] = None,
        approval_state: Optional[str] = None,
    ) -> ApprovalListResponse:
        rows = self._repo.list_approvals(
            workflow_id=workflow_id, approval_state=approval_state
        )
        return ApprovalListResponse(
            items=[_approval_to_response(r) for r in rows],
            total=len(rows),
        )

    def approve_approval(
        self, approval_id: str, req: ApproveRequest, *, actor_id: str
    ) -> ApprovalResponse:
        row = self._repo.get_approval(approval_id)
        if row is None:
            raise GovernanceOrchestrationNotFound(f"Approval {approval_id!r} not found")
        from services.governance_orchestration.models import ACTIVE_APPROVAL_STATES

        if row.approval_state not in {s.value for s in ACTIVE_APPROVAL_STATES}:
            raise GovernanceOrchestrationApprovalError(
                f"Approval {approval_id!r} is not in an active state "
                f"(current: {row.approval_state!r})"
            )
        decision = req.decision.upper()
        if decision not in {"APPROVE", "REJECT", "DELEGATE"}:
            raise GovernanceOrchestrationApprovalError(
                "decision must be APPROVE / REJECT / DELEGATE"
            )
        if decision == "APPROVE":
            row.approval_state = "APPROVED"
        elif decision == "REJECT":
            row.approval_state = "REJECTED"
        else:
            row.approval_state = "DELEGATED"
            row.delegated_to = req.delegated_to
        row.decision = decision
        row.reason = req.reason
        self._repo.update_approval(row)
        self._repo.append_timeline(
            entity_type="approval",
            entity_id=approval_id,
            event_type=f"approval_{decision.lower()}",
            actor_id=actor_id,
            event_metadata={"decision": decision},
        )
        return _approval_to_response(row)

    # ------------------------------------------------------------------
    # Maintenance windows
    # ------------------------------------------------------------------

    def create_maintenance_window(
        self, req: CreateMaintenanceWindowRequest, *, actor_id: str
    ) -> MaintenanceWindowResponse:
        if req.starts_at >= req.ends_at:
            raise GovernanceOrchestrationValidationError(
                "starts_at must be before ends_at"
            )
        row = self._repo.create_maintenance_window(
            name=req.name,
            starts_at=req.starts_at,
            ends_at=req.ends_at,
            reason=req.reason,
        )
        self._repo.append_timeline(
            entity_type="maintenance_window",
            entity_id=row.id,
            event_type="window_created",
            actor_id=actor_id,
            event_metadata={"starts_at": req.starts_at, "ends_at": req.ends_at},
        )
        return _window_to_response(row)

    def get_maintenance_window(self, window_id: str) -> MaintenanceWindowResponse:
        row = self._repo.get_maintenance_window(window_id)
        if row is None:
            raise GovernanceOrchestrationNotFound(
                f"Maintenance window {window_id!r} not found"
            )
        return _window_to_response(row)

    def list_maintenance_windows(
        self, *, window_state: Optional[str] = None
    ) -> MaintenanceWindowListResponse:
        rows = self._repo.list_maintenance_windows(window_state=window_state)
        return MaintenanceWindowListResponse(
            items=[_window_to_response(r) for r in rows],
            total=len(rows),
        )

    def open_maintenance_window(
        self, window_id: str, *, actor_id: str
    ) -> MaintenanceWindowResponse:
        from services.governance_orchestration.maintenance_windows import (
            open_maintenance_window as _open,
        )

        _open(self._db, self._tenant_id, window_id)
        self._repo.append_timeline(
            entity_type="maintenance_window",
            entity_id=window_id,
            event_type="window_opened",
            actor_id=actor_id,
            event_metadata={},
        )
        return self.get_maintenance_window(window_id)

    def close_maintenance_window(
        self, window_id: str, *, actor_id: str
    ) -> MaintenanceWindowResponse:
        from services.governance_orchestration.maintenance_windows import (
            close_maintenance_window as _close,
        )

        _close(self._db, self._tenant_id, window_id)
        self._repo.append_timeline(
            entity_type="maintenance_window",
            entity_id=window_id,
            event_type="window_closed",
            actor_id=actor_id,
            event_metadata={},
        )
        return self.get_maintenance_window(window_id)

    # ------------------------------------------------------------------
    # Change detection
    # ------------------------------------------------------------------

    def create_change_detection(
        self, req: CreateChangeDetectionRequest, *, actor_id: str
    ) -> ChangeDetectionResponse:
        row = self._repo.create_change_detection(
            change_type=req.change_type,
            source_id=req.source_id,
            impact_level=req.impact_level,
            change_data=req.change_data or {},
        )
        self._repo.append_timeline(
            entity_type="change_detection",
            entity_id=row.id,
            event_type="change_recorded",
            actor_id=actor_id,
            event_metadata={"change_type": req.change_type},
        )
        return _change_to_response(row)

    def list_change_detections(
        self,
        *,
        change_type: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> ChangeDetectionListResponse:
        validate_limit_offset(limit, offset)
        rows, total = self._repo.list_change_detections(
            change_type=change_type, offset=offset, limit=limit
        )
        return ChangeDetectionListResponse(
            items=[_change_to_response(r) for r in rows],
            total=total,
            offset=offset,
            limit=limit,
        )

    # ------------------------------------------------------------------
    # Timeline / history
    # ------------------------------------------------------------------

    def get_timeline(
        self,
        *,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> TimelineResponse:
        validate_limit_offset(limit, offset)
        rows, total = self._repo.list_timeline(
            entity_type=entity_type,
            entity_id=entity_id,
            offset=offset,
            limit=limit,
        )
        return TimelineResponse(
            events=[_timeline_to_response(r) for r in rows],
            total=total,
            offset=offset,
            limit=limit,
        )

    def get_history(self, entity_type: str, entity_id: str) -> HistoryResponse:
        rows, total = self._repo.list_timeline(
            entity_type=entity_type,
            entity_id=entity_id,
            offset=0,
            limit=500,
        )
        return HistoryResponse(
            entity_type=entity_type,
            entity_id=entity_id,
            events=[_timeline_to_response(r) for r in rows],
            total=total,
        )

    # ------------------------------------------------------------------
    # Dashboard / statistics / impact / search
    # ------------------------------------------------------------------

    def get_dashboard(self) -> DashboardResponse:
        policies, _ = self._repo.list_policies(active=True, offset=0, limit=500)
        workflows_active, _ = self._repo.list_workflows(offset=0, limit=500)
        pending_reassess, _ = self._repo.list_reassessments(
            reassessment_state=ReassessmentState.REQUESTED.value,
            offset=0,
            limit=500,
        )
        approvals = self._repo.list_approvals(approval_state="PENDING")
        windows = self._repo.list_maintenance_windows(window_state="ACTIVE")
        triggers, _ = self._repo.list_triggers(offset=0, limit=500)
        posture = _gov_loop.evaluate_governance_posture(self._db, self._tenant_id)
        evidence = _gov_loop.compute_evidence_sufficiency(self._db, self._tenant_id)
        control = _gov_loop.evaluate_control_health(self._db, self._tenant_id)
        return DashboardResponse(
            tenant_id=self._tenant_id,
            active_policies=sum(1 for p in policies if p.active),
            active_workflows=sum(
                1
                for w in workflows_active
                if w.workflow_state in {"RUNNING", "WAITING_APPROVAL"}
            ),
            pending_reassessments=len(pending_reassess),
            pending_approvals=len(approvals),
            active_maintenance_windows=len(windows),
            recent_triggers=len(triggers),
            evidence_sufficiency_pct=float(evidence.get("coverage_pct", 0.0)),
            control_health_pct=float(control.get("health_pct", 0.0)),
            governance_score=float(posture.get("score", 0.0)),
            computed_at=_now(),
        )

    def get_statistics(self) -> StatisticsResponse:
        s = _stats.compute_orchestration_statistics(self._db, self._tenant_id)
        return StatisticsResponse(
            tenant_id=self._tenant_id,
            total_policies=s["total_policies"],
            total_playbooks=s["total_playbooks"],
            total_workflows=s["total_workflows"],
            total_reassessments=s["total_reassessments"],
            total_triggers=s["total_triggers"],
            total_approvals=s["total_approvals"],
            workflow_by_state=s["workflow_by_state"],
            reassessment_by_state=s["reassessment_by_state"],
            trigger_by_type=s["trigger_by_type"],
            approval_by_state=s["approval_by_state"],
            computed_at=_now(),
        )

    def get_impact_analysis(
        self, *, change_type: str, change_data: Optional[dict[str, Any]] = None
    ) -> ImpactAnalysisResponse:
        result = analyze_impact(
            self._db, self._tenant_id, change_type, change_data or {}
        )
        return ImpactAnalysisResponse(
            tenant_id=self._tenant_id,
            change_type=result["change_type"],
            impact_level=result["impact_level"],
            governance_score_delta=result["governance_score_delta"],
            control_effectiveness_delta=result["control_effectiveness_delta"],
            risk_reduction=result["risk_reduction"],
            affected_controls=result["affected_controls"],
            affected_evidence=result["affected_evidence"],
            recommendations=result["recommendations"],
            computed_at=_now(),
        )

    def search(self, query: str) -> SearchResponse:
        validate_search_query(query)
        pattern = query.strip().lower()
        # Simple in-memory filter for portability across sqlite/postgres.
        policies, _ = self._repo.list_policies(offset=0, limit=500)
        playbooks, _ = self._repo.list_playbooks(offset=0, limit=500)
        workflows, _ = self._repo.list_workflows(offset=0, limit=500)
        matched_p = [
            _policy_to_response(r)
            for r in policies
            if pattern in (r.name or "").lower()
            or pattern in (r.description or "").lower()
        ]
        matched_pb = [
            _playbook_to_response(r)
            for r in playbooks
            if pattern in (r.name or "").lower()
            or pattern in (r.description or "").lower()
        ]
        matched_wf = [
            _workflow_to_response(r)
            for r in workflows
            if pattern in (r.name or "").lower()
        ]
        return SearchResponse(
            query=query,
            policies=matched_p,
            playbooks=matched_pb,
            workflows=matched_wf,
            total=len(matched_p) + len(matched_pb) + len(matched_wf),
        )

    # ------------------------------------------------------------------
    # Governance loop
    # ------------------------------------------------------------------

    def evaluate_governance_loop(
        self, context: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        return _gov_loop.evaluate_governance_state(self._db, self._tenant_id, context)

    def compute_evidence_sufficiency(
        self, tenant_id: str | None = None, assessment_id: str | None = None
    ) -> dict[str, Any]:
        # tenant_id kept for signature parity; engine is already tenant-scoped.
        return _gov_loop.compute_evidence_sufficiency(self._db, self._tenant_id)
