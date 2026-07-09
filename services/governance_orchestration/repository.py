"""Tenant-scoped data access for the Governance Orchestration Authority.

Every query includes a tenant_id predicate. Caller (engine / API) owns
``db.commit()``.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Optional

from sqlalchemy.orm import Session

from api.db_models_governance_orchestration import (
    GovOrchApproval,
    GovOrchChangeDetection,
    GovOrchMaintenanceWindow,
    GovOrchPlaybook,
    GovOrchPolicy,
    GovOrchPolicyVersion,
    GovOrchReassessment,
    GovOrchSimulation,
    GovOrchTimeline,
    GovOrchTrigger,
    GovOrchTriggerTimeline,
    GovOrchWorkflow,
)
from services.canonical import utc_iso8601_z_now


def _now() -> str:
    return utc_iso8601_z_now()


def _new_id() -> str:
    return str(uuid.uuid4())


def _dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True)


class GovernanceOrchestrationRepository:
    """Tenant-scoped data access for the fa_gov_orch_* tables."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def create_policy(self, **fields: Any) -> GovOrchPolicy:
        now = _now()
        row = GovOrchPolicy(
            id=fields.get("id") or _new_id(),
            tenant_id=self._tenant_id,
            name=fields["name"],
            description=fields.get("description"),
            risk_level=fields.get("risk_level", "MEDIUM"),
            policy_data=_dumps(fields.get("policy_data") or {}),
            active=1 if fields.get("active", True) else 0,
            version=fields.get("version", "1.0"),
            created_at=now,
            updated_at=now,
        )
        self._db.add(row)
        self._db.flush()
        return row

    def get_policy(self, policy_id: str) -> Optional[GovOrchPolicy]:
        return (
            self._db.query(GovOrchPolicy)
            .filter(
                GovOrchPolicy.id == policy_id,
                GovOrchPolicy.tenant_id == self._tenant_id,
            )
            .first()
        )

    def list_policies(
        self, *, active: Optional[bool] = None, offset: int = 0, limit: int = 50
    ) -> tuple[list[GovOrchPolicy], int]:
        q = self._db.query(GovOrchPolicy).filter(
            GovOrchPolicy.tenant_id == self._tenant_id
        )
        if active is not None:
            q = q.filter(GovOrchPolicy.active == (1 if active else 0))
        total = q.count()
        items = (
            q.order_by(GovOrchPolicy.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total

    def update_policy(self, row: GovOrchPolicy) -> GovOrchPolicy:
        row.updated_at = _now()
        self._db.flush()
        return row

    def append_policy_version(
        self,
        *,
        policy_id: str,
        version: str,
        policy_data: dict[str, Any],
        actor_id: Optional[str],
    ) -> GovOrchPolicyVersion:
        row = GovOrchPolicyVersion(
            id=_new_id(),
            tenant_id=self._tenant_id,
            policy_id=policy_id,
            version=version,
            policy_data=_dumps(policy_data),
            actor_id=actor_id,
            created_at=_now(),
        )
        self._db.add(row)
        self._db.flush()
        return row

    def list_policy_versions(self, policy_id: str) -> list[GovOrchPolicyVersion]:
        return (
            self._db.query(GovOrchPolicyVersion)
            .filter(
                GovOrchPolicyVersion.tenant_id == self._tenant_id,
                GovOrchPolicyVersion.policy_id == policy_id,
            )
            .order_by(GovOrchPolicyVersion.created_at.asc())
            .all()
        )

    # ------------------------------------------------------------------
    # Playbooks
    # ------------------------------------------------------------------

    def create_playbook(self, **fields: Any) -> GovOrchPlaybook:
        now = _now()
        row = GovOrchPlaybook(
            id=fields.get("id") or _new_id(),
            tenant_id=self._tenant_id,
            name=fields["name"],
            playbook_type=fields["playbook_type"],
            description=fields.get("description"),
            playbook_data=_dumps(fields.get("playbook_data") or {}),
            created_at=now,
            updated_at=now,
        )
        self._db.add(row)
        self._db.flush()
        return row

    def get_playbook(self, playbook_id: str) -> Optional[GovOrchPlaybook]:
        return (
            self._db.query(GovOrchPlaybook)
            .filter(
                GovOrchPlaybook.id == playbook_id,
                GovOrchPlaybook.tenant_id == self._tenant_id,
            )
            .first()
        )

    def list_playbooks(
        self,
        *,
        playbook_type: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[GovOrchPlaybook], int]:
        q = self._db.query(GovOrchPlaybook).filter(
            GovOrchPlaybook.tenant_id == self._tenant_id
        )
        if playbook_type is not None:
            q = q.filter(GovOrchPlaybook.playbook_type == playbook_type)
        total = q.count()
        items = (
            q.order_by(GovOrchPlaybook.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total

    # ------------------------------------------------------------------
    # Workflows
    # ------------------------------------------------------------------

    def create_workflow(self, **fields: Any) -> GovOrchWorkflow:
        now = _now()
        row = GovOrchWorkflow(
            id=fields.get("id") or _new_id(),
            tenant_id=self._tenant_id,
            name=fields["name"],
            workflow_state=fields.get("workflow_state", "PENDING"),
            playbook_id=fields.get("playbook_id"),
            trigger_id=fields.get("trigger_id"),
            context=_dumps(fields.get("context") or {}),
            created_at=now,
            updated_at=now,
            completed_at=None,
        )
        self._db.add(row)
        self._db.flush()
        return row

    def get_workflow(self, workflow_id: str) -> Optional[GovOrchWorkflow]:
        return (
            self._db.query(GovOrchWorkflow)
            .filter(
                GovOrchWorkflow.id == workflow_id,
                GovOrchWorkflow.tenant_id == self._tenant_id,
            )
            .first()
        )

    def list_workflows(
        self,
        *,
        workflow_state: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[GovOrchWorkflow], int]:
        q = self._db.query(GovOrchWorkflow).filter(
            GovOrchWorkflow.tenant_id == self._tenant_id
        )
        if workflow_state is not None:
            q = q.filter(GovOrchWorkflow.workflow_state == workflow_state)
        total = q.count()
        items = (
            q.order_by(GovOrchWorkflow.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total

    def update_workflow(self, row: GovOrchWorkflow) -> GovOrchWorkflow:
        row.updated_at = _now()
        self._db.flush()
        return row

    # ------------------------------------------------------------------
    # Reassessments
    # ------------------------------------------------------------------

    def create_reassessment(self, **fields: Any) -> GovOrchReassessment:
        now = _now()
        row = GovOrchReassessment(
            id=fields.get("id") or _new_id(),
            tenant_id=self._tenant_id,
            assessment_id=fields["assessment_id"],
            trigger_id=fields.get("trigger_id"),
            reassessment_state=fields.get("reassessment_state", "REQUESTED"),
            reason=fields.get("reason"),
            scheduled_at=fields.get("scheduled_at"),
            completed_at=None,
            outcome=None,
            created_at=now,
            updated_at=now,
        )
        self._db.add(row)
        self._db.flush()
        return row

    def get_reassessment(self, reassessment_id: str) -> Optional[GovOrchReassessment]:
        return (
            self._db.query(GovOrchReassessment)
            .filter(
                GovOrchReassessment.id == reassessment_id,
                GovOrchReassessment.tenant_id == self._tenant_id,
            )
            .first()
        )

    def list_reassessments(
        self,
        *,
        reassessment_state: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[GovOrchReassessment], int]:
        q = self._db.query(GovOrchReassessment).filter(
            GovOrchReassessment.tenant_id == self._tenant_id
        )
        if reassessment_state is not None:
            q = q.filter(GovOrchReassessment.reassessment_state == reassessment_state)
        total = q.count()
        items = (
            q.order_by(GovOrchReassessment.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total

    def update_reassessment(self, row: GovOrchReassessment) -> GovOrchReassessment:
        row.updated_at = _now()
        self._db.flush()
        return row

    # ------------------------------------------------------------------
    # Triggers
    # ------------------------------------------------------------------

    def create_trigger(self, **fields: Any) -> GovOrchTrigger:
        row = GovOrchTrigger(
            id=fields.get("id") or _new_id(),
            tenant_id=self._tenant_id,
            trigger_type=fields["trigger_type"],
            source_id=fields.get("source_id"),
            reason=fields.get("reason"),
            confidence=float(fields.get("confidence", 1.0)),
            policy_version=fields.get("policy_version", "1.0"),
            created_at=_now(),
        )
        self._db.add(row)
        self._db.flush()
        return row

    def get_trigger(self, trigger_id: str) -> Optional[GovOrchTrigger]:
        return (
            self._db.query(GovOrchTrigger)
            .filter(
                GovOrchTrigger.id == trigger_id,
                GovOrchTrigger.tenant_id == self._tenant_id,
            )
            .first()
        )

    def list_triggers(
        self,
        *,
        trigger_type: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[GovOrchTrigger], int]:
        q = self._db.query(GovOrchTrigger).filter(
            GovOrchTrigger.tenant_id == self._tenant_id
        )
        if trigger_type is not None:
            q = q.filter(GovOrchTrigger.trigger_type == trigger_type)
        total = q.count()
        items = (
            q.order_by(GovOrchTrigger.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total

    def append_trigger_timeline(
        self,
        *,
        trigger_id: str,
        event_type: str,
        actor_id: Optional[str],
        event_metadata: Optional[dict[str, Any]] = None,
    ) -> GovOrchTriggerTimeline:
        row = GovOrchTriggerTimeline(
            id=_new_id(),
            tenant_id=self._tenant_id,
            trigger_id=trigger_id,
            event_type=event_type,
            actor_id=actor_id,
            event_metadata=_dumps(event_metadata or {}),
            created_at=_now(),
        )
        self._db.add(row)
        self._db.flush()
        return row

    # ------------------------------------------------------------------
    # Simulations
    # ------------------------------------------------------------------

    def create_simulation(self, **fields: Any) -> GovOrchSimulation:
        now = _now()
        row = GovOrchSimulation(
            id=fields.get("id") or _new_id(),
            tenant_id=self._tenant_id,
            name=fields["name"],
            change_type=fields["change_type"],
            change_data=_dumps(fields.get("change_data") or {}),
            simulation_state=fields.get("simulation_state", "PENDING"),
            result=_dumps(fields.get("result") or {}),
            created_at=now,
            updated_at=now,
        )
        self._db.add(row)
        self._db.flush()
        return row

    def get_simulation(self, simulation_id: str) -> Optional[GovOrchSimulation]:
        return (
            self._db.query(GovOrchSimulation)
            .filter(
                GovOrchSimulation.id == simulation_id,
                GovOrchSimulation.tenant_id == self._tenant_id,
            )
            .first()
        )

    def list_simulations(
        self, *, offset: int = 0, limit: int = 50
    ) -> tuple[list[GovOrchSimulation], int]:
        q = self._db.query(GovOrchSimulation).filter(
            GovOrchSimulation.tenant_id == self._tenant_id
        )
        total = q.count()
        items = (
            q.order_by(GovOrchSimulation.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total

    def update_simulation(self, row: GovOrchSimulation) -> GovOrchSimulation:
        row.updated_at = _now()
        self._db.flush()
        return row

    # ------------------------------------------------------------------
    # Approvals
    # ------------------------------------------------------------------

    def create_approval(self, **fields: Any) -> GovOrchApproval:
        now = _now()
        row = GovOrchApproval(
            id=fields.get("id") or _new_id(),
            tenant_id=self._tenant_id,
            workflow_id=fields["workflow_id"],
            actor_id=fields["actor_id"],
            stage=int(fields.get("stage", 1)),
            quorum=int(fields.get("quorum", 1)),
            approval_state=fields.get("approval_state", "PENDING"),
            decision=fields.get("decision"),
            reason=fields.get("reason"),
            delegated_to=fields.get("delegated_to"),
            created_at=now,
            updated_at=now,
        )
        self._db.add(row)
        self._db.flush()
        return row

    def get_approval(self, approval_id: str) -> Optional[GovOrchApproval]:
        return (
            self._db.query(GovOrchApproval)
            .filter(
                GovOrchApproval.id == approval_id,
                GovOrchApproval.tenant_id == self._tenant_id,
            )
            .first()
        )

    def list_approvals(
        self,
        *,
        workflow_id: Optional[str] = None,
        approval_state: Optional[str] = None,
    ) -> list[GovOrchApproval]:
        q = self._db.query(GovOrchApproval).filter(
            GovOrchApproval.tenant_id == self._tenant_id
        )
        if workflow_id is not None:
            q = q.filter(GovOrchApproval.workflow_id == workflow_id)
        if approval_state is not None:
            q = q.filter(GovOrchApproval.approval_state == approval_state)
        return q.order_by(
            GovOrchApproval.stage.asc(), GovOrchApproval.created_at.asc()
        ).all()

    def update_approval(self, row: GovOrchApproval) -> GovOrchApproval:
        row.updated_at = _now()
        self._db.flush()
        return row

    # ------------------------------------------------------------------
    # Maintenance windows
    # ------------------------------------------------------------------

    def create_maintenance_window(self, **fields: Any) -> GovOrchMaintenanceWindow:
        now = _now()
        row = GovOrchMaintenanceWindow(
            id=fields.get("id") or _new_id(),
            tenant_id=self._tenant_id,
            name=fields["name"],
            window_state=fields.get("window_state", "SCHEDULED"),
            starts_at=fields["starts_at"],
            ends_at=fields["ends_at"],
            reason=fields.get("reason"),
            created_at=now,
            updated_at=now,
        )
        self._db.add(row)
        self._db.flush()
        return row

    def get_maintenance_window(
        self, window_id: str
    ) -> Optional[GovOrchMaintenanceWindow]:
        return (
            self._db.query(GovOrchMaintenanceWindow)
            .filter(
                GovOrchMaintenanceWindow.id == window_id,
                GovOrchMaintenanceWindow.tenant_id == self._tenant_id,
            )
            .first()
        )

    def list_maintenance_windows(
        self, *, window_state: Optional[str] = None
    ) -> list[GovOrchMaintenanceWindow]:
        q = self._db.query(GovOrchMaintenanceWindow).filter(
            GovOrchMaintenanceWindow.tenant_id == self._tenant_id
        )
        if window_state is not None:
            q = q.filter(GovOrchMaintenanceWindow.window_state == window_state)
        return q.order_by(GovOrchMaintenanceWindow.created_at.desc()).all()

    def update_maintenance_window(
        self, row: GovOrchMaintenanceWindow
    ) -> GovOrchMaintenanceWindow:
        row.updated_at = _now()
        self._db.flush()
        return row

    # ------------------------------------------------------------------
    # Change detections
    # ------------------------------------------------------------------

    def create_change_detection(self, **fields: Any) -> GovOrchChangeDetection:
        row = GovOrchChangeDetection(
            id=fields.get("id") or _new_id(),
            tenant_id=self._tenant_id,
            change_type=fields["change_type"],
            source_id=fields.get("source_id"),
            impact_level=fields.get("impact_level", "LOW"),
            change_data=_dumps(fields.get("change_data") or {}),
            created_at=_now(),
        )
        self._db.add(row)
        self._db.flush()
        return row

    def list_change_detections(
        self,
        *,
        change_type: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[GovOrchChangeDetection], int]:
        q = self._db.query(GovOrchChangeDetection).filter(
            GovOrchChangeDetection.tenant_id == self._tenant_id
        )
        if change_type is not None:
            q = q.filter(GovOrchChangeDetection.change_type == change_type)
        total = q.count()
        items = (
            q.order_by(GovOrchChangeDetection.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total

    # ------------------------------------------------------------------
    # Timeline (append-only)
    # ------------------------------------------------------------------

    def append_timeline(
        self,
        *,
        entity_type: str,
        entity_id: str,
        event_type: str,
        actor_id: Optional[str],
        event_metadata: Optional[dict[str, Any]] = None,
    ) -> GovOrchTimeline:
        row = GovOrchTimeline(
            id=_new_id(),
            tenant_id=self._tenant_id,
            entity_type=entity_type,
            entity_id=entity_id,
            event_type=event_type,
            actor_id=actor_id,
            event_metadata=_dumps(event_metadata or {}),
            created_at=_now(),
        )
        self._db.add(row)
        self._db.flush()
        return row

    def list_timeline(
        self,
        *,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[GovOrchTimeline], int]:
        q = self._db.query(GovOrchTimeline).filter(
            GovOrchTimeline.tenant_id == self._tenant_id
        )
        if entity_type is not None:
            q = q.filter(GovOrchTimeline.entity_type == entity_type)
        if entity_id is not None:
            q = q.filter(GovOrchTimeline.entity_id == entity_id)
        total = q.count()
        items = (
            q.order_by(GovOrchTimeline.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total
