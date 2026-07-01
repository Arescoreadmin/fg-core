"""Tenant-scoped data access for the Remediation Authority.

Every query includes a tenant_id predicate. This is the only module that
touches the ``fa_rem_*`` tables directly. Caller (engine / API) owns
``db.commit()``.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Optional

from sqlalchemy.orm import Session

from api.db_models_remediation_authority import (
    RemAuthAssignment,
    RemAuthDependency,
    RemAuthEvidenceLink,
    RemAuthPlan,
    RemAuthTask,
    RemAuthTimeline,
    RemAuthVerification,
)
from services.canonical import utc_iso8601_z_now


def _now() -> str:
    return utc_iso8601_z_now()


def _new_id() -> str:
    return str(uuid.uuid4())


class RemediationAuthorityRepository:
    """Tenant-scoped data access for the fa_rem_* tables."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    # ------------------------------------------------------------------
    # Plans
    # ------------------------------------------------------------------

    def create_plan(self, **fields: Any) -> RemAuthPlan:
        now = _now()
        row = RemAuthPlan(
            id=fields.get("id") or _new_id(),
            tenant_id=self._tenant_id,
            title=fields["title"],
            description=fields.get("description"),
            plan_state=fields.get("plan_state", "DRAFT"),
            assessment_id=fields.get("assessment_id"),
            target_date=fields.get("target_date"),
            created_at=now,
            updated_at=now,
            completed_at=None,
        )
        self._db.add(row)
        self._db.flush()
        return row

    def get_plan(self, plan_id: str) -> Optional[RemAuthPlan]:
        return (
            self._db.query(RemAuthPlan)
            .filter(
                RemAuthPlan.id == plan_id,
                RemAuthPlan.tenant_id == self._tenant_id,
            )
            .first()
        )

    def list_plans(
        self,
        *,
        plan_state: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[RemAuthPlan], int]:
        q = self._db.query(RemAuthPlan).filter(RemAuthPlan.tenant_id == self._tenant_id)
        if plan_state is not None:
            q = q.filter(RemAuthPlan.plan_state == plan_state)
        total = q.count()
        items = (
            q.order_by(RemAuthPlan.created_at.desc()).offset(offset).limit(limit).all()
        )
        return items, total

    def update_plan(self, row: RemAuthPlan) -> RemAuthPlan:
        row.updated_at = _now()
        self._db.flush()
        return row

    # ------------------------------------------------------------------
    # Tasks
    # ------------------------------------------------------------------

    def create_task(self, **fields: Any) -> RemAuthTask:
        now = _now()
        row = RemAuthTask(
            id=fields.get("id") or _new_id(),
            tenant_id=self._tenant_id,
            plan_id=fields.get("plan_id"),
            title=fields["title"],
            description=fields.get("description"),
            task_state=fields.get("task_state", "OPEN"),
            priority=fields.get("priority", "MEDIUM"),
            owner_id=fields.get("owner_id"),
            reviewer_id=fields.get("reviewer_id"),
            approver_id=fields.get("approver_id"),
            finding_id=fields.get("finding_id"),
            control_id=fields.get("control_id"),
            evidence_id=fields.get("evidence_id"),
            target_date=fields.get("target_date"),
            risk_score=fields.get("risk_score"),
            sla_status=fields.get("sla_status", "UNSCHEDULED"),
            created_at=now,
            updated_at=now,
            completed_at=None,
        )
        self._db.add(row)
        self._db.flush()
        return row

    def get_task(self, task_id: str) -> Optional[RemAuthTask]:
        return (
            self._db.query(RemAuthTask)
            .filter(
                RemAuthTask.id == task_id,
                RemAuthTask.tenant_id == self._tenant_id,
            )
            .first()
        )

    def list_tasks(
        self,
        *,
        plan_id: Optional[str] = None,
        task_state: Optional[str] = None,
        priority: Optional[str] = None,
        owner_id: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[RemAuthTask], int]:
        q = self._db.query(RemAuthTask).filter(RemAuthTask.tenant_id == self._tenant_id)
        if plan_id is not None:
            q = q.filter(RemAuthTask.plan_id == plan_id)
        if task_state is not None:
            q = q.filter(RemAuthTask.task_state == task_state)
        if priority is not None:
            q = q.filter(RemAuthTask.priority == priority)
        if owner_id is not None:
            q = q.filter(RemAuthTask.owner_id == owner_id)
        total = q.count()
        items = (
            q.order_by(RemAuthTask.created_at.desc()).offset(offset).limit(limit).all()
        )
        return items, total

    def all_tasks(self) -> list[RemAuthTask]:
        """Return every task for the tenant. Used for aggregate computations."""
        return (
            self._db.query(RemAuthTask)
            .filter(RemAuthTask.tenant_id == self._tenant_id)
            .all()
        )

    def update_task(self, row: RemAuthTask) -> RemAuthTask:
        row.updated_at = _now()
        self._db.flush()
        return row

    def search_tasks(
        self, query: str, *, offset: int = 0, limit: int = 50
    ) -> tuple[list[RemAuthTask], int]:
        pattern = f"%{query.strip()}%"
        q = self._db.query(RemAuthTask).filter(
            RemAuthTask.tenant_id == self._tenant_id,
            (RemAuthTask.title.ilike(pattern))
            | (RemAuthTask.description.ilike(pattern)),
        )
        total = q.count()
        items = (
            q.order_by(RemAuthTask.created_at.desc()).offset(offset).limit(limit).all()
        )
        return items, total

    # ------------------------------------------------------------------
    # Timeline (append-only)
    # ------------------------------------------------------------------

    def append_timeline(
        self,
        *,
        task_id: str,
        event_type: str,
        from_state: Optional[str],
        to_state: Optional[str],
        actor_id: Optional[str],
        reason: Optional[str],
        event_metadata: Optional[dict[str, Any]] = None,
    ) -> RemAuthTimeline:
        row = RemAuthTimeline(
            id=_new_id(),
            tenant_id=self._tenant_id,
            task_id=task_id,
            event_type=event_type,
            from_state=from_state,
            to_state=to_state,
            actor_id=actor_id,
            reason=reason,
            event_metadata=json.dumps(event_metadata or {}),
            created_at=_now(),
        )
        self._db.add(row)
        self._db.flush()
        return row

    def list_timeline(self, task_id: str) -> list[RemAuthTimeline]:
        return (
            self._db.query(RemAuthTimeline)
            .filter(
                RemAuthTimeline.tenant_id == self._tenant_id,
                RemAuthTimeline.task_id == task_id,
            )
            .order_by(RemAuthTimeline.created_at.asc())
            .all()
        )

    # ------------------------------------------------------------------
    # Assignments
    # ------------------------------------------------------------------

    def create_assignment(
        self, *, task_id: str, actor_id: str, role: str
    ) -> RemAuthAssignment:
        row = RemAuthAssignment(
            id=_new_id(),
            tenant_id=self._tenant_id,
            task_id=task_id,
            actor_id=actor_id,
            role=role,
            created_at=_now(),
        )
        self._db.add(row)
        self._db.flush()
        return row

    def list_assignments(
        self, *, task_id: Optional[str] = None
    ) -> list[RemAuthAssignment]:
        q = self._db.query(RemAuthAssignment).filter(
            RemAuthAssignment.tenant_id == self._tenant_id
        )
        if task_id is not None:
            q = q.filter(RemAuthAssignment.task_id == task_id)
        return q.order_by(RemAuthAssignment.created_at.asc()).all()

    # ------------------------------------------------------------------
    # Dependencies
    # ------------------------------------------------------------------

    def create_dependency(
        self,
        *,
        source_task_id: str,
        target_task_id: str,
        dependency_type: str,
    ) -> RemAuthDependency:
        row = RemAuthDependency(
            id=_new_id(),
            tenant_id=self._tenant_id,
            source_task_id=source_task_id,
            target_task_id=target_task_id,
            dependency_type=dependency_type,
            created_at=_now(),
        )
        self._db.add(row)
        self._db.flush()
        return row

    def list_dependencies(self) -> list[RemAuthDependency]:
        return (
            self._db.query(RemAuthDependency)
            .filter(RemAuthDependency.tenant_id == self._tenant_id)
            .order_by(RemAuthDependency.created_at.asc())
            .all()
        )

    def get_dependency(self, dep_id: str) -> Optional[RemAuthDependency]:
        return (
            self._db.query(RemAuthDependency)
            .filter(
                RemAuthDependency.id == dep_id,
                RemAuthDependency.tenant_id == self._tenant_id,
            )
            .first()
        )

    def delete_dependency(self, dep_id: str) -> bool:
        row = self.get_dependency(dep_id)
        if row is None:
            return False
        self._db.delete(row)
        self._db.flush()
        return True

    # ------------------------------------------------------------------
    # Verifications
    # ------------------------------------------------------------------

    def create_verification(
        self,
        *,
        task_id: str,
        verifier_id: str,
        verification_state: str,
        evidence_id: Optional[str],
        notes: Optional[str],
    ) -> RemAuthVerification:
        row = RemAuthVerification(
            id=_new_id(),
            tenant_id=self._tenant_id,
            task_id=task_id,
            verifier_id=verifier_id,
            verification_state=verification_state,
            evidence_id=evidence_id,
            notes=notes,
            created_at=_now(),
        )
        self._db.add(row)
        self._db.flush()
        return row

    def list_verifications(
        self, *, task_id: Optional[str] = None
    ) -> list[RemAuthVerification]:
        q = self._db.query(RemAuthVerification).filter(
            RemAuthVerification.tenant_id == self._tenant_id
        )
        if task_id is not None:
            q = q.filter(RemAuthVerification.task_id == task_id)
        return q.order_by(RemAuthVerification.created_at.asc()).all()

    # ------------------------------------------------------------------
    # Evidence link (helper for future callers)
    # ------------------------------------------------------------------

    def create_evidence_link(
        self, *, task_id: str, evidence_id: str
    ) -> RemAuthEvidenceLink:
        row = RemAuthEvidenceLink(
            id=_new_id(),
            tenant_id=self._tenant_id,
            task_id=task_id,
            evidence_id=evidence_id,
            created_at=_now(),
        )
        self._db.add(row)
        self._db.flush()
        return row
