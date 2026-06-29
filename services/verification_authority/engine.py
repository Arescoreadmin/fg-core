"""services/verification_authority/engine.py — Business logic for Verification Workflow Authority.

This engine is the single write authority for fa_verification_request* tables.
No other service writes to these tables directly.

All mutating operations:
  1. Validate inputs (fail-closed)
  2. Enforce tenant isolation
  3. Execute state transition via the formal state machine
  4. Write the audit event (always, never skipped)
  5. Emit the timeline event (wrapped in try/except — never blocks)
  6. Commit

The engine never exposes raw ORM rows — it always returns schema objects.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from api.db_models_verification_authority import (
    FaVerificationRequest,
    FaVerificationRequestAudit,
    FaVerificationResult,
)
from services.verification_authority.models import (
    TERMINAL_WORKFLOW_STATES,
    VerificationRequestAuditEventType,
    VerificationWorkflowState,
    WorkflowSlaStatus,
    validate_workflow_transition,
)
from services.cgin.privacy import fingerprint_tenant
from services.verification_authority.repository import VerificationWorkflowRepository
from services.verification_authority.schemas import (
    AssignVerificationRequest,
    CreateVerificationRequestRequest,
    EscalateVerificationRequest,
    QueueItemResponse,
    QueueResponse,
    RecordResultRequest,
    SetWorkflowSlaRequest,
    TransitionWorkflowRequest,
    VerificationAuditListResponse,
    VerificationAuditResponse,
    VerificationRequestListResponse,
    VerificationRequestNotFound,
    VerificationRequestResponse,
    VerificationResultResponse,
    VerificationWorkflowInvalidTransition,
    WorkflowCginSnapshot,
    WorkflowDashboardResponse,
    WorkflowSlaStatusResponse,
)


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


def _sla_status_for_field(value: Optional[str], now_iso: str) -> Optional[str]:
    """Compute SLA status for a single due-at field."""
    if value is None:
        return None
    try:
        due = datetime.fromisoformat(value.replace("Z", "+00:00"))
        now = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
        if not due.tzinfo:
            due = due.replace(tzinfo=timezone.utc)
        if not now.tzinfo:
            now = now.replace(tzinfo=timezone.utc)
        if due < now:
            return WorkflowSlaStatus.OVERDUE.value
        elif due < now + timedelta(days=7):
            return WorkflowSlaStatus.DUE_SOON.value
        else:
            return WorkflowSlaStatus.ON_TRACK.value
    except Exception:
        return None


class VerificationAuthorityEngine:
    """Business logic engine for Verification Workflow Authority."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id
        self._repo = VerificationWorkflowRepository(db, tenant_id)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _now(self) -> str:
        return _now()

    def _new_id(self) -> str:
        return _new_id()

    def _write_audit(
        self,
        request_id: str,
        evidence_id: str,
        event_type: str,
        actor_id: str,
        actor_type: str,
        old_state: Optional[str] = None,
        new_state: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> None:
        now = self._now()
        audit = FaVerificationRequestAudit(
            id=self._new_id(),
            tenant_id=self._tenant_id,
            request_id=request_id,
            evidence_id=evidence_id,
            event_type=event_type,
            actor_id=actor_id,
            actor_type=actor_type,
            old_state=old_state,
            new_state=new_state,
            details=json.dumps(details, sort_keys=True) if details else None,
            occurred_at=now,
            created_at=now,
        )
        self._repo.create_audit(audit)

    def _emit_timeline_event(
        self,
        source_id: str,
        event_type: str,
        payload: dict,
    ) -> None:
        try:
            from services.governance.timeline import TimelineStore
            from services.governance.timeline.adapters import (
                verification_workflow_to_timeline_event,
            )

            store = TimelineStore()
            event = verification_workflow_to_timeline_event(
                tenant_id=self._tenant_id,
                source_id=source_id,
                event_type=event_type,
                occurred_at=self._now(),
                payload=payload,
                replay_eligible=False,
            )
            store.record(self._db, event)
        except Exception:
            pass  # never block workflow operations due to timeline failures

    def _compute_sla_status(
        self, row: FaVerificationRequest
    ) -> Optional[WorkflowSlaStatus]:
        """Compute overall SLA status from all due fields."""
        now_iso = self._now()
        fields = [
            row.review_due_at,
            row.decision_due_at,
            row.escalation_due_at,
            row.assigned_due_at,
        ]
        if all(f is None for f in fields):
            return None
        statuses = [_sla_status_for_field(f, now_iso) for f in fields if f is not None]
        if WorkflowSlaStatus.OVERDUE.value in statuses:
            return WorkflowSlaStatus.OVERDUE
        if WorkflowSlaStatus.DUE_SOON.value in statuses:
            return WorkflowSlaStatus.DUE_SOON
        return WorkflowSlaStatus.ON_TRACK

    def _to_request_response(
        self, row: FaVerificationRequest
    ) -> VerificationRequestResponse:
        return VerificationRequestResponse(
            id=row.id,
            tenant_id=row.tenant_id,
            evidence_id=row.evidence_id,
            workflow_state=row.workflow_state,
            requested_by=row.requested_by,
            requester_actor_type=row.requester_actor_type,
            requested_at=row.requested_at,
            assignee_id=row.assignee_id,
            assignee_type=row.assignee_type,
            assigned_at=row.assigned_at,
            priority=row.priority,
            notes=row.notes,
            review_due_at=row.review_due_at,
            decision_due_at=row.decision_due_at,
            escalation_due_at=row.escalation_due_at,
            assigned_due_at=row.assigned_due_at,
            completed_at=row.completed_at,
            cancelled_at=row.cancelled_at,
            expired_at=row.expired_at,
            escalation_count=row.escalation_count,
            last_escalation_type=row.last_escalation_type,
            last_escalated_at=row.last_escalated_at,
            last_escalated_by=row.last_escalated_by,
            created_at=row.created_at,
            updated_at=row.updated_at,
            sla_status=self._compute_sla_status(row),
        )

    def _to_queue_item(self, row: FaVerificationRequest) -> QueueItemResponse:
        now_iso = self._now()
        sla = _sla_status_for_field(row.review_due_at, now_iso)
        return QueueItemResponse(
            request_id=row.id,
            evidence_id=row.evidence_id,
            workflow_state=row.workflow_state,
            priority=row.priority,
            assignee_id=row.assignee_id,
            assignee_type=row.assignee_type,
            review_due_at=row.review_due_at,
            sla_status=sla,
        )

    def _update_evidence_trust_state(
        self,
        evidence_id: str,
        actor_id: str,
        actor_type: str,
        approved: bool,
    ) -> None:
        try:
            from services.evidence_authority.engine import EvidenceAuthorityEngine
            from services.evidence_authority.models import (
                EvidenceTrustState,
                VerificationSource,
            )
            from services.evidence_authority.schemas import VerifyEvidenceRequest

            ea_engine = EvidenceAuthorityEngine(self._db, tenant_id=self._tenant_id)
            to_trust_state = (
                EvidenceTrustState.VERIFIED if approved else EvidenceTrustState.DISPUTED
            )
            req = VerifyEvidenceRequest(
                to_trust_state=to_trust_state,
                verification_source=VerificationSource.HUMAN,
                verification_method="MANUAL_REVIEW",
                notes=f"Workflow {'approved' if approved else 'rejected'} by {actor_id}",
            )
            ea_engine.verify_evidence(
                evidence_id, req, actor_id=actor_id, actor_type=actor_type
            )
        except Exception:
            pass  # never block workflow operations due to evidence update failures

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def create_request(
        self,
        req: CreateVerificationRequestRequest,
        actor_id: str,
        actor_type: str,
    ) -> VerificationRequestResponse:
        if not req.evidence_id or not req.evidence_id.strip():
            raise ValueError("evidence_id must be non-empty")

        now = self._now()
        row = FaVerificationRequest(
            id=self._new_id(),
            tenant_id=self._tenant_id,
            evidence_id=req.evidence_id,
            workflow_state=VerificationWorkflowState.REQUESTED.value,
            requested_by=actor_id,
            requester_actor_type=actor_type,
            requested_at=now,
            priority=req.priority,
            notes=req.notes,
            review_due_at=req.review_due_at,
            decision_due_at=req.decision_due_at,
            escalation_count=0,
            created_at=now,
            updated_at=now,
        )
        self._repo.create_request(row)

        self._write_audit(
            request_id=row.id,
            evidence_id=row.evidence_id,
            event_type=VerificationRequestAuditEventType.CREATED.value,
            actor_id=actor_id,
            actor_type=actor_type,
            new_state=VerificationWorkflowState.REQUESTED.value,
            details={"evidence_id": req.evidence_id, "priority": req.priority},
        )

        self._emit_timeline_event(
            source_id=row.id,
            event_type="verification_request.created",
            payload={"evidence_id": req.evidence_id, "request_id": row.id},
        )

        self._db.commit()

        try:
            from api.observability.metrics import VERIFICATION_WORKFLOW_REQUESTS_TOTAL

            VERIFICATION_WORKFLOW_REQUESTS_TOTAL.inc()
        except Exception:
            pass

        self._db.refresh(row)
        return self._to_request_response(row)

    def get_request(self, request_id: str) -> VerificationRequestResponse:
        row = self._repo.get_request(request_id)
        if not row:
            raise VerificationRequestNotFound(f"Request {request_id!r} not found")
        return self._to_request_response(row)

    def list_requests(
        self,
        evidence_id: Optional[str] = None,
        workflow_state: Optional[str] = None,
        assignee_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> VerificationRequestListResponse:
        items, total = self._repo.list_requests(
            evidence_id=evidence_id,
            workflow_state=workflow_state,
            assignee_id=assignee_id,
            limit=limit,
            offset=offset,
        )
        return VerificationRequestListResponse(
            items=[self._to_request_response(r) for r in items],
            total=total,
        )

    def assign_verification(
        self,
        request_id: str,
        req: AssignVerificationRequest,
        actor_id: str,
        actor_type: str,
    ) -> VerificationRequestResponse:
        row = self._repo.get_request(request_id)
        if not row:
            raise VerificationRequestNotFound(f"Request {request_id!r} not found")

        valid_assign_states = {
            VerificationWorkflowState.REQUESTED.value,
            VerificationWorkflowState.QUEUED.value,
            VerificationWorkflowState.ASSIGNED.value,
        }
        if row.workflow_state not in valid_assign_states:
            raise VerificationWorkflowInvalidTransition(
                f"Cannot assign in state {row.workflow_state!r}"
            )

        is_reassignment = row.assignee_id is not None
        event_type = (
            VerificationRequestAuditEventType.REASSIGNED.value
            if is_reassignment
            else VerificationRequestAuditEventType.ASSIGNED.value
        )

        now = self._now()
        old_state = row.workflow_state

        row.assignee_id = req.assignee_id
        row.assignee_type = req.assignee_type.value
        row.assigned_at = now
        if req.assigned_due_at is not None:
            row.assigned_due_at = req.assigned_due_at
        row.updated_at = now

        if row.workflow_state in (
            VerificationWorkflowState.REQUESTED.value,
            VerificationWorkflowState.QUEUED.value,
        ):
            row.workflow_state = VerificationWorkflowState.ASSIGNED.value

        self._write_audit(
            request_id=row.id,
            evidence_id=row.evidence_id,
            event_type=event_type,
            actor_id=actor_id,
            actor_type=actor_type,
            old_state=old_state,
            new_state=row.workflow_state,
            details={
                "assignee_id": req.assignee_id,
                "assignee_type": req.assignee_type.value,
            },
        )

        self._emit_timeline_event(
            source_id=row.id,
            event_type=(
                "verification_request.reassigned"
                if is_reassignment
                else "verification_request.assigned"
            ),
            payload={"request_id": row.id, "assignee_id": req.assignee_id},
        )

        self._db.commit()
        self._db.refresh(row)
        return self._to_request_response(row)

    def transition_workflow(
        self,
        request_id: str,
        req: TransitionWorkflowRequest,
        actor_id: str,
        actor_type: str,
    ) -> VerificationRequestResponse:
        row = self._repo.get_request(request_id)
        if not row:
            raise VerificationRequestNotFound(f"Request {request_id!r} not found")

        try:
            validate_workflow_transition(row.workflow_state, req.to_state.value)
        except ValueError as exc:
            raise VerificationWorkflowInvalidTransition(str(exc)) from exc

        now = self._now()
        old_state = row.workflow_state
        new_state = req.to_state.value

        row.workflow_state = new_state
        row.updated_at = now

        # Mirror escalation bookkeeping so dashboards/audits do not under-report
        if new_state == VerificationWorkflowState.ESCALATED.value:
            row.escalation_count = (row.escalation_count or 0) + 1
            row.last_escalation_type = "MANUAL"
            row.last_escalated_at = now
            row.last_escalated_by = actor_id

        # Set terminal timestamps
        if new_state == VerificationWorkflowState.COMPLETED.value:
            row.completed_at = now
        elif new_state == VerificationWorkflowState.CANCELLED.value:
            row.cancelled_at = now
        elif new_state == VerificationWorkflowState.EXPIRED.value:
            row.expired_at = now

        # Map state → audit event type
        _state_to_event = {
            VerificationWorkflowState.QUEUED.value: VerificationRequestAuditEventType.QUEUED.value,
            VerificationWorkflowState.ASSIGNED.value: VerificationRequestAuditEventType.ASSIGNED.value,
            VerificationWorkflowState.IN_REVIEW.value: VerificationRequestAuditEventType.REVIEW_STARTED.value,
            VerificationWorkflowState.PENDING_INFORMATION.value: VerificationRequestAuditEventType.INFORMATION_REQUESTED.value,
            VerificationWorkflowState.APPROVED.value: VerificationRequestAuditEventType.APPROVED.value,
            VerificationWorkflowState.REJECTED.value: VerificationRequestAuditEventType.REJECTED.value,
            VerificationWorkflowState.ESCALATED.value: VerificationRequestAuditEventType.ESCALATED.value,
            VerificationWorkflowState.EXPIRED.value: VerificationRequestAuditEventType.EXPIRED.value,
            VerificationWorkflowState.CANCELLED.value: VerificationRequestAuditEventType.CANCELLED.value,
            VerificationWorkflowState.COMPLETED.value: VerificationRequestAuditEventType.COMPLETED.value,
        }
        event_type = _state_to_event.get(new_state, new_state)

        self._write_audit(
            request_id=row.id,
            evidence_id=row.evidence_id,
            event_type=event_type,
            actor_id=actor_id,
            actor_type=actor_type,
            old_state=old_state,
            new_state=new_state,
            details={"notes": req.notes} if req.notes else None,
        )

        # Map state → timeline event type
        _state_to_timeline = {
            VerificationWorkflowState.QUEUED.value: "verification_request.queued",
            VerificationWorkflowState.ASSIGNED.value: "verification_request.assigned",
            VerificationWorkflowState.IN_REVIEW.value: "verification_request.review_started",
            VerificationWorkflowState.PENDING_INFORMATION.value: "verification_request.information_requested",
            VerificationWorkflowState.APPROVED.value: "verification_request.approved",
            VerificationWorkflowState.REJECTED.value: "verification_request.rejected",
            VerificationWorkflowState.ESCALATED.value: "verification_request.escalated",
            VerificationWorkflowState.COMPLETED.value: "verification_request.completed",
        }
        timeline_event = _state_to_timeline.get(new_state)
        if timeline_event:
            self._emit_timeline_event(
                source_id=row.id,
                event_type=timeline_event,
                payload={
                    "request_id": row.id,
                    "old_state": old_state,
                    "new_state": new_state,
                },
            )

        # Evidence trust state integration
        if req.to_state in (
            VerificationWorkflowState.APPROVED,
            VerificationWorkflowState.COMPLETED,
        ):
            self._update_evidence_trust_state(
                row.evidence_id, actor_id, actor_type, approved=True
            )
        elif req.to_state == VerificationWorkflowState.REJECTED:
            self._update_evidence_trust_state(
                row.evidence_id, actor_id, actor_type, approved=False
            )

        self._db.commit()

        try:
            from api.observability.metrics import (
                VERIFICATION_WORKFLOW_TRANSITIONS_TOTAL,
            )

            VERIFICATION_WORKFLOW_TRANSITIONS_TOTAL.labels(to_state=new_state).inc()
        except Exception:
            pass

        if new_state == VerificationWorkflowState.APPROVED.value:
            try:
                from api.observability.metrics import (
                    VERIFICATION_WORKFLOW_APPROVALS_TOTAL,
                )

                VERIFICATION_WORKFLOW_APPROVALS_TOTAL.inc()
            except Exception:
                pass
        elif new_state == VerificationWorkflowState.REJECTED.value:
            try:
                from api.observability.metrics import (
                    VERIFICATION_WORKFLOW_REJECTIONS_TOTAL,
                )

                VERIFICATION_WORKFLOW_REJECTIONS_TOTAL.inc()
            except Exception:
                pass

        self._db.refresh(row)
        return self._to_request_response(row)

    def escalate_verification(
        self,
        request_id: str,
        req: EscalateVerificationRequest,
        actor_id: str,
        actor_type: str,
    ) -> VerificationRequestResponse:
        row = self._repo.get_request(request_id)
        if not row:
            raise VerificationRequestNotFound(f"Request {request_id!r} not found")

        valid_escalation_states = {
            VerificationWorkflowState.IN_REVIEW.value,
            VerificationWorkflowState.PENDING_INFORMATION.value,
        }
        if row.workflow_state not in valid_escalation_states:
            raise VerificationWorkflowInvalidTransition(
                f"Cannot escalate from state {row.workflow_state!r}; "
                f"allowed: {sorted(valid_escalation_states)}"
            )

        now = self._now()
        old_state = row.workflow_state

        row.workflow_state = VerificationWorkflowState.ESCALATED.value
        row.escalation_count = (row.escalation_count or 0) + 1
        row.last_escalation_type = req.escalation_type.value
        row.last_escalated_at = now
        row.last_escalated_by = actor_id
        row.updated_at = now

        self._write_audit(
            request_id=row.id,
            evidence_id=row.evidence_id,
            event_type=VerificationRequestAuditEventType.ESCALATED.value,
            actor_id=actor_id,
            actor_type=actor_type,
            old_state=old_state,
            new_state=VerificationWorkflowState.ESCALATED.value,
            details={
                "escalation_type": req.escalation_type.value,
                "escalation_notes": req.escalation_notes,
                "escalated_to": req.escalated_to,
            },
        )

        self._emit_timeline_event(
            source_id=row.id,
            event_type="verification_request.escalated",
            payload={
                "request_id": row.id,
                "escalation_type": req.escalation_type.value,
                "escalation_count": row.escalation_count,
            },
        )

        self._db.commit()

        try:
            from api.observability.metrics import (
                VERIFICATION_WORKFLOW_ESCALATIONS_TOTAL,
            )

            VERIFICATION_WORKFLOW_ESCALATIONS_TOTAL.labels(
                escalation_type=req.escalation_type.value
            ).inc()
        except Exception:
            pass

        self._db.refresh(row)
        return self._to_request_response(row)

    def record_result(
        self,
        request_id: str,
        req: RecordResultRequest,
        actor_id: str,
        actor_type: str,
    ) -> VerificationResultResponse:
        row = self._repo.get_request(request_id)
        if not row:
            raise VerificationRequestNotFound(f"Request {request_id!r} not found")

        valid_result_states = {
            VerificationWorkflowState.IN_REVIEW.value,
            VerificationWorkflowState.ESCALATED.value,
            VerificationWorkflowState.APPROVED.value,
        }
        if row.workflow_state not in valid_result_states:
            raise VerificationWorkflowInvalidTransition(
                f"Cannot record result in state {row.workflow_state!r}"
            )

        now = self._now()
        result_row = FaVerificationResult(
            id=self._new_id(),
            tenant_id=self._tenant_id,
            request_id=request_id,
            evidence_id=row.evidence_id,
            result=req.result,
            decided_by=actor_id,
            decider_actor_type=actor_type,
            decision_notes=req.decision_notes,
            decided_at=now,
            created_at=now,
        )
        self._repo.create_result(result_row)

        self._write_audit(
            request_id=row.id,
            evidence_id=row.evidence_id,
            event_type=VerificationRequestAuditEventType.RESULT_RECORDED.value,
            actor_id=actor_id,
            actor_type=actor_type,
            details={"result": req.result, "decision_notes": req.decision_notes},
        )

        self._emit_timeline_event(
            source_id=row.id,
            event_type=(
                "verification_request.approved"
                if req.result == "APPROVED"
                else "verification_request.rejected"
            ),
            payload={"request_id": row.id, "result": req.result},
        )

        self._db.commit()

        try:
            from api.observability.metrics import VERIFICATION_WORKFLOW_RESULTS_TOTAL

            VERIFICATION_WORKFLOW_RESULTS_TOTAL.labels(result=req.result).inc()
        except Exception:
            pass

        self._db.refresh(result_row)
        return VerificationResultResponse(
            id=result_row.id,
            tenant_id=result_row.tenant_id,
            request_id=result_row.request_id,
            evidence_id=result_row.evidence_id,
            result=result_row.result,
            decided_by=result_row.decided_by,
            decider_actor_type=result_row.decider_actor_type,
            decision_notes=result_row.decision_notes,
            decided_at=result_row.decided_at,
            created_at=result_row.created_at,
        )

    def set_sla_deadlines(
        self,
        request_id: str,
        req: SetWorkflowSlaRequest,
        actor_id: str,
        actor_type: str,
    ) -> WorkflowSlaStatusResponse:
        row = self._repo.get_request(request_id)
        if not row:
            raise VerificationRequestNotFound(f"Request {request_id!r} not found")

        now = self._now()
        if req.review_due_at is not None:
            row.review_due_at = req.review_due_at
        if req.decision_due_at is not None:
            row.decision_due_at = req.decision_due_at
        if req.escalation_due_at is not None:
            row.escalation_due_at = req.escalation_due_at
        if req.assigned_due_at is not None:
            row.assigned_due_at = req.assigned_due_at
        row.updated_at = now

        self._write_audit(
            request_id=row.id,
            evidence_id=row.evidence_id,
            event_type=VerificationRequestAuditEventType.SLA_SET.value,
            actor_id=actor_id,
            actor_type=actor_type,
            details={
                "review_due_at": req.review_due_at,
                "decision_due_at": req.decision_due_at,
                "escalation_due_at": req.escalation_due_at,
                "assigned_due_at": req.assigned_due_at,
            },
        )

        self._db.commit()

        try:
            from api.observability.metrics import (
                VERIFICATION_WORKFLOW_SLA_UPDATES_TOTAL,
            )

            VERIFICATION_WORKFLOW_SLA_UPDATES_TOTAL.inc()
        except Exception:
            pass

        self._db.refresh(row)
        return self._build_sla_status_response(row)

    def get_sla_status(self, request_id: str) -> WorkflowSlaStatusResponse:
        row = self._repo.get_request(request_id)
        if not row:
            raise VerificationRequestNotFound(f"Request {request_id!r} not found")
        return self._build_sla_status_response(row)

    def _build_sla_status_response(
        self, row: FaVerificationRequest
    ) -> WorkflowSlaStatusResponse:
        now_iso = self._now()
        review_status = _sla_status_for_field(row.review_due_at, now_iso)
        decision_status = _sla_status_for_field(row.decision_due_at, now_iso)
        escalation_status = _sla_status_for_field(row.escalation_due_at, now_iso)
        assigned_status = _sla_status_for_field(row.assigned_due_at, now_iso)

        overdue_fields = []
        if review_status == WorkflowSlaStatus.OVERDUE.value:
            overdue_fields.append("review_due_at")
        if decision_status == WorkflowSlaStatus.OVERDUE.value:
            overdue_fields.append("decision_due_at")
        if escalation_status == WorkflowSlaStatus.OVERDUE.value:
            overdue_fields.append("escalation_due_at")
        if assigned_status == WorkflowSlaStatus.OVERDUE.value:
            overdue_fields.append("assigned_due_at")

        return WorkflowSlaStatusResponse(
            request_id=row.id,
            review_sla_status=review_status,
            decision_sla_status=decision_status,
            escalation_sla_status=escalation_status,
            assigned_sla_status=assigned_status,
            overdue_fields=overdue_fields,
        )

    def get_queue(self, workflow_state: str, limit: int = 50) -> QueueResponse:
        items = self._repo.get_queue_by_state(workflow_state, limit)
        return QueueResponse(
            state=workflow_state,
            items=[self._to_queue_item(r) for r in items],
            total=len(items),
        )

    def list_audit_trail(
        self, request_id: str, limit: int = 100
    ) -> VerificationAuditListResponse:
        row = self._repo.get_request(request_id)
        if not row:
            raise VerificationRequestNotFound(f"Request {request_id!r} not found")

        audits = self._repo.list_audits(request_id, limit)
        return VerificationAuditListResponse(
            items=[
                VerificationAuditResponse(
                    id=a.id,
                    tenant_id=a.tenant_id,
                    request_id=a.request_id,
                    evidence_id=a.evidence_id,
                    event_type=a.event_type,
                    actor_id=a.actor_id,
                    actor_type=a.actor_type,
                    old_state=a.old_state,
                    new_state=a.new_state,
                    details=a.details,
                    occurred_at=a.occurred_at,
                    created_at=a.created_at,
                )
                for a in audits
            ],
            total=len(audits),
            request_id=request_id,
        )

    def get_dashboard_metrics(self) -> WorkflowDashboardResponse:
        by_state = self._repo.count_by_state()
        now_iso = self._now()
        overdue_count = self._repo.count_overdue(now_iso)
        unassigned_count = self._repo.count_unassigned()
        escalated_count = self._repo.count_escalated()

        all_rows = self._repo.list_all_for_avg_priority()
        total_requests = len(all_rows)
        avg_priority = (
            sum(r.priority for r in all_rows) / total_requests
            if total_requests > 0
            else 0.0
        )
        completed_count = sum(1 for r in all_rows if r.completed_at is not None)

        # due_soon: any non-terminal row with review_due_at or decision_due_at within 7 days
        due_soon_count = 0
        terminal_values = [s.value for s in TERMINAL_WORKFLOW_STATES]
        for r in all_rows:
            if r.workflow_state in terminal_values:
                continue
            review_status = _sla_status_for_field(r.review_due_at, now_iso)
            decision_status = _sla_status_for_field(r.decision_due_at, now_iso)
            if (
                review_status == WorkflowSlaStatus.DUE_SOON.value
                or decision_status == WorkflowSlaStatus.DUE_SOON.value
            ):
                due_soon_count += 1

        return WorkflowDashboardResponse(
            total_requests=total_requests,
            by_state=by_state,
            overdue_count=overdue_count,
            due_soon_count=due_soon_count,
            avg_priority=avg_priority,
            unassigned_count=unassigned_count,
            escalated_count=escalated_count,
            completed_count=completed_count,
        )

    def get_cgin_snapshot(self) -> WorkflowCginSnapshot:
        now_iso = self._now()
        by_state = self._repo.count_by_state()
        overdue_count = self._repo.count_overdue(now_iso)
        escalated_count = self._repo.count_escalated()

        from datetime import timedelta

        since_30d = (datetime.now(tz=timezone.utc) - timedelta(days=30)).isoformat()
        completed_last_30d = self._repo.count_completed_last_30d(since_30d)

        total_requests = sum(by_state.values())

        return WorkflowCginSnapshot(
            snapshot_at=now_iso,
            tenant_fingerprint=fingerprint_tenant(self._tenant_id),
            total_requests=total_requests,
            by_state=by_state,
            overdue_count=overdue_count,
            escalated_count=escalated_count,
            completed_last_30d=completed_last_30d,
        )
