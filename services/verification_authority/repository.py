"""services/verification_authority/repository.py — Data access layer for Verification Workflow Authority.

All queries are tenant-scoped. No query path bypasses tenant_id.
This layer is the only code that touches fa_verification_request* tables directly.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from api.db_models_verification_authority import (
    FaVerificationRequest,
    FaVerificationRequestAudit,
    FaVerificationResult,
)
from services.verification_authority.models import (
    TERMINAL_WORKFLOW_STATES,
    VerificationWorkflowState,
)

_TERMINAL_STATE_VALUES = [s.value for s in TERMINAL_WORKFLOW_STATES]


class VerificationWorkflowRepository:
    """Tenant-scoped data access for fa_verification_request* tables."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    # ------------------------------------------------------------------
    # fa_verification_requests
    # ------------------------------------------------------------------

    def create_request(self, row: FaVerificationRequest) -> None:
        self._db.add(row)
        self._db.flush()

    def get_request(self, request_id: str) -> Optional[FaVerificationRequest]:
        return (
            self._db.query(FaVerificationRequest)
            .filter(
                FaVerificationRequest.id == request_id,
                FaVerificationRequest.tenant_id == self._tenant_id,
            )
            .first()
        )

    def save_request(self, row: FaVerificationRequest) -> None:
        self._db.add(row)
        self._db.merge(row)

    def list_requests(
        self,
        evidence_id: Optional[str],
        workflow_state: Optional[str],
        assignee_id: Optional[str],
        limit: int,
        offset: int,
    ) -> tuple[list[FaVerificationRequest], int]:
        q = self._db.query(FaVerificationRequest).filter(
            FaVerificationRequest.tenant_id == self._tenant_id
        )
        if evidence_id is not None:
            q = q.filter(FaVerificationRequest.evidence_id == evidence_id)
        if workflow_state is not None:
            q = q.filter(FaVerificationRequest.workflow_state == workflow_state)
        if assignee_id is not None:
            q = q.filter(FaVerificationRequest.assignee_id == assignee_id)
        total = q.count()
        items = (
            q.order_by(FaVerificationRequest.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total

    # ------------------------------------------------------------------
    # fa_verification_results
    # ------------------------------------------------------------------

    def create_result(self, row: FaVerificationResult) -> None:
        self._db.add(row)
        self._db.flush()

    def list_results(self, request_id: str) -> list[FaVerificationResult]:
        return (
            self._db.query(FaVerificationResult)
            .filter(
                FaVerificationResult.tenant_id == self._tenant_id,
                FaVerificationResult.request_id == request_id,
            )
            .order_by(FaVerificationResult.created_at.desc())
            .all()
        )

    # ------------------------------------------------------------------
    # fa_verification_request_audits
    # ------------------------------------------------------------------

    def create_audit(self, row: FaVerificationRequestAudit) -> None:
        self._db.add(row)
        self._db.flush()

    def list_audits(
        self, request_id: str, limit: int
    ) -> list[FaVerificationRequestAudit]:
        return (
            self._db.query(FaVerificationRequestAudit)
            .filter(
                FaVerificationRequestAudit.tenant_id == self._tenant_id,
                FaVerificationRequestAudit.request_id == request_id,
            )
            .order_by(FaVerificationRequestAudit.occurred_at.asc())
            .limit(limit)
            .all()
        )

    # ------------------------------------------------------------------
    # Queue & aggregation
    # ------------------------------------------------------------------

    def get_queue_by_state(
        self, workflow_state: str, limit: int
    ) -> list[FaVerificationRequest]:
        return (
            self._db.query(FaVerificationRequest)
            .filter(
                FaVerificationRequest.tenant_id == self._tenant_id,
                FaVerificationRequest.workflow_state == workflow_state,
            )
            .order_by(FaVerificationRequest.priority.desc())
            .limit(limit)
            .all()
        )

    def count_by_state(self) -> dict[str, int]:
        rows = (
            self._db.query(
                FaVerificationRequest.workflow_state,
                func.count(FaVerificationRequest.id),
            )
            .filter(FaVerificationRequest.tenant_id == self._tenant_id)
            .group_by(FaVerificationRequest.workflow_state)
            .all()
        )
        return {state: count for state, count in rows}

    def count_overdue(self, now_iso: str) -> int:
        """Count requests where any of the four due fields is past now and state is not terminal."""
        from sqlalchemy import or_

        return (
            self._db.query(FaVerificationRequest)
            .filter(
                FaVerificationRequest.tenant_id == self._tenant_id,
                FaVerificationRequest.workflow_state.notin_(_TERMINAL_STATE_VALUES),
                or_(
                    (FaVerificationRequest.review_due_at != None)  # noqa: E711
                    & (FaVerificationRequest.review_due_at < now_iso),
                    (FaVerificationRequest.decision_due_at != None)  # noqa: E711
                    & (FaVerificationRequest.decision_due_at < now_iso),
                    (FaVerificationRequest.escalation_due_at != None)  # noqa: E711
                    & (FaVerificationRequest.escalation_due_at < now_iso),
                    (FaVerificationRequest.assigned_due_at != None)  # noqa: E711
                    & (FaVerificationRequest.assigned_due_at < now_iso),
                ),
            )
            .count()
        )

    def count_unassigned(self) -> int:
        """Count requests in REQUESTED or QUEUED with no assignee."""
        return (
            self._db.query(FaVerificationRequest)
            .filter(
                FaVerificationRequest.tenant_id == self._tenant_id,
                FaVerificationRequest.workflow_state.in_(
                    [
                        VerificationWorkflowState.REQUESTED.value,
                        VerificationWorkflowState.QUEUED.value,
                    ]
                ),
                FaVerificationRequest.assignee_id == None,  # noqa: E711
            )
            .count()
        )

    def count_escalated(self) -> int:
        return (
            self._db.query(FaVerificationRequest)
            .filter(
                FaVerificationRequest.tenant_id == self._tenant_id,
                FaVerificationRequest.workflow_state
                == VerificationWorkflowState.ESCALATED.value,
            )
            .count()
        )

    def count_completed_last_30d(self, since_iso: str) -> int:
        return (
            self._db.query(FaVerificationRequest)
            .filter(
                FaVerificationRequest.tenant_id == self._tenant_id,
                FaVerificationRequest.workflow_state
                == VerificationWorkflowState.COMPLETED.value,
                FaVerificationRequest.completed_at != None,  # noqa: E711
                FaVerificationRequest.completed_at >= since_iso,
            )
            .count()
        )

    def list_all_for_avg_priority(self) -> list[FaVerificationRequest]:
        return (
            self._db.query(FaVerificationRequest)
            .filter(FaVerificationRequest.tenant_id == self._tenant_id)
            .all()
        )
