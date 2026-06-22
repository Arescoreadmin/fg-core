# services/risk_governance/engine.py
"""Risk Governance Engine — PR 14.2.

All public methods are tenant-scoped. Caller (route handler) owns db.commit().

Bounded context separation:
  services/risk_acceptance/ — owns governance records (the decision)
  services/risk_governance/ — owns governance workflows (the process)

Approval lifecycle:
  PENDING → APPROVED | REJECTED | EXPIRED | REVOKED

Review lifecycle:
  PENDING → COMPLETED | WAIVED | OVERDUE (automatic)

Escalations are append-only governance signals; not a state machine.
"""

from __future__ import annotations
from datetime import datetime, timezone

import uuid
from typing import Any

from sqlalchemy.orm import Session

from api.db_models_risk_governance import (
    RiskAcceptanceApproval,
    RiskAcceptanceApprovalAudit,
    RiskApprovalPolicy,
    RiskGovernanceEscalation,
    RiskReview,
)
from api.observability.metrics import (
    RISK_APPROVALS_GRANTED_TOTAL,
    RISK_APPROVALS_REJECTED_TOTAL,
    RISK_APPROVALS_TOTAL,
    RISK_GOVERNANCE_ESCALATIONS_TOTAL,
    RISK_REVIEWS_COMPLETED_TOTAL,
    RISK_REVIEWS_OVERDUE_TOTAL,
    RISK_REVIEWS_TOTAL,
)
from services.canonical import utc_iso8601_z_now
from services.governance.timeline.identity import derive_event_id
from services.governance.timeline.models import SourceType, TimelineEvent
from services.governance.timeline.store import TimelineStore
from services.notifications.engine import NotificationEngine
from services.notifications.schemas import NotificationTrigger
from services.risk_governance.repository import (
    assert_risk_acceptance_owned,
    count_approvals,
    count_approval_audits,
    count_escalations,
    count_overdue_reviews,
    count_pending_approvals,
    count_policies,
    count_reviews,
    count_unresolved_escalations,
    fetch_approval,
    fetch_approval_audits,
    fetch_approvals,
    fetch_escalations,
    fetch_expired_pending_approvals,
    fetch_overdue_pending_reviews,
    fetch_policies,
    fetch_policy,
    fetch_review,
    fetch_reviews,
    insert_approval,
    insert_approval_audit,
    insert_escalation,
    insert_policy,
    insert_review,
    snapshot_approval,
)
from services.risk_governance.schemas import (
    APPROVAL_ALLOWED_TRANSITIONS,
    ApprovalAuditListResponse,
    ApprovalAuditResponse,
    ApprovalDecisionRequest,
    ApprovalInvalidTransition,
    ApprovalListResponse,
    ApprovalNotFound,
    ApprovalResponse,
    ApprovalStatus,
    CompleteReviewRequest,
    CreateApprovalRequest,
    CreatePolicyRequest,
    CreateReviewRequest,
    EscalationLevel,
    EscalationListResponse,
    EscalationResponse,
    EscalationTrigger,
    GovernanceDashboardResponse,
    GovernanceEventType,
    PolicyListResponse,
    PolicyNotFound,
    PolicyResponse,
    ReviewConflict,
    ReviewListResponse,
    ReviewNotFound,
    ReviewResponse,
    ReviewStatus,
    TERMINAL_APPROVAL_STATUSES,
)

_timeline_store = TimelineStore()


def _new_id() -> str:
    return uuid.uuid4().hex


def _now() -> str:
    return utc_iso8601_z_now()


class GovernanceEngine:
    """Risk Governance Engine — authoritative service layer for PR 14.2."""

    def __init__(self, db: Session, *, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    # -----------------------------------------------------------------------
    # Approval workflow
    # -----------------------------------------------------------------------

    def create_approval(
        self,
        risk_acceptance_id: str,
        request: CreateApprovalRequest,
        *,
        actor: str,
        notification_recipient: str | None = None,
    ) -> ApprovalResponse:
        assert_risk_acceptance_owned(
            self._db, tenant_id=self._tenant_id, risk_acceptance_id=risk_acceptance_id
        )
        now = _now()
        approval = RiskAcceptanceApproval(
            id=_new_id(),
            tenant_id=self._tenant_id,
            risk_acceptance_id=risk_acceptance_id,
            approver_name=request.approver_name,
            approver_email=request.approver_email,
            approver_role=request.approver_role,
            approval_authority=request.approval_authority,
            approval_type=request.approval_type.value,
            status=ApprovalStatus.PENDING.value,
            comments=request.comments,
            approved_at=None,
            expires_at=request.expires_at,
            quorum_required=request.quorum_required,
            quorum_position=request.quorum_position,
            is_required=request.is_required,
            created_at=now,
            updated_at=now,
        )
        insert_approval(self._db, approval=approval)

        self._emit_approval_audit(
            approval,
            event_type=GovernanceEventType.APPROVAL_REQUESTED.value,
            actor=actor,
            old_state=None,
            new_state=snapshot_approval(approval),
        )
        self._emit_timeline(
            risk_acceptance_id=risk_acceptance_id,
            event_type=GovernanceEventType.APPROVAL_REQUESTED.value,
            payload={
                "approval_id": approval.id,
                "approver_name": approval.approver_name,
            },
        )
        RISK_APPROVALS_TOTAL.inc()

        if notification_recipient:
            try:
                ne = NotificationEngine(self._db, tenant_id=self._tenant_id)
                ne.notify(
                    task_id=risk_acceptance_id,
                    trigger=NotificationTrigger.RISK_APPROVAL_PENDING,
                    recipient=notification_recipient,
                    metadata={
                        "approval_id": approval.id,
                        "approver_name": approval.approver_name,
                    },
                )
            except Exception:
                pass

        return self._approval_response(approval)

    def decide_approval(
        self,
        risk_acceptance_id: str,
        approval_id: str,
        request: ApprovalDecisionRequest,
        *,
        actor: str,
        notification_recipient: str | None = None,
    ) -> ApprovalResponse:
        assert_risk_acceptance_owned(
            self._db, tenant_id=self._tenant_id, risk_acceptance_id=risk_acceptance_id
        )
        approval = fetch_approval(
            self._db, tenant_id=self._tenant_id, approval_id=approval_id
        )
        if approval is None or approval.risk_acceptance_id != risk_acceptance_id:
            raise ApprovalNotFound(f"approval_id={approval_id!r} not found.")

        current = ApprovalStatus(approval.status)
        target = request.decision

        if target not in {
            ApprovalStatus.APPROVED,
            ApprovalStatus.REJECTED,
            ApprovalStatus.REVOKED,
        }:
            raise ApprovalInvalidTransition(
                f"decision must be APPROVED, REJECTED, or REVOKED, got {target.value!r}."
            )
        if current in TERMINAL_APPROVAL_STATUSES:
            raise ApprovalInvalidTransition(
                f"approval is in terminal state {current.value!r}; no further transitions."
            )
        if target not in APPROVAL_ALLOWED_TRANSITIONS.get(current, set()):
            raise ApprovalInvalidTransition(
                f"transition {current.value!r} → {target.value!r} is not allowed."
            )

        old_state = snapshot_approval(approval)
        now = _now()
        approval.status = target.value
        approval.updated_at = now
        if request.comments:
            approval.comments = request.comments
        if target == ApprovalStatus.APPROVED:
            approval.approved_at = now
            RISK_APPROVALS_GRANTED_TOTAL.inc()
        elif target == ApprovalStatus.REJECTED:
            RISK_APPROVALS_REJECTED_TOTAL.inc()

        self._db.flush()

        if target == ApprovalStatus.APPROVED:
            audit_event = GovernanceEventType.APPROVAL_GRANTED.value
        elif target == ApprovalStatus.REJECTED:
            audit_event = GovernanceEventType.APPROVAL_REJECTED.value
        else:
            audit_event = GovernanceEventType.APPROVAL_REVOKED.value

        self._emit_approval_audit(
            approval,
            event_type=audit_event,
            actor=actor,
            old_state=old_state,
            new_state=snapshot_approval(approval),
            reason=request.reason,
        )
        self._emit_timeline(
            risk_acceptance_id=risk_acceptance_id,
            event_type=audit_event,
            payload={"approval_id": approval.id, "decision": target.value},
        )

        if notification_recipient:
            if target == ApprovalStatus.APPROVED:
                trigger = NotificationTrigger.RISK_APPROVAL_GRANTED
            elif target == ApprovalStatus.REJECTED:
                trigger = NotificationTrigger.RISK_APPROVAL_REJECTED
            else:
                trigger = None
            if trigger is not None:
                try:
                    ne = NotificationEngine(self._db, tenant_id=self._tenant_id)
                    ne.notify(
                        task_id=risk_acceptance_id,
                        trigger=trigger,
                        recipient=notification_recipient,
                        metadata={"approval_id": approval.id},
                    )
                except Exception:
                    pass

        return self._approval_response(approval)

    def list_approvals(
        self,
        risk_acceptance_id: str,
        *,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> ApprovalListResponse:
        assert_risk_acceptance_owned(
            self._db, tenant_id=self._tenant_id, risk_acceptance_id=risk_acceptance_id
        )
        items = fetch_approvals(
            self._db,
            tenant_id=self._tenant_id,
            risk_acceptance_id=risk_acceptance_id,
            status=status,
            limit=limit,
            offset=offset,
        )
        total = count_approvals(
            self._db,
            tenant_id=self._tenant_id,
            risk_acceptance_id=risk_acceptance_id,
            status=status,
        )
        return ApprovalListResponse(
            items=[self._approval_response(a) for a in items],
            total=total,
        )

    def get_approval(
        self, risk_acceptance_id: str, approval_id: str
    ) -> ApprovalResponse:
        assert_risk_acceptance_owned(
            self._db, tenant_id=self._tenant_id, risk_acceptance_id=risk_acceptance_id
        )
        approval = fetch_approval(
            self._db, tenant_id=self._tenant_id, approval_id=approval_id
        )
        if approval is None or approval.risk_acceptance_id != risk_acceptance_id:
            raise ApprovalNotFound(f"approval_id={approval_id!r} not found.")
        return self._approval_response(approval)

    def get_approval_audit(
        self,
        risk_acceptance_id: str,
        approval_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> ApprovalAuditListResponse:
        assert_risk_acceptance_owned(
            self._db, tenant_id=self._tenant_id, risk_acceptance_id=risk_acceptance_id
        )
        approval = fetch_approval(
            self._db, tenant_id=self._tenant_id, approval_id=approval_id
        )
        if approval is None or approval.risk_acceptance_id != risk_acceptance_id:
            raise ApprovalNotFound(f"approval_id={approval_id!r} not found.")
        items = fetch_approval_audits(
            self._db,
            tenant_id=self._tenant_id,
            approval_id=approval_id,
            limit=limit,
            offset=offset,
        )
        total = count_approval_audits(
            self._db, tenant_id=self._tenant_id, approval_id=approval_id
        )
        return ApprovalAuditListResponse(
            items=[
                ApprovalAuditResponse(
                    id=a.id,
                    tenant_id=a.tenant_id,
                    approval_id=a.approval_id,
                    risk_acceptance_id=a.risk_acceptance_id,
                    event_type=a.event_type,
                    actor=a.actor,
                    old_state=a.old_state,
                    new_state=a.new_state,
                    reason=a.reason,
                    event_at=a.event_at,
                )
                for a in items
            ],
            total=total,
        )

    def expire_overdue_approvals(self, *, actor: str) -> int:
        """Expire all PENDING approvals whose expires_at has passed. Returns count."""
        now = _now()
        expired = fetch_expired_pending_approvals(
            self._db, tenant_id=self._tenant_id, now_iso=now
        )
        for approval in expired:
            old_state = snapshot_approval(approval)
            approval.status = ApprovalStatus.EXPIRED.value
            approval.updated_at = now
            self._db.flush()
            self._emit_approval_audit(
                approval,
                event_type=GovernanceEventType.APPROVAL_EXPIRED.value,
                actor=actor,
                old_state=old_state,
                new_state=snapshot_approval(approval),
                reason="Automatic expiration — approval expires_at reached.",
            )
            self._emit_timeline(
                risk_acceptance_id=approval.risk_acceptance_id,
                event_type=GovernanceEventType.APPROVAL_EXPIRED.value,
                payload={"approval_id": approval.id},
            )
        return len(expired)

    # -----------------------------------------------------------------------
    # Policy management
    # -----------------------------------------------------------------------

    def create_policy(
        self, request: CreatePolicyRequest, *, actor: str
    ) -> PolicyResponse:
        now = _now()
        policy = RiskApprovalPolicy(
            id=_new_id(),
            tenant_id=self._tenant_id,
            policy_name=request.policy_name,
            description=request.description,
            active=True,
            approval_threshold=request.approval_threshold.value,
            required_roles=request.required_roles,
            required_count=request.required_count,
            quorum_percentage=request.quorum_percentage,
            auto_expire_days=request.auto_expire_days,
            review_frequency_days=request.review_frequency_days,
            sequential=request.sequential,
            created_at=now,
            updated_at=now,
        )
        insert_policy(self._db, policy=policy)
        return self._policy_response(policy)

    def list_policies(
        self,
        *,
        active_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> PolicyListResponse:
        items = fetch_policies(
            self._db,
            tenant_id=self._tenant_id,
            active_only=active_only,
            limit=limit,
            offset=offset,
        )
        total = count_policies(
            self._db, tenant_id=self._tenant_id, active_only=active_only
        )
        return PolicyListResponse(
            items=[self._policy_response(p) for p in items],
            total=total,
        )

    def get_policy(self, policy_id: str) -> PolicyResponse:
        policy = fetch_policy(self._db, tenant_id=self._tenant_id, policy_id=policy_id)
        if policy is None:
            raise PolicyNotFound(f"policy_id={policy_id!r} not found.")
        return self._policy_response(policy)

    # -----------------------------------------------------------------------
    # Review workflow
    # -----------------------------------------------------------------------

    def create_review(
        self,
        risk_acceptance_id: str,
        request: CreateReviewRequest,
        *,
        actor: str,
        notification_recipient: str | None = None,
    ) -> ReviewResponse:
        assert_risk_acceptance_owned(
            self._db, tenant_id=self._tenant_id, risk_acceptance_id=risk_acceptance_id
        )
        now = _now()
        review = RiskReview(
            id=_new_id(),
            tenant_id=self._tenant_id,
            risk_acceptance_id=risk_acceptance_id,
            review_type=request.review_type.value,
            reviewer=request.reviewer,
            status=ReviewStatus.PENDING.value,
            review_due_at=request.review_due_at,
            review_completed_at=None,
            review_notes=request.review_notes,
            outcome=None,
            created_at=now,
            updated_at=now,
        )
        insert_review(self._db, review=review)

        self._emit_timeline(
            risk_acceptance_id=risk_acceptance_id,
            event_type=GovernanceEventType.REVIEW_CREATED.value,
            payload={
                "review_id": review.id,
                "review_type": review.review_type,
                "review_due_at": review.review_due_at,
            },
        )
        RISK_REVIEWS_TOTAL.inc()

        if notification_recipient:
            try:
                ne = NotificationEngine(self._db, tenant_id=self._tenant_id)
                ne.notify(
                    task_id=risk_acceptance_id,
                    trigger=NotificationTrigger.RISK_REVIEW_DUE,
                    recipient=notification_recipient,
                    metadata={
                        "review_id": review.id,
                        "review_due_at": review.review_due_at,
                    },
                )
            except Exception:
                pass

        return self._review_response(review)

    def complete_review(
        self,
        risk_acceptance_id: str,
        review_id: str,
        request: CompleteReviewRequest,
        *,
        actor: str,
        notification_recipient: str | None = None,
    ) -> ReviewResponse:
        assert_risk_acceptance_owned(
            self._db, tenant_id=self._tenant_id, risk_acceptance_id=risk_acceptance_id
        )
        review = fetch_review(self._db, tenant_id=self._tenant_id, review_id=review_id)
        if review is None or review.risk_acceptance_id != risk_acceptance_id:
            raise ReviewNotFound(f"review_id={review_id!r} not found.")

        current = ReviewStatus(review.status)
        if current in {ReviewStatus.COMPLETED, ReviewStatus.WAIVED}:
            raise ReviewConflict(
                f"review is already in terminal state {current.value!r}."
            )
        if request.status not in {ReviewStatus.COMPLETED, ReviewStatus.WAIVED}:
            raise ReviewConflict(
                f"status must be COMPLETED or WAIVED, got {request.status.value!r}."
            )

        now = _now()
        review.status = request.status.value
        review.review_completed_at = now
        review.updated_at = now
        if request.outcome:
            review.outcome = request.outcome.value
        if request.review_notes:
            review.review_notes = request.review_notes
        if request.reviewer:
            review.reviewer = request.reviewer
        self._db.flush()

        event_type = (
            GovernanceEventType.REVIEW_COMPLETED.value
            if request.status == ReviewStatus.COMPLETED
            else GovernanceEventType.REVIEW_WAIVED.value
        )
        self._emit_timeline(
            risk_acceptance_id=risk_acceptance_id,
            event_type=event_type,
            payload={"review_id": review.id, "outcome": review.outcome},
        )
        RISK_REVIEWS_COMPLETED_TOTAL.inc()

        if notification_recipient:
            try:
                ne = NotificationEngine(self._db, tenant_id=self._tenant_id)
                ne.notify(
                    task_id=risk_acceptance_id,
                    trigger=NotificationTrigger.RISK_REVIEW_COMPLETED,
                    recipient=notification_recipient,
                    metadata={"review_id": review.id},
                )
            except Exception:
                pass

        return self._review_response(review)

    def list_reviews(
        self,
        risk_acceptance_id: str,
        *,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> ReviewListResponse:
        assert_risk_acceptance_owned(
            self._db, tenant_id=self._tenant_id, risk_acceptance_id=risk_acceptance_id
        )
        items = fetch_reviews(
            self._db,
            tenant_id=self._tenant_id,
            risk_acceptance_id=risk_acceptance_id,
            status=status,
            limit=limit,
            offset=offset,
        )
        total = count_reviews(
            self._db,
            tenant_id=self._tenant_id,
            risk_acceptance_id=risk_acceptance_id,
            status=status,
        )
        return ReviewListResponse(
            items=[self._review_response(r) for r in items],
            total=total,
        )

    def get_review(self, risk_acceptance_id: str, review_id: str) -> ReviewResponse:
        assert_risk_acceptance_owned(
            self._db, tenant_id=self._tenant_id, risk_acceptance_id=risk_acceptance_id
        )
        review = fetch_review(self._db, tenant_id=self._tenant_id, review_id=review_id)
        if review is None or review.risk_acceptance_id != risk_acceptance_id:
            raise ReviewNotFound(f"review_id={review_id!r} not found.")
        return self._review_response(review)

    def mark_overdue_reviews(self, *, actor: str) -> int:
        """Mark PENDING reviews past their due date as OVERDUE. Returns count."""
        now = _now()
        overdue = fetch_overdue_pending_reviews(
            self._db, tenant_id=self._tenant_id, now_iso=now
        )
        for review in overdue:
            review.status = ReviewStatus.OVERDUE.value
            review.updated_at = now
            self._db.flush()
            self._emit_timeline(
                risk_acceptance_id=review.risk_acceptance_id,
                event_type=GovernanceEventType.REVIEW_OVERDUE.value,
                payload={"review_id": review.id, "review_due_at": review.review_due_at},
            )
            RISK_REVIEWS_OVERDUE_TOTAL.inc()
        return len(overdue)

    # -----------------------------------------------------------------------
    # Escalation management
    # -----------------------------------------------------------------------

    def create_escalation(
        self,
        risk_acceptance_id: str,
        *,
        trigger: EscalationTrigger,
        level: EscalationLevel,
        actor: str,
        details: dict[str, Any] | None = None,
        notification_recipient: str | None = None,
    ) -> EscalationResponse:
        assert_risk_acceptance_owned(
            self._db, tenant_id=self._tenant_id, risk_acceptance_id=risk_acceptance_id
        )
        now = _now()
        escalation = RiskGovernanceEscalation(
            id=_new_id(),
            tenant_id=self._tenant_id,
            risk_acceptance_id=risk_acceptance_id,
            trigger=trigger.value,
            level=level.value,
            details=details or {},
            actor=actor,
            resolved=False,
            resolved_at=None,
            resolved_by=None,
            created_at=now,
        )
        insert_escalation(self._db, escalation=escalation)

        self._emit_timeline(
            risk_acceptance_id=risk_acceptance_id,
            event_type=GovernanceEventType.ESCALATION_CREATED.value,
            payload={
                "escalation_id": escalation.id,
                "trigger": trigger.value,
                "level": level.value,
            },
        )
        RISK_GOVERNANCE_ESCALATIONS_TOTAL.inc()

        if notification_recipient:
            try:
                ne = NotificationEngine(self._db, tenant_id=self._tenant_id)
                ne.notify(
                    task_id=risk_acceptance_id,
                    trigger=NotificationTrigger.RISK_ESCALATED,
                    recipient=notification_recipient,
                    metadata={"escalation_id": escalation.id, "level": level.value},
                )
            except Exception:
                pass

        return self._escalation_response(escalation)

    def list_escalations(
        self,
        risk_acceptance_id: str,
        *,
        resolved: bool | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> EscalationListResponse:
        assert_risk_acceptance_owned(
            self._db, tenant_id=self._tenant_id, risk_acceptance_id=risk_acceptance_id
        )
        items = fetch_escalations(
            self._db,
            tenant_id=self._tenant_id,
            risk_acceptance_id=risk_acceptance_id,
            resolved=resolved,
            limit=limit,
            offset=offset,
        )
        total = count_escalations(
            self._db,
            tenant_id=self._tenant_id,
            risk_acceptance_id=risk_acceptance_id,
            resolved=resolved,
        )
        return EscalationListResponse(
            items=[self._escalation_response(e) for e in items],
            total=total,
        )

    # -----------------------------------------------------------------------
    # Dashboard readiness
    # -----------------------------------------------------------------------

    def governance_dashboard(self) -> GovernanceDashboardResponse:
        """Return governance KPIs for dashboard readiness (PR 14.2)."""
        pending_approvals = count_pending_approvals(self._db, tenant_id=self._tenant_id)
        overdue_reviews = count_overdue_reviews(self._db, tenant_id=self._tenant_id)
        unresolved_escalations = count_unresolved_escalations(
            self._db, tenant_id=self._tenant_id
        )

        from api.db_models_risk_acceptance import RiskAcceptance

        now_str = _now()
        now_dt = datetime.fromisoformat(now_str)

        expired_risks = (
            self._db.query(RiskAcceptance)
            .filter(
                RiskAcceptance.tenant_id == self._tenant_id,
                RiskAcceptance.status == "expired",
            )
            .count()
        )

        threshold_30 = "2099-01-01T00:00:00+00:00"
        try:
            from datetime import timedelta

            t30 = (now_dt + timedelta(days=30)).isoformat()
            threshold_30 = t30
        except Exception:
            pass

        candidates = (
            self._db.query(RiskAcceptance)
            .filter(
                RiskAcceptance.tenant_id == self._tenant_id,
                RiskAcceptance.status == "active",
                RiskAcceptance.expires_at.isnot(None),
            )
            .all()
        )
        upcoming_30 = 0
        for ra in candidates:
            expires_at = ra.expires_at
            if expires_at is None:
                continue
            try:
                exp_dt = datetime.fromisoformat(expires_at)
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                if now_dt <= exp_dt <= datetime.fromisoformat(threshold_30):
                    upcoming_30 += 1
            except (ValueError, TypeError):
                pass

        debt = pending_approvals * 2 + overdue_reviews * 3 + unresolved_escalations * 5
        return GovernanceDashboardResponse(
            tenant_id=self._tenant_id,
            pending_approvals=pending_approvals,
            overdue_reviews=overdue_reviews,
            unresolved_escalations=unresolved_escalations,
            expired_risks=expired_risks,
            upcoming_expirations_30d=upcoming_30,
            governance_debt_score=debt,
        )

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _emit_approval_audit(
        self,
        approval: RiskAcceptanceApproval,
        *,
        event_type: str,
        actor: str,
        old_state: dict[str, Any] | None,
        new_state: dict[str, Any] | None,
        reason: str | None = None,
    ) -> None:
        audit = RiskAcceptanceApprovalAudit(
            id=_new_id(),
            tenant_id=self._tenant_id,
            approval_id=approval.id,
            risk_acceptance_id=approval.risk_acceptance_id,
            event_type=event_type,
            actor=actor,
            old_state=old_state,
            new_state=new_state,
            reason=reason,
            event_at=_now(),
        )
        insert_approval_audit(self._db, audit=audit)

    def _emit_timeline(
        self,
        *,
        risk_acceptance_id: str,
        event_type: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        now = _now()
        event_id = derive_event_id(
            tenant_id=self._tenant_id,
            source_type=SourceType.RISK_GOVERNANCE.value,
            source_id=risk_acceptance_id,
            event_type=event_type,
            occurred_at=now,
        )
        event = TimelineEvent(
            event_id=event_id,
            tenant_id=self._tenant_id,
            source_type=SourceType.RISK_GOVERNANCE,
            source_id=risk_acceptance_id,
            event_type=event_type,
            occurred_at=now,
            recorded_at=now,
            payload=payload or {},
            replay_eligible=False,
        )
        _timeline_store.record(self._db, event)

    def _approval_response(self, approval: RiskAcceptanceApproval) -> ApprovalResponse:
        return ApprovalResponse(
            id=approval.id,
            tenant_id=approval.tenant_id,
            risk_acceptance_id=approval.risk_acceptance_id,
            approver_name=approval.approver_name,
            approver_email=approval.approver_email,
            approver_role=approval.approver_role,
            approval_authority=approval.approval_authority,
            approval_type=approval.approval_type,
            status=approval.status,
            comments=approval.comments,
            approved_at=approval.approved_at,
            expires_at=approval.expires_at,
            quorum_required=approval.quorum_required,
            quorum_position=approval.quorum_position,
            is_required=approval.is_required,
            created_at=approval.created_at,
            updated_at=approval.updated_at,
            schema_version=approval.schema_version,
        )

    def _review_response(self, review: RiskReview) -> ReviewResponse:
        return ReviewResponse(
            id=review.id,
            tenant_id=review.tenant_id,
            risk_acceptance_id=review.risk_acceptance_id,
            review_type=review.review_type,
            reviewer=review.reviewer,
            status=review.status,
            review_due_at=review.review_due_at,
            review_completed_at=review.review_completed_at,
            review_notes=review.review_notes,
            outcome=review.outcome,
            created_at=review.created_at,
            updated_at=review.updated_at,
            schema_version=review.schema_version,
        )

    def _escalation_response(
        self, escalation: RiskGovernanceEscalation
    ) -> EscalationResponse:
        return EscalationResponse(
            id=escalation.id,
            tenant_id=escalation.tenant_id,
            risk_acceptance_id=escalation.risk_acceptance_id,
            trigger=escalation.trigger,
            level=escalation.level,
            details=escalation.details,
            actor=escalation.actor,
            resolved=escalation.resolved,
            resolved_at=escalation.resolved_at,
            resolved_by=escalation.resolved_by,
            created_at=escalation.created_at,
            schema_version=escalation.schema_version,
        )

    def _policy_response(self, policy: RiskApprovalPolicy) -> PolicyResponse:
        return PolicyResponse(
            id=policy.id,
            tenant_id=policy.tenant_id,
            policy_name=policy.policy_name,
            description=policy.description,
            active=policy.active,
            approval_threshold=policy.approval_threshold,
            required_roles=policy.required_roles,
            required_count=policy.required_count,
            quorum_percentage=policy.quorum_percentage,
            auto_expire_days=policy.auto_expire_days,
            review_frequency_days=policy.review_frequency_days,
            sequential=policy.sequential,
            created_at=policy.created_at,
            updated_at=policy.updated_at,
            schema_version=policy.schema_version,
        )
