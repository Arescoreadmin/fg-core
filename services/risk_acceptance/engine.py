# services/risk_acceptance/engine.py
"""Risk Acceptance Engine — authoritative service layer for PR 14.1.

All public methods are tenant-scoped.  No direct ORM access from routes.
Caller (route handler) owns db.commit() — every method prepares the
transaction but does not commit, enabling atomic route-level commits.

State machine:
  DRAFT           → PENDING_APPROVAL | REVOKED
  PENDING_APPROVAL → APPROVED | REJECTED | REVOKED
  APPROVED        → ACTIVE | REVOKED
  ACTIVE          → EXPIRED (automatic) | REVOKED
  EXPIRED, REVOKED, REJECTED  — terminal; no further transitions

Illegal transitions return RiskAcceptanceInvalidTransition (HTTP 422).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from api.db_models_risk_acceptance import RiskAcceptance, RiskAcceptanceAudit
from api.observability.metrics import (
    RISK_ACCEPTANCE_TOTAL,
    RISK_APPROVED_TOTAL,
    RISK_EXPIRED_TOTAL,
    RISK_INVALID_TRANSITIONS_TOTAL,
    RISK_REJECTED_TOTAL,
    RISK_REVOKED_TOTAL,
    RISK_STATUS_TRANSITIONS_TOTAL,
)
from services.notifications.engine import NotificationEngine
from services.notifications.schemas import NotificationTrigger
from services.risk_acceptance.repository import (
    assert_assessment_exists,
    assert_finding_belongs_to_tenant,
    count_audit_events,
    count_risk_acceptances,
    fetch_audit_events,
    fetch_expired_active,
    fetch_risk_acceptance,
    fetch_risk_acceptances,
    insert_audit_event,
    insert_risk_acceptance,
    snapshot_risk_acceptance,
)
from services.risk_acceptance.schemas import (
    ALLOWED_TRANSITIONS,
    AllowedTransitionsResponse,
    CreateRiskAcceptanceRequest,
    RiskAcceptanceAuditListResponse,
    RiskAcceptanceAuditResponse,
    RiskAcceptanceConflict,
    RiskAcceptanceEventType,
    RiskAcceptanceInvalidTransition,
    RiskAcceptanceListResponse,
    RiskAcceptanceNotFound,
    RiskAcceptanceResponse,
    RiskAcceptanceStatus,
    TERMINAL_STATUSES,
    TransitionRiskAcceptanceRequest,
    UpdateRiskAcceptanceRequest,
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return uuid.uuid4().hex


def _to_response(ra: RiskAcceptance) -> RiskAcceptanceResponse:
    return RiskAcceptanceResponse.model_validate(ra)


_TRANSITION_EVENT: dict[RiskAcceptanceStatus, RiskAcceptanceEventType] = {
    RiskAcceptanceStatus.PENDING_APPROVAL: RiskAcceptanceEventType.RISK_SUBMITTED,
    RiskAcceptanceStatus.APPROVED: RiskAcceptanceEventType.RISK_APPROVED,
    RiskAcceptanceStatus.ACTIVE: RiskAcceptanceEventType.RISK_ACTIVATED,
    RiskAcceptanceStatus.REJECTED: RiskAcceptanceEventType.RISK_REJECTED,
    RiskAcceptanceStatus.REVOKED: RiskAcceptanceEventType.RISK_REVOKED,
    RiskAcceptanceStatus.EXPIRED: RiskAcceptanceEventType.RISK_EXPIRED,
}

_TRANSITION_NOTIFICATION: dict[RiskAcceptanceStatus, NotificationTrigger] = {
    RiskAcceptanceStatus.PENDING_APPROVAL: NotificationTrigger.RISK_APPROVAL_REQUESTED,
    RiskAcceptanceStatus.APPROVED: NotificationTrigger.RISK_APPROVED,
    RiskAcceptanceStatus.REJECTED: NotificationTrigger.RISK_REJECTED,
    RiskAcceptanceStatus.EXPIRED: NotificationTrigger.RISK_EXPIRED,
    RiskAcceptanceStatus.REVOKED: NotificationTrigger.RISK_REVOKED,
}


class RiskAcceptanceEngine:
    """Tenant-scoped risk acceptance service.

    Caller owns db.commit() — every method prepares the transaction but
    does not commit, enabling atomic route-level commits.
    """

    def __init__(self, db: Session, *, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    # -----------------------------------------------------------------------
    # Create
    # -----------------------------------------------------------------------

    def create(
        self, request: CreateRiskAcceptanceRequest, *, actor: str
    ) -> RiskAcceptanceResponse:
        # Validate that the referenced assessment and finding exist for this
        # tenant and that the finding belongs to the given assessment.
        # Prevents orphaned acceptances and cross-tenant reference pollution.
        assert_assessment_exists(
            self._db,
            tenant_id=self._tenant_id,
            assessment_id=request.assessment_id,
        )
        assert_finding_belongs_to_tenant(
            self._db,
            tenant_id=self._tenant_id,
            finding_id=request.finding_id,
            assessment_id=request.assessment_id,
        )

        now = _utcnow()
        ra = RiskAcceptance(
            id=_new_id(),
            tenant_id=self._tenant_id,
            schema_version="1.0",
            finding_id=request.finding_id,
            assessment_id=request.assessment_id,
            remediation_task_id=request.remediation_task_id,
            status=RiskAcceptanceStatus.DRAFT.value,
            title=request.title,
            business_justification=request.business_justification,
            risk_rationale=request.risk_rationale,
            accepted_by=request.accepted_by,
            accepted_at=None,
            approver_name=request.approver_name,
            approver_role=request.approver_role,
            approval_authority=(
                request.approval_authority.value if request.approval_authority else None
            ),
            approval_source=request.approval_source,
            expires_at=request.expires_at,
            inherent_risk=request.inherent_risk.value
            if request.inherent_risk
            else None,
            residual_risk=request.residual_risk.value
            if request.residual_risk
            else None,
            compensating_controls=[
                c.model_dump() for c in request.compensating_controls
            ],
            review_required=request.review_required,
            review_frequency_days=request.review_frequency_days,
            next_review_at=request.next_review_at,
            created_at=now,
            updated_at=now,
        )
        insert_risk_acceptance(self._db, ra=ra)
        self._emit_audit(
            ra=ra,
            event_type=RiskAcceptanceEventType.RISK_CREATED,
            actor=actor,
            old_state=None,
            new_state=snapshot_risk_acceptance(ra),
        )
        RISK_ACCEPTANCE_TOTAL.inc()
        return _to_response(ra)

    # -----------------------------------------------------------------------
    # Read
    # -----------------------------------------------------------------------

    def get(self, ra_id: str) -> RiskAcceptanceResponse:
        ra = self._require(ra_id)
        return _to_response(ra)

    def list(
        self,
        *,
        status: str | None = None,
        finding_id: str | None = None,
        assessment_id: str | None = None,
        remediation_task_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> RiskAcceptanceListResponse:
        items = fetch_risk_acceptances(
            self._db,
            tenant_id=self._tenant_id,
            status=status,
            finding_id=finding_id,
            assessment_id=assessment_id,
            remediation_task_id=remediation_task_id,
            limit=limit,
            offset=offset,
        )
        total = count_risk_acceptances(
            self._db,
            tenant_id=self._tenant_id,
            status=status,
            finding_id=finding_id,
            assessment_id=assessment_id,
            remediation_task_id=remediation_task_id,
        )
        return RiskAcceptanceListResponse(
            items=[_to_response(ra) for ra in items],
            total=total,
            limit=limit,
            offset=offset,
        )

    # -----------------------------------------------------------------------
    # Update (field-level, status unchanged)
    # -----------------------------------------------------------------------

    def update(
        self,
        ra_id: str,
        request: UpdateRiskAcceptanceRequest,
        *,
        actor: str,
    ) -> RiskAcceptanceResponse:
        ra = self._require(ra_id)
        if ra.status in {s.value for s in TERMINAL_STATUSES}:
            raise RiskAcceptanceConflict(
                f"Risk acceptance {ra_id!r} is terminal ({ra.status}); cannot update."
            )

        old_state = snapshot_risk_acceptance(ra)
        now = _utcnow()

        if request.title is not None:
            ra.title = request.title
        if request.business_justification is not None:
            ra.business_justification = request.business_justification
        if request.risk_rationale is not None:
            ra.risk_rationale = request.risk_rationale
        if request.approver_name is not None:
            ra.approver_name = request.approver_name
        if request.approver_role is not None:
            ra.approver_role = request.approver_role
        if request.approval_authority is not None:
            ra.approval_authority = request.approval_authority.value
        if request.expires_at is not None:
            ra.expires_at = request.expires_at
        if request.inherent_risk is not None:
            ra.inherent_risk = request.inherent_risk.value
        if request.residual_risk is not None:
            ra.residual_risk = request.residual_risk.value
        if request.compensating_controls is not None:
            ra.compensating_controls = [
                c.model_dump() for c in request.compensating_controls
            ]
        if request.review_required is not None:
            ra.review_required = request.review_required
        if request.review_frequency_days is not None:
            ra.review_frequency_days = request.review_frequency_days
        if request.next_review_at is not None:
            ra.next_review_at = request.next_review_at
        if request.remediation_task_id is not None:
            ra.remediation_task_id = request.remediation_task_id

        ra.updated_at = now
        self._db.flush()

        self._emit_audit(
            ra=ra,
            event_type=RiskAcceptanceEventType.RISK_UPDATED,
            actor=actor,
            old_state=old_state,
            new_state=snapshot_risk_acceptance(ra),
        )
        return _to_response(ra)

    # -----------------------------------------------------------------------
    # Transition (state machine)
    # -----------------------------------------------------------------------

    def transition(
        self,
        ra_id: str,
        request: TransitionRiskAcceptanceRequest,
        *,
        actor: str,
        notification_recipient: str | None = None,
    ) -> RiskAcceptanceResponse:
        ra = self._require(ra_id)
        current = RiskAcceptanceStatus(ra.status)
        target = request.target_status

        allowed = ALLOWED_TRANSITIONS.get(current, set())
        if target not in allowed:
            RISK_INVALID_TRANSITIONS_TOTAL.inc()
            raise RiskAcceptanceInvalidTransition(
                f"Transition {current.value!r} → {target.value!r} is not permitted. "
                f"Allowed: {[s.value for s in allowed]}"
            )

        old_state = snapshot_risk_acceptance(ra)
        now = _utcnow()

        ra.status = target.value
        ra.updated_at = now

        # Apply approval attribution when moving to APPROVED
        if target == RiskAcceptanceStatus.APPROVED:
            if request.approver_name:
                ra.approver_name = request.approver_name
            if request.approver_role:
                ra.approver_role = request.approver_role
            if request.approval_authority:
                ra.approval_authority = request.approval_authority.value

        # Require expires_at before activating — accepted risks cannot live forever.
        if target == RiskAcceptanceStatus.ACTIVE and not ra.expires_at:
            raise RiskAcceptanceInvalidTransition(
                "expires_at must be set before a risk acceptance can become active. "
                "Accepted risks without an expiry date are not permitted."
            )

        # Record acceptance timestamp when becoming ACTIVE
        if target == RiskAcceptanceStatus.ACTIVE:
            ra.accepted_at = now

        self._db.flush()

        event_type = _TRANSITION_EVENT.get(target, RiskAcceptanceEventType.RISK_UPDATED)
        self._emit_audit(
            ra=ra,
            event_type=event_type,
            actor=actor,
            old_state=old_state,
            new_state=snapshot_risk_acceptance(ra),
            reason=request.reason,
        )

        RISK_STATUS_TRANSITIONS_TOTAL.labels(
            from_status=current.value, to_status=target.value
        ).inc()
        self._increment_terminal_metric(target)

        # Governance notifications
        if notification_recipient:
            trigger = _TRANSITION_NOTIFICATION.get(target)
            if trigger:
                ne = NotificationEngine(self._db, tenant_id=self._tenant_id)
                ne.notify(
                    task_id=ra.id,
                    trigger=trigger,
                    recipient=notification_recipient,
                    subject=self._notification_subject(target, ra),
                    body=self._notification_body(target, ra, request.reason, actor),
                    metadata={"risk_acceptance_id": ra.id, "actor": actor},
                )

        return _to_response(ra)

    # -----------------------------------------------------------------------
    # Expiration sweep (called by background job or cron)
    # -----------------------------------------------------------------------

    def expire_overdue(self, *, actor: str = "system") -> int:
        """Expire all ACTIVE records whose expires_at has passed.

        Returns count of records transitioned to EXPIRED.
        Caller owns db.commit().
        """
        now = _utcnow()
        expired_records = fetch_expired_active(
            self._db, tenant_id=self._tenant_id, now_iso=now
        )
        for ra in expired_records:
            old_state = snapshot_risk_acceptance(ra)
            ra.status = RiskAcceptanceStatus.EXPIRED.value
            ra.updated_at = now
            self._db.flush()
            self._emit_audit(
                ra=ra,
                event_type=RiskAcceptanceEventType.RISK_EXPIRED,
                actor=actor,
                old_state=old_state,
                new_state=snapshot_risk_acceptance(ra),
                reason="Automatic expiration — expires_at reached.",
            )
            RISK_STATUS_TRANSITIONS_TOTAL.labels(
                from_status="active", to_status="expired"
            ).inc()
            RISK_EXPIRED_TOTAL.inc()
        return len(expired_records)

    # -----------------------------------------------------------------------
    # Audit trail
    # -----------------------------------------------------------------------

    def get_audit(
        self,
        ra_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> RiskAcceptanceAuditListResponse:
        self._require(ra_id)
        events = fetch_audit_events(
            self._db,
            tenant_id=self._tenant_id,
            ra_id=ra_id,
            limit=limit,
            offset=offset,
        )
        total = count_audit_events(self._db, tenant_id=self._tenant_id, ra_id=ra_id)
        return RiskAcceptanceAuditListResponse(
            items=[RiskAcceptanceAuditResponse.model_validate(e) for e in events],
            total=total,
        )

    # -----------------------------------------------------------------------
    # Allowed transitions helper
    # -----------------------------------------------------------------------

    def allowed_transitions(self, ra_id: str) -> AllowedTransitionsResponse:
        ra = self._require(ra_id)
        current = RiskAcceptanceStatus(ra.status)
        allowed = ALLOWED_TRANSITIONS.get(current, set())
        return AllowedTransitionsResponse(
            current_status=current.value,
            allowed=[s.value for s in sorted(allowed, key=lambda x: x.value)],
        )

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _require(self, ra_id: str) -> RiskAcceptance:
        ra = fetch_risk_acceptance(self._db, tenant_id=self._tenant_id, ra_id=ra_id)
        if ra is None:
            raise RiskAcceptanceNotFound(
                f"Risk acceptance {ra_id!r} not found for tenant."
            )
        return ra

    def _emit_audit(
        self,
        *,
        ra: RiskAcceptance,
        event_type: RiskAcceptanceEventType,
        actor: str,
        old_state: dict[str, Any] | None,
        new_state: dict[str, Any] | None,
        reason: str | None = None,
    ) -> None:
        audit = RiskAcceptanceAudit(
            id=_new_id(),
            tenant_id=self._tenant_id,
            risk_acceptance_id=ra.id,
            event_type=event_type.value,
            actor=actor,
            old_state=old_state,
            new_state=new_state,
            reason=reason,
            event_at=_utcnow(),
        )
        insert_audit_event(self._db, audit=audit)

    @staticmethod
    def _increment_terminal_metric(target: RiskAcceptanceStatus) -> None:
        if target == RiskAcceptanceStatus.APPROVED:
            RISK_APPROVED_TOTAL.inc()
        elif target == RiskAcceptanceStatus.REJECTED:
            RISK_REJECTED_TOTAL.inc()
        elif target == RiskAcceptanceStatus.REVOKED:
            RISK_REVOKED_TOTAL.inc()
        elif target == RiskAcceptanceStatus.EXPIRED:
            RISK_EXPIRED_TOTAL.inc()

    @staticmethod
    def _notification_subject(target: RiskAcceptanceStatus, ra: RiskAcceptance) -> str:
        messages = {
            RiskAcceptanceStatus.PENDING_APPROVAL: f"Risk acceptance approval requested: {ra.title}",
            RiskAcceptanceStatus.APPROVED: f"Risk acceptance approved: {ra.title}",
            RiskAcceptanceStatus.REJECTED: f"Risk acceptance rejected: {ra.title}",
            RiskAcceptanceStatus.EXPIRED: f"Risk acceptance expired: {ra.title}",
            RiskAcceptanceStatus.REVOKED: f"Risk acceptance revoked: {ra.title}",
        }
        return messages.get(target, f"Risk acceptance update: {ra.title}")

    @staticmethod
    def _notification_body(
        target: RiskAcceptanceStatus,
        ra: RiskAcceptance,
        reason: str | None,
        actor: str,
    ) -> str:
        lines = [
            f"Risk Acceptance: {ra.title}",
            f"ID: {ra.id}",
            f"Status: {target.value}",
            f"Finding: {ra.finding_id}",
            f"Accepted by: {ra.accepted_by}",
        ]
        if reason:
            lines.append(f"Reason: {reason}")
        lines.append(f"Actor: {actor}")
        return "\n".join(lines)
