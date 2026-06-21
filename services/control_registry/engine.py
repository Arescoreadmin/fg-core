# services/control_registry/engine.py
"""Control Registry Engine — PR 14.3.

All public methods are tenant-scoped. Caller (route handler) owns db.commit().

Bounded context separation:
  services/control_registry/ — owns controls (the process and evidence)
  services/risk_governance/  — consumes controls (links risk acceptances to controls)

Control lifecycle:
  DRAFT → ACTIVE → RETIRED | SUSPENDED
  SUSPENDED → ACTIVE

Verification lifecycle:
  UNVERIFIED → PENDING → VERIFIED → EXPIRED | FAILED

Evidence freshness:
  FRESH: elapsed < 50% of review_frequency_days
  AGING: 50-99%
  STALE: 100-149%
  EXPIRED: >= 150% or no last_verified_at
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from api.db_models_control_registry import (
    ControlAudit,
    ControlEvidenceLink,
    ControlRegistry,
    ControlReview,
    RiskAcceptanceControlLink,
)
from api.observability.metrics import (
    CONTROLS_EVIDENCE_LINKS_TOTAL,
    CONTROLS_EXPIRED_TOTAL,
    CONTROLS_REVIEWS_OVERDUE_TOTAL,
    CONTROLS_REVIEWS_TOTAL,
    CONTROLS_TOTAL,
    CONTROLS_VERIFIED_TOTAL,
)
from services.canonical import utc_iso8601_z_now
from services.control_registry.repository import (
    count_control_audits,
    count_controls,
    count_controls_due_for_review,
    count_controls_without_evidence,
    count_controls_without_owner,
    count_evidence_links,
    count_reviews,
    count_risk_links,
    fetch_control,
    fetch_control_audits,
    fetch_control_owned,
    fetch_evidence_links,
    fetch_overdue_pending_reviews,
    fetch_review,
    fetch_reviews,
    fetch_risk_links,
    fetch_verified_controls_for_freshness,
    insert_control,
    insert_control_audit,
    insert_evidence_link,
    insert_review,
    insert_risk_link,
    snapshot_control,
)
from services.control_registry.schemas import (
    CONTROL_STATUS_TRANSITIONS,
    ControlAuditListResponse,
    ControlAuditResponse,
    ControlConflict,
    ControlDashboardResponse,
    ControlEvidenceLinkListResponse,
    ControlEvidenceLinkResponse,
    ControlEventType,
    ControlFreshness,
    ControlListResponse,
    ControlNotFound,
    ControlResponse,
    ControlReviewConflict,
    ControlReviewListResponse,
    ControlReviewOutcome,
    ControlReviewResponse,
    ControlReviewStatus,
    ControlStatus,
    ControlVerificationError,
    CompleteControlReviewRequest,
    CreateControlRequest,
    CreateControlReviewRequest,
    EffectivenessRating,
    FreshnessSweepResponse,
    LinkEvidenceRequest,
    LinkRiskRequest,
    ReviewSweepResponse,
    RiskAcceptanceControlLinkListResponse,
    RiskAcceptanceControlLinkResponse,
    ControlInvalidTransition,
    UpdateControlRequest,
    VerificationStatus,
    VerifyControlRequest,
)
from services.governance.timeline.adapters import control_registry_to_timeline_event
from services.governance.timeline.store import TimelineStore
from services.notifications.engine import NotificationEngine
from services.notifications.schemas import NotificationTrigger

_timeline_store = TimelineStore()


def _new_id() -> str:
    return uuid.uuid4().hex


def _now() -> str:
    return utc_iso8601_z_now()


def _compute_freshness(control: ControlRegistry, now_iso: str) -> str:
    """Compute evidence freshness based on last_verified_at vs review_frequency_days."""
    if control.last_verified_at is None:
        return ControlFreshness.EXPIRED.value

    try:
        now_dt = datetime.fromisoformat(now_iso)
        if now_dt.tzinfo is None:
            now_dt = now_dt.replace(tzinfo=timezone.utc)
        verified_dt = datetime.fromisoformat(control.last_verified_at)
        if verified_dt.tzinfo is None:
            verified_dt = verified_dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return ControlFreshness.EXPIRED.value

    elapsed_days = (now_dt - verified_dt).days
    freq = control.review_frequency_days or 90
    ratio = elapsed_days / freq

    if ratio < 0.5:
        return ControlFreshness.FRESH.value
    if ratio < 1.0:
        return ControlFreshness.AGING.value
    if ratio < 1.5:
        return ControlFreshness.STALE.value
    return ControlFreshness.EXPIRED.value


class ControlRegistryEngine:
    """Control Registry Engine — authoritative service layer for PR 14.3."""

    def __init__(self, db: Session, *, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    # -----------------------------------------------------------------------
    # Control CRUD
    # -----------------------------------------------------------------------

    def create_control(
        self,
        request: CreateControlRequest,
        *,
        actor: str,
        notification_recipient: str | None = None,
    ) -> ControlResponse:
        now = _now()
        ctl_id = _new_id()
        public_id = request.control_id or ctl_id[:16].upper()

        control = ControlRegistry(
            id=ctl_id,
            tenant_id=self._tenant_id,
            control_id=public_id,
            title=request.title,
            description=request.description,
            control_type=request.control_type.value,
            criticality=request.criticality.value,
            owner=request.owner,
            owner_email=request.owner_email,
            business_unit=request.business_unit,
            effectiveness_rating=request.effectiveness_rating.value,
            verification_status=VerificationStatus.UNVERIFIED.value,
            control_status=ControlStatus.DRAFT.value,
            review_frequency_days=request.review_frequency_days,
            next_review_at=None,
            last_review_at=None,
            last_verified_at=None,
            created_at=now,
            updated_at=now,
        )
        insert_control(self._db, control=control)

        self._emit_audit(
            control,
            event_type=ControlEventType.CONTROL_CREATED.value,
            actor=actor,
            old_state=None,
            new_state=snapshot_control(control),
        )
        self._emit_timeline(
            control_id=ctl_id,
            event_type=ControlEventType.CONTROL_CREATED.value,
            payload={"control_id": public_id, "title": control.title},
        )
        CONTROLS_TOTAL.inc()

        if notification_recipient:
            self._notify(
                task_id=ctl_id,
                trigger=NotificationTrigger.CONTROL_CREATED,
                recipient=notification_recipient,
                metadata={"control_id": public_id},
            )

        return self._control_response(control)

    def get_control(self, ctl_id: str) -> ControlResponse:
        control = fetch_control(self._db, tenant_id=self._tenant_id, ctl_id=ctl_id)
        if control is None:
            raise ControlNotFound(f"control id={ctl_id!r} not found.")
        return self._control_response(control)

    def list_controls(
        self,
        *,
        control_status: str | None = None,
        control_type: str | None = None,
        verification_status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> ControlListResponse:
        from services.control_registry.repository import fetch_controls

        items = fetch_controls(
            self._db,
            tenant_id=self._tenant_id,
            control_status=control_status,
            control_type=control_type,
            verification_status=verification_status,
            limit=limit,
            offset=offset,
        )
        total = count_controls(
            self._db,
            tenant_id=self._tenant_id,
            control_status=control_status,
            control_type=control_type,
            verification_status=verification_status,
        )
        return ControlListResponse(
            items=[self._control_response(c) for c in items],
            total=total,
        )

    def update_control(
        self,
        ctl_id: str,
        request: UpdateControlRequest,
        *,
        actor: str,
        notification_recipient: str | None = None,
    ) -> ControlResponse:
        control = fetch_control_owned(
            self._db, tenant_id=self._tenant_id, ctl_id=ctl_id
        )
        old_state = snapshot_control(control)

        # Governance rule: HIGHLY_EFFECTIVE requires verified status
        target_effectiveness = request.effectiveness_rating
        if target_effectiveness == EffectivenessRating.HIGHLY_EFFECTIVE:
            current_verification = control.verification_status
            if current_verification == VerificationStatus.UNVERIFIED.value:
                raise ControlConflict(
                    "Cannot set effectiveness to HIGHLY_EFFECTIVE when verification_status is UNVERIFIED."
                )

        # Governance rule: status transition validation
        if request.control_status is not None:
            current = ControlStatus(control.control_status)
            target_status = request.control_status
            allowed = CONTROL_STATUS_TRANSITIONS.get(current, set())
            if target_status not in allowed:
                raise ControlInvalidTransition(
                    f"transition {current.value!r} → {target_status.value!r} is not allowed."
                )

        now = _now()
        if request.title is not None:
            control.title = request.title
        if request.description is not None:
            control.description = request.description
        if request.control_type is not None:
            control.control_type = request.control_type.value
        if request.criticality is not None:
            control.criticality = request.criticality.value
        if request.owner is not None:
            control.owner = request.owner
        if request.owner_email is not None:
            control.owner_email = request.owner_email
        if request.business_unit is not None:
            control.business_unit = request.business_unit
        if request.effectiveness_rating is not None:
            control.effectiveness_rating = request.effectiveness_rating.value
        if request.review_frequency_days is not None:
            control.review_frequency_days = request.review_frequency_days
        if request.next_review_at is not None:
            control.next_review_at = request.next_review_at
        if request.control_status is not None:
            control.control_status = request.control_status.value
        control.updated_at = now

        self._db.flush()

        # Determine audit event type for status changes
        if request.control_status is not None:
            if request.control_status == ControlStatus.ACTIVE:
                prev_status = old_state["control_status"]
                if prev_status == ControlStatus.DRAFT.value:
                    event_type = ControlEventType.CONTROL_ACTIVATED.value
                else:
                    event_type = ControlEventType.CONTROL_REACTIVATED.value
            elif request.control_status == ControlStatus.RETIRED:
                event_type = ControlEventType.CONTROL_RETIRED.value
            elif request.control_status == ControlStatus.SUSPENDED:
                event_type = ControlEventType.CONTROL_SUSPENDED.value
            else:
                event_type = ControlEventType.CONTROL_UPDATED.value
        else:
            event_type = ControlEventType.CONTROL_UPDATED.value

        self._emit_audit(
            control,
            event_type=event_type,
            actor=actor,
            old_state=old_state,
            new_state=snapshot_control(control),
        )
        self._emit_timeline(
            control_id=ctl_id,
            event_type=event_type,
            payload={"control_id": control.control_id},
        )

        return self._control_response(control)

    # -----------------------------------------------------------------------
    # Verification
    # -----------------------------------------------------------------------

    def verify_control(
        self,
        ctl_id: str,
        request: VerifyControlRequest,
        *,
        actor: str,
        notification_recipient: str | None = None,
    ) -> ControlResponse:
        control = fetch_control_owned(
            self._db, tenant_id=self._tenant_id, ctl_id=ctl_id
        )

        # Governance rule: cannot verify without linked evidence
        evidence_count = count_evidence_links(
            self._db, tenant_id=self._tenant_id, control_id=ctl_id
        )
        if evidence_count == 0:
            raise ControlVerificationError(
                "Cannot verify control without linked evidence. "
                "Link at least one evidence record before verifying."
            )

        old_state = snapshot_control(control)
        now = _now()
        control.verification_status = VerificationStatus.VERIFIED.value
        control.last_verified_at = now
        control.updated_at = now
        self._db.flush()

        self._emit_audit(
            control,
            event_type=ControlEventType.CONTROL_VERIFIED.value,
            actor=actor,
            old_state=old_state,
            new_state=snapshot_control(control),
            reason=request.notes,
        )
        self._emit_timeline(
            control_id=ctl_id,
            event_type=ControlEventType.CONTROL_VERIFIED.value,
            payload={"control_id": control.control_id, "evidence_count": evidence_count},
        )
        CONTROLS_VERIFIED_TOTAL.inc()

        if notification_recipient:
            self._notify(
                task_id=ctl_id,
                trigger=NotificationTrigger.CONTROL_VERIFIED,
                recipient=notification_recipient,
                metadata={"control_id": control.control_id},
            )

        return self._control_response(control)

    # -----------------------------------------------------------------------
    # Evidence links
    # -----------------------------------------------------------------------

    def link_evidence(
        self,
        ctl_id: str,
        request: LinkEvidenceRequest,
        *,
        actor: str,
        notification_recipient: str | None = None,
    ) -> ControlEvidenceLinkResponse:
        control = fetch_control_owned(
            self._db, tenant_id=self._tenant_id, ctl_id=ctl_id
        )
        now = _now()
        link = ControlEvidenceLink(
            id=_new_id(),
            tenant_id=self._tenant_id,
            control_id=ctl_id,
            evidence_id=request.evidence_id,
            evidence_type=request.evidence_type,
            linked_at=now,
            linked_by=request.linked_by or actor,
        )
        insert_evidence_link(self._db, link=link)

        self._emit_audit(
            control,
            event_type=ControlEventType.CONTROL_EVIDENCE_LINKED.value,
            actor=actor,
            old_state=None,
            new_state={
                "evidence_id": request.evidence_id,
                "evidence_type": request.evidence_type,
            },
        )
        self._emit_timeline(
            control_id=ctl_id,
            event_type=ControlEventType.CONTROL_EVIDENCE_LINKED.value,
            payload={"control_id": control.control_id, "evidence_id": request.evidence_id},
        )
        CONTROLS_EVIDENCE_LINKS_TOTAL.inc()

        if notification_recipient:
            self._notify(
                task_id=ctl_id,
                trigger=NotificationTrigger.CONTROL_EVIDENCE_ADDED,
                recipient=notification_recipient,
                metadata={"control_id": control.control_id, "evidence_id": request.evidence_id},
            )

        return self._evidence_link_response(link)

    def list_evidence(
        self,
        ctl_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> ControlEvidenceLinkListResponse:
        fetch_control_owned(self._db, tenant_id=self._tenant_id, ctl_id=ctl_id)
        items = fetch_evidence_links(
            self._db,
            tenant_id=self._tenant_id,
            control_id=ctl_id,
            limit=limit,
            offset=offset,
        )
        total = count_evidence_links(
            self._db, tenant_id=self._tenant_id, control_id=ctl_id
        )
        return ControlEvidenceLinkListResponse(
            items=[self._evidence_link_response(e) for e in items],
            total=total,
        )

    # -----------------------------------------------------------------------
    # Risk acceptance links
    # -----------------------------------------------------------------------

    def link_risk(
        self,
        ctl_id: str,
        request: LinkRiskRequest,
        *,
        actor: str,
        notification_recipient: str | None = None,
    ) -> RiskAcceptanceControlLinkResponse:
        control = fetch_control_owned(
            self._db, tenant_id=self._tenant_id, ctl_id=ctl_id
        )

        # Governance rule: cannot link RETIRED control to risk acceptance
        if control.control_status == ControlStatus.RETIRED.value:
            raise ControlConflict(
                "Cannot link a RETIRED control to a risk acceptance."
            )

        now = _now()
        link = RiskAcceptanceControlLink(
            id=_new_id(),
            tenant_id=self._tenant_id,
            risk_acceptance_id=request.risk_acceptance_id,
            control_id=ctl_id,
            rationale=request.rationale,
            created_at=now,
        )
        insert_risk_link(self._db, link=link)

        self._emit_audit(
            control,
            event_type=ControlEventType.CONTROL_RISK_LINKED.value,
            actor=actor,
            old_state=None,
            new_state={"risk_acceptance_id": request.risk_acceptance_id},
        )
        self._emit_timeline(
            control_id=ctl_id,
            event_type=ControlEventType.CONTROL_RISK_LINKED.value,
            payload={
                "control_id": control.control_id,
                "risk_acceptance_id": request.risk_acceptance_id,
            },
        )

        if notification_recipient:
            self._notify(
                task_id=ctl_id,
                trigger=NotificationTrigger.CONTROL_LINKED_TO_RISK,
                recipient=notification_recipient,
                metadata={
                    "control_id": control.control_id,
                    "risk_acceptance_id": request.risk_acceptance_id,
                },
            )

        return self._risk_link_response(link)

    def list_risk_links(
        self,
        ctl_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> RiskAcceptanceControlLinkListResponse:
        fetch_control_owned(self._db, tenant_id=self._tenant_id, ctl_id=ctl_id)
        items = fetch_risk_links(
            self._db,
            tenant_id=self._tenant_id,
            control_id=ctl_id,
            limit=limit,
            offset=offset,
        )
        total = count_risk_links(
            self._db, tenant_id=self._tenant_id, control_id=ctl_id
        )
        return RiskAcceptanceControlLinkListResponse(
            items=[self._risk_link_response(r) for r in items],
            total=total,
        )

    # -----------------------------------------------------------------------
    # Reviews
    # -----------------------------------------------------------------------

    def create_review(
        self,
        ctl_id: str,
        request: CreateControlReviewRequest,
        *,
        actor: str,
        notification_recipient: str | None = None,
    ) -> ControlReviewResponse:
        control = fetch_control_owned(
            self._db, tenant_id=self._tenant_id, ctl_id=ctl_id
        )
        now = _now()
        review = ControlReview(
            id=_new_id(),
            tenant_id=self._tenant_id,
            control_id=ctl_id,
            reviewer=request.reviewer,
            status=ControlReviewStatus.PENDING.value,
            review_date=request.review_date,
            completed_at=None,
            outcome=request.outcome.value if request.outcome else None,
            notes=request.notes,
            effectiveness_before=request.effectiveness_before.value
            if request.effectiveness_before
            else None,
            effectiveness_after=request.effectiveness_after.value
            if request.effectiveness_after
            else None,
            evidence_snapshot=None,
            created_at=now,
            updated_at=now,
        )
        insert_review(self._db, review=review)

        self._emit_audit(
            control,
            event_type=ControlEventType.CONTROL_REVIEW_CREATED.value,
            actor=actor,
            old_state=None,
            new_state={"review_id": review.id, "review_date": request.review_date},
        )
        self._emit_timeline(
            control_id=ctl_id,
            event_type=ControlEventType.CONTROL_REVIEW_CREATED.value,
            payload={"control_id": control.control_id, "review_id": review.id},
        )
        CONTROLS_REVIEWS_TOTAL.inc()

        # Update last_review_at on the control
        control.last_review_at = now
        control.updated_at = now

        if notification_recipient:
            self._notify(
                task_id=ctl_id,
                trigger=NotificationTrigger.CONTROL_REVIEW_DUE,
                recipient=notification_recipient,
                metadata={"control_id": control.control_id, "review_date": request.review_date},
            )

        return self._review_response(review)

    def complete_review(
        self,
        ctl_id: str,
        review_id: str,
        request: CompleteControlReviewRequest,
        *,
        actor: str,
        notification_recipient: str | None = None,
    ) -> ControlReviewResponse:
        control = fetch_control_owned(
            self._db, tenant_id=self._tenant_id, ctl_id=ctl_id
        )
        review = fetch_review(self._db, tenant_id=self._tenant_id, review_id=review_id)
        if review is None or review.control_id != ctl_id:
            from services.control_registry.schemas import ControlReviewNotFound
            raise ControlReviewNotFound(f"review_id={review_id!r} not found.")
        if review.status != ControlReviewStatus.PENDING.value:
            raise ControlReviewConflict(
                f"Review is already in terminal state {review.status!r}."
            )

        now = _now()
        review.status = ControlReviewStatus.COMPLETED.value
        review.completed_at = now
        review.outcome = request.outcome.value
        if request.notes:
            review.notes = request.notes
        if request.effectiveness_before:
            review.effectiveness_before = request.effectiveness_before.value
        if request.effectiveness_after:
            review.effectiveness_after = request.effectiveness_after.value
        review.updated_at = now
        self._db.flush()

        self._emit_audit(
            control,
            event_type=ControlEventType.CONTROL_REVIEW_COMPLETED.value,
            actor=actor,
            old_state=None,
            new_state={"review_id": review_id, "outcome": request.outcome.value},
        )
        self._emit_timeline(
            control_id=ctl_id,
            event_type=ControlEventType.CONTROL_REVIEW_COMPLETED.value,
            payload={"control_id": control.control_id, "outcome": request.outcome.value},
        )

        if notification_recipient:
            self._notify(
                task_id=ctl_id,
                trigger=NotificationTrigger.CONTROL_REVIEW_COMPLETED,
                recipient=notification_recipient,
                metadata={"control_id": control.control_id},
            )

        return self._review_response(review)

    def list_reviews(
        self,
        ctl_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> ControlReviewListResponse:
        fetch_control_owned(self._db, tenant_id=self._tenant_id, ctl_id=ctl_id)
        items = fetch_reviews(
            self._db,
            tenant_id=self._tenant_id,
            control_id=ctl_id,
            limit=limit,
            offset=offset,
        )
        total = count_reviews(
            self._db, tenant_id=self._tenant_id, control_id=ctl_id
        )
        return ControlReviewListResponse(
            items=[self._review_response(r) for r in items],
            total=total,
        )

    # -----------------------------------------------------------------------
    # Audit
    # -----------------------------------------------------------------------

    def get_audit(
        self,
        ctl_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> ControlAuditListResponse:
        fetch_control_owned(self._db, tenant_id=self._tenant_id, ctl_id=ctl_id)
        items = fetch_control_audits(
            self._db,
            tenant_id=self._tenant_id,
            control_id=ctl_id,
            limit=limit,
            offset=offset,
        )
        total = count_control_audits(
            self._db, tenant_id=self._tenant_id, control_id=ctl_id
        )
        return ControlAuditListResponse(
            items=[self._audit_response(a) for a in items],
            total=total,
        )

    # -----------------------------------------------------------------------
    # Dashboard
    # -----------------------------------------------------------------------

    def dashboard(self) -> ControlDashboardResponse:
        now = _now()
        return ControlDashboardResponse(
            tenant_id=self._tenant_id,
            total_controls=count_controls(self._db, tenant_id=self._tenant_id),
            active_controls=count_controls(
                self._db, tenant_id=self._tenant_id, control_status="active"
            ),
            draft_controls=count_controls(
                self._db, tenant_id=self._tenant_id, control_status="draft"
            ),
            retired_controls=count_controls(
                self._db, tenant_id=self._tenant_id, control_status="retired"
            ),
            verified_controls=count_controls(
                self._db, tenant_id=self._tenant_id, verification_status="verified"
            ),
            unverified_controls=count_controls(
                self._db, tenant_id=self._tenant_id, verification_status="unverified"
            ),
            controls_without_evidence=count_controls_without_evidence(
                self._db, tenant_id=self._tenant_id
            ),
            controls_without_owner=count_controls_without_owner(
                self._db, tenant_id=self._tenant_id
            ),
            controls_with_expired_verification=count_controls(
                self._db, tenant_id=self._tenant_id, verification_status="expired"
            ),
            controls_due_for_review=count_controls_due_for_review(
                self._db, tenant_id=self._tenant_id, now_iso=now
            ),
            high_criticality_unverified=self._count_high_criticality_unverified(),
        )

    def _count_high_criticality_unverified(self) -> int:
        from api.db_models_control_registry import ControlRegistry as CR

        return (
            self._db.query(CR)
            .filter(
                CR.tenant_id == self._tenant_id,
                CR.criticality.in_(["high", "critical"]),
                CR.verification_status == "unverified",
            )
            .count()
        )

    # -----------------------------------------------------------------------
    # Maintenance sweeps
    # -----------------------------------------------------------------------

    def expire_stale_verifications(
        self, *, actor: str
    ) -> FreshnessSweepResponse:
        now = _now()
        stale = fetch_verified_controls_for_freshness(
            self._db, tenant_id=self._tenant_id, now_iso=now
        )
        count = 0
        for control in stale:
            old_state = snapshot_control(control)
            control.verification_status = VerificationStatus.EXPIRED.value
            control.updated_at = now
            self._db.flush()
            self._emit_audit(
                control,
                event_type=ControlEventType.CONTROL_VERIFICATION_EXPIRED.value,
                actor=actor,
                old_state=old_state,
                new_state=snapshot_control(control),
            )
            CONTROLS_EXPIRED_TOTAL.inc()
            count += 1
        return FreshnessSweepResponse(expired=count)

    def mark_overdue_reviews(self, *, actor: str) -> ReviewSweepResponse:
        now = _now()
        overdue = fetch_overdue_pending_reviews(
            self._db, tenant_id=self._tenant_id, now_iso=now
        )
        count = 0
        for review in overdue:
            review.status = ControlReviewStatus.OVERDUE.value
            review.updated_at = now
            self._db.flush()
            CONTROLS_REVIEWS_OVERDUE_TOTAL.inc()
            count += 1
        return ReviewSweepResponse(marked_overdue=count)

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _control_response(self, control: ControlRegistry) -> ControlResponse:
        now = _now()
        return ControlResponse(
            id=control.id,
            tenant_id=control.tenant_id,
            control_id=control.control_id,
            title=control.title,
            description=control.description,
            control_type=control.control_type,
            criticality=control.criticality,
            owner=control.owner,
            owner_email=control.owner_email,
            business_unit=control.business_unit,
            effectiveness_rating=control.effectiveness_rating,
            verification_status=control.verification_status,
            control_status=control.control_status,
            review_frequency_days=control.review_frequency_days,
            next_review_at=control.next_review_at,
            last_review_at=control.last_review_at,
            last_verified_at=control.last_verified_at,
            freshness=_compute_freshness(control, now),
            created_at=control.created_at,
            updated_at=control.updated_at,
            schema_version=control.schema_version,
        )

    def _evidence_link_response(
        self, link: ControlEvidenceLink
    ) -> ControlEvidenceLinkResponse:
        return ControlEvidenceLinkResponse(
            id=link.id,
            tenant_id=link.tenant_id,
            control_id=link.control_id,
            evidence_id=link.evidence_id,
            evidence_type=link.evidence_type,
            linked_at=link.linked_at,
            linked_by=link.linked_by,
        )

    def _risk_link_response(
        self, link: RiskAcceptanceControlLink
    ) -> RiskAcceptanceControlLinkResponse:
        return RiskAcceptanceControlLinkResponse(
            id=link.id,
            tenant_id=link.tenant_id,
            risk_acceptance_id=link.risk_acceptance_id,
            control_id=link.control_id,
            rationale=link.rationale,
            created_at=link.created_at,
        )

    def _review_response(self, review: ControlReview) -> ControlReviewResponse:
        return ControlReviewResponse(
            id=review.id,
            tenant_id=review.tenant_id,
            control_id=review.control_id,
            reviewer=review.reviewer,
            status=review.status,
            review_date=review.review_date,
            completed_at=review.completed_at,
            outcome=review.outcome,
            notes=review.notes,
            effectiveness_before=review.effectiveness_before,
            effectiveness_after=review.effectiveness_after,
            created_at=review.created_at,
            updated_at=review.updated_at,
            schema_version=review.schema_version,
        )

    def _audit_response(self, audit: ControlAudit) -> ControlAuditResponse:
        return ControlAuditResponse(
            id=audit.id,
            tenant_id=audit.tenant_id,
            control_id=audit.control_id,
            event_type=audit.event_type,
            actor=audit.actor,
            old_state=audit.old_state,
            new_state=audit.new_state,
            reason=audit.reason,
            event_at=audit.event_at,
        )

    def _emit_audit(
        self,
        control: ControlRegistry,
        *,
        event_type: str,
        actor: str,
        old_state: dict[str, Any] | None,
        new_state: dict[str, Any] | None,
        reason: str | None = None,
    ) -> None:
        audit = ControlAudit(
            id=_new_id(),
            tenant_id=self._tenant_id,
            control_id=control.id,
            event_type=event_type,
            actor=actor,
            old_state=old_state,
            new_state=new_state,
            reason=reason,
            event_at=_now(),
        )
        insert_control_audit(self._db, audit=audit)

    def _emit_timeline(
        self,
        *,
        control_id: str,
        event_type: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        now = _now()
        evt = control_registry_to_timeline_event(
            tenant_id=self._tenant_id,
            source_id=control_id,
            event_type=event_type,
            occurred_at=now,
            payload=payload or {},
        )
        try:
            _timeline_store.record(self._db, evt)
        except Exception:
            pass

    def _notify(
        self,
        *,
        task_id: str,
        trigger: NotificationTrigger,
        recipient: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        try:
            ne = NotificationEngine(self._db, tenant_id=self._tenant_id)
            ne.notify(
                task_id=task_id,
                trigger=trigger,
                recipient=recipient,
                metadata=metadata or {},
            )
        except Exception:
            pass
