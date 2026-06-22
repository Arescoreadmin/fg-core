# services/governance_portal/engine.py
"""Service layer for the Governance Portal bounded context (PR 14.4).

All methods are tenant-scoped. Caller (API layer) owns db.commit().
Read-only on risk_acceptance, risk_governance, control_registry.
Write-only on portal_acknowledgements and governance_portal_audits (append-only).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from api.db_models_governance_portal import GovernancePortalAudit, PortalAcknowledgement
from api.observability.metrics import (
    GOVERNANCE_PORTAL_ACKNOWLEDGEMENTS_TOTAL,
    GOVERNANCE_PORTAL_CONTROLS_TOTAL,
    GOVERNANCE_PORTAL_EVIDENCE_TOTAL,
    GOVERNANCE_PORTAL_RISKS_TOTAL,
    GOVERNANCE_PORTAL_VIEWS_TOTAL,
)
from services.canonical import utc_iso8601_z_now
from services.governance.timeline.adapters import governance_portal_to_timeline_event
from services.governance.timeline.store import TimelineStore
from services.governance_portal.repository import (
    _compute_evidence_freshness,
    count_acknowledgements,
    count_acknowledgements_since,
    count_expired_risks,
    count_expiring_risks,
    count_evidence_for_control,
    count_evidence_with_freshness,
    count_portal_audits,
    count_portal_controls,
    count_portal_evidence,
    count_risks,
    count_risks_by_status,
    fetch_acknowledgement_by_id,
    fetch_acknowledgements,
    fetch_approvals_for_risk,
    fetch_portal_audits,
    fetch_portal_control_by_id,
    fetch_portal_controls,
    fetch_portal_evidence,
    fetch_portal_evidence_by_id,
    fetch_risk_by_id,
    fetch_risks,
    insert_acknowledgement,
    insert_portal_audit,
)
from services.governance_portal.schemas import (
    AcknowledgementListResponse,
    AcknowledgementResponse,
    CreateAcknowledgementRequest,
    EvidenceFreshnessState,
    PortalApprovalSummary,
    PortalAuditEntryResponse,
    PortalAuditEventType,
    PortalAuditListResponse,
    PortalControlDetailResponse,
    PortalControlListResponse,
    PortalControlSummary,
    PortalDashboardResponse,
    PortalEntityNotFound,
    PortalEvidenceDetailResponse,
    PortalEvidenceListResponse,
    PortalEvidenceSummary,
    PortalRiskDetailResponse,
    PortalRiskListResponse,
    PortalRiskSummary,
)
from services.notifications.engine import NotificationEngine
from services.notifications.schemas import NotificationTrigger

_timeline_store = TimelineStore()

_RECENT_DAYS = 30


def _now_iso() -> str:
    return utc_iso8601_z_now()


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


class GovernancePortalEngine:
    """Governance Portal Engine — read-through façade with audit and acknowledgement writes."""

    def __init__(self, db: Session, *, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    # -----------------------------------------------------------------------
    # Dashboard
    # -----------------------------------------------------------------------

    def dashboard(self) -> PortalDashboardResponse:
        now = _now_iso()

        total_risks = count_risks(self._db, tenant_id=self._tenant_id)
        active_risks = count_risks_by_status(
            self._db, tenant_id=self._tenant_id, status="active"
        )
        expiring_risks = count_expiring_risks(
            self._db, tenant_id=self._tenant_id, now_iso=now
        )
        expired_risks = count_expired_risks(
            self._db, tenant_id=self._tenant_id, now_iso=now
        )

        total_controls = count_portal_controls(self._db, tenant_id=self._tenant_id)
        active_controls = count_portal_controls(
            self._db, tenant_id=self._tenant_id, control_status="active"
        )
        verified_controls = count_portal_controls(
            self._db,
            tenant_id=self._tenant_id,
            verification_status="verified",
        )
        unverified_controls = count_portal_controls(
            self._db,
            tenant_id=self._tenant_id,
            verification_status="unverified",
        )

        total_evidence = count_portal_evidence(self._db, tenant_id=self._tenant_id)
        fresh_evidence = count_evidence_with_freshness(
            self._db,
            tenant_id=self._tenant_id,
            now_iso=now,
            target_states={EvidenceFreshnessState.FRESH},
        )
        stale_evidence = count_evidence_with_freshness(
            self._db,
            tenant_id=self._tenant_id,
            now_iso=now,
            target_states={
                EvidenceFreshnessState.AGING,
                EvidenceFreshnessState.EXPIRING_SOON,
                EvidenceFreshnessState.EXPIRED,
            },
        )
        controls_with_expired_evidence = count_evidence_with_freshness(
            self._db,
            tenant_id=self._tenant_id,
            now_iso=now,
            target_states={EvidenceFreshnessState.EXPIRED},
        )

        # 30-day look-back for recent acks
        thirty_days_ago = _thirty_days_ago_iso()
        recent_acknowledgements = count_acknowledgements_since(
            self._db, tenant_id=self._tenant_id, since_iso=thirty_days_ago
        )
        pending_acknowledgements = max(
            0, total_risks + total_controls - recent_acknowledgements
        )

        # Governance health score 0-100
        # Weighted: verified ratio (40%), fresh evidence ratio (30%), active risk ratio (30%)
        health_score = _compute_health_score(
            total_controls=total_controls,
            verified_controls=verified_controls,
            total_evidence=total_evidence,
            fresh_evidence=fresh_evidence,
            total_risks=total_risks,
            active_risks=active_risks,
        )

        self._audit(
            event_type=PortalAuditEventType.DASHBOARD_VIEWED,
            actor="system",
        )
        GOVERNANCE_PORTAL_VIEWS_TOTAL.inc()

        return PortalDashboardResponse(
            total_risks=total_risks,
            active_risks=active_risks,
            expiring_risks=expiring_risks,
            expired_risks=expired_risks,
            total_controls=total_controls,
            active_controls=active_controls,
            verified_controls=verified_controls,
            unverified_controls=unverified_controls,
            controls_with_expired_evidence=controls_with_expired_evidence,
            total_evidence=total_evidence,
            fresh_evidence=fresh_evidence,
            stale_evidence=stale_evidence,
            pending_acknowledgements=pending_acknowledgements,
            recent_acknowledgements=recent_acknowledgements,
            governance_health_score=health_score,
        )

    # -----------------------------------------------------------------------
    # Risk visibility
    # -----------------------------------------------------------------------

    def list_risks(self, *, limit: int = 50, offset: int = 0) -> PortalRiskListResponse:
        risks = fetch_risks(
            self._db, tenant_id=self._tenant_id, limit=limit, offset=offset
        )
        total = count_risks(self._db, tenant_id=self._tenant_id)

        items = []
        for r in risks:
            controls = r.compensating_controls or []
            items.append(
                PortalRiskSummary(
                    id=r.id,
                    title=r.title,
                    status=r.status,
                    residual_risk=r.residual_risk,
                    inherent_risk=r.inherent_risk,
                    expires_at=r.expires_at,
                    next_review_at=r.next_review_at,
                    accepted_by=r.accepted_by,
                    compensating_controls_count=len(controls),
                    schema_version=r.schema_version,
                )
            )

        GOVERNANCE_PORTAL_RISKS_TOTAL.inc()
        return PortalRiskListResponse(
            items=items, total=total, limit=limit, offset=offset
        )

    def get_risk(
        self, risk_id: str, *, actor: str = "unknown"
    ) -> PortalRiskDetailResponse:
        risk = fetch_risk_by_id(self._db, tenant_id=self._tenant_id, risk_id=risk_id)
        approvals = fetch_approvals_for_risk(
            self._db, tenant_id=self._tenant_id, risk_id=risk_id
        )

        approval_summaries = [
            PortalApprovalSummary(
                id=a.id,
                approver_name=a.approver_name,
                approver_role=a.approver_role,
                approval_type=a.approval_type,
                status=a.status,
                approved_at=a.approved_at,
                comments=a.comments,
            )
            for a in approvals
        ]

        controls = risk.compensating_controls or []

        self._audit(
            event_type=PortalAuditEventType.RISK_VIEWED,
            actor=actor,
            entity_type="accepted_risk",
            entity_id=risk_id,
        )
        GOVERNANCE_PORTAL_RISKS_TOTAL.inc()

        return PortalRiskDetailResponse(
            id=risk.id,
            title=risk.title,
            status=risk.status,
            business_justification=risk.business_justification,
            risk_rationale=risk.risk_rationale,
            residual_risk=risk.residual_risk,
            inherent_risk=risk.inherent_risk,
            expires_at=risk.expires_at,
            next_review_at=risk.next_review_at,
            accepted_by=risk.accepted_by,
            approver_name=risk.approver_name,
            approver_role=risk.approver_role,
            approval_authority=risk.approval_authority,
            approval_source=risk.approval_source,
            compensating_controls=controls if isinstance(controls, list) else [],
            approvals=approval_summaries,
            schema_version=risk.schema_version,
            created_at=risk.created_at,
            updated_at=risk.updated_at,
        )

    # -----------------------------------------------------------------------
    # Control visibility
    # -----------------------------------------------------------------------

    def list_controls(
        self,
        *,
        control_status: str | None = None,
        verification_status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> PortalControlListResponse:
        controls = fetch_portal_controls(
            self._db,
            tenant_id=self._tenant_id,
            control_status=control_status,
            verification_status=verification_status,
            limit=limit,
            offset=offset,
        )
        total = count_portal_controls(
            self._db,
            tenant_id=self._tenant_id,
            control_status=control_status,
            verification_status=verification_status,
        )
        now_dt = _now_dt()

        items = [
            PortalControlSummary(
                id=c.id,
                control_id=c.control_id,
                title=c.title,
                control_type=c.control_type,
                control_status=c.control_status,
                effectiveness_rating=c.effectiveness_rating,
                verification_status=c.verification_status,
                criticality=c.criticality,
                owner=c.owner,
                last_verified_at=c.last_verified_at,
                evidence_freshness=_compute_evidence_freshness(
                    c.last_verified_at, c.review_frequency_days, now_dt
                ),
                schema_version=c.schema_version,
            )
            for c in controls
        ]

        GOVERNANCE_PORTAL_CONTROLS_TOTAL.inc()
        return PortalControlListResponse(
            items=items, total=total, limit=limit, offset=offset
        )

    def get_control(
        self, ctl_id: str, *, actor: str = "unknown"
    ) -> PortalControlDetailResponse:
        ctrl = fetch_portal_control_by_id(
            self._db, tenant_id=self._tenant_id, ctl_id=ctl_id
        )
        evidence_count = count_evidence_for_control(
            self._db, tenant_id=self._tenant_id, control_id=ctrl.id
        )
        now_dt = _now_dt()
        freshness = _compute_evidence_freshness(
            ctrl.last_verified_at, ctrl.review_frequency_days, now_dt
        )

        self._audit(
            event_type=PortalAuditEventType.CONTROL_VIEWED,
            actor=actor,
            entity_type="control",
            entity_id=ctl_id,
        )
        GOVERNANCE_PORTAL_CONTROLS_TOTAL.inc()

        return PortalControlDetailResponse(
            id=ctrl.id,
            control_id=ctrl.control_id,
            title=ctrl.title,
            description=ctrl.description,
            control_type=ctrl.control_type,
            control_status=ctrl.control_status,
            effectiveness_rating=ctrl.effectiveness_rating,
            verification_status=ctrl.verification_status,
            criticality=ctrl.criticality,
            owner=ctrl.owner,
            owner_email=ctrl.owner_email,
            business_unit=ctrl.business_unit,
            last_verified_at=ctrl.last_verified_at,
            next_review_at=ctrl.next_review_at,
            review_frequency_days=ctrl.review_frequency_days,
            evidence_count=evidence_count,
            evidence_freshness=freshness,
            schema_version=ctrl.schema_version,
            created_at=ctrl.created_at,
            updated_at=ctrl.updated_at,
        )

    # -----------------------------------------------------------------------
    # Evidence visibility
    # -----------------------------------------------------------------------

    def list_evidence(
        self,
        *,
        control_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> PortalEvidenceListResponse:
        evidence_links = fetch_portal_evidence(
            self._db,
            tenant_id=self._tenant_id,
            control_id=control_id,
            limit=limit,
            offset=offset,
        )
        total = count_portal_evidence(
            self._db, tenant_id=self._tenant_id, control_id=control_id
        )
        now_dt = _now_dt()

        # Preload controls for freshness calculation
        control_ids = {e.control_id for e in evidence_links}
        from api.db_models_control_registry import ControlRegistry

        ctrl_map: dict[str, Any] = {}
        for ctrl in (
            self._db.query(ControlRegistry)
            .filter(
                ControlRegistry.tenant_id == self._tenant_id,
                ControlRegistry.id.in_(control_ids),
            )
            .all()
        ):
            ctrl_map[ctrl.id] = ctrl

        items = []
        for ev in evidence_links:
            linked_control = ctrl_map.get(ev.control_id)
            last_verified_at = (
                linked_control.last_verified_at if linked_control is not None else None
            )
            review_frequency_days = (
                linked_control.review_frequency_days
                if linked_control is not None
                else None
            )
            freshness = _compute_evidence_freshness(
                last_verified_at,
                review_frequency_days,
                now_dt,
            )
            items.append(
                PortalEvidenceSummary(
                    id=ev.id,
                    control_id=ev.control_id,
                    evidence_id=ev.evidence_id,
                    evidence_type=ev.evidence_type,
                    linked_by=ev.linked_by,
                    linked_at=ev.linked_at,
                    freshness=freshness,
                )
            )

        GOVERNANCE_PORTAL_EVIDENCE_TOTAL.inc()
        return PortalEvidenceListResponse(
            items=items, total=total, limit=limit, offset=offset
        )

    def get_evidence(
        self, evidence_id: str, *, actor: str = "unknown"
    ) -> PortalEvidenceDetailResponse:
        ev = fetch_portal_evidence_by_id(
            self._db, tenant_id=self._tenant_id, evidence_id=evidence_id
        )
        now_dt = _now_dt()

        ctrl = None
        try:
            ctrl = fetch_portal_control_by_id(
                self._db, tenant_id=self._tenant_id, ctl_id=ev.control_id
            )
        except PortalEntityNotFound:
            pass

        freshness = _compute_evidence_freshness(
            ctrl.last_verified_at if ctrl else None,
            ctrl.review_frequency_days if ctrl else None,
            now_dt,
        )

        self._audit(
            event_type=PortalAuditEventType.EVIDENCE_VIEWED,
            actor=actor,
            entity_type="evidence",
            entity_id=evidence_id,
        )
        GOVERNANCE_PORTAL_EVIDENCE_TOTAL.inc()

        return PortalEvidenceDetailResponse(
            id=ev.id,
            control_id=ev.control_id,
            evidence_id=ev.evidence_id,
            evidence_type=ev.evidence_type,
            description=ev.description if hasattr(ev, "description") else None,
            linked_by=ev.linked_by,
            linked_at=ev.linked_at,
            freshness=freshness,
            control_title=ctrl.title if ctrl else None,
            control_verification_status=ctrl.verification_status if ctrl else None,
        )

    # -----------------------------------------------------------------------
    # Acknowledgements (append-only write)
    # -----------------------------------------------------------------------

    def create_acknowledgement(
        self,
        request: CreateAcknowledgementRequest,
        *,
        actor: str = "unknown",
        notification_recipient: str | None = None,
    ) -> AcknowledgementResponse:
        now = _now_iso()
        ack_id = uuid.uuid4().hex

        ack = PortalAcknowledgement(
            id=ack_id,
            tenant_id=self._tenant_id,
            schema_version="1.0",
            entity_type=request.entity_type.value,
            entity_id=request.entity_id,
            acknowledged_by=request.acknowledged_by,
            acknowledged_at=now,
            comments=request.comments,
            created_at=now,
        )
        insert_acknowledgement(self._db, ack=ack)

        self._audit(
            event_type=PortalAuditEventType.ACK_CREATED,
            actor=actor,
            entity_type=request.entity_type.value,
            entity_id=request.entity_id,
        )

        evt = governance_portal_to_timeline_event(
            tenant_id=self._tenant_id,
            source_id=ack_id,
            event_type="portal.acknowledgement_created",
            occurred_at=now,
            payload={
                "entity_type": request.entity_type.value,
                "entity_id": request.entity_id,
                "acknowledged_by": request.acknowledged_by,
            },
        )
        try:
            _timeline_store.record(self._db, evt)
        except Exception:
            pass

        if notification_recipient:
            self._notify(
                task_id=ack_id,
                trigger=NotificationTrigger.PORTAL_ACK_CREATED,
                recipient=notification_recipient,
                metadata={
                    "entity_type": request.entity_type.value,
                    "entity_id": request.entity_id,
                },
            )

        GOVERNANCE_PORTAL_ACKNOWLEDGEMENTS_TOTAL.inc()

        return AcknowledgementResponse(
            id=ack_id,
            tenant_id=self._tenant_id,
            entity_type=request.entity_type.value,
            entity_id=request.entity_id,
            acknowledged_by=request.acknowledged_by,
            acknowledged_at=now,
            comments=request.comments,
            schema_version="1.0",
            created_at=now,
        )

    def list_acknowledgements(
        self,
        *,
        entity_type: str | None = None,
        entity_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> AcknowledgementListResponse:
        acks = fetch_acknowledgements(
            self._db,
            tenant_id=self._tenant_id,
            entity_type=entity_type,
            entity_id=entity_id,
            limit=limit,
            offset=offset,
        )
        total = count_acknowledgements(
            self._db,
            tenant_id=self._tenant_id,
            entity_type=entity_type,
            entity_id=entity_id,
        )

        items = [
            AcknowledgementResponse(
                id=a.id,
                tenant_id=a.tenant_id,
                entity_type=a.entity_type,
                entity_id=a.entity_id,
                acknowledged_by=a.acknowledged_by,
                acknowledged_at=a.acknowledged_at,
                comments=a.comments,
                schema_version=a.schema_version,
                created_at=a.created_at,
            )
            for a in acks
        ]
        return AcknowledgementListResponse(
            items=items, total=total, limit=limit, offset=offset
        )

    def get_acknowledgement(self, ack_id: str) -> AcknowledgementResponse:
        ack = fetch_acknowledgement_by_id(
            self._db, tenant_id=self._tenant_id, ack_id=ack_id
        )
        return AcknowledgementResponse(
            id=ack.id,
            tenant_id=ack.tenant_id,
            entity_type=ack.entity_type,
            entity_id=ack.entity_id,
            acknowledged_by=ack.acknowledged_by,
            acknowledged_at=ack.acknowledged_at,
            comments=ack.comments,
            schema_version=ack.schema_version,
            created_at=ack.created_at,
        )

    # -----------------------------------------------------------------------
    # Portal audit (read)
    # -----------------------------------------------------------------------

    def get_audit(
        self, *, limit: int = 100, offset: int = 0, actor: str = "unknown"
    ) -> PortalAuditListResponse:
        audits = fetch_portal_audits(
            self._db, tenant_id=self._tenant_id, limit=limit, offset=offset
        )
        total = count_portal_audits(self._db, tenant_id=self._tenant_id)

        self._audit(
            event_type=PortalAuditEventType.AUDIT_ACCESSED,
            actor=actor,
        )

        items = [
            PortalAuditEntryResponse(
                id=a.id,
                event_type=a.event_type,
                actor=a.actor,
                entity_type=a.entity_type,
                entity_id=a.entity_id,
                event_at=a.event_at,
                schema_version=a.schema_version,
            )
            for a in audits
        ]
        return PortalAuditListResponse(
            items=items, total=total, limit=limit, offset=offset
        )

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _audit(
        self,
        *,
        event_type: PortalAuditEventType,
        actor: str,
        entity_type: str | None = None,
        entity_id: str | None = None,
    ) -> None:
        now = _now_iso()
        audit = GovernancePortalAudit(
            id=uuid.uuid4().hex,
            tenant_id=self._tenant_id,
            schema_version="1.0",
            event_type=event_type.value,
            actor=actor,
            entity_type=entity_type,
            entity_id=entity_id,
            event_at=now,
            created_at=now,
        )
        try:
            insert_portal_audit(self._db, audit=audit)
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


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _thirty_days_ago_iso() -> str:
    from datetime import timedelta

    dt = datetime.now(timezone.utc) - timedelta(days=_RECENT_DAYS)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _compute_health_score(
    *,
    total_controls: int,
    verified_controls: int,
    total_evidence: int,
    fresh_evidence: int,
    total_risks: int,
    active_risks: int,
) -> int:
    """Compute a 0-100 governance health score.

    Weights:
      40% — verified control ratio
      30% — fresh evidence ratio
      30% — non-active (approved/managed) risk ratio
    """
    verified_ratio = (verified_controls / total_controls) if total_controls > 0 else 0.0
    fresh_ratio = (fresh_evidence / total_evidence) if total_evidence > 0 else 1.0
    managed_ratio = (1.0 - (active_risks / total_risks)) if total_risks > 0 else 1.0

    raw = (verified_ratio * 40) + (fresh_ratio * 30) + (managed_ratio * 30)
    return max(0, min(100, round(raw)))
