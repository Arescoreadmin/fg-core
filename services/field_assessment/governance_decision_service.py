"""H14: GovernanceDecisionService — single write authority for governance decisions.

Design
------
record_decision() is the ONLY write path for FaGovernanceDecision records.
No direct table writes from outside this service. The service enforces:

  1. Full actor attribution (id, name, email, role, auth_source)
  2. Atomic governance decision + audit event (H13 AuditAtomicityService pattern)
  3. Pre-generated transaction_id set on the decision record at INSERT time
     (avoids updating the record after the fact, which would trigger the
     append-only DB trigger)
  4. No mutation methods — no update, no delete

Decision types (extensible)
----------------------------
  report_approved      — report QA-approved for client delivery
  risk_accepted        — risk formally accepted with owner + expiry
  finding_closed       — finding marked remediated/closed with attribution
  remediation_approved — remediation plan formally approved
  exception_granted    — governance exception with owner + expiry
  policy_approved      — policy artifact approved
  legal_hold_applied   — legal hold applied to evidence
  assessment_completed — engagement transitions to delivered

Future governance intelligence
-------------------------------
The decision ledger accumulates attribution, provenance, and outcome data.
Future analysis surfaces:
  - Which decisions most frequently prevent incidents?
  - Which accepted risks become findings?
  - Which governance patterns correlate with compliance success?
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models_governance_decision import (
    FaGovernanceDecision,
    FaGovernanceException,
    FaRiskAcceptance,
)
from services.canonical import utc_iso8601_z_now
from services.field_assessment.audit import emit_engagement_audit_event


def _json_list(v: list | None) -> str | None:
    return json.dumps(v) if v else None


class GovernanceDecisionService:
    """Single write authority for the governance decision ledger."""

    # ------------------------------------------------------------------
    # Core decision recording
    # ------------------------------------------------------------------

    def record_decision(
        self,
        db: Session,
        *,
        tenant_id: str,
        engagement_id: str,
        decision_type: str,
        entity_type: str,
        entity_id: str,
        actor_id: str,
        actor_subject: str | None = None,
        actor_name: str | None = None,
        actor_email: str | None = None,
        actor_role: str | None = None,
        actor_auth_source: str = "api_key",
        decision_reason: str,
        decision_notes: str | None = None,
        approver_id: str | None = None,
        creator_id: str | None = None,
        reviewer_id: str | None = None,
        evidence_snapshot: dict | None = None,
        evidence_refs: list[str] | None = None,
        related_finding_ids: list[str] | None = None,
        related_control_ids: list[str] | None = None,
        effective_until: str | None = None,
        review_date: str | None = None,
        correlation_id: str | None = None,
        decision_metadata: dict | None = None,
    ) -> FaGovernanceDecision:
        """Create an immutable governance decision record with atomic audit event.

        The transaction_id is pre-generated and set on the decision record at
        INSERT time. The same transaction_id appears in the H13 audit event,
        linking them without needing a post-INSERT UPDATE (which would violate
        the append-only trigger).

        MUST be called before db.commit(). The caller commits.
        """
        now = utc_iso8601_z_now()
        decision_id = uuid.uuid4().hex[:32]
        tx_id = uuid.uuid4().hex[:32]

        evidence_snapshot_hash: str | None = None
        if evidence_snapshot:
            evidence_snapshot_hash = hashlib.sha256(
                json.dumps(evidence_snapshot, sort_keys=True).encode()
            ).hexdigest()[:32]

        resolved_approver = approver_id or actor_id

        decision = FaGovernanceDecision(
            id=decision_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            decision_type=decision_type,
            entity_type=entity_type,
            entity_id=entity_id,
            actor_id=actor_id,
            actor_subject=actor_subject,
            actor_name=actor_name,
            actor_email=actor_email,
            actor_role=actor_role,
            actor_auth_source=actor_auth_source,
            creator_id=creator_id or actor_id,
            reviewer_id=reviewer_id,
            approver_id=resolved_approver,
            decision_reason=decision_reason,
            decision_notes=decision_notes,
            status="active",
            evidence_snapshot_hash=evidence_snapshot_hash,
            evidence_refs=_json_list(evidence_refs),
            related_finding_ids=_json_list(related_finding_ids),
            related_control_ids=_json_list(related_control_ids),
            decision_at=now,
            effective_until=effective_until,
            review_date=review_date,
            transaction_id=tx_id,
            correlation_id=correlation_id,
            decision_metadata=json.dumps(decision_metadata)
            if decision_metadata
            else None,
        )
        db.add(decision)
        db.flush()

        emit_engagement_audit_event(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            event_type=f"decision.{decision_type}",
            actor=actor_id,
            reason_code=f"DECISION_{decision_type.upper()}",
            payload={
                "decision_id": decision_id,
                "decision_type": decision_type,
                "entity_type": entity_type,
                "entity_id": entity_id,
                "actor_name": actor_name,
                "actor_email": actor_email,
                "actor_role": actor_role,
                "decision_reason": decision_reason,
                "evidence_snapshot_hash": evidence_snapshot_hash,
                "effective_until": effective_until,
            },
            transaction_id=tx_id,
            correlation_id=correlation_id,
            entity_type=entity_type,
            entity_id=entity_id,
            actor_type="human_operator",
        )

        return decision

    def record_decision_with_risk_acceptance(
        self,
        db: Session,
        *,
        tenant_id: str,
        engagement_id: str,
        finding_id: str,
        actor_id: str,
        actor_subject: str | None = None,
        actor_name: str | None = None,
        actor_email: str | None = None,
        actor_role: str | None = None,
        decision_reason: str,
        risk_owner: str,
        risk_owner_email: str | None = None,
        business_justification: str,
        accepted_risk_level: str,
        expires_at: str,
        review_date: str,
        evidence_refs: list[str] | None = None,
        approver_name: str | None = None,
        approver_email: str | None = None,
        decision_notes: str | None = None,
        correlation_id: str | None = None,
    ) -> tuple[FaGovernanceDecision, FaRiskAcceptance]:
        """Create a risk acceptance record plus its governance decision atomically."""
        decision = self.record_decision(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            decision_type="risk_accepted",
            entity_type="finding",
            entity_id=finding_id,
            actor_id=actor_id,
            actor_subject=actor_subject,
            actor_name=actor_name,
            actor_email=actor_email,
            actor_role=actor_role,
            decision_reason=decision_reason,
            decision_notes=decision_notes,
            evidence_refs=evidence_refs,
            related_finding_ids=[finding_id],
            effective_until=expires_at,
            review_date=review_date,
            correlation_id=correlation_id,
            decision_metadata={
                "risk_owner": risk_owner,
                "accepted_risk_level": accepted_risk_level,
                "business_justification": business_justification,
            },
        )

        acceptance = FaRiskAcceptance(
            id=uuid.uuid4().hex[:32],
            decision_id=decision.id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            finding_id=finding_id,
            risk_owner=risk_owner,
            risk_owner_email=risk_owner_email,
            business_justification=business_justification,
            accepted_risk_level=accepted_risk_level,
            expires_at=expires_at,
            review_date=review_date,
            evidence_refs=_json_list(evidence_refs),
            approver_id=actor_id,
            approver_name=approver_name or actor_name,
            approver_email=approver_email or actor_email,
            status="active",
            created_at=utc_iso8601_z_now(),
        )
        db.add(acceptance)
        db.flush()

        return decision, acceptance

    def record_decision_with_exception(
        self,
        db: Session,
        *,
        tenant_id: str,
        engagement_id: str,
        actor_id: str,
        actor_subject: str | None = None,
        actor_name: str | None = None,
        actor_email: str | None = None,
        actor_role: str | None = None,
        decision_reason: str,
        exception_type: str,
        owner: str,
        owner_email: str | None = None,
        business_justification: str,
        expires_at: str,
        review_schedule: str | None = None,
        related_control_ids: list[str] | None = None,
        related_finding_ids: list[str] | None = None,
        compensating_controls: list[str] | None = None,
        approver_name: str | None = None,
        decision_notes: str | None = None,
        correlation_id: str | None = None,
    ) -> tuple[FaGovernanceDecision, FaGovernanceException]:
        """Create a governance exception record plus its decision atomically."""
        decision = self.record_decision(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            decision_type="exception_granted",
            entity_type="exception",
            entity_id=uuid.uuid4().hex[:16],
            actor_id=actor_id,
            actor_subject=actor_subject,
            actor_name=actor_name,
            actor_email=actor_email,
            actor_role=actor_role,
            decision_reason=decision_reason,
            decision_notes=decision_notes,
            related_control_ids=related_control_ids,
            related_finding_ids=related_finding_ids,
            effective_until=expires_at,
            review_date=review_schedule,
            correlation_id=correlation_id,
            decision_metadata={
                "exception_type": exception_type,
                "owner": owner,
                "business_justification": business_justification,
            },
        )

        exception = FaGovernanceException(
            id=uuid.uuid4().hex[:32],
            decision_id=decision.id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            exception_type=exception_type,
            owner=owner,
            owner_email=owner_email,
            business_justification=business_justification,
            expires_at=expires_at,
            review_schedule=review_schedule,
            related_control_ids=_json_list(related_control_ids),
            related_finding_ids=_json_list(related_finding_ids),
            compensating_controls=_json_list(compensating_controls),
            approver_id=actor_id,
            approver_name=approver_name or actor_name,
            status="active",
            created_at=utc_iso8601_z_now(),
        )
        db.add(exception)
        db.flush()

        return decision, exception

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_decision(
        self,
        db: Session,
        *,
        decision_id: str,
        tenant_id: str,
    ) -> FaGovernanceDecision | None:
        return db.execute(
            select(FaGovernanceDecision).where(
                FaGovernanceDecision.id == decision_id,
                FaGovernanceDecision.tenant_id == tenant_id,
            )
        ).scalar_one_or_none()

    def list_decisions(
        self,
        db: Session,
        *,
        tenant_id: str,
        engagement_id: str,
        decision_type: str | None = None,
        limit: int = 100,
    ) -> list[FaGovernanceDecision]:
        q = select(FaGovernanceDecision).where(
            FaGovernanceDecision.tenant_id == tenant_id,
            FaGovernanceDecision.engagement_id == engagement_id,
        )
        if decision_type:
            q = q.where(FaGovernanceDecision.decision_type == decision_type)
        q = q.order_by(FaGovernanceDecision.decision_at.desc()).limit(limit)
        return list(db.execute(q).scalars())

    def get_risk_acceptance(
        self,
        db: Session,
        *,
        acceptance_id: str,
        tenant_id: str,
    ) -> FaRiskAcceptance | None:
        return db.execute(
            select(FaRiskAcceptance).where(
                FaRiskAcceptance.id == acceptance_id,
                FaRiskAcceptance.tenant_id == tenant_id,
            )
        ).scalar_one_or_none()

    def list_risk_acceptances(
        self,
        db: Session,
        *,
        tenant_id: str,
        engagement_id: str,
        status: str | None = None,
        limit: int = 100,
    ) -> list[FaRiskAcceptance]:
        q = select(FaRiskAcceptance).where(
            FaRiskAcceptance.tenant_id == tenant_id,
            FaRiskAcceptance.engagement_id == engagement_id,
        )
        if status:
            q = q.where(FaRiskAcceptance.status == status)
        q = q.order_by(FaRiskAcceptance.created_at.desc()).limit(limit)
        return list(db.execute(q).scalars())

    def get_exception(
        self,
        db: Session,
        *,
        exception_id: str,
        tenant_id: str,
    ) -> FaGovernanceException | None:
        return db.execute(
            select(FaGovernanceException).where(
                FaGovernanceException.id == exception_id,
                FaGovernanceException.tenant_id == tenant_id,
            )
        ).scalar_one_or_none()

    def list_exceptions(
        self,
        db: Session,
        *,
        tenant_id: str,
        engagement_id: str,
        status: str | None = None,
        limit: int = 100,
    ) -> list[FaGovernanceException]:
        q = select(FaGovernanceException).where(
            FaGovernanceException.tenant_id == tenant_id,
            FaGovernanceException.engagement_id == engagement_id,
        )
        if status:
            q = q.where(FaGovernanceException.status == status)
        q = q.order_by(FaGovernanceException.created_at.desc()).limit(limit)
        return list(db.execute(q).scalars())

    # ------------------------------------------------------------------
    # Serialization helpers
    # ------------------------------------------------------------------

    @staticmethod
    def decision_to_dict(d: FaGovernanceDecision) -> dict[str, Any]:
        return {
            "decision_id": d.id,
            "tenant_id": d.tenant_id,
            "engagement_id": d.engagement_id,
            "decision_type": d.decision_type,
            "entity_type": d.entity_type,
            "entity_id": d.entity_id,
            "actor_id": d.actor_id,
            "actor_name": d.actor_name,
            "actor_email": d.actor_email,
            "actor_role": d.actor_role,
            "actor_auth_source": d.actor_auth_source,
            "approver_id": d.approver_id,
            "decision_reason": d.decision_reason,
            "decision_notes": d.decision_notes,
            "status": d.status,
            "evidence_snapshot_hash": d.evidence_snapshot_hash,
            "evidence_refs": json.loads(d.evidence_refs) if d.evidence_refs else [],
            "related_finding_ids": (
                json.loads(d.related_finding_ids) if d.related_finding_ids else []
            ),
            "related_control_ids": (
                json.loads(d.related_control_ids) if d.related_control_ids else []
            ),
            "decision_at": d.decision_at,
            "effective_until": d.effective_until,
            "review_date": d.review_date,
            "transaction_id": d.transaction_id,
            "correlation_id": d.correlation_id,
        }

    @staticmethod
    def risk_acceptance_to_dict(r: FaRiskAcceptance) -> dict[str, Any]:
        return {
            "acceptance_id": r.id,
            "decision_id": r.decision_id,
            "tenant_id": r.tenant_id,
            "engagement_id": r.engagement_id,
            "finding_id": r.finding_id,
            "risk_owner": r.risk_owner,
            "risk_owner_email": r.risk_owner_email,
            "business_justification": r.business_justification,
            "accepted_risk_level": r.accepted_risk_level,
            "expires_at": r.expires_at,
            "review_date": r.review_date,
            "evidence_refs": json.loads(r.evidence_refs) if r.evidence_refs else [],
            "approver_id": r.approver_id,
            "approver_name": r.approver_name,
            "approver_email": r.approver_email,
            "status": r.status,
            "created_at": r.created_at,
        }

    @staticmethod
    def exception_to_dict(e: FaGovernanceException) -> dict[str, Any]:
        return {
            "exception_id": e.id,
            "decision_id": e.decision_id,
            "tenant_id": e.tenant_id,
            "engagement_id": e.engagement_id,
            "exception_type": e.exception_type,
            "owner": e.owner,
            "owner_email": e.owner_email,
            "business_justification": e.business_justification,
            "expires_at": e.expires_at,
            "review_schedule": e.review_schedule,
            "related_control_ids": (
                json.loads(e.related_control_ids) if e.related_control_ids else []
            ),
            "related_finding_ids": (
                json.loads(e.related_finding_ids) if e.related_finding_ids else []
            ),
            "compensating_controls": (
                json.loads(e.compensating_controls) if e.compensating_controls else []
            ),
            "approver_id": e.approver_id,
            "approver_name": e.approver_name,
            "status": e.status,
            "created_at": e.created_at,
        }


governance_decision_svc = GovernanceDecisionService()
