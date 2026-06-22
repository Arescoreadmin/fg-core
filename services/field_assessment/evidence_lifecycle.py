"""H15: Evidence Lifecycle Locks & Chain-of-Custody Enforcement.

EvidenceLifecycleService enforces a 3-state lifecycle for all evidence entities:

  collected  →  locked  →  legal_hold
                          ↑
              (operator can also apply legal_hold from collected)

'collected'  — default; evidence is mutable
'locked'     — applied in bulk at QA approval; content and deletion blocked
'legal_hold' — operator-applied; supersedes locked; removal also audited

Public API
----------
assert_mutable(db, *, ...)       — raise HTTP 409 if evidence is locked/legal_hold
assert_links_not_locked(db, *,)  — raise HTTP 409 if any link to/from entity is locked
lock_evidence_for_engagement()   — bulk collected→locked at QA approval
apply_legal_hold()               — transition a single evidence item to legal_hold
                                   works from both 'collected' and 'locked' states

Legal hold release is out of scope for H15 — requires dual authorization and
a future LEGAL_HOLD_RELEASE_WORKFLOW capability.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import HTTPException
from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from api.error_contracts import api_error
from api.db_models_field_assessment import (
    FaDocumentAnalysis,
    FaEvidenceLifecycleEvent,
    FaEvidenceLink,
    FaFieldObservation,
    FaLegalHold,
    FaScanResult,
)
from services.canonical import utc_iso8601_z_now
from services.field_assessment.audit import audit_atomicity_svc

_EVIDENCE_MODEL_MAP: dict[str, Any] = {
    "field_observation": FaFieldObservation,
    "scan_result": FaScanResult,
    "document_analysis": FaDocumentAnalysis,
    "evidence_link": FaEvidenceLink,
}

_MUTABLE_STATES = frozenset({"collected"})
_IMMUTABLE_STATES = frozenset({"locked", "legal_hold"})


class EvidenceLifecycleService:
    """H15 lifecycle state machine and chain-of-custody enforcement."""

    # ------------------------------------------------------------------
    # Guards (called from route handlers before mutations)
    # ------------------------------------------------------------------

    def assert_mutable(
        self,
        db: Session,
        *,
        tenant_id: str,
        engagement_id: str,
        evidence_type: str,
        evidence_id: str,
    ) -> None:
        """Raise HTTP 409 if the evidence item is locked or under legal hold."""
        model = _EVIDENCE_MODEL_MAP.get(evidence_type)
        if model is None:
            return
        state = db.execute(
            select(model.lifecycle_state).where(
                model.id == evidence_id,
                model.engagement_id == engagement_id,
                model.tenant_id == tenant_id,
            )
        ).scalar_one_or_none()
        if state in _IMMUTABLE_STATES:
            raise HTTPException(
                status_code=409,
                detail=api_error(
                    "EVIDENCE_LOCKED",
                    f"{evidence_type} {evidence_id!r} is {state!r} "
                    "and cannot be mutated or deleted",
                ),
            )

    def assert_links_not_locked(
        self,
        db: Session,
        *,
        tenant_id: str,
        engagement_id: str,
        entity_id: str,
        entity_type: str,
    ) -> None:
        """Raise HTTP 409 if any evidence link attached to entity_id is locked."""
        locked_link_id = db.execute(
            select(FaEvidenceLink.id)
            .where(
                FaEvidenceLink.tenant_id == tenant_id,
                FaEvidenceLink.engagement_id == engagement_id,
                or_(
                    FaEvidenceLink.source_entity_id == entity_id,
                    FaEvidenceLink.evidence_entity_id == entity_id,
                ),
                FaEvidenceLink.lifecycle_state.in_(list(_IMMUTABLE_STATES)),
            )
            .limit(1)
        ).scalar_one_or_none()
        if locked_link_id is not None:
            raise HTTPException(
                status_code=409,
                detail=api_error(
                    "EVIDENCE_LINK_LOCKED",
                    f"A locked evidence link exists for {entity_type} {entity_id!r} "
                    "and cannot be removed or replaced",
                ),
            )

    # ------------------------------------------------------------------
    # Lifecycle transitions
    # ------------------------------------------------------------------

    def lock_evidence_for_engagement(
        self,
        db: Session,
        *,
        tenant_id: str,
        engagement_id: str,
        actor: str,
        actor_type: str,
        reason: str,
    ) -> int:
        """Bulk-transition all collected evidence in the engagement to locked.

        Emits one audit event per evidence type summarising the count.
        Writes one FaEvidenceLifecycleEvent row per item for chain-of-custody.
        Returns the total count of items locked.
        """
        now = utc_iso8601_z_now()
        total_locked = 0

        for evidence_type, model in _EVIDENCE_MODEL_MAP.items():
            ids: list[str] = list(
                db.execute(
                    select(model.id).where(
                        model.tenant_id == tenant_id,
                        model.engagement_id == engagement_id,
                        model.lifecycle_state == "collected",
                    )
                ).scalars()
            )
            if not ids:
                continue

            db.execute(
                update(model)
                .where(
                    model.tenant_id == tenant_id,
                    model.engagement_id == engagement_id,
                    model.id.in_(ids),
                )
                .values(lifecycle_state="locked")
            )

            tx_id = audit_atomicity_svc.emit(
                db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                event_type="evidence.lifecycle.locked",
                actor=actor,
                actor_type=actor_type,
                reason_code="EVIDENCE_LIFECYCLE_TRANSITION",
                entity_type=evidence_type,
                entity_id=f"bulk:{len(ids)}",
                payload={
                    "old_state": "collected",
                    "new_state": "locked",
                    "reason": reason,
                    "count": len(ids),
                    "evidence_ids": ids,
                },
            )

            for evidence_id in ids:
                db.add(
                    FaEvidenceLifecycleEvent(
                        id=uuid.uuid4().hex[:32],
                        tenant_id=tenant_id,
                        engagement_id=engagement_id,
                        evidence_type=evidence_type,
                        evidence_id=evidence_id,
                        old_state="collected",
                        new_state="locked",
                        actor=actor,
                        actor_type=actor_type,
                        reason=reason,
                        transaction_id=tx_id,
                        created_at=now,
                        schema_version="1.0",
                    )
                )

            total_locked += len(ids)

        return total_locked

    def apply_legal_hold(
        self,
        db: Session,
        *,
        tenant_id: str,
        engagement_id: str,
        evidence_type: str,
        evidence_id: str,
        reason: str,
        actor: str,
        actor_type: str,
    ) -> None:
        """Transition evidence to legal_hold state."""
        model = _EVIDENCE_MODEL_MAP[evidence_type]
        row = db.execute(
            select(model.lifecycle_state).where(
                model.id == evidence_id,
                model.tenant_id == tenant_id,
                model.engagement_id == engagement_id,
            )
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(
                status_code=404,
                detail=api_error(
                    "EVIDENCE_NOT_FOUND", f"{evidence_type} {evidence_id!r} not found"
                ),
            )
        old_state: str = row
        db.execute(
            update(model)
            .where(
                model.id == evidence_id,
                model.tenant_id == tenant_id,
                model.engagement_id == engagement_id,
            )
            .values(lifecycle_state="legal_hold")
        )
        now = utc_iso8601_z_now()
        tx_id = audit_atomicity_svc.emit(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            event_type="evidence.lifecycle.legal_hold",
            actor=actor,
            actor_type=actor_type,
            reason_code="EVIDENCE_LEGAL_HOLD_APPLIED",
            entity_type=evidence_type,
            entity_id=evidence_id,
            payload={
                "old_state": old_state,
                "new_state": "legal_hold",
                "reason": reason,
            },
        )
        db.add(
            FaLegalHold(
                id=uuid.uuid4().hex[:32],
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                evidence_type=evidence_type,
                evidence_id=evidence_id,
                action="applied",
                reason=reason,
                actor=actor,
                actor_type=actor_type,
                transaction_id=tx_id,
                created_at=now,
                schema_version="1.0",
            )
        )
        db.add(
            FaEvidenceLifecycleEvent(
                id=uuid.uuid4().hex[:32],
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                evidence_type=evidence_type,
                evidence_id=evidence_id,
                old_state=old_state,
                new_state="legal_hold",
                actor=actor,
                actor_type=actor_type,
                reason=reason,
                transaction_id=tx_id,
                created_at=now,
                schema_version="1.0",
            )
        )

    # remove_legal_hold() is out of scope for H15.
    # Legal hold release requires dual authorization + justification + audit review
    # and is deferred to a future LEGAL_HOLD_RELEASE_WORKFLOW capability.


evidence_lifecycle_svc = EvidenceLifecycleService()
