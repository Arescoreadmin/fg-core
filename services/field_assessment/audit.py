"""Field assessment audit event emission.

H13 fix: AuditAtomicityService enforces the invariant that every audit event
is flushed into the same DB transaction as its corresponding mutation, so
mutation + audit commit atomically or rollback together.

Usage:
    from services.field_assessment.audit import audit_atomicity_svc

    # Inside a route handler, BEFORE db.commit():
    tx_id = audit_atomicity_svc.emit(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        event_type="engagement.metadata_updated",
        actor=actor,
        actor_type="human_operator",
        reason_code="ENGAGEMENT_METADATA_UPDATED",
        entity_type="engagement",
        entity_id=engagement_id,
        payload={"before": before_snapshot, "after": after_snapshot},
    )
    db.commit()
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaEngagementAuditEvent
from services.canonical import utc_iso8601_z_now


def emit_engagement_audit_event(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    event_type: str,
    actor: str,
    reason_code: str,
    payload: dict[str, Any],
    # H13 transaction correlation fields (populated by AuditAtomicityService)
    transaction_id: str | None = None,
    correlation_id: str | None = None,
    before_hash: str | None = None,
    after_hash: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    actor_type: str | None = None,
) -> None:
    """Append an immutable audit event. MUST be called before db.commit().

    Calling this function after db.commit() is a bug: the flush below will
    execute in a new implicit transaction that is never committed, causing the
    audit event to be silently discarded when the session closes.
    """
    event_id = hashlib.sha256(
        f"{tenant_id}|{engagement_id}|{event_type}|{utc_iso8601_z_now()}|{uuid.uuid4()}".encode()
    ).hexdigest()[:32]

    schema_v = "2.0" if transaction_id is not None else "1.0"

    db.add(
        FaEngagementAuditEvent(
            id=event_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            event_type=event_type,
            actor=actor,
            reason_code=reason_code,
            payload=payload,
            schema_version=schema_v,
            created_at=utc_iso8601_z_now(),
            transaction_id=transaction_id,
            correlation_id=correlation_id,
            before_hash=before_hash,
            after_hash=after_hash,
            entity_type=entity_type,
            entity_id=entity_id,
            actor_type=actor_type,
        )
    )
    db.flush()


class AuditAtomicityService:
    """Transaction-bound audit emission guaranteeing mutation + event atomicity.

    Every call to emit() flushes the audit event into the current open
    transaction.  The route is responsible for a single db.commit() that
    commits both the mutation and the audit event together.

    Invariant: emit() MUST be called BEFORE db.commit(). Any exception raised
    inside emit() will propagate and prevent db.commit() from running, so
    SQLAlchemy will roll back the entire transaction (mutation + partial audit
    state) when the session closes.
    """

    @staticmethod
    def compute_entity_hash(entity_state: dict[str, Any]) -> str:
        """SHA-256 of canonical JSON entity state for before/after integrity records."""
        canonical = json.dumps(entity_state, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()

    @staticmethod
    def emit(
        db: Session,
        *,
        tenant_id: str,
        engagement_id: str,
        event_type: str,
        actor: str,
        actor_type: str,
        reason_code: str,
        entity_type: str,
        entity_id: str,
        payload: dict[str, Any],
        before_hash: str | None = None,
        after_hash: str | None = None,
        correlation_id: str | None = None,
    ) -> str:
        """Emit a schema v2.0 audit event. Returns the generated transaction_id."""
        tx_id = uuid.uuid4().hex[:32]
        emit_engagement_audit_event(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            event_type=event_type,
            actor=actor,
            reason_code=reason_code,
            payload=payload,
            transaction_id=tx_id,
            correlation_id=correlation_id,
            before_hash=before_hash,
            after_hash=after_hash,
            entity_type=entity_type,
            entity_id=entity_id,
            actor_type=actor_type,
        )
        return tx_id


audit_atomicity_svc = AuditAtomicityService()
