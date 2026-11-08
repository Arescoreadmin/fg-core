"""
Chain of custody service for scanner evidence envelopes.

L14-SCAN-INTEGRITY-001

Records append-only custody events against fa_evidence_custody_events.
Every custody event is immutable after insertion (enforced by DB trigger
``fa_evidence_custody_append_only_trigger`` added in migration 0201).

Custody events answer: who handled this evidence, when, and what state
transition occurred?

NOT_STANDALONE: Requires the full fg-core stack (api/, services/, Postgres).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import text
from sqlalchemy.orm import Session

# ---------------------------------------------------------------------------
# Custody event types
# ---------------------------------------------------------------------------


class CustodyEventType(str, Enum):
    """Recognized chain-of-custody event types.

    COLLECTED       — evidence payload received from scanner runner
    INGESTED        — stored in fa_scan_evidence_envelopes
    NORMALIZED      — findings extracted and stored in fa_normalized_findings
    VERIFIED        — digest/signature verification completed
    LOCKED          — evidence locked by QA approval (H15 lifecycle)
    REVIEWED        — assessor reviewed the evidence
    REFERENCED_IN_REPORT — evidence cited in a generated report
    EXPORTED        — evidence exported for external consumption
    RETAINED        — retention policy applied
    LEGAL_HOLD      — legal hold applied by operator
    SUPERSEDED      — this evidence record was replaced by a newer scan
    """

    COLLECTED = "COLLECTED"
    INGESTED = "INGESTED"
    NORMALIZED = "NORMALIZED"
    VERIFIED = "VERIFIED"
    LOCKED = "LOCKED"
    REVIEWED = "REVIEWED"
    REFERENCED_IN_REPORT = "REFERENCED_IN_REPORT"
    EXPORTED = "EXPORTED"
    RETAINED = "RETAINED"
    LEGAL_HOLD = "LEGAL_HOLD"
    SUPERSEDED = "SUPERSEDED"


# ---------------------------------------------------------------------------
# Custody service
# ---------------------------------------------------------------------------


class EvidenceCustodyService:
    """Record and retrieve chain-of-custody events for scanner evidence.

    All methods are fail-closed:
    - Cross-tenant access raises PermissionError (never leaks data)
    - Missing evidence raises LookupError on get_history
    - record() raises on cross-tenant evidence_id
    """

    def _assert_tenant(self, db: Session, evidence_id: str, tenant_id: str) -> None:
        """Verify the evidence record belongs to tenant_id.

        Raises PermissionError on mismatch (fail-closed).
        Raises LookupError when evidence_id does not exist.
        """
        row = db.execute(
            text("SELECT tenant_id FROM fa_scan_evidence_envelopes WHERE id = :eid"),
            {"eid": evidence_id},
        ).fetchone()
        if row is None:
            raise LookupError(f"Evidence record not found: {evidence_id}")
        if row.tenant_id != tenant_id:
            # Fail-closed: raise rather than return MISSING to force explicit
            # handling in the caller (unlike verify_by_id which is query-only).
            raise PermissionError("Cross-tenant custody access denied")

    def record(
        self,
        db: Session,
        *,
        evidence_id: str,
        tenant_id: str,
        engagement_id: str,
        event_type: CustodyEventType,
        actor: str,
        actor_type: str = "system",
        from_state: str | None = None,
        to_state: str | None = None,
        reason: str | None = None,
        correlation_id: str | None = None,
        digest_ref: str | None = None,
        commit: bool = True,
    ) -> str:
        """Insert a custody event.  Returns the new event UUID.

        Raises PermissionError on cross-tenant access.
        Raises LookupError if evidence_id does not exist.

        Duplicate event types are allowed (idempotent logging — the caller
        may retry on transient failure and the second insert is preserved as
        a separate event with its own timestamp).

        Out-of-order events are allowed — the custody log is append-only
        and no ordering enforcement is applied at the service level.
        """
        self._assert_tenant(db, evidence_id, tenant_id)

        event_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        db.execute(
            text(
                """
                INSERT INTO fa_evidence_custody_events
                    (id, evidence_id, tenant_id, engagement_id, event_type,
                     actor, actor_type, from_state, to_state, reason,
                     correlation_id, digest_ref, created_at)
                VALUES
                    (:id, :evidence_id, :tenant_id, :engagement_id, :event_type,
                     :actor, :actor_type, :from_state, :to_state, :reason,
                     :correlation_id, :digest_ref, :created_at)
                """
            ),
            {
                "id": event_id,
                "evidence_id": evidence_id,
                "tenant_id": tenant_id,
                "engagement_id": engagement_id,
                "event_type": event_type.value,
                "actor": actor,
                "actor_type": actor_type,
                "from_state": from_state,
                "to_state": to_state,
                "reason": reason,
                "correlation_id": correlation_id,
                "digest_ref": digest_ref,
                "created_at": now,
            },
        )
        # commit=False lets runtime capture persist the envelope and its custody
        # events atomically in the caller's transaction (L14-SCAN-RUNNER-INTEGRITY-001).
        if commit:
            db.commit()
        return event_id

    def get_history(
        self, db: Session, *, evidence_id: str, tenant_id: str
    ) -> list[dict]:
        """Return ordered custody events for an evidence record.

        Events are returned in ascending ``created_at`` order (oldest first).
        Each item is a plain dict with all custody event columns.

        Raises PermissionError on cross-tenant access.
        Raises LookupError if evidence_id does not exist.
        """
        self._assert_tenant(db, evidence_id, tenant_id)

        rows = db.execute(
            text(
                """
                SELECT id, evidence_id, tenant_id, engagement_id, event_type,
                       actor, actor_type, from_state, to_state, reason,
                       correlation_id, digest_ref, created_at
                FROM fa_evidence_custody_events
                WHERE evidence_id = :eid AND tenant_id = :tid
                ORDER BY created_at ASC
                """
            ),
            {"eid": evidence_id, "tid": tenant_id},
        ).fetchall()

        return [dict(row._mapping) for row in rows]


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

custody_svc = EvidenceCustodyService()
