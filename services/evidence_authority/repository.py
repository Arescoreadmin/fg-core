"""services/evidence_authority/repository.py — Data access layer for Evidence Authority.

All queries are tenant-scoped. No query path bypasses tenant_id.
This layer is the only code that touches fa_evidence* tables directly.

SQLAlchemy Session (sync) — consistent with the rest of fg-core.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from api.db_models_evidence_authority import (
    FaEvidence,
    FaEvidenceAuditEvent,
    FaEvidenceOwnership,
    FaEvidenceRelationship,
    FaEvidenceTrustEvent,
)
from services.evidence_authority.models import (
    EvidenceAuditEventType,
    EvidenceLifecycleState,
    EvidenceTrustState,
)


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class EvidenceRepository:
    """Tenant-scoped data access for fa_evidence* tables."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    # ------------------------------------------------------------------
    # fa_evidence
    # ------------------------------------------------------------------

    def create_evidence(self, record: FaEvidence) -> FaEvidence:
        self._db.add(record)
        self._db.flush()
        return record

    def get_evidence(self, evidence_id: str) -> Optional[FaEvidence]:
        return (
            self._db.query(FaEvidence)
            .filter(
                FaEvidence.id == evidence_id,
                FaEvidence.tenant_id == self._tenant_id,
            )
            .first()
        )

    def get_evidence_by_ref(self, evidence_ref: str) -> Optional[FaEvidence]:
        return (
            self._db.query(FaEvidence)
            .filter(
                FaEvidence.evidence_ref == evidence_ref,
                FaEvidence.tenant_id == self._tenant_id,
            )
            .first()
        )

    def list_evidence(
        self,
        *,
        lifecycle_state: Optional[str] = None,
        trust_state: Optional[str] = None,
        classification: Optional[str] = None,
        source_type: Optional[str] = None,
        engagement_id: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[FaEvidence], int]:
        q = self._db.query(FaEvidence).filter(
            FaEvidence.tenant_id == self._tenant_id
        )
        if lifecycle_state:
            q = q.filter(FaEvidence.lifecycle_state == lifecycle_state)
        if trust_state:
            q = q.filter(FaEvidence.trust_state == trust_state)
        if classification:
            q = q.filter(FaEvidence.classification == classification)
        if source_type:
            q = q.filter(FaEvidence.source_type == source_type)
        if engagement_id:
            q = q.filter(FaEvidence.engagement_id == engagement_id)

        total = q.count()
        items = (
            q.order_by(FaEvidence.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total

    def save_evidence(self, record: FaEvidence) -> FaEvidence:
        self._db.flush()
        return record

    # ------------------------------------------------------------------
    # fa_evidence_ownership
    # ------------------------------------------------------------------

    def create_ownership(self, record: FaEvidenceOwnership) -> FaEvidenceOwnership:
        self._db.add(record)
        self._db.flush()
        return record

    def get_ownership(self, ownership_id: str) -> Optional[FaEvidenceOwnership]:
        return (
            self._db.query(FaEvidenceOwnership)
            .filter(
                FaEvidenceOwnership.id == ownership_id,
                FaEvidenceOwnership.tenant_id == self._tenant_id,
            )
            .first()
        )

    def list_ownership(
        self,
        evidence_id: str,
        *,
        active_only: bool = False,
    ) -> list[FaEvidenceOwnership]:
        q = self._db.query(FaEvidenceOwnership).filter(
            FaEvidenceOwnership.tenant_id == self._tenant_id,
            FaEvidenceOwnership.evidence_id == evidence_id,
        )
        if active_only:
            q = q.filter(FaEvidenceOwnership.is_active == 1)
        return q.order_by(FaEvidenceOwnership.assigned_at.desc()).all()

    def save_ownership(self, record: FaEvidenceOwnership) -> FaEvidenceOwnership:
        self._db.flush()
        return record

    # ------------------------------------------------------------------
    # fa_evidence_relationships
    # ------------------------------------------------------------------

    def create_relationship(
        self, record: FaEvidenceRelationship
    ) -> FaEvidenceRelationship:
        self._db.add(record)
        self._db.flush()
        return record

    def get_relationship(
        self,
        evidence_id: str,
        related_entity_type: str,
        related_entity_id: str,
        relationship_type: str,
    ) -> Optional[FaEvidenceRelationship]:
        return (
            self._db.query(FaEvidenceRelationship)
            .filter(
                FaEvidenceRelationship.tenant_id == self._tenant_id,
                FaEvidenceRelationship.evidence_id == evidence_id,
                FaEvidenceRelationship.related_entity_type == related_entity_type,
                FaEvidenceRelationship.related_entity_id == related_entity_id,
                FaEvidenceRelationship.relationship_type == relationship_type,
            )
            .first()
        )

    def list_relationships(
        self,
        evidence_id: str,
        *,
        related_entity_type: Optional[str] = None,
    ) -> list[FaEvidenceRelationship]:
        q = self._db.query(FaEvidenceRelationship).filter(
            FaEvidenceRelationship.tenant_id == self._tenant_id,
            FaEvidenceRelationship.evidence_id == evidence_id,
        )
        if related_entity_type:
            q = q.filter(
                FaEvidenceRelationship.related_entity_type == related_entity_type
            )
        return q.order_by(FaEvidenceRelationship.created_at.desc()).all()

    def list_evidence_for_entity(
        self,
        related_entity_type: str,
        related_entity_id: str,
    ) -> list[FaEvidenceRelationship]:
        return (
            self._db.query(FaEvidenceRelationship)
            .filter(
                FaEvidenceRelationship.tenant_id == self._tenant_id,
                FaEvidenceRelationship.related_entity_type == related_entity_type,
                FaEvidenceRelationship.related_entity_id == related_entity_id,
            )
            .order_by(FaEvidenceRelationship.created_at.desc())
            .all()
        )

    # ------------------------------------------------------------------
    # fa_evidence_trust_events
    # ------------------------------------------------------------------

    def create_trust_event(
        self, record: FaEvidenceTrustEvent
    ) -> FaEvidenceTrustEvent:
        self._db.add(record)
        self._db.flush()
        return record

    def get_latest_trust_event(
        self, evidence_id: str
    ) -> Optional[FaEvidenceTrustEvent]:
        return (
            self._db.query(FaEvidenceTrustEvent)
            .filter(
                FaEvidenceTrustEvent.tenant_id == self._tenant_id,
                FaEvidenceTrustEvent.evidence_id == evidence_id,
            )
            .order_by(FaEvidenceTrustEvent.created_at.desc())
            .first()
        )

    def list_trust_events(self, evidence_id: str) -> list[FaEvidenceTrustEvent]:
        return (
            self._db.query(FaEvidenceTrustEvent)
            .filter(
                FaEvidenceTrustEvent.tenant_id == self._tenant_id,
                FaEvidenceTrustEvent.evidence_id == evidence_id,
            )
            .order_by(FaEvidenceTrustEvent.created_at.asc())
            .all()
        )

    def compute_trust_event_hash(
        self,
        event_id: str,
        evidence_id: str,
        from_state: str,
        to_state: str,
        verifier_id: str,
        created_at: str,
        prev_event_hash: Optional[str],
    ) -> str:
        canonical = json.dumps(
            {
                "event_id": event_id,
                "evidence_id": evidence_id,
                "tenant_id": self._tenant_id,
                "from_trust_state": from_state,
                "to_trust_state": to_state,
                "verifier_id": verifier_id,
                "created_at": created_at,
                "prev_event_hash": prev_event_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return _sha256(canonical)

    # ------------------------------------------------------------------
    # fa_evidence_audit_events
    # ------------------------------------------------------------------

    def create_audit_event(
        self, record: FaEvidenceAuditEvent
    ) -> FaEvidenceAuditEvent:
        self._db.add(record)
        self._db.flush()
        return record

    def list_audit_events(
        self,
        evidence_id: str,
        *,
        event_type: Optional[str] = None,
        offset: int = 0,
        limit: int = 100,
    ) -> tuple[list[FaEvidenceAuditEvent], int]:
        q = self._db.query(FaEvidenceAuditEvent).filter(
            FaEvidenceAuditEvent.tenant_id == self._tenant_id,
            FaEvidenceAuditEvent.evidence_id == evidence_id,
        )
        if event_type:
            q = q.filter(FaEvidenceAuditEvent.event_type == event_type)
        total = q.count()
        items = (
            q.order_by(FaEvidenceAuditEvent.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total

    # ------------------------------------------------------------------
    # Dashboard aggregation
    # ------------------------------------------------------------------

    def count_by_lifecycle_state(self) -> dict[str, int]:
        rows = (
            self._db.query(
                FaEvidence.lifecycle_state,
                # SQLAlchemy func.count
            )
            .filter(FaEvidence.tenant_id == self._tenant_id)
            .all()
        )
        from sqlalchemy import func as sa_func
        results = (
            self._db.query(
                FaEvidence.lifecycle_state,
                sa_func.count(FaEvidence.id).label("cnt"),
            )
            .filter(FaEvidence.tenant_id == self._tenant_id)
            .group_by(FaEvidence.lifecycle_state)
            .all()
        )
        return {state: cnt for state, cnt in results}

    def count_by_trust_state(self) -> dict[str, int]:
        from sqlalchemy import func as sa_func
        results = (
            self._db.query(
                FaEvidence.trust_state,
                sa_func.count(FaEvidence.id).label("cnt"),
            )
            .filter(FaEvidence.tenant_id == self._tenant_id)
            .group_by(FaEvidence.trust_state)
            .all()
        )
        return {state: cnt for state, cnt in results}

    def count_by_classification(self) -> dict[str, int]:
        from sqlalchemy import func as sa_func
        results = (
            self._db.query(
                FaEvidence.classification,
                sa_func.count(FaEvidence.id).label("cnt"),
            )
            .filter(FaEvidence.tenant_id == self._tenant_id)
            .group_by(FaEvidence.classification)
            .all()
        )
        return {cls: cnt for cls, cnt in results}

    def count_by_source_type(self) -> dict[str, int]:
        from sqlalchemy import func as sa_func
        results = (
            self._db.query(
                FaEvidence.source_type,
                sa_func.count(FaEvidence.id).label("cnt"),
            )
            .filter(FaEvidence.tenant_id == self._tenant_id)
            .group_by(FaEvidence.source_type)
            .all()
        )
        return {src: cnt for src, cnt in results}

    def count_expiring_soon(self, days: int = 30) -> int:
        from datetime import timedelta
        cutoff = (datetime.now(tz=timezone.utc) + timedelta(days=days)).isoformat()
        now = datetime.now(tz=timezone.utc).isoformat()
        return (
            self._db.query(FaEvidence)
            .filter(
                FaEvidence.tenant_id == self._tenant_id,
                FaEvidence.expires_at.isnot(None),
                FaEvidence.expires_at > now,
                FaEvidence.expires_at <= cutoff,
                FaEvidence.lifecycle_state.notin_([
                    EvidenceLifecycleState.EXPIRED.value,
                    EvidenceLifecycleState.REVOKED.value,
                    EvidenceLifecycleState.ARCHIVED.value,
                ]),
            )
            .count()
        )

    def count_without_owner(self) -> int:
        return (
            self._db.query(FaEvidence)
            .filter(
                FaEvidence.tenant_id == self._tenant_id,
                FaEvidence.owner_id.is_(None),
            )
            .count()
        )

    def count_without_relationships(self) -> int:
        from sqlalchemy import func as sa_func, not_, exists
        return (
            self._db.query(FaEvidence)
            .filter(
                FaEvidence.tenant_id == self._tenant_id,
                ~exists().where(
                    FaEvidenceRelationship.evidence_id == FaEvidence.id,
                    FaEvidenceRelationship.tenant_id == self._tenant_id,
                ),
            )
            .count()
        )
