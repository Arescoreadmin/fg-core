"""services/evidence_authority/engine.py — Business logic for Evidence Authority.

This engine is the single write authority for fa_evidence* tables.
No other service writes to these tables directly.

All mutating operations:
  1. Validate inputs (fail-closed)
  2. Enforce tenant isolation
  3. Execute state transition via the formal state machine
  4. Write the audit event (always, never skipped)
  5. Emit the timeline event
  6. Update the canonical fa_evidence record last (idempotent write order)

The engine never exposes raw ORM rows — it always returns schema objects.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from api.db_models_evidence_authority import (
    FaEvidence,
    FaEvidenceAuditEvent,
    FaEvidenceControlLink,
    FaEvidenceOwnership,
    FaEvidenceRelationship,
    FaEvidenceRiskLink,
    FaEvidenceTrustEvent,
    FaVerification,
)
from services.evidence_authority.models import (
    IMMUTABLE_LIFECYCLE_STATES,
    TRUST_STATE_SCORE_FLOOR,
    ActorType,
    EvidenceAuditEventType,
    EvidenceLifecycleState,
    EvidenceOwnershipRole,
    EvidenceTrustState,
    VerificationResult,
    VerificationSlaStatus,
    validate_lifecycle_transition,
    validate_trust_transition,
)
from services.evidence_authority.repository import EvidenceRepository
from services.evidence_authority.quality import compute_quality_scores
from services.evidence_authority.schemas import (
    AssignOwnershipRequest,
    CGINSnapshotBundle,
    ControlLinkConflict,
    ControlLinkListResponse,
    ControlLinkResponse,
    CoverageAnalyticsResponse,
    CoverageSnapshot,
    CreateEvidenceRequest,
    CreateVerificationRequest,
    EvidenceAuditEventResponse,
    EvidenceAuditListResponse,
    EvidenceDashboardResponse,
    EvidenceImmutableState,
    EvidenceInvalidTransition,
    EvidenceInvalidTrustTransition,
    EvidenceListResponse,
    EvidenceNotFound,
    EvidenceOwnershipListResponse,
    EvidenceOwnershipNotFound,
    EvidenceOwnershipResponse,
    EvidenceQualityScoreResponse,
    EvidenceRelationshipConflict,
    EvidenceRelationshipListResponse,
    EvidenceRelationshipResponse,
    EvidenceResponse,
    EvidenceStatusItemResponse,
    EvidenceStatusReportResponse,
    EvidenceStatusSnapshot,
    EvidenceTrustEventResponse,
    EvidenceTrustHistoryResponse,
    HealthSignalsResponse,
    HealthSnapshot,
    LinkControlRequest,
    LinkRelationshipRequest,
    LinkRiskRequest,
    RevokeOwnershipRequest,
    RiskLinkConflict,
    RiskLinkListResponse,
    RiskLinkResponse,
    SetSlaDeadlinesRequest,
    SlaStatusResponse,
    TransitionLifecycleRequest,
    UpdateEvidenceMetadataRequest,
    VerificationListResponse,
    VerificationResponse,
    VerificationSnapshot,
    VerificationSummaryResponse,
    VerifyEvidenceRequest,
)

from services.governance.timeline import TimelineStore
from services.governance.timeline.identity import derive_event_id
from services.governance.timeline.models import (
    SourceType as TimelineSourceType,
    TimelineEvent,
)
from services.canonical import utc_iso8601_z_now

# Timeline event source type for this service
_TIMELINE_SOURCE_TYPE = "EVIDENCE"
_SCHEMA_VERSION = "1.0"

_timeline_store = TimelineStore()


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


def _slugify_ref(title: str, uid: str) -> str:
    """Create a stable human-friendly evidence_ref from title + id prefix."""
    slug = title.lower().replace(" ", "-")[:40]
    # keep only safe chars
    slug = "".join(c for c in slug if c.isalnum() or c == "-")
    return f"{slug}-{uid[:8]}"


def _compute_integrity_hash(
    evidence_id: str,
    tenant_id: str,
    title: str,
    source_type: str,
    collection_method: str,
    collected_at: str,
    creator_id: str,
) -> str:
    """Deterministic integrity hash of the immutable identity fields."""
    canonical = json.dumps(
        {
            "evidence_id": evidence_id,
            "tenant_id": tenant_id,
            "title": title,
            "source_type": source_type,
            "collection_method": collection_method,
            "collected_at": collected_at,
            "creator_id": creator_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _to_response(row: FaEvidence) -> EvidenceResponse:
    import json as _json

    labels_raw = getattr(row, "classification_labels", "[]") or "[]"
    try:
        labels = _json.loads(labels_raw) if isinstance(labels_raw, str) else labels_raw
    except Exception:
        labels = []
    return EvidenceResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        evidence_ref=row.evidence_ref,
        lifecycle_state=row.lifecycle_state,
        classification=row.classification,
        classification_labels=labels,
        source_type=row.source_type,
        source_system=row.source_system,
        source_ref=row.source_ref,
        collection_method=row.collection_method,
        title=row.title,
        description=row.description,
        content_hash=row.content_hash,
        content_hash_algorithm=row.content_hash_algorithm,
        integrity_hash=row.integrity_hash,
        trust_state=row.trust_state,
        trust_score=row.trust_score,
        verification_count=row.verification_count,
        last_verification_source=row.last_verification_source,
        owner_id=row.owner_id,
        owner_type=row.owner_type,
        creator_id=row.creator_id,
        creator_type=row.creator_type,
        engagement_id=row.engagement_id,
        collected_at=row.collected_at,
        submitted_at=row.submitted_at,
        reviewed_at=row.reviewed_at,
        verified_at=row.verified_at,
        expires_at=row.expires_at,
        revoked_at=row.revoked_at,
        archived_at=row.archived_at,
        evidence_version=row.evidence_version,
        superseded_by=row.superseded_by,
        schema_version=row.schema_version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        freshness_score=getattr(row, "freshness_score", None),
        verification_score=getattr(row, "verification_score", None),
        completeness_score=getattr(row, "completeness_score", None),
        quality_last_computed_at=getattr(row, "quality_last_computed_at", None),
    )


def _to_ownership_response(row: FaEvidenceOwnership) -> EvidenceOwnershipResponse:
    return EvidenceOwnershipResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        evidence_id=row.evidence_id,
        role=row.role,
        actor_id=row.actor_id,
        actor_type=row.actor_type,
        assigned_at=row.assigned_at,
        assigned_by=row.assigned_by,
        revoked_at=row.revoked_at,
        revoked_by=row.revoked_by,
        is_active=bool(row.is_active),
        created_at=row.created_at,
    )


def _to_relationship_response(
    row: FaEvidenceRelationship,
) -> EvidenceRelationshipResponse:
    import json as _json

    meta_raw = getattr(row, "link_metadata", "{}") or "{}"
    try:
        meta = _json.loads(meta_raw) if isinstance(meta_raw, str) else meta_raw
    except Exception:
        meta = {}
    return EvidenceRelationshipResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        evidence_id=row.evidence_id,
        related_entity_type=row.related_entity_type,
        related_entity_id=row.related_entity_id,
        relationship_type=row.relationship_type,
        link_metadata=meta,
        linked_at=row.linked_at,
        linked_by=row.linked_by,
        created_at=row.created_at,
    )


def _to_trust_event_response(row: FaEvidenceTrustEvent) -> EvidenceTrustEventResponse:
    return EvidenceTrustEventResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        evidence_id=row.evidence_id,
        from_trust_state=row.from_trust_state,
        to_trust_state=row.to_trust_state,
        verification_source=row.verification_source,
        verifier_id=row.verifier_id,
        verifier_type=row.verifier_type,
        verification_method=row.verification_method,
        confidence_score=row.confidence_score,
        notes=row.notes,
        event_hash=row.event_hash,
        prev_event_hash=row.prev_event_hash,
        created_at=row.created_at,
    )


def _to_audit_event_response(row: FaEvidenceAuditEvent) -> EvidenceAuditEventResponse:
    import json as _json

    meta_raw = getattr(row, "event_metadata", "{}") or "{}"
    try:
        meta = _json.loads(meta_raw) if isinstance(meta_raw, str) else meta_raw
    except Exception:
        meta = {}
    return EvidenceAuditEventResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        evidence_id=row.evidence_id,
        event_type=row.event_type,
        from_state=row.from_state,
        to_state=row.to_state,
        actor_id=row.actor_id,
        actor_type=row.actor_type,
        reason=row.reason,
        event_metadata=meta,
        transaction_id=row.transaction_id,
        created_at=row.created_at,
    )


class EvidenceAuthorityEngine:
    """Single write authority for FrostGate evidence.

    All callers interact with evidence exclusively through this engine.
    No direct ORM access permitted outside this class.
    """

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id
        self._repo = EvidenceRepository(db, tenant_id)

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def create_evidence(
        self,
        req: CreateEvidenceRequest,
        actor_id: str,
        actor_type: str = ActorType.HUMAN.value,
    ) -> EvidenceResponse:
        evidence_id = _new_id()
        now = _now()
        evidence_ref = _slugify_ref(req.title, evidence_id)

        integrity_hash = _compute_integrity_hash(
            evidence_id=evidence_id,
            tenant_id=self._tenant_id,
            title=req.title,
            source_type=req.source_type.value,
            collection_method=req.collection_method.value,
            collected_at=req.collected_at,
            creator_id=actor_id,
        )

        labels_json = json.dumps(req.classification_labels)

        row = FaEvidence(
            id=evidence_id,
            tenant_id=self._tenant_id,
            evidence_ref=evidence_ref,
            lifecycle_state=EvidenceLifecycleState.COLLECTED.value,
            classification=req.classification.value,
            classification_labels=labels_json,
            source_type=req.source_type.value,
            source_system=req.source_system,
            source_ref=req.source_ref,
            collection_method=req.collection_method.value,
            title=req.title,
            description=req.description,
            integrity_hash=integrity_hash,
            integrity_hash_algorithm="sha256",
            trust_state=EvidenceTrustState.UNVERIFIED.value,
            verification_count=0,
            creator_id=actor_id,
            creator_type=actor_type,
            engagement_id=req.engagement_id,
            collected_at=req.collected_at,
            expires_at=req.expires_at,
            evidence_version="1",
            schema_version=_SCHEMA_VERSION,
            created_at=now,
            updated_at=now,
        )
        self._repo.create_evidence(row)

        self._write_audit(
            evidence_id=evidence_id,
            event_type=EvidenceAuditEventType.EVIDENCE_CREATED.value,
            from_state=None,
            to_state=EvidenceLifecycleState.COLLECTED.value,
            actor_id=actor_id,
            actor_type=actor_type,
            reason="evidence created",
            metadata={
                "source_type": req.source_type.value,
                "classification": req.classification.value,
            },
        )

        self._emit_timeline_event(
            source_id=evidence_id,
            event_type="evidence_created",
            payload={
                "source_type": req.source_type.value,
                "classification": req.classification.value,
            },
        )

        self._persist_quality_scores(row)
        self._db.commit()
        return _to_response(row)

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_evidence(self, evidence_id: str) -> EvidenceResponse:
        row = self._repo.get_evidence(evidence_id)
        if not row:
            raise EvidenceNotFound(f"Evidence {evidence_id!r} not found")
        return _to_response(row)

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
    ) -> EvidenceListResponse:
        items, total = self._repo.list_evidence(
            lifecycle_state=lifecycle_state,
            trust_state=trust_state,
            classification=classification,
            source_type=source_type,
            engagement_id=engagement_id,
            offset=offset,
            limit=limit,
        )
        return EvidenceListResponse(
            items=[_to_response(r) for r in items],
            total=total,
            offset=offset,
            limit=limit,
        )

    # ------------------------------------------------------------------
    # Update metadata
    # ------------------------------------------------------------------

    def update_metadata(
        self,
        evidence_id: str,
        req: UpdateEvidenceMetadataRequest,
        actor_id: str,
        actor_type: str = ActorType.HUMAN.value,
    ) -> EvidenceResponse:
        row = self._repo.get_evidence(evidence_id)
        if not row:
            raise EvidenceNotFound(f"Evidence {evidence_id!r} not found")

        state = EvidenceLifecycleState(row.lifecycle_state)
        if state in IMMUTABLE_LIFECYCLE_STATES:
            raise EvidenceImmutableState(
                f"Evidence in state {state.value!r} is immutable — create a superseding record instead"
            )

        changed: dict = {}
        if req.title is not None and req.title != row.title:
            changed["title"] = req.title
            row.title = req.title
        if req.description is not None and req.description != row.description:
            changed["description"] = req.description
            row.description = req.description
        if req.source_system is not None and req.source_system != row.source_system:
            changed["source_system"] = req.source_system
            row.source_system = req.source_system
        if req.source_ref is not None and req.source_ref != row.source_ref:
            changed["source_ref"] = req.source_ref
            row.source_ref = req.source_ref
        if req.expires_at is not None and req.expires_at != row.expires_at:
            changed["expires_at"] = req.expires_at
            row.expires_at = req.expires_at

        _SCORE_INPUTS = {"description", "source_system", "source_ref", "expires_at"}
        if changed:
            row.updated_at = _now()
            self._repo.save_evidence(row)
            self._write_audit(
                evidence_id=evidence_id,
                event_type=EvidenceAuditEventType.METADATA_UPDATED.value,
                from_state=None,
                to_state=None,
                actor_id=actor_id,
                actor_type=actor_type,
                reason=None,
                metadata={"changed_fields": list(changed.keys())},
            )
            if changed.keys() & _SCORE_INPUTS:
                self._persist_quality_scores(row)
            self._db.commit()

        return _to_response(row)

    # ------------------------------------------------------------------
    # Lifecycle transition
    # ------------------------------------------------------------------

    def transition_lifecycle(
        self,
        evidence_id: str,
        req: TransitionLifecycleRequest,
        actor_id: str,
        actor_type: str = ActorType.HUMAN.value,
    ) -> EvidenceResponse:
        row = self._repo.get_evidence(evidence_id)
        if not row:
            raise EvidenceNotFound(f"Evidence {evidence_id!r} not found")

        from_state = EvidenceLifecycleState(row.lifecycle_state)
        to_state = req.to_state

        try:
            validate_lifecycle_transition(from_state, to_state)
        except ValueError as exc:
            raise EvidenceInvalidTransition(str(exc)) from exc

        now = _now()
        row.lifecycle_state = to_state.value
        row.updated_at = now

        # Apply temporal markers
        if to_state == EvidenceLifecycleState.SUBMITTED:
            row.submitted_at = now
        elif to_state == EvidenceLifecycleState.UNDER_REVIEW:
            row.reviewed_at = now
        elif to_state == EvidenceLifecycleState.VERIFIED:
            row.verified_at = now
        elif to_state == EvidenceLifecycleState.REVOKED:
            row.revoked_at = now
        elif to_state == EvidenceLifecycleState.ARCHIVED:
            row.archived_at = now
        elif to_state == EvidenceLifecycleState.EXPIRED:
            pass  # expires_at was already set at creation

        self._repo.save_evidence(row)

        audit_type = EvidenceAuditEventType.LIFECYCLE_TRANSITIONED.value
        if to_state == EvidenceLifecycleState.REVOKED:
            audit_type = EvidenceAuditEventType.EVIDENCE_REVOKED.value
        elif to_state == EvidenceLifecycleState.ARCHIVED:
            audit_type = EvidenceAuditEventType.EVIDENCE_ARCHIVED.value
        elif to_state == EvidenceLifecycleState.EXPIRED:
            audit_type = EvidenceAuditEventType.EVIDENCE_EXPIRED.value
        elif to_state == EvidenceLifecycleState.SUPERSEDED:
            audit_type = EvidenceAuditEventType.EVIDENCE_SUPERSEDED.value

        self._write_audit(
            evidence_id=evidence_id,
            event_type=audit_type,
            from_state=from_state.value,
            to_state=to_state.value,
            actor_id=actor_id,
            actor_type=actor_type,
            reason=req.reason,
            metadata={},
        )

        self._emit_timeline_event(
            source_id=evidence_id,
            event_type=f"evidence_{to_state.value.lower()}",
            payload={
                "from_state": from_state.value,
                "to_state": to_state.value,
                "reason": req.reason,
            },
        )

        self._emit_status_changed_event(
            evidence_id=evidence_id,
            change_type="lifecycle",
            from_state=from_state.value,
            to_state=to_state.value,
            actor_id=actor_id,
            actor_type=actor_type,
            reason=req.reason,
        )

        self._persist_quality_scores(row)
        self._db.commit()
        return _to_response(row)

    # ------------------------------------------------------------------
    # Ownership
    # ------------------------------------------------------------------

    def assign_ownership(
        self,
        evidence_id: str,
        req: AssignOwnershipRequest,
        actor_id: str,
        actor_type: str = ActorType.HUMAN.value,
    ) -> EvidenceOwnershipResponse:
        row = self._repo.get_evidence(evidence_id)
        if not row:
            raise EvidenceNotFound(f"Evidence {evidence_id!r} not found")

        now = _now()
        ownership_id = _new_id()

        own = FaEvidenceOwnership(
            id=ownership_id,
            tenant_id=self._tenant_id,
            evidence_id=evidence_id,
            role=req.role.value,
            actor_id=req.actor_id,
            actor_type=req.actor_type.value,
            assigned_at=now,
            assigned_by=actor_id,
            assigned_by_type=actor_type,
            is_active=1,
            schema_version=_SCHEMA_VERSION,
            created_at=now,
        )
        self._repo.create_ownership(own)

        # Update primary owner if role=OWNER; owner_id affects completeness_score
        owner_changed = req.role == EvidenceOwnershipRole.OWNER
        if owner_changed:
            row.owner_id = req.actor_id
            row.owner_type = req.actor_type.value
            row.updated_at = now
            self._repo.save_evidence(row)

        self._write_audit(
            evidence_id=evidence_id,
            event_type=EvidenceAuditEventType.OWNERSHIP_ASSIGNED.value,
            from_state=None,
            to_state=None,
            actor_id=actor_id,
            actor_type=actor_type,
            reason=None,
            metadata={
                "role": req.role.value,
                "assigned_to": req.actor_id,
                "assigned_to_type": req.actor_type.value,
            },
        )

        if owner_changed:
            self._persist_quality_scores(row)
        self._db.commit()
        return _to_ownership_response(own)

    def revoke_ownership(
        self,
        evidence_id: str,
        req: RevokeOwnershipRequest,
        actor_id: str,
        actor_type: str = ActorType.HUMAN.value,
    ) -> EvidenceOwnershipResponse:
        own = self._repo.get_ownership(req.ownership_id)
        if not own or own.evidence_id != evidence_id:
            raise EvidenceOwnershipNotFound(
                f"Ownership {req.ownership_id!r} not found for evidence {evidence_id!r}"
            )

        now = _now()
        own.revoked_at = now
        own.revoked_by = actor_id
        own.is_active = 0
        self._repo.save_ownership(own)

        # If revoking an OWNER, update fa_evidence.owner_id to next active OWNER or None
        owner_changed = False
        if own.role == EvidenceOwnershipRole.OWNER.value:
            ev = self._repo.get_evidence(evidence_id)
            if ev is not None and ev.owner_id == own.actor_id:
                active_owners = [
                    o
                    for o in self._repo.list_ownership(evidence_id, active_only=True)
                    if o.role == EvidenceOwnershipRole.OWNER.value
                ]
                if active_owners:
                    next_owner = active_owners[0]
                    ev.owner_id = next_owner.actor_id
                    ev.owner_type = next_owner.actor_type
                else:
                    ev.owner_id = None
                    ev.owner_type = None
                ev.updated_at = now
                self._repo.save_evidence(ev)
                owner_changed = True

        self._write_audit(
            evidence_id=evidence_id,
            event_type=EvidenceAuditEventType.OWNERSHIP_REVOKED.value,
            from_state=None,
            to_state=None,
            actor_id=actor_id,
            actor_type=actor_type,
            reason=req.reason,
            metadata={"ownership_id": req.ownership_id, "role": own.role},
        )

        if owner_changed:
            self._persist_quality_scores(ev)
        self._db.commit()
        return _to_ownership_response(own)

    def list_ownership(
        self,
        evidence_id: str,
        *,
        active_only: bool = False,
    ) -> EvidenceOwnershipListResponse:
        row = self._repo.get_evidence(evidence_id)
        if not row:
            raise EvidenceNotFound(f"Evidence {evidence_id!r} not found")
        items = self._repo.list_ownership(evidence_id, active_only=active_only)
        return EvidenceOwnershipListResponse(
            items=[_to_ownership_response(r) for r in items],
            total=len(items),
        )

    # ------------------------------------------------------------------
    # Verify Evidence (trust state transition)
    # ------------------------------------------------------------------

    def verify_evidence(
        self,
        evidence_id: str,
        req: VerifyEvidenceRequest,
        actor_id: str,
        actor_type: str = ActorType.HUMAN.value,
    ) -> EvidenceTrustHistoryResponse:
        row = self._repo.lock_evidence_for_update(evidence_id)
        if not row:
            raise EvidenceNotFound(f"Evidence {evidence_id!r} not found")

        from_state = EvidenceTrustState(row.trust_state)
        to_state = req.to_trust_state

        try:
            validate_trust_transition(from_state, to_state)
        except ValueError as exc:
            raise EvidenceInvalidTrustTransition(str(exc)) from exc

        now = _now()
        event_id = _new_id()

        latest_event = self._repo.get_latest_trust_event(evidence_id)
        prev_hash = latest_event.event_hash if latest_event else None

        event_hash = self._repo.compute_trust_event_hash(
            event_id=event_id,
            evidence_id=evidence_id,
            from_state=from_state.value,
            to_state=to_state.value,
            verifier_id=actor_id,
            created_at=now,
            prev_event_hash=prev_hash,
        )

        trust_event = FaEvidenceTrustEvent(
            id=event_id,
            tenant_id=self._tenant_id,
            evidence_id=evidence_id,
            from_trust_state=from_state.value,
            to_trust_state=to_state.value,
            verification_source=req.verification_source.value,
            verifier_id=actor_id,
            verifier_type=actor_type,
            verification_method=req.verification_method,
            confidence_score=req.confidence_score,
            notes=req.notes,
            event_hash=event_hash,
            prev_event_hash=prev_hash,
            schema_version=_SCHEMA_VERSION,
            created_at=now,
        )
        self._repo.create_trust_event(trust_event)

        # Update evidence trust state and counters
        row.trust_state = to_state.value
        row.verification_count = (row.verification_count or 0) + 1
        row.last_verification_source = req.verification_source.value
        row.last_verifier_id = actor_id

        # Update trust_score: take the better of current score or the state floor
        state_floor = TRUST_STATE_SCORE_FLOOR[to_state]
        if req.confidence_score is not None:
            row.trust_score = max(state_floor, req.confidence_score)
        else:
            current_score = row.trust_score or 0
            row.trust_score = max(state_floor, current_score)

        # If achieving VERIFIED trust while lifecycle allows, ensure verified_at is set
        if to_state in (
            EvidenceTrustState.VERIFIED,
            EvidenceTrustState.HIGH_CONFIDENCE,
        ):
            if not row.verified_at:
                row.verified_at = now

        row.updated_at = now
        self._repo.save_evidence(row)

        self._write_audit(
            evidence_id=evidence_id,
            event_type=EvidenceAuditEventType.TRUST_STATE_CHANGED.value,
            from_state=from_state.value,
            to_state=to_state.value,
            actor_id=actor_id,
            actor_type=actor_type,
            reason=req.notes,
            metadata={
                "verification_source": req.verification_source.value,
                "confidence_score": req.confidence_score,
                "trust_score": row.trust_score,
            },
        )

        self._emit_timeline_event(
            source_id=evidence_id,
            event_type="evidence_trust_changed",
            payload={
                "from_trust_state": from_state.value,
                "to_trust_state": to_state.value,
                "verification_source": req.verification_source.value,
                "trust_score": row.trust_score,
            },
        )

        self._emit_status_changed_event(
            evidence_id=evidence_id,
            change_type="trust",
            from_state=from_state.value,
            to_state=to_state.value,
            actor_id=actor_id,
            actor_type=actor_type,
            reason=req.notes,
        )

        self._persist_quality_scores(row)
        self._db.commit()
        return self.query_trust_history(evidence_id)

    def query_trust_history(self, evidence_id: str) -> EvidenceTrustHistoryResponse:
        row = self._repo.get_evidence(evidence_id)
        if not row:
            raise EvidenceNotFound(f"Evidence {evidence_id!r} not found")
        events = self._repo.list_trust_events(evidence_id)
        return EvidenceTrustHistoryResponse(
            evidence_id=evidence_id,
            current_trust_state=row.trust_state,
            trust_score=row.trust_score,
            verification_count=row.verification_count,
            events=[_to_trust_event_response(e) for e in events],
        )

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------

    def link_relationship(
        self,
        evidence_id: str,
        req: LinkRelationshipRequest,
        actor_id: str,
        actor_type: str = ActorType.HUMAN.value,
    ) -> EvidenceRelationshipResponse:
        row = self._repo.get_evidence(evidence_id)
        if not row:
            raise EvidenceNotFound(f"Evidence {evidence_id!r} not found")

        existing = self._repo.get_relationship(
            evidence_id=evidence_id,
            related_entity_type=req.related_entity_type.value,
            related_entity_id=req.related_entity_id,
            relationship_type=req.relationship_type.value,
        )
        if existing:
            raise EvidenceRelationshipConflict(
                f"Relationship already exists: {evidence_id!r} → "
                f"{req.related_entity_type.value}:{req.related_entity_id!r} "
                f"({req.relationship_type.value})"
            )

        now = _now()
        rel_id = _new_id()

        rel = FaEvidenceRelationship(
            id=rel_id,
            tenant_id=self._tenant_id,
            evidence_id=evidence_id,
            related_entity_type=req.related_entity_type.value,
            related_entity_id=req.related_entity_id,
            relationship_type=req.relationship_type.value,
            link_metadata=json.dumps(req.link_metadata),
            linked_at=now,
            linked_by=actor_id,
            linked_by_type=actor_type,
            schema_version=_SCHEMA_VERSION,
            created_at=now,
        )
        self._repo.create_relationship(rel)

        self._write_audit(
            evidence_id=evidence_id,
            event_type=EvidenceAuditEventType.RELATIONSHIP_LINKED.value,
            from_state=None,
            to_state=None,
            actor_id=actor_id,
            actor_type=actor_type,
            reason=None,
            metadata={
                "related_entity_type": req.related_entity_type.value,
                "related_entity_id": req.related_entity_id,
                "relationship_type": req.relationship_type.value,
            },
        )

        self._emit_timeline_event(
            source_id=evidence_id,
            event_type="evidence_relationship_linked",
            payload={
                "related_entity_type": req.related_entity_type.value,
                "related_entity_id": req.related_entity_id,
                "relationship_type": req.relationship_type.value,
            },
        )

        self._db.commit()
        return _to_relationship_response(rel)

    def list_relationships(
        self,
        evidence_id: str,
        *,
        related_entity_type: Optional[str] = None,
    ) -> EvidenceRelationshipListResponse:
        row = self._repo.get_evidence(evidence_id)
        if not row:
            raise EvidenceNotFound(f"Evidence {evidence_id!r} not found")
        items = self._repo.list_relationships(
            evidence_id, related_entity_type=related_entity_type
        )
        return EvidenceRelationshipListResponse(
            items=[_to_relationship_response(r) for r in items],
            total=len(items),
        )

    def list_evidence_for_entity(
        self,
        related_entity_type: str,
        related_entity_id: str,
    ) -> EvidenceRelationshipListResponse:
        items = self._repo.list_evidence_for_entity(
            related_entity_type=related_entity_type,
            related_entity_id=related_entity_id,
        )
        return EvidenceRelationshipListResponse(
            items=[_to_relationship_response(r) for r in items],
            total=len(items),
        )

    # ------------------------------------------------------------------
    # Audit trail
    # ------------------------------------------------------------------

    def list_audit_events(
        self,
        evidence_id: str,
        *,
        event_type: Optional[str] = None,
        offset: int = 0,
        limit: int = 100,
    ) -> EvidenceAuditListResponse:
        row = self._repo.get_evidence(evidence_id)
        if not row:
            raise EvidenceNotFound(f"Evidence {evidence_id!r} not found")
        items, total = self._repo.list_audit_events(
            evidence_id, event_type=event_type, offset=offset, limit=limit
        )
        return EvidenceAuditListResponse(
            items=[_to_audit_event_response(r) for r in items],
            total=total,
        )

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    def dashboard(self) -> EvidenceDashboardResponse:
        by_lifecycle = self._repo.count_by_lifecycle_state()
        by_trust = self._repo.count_by_trust_state()
        by_class = self._repo.count_by_classification()
        by_source = self._repo.count_by_source_type()

        total = sum(by_lifecycle.values())
        verified = by_lifecycle.get(EvidenceLifecycleState.VERIFIED.value, 0)
        unverified = by_trust.get(EvidenceTrustState.UNVERIFIED.value, 0)
        expired = by_lifecycle.get(EvidenceLifecycleState.EXPIRED.value, 0)
        revoked = by_lifecycle.get(EvidenceLifecycleState.REVOKED.value, 0)
        high_conf = by_trust.get(EvidenceTrustState.HIGH_CONFIDENCE.value, 0)
        disputed = by_trust.get(EvidenceTrustState.DISPUTED.value, 0)

        return EvidenceDashboardResponse(
            tenant_id=self._tenant_id,
            total_evidence=total,
            by_lifecycle_state=by_lifecycle,
            by_trust_state=by_trust,
            by_classification=by_class,
            by_source_type=by_source,
            verified_count=verified,
            unverified_count=unverified,
            expired_count=expired,
            revoked_count=revoked,
            high_confidence_count=high_conf,
            disputed_count=disputed,
            expiring_soon_count=self._repo.count_expiring_soon(days=30),
            without_owner_count=self._repo.count_without_owner(),
            without_relationships_count=self._repo.count_without_relationships(),
        )

    # ------------------------------------------------------------------
    # PR 14.6.5 — Quality scoring
    # ------------------------------------------------------------------

    def recompute_quality_scores(
        self,
        evidence_id: str,
        actor_id: str = "system",
        actor_type: str = "service",
    ) -> EvidenceQualityScoreResponse:
        """Explicitly (re)compute and persist quality scores for an evidence record.

        Called automatically on all mutating operations. Also available as an
        explicit HTTP trigger for bulk recomputes or on-demand freshness updates.
        """
        row = self._repo.get_evidence(evidence_id)
        if not row:
            raise EvidenceNotFound(f"Evidence {evidence_id!r} not found")

        self._persist_quality_scores(row)

        self._write_audit(
            evidence_id=evidence_id,
            event_type=EvidenceAuditEventType.QUALITY_SCORES_COMPUTED.value,
            from_state=None,
            to_state=None,
            actor_id=actor_id,
            actor_type=actor_type,
            reason=None,
            metadata={
                "freshness_score": row.freshness_score,
                "verification_score": row.verification_score,
                "completeness_score": row.completeness_score,
            },
        )
        self._db.commit()

        now = _now()
        return EvidenceQualityScoreResponse(
            evidence_id=evidence_id,
            freshness_score=row.freshness_score or 0,
            verification_score=row.verification_score or 0,
            completeness_score=row.completeness_score or 0,
            trust_score=row.trust_score,
            quality_last_computed_at=row.quality_last_computed_at or now,
        )

    # ------------------------------------------------------------------
    # PR 14.6.5 — Governance status report
    # ------------------------------------------------------------------

    def get_status_report(
        self,
        *,
        offset: int = 0,
        limit: int = 200,
    ) -> EvidenceStatusReportResponse:
        """Return governance-ready evidence status report for the tenant.

        All status information originates here. Governance consumers must not
        compute status from any other source.
        """
        items, total = self._repo.list_all_evidence_for_status_report(
            offset=offset, limit=limit
        )
        by_lifecycle = self._repo.count_by_lifecycle_state()
        by_trust = self._repo.count_by_trust_state()
        avg_scores = self._repo.avg_quality_scores()

        status_items = [
            EvidenceStatusItemResponse(
                id=row.id,
                evidence_ref=row.evidence_ref,
                title=row.title,
                lifecycle_state=row.lifecycle_state,
                trust_state=row.trust_state,
                freshness_score=getattr(row, "freshness_score", None),
                trust_score=row.trust_score,
                verification_score=getattr(row, "verification_score", None),
                completeness_score=getattr(row, "completeness_score", None),
                quality_last_computed_at=getattr(row, "quality_last_computed_at", None),
                owner_id=row.owner_id,
                expires_at=row.expires_at,
                verified_at=row.verified_at,
                collected_at=row.collected_at,
            )
            for row in items
        ]

        from services.evidence_authority.models import EvidenceTrustState

        return EvidenceStatusReportResponse(
            tenant_id=self._tenant_id,
            generated_at=_now(),
            total=total,
            items=status_items,
            by_lifecycle_state=by_lifecycle,
            by_trust_state=by_trust,
            avg_freshness_score=avg_scores["avg_freshness"],
            avg_verification_score=avg_scores["avg_verification"],
            avg_completeness_score=avg_scores["avg_completeness"],
            avg_trust_score=avg_scores["avg_trust"],
            without_owner_count=self._repo.count_without_owner(),
            expired_count=by_lifecycle.get(EvidenceLifecycleState.EXPIRED.value, 0),
            expiring_soon_count=self._repo.count_expiring_soon(days=30),
            disputed_count=by_trust.get(EvidenceTrustState.DISPUTED.value, 0),
            invalidated_count=by_trust.get(EvidenceTrustState.INVALIDATED.value, 0),
            attested_count=by_trust.get(EvidenceTrustState.ATTESTED.value, 0),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _write_audit(
        self,
        *,
        evidence_id: str,
        event_type: str,
        from_state: Optional[str],
        to_state: Optional[str],
        actor_id: str,
        actor_type: str,
        reason: Optional[str],
        metadata: dict,
        transaction_id: Optional[str] = None,
    ) -> None:
        event = FaEvidenceAuditEvent(
            id=_new_id(),
            tenant_id=self._tenant_id,
            evidence_id=evidence_id,
            event_type=event_type,
            from_state=from_state,
            to_state=to_state,
            actor_id=actor_id,
            actor_type=actor_type,
            reason=reason,
            event_metadata=json.dumps(metadata),
            transaction_id=transaction_id,
            schema_version=_SCHEMA_VERSION,
            created_at=_now(),
        )
        self._repo.create_audit_event(event)

    def _persist_quality_scores(self, row: "FaEvidence") -> None:
        """Compute and persist all quality scores for an evidence row in place.

        Mutates row directly so callers can read updated values without a
        second DB fetch. The caller is responsible for flushing/committing.
        """
        now = _now()
        scores = compute_quality_scores(
            lifecycle_state=row.lifecycle_state,
            trust_state=row.trust_state,
            collected_at=row.collected_at,
            expires_at=row.expires_at,
            description=row.description,
            owner_id=row.owner_id,
            source_system=row.source_system,
            source_ref=row.source_ref,
            engagement_id=row.engagement_id,
            verification_count=row.verification_count or 0,
            last_verification_source=row.last_verification_source,
            trust_score=row.trust_score,
        )
        row.freshness_score = scores.freshness_score
        row.verification_score = scores.verification_score
        row.completeness_score = scores.completeness_score
        row.quality_last_computed_at = now
        row.updated_at = now
        self._repo.save_evidence(row)

    def _emit_status_changed_event(
        self,
        *,
        evidence_id: str,
        change_type: str,
        from_state: str,
        to_state: str,
        actor_id: str,
        actor_type: str,
        reason: Optional[str],
    ) -> None:
        """Emit canonical EvidenceStatusChanged timeline event.

        Fired on every lifecycle AND trust state transition so governance
        consumers receive a single, consistent event type.
        """
        self._emit_timeline_event(
            source_id=evidence_id,
            event_type="evidence_status_changed",
            payload={
                "change_type": change_type,
                "from_state": from_state,
                "to_state": to_state,
                "actor_id": actor_id,
                "actor_type": actor_type,
                "reason": reason,
            },
        )

    def _emit_timeline_event(
        self,
        source_id: str,
        event_type: str,
        payload: dict,
    ) -> None:
        """Persist a governance timeline event for this evidence action.

        Uses SourceType.EVIDENCE (existing registry entry). Idempotent:
        duplicate event_id is a no-op via TimelineStore. Wrapped in
        try/except so timeline persistence never blocks core operations.
        """
        try:
            occurred_at = utc_iso8601_z_now()
            event_id = derive_event_id(
                tenant_id=self._tenant_id,
                source_type=TimelineSourceType.EVIDENCE.value,
                source_id=source_id,
                event_type=event_type,
                occurred_at=occurred_at,
            )
            event = TimelineEvent(
                event_id=event_id,
                tenant_id=self._tenant_id,
                source_type=TimelineSourceType.EVIDENCE,
                source_id=source_id,
                event_type=event_type,
                occurred_at=occurred_at,
                recorded_at=utc_iso8601_z_now(),
                payload=payload,
                classification="internal",
                replay_eligible=False,
                schema_version=_SCHEMA_VERSION,
                event_version="1.0",
            )
            _timeline_store.record(self._db, event)
        except Exception:
            pass  # timeline persistence must never block evidence operations

    # -----------------------------------------------------------------------
    # PR 14.6.5A — Verifications
    # -----------------------------------------------------------------------

    def create_verification(
        self,
        evidence_id: str,
        req: "CreateVerificationRequest",
        actor_id: str,
        actor_type: str = "human",
    ) -> "VerificationResponse":
        row = self._repo.get_evidence(evidence_id)
        if not row:
            raise EvidenceNotFound(f"Evidence {evidence_id!r} not found")
        now = _now()
        ver_id = _new_id()
        ver = FaVerification(
            id=ver_id,
            tenant_id=self._tenant_id,
            evidence_id=evidence_id,
            verification_type=req.verification_type.value,
            verification_method=req.verification_method,
            verification_result=req.verification_result.value,
            verification_confidence=req.verification_confidence,
            verification_notes=req.verification_notes,
            verified_by=req.verified_by,
            verified_actor_type=req.verified_actor_type.value,
            verified_at=req.verified_at,
            schema_version=_SCHEMA_VERSION,
            created_at=now,
        )
        self._repo.create_verification(ver)
        self._write_audit(
            evidence_id=evidence_id,
            event_type=EvidenceAuditEventType.VERIFICATION_CREATED.value,
            from_state=None,
            to_state=req.verification_result.value,
            actor_id=actor_id,
            actor_type=actor_type,
            reason=req.verification_notes,
            metadata={
                "verification_type": req.verification_type.value,
                "verification_result": req.verification_result.value,
            },
        )
        self._emit_timeline_event(
            source_id=evidence_id,
            event_type="verification_created",
            payload={
                "verification_type": req.verification_type.value,
                "verification_result": req.verification_result.value,
                "verified_by": req.verified_by,
                "verified_actor_type": req.verified_actor_type.value,
            },
        )
        if req.verification_result == VerificationResult.FAIL:
            self._emit_timeline_event(
                source_id=evidence_id,
                event_type="verification_failed",
                payload={
                    "verification_type": req.verification_type.value,
                    "verified_by": req.verified_by,
                },
            )
        self._db.commit()
        return _to_verification_response(ver)

    def list_verifications(self, evidence_id: str) -> "VerificationListResponse":
        row = self._repo.get_evidence(evidence_id)
        if not row:
            raise EvidenceNotFound(f"Evidence {evidence_id!r} not found")
        items = self._repo.list_verifications(evidence_id)
        return VerificationListResponse(
            items=[_to_verification_response(v) for v in items],
            total=len(items),
        )

    def get_verification_summary(
        self, evidence_id: str
    ) -> "VerificationSummaryResponse":
        row = self._repo.get_evidence(evidence_id)
        if not row:
            raise EvidenceNotFound(f"Evidence {evidence_id!r} not found")
        items = self._repo.list_verifications(evidence_id)
        total = len(items)
        passed = sum(1 for v in items if v.verification_result == "PASS")
        failed = sum(1 for v in items if v.verification_result == "FAIL")
        inconclusive = sum(1 for v in items if v.verification_result == "INCONCLUSIVE")
        latest = items[0] if items else None
        success_rate = round(passed / total, 4) if total > 0 else None
        age_days = None
        if latest:
            try:
                latest_dt = datetime.fromisoformat(
                    latest.verified_at.replace("Z", "+00:00")
                )
                now_dt = datetime.now(tz=timezone.utc)
                age_days = max(0, (now_dt - latest_dt).days)
            except Exception:
                pass
        return VerificationSummaryResponse(
            evidence_id=evidence_id,
            verification_count=total,
            passed_count=passed,
            failed_count=failed,
            inconclusive_count=inconclusive,
            verification_success_rate=success_rate,
            verification_age_days=age_days,
            latest_verification_at=latest.verified_at if latest else None,
            latest_verification_result=latest.verification_result if latest else None,
            latest_verification_type=latest.verification_type if latest else None,
        )

    # -----------------------------------------------------------------------
    # PR 14.6.5A — SLA Deadlines
    # -----------------------------------------------------------------------

    def set_sla_deadlines(
        self,
        evidence_id: str,
        req: "SetSlaDeadlinesRequest",
        actor_id: str,
        actor_type: str = "human",
    ) -> "SlaStatusResponse":
        row = self._repo.get_evidence(evidence_id)
        if not row:
            raise EvidenceNotFound(f"Evidence {evidence_id!r} not found")
        now = _now()
        if req.review_due_at is not None:
            row.review_due_at = req.review_due_at
        if req.verification_due_at is not None:
            row.verification_due_at = req.verification_due_at
        if req.freshness_due_at is not None:
            row.freshness_due_at = req.freshness_due_at
        row.updated_at = now
        self._repo.save_evidence(row)
        self._write_audit(
            evidence_id=evidence_id,
            event_type=EvidenceAuditEventType.SLA_DEADLINES_SET.value,
            from_state=None,
            to_state=None,
            actor_id=actor_id,
            actor_type=actor_type,
            reason=None,
            metadata={
                "review_due_at": req.review_due_at,
                "verification_due_at": req.verification_due_at,
                "freshness_due_at": req.freshness_due_at,
            },
        )
        self._db.commit()
        return self._compute_sla_status(row)

    def get_sla_status(self, evidence_id: str) -> "SlaStatusResponse":
        row = self._repo.get_evidence(evidence_id)
        if not row:
            raise EvidenceNotFound(f"Evidence {evidence_id!r} not found")
        return self._compute_sla_status(row)

    def _compute_sla_status(self, row: "FaEvidence") -> "SlaStatusResponse":
        now_dt = datetime.now(tz=timezone.utc)

        def _sla_status(due_at: "str | None") -> "str | None":
            if not due_at:
                return None
            try:
                due_dt = datetime.fromisoformat(due_at.replace("Z", "+00:00"))
                delta = (due_dt - now_dt).total_seconds()
                if delta < 0:
                    return VerificationSlaStatus.OVERDUE.value
                elif delta < 7 * 86400:
                    return VerificationSlaStatus.DUE_SOON.value
                return VerificationSlaStatus.ON_TRACK.value
            except Exception:
                return None

        return SlaStatusResponse(
            evidence_id=row.id,
            review_due_at=getattr(row, "review_due_at", None),
            verification_due_at=getattr(row, "verification_due_at", None),
            freshness_due_at=getattr(row, "freshness_due_at", None),
            review_sla_status=_sla_status(getattr(row, "review_due_at", None)),
            verification_sla_status=_sla_status(
                getattr(row, "verification_due_at", None)
            ),
            freshness_sla_status=_sla_status(getattr(row, "freshness_due_at", None)),
            computed_at=_now(),
        )

    # -----------------------------------------------------------------------
    # PR 14.6.5A — Control Links
    # -----------------------------------------------------------------------

    def link_to_control(
        self,
        evidence_id: str,
        req: "LinkControlRequest",
        actor_id: str,
        actor_type: str = "human",
    ) -> "ControlLinkResponse":
        row = self._repo.get_evidence(evidence_id)
        if not row:
            raise EvidenceNotFound(f"Evidence {evidence_id!r} not found")
        existing = self._repo.get_control_link(evidence_id, req.control_id)
        if existing:
            raise ControlLinkConflict(
                f"Evidence {evidence_id!r} already linked to control {req.control_id!r}"
            )
        now = _now()
        link = FaEvidenceControlLink(
            id=_new_id(),
            tenant_id=self._tenant_id,
            evidence_id=evidence_id,
            control_id=req.control_id,
            linked_by=actor_id,
            linked_at=now,
            schema_version=_SCHEMA_VERSION,
            created_at=now,
        )
        self._repo.create_control_link(link)
        self._write_audit(
            evidence_id=evidence_id,
            event_type=EvidenceAuditEventType.CONTROL_LINKED.value,
            from_state=None,
            to_state=None,
            actor_id=actor_id,
            actor_type=actor_type,
            reason=None,
            metadata={"control_id": req.control_id},
        )
        self._emit_timeline_event(
            source_id=evidence_id,
            event_type="evidence_linked_to_control",
            payload={"control_id": req.control_id},
        )
        self._db.commit()
        return _to_control_link_response(link)

    def list_control_links(self, evidence_id: str) -> "ControlLinkListResponse":
        row = self._repo.get_evidence(evidence_id)
        if not row:
            raise EvidenceNotFound(f"Evidence {evidence_id!r} not found")
        items = self._repo.list_control_links(evidence_id)
        return ControlLinkListResponse(
            items=[_to_control_link_response(lnk) for lnk in items],
            total=len(items),
        )

    # -----------------------------------------------------------------------
    # PR 14.6.5A — Risk/Finding/Exception Links
    # -----------------------------------------------------------------------

    def link_to_risk(
        self,
        evidence_id: str,
        req: "LinkRiskRequest",
        actor_id: str,
        actor_type: str = "human",
    ) -> "RiskLinkResponse":
        row = self._repo.get_evidence(evidence_id)
        if not row:
            raise EvidenceNotFound(f"Evidence {evidence_id!r} not found")
        existing = self._repo.get_risk_link(
            evidence_id, req.linked_resource_id, req.link_type.value
        )
        if existing:
            raise RiskLinkConflict(
                f"Evidence {evidence_id!r} already linked to "
                f"{req.link_type.value} {req.linked_resource_id!r}"
            )
        now = _now()
        link = FaEvidenceRiskLink(
            id=_new_id(),
            tenant_id=self._tenant_id,
            evidence_id=evidence_id,
            linked_resource_id=req.linked_resource_id,
            link_type=req.link_type.value,
            linked_by=actor_id,
            linked_at=now,
            schema_version=_SCHEMA_VERSION,
            created_at=now,
        )
        self._repo.create_risk_link(link)
        self._write_audit(
            evidence_id=evidence_id,
            event_type=EvidenceAuditEventType.RISK_LINKED.value,
            from_state=None,
            to_state=None,
            actor_id=actor_id,
            actor_type=actor_type,
            reason=None,
            metadata={
                "linked_resource_id": req.linked_resource_id,
                "link_type": req.link_type.value,
            },
        )
        tl_event = f"evidence_linked_to_{req.link_type.value.lower()}"
        self._emit_timeline_event(
            source_id=evidence_id,
            event_type=tl_event,
            payload={
                "linked_resource_id": req.linked_resource_id,
                "link_type": req.link_type.value,
            },
        )
        self._db.commit()
        return _to_risk_link_response(link)

    def list_risk_links(
        self,
        evidence_id: str,
        *,
        link_type: "str | None" = None,
    ) -> "RiskLinkListResponse":
        row = self._repo.get_evidence(evidence_id)
        if not row:
            raise EvidenceNotFound(f"Evidence {evidence_id!r} not found")
        items = self._repo.list_risk_links(evidence_id, link_type=link_type)
        return RiskLinkListResponse(
            items=[_to_risk_link_response(lnk) for lnk in items],
            total=len(items),
        )

    # -----------------------------------------------------------------------
    # PR 14.6.5A — Coverage Analytics
    # -----------------------------------------------------------------------

    def get_coverage_analytics(self) -> "CoverageAnalyticsResponse":
        controls_with = self._repo.count_distinct_controls_with_evidence()
        total_known_controls = self._repo.count_total_known_controls()
        controls_without = max(0, total_known_controls - controls_with)
        risks_with = self._repo.count_distinct_risks_with_evidence("RISK")
        total_known_risks = self._repo.count_total_known_risks()
        risks_without = max(0, total_known_risks - risks_with)
        findings_with = self._repo.count_distinct_risks_with_evidence("FINDING")
        exceptions_with = self._repo.count_distinct_risks_with_evidence("EXCEPTION")
        verified_controls = self._repo.count_verified_controls()
        unverified_controls = max(0, controls_with - verified_controls)
        total_control_links = self._repo.count_total_control_links()
        total_risk_links = self._repo.count_total_risk_links()
        evidence_density = round(total_control_links / max(1, controls_with), 4)
        coverage_pct = round((controls_with / max(1, total_known_controls)) * 100, 2)
        return CoverageAnalyticsResponse(
            tenant_id=self._tenant_id,
            generated_at=_now(),
            controls_with_evidence=controls_with,
            controls_without_evidence=controls_without,
            risks_with_evidence=risks_with,
            risks_without_evidence=risks_without,
            findings_with_evidence=findings_with,
            exceptions_with_evidence=exceptions_with,
            verified_controls=verified_controls,
            unverified_controls=unverified_controls,
            total_control_links=total_control_links,
            total_risk_links=total_risk_links,
            evidence_density=evidence_density,
            coverage_percentage=coverage_pct,
            total_known_controls=total_known_controls,
        )

    # -----------------------------------------------------------------------
    # PR 14.6.5A — Health Signals
    # -----------------------------------------------------------------------

    def get_health_signals(self) -> "HealthSignalsResponse":
        by_trust = self._repo.count_by_trust_state()
        return HealthSignalsResponse(
            tenant_id=self._tenant_id,
            generated_at=_now(),
            verification_overdue_count=self._repo.count_overdue_by_sla_field(
                "verification_due_at"
            ),
            review_overdue_count=self._repo.count_overdue_by_sla_field("review_due_at"),
            freshness_overdue_count=self._repo.count_overdue_by_sla_field(
                "freshness_due_at"
            ),
            orphaned_evidence_count=self._repo.count_orphaned_evidence(),
            unlinked_evidence_count=self._repo.count_unlinked_evidence(),
            disputed_evidence_count=by_trust.get("DISPUTED", 0),
            invalidated_evidence_count=by_trust.get("INVALIDATED", 0),
            attested_evidence_count=by_trust.get("ATTESTED", 0),
            verified_evidence_count=by_trust.get("VERIFIED", 0)
            + by_trust.get("HIGH_CONFIDENCE", 0),
        )

    # -----------------------------------------------------------------------
    # PR 14.6.5A — CGIN Snapshot Bundle
    # -----------------------------------------------------------------------

    def get_cgin_snapshot(self) -> "CGINSnapshotBundle":
        bundle_id = _new_id()
        generated_at = _now()
        items, _ = self._repo.list_all_evidence_for_status_report(offset=0, limit=500)
        ev_snapshots = []
        ver_snapshots = []
        for ev in items:
            sla = self._compute_sla_status(ev)
            ev_snapshots.append(
                EvidenceStatusSnapshot(
                    snapshot_id=_new_id(),
                    snapshot_version="1.0",
                    tenant_id=self._tenant_id,
                    generated_at=generated_at,
                    evidence_id=ev.id,
                    lifecycle_state=ev.lifecycle_state,
                    trust_state=ev.trust_state,
                    freshness_score=getattr(ev, "freshness_score", None),
                    verification_score=getattr(ev, "verification_score", None),
                    completeness_score=getattr(ev, "completeness_score", None),
                    trust_score=ev.trust_score,
                    sla_review_status=sla.review_sla_status,
                    sla_verification_status=sla.verification_sla_status,
                    benchmark_freshness_percentile=getattr(
                        ev, "benchmark_freshness_percentile", None
                    ),
                    benchmark_verification_percentile=getattr(
                        ev, "benchmark_verification_percentile", None
                    ),
                )
            )
            summary = self.get_verification_summary(ev.id)
            ver_snapshots.append(
                VerificationSnapshot(
                    snapshot_id=_new_id(),
                    snapshot_version="1.0",
                    tenant_id=self._tenant_id,
                    evidence_id=ev.id,
                    generated_at=generated_at,
                    verification_count=summary.verification_count,
                    passed_count=summary.passed_count,
                    verification_success_rate=summary.verification_success_rate,
                    latest_verification_at=summary.latest_verification_at,
                    latest_verification_type=summary.latest_verification_type,
                    verification_age_days=summary.verification_age_days,
                )
            )
        cov = self.get_coverage_analytics()
        health = self.get_health_signals()
        return CGINSnapshotBundle(
            bundle_id=bundle_id,
            bundle_version="1.0",
            tenant_id=self._tenant_id,
            generated_at=generated_at,
            evidence_snapshots=ev_snapshots,
            verification_snapshots=ver_snapshots,
            coverage=CoverageSnapshot(
                snapshot_id=_new_id(),
                snapshot_version="1.0",
                tenant_id=self._tenant_id,
                generated_at=generated_at,
                controls_with_evidence=cov.controls_with_evidence,
                controls_without_evidence=cov.controls_without_evidence,
                risks_with_evidence=cov.risks_with_evidence,
                verified_controls=cov.verified_controls,
                evidence_density=cov.evidence_density,
                coverage_percentage=cov.coverage_percentage,
            ),
            health=HealthSnapshot(
                snapshot_id=_new_id(),
                snapshot_version="1.0",
                tenant_id=self._tenant_id,
                generated_at=generated_at,
                **health.model_dump(exclude={"tenant_id", "generated_at"}),
            ),
        )


# ---------------------------------------------------------------------------
# PR 14.6.5A — private row-to-response converters (module-level)
# ---------------------------------------------------------------------------


def _to_verification_response(row: "FaVerification") -> VerificationResponse:
    return VerificationResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        evidence_id=row.evidence_id,
        verification_type=row.verification_type,
        verification_method=row.verification_method,
        verification_result=row.verification_result,
        verification_confidence=row.verification_confidence,
        verification_notes=row.verification_notes,
        verified_by=row.verified_by,
        verified_actor_type=row.verified_actor_type,
        verified_at=row.verified_at,
        schema_version=row.schema_version,
        created_at=row.created_at,
    )


def _to_control_link_response(row: "FaEvidenceControlLink") -> ControlLinkResponse:
    return ControlLinkResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        evidence_id=row.evidence_id,
        control_id=row.control_id,
        linked_by=row.linked_by,
        linked_at=row.linked_at,
        created_at=row.created_at,
    )


def _to_risk_link_response(row: "FaEvidenceRiskLink") -> RiskLinkResponse:
    return RiskLinkResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        evidence_id=row.evidence_id,
        linked_resource_id=row.linked_resource_id,
        link_type=row.link_type,
        linked_by=row.linked_by,
        linked_at=row.linked_at,
        created_at=row.created_at,
    )
