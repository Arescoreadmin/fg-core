"""services/evidence_freshness_authority/engine.py — Business logic for Evidence Freshness Authority.

This engine is the single write authority for fa_freshness_* tables.
No other service writes to these tables directly.

All mutating operations:
  1. Validate inputs (fail-closed)
  2. Enforce tenant isolation
  3. Execute state/score computation
  4. Emit timeline event (wrapped in try/except — never blocks)
  5. Commit

The engine never exposes raw ORM rows — it always returns schema objects.

PR 14.6.7 — Evidence Freshness Authority
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from api.db_models_evidence_freshness_authority import (
    FaEvidenceFreshnessRecord,
    FaFreshnessException,
    FaFreshnessPolicy,
)
from services.evidence_freshness_authority.models import (
    FreshnessCriticality,
    FreshnessExceptionStatus,
    FreshnessState,
    compute_freshness_score,
    compute_freshness_state,
)
from services.evidence_freshness_authority.repository import EvidenceFreshnessRepository
from services.evidence_freshness_authority.schemas import (
    CreateFreshnessExceptionRequest,
    CreateFreshnessPolicyRequest,
    CreateFreshnessRecordRequest,
    FreshnessCGINSnapshot,
    FreshnessDashboardResponse,
    FreshnessExceptionListResponse,
    FreshnessExceptionNotFound,
    FreshnessExceptionResponse,
    FreshnessPolicyListResponse,
    FreshnessPolicyNotFound,
    FreshnessPolicyResponse,
    FreshnessRecordConflict,
    FreshnessRecordListResponse,
    FreshnessRecordNotFound,
    FreshnessRecordResponse,
    RevokeFreshnessExceptionRequest,
    UpdateFreshnessPolicyRequest,
    UpdateFreshnessRecordRequest,
)


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


def _days_since(ts: Optional[str], now_iso: str) -> Optional[float]:
    """Compute days since a timestamp. Returns None if ts is None."""
    if ts is None:
        return None
    try:
        t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        now = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        delta = now - t
        return max(0.0, delta.total_seconds() / 86400.0)
    except Exception:
        return None


class EvidenceFreshnessEngine:
    """Business logic engine for Evidence Freshness Authority."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id
        self._repo = EvidenceFreshnessRepository(db, tenant_id)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _now(self) -> str:
        return _now()

    def _new_id(self) -> str:
        return _new_id()

    def _emit_timeline_event(
        self, source_id: str, event_type: str, payload: dict
    ) -> None:
        """Emit a timeline event. Wrapped in try/except — never blocks core operations."""
        try:
            from services.governance.timeline.adapters import (
                evidence_freshness_to_timeline_event,
            )
            from services.governance.timeline.store import TimelineStore

            event = evidence_freshness_to_timeline_event(
                tenant_id=self._tenant_id,
                source_id=source_id,
                event_type=event_type,
                occurred_at=self._now(),
                payload=payload,
                replay_eligible=False,
            )
            store = TimelineStore()
            store.record(self._db, event)
        except Exception:
            pass

    def _recompute_record(self, row: FaEvidenceFreshnessRecord) -> None:
        """Recompute freshness_state + freshness_score in-place on the ORM row."""
        now_iso = self._now()

        # Determine state
        new_state = compute_freshness_state(
            review_due_at=row.review_due_at,
            verification_due_at=row.verification_due_at,
            expiration_due_at=row.expiration_due_at,
            now_iso=now_iso,
        )

        # Determine criticality from policy if linked
        criticality = FreshnessCriticality.MEDIUM.value
        if row.policy_id is not None:
            policy = self._repo.get_policy(row.policy_id)
            if policy is not None:
                criticality = policy.criticality

        # Count active exceptions
        has_active_exception = (
            self._repo.count_active_exceptions_for_evidence(row.evidence_id) > 0
        )

        # Age penalties
        days_since_verified = _days_since(row.last_verified_at, now_iso)
        days_since_reviewed = _days_since(row.last_reviewed_at, now_iso)

        new_score = compute_freshness_score(
            freshness_state=new_state,
            criticality=criticality,
            days_since_last_verified=days_since_verified,
            days_since_last_reviewed=days_since_reviewed,
            has_active_exception=has_active_exception,
        )

        row.freshness_state = new_state.value
        row.freshness_score = new_score
        row.updated_at = now_iso

    def _to_policy_response(self, row: FaFreshnessPolicy) -> FreshnessPolicyResponse:
        return FreshnessPolicyResponse(
            id=row.id,
            tenant_id=row.tenant_id,
            name=row.name,
            description=row.description,
            evidence_type=row.evidence_type,
            review_interval_days=row.review_interval_days,
            verification_interval_days=row.verification_interval_days,
            expiration_interval_days=row.expiration_interval_days,
            criticality=row.criticality,
            enabled=bool(row.enabled),
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    def _to_record_response(
        self, row: FaEvidenceFreshnessRecord
    ) -> FreshnessRecordResponse:
        return FreshnessRecordResponse(
            id=row.id,
            tenant_id=row.tenant_id,
            evidence_id=row.evidence_id,
            policy_id=row.policy_id,
            review_due_at=row.review_due_at,
            verification_due_at=row.verification_due_at,
            expiration_due_at=row.expiration_due_at,
            last_reviewed_at=row.last_reviewed_at,
            last_verified_at=row.last_verified_at,
            freshness_score=row.freshness_score,
            freshness_state=FreshnessState(row.freshness_state),
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    def _to_exception_response(
        self, row: FaFreshnessException
    ) -> FreshnessExceptionResponse:
        return FreshnessExceptionResponse(
            id=row.id,
            tenant_id=row.tenant_id,
            evidence_id=row.evidence_id,
            reason=row.reason,
            approved_by=row.approved_by,
            expires_at=row.expires_at,
            status=row.status,
            created_at=row.created_at,
        )

    # ------------------------------------------------------------------
    # Policy Management
    # ------------------------------------------------------------------

    def create_policy(
        self,
        req: CreateFreshnessPolicyRequest,
        actor_id: str,
        actor_type: str,
    ) -> FreshnessPolicyResponse:
        now = self._now()
        row = FaFreshnessPolicy(
            id=self._new_id(),
            tenant_id=self._tenant_id,
            name=req.name,
            description=req.description,
            evidence_type=req.evidence_type,
            review_interval_days=req.review_interval_days,
            verification_interval_days=req.verification_interval_days,
            expiration_interval_days=req.expiration_interval_days,
            criticality=req.criticality.value,
            enabled=1 if req.enabled else 0,
            created_at=now,
            updated_at=now,
        )
        self._repo.create_policy(row)
        self._db.commit()
        self._db.refresh(row)

        self._emit_timeline_event(
            row.id,
            "freshness.policy.created",
            {
                "policy_id": row.id,
                "name": row.name,
                "actor_id": actor_id,
                "actor_type": actor_type,
            },
        )

        try:
            from api.observability.metrics import FRESHNESS_POLICIES_CREATED_TOTAL

            FRESHNESS_POLICIES_CREATED_TOTAL.inc()
        except Exception:
            pass

        return self._to_policy_response(row)

    def get_policy(self, policy_id: str) -> FreshnessPolicyResponse:
        row = self._repo.get_policy(policy_id)
        if row is None:
            raise FreshnessPolicyNotFound(policy_id)
        return self._to_policy_response(row)

    def list_policies(
        self,
        evidence_type: Optional[str] = None,
        enabled_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> FreshnessPolicyListResponse:
        items, total = self._repo.list_policies(
            evidence_type=evidence_type,
            enabled_only=enabled_only,
            limit=limit,
            offset=offset,
        )
        return FreshnessPolicyListResponse(
            items=[self._to_policy_response(r) for r in items],
            total=total,
        )

    def update_policy(
        self,
        policy_id: str,
        req: UpdateFreshnessPolicyRequest,
        actor_id: str,
        actor_type: str,
    ) -> FreshnessPolicyResponse:
        row = self._repo.get_policy(policy_id)
        if row is None:
            raise FreshnessPolicyNotFound(policy_id)

        if req.name is not None:
            row.name = req.name
        if req.description is not None:
            row.description = req.description
        if req.evidence_type is not None:
            row.evidence_type = req.evidence_type
        if req.review_interval_days is not None:
            row.review_interval_days = req.review_interval_days
        if req.verification_interval_days is not None:
            row.verification_interval_days = req.verification_interval_days
        if req.expiration_interval_days is not None:
            row.expiration_interval_days = req.expiration_interval_days
        if req.criticality is not None:
            row.criticality = req.criticality.value
        if req.enabled is not None:
            row.enabled = 1 if req.enabled else 0

        row.updated_at = self._now()
        self._repo.save_policy(row)
        self._db.commit()
        self._db.refresh(row)

        self._emit_timeline_event(
            row.id,
            "freshness.policy.updated",
            {
                "policy_id": row.id,
                "actor_id": actor_id,
                "actor_type": actor_type,
            },
        )

        try:
            from api.observability.metrics import FRESHNESS_POLICIES_UPDATED_TOTAL

            FRESHNESS_POLICIES_UPDATED_TOTAL.inc()
        except Exception:
            pass

        return self._to_policy_response(row)

    # ------------------------------------------------------------------
    # Freshness Record Management
    # ------------------------------------------------------------------

    def create_freshness_record(
        self,
        req: CreateFreshnessRecordRequest,
        actor_id: str,
        actor_type: str,
    ) -> FreshnessRecordResponse:
        # Conflict check: one record per evidence per tenant
        existing = self._repo.get_record_by_evidence(req.evidence_id)
        if existing is not None:
            raise FreshnessRecordConflict(
                f"Freshness record already exists for evidence_id={req.evidence_id!r}"
            )

        now = self._now()
        row = FaEvidenceFreshnessRecord(
            id=self._new_id(),
            tenant_id=self._tenant_id,
            evidence_id=req.evidence_id,
            policy_id=req.policy_id,
            review_due_at=req.review_due_at,
            verification_due_at=req.verification_due_at,
            expiration_due_at=req.expiration_due_at,
            last_reviewed_at=req.last_reviewed_at,
            last_verified_at=req.last_verified_at,
            freshness_score=100,
            freshness_state=FreshnessState.CURRENT.value,
            created_at=now,
            updated_at=now,
        )
        # Compute initial state & score
        self._recompute_record(row)
        self._repo.create_record(row)
        self._db.commit()
        self._db.refresh(row)

        self._emit_timeline_event(
            row.id,
            "freshness.record.created",
            {
                "record_id": row.id,
                "evidence_id": row.evidence_id,
                "freshness_state": row.freshness_state,
                "freshness_score": row.freshness_score,
                "actor_id": actor_id,
                "actor_type": actor_type,
            },
        )

        try:
            from api.observability.metrics import FRESHNESS_RECORDS_CREATED_TOTAL

            FRESHNESS_RECORDS_CREATED_TOTAL.inc()
        except Exception:
            pass

        return self._to_record_response(row)

    def get_freshness_record(self, evidence_id: str) -> FreshnessRecordResponse:
        row = self._repo.get_record_by_evidence(evidence_id)
        if row is None:
            raise FreshnessRecordNotFound(evidence_id)
        return self._to_record_response(row)

    def list_freshness_records(
        self,
        freshness_state: Optional[str] = None,
        policy_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> FreshnessRecordListResponse:
        items, total = self._repo.list_records(
            freshness_state=freshness_state,
            policy_id=policy_id,
            limit=limit,
            offset=offset,
        )
        return FreshnessRecordListResponse(
            items=[self._to_record_response(r) for r in items],
            total=total,
        )

    def update_freshness_record(
        self,
        evidence_id: str,
        req: UpdateFreshnessRecordRequest,
        actor_id: str,
        actor_type: str,
    ) -> FreshnessRecordResponse:
        row = self._repo.get_record_by_evidence(evidence_id)
        if row is None:
            raise FreshnessRecordNotFound(evidence_id)

        old_state = row.freshness_state

        if req.policy_id is not None:
            row.policy_id = req.policy_id
        if req.review_due_at is not None:
            row.review_due_at = req.review_due_at
        if req.verification_due_at is not None:
            row.verification_due_at = req.verification_due_at
        if req.expiration_due_at is not None:
            row.expiration_due_at = req.expiration_due_at
        if req.last_reviewed_at is not None:
            row.last_reviewed_at = req.last_reviewed_at
        if req.last_verified_at is not None:
            row.last_verified_at = req.last_verified_at

        self._recompute_record(row)
        new_state = row.freshness_state

        self._repo.save_record(row)
        self._db.commit()
        self._db.refresh(row)

        # Emit state change event if state changed
        if old_state != new_state:
            self._emit_timeline_event(
                row.id,
                "freshness.state.changed",
                {
                    "record_id": row.id,
                    "evidence_id": row.evidence_id,
                    "from_state": old_state,
                    "to_state": new_state,
                    "actor_id": actor_id,
                    "actor_type": actor_type,
                },
            )
            try:
                from api.observability.metrics import FRESHNESS_STATE_TRANSITIONS_TOTAL

                FRESHNESS_STATE_TRANSITIONS_TOTAL.labels(to_state=new_state).inc()
            except Exception:
                pass

        self._emit_timeline_event(
            row.id,
            "freshness.record.updated",
            {
                "record_id": row.id,
                "evidence_id": row.evidence_id,
                "freshness_state": new_state,
                "freshness_score": row.freshness_score,
                "actor_id": actor_id,
                "actor_type": actor_type,
            },
        )

        try:
            from api.observability.metrics import FRESHNESS_RECORDS_UPDATED_TOTAL

            FRESHNESS_RECORDS_UPDATED_TOTAL.inc()
        except Exception:
            pass

        return self._to_record_response(row)

    def recompute_freshness(
        self,
        evidence_id: str,
        actor_id: str,
        actor_type: str,
    ) -> FreshnessRecordResponse:
        row = self._repo.get_record_by_evidence(evidence_id)
        if row is None:
            raise FreshnessRecordNotFound(evidence_id)

        self._recompute_record(row)
        self._repo.save_record(row)
        self._db.commit()
        self._db.refresh(row)

        self._emit_timeline_event(
            row.id,
            "freshness.score.recomputed",
            {
                "record_id": row.id,
                "evidence_id": row.evidence_id,
                "freshness_state": row.freshness_state,
                "freshness_score": row.freshness_score,
                "actor_id": actor_id,
                "actor_type": actor_type,
            },
        )

        try:
            from api.observability.metrics import FRESHNESS_SCORE_RECOMPUTATIONS_TOTAL

            FRESHNESS_SCORE_RECOMPUTATIONS_TOTAL.inc()
        except Exception:
            pass

        return self._to_record_response(row)

    # ------------------------------------------------------------------
    # Exception Management
    # ------------------------------------------------------------------

    def create_exception(
        self,
        req: CreateFreshnessExceptionRequest,
        actor_id: str,
        actor_type: str,
    ) -> FreshnessExceptionResponse:
        now = self._now()
        row = FaFreshnessException(
            id=self._new_id(),
            tenant_id=self._tenant_id,
            evidence_id=req.evidence_id,
            reason=req.reason,
            approved_by=req.approved_by,
            expires_at=req.expires_at,
            status=FreshnessExceptionStatus.ACTIVE.value,
            created_at=now,
        )
        self._repo.create_exception(row)
        self._db.commit()
        self._db.refresh(row)

        self._emit_timeline_event(
            row.id,
            "freshness.exception.created",
            {
                "exception_id": row.id,
                "evidence_id": row.evidence_id,
                "approved_by": row.approved_by,
                "expires_at": row.expires_at,
                "actor_id": actor_id,
                "actor_type": actor_type,
            },
        )

        try:
            from api.observability.metrics import FRESHNESS_EXCEPTIONS_CREATED_TOTAL

            FRESHNESS_EXCEPTIONS_CREATED_TOTAL.inc()
        except Exception:
            pass

        # Recompute freshness for this evidence (exception gives +5 bonus)
        try:
            evidence_row = self._repo.get_record_by_evidence(req.evidence_id)
            if evidence_row is not None:
                self._recompute_record(evidence_row)
                self._repo.save_record(evidence_row)
                self._db.commit()
        except Exception:
            pass

        return self._to_exception_response(row)

    def revoke_exception(
        self,
        exception_id: str,
        req: RevokeFreshnessExceptionRequest,
        actor_id: str,
        actor_type: str,
    ) -> FreshnessExceptionResponse:
        row = self._repo.get_exception(exception_id)
        if row is None:
            raise FreshnessExceptionNotFound(exception_id)

        if row.status != FreshnessExceptionStatus.ACTIVE.value:
            raise FreshnessExceptionNotFound(
                f"Exception {exception_id!r} is not active (status={row.status!r})"
            )

        # Update status to REVOKED (ORM allows updates; only DELETE is blocked)
        row.status = FreshnessExceptionStatus.REVOKED.value
        self._db.merge(row)
        self._db.commit()
        self._db.refresh(row)

        self._emit_timeline_event(
            row.id,
            "freshness.exception.revoked",
            {
                "exception_id": row.id,
                "evidence_id": row.evidence_id,
                "reason": req.reason,
                "actor_id": actor_id,
                "actor_type": actor_type,
            },
        )

        try:
            from api.observability.metrics import FRESHNESS_EXCEPTIONS_REVOKED_TOTAL

            FRESHNESS_EXCEPTIONS_REVOKED_TOTAL.inc()
        except Exception:
            pass

        # Recompute freshness for this evidence (exception bonus may be removed)
        try:
            evidence_row = self._repo.get_record_by_evidence(row.evidence_id)
            if evidence_row is not None:
                self._recompute_record(evidence_row)
                self._repo.save_record(evidence_row)
                self._db.commit()
        except Exception:
            pass

        return self._to_exception_response(row)

    def list_exceptions(
        self,
        evidence_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> FreshnessExceptionListResponse:
        items, total = self._repo.list_exceptions(
            evidence_id=evidence_id,
            status=status,
            limit=limit,
            offset=offset,
        )
        return FreshnessExceptionListResponse(
            items=[self._to_exception_response(r) for r in items],
            total=total,
        )

    # ------------------------------------------------------------------
    # Dashboard & Analytics
    # ------------------------------------------------------------------

    def get_dashboard(self) -> FreshnessDashboardResponse:
        state_counts = self._repo.count_by_state()
        avg_score = self._repo.avg_freshness_score()
        exceptions_count = self._repo.count_active_exceptions()

        fresh_count = state_counts.get(FreshnessState.CURRENT.value, 0)
        due_soon_count = state_counts.get(FreshnessState.DUE_SOON.value, 0)
        review_required_count = state_counts.get(
            FreshnessState.REVIEW_REQUIRED.value, 0
        )
        verification_required_count = state_counts.get(
            FreshnessState.VERIFICATION_REQUIRED.value, 0
        )
        stale_count = state_counts.get(FreshnessState.STALE.value, 0)
        expired_count = state_counts.get(FreshnessState.EXPIRED.value, 0)

        total = sum(state_counts.values())
        coverage_at_risk = (
            review_required_count + verification_required_count + expired_count
        )

        return FreshnessDashboardResponse(
            fresh_count=fresh_count,
            due_soon_count=due_soon_count,
            review_required_count=review_required_count,
            verification_required_count=verification_required_count,
            stale_count=stale_count,
            expired_count=expired_count,
            total=total,
            avg_freshness_score=round(avg_score, 2),
            freshness_exceptions_count=exceptions_count,
            coverage_at_risk_count=coverage_at_risk,
        )

    def get_cgin_snapshot(self) -> FreshnessCGINSnapshot:
        state_counts = self._repo.count_by_state()
        avg_score = self._repo.avg_freshness_score()
        exceptions_count = self._repo.count_active_exceptions()

        fresh_evidence = state_counts.get(
            FreshnessState.CURRENT.value, 0
        ) + state_counts.get(FreshnessState.DUE_SOON.value, 0)
        stale_evidence = (
            state_counts.get(FreshnessState.REVIEW_REQUIRED.value, 0)
            + state_counts.get(FreshnessState.VERIFICATION_REQUIRED.value, 0)
            + state_counts.get(FreshnessState.STALE.value, 0)
        )
        expired_evidence = state_counts.get(FreshnessState.EXPIRED.value, 0)
        coverage_at_risk = (
            state_counts.get(FreshnessState.REVIEW_REQUIRED.value, 0)
            + state_counts.get(FreshnessState.VERIFICATION_REQUIRED.value, 0)
            + expired_evidence
        )

        return FreshnessCGINSnapshot(
            snapshot_at=self._now(),
            tenant_id=self._tenant_id,
            fresh_evidence=fresh_evidence,
            stale_evidence=stale_evidence,
            expired_evidence=expired_evidence,
            avg_freshness_score=round(avg_score, 2),
            coverage_at_risk=coverage_at_risk,
            freshness_exceptions_count=exceptions_count,
        )

    # ------------------------------------------------------------------
    # Verification Authority Integration
    # ------------------------------------------------------------------

    def on_verification_approved(
        self,
        evidence_id: str,
        verified_at: str,
        actor_id: str,
        actor_type: str,
    ) -> None:
        """Called when a verification is approved. Never raises."""
        try:
            row = self._repo.get_record_by_evidence(evidence_id)
            if row is None:
                # Create a minimal record for this evidence
                now = self._now()
                row = FaEvidenceFreshnessRecord(
                    id=self._new_id(),
                    tenant_id=self._tenant_id,
                    evidence_id=evidence_id,
                    policy_id=None,
                    review_due_at=None,
                    verification_due_at=None,
                    expiration_due_at=None,
                    last_reviewed_at=None,
                    last_verified_at=verified_at,
                    freshness_score=100,
                    freshness_state=FreshnessState.CURRENT.value,
                    created_at=now,
                    updated_at=now,
                )
                self._repo.create_record(row)
            else:
                row.last_verified_at = verified_at
                # Reset verification_due_at based on policy or default 180d
                interval_days = 180
                if row.policy_id is not None:
                    policy = self._repo.get_policy(row.policy_id)
                    if policy is not None:
                        interval_days = policy.verification_interval_days
                try:
                    vt = datetime.fromisoformat(verified_at.replace("Z", "+00:00"))
                    if vt.tzinfo is None:
                        vt = vt.replace(tzinfo=timezone.utc)
                    new_due = vt + timedelta(days=interval_days)
                    row.verification_due_at = new_due.isoformat()
                except Exception:
                    pass
                self._recompute_record(row)
                self._repo.save_record(row)

            self._db.commit()

            self._emit_timeline_event(
                row.id,
                "freshness.verification.acknowledged",
                {
                    "record_id": row.id,
                    "evidence_id": evidence_id,
                    "verified_at": verified_at,
                    "actor_id": actor_id,
                    "actor_type": actor_type,
                },
            )
        except Exception:
            pass

    def on_verification_rejected(
        self,
        evidence_id: str,
        actor_id: str,
        actor_type: str,
    ) -> None:
        """Called when a verification is rejected. Never raises."""
        try:
            row = self._repo.get_record_by_evidence(evidence_id)
            if row is None:
                return

            # Apply VERIFICATION_REQUIRED penalty even if not yet due
            current_score = row.freshness_score
            penalized_score = max(0, current_score - 20)
            row.freshness_score = penalized_score
            row.updated_at = self._now()
            self._repo.save_record(row)
            self._db.commit()

            self._emit_timeline_event(
                row.id,
                "freshness.verification.rejected",
                {
                    "record_id": row.id,
                    "evidence_id": evidence_id,
                    "score_before": current_score,
                    "score_after": penalized_score,
                    "actor_id": actor_id,
                    "actor_type": actor_type,
                },
            )
        except Exception:
            pass
