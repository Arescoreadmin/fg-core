"""services/governance_learning/repository.py

Tenant-scoped data access for governance learning tables.
All queries are tenant-scoped. No query path bypasses tenant_id.

PR 17.6B — Governance Learning Loop Authority
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from api.db_models_governance_learning import (
    FaGovernanceLearningAggregate,
    FaGovernanceLearningRecord,
)


class GovernanceLearningRepository:
    """Tenant-scoped data access for governance learning tables."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    # ------------------------------------------------------------------
    # Records (append-only)
    # ------------------------------------------------------------------

    def create_record(self, row: FaGovernanceLearningRecord) -> None:
        """Insert a new learning record."""
        self._db.add(row)
        self._db.flush()

    def get_record(self, record_id: str) -> Optional[FaGovernanceLearningRecord]:
        """Fetch a single learning record by ID, scoped to this tenant."""
        return (
            self._db.query(FaGovernanceLearningRecord)
            .filter(
                FaGovernanceLearningRecord.tenant_id == self._tenant_id,
                FaGovernanceLearningRecord.id == record_id,
            )
            .first()
        )

    def list_records(
        self,
        learning_category: Optional[str] = None,
        remediation_category: Optional[str] = None,
        control_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[FaGovernanceLearningRecord], int]:
        """List learning records with optional filters. Returns (rows, total_count)."""
        q = self._db.query(FaGovernanceLearningRecord).filter(
            FaGovernanceLearningRecord.tenant_id == self._tenant_id
        )
        if learning_category is not None:
            q = q.filter(
                FaGovernanceLearningRecord.learning_category == learning_category
            )
        if remediation_category is not None:
            q = q.filter(
                FaGovernanceLearningRecord.remediation_category == remediation_category
            )
        if control_id is not None:
            q = q.filter(FaGovernanceLearningRecord.control_id == control_id)

        total = q.count()
        rows = (
            q.order_by(FaGovernanceLearningRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return rows, total

    def get_record_by_outcome(
        self, source_outcome_id: str
    ) -> Optional[FaGovernanceLearningRecord]:
        """Look up an existing learning record by source_outcome_id (idempotency check)."""
        return (
            self._db.query(FaGovernanceLearningRecord)
            .filter(
                FaGovernanceLearningRecord.tenant_id == self._tenant_id,
                FaGovernanceLearningRecord.source_outcome_id == source_outcome_id,
            )
            .first()
        )

    def list_records_for_category(
        self, remediation_category: str
    ) -> list[FaGovernanceLearningRecord]:
        """Fetch all records for a given remediation_category (used for aggregate rebuild)."""
        return (
            self._db.query(FaGovernanceLearningRecord)
            .filter(
                FaGovernanceLearningRecord.tenant_id == self._tenant_id,
                FaGovernanceLearningRecord.remediation_category == remediation_category,
            )
            .order_by(FaGovernanceLearningRecord.created_at.asc())
            .all()
        )

    def list_all_records(self) -> list[FaGovernanceLearningRecord]:
        """Fetch all records for this tenant (used for full recalculate)."""
        return (
            self._db.query(FaGovernanceLearningRecord)
            .filter(FaGovernanceLearningRecord.tenant_id == self._tenant_id)
            .order_by(FaGovernanceLearningRecord.created_at.asc())
            .all()
        )

    def list_recent_health_deltas(self, n: int = 50) -> list[float]:
        """Return the last n health_delta values (non-null) ordered by created_at desc."""
        rows = (
            self._db.query(FaGovernanceLearningRecord)
            .filter(
                FaGovernanceLearningRecord.tenant_id == self._tenant_id,
                FaGovernanceLearningRecord.health_delta.isnot(None),
            )
            .order_by(FaGovernanceLearningRecord.created_at.desc())
            .limit(n)
            .all()
        )
        return [r.health_delta for r in rows if r.health_delta is not None]

    def count_records_by_outcome_type(self) -> dict[str, int]:
        """Count records per outcome_type for this tenant."""
        rows = (
            self._db.query(FaGovernanceLearningRecord)
            .filter(FaGovernanceLearningRecord.tenant_id == self._tenant_id)
            .all()
        )
        counts: dict[str, int] = {}
        for r in rows:
            counts[r.outcome_type] = counts.get(r.outcome_type, 0) + 1
        return counts

    # ------------------------------------------------------------------
    # Aggregates (mutable)
    # ------------------------------------------------------------------

    def upsert_aggregate(
        self,
        tenant_id: str,
        remediation_category: str,
        updates: dict,
    ) -> FaGovernanceLearningAggregate:
        """Get existing aggregate or create new one, then apply updates and flush."""
        import uuid
        from datetime import datetime, timezone

        existing = self.get_aggregate(remediation_category)
        if existing is None:
            row = FaGovernanceLearningAggregate(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                remediation_category=remediation_category,
                last_updated_at=datetime.now(tz=timezone.utc).isoformat(),
            )
            for k, v in updates.items():
                setattr(row, k, v)
            self._db.add(row)
        else:
            for k, v in updates.items():
                setattr(existing, k, v)
            row = existing
        self._db.flush()
        return row

    def get_aggregate(
        self, remediation_category: str
    ) -> Optional[FaGovernanceLearningAggregate]:
        """Fetch aggregate for this tenant + remediation_category."""
        return (
            self._db.query(FaGovernanceLearningAggregate)
            .filter(
                FaGovernanceLearningAggregate.tenant_id == self._tenant_id,
                FaGovernanceLearningAggregate.remediation_category
                == remediation_category,
            )
            .first()
        )

    def list_aggregates(
        self, limit: int = 50, offset: int = 0
    ) -> tuple[list[FaGovernanceLearningAggregate], int]:
        """List all aggregates for this tenant. Returns (rows, total_count)."""
        q = self._db.query(FaGovernanceLearningAggregate).filter(
            FaGovernanceLearningAggregate.tenant_id == self._tenant_id
        )
        total = q.count()
        rows = (
            q.order_by(FaGovernanceLearningAggregate.remediation_category.asc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return rows, total

    def get_all_aggregates(self) -> list[FaGovernanceLearningAggregate]:
        """Fetch all aggregates for this tenant (no pagination)."""
        return (
            self._db.query(FaGovernanceLearningAggregate)
            .filter(FaGovernanceLearningAggregate.tenant_id == self._tenant_id)
            .order_by(FaGovernanceLearningAggregate.remediation_category.asc())
            .all()
        )
