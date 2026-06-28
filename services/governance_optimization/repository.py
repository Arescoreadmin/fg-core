"""services/governance_optimization/repository.py

Tenant-scoped data access for governance optimization tables.
All queries are tenant-scoped. No query path bypasses tenant_id.

PR 17.6D — Governance Optimization Engine
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from api.db_models_governance_optimization import (
    FaGovernanceOptimizationAggregate,
    FaGovernanceOptimizationDecision,
    FaGovernanceOptimizationSnapshot,
)


def _new_id() -> str:
    return str(uuid.uuid4())


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


class GovernanceOptimizationRepository:
    """Tenant-scoped data access for governance optimization tables."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    # ------------------------------------------------------------------
    # Decisions (append-only)
    # ------------------------------------------------------------------

    def create_decision(self, row: FaGovernanceOptimizationDecision) -> None:
        """Insert a new optimization decision row."""
        self._db.add(row)
        self._db.flush()

    def list_decisions(
        self,
        optimization_type: Optional[str] = None,
        target_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[FaGovernanceOptimizationDecision], int]:
        """List decisions for this tenant with optional filters and pagination."""
        q = self._db.query(FaGovernanceOptimizationDecision).filter(
            FaGovernanceOptimizationDecision.tenant_id == self._tenant_id
        )
        if optimization_type is not None:
            q = q.filter(
                FaGovernanceOptimizationDecision.optimization_type == optimization_type
            )
        if target_type is not None:
            q = q.filter(
                FaGovernanceOptimizationDecision.target_type == target_type
            )
        total = q.count()
        rows = (
            q.order_by(FaGovernanceOptimizationDecision.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return rows, total

    def list_all_decisions(
        self, optimization_type: Optional[str] = None
    ) -> list[FaGovernanceOptimizationDecision]:
        """Fetch all decisions for this tenant (no pagination)."""
        q = self._db.query(FaGovernanceOptimizationDecision).filter(
            FaGovernanceOptimizationDecision.tenant_id == self._tenant_id
        )
        if optimization_type is not None:
            q = q.filter(
                FaGovernanceOptimizationDecision.optimization_type == optimization_type
            )
        return q.order_by(FaGovernanceOptimizationDecision.created_at.desc()).all()

    # ------------------------------------------------------------------
    # Aggregates (mutable)
    # ------------------------------------------------------------------

    def get_aggregate(
        self, target_type: str, target_id: str, optimization_type: str
    ) -> Optional[FaGovernanceOptimizationAggregate]:
        """Fetch aggregate for this tenant + (target_type, target_id, optimization_type)."""
        return (
            self._db.query(FaGovernanceOptimizationAggregate)
            .filter(
                FaGovernanceOptimizationAggregate.tenant_id == self._tenant_id,
                FaGovernanceOptimizationAggregate.target_type == target_type,
                FaGovernanceOptimizationAggregate.target_id == target_id,
                FaGovernanceOptimizationAggregate.optimization_type == optimization_type,
            )
            .first()
        )

    def upsert_aggregate(
        self,
        target_type: str,
        target_id: str,
        optimization_type: str,
        updates: dict,
    ) -> FaGovernanceOptimizationAggregate:
        """Get or create aggregate, then apply updates and flush."""
        existing = self.get_aggregate(target_type, target_id, optimization_type)
        if existing is None:
            row = FaGovernanceOptimizationAggregate(
                id=_new_id(),
                tenant_id=self._tenant_id,
                target_type=target_type,
                target_id=target_id,
                optimization_type=optimization_type,
                last_ranked_at=_now_iso(),
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

    def list_aggregates(
        self,
        target_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[FaGovernanceOptimizationAggregate], int]:
        """List aggregates for this tenant with optional filter and pagination."""
        q = self._db.query(FaGovernanceOptimizationAggregate).filter(
            FaGovernanceOptimizationAggregate.tenant_id == self._tenant_id
        )
        if target_type is not None:
            q = q.filter(
                FaGovernanceOptimizationAggregate.target_type == target_type
            )
        total = q.count()
        rows = (
            q.order_by(FaGovernanceOptimizationAggregate.last_ranked_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return rows, total

    def list_all_aggregates(
        self, target_type: Optional[str] = None
    ) -> list[FaGovernanceOptimizationAggregate]:
        """Fetch all aggregates for this tenant (no pagination)."""
        q = self._db.query(FaGovernanceOptimizationAggregate).filter(
            FaGovernanceOptimizationAggregate.tenant_id == self._tenant_id
        )
        if target_type is not None:
            q = q.filter(
                FaGovernanceOptimizationAggregate.target_type == target_type
            )
        return q.order_by(FaGovernanceOptimizationAggregate.last_ranked_at.desc()).all()

    # ------------------------------------------------------------------
    # Snapshots (append-only)
    # ------------------------------------------------------------------

    def create_snapshot(self, row: FaGovernanceOptimizationSnapshot) -> None:
        """Insert a new optimization snapshot row."""
        self._db.add(row)
        self._db.flush()

    def list_snapshots(
        self,
        snapshot_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[FaGovernanceOptimizationSnapshot], int]:
        """List snapshots for this tenant with optional filter and pagination."""
        q = self._db.query(FaGovernanceOptimizationSnapshot).filter(
            FaGovernanceOptimizationSnapshot.tenant_id == self._tenant_id
        )
        if snapshot_type is not None:
            q = q.filter(
                FaGovernanceOptimizationSnapshot.snapshot_type == snapshot_type
            )
        total = q.count()
        rows = (
            q.order_by(FaGovernanceOptimizationSnapshot.generated_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return rows, total

    def list_all_snapshots(
        self, snapshot_type: Optional[str] = None
    ) -> list[FaGovernanceOptimizationSnapshot]:
        """Fetch all snapshots for this tenant (no pagination)."""
        q = self._db.query(FaGovernanceOptimizationSnapshot).filter(
            FaGovernanceOptimizationSnapshot.tenant_id == self._tenant_id
        )
        if snapshot_type is not None:
            q = q.filter(
                FaGovernanceOptimizationSnapshot.snapshot_type == snapshot_type
            )
        return q.order_by(FaGovernanceOptimizationSnapshot.generated_at.desc()).all()
