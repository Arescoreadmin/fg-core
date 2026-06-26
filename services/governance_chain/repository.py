"""services/governance_chain/repository.py — Data access for Governance Chain Authority.

All queries are tenant-scoped. No query path bypasses tenant_id.

PR 17.6 — Canonical Governance Chain Authority
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import func as sqlfunc
from sqlalchemy.orm import Session

from api.db_models_governance_chain import (
    FaGovernanceChainEvent,
    FaGovernanceChainExecution,
    FaGovernanceChainSnapshot,
    FaGovernanceHealthSnapshot,
)


class GovernanceChainRepository:
    """Tenant-scoped data access for governance chain tables."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    # ------------------------------------------------------------------
    # fa_governance_chain_events
    # ------------------------------------------------------------------

    def create_event(self, row: FaGovernanceChainEvent) -> None:
        self._db.add(row)
        self._db.flush()

    def get_event(self, event_id: str) -> Optional[FaGovernanceChainEvent]:
        return (
            self._db.query(FaGovernanceChainEvent)
            .filter(
                FaGovernanceChainEvent.id == event_id,
                FaGovernanceChainEvent.tenant_id == self._tenant_id,
            )
            .first()
        )

    def list_events_by_correlation(
        self, correlation_id: str
    ) -> list[FaGovernanceChainEvent]:
        return (
            self._db.query(FaGovernanceChainEvent)
            .filter(
                FaGovernanceChainEvent.tenant_id == self._tenant_id,
                FaGovernanceChainEvent.correlation_id == correlation_id,
            )
            .order_by(FaGovernanceChainEvent.created_at.asc())
            .all()
        )

    def list_events(
        self,
        event_type: Optional[str] = None,
        authority: Optional[str] = None,
        object_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[FaGovernanceChainEvent], int]:
        q = self._db.query(FaGovernanceChainEvent).filter(
            FaGovernanceChainEvent.tenant_id == self._tenant_id
        )
        if event_type:
            q = q.filter(FaGovernanceChainEvent.event_type == event_type)
        if authority:
            q = q.filter(FaGovernanceChainEvent.authority == authority)
        if object_type:
            q = q.filter(FaGovernanceChainEvent.object_type == object_type)
        total = q.count()
        rows = (
            q.order_by(FaGovernanceChainEvent.created_at.desc())
            .limit(limit)
            .offset(offset)
            .all()
        )
        return rows, total

    def count_events_by_type(self) -> dict[str, int]:
        rows = (
            self._db.query(
                FaGovernanceChainEvent.event_type,
                sqlfunc.count(FaGovernanceChainEvent.id),
            )
            .filter(FaGovernanceChainEvent.tenant_id == self._tenant_id)
            .group_by(FaGovernanceChainEvent.event_type)
            .all()
        )
        return {r[0]: r[1] for r in rows}

    # ------------------------------------------------------------------
    # fa_governance_chain_executions
    # ------------------------------------------------------------------

    def create_execution(self, row: FaGovernanceChainExecution) -> None:
        self._db.add(row)
        self._db.flush()

    def get_execution(self, execution_id: str) -> Optional[FaGovernanceChainExecution]:
        return (
            self._db.query(FaGovernanceChainExecution)
            .filter(
                FaGovernanceChainExecution.id == execution_id,
                FaGovernanceChainExecution.tenant_id == self._tenant_id,
            )
            .first()
        )

    def list_executions(
        self,
        bridge_type: Optional[str] = None,
        success: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[FaGovernanceChainExecution], int]:
        q = self._db.query(FaGovernanceChainExecution).filter(
            FaGovernanceChainExecution.tenant_id == self._tenant_id
        )
        if bridge_type:
            q = q.filter(FaGovernanceChainExecution.bridge_type == bridge_type)
        if success is not None:
            q = q.filter(FaGovernanceChainExecution.success == (1 if success else 0))
        total = q.count()
        rows = (
            q.order_by(FaGovernanceChainExecution.executed_at.desc())
            .limit(limit)
            .offset(offset)
            .all()
        )
        return rows, total

    def count_executions_by_bridge(self) -> dict[str, int]:
        rows = (
            self._db.query(
                FaGovernanceChainExecution.bridge_type,
                sqlfunc.count(FaGovernanceChainExecution.id),
            )
            .filter(FaGovernanceChainExecution.tenant_id == self._tenant_id)
            .group_by(FaGovernanceChainExecution.bridge_type)
            .all()
        )
        return {r[0]: r[1] for r in rows}

    def count_executions_success_failure(self) -> tuple[int, int, int]:
        """Returns (total, successful, failed)."""
        total = (
            self._db.query(FaGovernanceChainExecution)
            .filter(FaGovernanceChainExecution.tenant_id == self._tenant_id)
            .count()
        )
        success_count = (
            self._db.query(FaGovernanceChainExecution)
            .filter(
                FaGovernanceChainExecution.tenant_id == self._tenant_id,
                FaGovernanceChainExecution.success == 1,
            )
            .count()
        )
        failed_count = (
            self._db.query(FaGovernanceChainExecution)
            .filter(
                FaGovernanceChainExecution.tenant_id == self._tenant_id,
                FaGovernanceChainExecution.success == 0,
            )
            .count()
        )
        return total, success_count, failed_count

    def average_duration_by_bridge(self) -> dict[str, Optional[float]]:
        rows = (
            self._db.query(
                FaGovernanceChainExecution.bridge_type,
                sqlfunc.avg(FaGovernanceChainExecution.duration_ms),
            )
            .filter(FaGovernanceChainExecution.tenant_id == self._tenant_id)
            .group_by(FaGovernanceChainExecution.bridge_type)
            .all()
        )
        return {
            r[0]: (round(float(r[1]), 2) if r[1] is not None else None) for r in rows
        }

    # ------------------------------------------------------------------
    # fa_governance_health_snapshots
    # ------------------------------------------------------------------

    def create_health_snapshot(self, row: FaGovernanceHealthSnapshot) -> None:
        self._db.add(row)
        self._db.flush()

    def get_latest_health_snapshot(self) -> Optional[FaGovernanceHealthSnapshot]:
        return (
            self._db.query(FaGovernanceHealthSnapshot)
            .filter(FaGovernanceHealthSnapshot.tenant_id == self._tenant_id)
            .order_by(FaGovernanceHealthSnapshot.snapshot_at.desc())
            .first()
        )

    def list_health_snapshots(
        self, limit: int = 50, offset: int = 0
    ) -> tuple[list[FaGovernanceHealthSnapshot], int]:
        q = self._db.query(FaGovernanceHealthSnapshot).filter(
            FaGovernanceHealthSnapshot.tenant_id == self._tenant_id
        )
        total = q.count()
        rows = (
            q.order_by(FaGovernanceHealthSnapshot.snapshot_at.desc())
            .limit(limit)
            .offset(offset)
            .all()
        )
        return rows, total

    # ------------------------------------------------------------------
    # fa_governance_chain_snapshots (CGIN)
    # ------------------------------------------------------------------

    def create_chain_snapshot(self, row: FaGovernanceChainSnapshot) -> None:
        self._db.add(row)
        self._db.flush()

    def list_chain_snapshots(
        self, tenant_fingerprint: str
    ) -> list[FaGovernanceChainSnapshot]:
        return (
            self._db.query(FaGovernanceChainSnapshot)
            .filter(FaGovernanceChainSnapshot.tenant_fingerprint == tenant_fingerprint)
            .order_by(FaGovernanceChainSnapshot.generated_at.desc())
            .limit(50)
            .all()
        )
