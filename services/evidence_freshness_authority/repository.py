"""services/evidence_freshness_authority/repository.py — Data access layer for Evidence Freshness Authority.

All queries are tenant-scoped. No query path bypasses tenant_id.
This layer is the only code that touches fa_freshness_* tables directly.

PR 14.6.7 — Evidence Freshness Authority
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from api.db_models_evidence_freshness_authority import (
    FaEvidenceFreshnessRecord,
    FaFreshnessException,
    FaFreshnessPolicy,
)


class EvidenceFreshnessRepository:
    """Tenant-scoped data access for fa_freshness_* tables."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    # ------------------------------------------------------------------
    # FaFreshnessPolicy
    # ------------------------------------------------------------------

    def create_policy(self, row: FaFreshnessPolicy) -> None:
        self._db.add(row)
        self._db.flush()

    def get_policy(self, policy_id: str) -> Optional[FaFreshnessPolicy]:
        return (
            self._db.query(FaFreshnessPolicy)
            .filter(
                FaFreshnessPolicy.id == policy_id,
                FaFreshnessPolicy.tenant_id == self._tenant_id,
            )
            .first()
        )

    def save_policy(self, row: FaFreshnessPolicy) -> None:
        self._db.merge(row)

    def list_policies(
        self,
        evidence_type: Optional[str] = None,
        enabled_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[FaFreshnessPolicy], int]:
        q = self._db.query(FaFreshnessPolicy).filter(
            FaFreshnessPolicy.tenant_id == self._tenant_id
        )
        if evidence_type is not None:
            q = q.filter(FaFreshnessPolicy.evidence_type == evidence_type)
        if enabled_only:
            q = q.filter(FaFreshnessPolicy.enabled == 1)
        total = q.count()
        items = (
            q.order_by(FaFreshnessPolicy.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total

    # ------------------------------------------------------------------
    # FaEvidenceFreshnessRecord
    # ------------------------------------------------------------------

    def create_record(self, row: FaEvidenceFreshnessRecord) -> None:
        self._db.add(row)
        self._db.flush()

    def get_record_by_evidence(
        self, evidence_id: str
    ) -> Optional[FaEvidenceFreshnessRecord]:
        return (
            self._db.query(FaEvidenceFreshnessRecord)
            .filter(
                FaEvidenceFreshnessRecord.tenant_id == self._tenant_id,
                FaEvidenceFreshnessRecord.evidence_id == evidence_id,
            )
            .first()
        )

    def get_record(self, record_id: str) -> Optional[FaEvidenceFreshnessRecord]:
        return (
            self._db.query(FaEvidenceFreshnessRecord)
            .filter(
                FaEvidenceFreshnessRecord.id == record_id,
                FaEvidenceFreshnessRecord.tenant_id == self._tenant_id,
            )
            .first()
        )

    def save_record(self, row: FaEvidenceFreshnessRecord) -> None:
        self._db.merge(row)

    def list_records(
        self,
        freshness_state: Optional[str] = None,
        policy_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[FaEvidenceFreshnessRecord], int]:
        q = self._db.query(FaEvidenceFreshnessRecord).filter(
            FaEvidenceFreshnessRecord.tenant_id == self._tenant_id
        )
        if freshness_state is not None:
            q = q.filter(FaEvidenceFreshnessRecord.freshness_state == freshness_state)
        if policy_id is not None:
            q = q.filter(FaEvidenceFreshnessRecord.policy_id == policy_id)
        total = q.count()
        items = (
            q.order_by(FaEvidenceFreshnessRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total

    def list_all_records(self) -> list[FaEvidenceFreshnessRecord]:
        return (
            self._db.query(FaEvidenceFreshnessRecord)
            .filter(FaEvidenceFreshnessRecord.tenant_id == self._tenant_id)
            .all()
        )

    # ------------------------------------------------------------------
    # FaFreshnessException
    # ------------------------------------------------------------------

    def create_exception(self, row: FaFreshnessException) -> None:
        self._db.add(row)
        self._db.flush()

    def get_exception(self, exception_id: str) -> Optional[FaFreshnessException]:
        return (
            self._db.query(FaFreshnessException)
            .filter(
                FaFreshnessException.id == exception_id,
                FaFreshnessException.tenant_id == self._tenant_id,
            )
            .first()
        )

    def list_exceptions(
        self,
        evidence_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[FaFreshnessException], int]:
        q = self._db.query(FaFreshnessException).filter(
            FaFreshnessException.tenant_id == self._tenant_id
        )
        if evidence_id is not None:
            q = q.filter(FaFreshnessException.evidence_id == evidence_id)
        if status is not None:
            q = q.filter(FaFreshnessException.status == status)
        total = q.count()
        items = (
            q.order_by(FaFreshnessException.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total

    def count_active_exceptions_for_evidence(self, evidence_id: str) -> int:
        return (
            self._db.query(FaFreshnessException)
            .filter(
                FaFreshnessException.tenant_id == self._tenant_id,
                FaFreshnessException.evidence_id == evidence_id,
                FaFreshnessException.status == "ACTIVE",
            )
            .count()
        )

    # ------------------------------------------------------------------
    # Aggregations
    # ------------------------------------------------------------------

    def count_by_state(self) -> dict[str, int]:
        rows = (
            self._db.query(
                FaEvidenceFreshnessRecord.freshness_state,
                func.count(FaEvidenceFreshnessRecord.id),
            )
            .filter(FaEvidenceFreshnessRecord.tenant_id == self._tenant_id)
            .group_by(FaEvidenceFreshnessRecord.freshness_state)
            .all()
        )
        return {state: cnt for state, cnt in rows}

    def avg_freshness_score(self) -> float:
        result = (
            self._db.query(func.avg(FaEvidenceFreshnessRecord.freshness_score))
            .filter(FaEvidenceFreshnessRecord.tenant_id == self._tenant_id)
            .scalar()
        )
        return float(result) if result is not None else 0.0

    def count_active_exceptions(self) -> int:
        return (
            self._db.query(FaFreshnessException)
            .filter(
                FaFreshnessException.tenant_id == self._tenant_id,
                FaFreshnessException.status == "ACTIVE",
            )
            .count()
        )
