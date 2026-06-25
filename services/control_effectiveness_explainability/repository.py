"""services/control_effectiveness_explainability/repository.py

Tenant-scoped data access for fa_control_ranking.
All queries are tenant-scoped. No query path bypasses tenant_id.

PR 16.5.1 — Control Effectiveness Explainability & Governance Action Engine
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from api.db_models_control_effectiveness_explainability import FaControlRanking


class ExplainabilityRepository:
    """Tenant-scoped data access for ranking storage."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    # ------------------------------------------------------------------
    # Rankings
    # ------------------------------------------------------------------

    def replace_rankings(self, rank_type: str, rows: list[FaControlRanking]) -> None:
        """Delete existing rankings for this rank_type, then insert new ones."""
        self._db.query(FaControlRanking).filter(
            FaControlRanking.tenant_id == self._tenant_id,
            FaControlRanking.rank_type == rank_type,
        ).delete(synchronize_session=False)
        for row in rows:
            self._db.add(row)
        self._db.flush()

    def get_rankings(self, rank_type: str) -> list[FaControlRanking]:
        return (
            self._db.query(FaControlRanking)
            .filter(
                FaControlRanking.tenant_id == self._tenant_id,
                FaControlRanking.rank_type == rank_type,
            )
            .order_by(FaControlRanking.rank_position.asc())
            .all()
        )

    def get_all_rankings(self) -> list[FaControlRanking]:
        return (
            self._db.query(FaControlRanking)
            .filter(FaControlRanking.tenant_id == self._tenant_id)
            .order_by(
                FaControlRanking.rank_type.asc(),
                FaControlRanking.rank_position.asc(),
            )
            .all()
        )
