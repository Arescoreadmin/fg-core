"""services/control_effectiveness/repository.py — Data access for Control Effectiveness Engine.

All queries are tenant-scoped. No query path bypasses tenant_id.

PR 16.5 — Control Effectiveness Engine
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from api.db_models_control_effectiveness import (
    FaControlEffectiveness,
    FaControlEffectivenessHistory,
)
from api.db_models_evidence_authority import FaEvidenceControlLink


class ControlEffectivenessRepository:
    """Tenant-scoped data access for fa_control_effectiveness and history."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    # ------------------------------------------------------------------
    # FaControlEffectiveness — current state
    # ------------------------------------------------------------------

    def upsert_effectiveness(self, row: FaControlEffectiveness) -> None:
        existing = self.get_effectiveness(row.control_id)
        if existing is not None:
            existing.effectiveness_score = row.effectiveness_score
            existing.effectiveness_level = row.effectiveness_level
            existing.effectiveness_risk = row.effectiveness_risk
            existing.coverage_score = row.coverage_score
            existing.verification_score = row.verification_score
            existing.freshness_score = row.freshness_score
            existing.trend_score = row.trend_score
            existing.forecast_score = row.forecast_score
            existing.evidence_density_score = row.evidence_density_score
            existing.exception_score = row.exception_score
            existing.governance_health_score = row.governance_health_score
            existing.trend_direction = row.trend_direction
            existing.score_delta_7d = row.score_delta_7d
            existing.score_delta_30d = row.score_delta_30d
            existing.score_delta_90d = row.score_delta_90d
            existing.last_calculated_at = row.last_calculated_at
            existing.calculation_version = row.calculation_version
            self._db.flush()
        else:
            self._db.add(row)
            self._db.flush()

    def get_effectiveness(
        self, control_id: str
    ) -> Optional[FaControlEffectiveness]:
        return (
            self._db.query(FaControlEffectiveness)
            .filter(
                FaControlEffectiveness.tenant_id == self._tenant_id,
                FaControlEffectiveness.control_id == control_id,
            )
            .first()
        )

    def list_all_effectiveness(self) -> list[FaControlEffectiveness]:
        """Return every row for this tenant — used by dashboard/CGIN aggregation."""
        return (
            self._db.query(FaControlEffectiveness)
            .filter(FaControlEffectiveness.tenant_id == self._tenant_id)
            .order_by(FaControlEffectiveness.effectiveness_score.desc())
            .all()
        )

    def list_effectiveness(
        self, limit: int, offset: int
    ) -> tuple[list[FaControlEffectiveness], int]:
        q = self._db.query(FaControlEffectiveness).filter(
            FaControlEffectiveness.tenant_id == self._tenant_id,
        )
        total = q.count()
        items = (
            q.order_by(FaControlEffectiveness.effectiveness_score.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total

    # ------------------------------------------------------------------
    # FaControlEffectivenessHistory — append-only
    # ------------------------------------------------------------------

    def create_history(self, row: FaControlEffectivenessHistory) -> None:
        self._db.add(row)
        self._db.flush()

    def list_history(
        self, control_id: str, limit: int, offset: int
    ) -> tuple[list[FaControlEffectivenessHistory], int]:
        q = self._db.query(FaControlEffectivenessHistory).filter(
            FaControlEffectivenessHistory.tenant_id == self._tenant_id,
            FaControlEffectivenessHistory.control_id == control_id,
        )
        total = q.count()
        items = (
            q.order_by(FaControlEffectivenessHistory.captured_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total

    # ------------------------------------------------------------------
    # Cross-table helpers
    # ------------------------------------------------------------------

    def get_all_control_ids(self) -> list[str]:
        """Return distinct control_ids with evidence links for this tenant."""
        rows = (
            self._db.query(FaEvidenceControlLink.control_id)
            .filter(FaEvidenceControlLink.tenant_id == self._tenant_id)
            .distinct()
            .all()
        )
        return [r[0] for r in rows]
