"""services/governance_adaptive_intelligence/repository.py

Tenant-scoped data access for governance adaptive intelligence tables.
All queries are tenant-scoped. No query path bypasses tenant_id.

PR 17.6C — Governance Adaptive Intelligence Authority
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from api.db_models_governance_adaptive_intelligence import (
    FaGovernanceAccuracyAggregate,
    FaGovernancePlaybook,
    FaGovernanceRecommendationHistory,
    FaGovernanceRecommendationOutcome,
)


def _new_id() -> str:
    return str(uuid.uuid4())


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


class GovernanceAdaptiveIntelligenceRepository:
    """Tenant-scoped data access for governance adaptive intelligence tables."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    # ------------------------------------------------------------------
    # Recommendation history (append-only)
    # ------------------------------------------------------------------

    def create_history(self, row: FaGovernanceRecommendationHistory) -> None:
        """Insert a new recommendation history row."""
        self._db.add(row)
        self._db.flush()

    def get_history_by_id(
        self, history_id: str
    ) -> Optional[FaGovernanceRecommendationHistory]:
        """Fetch a history row by primary key, scoped to this tenant."""
        return (
            self._db.query(FaGovernanceRecommendationHistory)
            .filter(
                FaGovernanceRecommendationHistory.tenant_id == self._tenant_id,
                FaGovernanceRecommendationHistory.id == history_id,
            )
            .first()
        )

    def get_latest_history_for_recommendation(
        self, recommendation_id: str
    ) -> Optional[FaGovernanceRecommendationHistory]:
        """Return the most recent history row for a given recommendation_id."""
        return (
            self._db.query(FaGovernanceRecommendationHistory)
            .filter(
                FaGovernanceRecommendationHistory.tenant_id == self._tenant_id,
                FaGovernanceRecommendationHistory.recommendation_id
                == recommendation_id,
            )
            .order_by(FaGovernanceRecommendationHistory.generated_at.desc())
            .first()
        )

    def get_first_pending_for_recommendation(
        self, recommendation_id: str
    ) -> Optional[FaGovernanceRecommendationHistory]:
        """Return the first PENDING history row for a recommendation_id."""
        return (
            self._db.query(FaGovernanceRecommendationHistory)
            .filter(
                FaGovernanceRecommendationHistory.tenant_id == self._tenant_id,
                FaGovernanceRecommendationHistory.recommendation_id
                == recommendation_id,
                FaGovernanceRecommendationHistory.status == "PENDING",
            )
            .order_by(FaGovernanceRecommendationHistory.generated_at.asc())
            .first()
        )

    def list_history(
        self,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[FaGovernanceRecommendationHistory], int]:
        """List latest history rows per recommendation_id with optional status filter."""
        # First, get all rows for this tenant
        q = self._db.query(FaGovernanceRecommendationHistory).filter(
            FaGovernanceRecommendationHistory.tenant_id == self._tenant_id
        )
        if status is not None:
            q = q.filter(FaGovernanceRecommendationHistory.status == status)

        # To get only the latest per recommendation_id, load all and deduplicate
        all_rows: list[FaGovernanceRecommendationHistory] = (
            q.order_by(FaGovernanceRecommendationHistory.generated_at.desc()).all()
        )

        # Deduplicate: keep latest per recommendation_id
        seen: set[str] = set()
        deduped: list[FaGovernanceRecommendationHistory] = []
        for row in all_rows:
            if row.recommendation_id not in seen:
                seen.add(row.recommendation_id)
                deduped.append(row)

        total = len(deduped)
        paginated = deduped[offset : offset + limit]
        return paginated, total

    def list_all_history(self) -> list[FaGovernanceRecommendationHistory]:
        """Fetch all history rows for this tenant (no pagination)."""
        return (
            self._db.query(FaGovernanceRecommendationHistory)
            .filter(FaGovernanceRecommendationHistory.tenant_id == self._tenant_id)
            .order_by(FaGovernanceRecommendationHistory.generated_at.desc())
            .all()
        )

    # ------------------------------------------------------------------
    # Recommendation outcomes (mutable)
    # ------------------------------------------------------------------

    def create_outcome(self, row: FaGovernanceRecommendationOutcome) -> None:
        """Insert a new recommendation outcome row."""
        self._db.add(row)
        self._db.flush()

    def get_outcome_by_history_id(
        self, recommendation_history_id: str
    ) -> Optional[FaGovernanceRecommendationOutcome]:
        """Fetch outcome by recommendation_history_id for this tenant."""
        return (
            self._db.query(FaGovernanceRecommendationOutcome)
            .filter(
                FaGovernanceRecommendationOutcome.tenant_id == self._tenant_id,
                FaGovernanceRecommendationOutcome.recommendation_history_id
                == recommendation_history_id,
            )
            .first()
        )

    def list_outcomes(
        self, limit: int = 50, offset: int = 0
    ) -> tuple[list[FaGovernanceRecommendationOutcome], int]:
        """List all outcomes for this tenant with pagination."""
        q = self._db.query(FaGovernanceRecommendationOutcome).filter(
            FaGovernanceRecommendationOutcome.tenant_id == self._tenant_id
        )
        total = q.count()
        rows = (
            q.order_by(FaGovernanceRecommendationOutcome.recorded_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return rows, total

    def list_all_outcomes(self) -> list[FaGovernanceRecommendationOutcome]:
        """Fetch all outcomes for this tenant (for aggregate rebuild)."""
        return (
            self._db.query(FaGovernanceRecommendationOutcome)
            .filter(FaGovernanceRecommendationOutcome.tenant_id == self._tenant_id)
            .all()
        )

    def list_outcomes_for_type(
        self, recommendation_type: str
    ) -> list[FaGovernanceRecommendationOutcome]:
        """Fetch all outcomes associated with a specific recommendation type.

        Joins through history to filter by recommendation_type.
        """
        history_ids = [
            row.id
            for row in self._db.query(FaGovernanceRecommendationHistory)
            .filter(
                FaGovernanceRecommendationHistory.tenant_id == self._tenant_id,
                FaGovernanceRecommendationHistory.recommendation_type
                == recommendation_type,
            )
            .all()
        ]
        if not history_ids:
            return []
        return (
            self._db.query(FaGovernanceRecommendationOutcome)
            .filter(
                FaGovernanceRecommendationOutcome.tenant_id == self._tenant_id,
                FaGovernanceRecommendationOutcome.recommendation_history_id.in_(
                    history_ids
                ),
            )
            .all()
        )

    # ------------------------------------------------------------------
    # Accuracy aggregates (mutable)
    # ------------------------------------------------------------------

    def get_accuracy_aggregate(
        self, recommendation_type: str
    ) -> Optional[FaGovernanceAccuracyAggregate]:
        """Fetch accuracy aggregate for this tenant + recommendation_type."""
        return (
            self._db.query(FaGovernanceAccuracyAggregate)
            .filter(
                FaGovernanceAccuracyAggregate.tenant_id == self._tenant_id,
                FaGovernanceAccuracyAggregate.recommendation_type
                == recommendation_type,
            )
            .first()
        )

    def upsert_accuracy_aggregate(
        self, recommendation_type: str, updates: dict
    ) -> FaGovernanceAccuracyAggregate:
        """Get existing aggregate or create new one, then apply updates and flush."""
        existing = self.get_accuracy_aggregate(recommendation_type)
        if existing is None:
            row = FaGovernanceAccuracyAggregate(
                id=_new_id(),
                tenant_id=self._tenant_id,
                recommendation_type=recommendation_type,
                last_updated_at=_now_iso(),
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

    def list_all_accuracy_aggregates(self) -> list[FaGovernanceAccuracyAggregate]:
        """Fetch all accuracy aggregates for this tenant."""
        return (
            self._db.query(FaGovernanceAccuracyAggregate)
            .filter(FaGovernanceAccuracyAggregate.tenant_id == self._tenant_id)
            .order_by(FaGovernanceAccuracyAggregate.recommendation_type.asc())
            .all()
        )

    # ------------------------------------------------------------------
    # Playbooks (mutable)
    # ------------------------------------------------------------------

    def get_playbook(self, playbook_type: str) -> Optional[FaGovernancePlaybook]:
        """Fetch playbook for this tenant + playbook_type."""
        return (
            self._db.query(FaGovernancePlaybook)
            .filter(
                FaGovernancePlaybook.tenant_id == self._tenant_id,
                FaGovernancePlaybook.playbook_type == playbook_type,
            )
            .first()
        )

    def upsert_playbook(
        self, playbook_type: str, updates: dict
    ) -> FaGovernancePlaybook:
        """Get existing playbook or create new one, then apply updates and flush."""
        existing = self.get_playbook(playbook_type)
        if existing is None:
            row = FaGovernancePlaybook(
                id=_new_id(),
                tenant_id=self._tenant_id,
                playbook_type=playbook_type,
                last_updated_at=_now_iso(),
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

    def list_all_playbooks(self) -> list[FaGovernancePlaybook]:
        """Fetch all playbooks for this tenant."""
        return (
            self._db.query(FaGovernancePlaybook)
            .filter(FaGovernancePlaybook.tenant_id == self._tenant_id)
            .order_by(FaGovernancePlaybook.playbook_type.asc())
            .all()
        )
