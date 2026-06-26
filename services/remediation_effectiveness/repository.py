"""services/remediation_effectiveness/repository.py

Tenant-scoped data access for remediation effectiveness tables.
All queries are tenant-scoped. No query path bypasses tenant_id.

PR 17.5 — Remediation Effectiveness Analytics Authority
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from api.db_models_remediation_effectiveness import (
    FaRemediationLearning,
    FaRemediationOutcome,
    FaRemediationPattern,
    FaRemediationPersistence,
)


class RemediationEffectivenessRepository:
    """Tenant-scoped data access for remediation effectiveness tables."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    # ------------------------------------------------------------------
    # Outcomes
    # ------------------------------------------------------------------

    def create_outcome(self, row: FaRemediationOutcome) -> None:
        """Insert a new outcome record."""
        self._db.add(row)
        self._db.flush()

    def get_outcome_by_task(
        self, remediation_task_id: str, control_id: str
    ) -> FaRemediationOutcome | None:
        """Look up an existing outcome by (tenant, task, control) identity key."""
        return (
            self._db.query(FaRemediationOutcome)
            .filter(
                FaRemediationOutcome.tenant_id == self._tenant_id,
                FaRemediationOutcome.remediation_task_id == remediation_task_id,
                FaRemediationOutcome.control_id == control_id,
            )
            .first()
        )

    def get_outcome(self, remediation_id: str) -> FaRemediationOutcome | None:
        """Fetch a single outcome by ID, scoped to this tenant."""
        return (
            self._db.query(FaRemediationOutcome)
            .filter(
                FaRemediationOutcome.tenant_id == self._tenant_id,
                FaRemediationOutcome.id == remediation_id,
            )
            .first()
        )

    def list_outcomes(
        self,
        limit: int,
        offset: int,
        outcome_classification: str | None = None,
    ) -> list[FaRemediationOutcome]:
        """List outcomes for this tenant, optionally filtered by classification."""
        q = self._db.query(FaRemediationOutcome).filter(
            FaRemediationOutcome.tenant_id == self._tenant_id
        )
        if outcome_classification is not None:
            q = q.filter(
                FaRemediationOutcome.outcome_classification == outcome_classification
            )
        return (
            q.order_by(FaRemediationOutcome.measured_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

    def count_outcomes(self, outcome_classification: str | None = None) -> int:
        """Count outcomes for this tenant, optionally filtered by classification."""
        q = self._db.query(FaRemediationOutcome).filter(
            FaRemediationOutcome.tenant_id == self._tenant_id
        )
        if outcome_classification is not None:
            q = q.filter(
                FaRemediationOutcome.outcome_classification == outcome_classification
            )
        return q.count()

    def update_outcome_status(self, remediation_id: str, new_status: str) -> bool:
        """Update the status of an outcome. Returns True if updated."""
        row = self.get_outcome(remediation_id)
        if row is None:
            return False
        row.status = new_status
        self._db.flush()
        return True

    def get_outcomes_for_control(self, control_id: str) -> list[FaRemediationOutcome]:
        """Fetch all outcomes for a control, ordered by measured_at ascending."""
        return (
            self._db.query(FaRemediationOutcome)
            .filter(
                FaRemediationOutcome.tenant_id == self._tenant_id,
                FaRemediationOutcome.control_id == control_id,
            )
            .order_by(FaRemediationOutcome.measured_at.asc())
            .all()
        )

    def get_top_successes(self, limit: int = 10) -> list[FaRemediationOutcome]:
        """Fetch top outcomes by remediation_effectiveness_score descending."""
        return (
            self._db.query(FaRemediationOutcome)
            .filter(FaRemediationOutcome.tenant_id == self._tenant_id)
            .order_by(FaRemediationOutcome.remediation_effectiveness_score.desc())
            .limit(limit)
            .all()
        )

    def get_failures(self, limit: int = 50) -> list[FaRemediationOutcome]:
        """Fetch FAILURE and REGRESSION outcomes."""
        return (
            self._db.query(FaRemediationOutcome)
            .filter(
                FaRemediationOutcome.tenant_id == self._tenant_id,
                FaRemediationOutcome.outcome_classification.in_(
                    ["FAILURE", "REGRESSION"]
                ),
            )
            .order_by(FaRemediationOutcome.measured_at.desc())
            .limit(limit)
            .all()
        )

    def get_all_outcomes(self) -> list[FaRemediationOutcome]:
        """Fetch all outcomes for this tenant (used for learning rebuild)."""
        return (
            self._db.query(FaRemediationOutcome)
            .filter(FaRemediationOutcome.tenant_id == self._tenant_id)
            .order_by(FaRemediationOutcome.measured_at.asc())
            .all()
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def upsert_persistence_window(self, row: FaRemediationPersistence) -> None:
        """Insert a persistence window record (uniqueness enforced by DB constraint)."""
        self._db.add(row)
        self._db.flush()

    def get_persistence(self, remediation_id: str) -> list[FaRemediationPersistence]:
        """Fetch all persistence windows for a remediation."""
        return (
            self._db.query(FaRemediationPersistence)
            .filter(
                FaRemediationPersistence.tenant_id == self._tenant_id,
                FaRemediationPersistence.remediation_id == remediation_id,
            )
            .order_by(FaRemediationPersistence.window_days.asc())
            .all()
        )

    # ------------------------------------------------------------------
    # Learning
    # ------------------------------------------------------------------

    def upsert_learning(self, row: FaRemediationLearning) -> None:
        """Upsert a learning record by tenant + category."""
        existing = self.get_learning_for_category(row.remediation_category)
        if existing is None:
            self._db.add(row)
        else:
            existing.total_remediations = row.total_remediations
            existing.success_count = row.success_count
            existing.partial_success_count = row.partial_success_count
            existing.no_change_count = row.no_change_count
            existing.regression_count = row.regression_count
            existing.failure_count = row.failure_count
            existing.success_rate = row.success_rate
            existing.average_score_delta = row.average_score_delta
            existing.average_roi_score = row.average_roi_score
            existing.last_updated_at = row.last_updated_at
        self._db.flush()

    def get_all_learning(self) -> list[FaRemediationLearning]:
        """Fetch all learning records for this tenant."""
        return (
            self._db.query(FaRemediationLearning)
            .filter(FaRemediationLearning.tenant_id == self._tenant_id)
            .order_by(FaRemediationLearning.remediation_category.asc())
            .all()
        )

    def get_learning_for_category(self, category: str) -> FaRemediationLearning | None:
        """Fetch a learning record for a specific category."""
        return (
            self._db.query(FaRemediationLearning)
            .filter(
                FaRemediationLearning.tenant_id == self._tenant_id,
                FaRemediationLearning.remediation_category == category,
            )
            .first()
        )

    # ------------------------------------------------------------------
    # Patterns
    # ------------------------------------------------------------------

    def upsert_pattern(self, row: FaRemediationPattern) -> None:
        """Upsert a pattern by tenant + control + pattern_type."""
        existing = (
            self._db.query(FaRemediationPattern)
            .filter(
                FaRemediationPattern.tenant_id == self._tenant_id,
                FaRemediationPattern.control_id == row.control_id,
                FaRemediationPattern.pattern_type == row.pattern_type,
            )
            .first()
        )
        if existing is None:
            self._db.add(row)
        else:
            existing.severity = row.severity
            existing.occurrence_count = row.occurrence_count
            existing.description = row.description
            existing.last_seen_at = row.last_seen_at
        self._db.flush()

    def get_patterns(self) -> list[FaRemediationPattern]:
        """Fetch all patterns for this tenant."""
        return (
            self._db.query(FaRemediationPattern)
            .filter(FaRemediationPattern.tenant_id == self._tenant_id)
            .order_by(
                FaRemediationPattern.severity.asc(),
                FaRemediationPattern.control_id.asc(),
            )
            .all()
        )

    def get_patterns_for_control(self, control_id: str) -> list[FaRemediationPattern]:
        """Fetch all patterns for a specific control."""
        return (
            self._db.query(FaRemediationPattern)
            .filter(
                FaRemediationPattern.tenant_id == self._tenant_id,
                FaRemediationPattern.control_id == control_id,
            )
            .all()
        )

    def delete_patterns_for_control(self, control_id: str) -> None:
        """Delete all patterns for a specific control (used before re-detection)."""
        self._db.query(FaRemediationPattern).filter(
            FaRemediationPattern.tenant_id == self._tenant_id,
            FaRemediationPattern.control_id == control_id,
        ).delete(synchronize_session=False)
        self._db.flush()
