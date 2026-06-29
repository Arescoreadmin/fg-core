"""services/remediation_effectiveness/engine.py

Remediation Effectiveness Analytics Authority Engine.

Produces:
  - Per-remediation outcome recording and retrieval
  - Outcome listing with filtering
  - Dashboard aggregate statistics
  - Pattern detection per control
  - Learning aggregate rebuild per category
  - Top successes and failure drill-downs
  - CGIN benchmark-ready snapshots

No AI. No LLMs. All outputs are deterministic and auditable.

PR 17.5 — Remediation Effectiveness Analytics Authority
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from api.db_models_remediation_effectiveness import (
    FaRemediationLearning,
    FaRemediationOutcome,
    FaRemediationPattern,
)
from services.remediation_effectiveness.models import (
    REMEDIATION_EFFECTIVENESS_VERSION,
    OutcomeClassification,
    PatternSeverity,
    PatternType,
    classify_category_from_string,
    classify_effectiveness_level,
    classify_outcome,
    classify_roi,
    compute_remediation_effectiveness_score,
    compute_roi_score,
)
from services.cgin.privacy import fingerprint_tenant
from services.remediation_effectiveness.repository import (
    RemediationEffectivenessRepository,
)
from services.remediation_effectiveness.schemas import (
    CGINRemediationSnapshot,
    FailuresResponse,
    LearningItem,
    OutcomeListResponse,
    PatternItem,
    PatternsResponse,
    RecalculateResponse,
    RecordOutcomeRequest,
    RemediationDashboardResponse,
    RemediationOutcomeResponse,
    TopSuccessesResponse,
)


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


def _component_delta(before: float | None, after: float | None) -> float | None:
    if before is None or after is None:
        return None
    return round(after - before, 4)


class DuplicateRemediationOutcome(Exception):
    def __init__(self, outcome_id: str) -> None:
        self.outcome_id = outcome_id
        super().__init__(f"Outcome already exists: {outcome_id}")


class RemediationEffectivenessEngine:
    """Derives remediation effectiveness analytics from stored outcome data."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id
        self._repo = RemediationEffectivenessRepository(db, tenant_id)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _outcome_to_response(
        self, row: FaRemediationOutcome
    ) -> RemediationOutcomeResponse:
        return RemediationOutcomeResponse(
            id=row.id,
            tenant_id=row.tenant_id,
            remediation_task_id=row.remediation_task_id,
            control_id=row.control_id,
            before_score=row.before_score,
            after_score=row.after_score,
            score_delta=row.score_delta,
            before_effectiveness_level=row.before_effectiveness_level,
            after_effectiveness_level=row.after_effectiveness_level,
            outcome_classification=row.outcome_classification,
            remediation_effectiveness_score=row.remediation_effectiveness_score,
            effectiveness_level=row.effectiveness_level,
            roi_score=row.roi_score,
            roi_classification=row.roi_classification,
            remediation_category=row.remediation_category,
            verification_before=row.verification_before,
            verification_after=row.verification_after,
            verification_delta=row.verification_delta,
            freshness_before=row.freshness_before,
            freshness_after=row.freshness_after,
            freshness_delta=row.freshness_delta,
            forecast_before=row.forecast_before,
            forecast_after=row.forecast_after,
            forecast_delta=row.forecast_delta,
            governance_health_before=row.governance_health_before,
            governance_health_after=row.governance_health_after,
            governance_health_delta=row.governance_health_delta,
            status=row.status,
            measured_at=row.measured_at,
            generated_at=_now_iso(),
        )

    def _detect_patterns_for_control(self, control_id: str) -> list[dict]:
        """Detect remediation patterns for a specific control.

        Returns a list of pattern dicts with keys matching FaRemediationPattern fields.
        """
        outcomes = self._repo.get_outcomes_for_control(control_id)
        if not outcomes:
            return []

        now = _now_iso()
        patterns: list[dict] = []

        classifications = [o.outcome_classification for o in outcomes]
        failure_count = classifications.count(OutcomeClassification.FAILURE.value)
        regression_count = classifications.count(OutcomeClassification.REGRESSION.value)
        no_change_count = classifications.count(OutcomeClassification.NO_CHANGE.value)
        success_count = sum(
            1
            for c in classifications
            if c
            in (
                OutcomeClassification.SUCCESS.value,
                OutcomeClassification.PARTIAL_SUCCESS.value,
            )
        )

        # REPEATED_FAILURE: 3+ FAILURE outcomes → CRITICAL
        if failure_count >= 3:
            patterns.append(
                {
                    "pattern_type": PatternType.REPEATED_FAILURE.value,
                    "severity": PatternSeverity.CRITICAL.value,
                    "occurrence_count": failure_count,
                    "description": (
                        f"Control {control_id} has {failure_count} repeated failure "
                        "outcomes indicating systemic remediation breakdown."
                    ),
                    "detected_at": now,
                    "last_seen_at": now,
                }
            )

        # RECURRING_DEGRADATION: 2+ REGRESSION outcomes → HIGH
        if regression_count >= 2:
            patterns.append(
                {
                    "pattern_type": PatternType.RECURRING_DEGRADATION.value,
                    "severity": PatternSeverity.HIGH.value,
                    "occurrence_count": regression_count,
                    "description": (
                        f"Control {control_id} has {regression_count} regression "
                        "outcomes indicating recurring score degradation."
                    ),
                    "detected_at": now,
                    "last_seen_at": now,
                }
            )

        # NO_IMPROVEMENT: 3+ NO_CHANGE outcomes with no SUCCESS → HIGH
        if no_change_count >= 3 and success_count == 0:
            patterns.append(
                {
                    "pattern_type": PatternType.NO_IMPROVEMENT.value,
                    "severity": PatternSeverity.HIGH.value,
                    "occurrence_count": no_change_count,
                    "description": (
                        f"Control {control_id} has {no_change_count} no-change "
                        "outcomes with no successful remediations."
                    ),
                    "detected_at": now,
                    "last_seen_at": now,
                }
            )

        # ROLLBACK_PATTERN: any SUCCESS/PARTIAL followed by FAILURE → HIGH
        _positive = {
            OutcomeClassification.SUCCESS.value,
            OutcomeClassification.PARTIAL_SUCCESS.value,
        }
        for i in range(len(outcomes) - 1):
            if (
                outcomes[i].outcome_classification in _positive
                and outcomes[i + 1].outcome_classification
                == OutcomeClassification.FAILURE.value
            ):
                patterns.append(
                    {
                        "pattern_type": PatternType.ROLLBACK_PATTERN.value,
                        "severity": PatternSeverity.HIGH.value,
                        "occurrence_count": 1,
                        "description": (
                            f"Control {control_id} shows a rollback pattern: "
                            "success followed by failure outcome."
                        ),
                        "detected_at": now,
                        "last_seen_at": now,
                    }
                )
                break

        # CONSISTENT_IMPROVEMENT: 3+ consecutive SUCCESS/PARTIAL_SUCCESS → LOW
        max_consecutive = 0
        current_consecutive = 0
        for o in outcomes:
            if o.outcome_classification in _positive:
                current_consecutive += 1
                max_consecutive = max(max_consecutive, current_consecutive)
            else:
                current_consecutive = 0

        if max_consecutive >= 3:
            patterns.append(
                {
                    "pattern_type": PatternType.CONSISTENT_IMPROVEMENT.value,
                    "severity": PatternSeverity.LOW.value,
                    "occurrence_count": max_consecutive,
                    "description": (
                        f"Control {control_id} shows {max_consecutive} consecutive "
                        "successful remediations indicating consistent improvement."
                    ),
                    "detected_at": now,
                    "last_seen_at": now,
                }
            )

        # RAPID_REGRESSION: score improved > 10 then outcome = FAILURE → HIGH
        for i in range(len(outcomes) - 1):
            if (
                outcomes[i].score_delta > 10.0
                and outcomes[i + 1].outcome_classification
                == OutcomeClassification.FAILURE.value
            ):
                patterns.append(
                    {
                        "pattern_type": PatternType.RAPID_REGRESSION.value,
                        "severity": PatternSeverity.HIGH.value,
                        "occurrence_count": 1,
                        "description": (
                            f"Control {control_id} improved by more than 10 points "
                            "but subsequently failed — indicating rapid regression."
                        ),
                        "detected_at": now,
                        "last_seen_at": now,
                    }
                )
                break

        return patterns

    def _rebuild_learning(self) -> int:
        """Rebuild learning aggregates from all outcomes.

        Returns count of categories updated.
        """
        now = _now_iso()
        all_outcomes = self._repo.get_all_outcomes()

        # Group by category
        by_category: dict[str, list] = {}
        for o in all_outcomes:
            cat = o.remediation_category
            by_category.setdefault(cat, []).append(o)

        count = 0
        for category, outcomes in by_category.items():
            total = len(outcomes)
            success_c = sum(
                1
                for o in outcomes
                if o.outcome_classification == OutcomeClassification.SUCCESS.value
            )
            partial_c = sum(
                1
                for o in outcomes
                if o.outcome_classification
                == OutcomeClassification.PARTIAL_SUCCESS.value
            )
            no_change_c = sum(
                1
                for o in outcomes
                if o.outcome_classification == OutcomeClassification.NO_CHANGE.value
            )
            regression_c = sum(
                1
                for o in outcomes
                if o.outcome_classification == OutcomeClassification.REGRESSION.value
            )
            failure_c = sum(
                1
                for o in outcomes
                if o.outcome_classification == OutcomeClassification.FAILURE.value
            )
            success_rate = round(success_c / total, 4) if total > 0 else 0.0
            avg_delta = (
                round(sum(o.score_delta for o in outcomes) / total, 4)
                if total > 0
                else 0.0
            )
            avg_roi = (
                round(sum(o.roi_score for o in outcomes) / total, 4)
                if total > 0
                else 0.0
            )

            row = FaRemediationLearning(
                id=_new_id(),
                tenant_id=self._tenant_id,
                remediation_category=category,
                total_remediations=total,
                success_count=success_c,
                partial_success_count=partial_c,
                no_change_count=no_change_c,
                regression_count=regression_c,
                failure_count=failure_c,
                success_rate=success_rate,
                average_score_delta=avg_delta,
                average_roi_score=avg_roi,
                last_updated_at=now,
            )
            self._repo.upsert_learning(row)
            count += 1

        return count

    # ------------------------------------------------------------------
    # Public: POST /remediation-effectiveness
    # ------------------------------------------------------------------

    def record_outcome(
        self, request: RecordOutcomeRequest
    ) -> RemediationOutcomeResponse:
        """Record a new remediation outcome and compute all derived metrics."""
        existing = self._repo.get_outcome_by_task(
            request.remediation_task_id, request.control_id
        )
        if existing is not None:
            raise DuplicateRemediationOutcome(existing.id)

        now = _now_iso()
        score_delta = request.after_score - request.before_score
        outcome_cls = classify_outcome(score_delta)
        res = compute_remediation_effectiveness_score(
            request.before_score, request.after_score
        )
        eff_level = classify_effectiveness_level(res)
        roi = compute_roi_score(request.before_score, score_delta)
        roi_cls = classify_roi(roi)
        category = classify_category_from_string(request.remediation_category)

        row = FaRemediationOutcome(
            id=_new_id(),
            tenant_id=self._tenant_id,
            remediation_task_id=request.remediation_task_id,
            control_id=request.control_id,
            before_score=request.before_score,
            after_score=request.after_score,
            score_delta=round(score_delta, 4),
            before_effectiveness_level=request.before_effectiveness_level,
            after_effectiveness_level=request.after_effectiveness_level,
            outcome_classification=outcome_cls.value,
            remediation_effectiveness_score=round(res, 4),
            effectiveness_level=eff_level.value,
            roi_score=round(roi, 4),
            roi_classification=roi_cls.value,
            remediation_category=category.value,
            verification_before=request.verification_before,
            verification_after=request.verification_after,
            verification_delta=_component_delta(
                request.verification_before, request.verification_after
            ),
            freshness_before=request.freshness_before,
            freshness_after=request.freshness_after,
            freshness_delta=_component_delta(
                request.freshness_before, request.freshness_after
            ),
            forecast_before=request.forecast_before,
            forecast_after=request.forecast_after,
            forecast_delta=_component_delta(
                request.forecast_before, request.forecast_after
            ),
            governance_health_before=request.governance_health_before,
            governance_health_after=request.governance_health_after,
            governance_health_delta=_component_delta(
                request.governance_health_before, request.governance_health_after
            ),
            status="COMPLETE",
            measured_at=now,
            calculation_version=REMEDIATION_EFFECTIVENESS_VERSION,
        )
        self._repo.create_outcome(row)
        self._db.commit()
        return self._outcome_to_response(row)

    # ------------------------------------------------------------------
    # Public: GET /remediation-effectiveness/{remediation_id}
    # ------------------------------------------------------------------

    def get_outcome(self, remediation_id: str) -> Optional[RemediationOutcomeResponse]:
        """Retrieve a single outcome by ID."""
        row = self._repo.get_outcome(remediation_id)
        if row is None:
            return None
        return self._outcome_to_response(row)

    # ------------------------------------------------------------------
    # Public: GET /remediation-effectiveness
    # ------------------------------------------------------------------

    def list_outcomes(
        self,
        limit: int,
        offset: int,
        outcome_classification: Optional[str] = None,
    ) -> OutcomeListResponse:
        """List outcomes with optional classification filter."""
        now = _now_iso()
        items = self._repo.list_outcomes(
            limit=limit,
            offset=offset,
            outcome_classification=outcome_classification,
        )
        total = self._repo.count_outcomes(outcome_classification=outcome_classification)
        success_count = self._repo.count_outcomes(
            outcome_classification=OutcomeClassification.SUCCESS.value
        )
        failure_count = self._repo.count_outcomes(
            outcome_classification=OutcomeClassification.FAILURE.value
        )
        return OutcomeListResponse(
            tenant_id=self._tenant_id,
            items=[self._outcome_to_response(r) for r in items],
            total=total,
            success_count=success_count,
            failure_count=failure_count,
            generated_at=now,
        )

    # ------------------------------------------------------------------
    # Public: GET /remediation-effectiveness/dashboard
    # ------------------------------------------------------------------

    def get_dashboard(self) -> RemediationDashboardResponse:
        """Compute dashboard aggregate statistics."""
        now = _now_iso()
        all_outcomes = self._repo.get_all_outcomes()
        total = len(all_outcomes)

        success_c = sum(
            1
            for o in all_outcomes
            if o.outcome_classification == OutcomeClassification.SUCCESS.value
        )
        partial_c = sum(
            1
            for o in all_outcomes
            if o.outcome_classification == OutcomeClassification.PARTIAL_SUCCESS.value
        )
        no_change_c = sum(
            1
            for o in all_outcomes
            if o.outcome_classification == OutcomeClassification.NO_CHANGE.value
        )
        regression_c = sum(
            1
            for o in all_outcomes
            if o.outcome_classification == OutcomeClassification.REGRESSION.value
        )
        failure_c = sum(
            1
            for o in all_outcomes
            if o.outcome_classification == OutcomeClassification.FAILURE.value
        )

        success_rate = round(success_c / total, 4) if total > 0 else 0.0
        avg_delta = (
            round(sum(o.score_delta for o in all_outcomes) / total, 4)
            if total > 0
            else 0.0
        )
        avg_roi = (
            round(sum(o.roi_score for o in all_outcomes) / total, 4)
            if total > 0
            else 0.0
        )
        avg_res = (
            round(
                sum(o.remediation_effectiveness_score for o in all_outcomes) / total, 4
            )
            if total > 0
            else 0.0
        )

        # Top / worst performing category by success_rate
        all_learning = self._repo.get_all_learning()
        top_cat: Optional[str] = None
        worst_cat: Optional[str] = None
        if all_learning:
            best = max(all_learning, key=lambda learning: learning.success_rate)
            worst = min(all_learning, key=lambda learning: learning.success_rate)
            top_cat = best.remediation_category
            worst_cat = worst.remediation_category

        all_patterns = self._repo.get_patterns()
        active_patterns = len(all_patterns)
        critical_patterns = sum(
            1 for p in all_patterns if p.severity == PatternSeverity.CRITICAL.value
        )

        learning_items = [
            LearningItem(
                remediation_category=learning.remediation_category,
                total_remediations=learning.total_remediations,
                success_count=learning.success_count,
                partial_success_count=learning.partial_success_count,
                no_change_count=learning.no_change_count,
                regression_count=learning.regression_count,
                failure_count=learning.failure_count,
                success_rate=learning.success_rate,
                average_score_delta=learning.average_score_delta,
                average_roi_score=learning.average_roi_score,
                last_updated_at=learning.last_updated_at,
            )
            for learning in all_learning
        ]

        return RemediationDashboardResponse(
            tenant_id=self._tenant_id,
            total_remediations=total,
            success_count=success_c,
            partial_success_count=partial_c,
            no_change_count=no_change_c,
            regression_count=regression_c,
            failure_count=failure_c,
            success_rate=success_rate,
            average_score_delta=avg_delta,
            average_roi_score=avg_roi,
            average_effectiveness_score=avg_res,
            top_performing_category=top_cat,
            worst_performing_category=worst_cat,
            active_patterns=active_patterns,
            critical_patterns=critical_patterns,
            learning=learning_items,
            generated_at=now,
        )

    # ------------------------------------------------------------------
    # Public: GET /remediation-effectiveness/patterns
    # ------------------------------------------------------------------

    def get_patterns(self) -> PatternsResponse:
        """Return all detected patterns for this tenant."""
        now = _now_iso()
        all_patterns = self._repo.get_patterns()
        critical_c = sum(
            1 for p in all_patterns if p.severity == PatternSeverity.CRITICAL.value
        )
        high_c = sum(
            1 for p in all_patterns if p.severity == PatternSeverity.HIGH.value
        )
        items = [
            PatternItem(
                control_id=p.control_id,
                pattern_type=p.pattern_type,
                severity=p.severity,
                occurrence_count=p.occurrence_count,
                description=p.description,
                detected_at=p.detected_at,
                last_seen_at=p.last_seen_at,
            )
            for p in all_patterns
        ]
        return PatternsResponse(
            tenant_id=self._tenant_id,
            patterns=items,
            total=len(items),
            critical_count=critical_c,
            high_count=high_c,
            generated_at=now,
        )

    # ------------------------------------------------------------------
    # Public: GET /remediation-effectiveness/top-successes
    # ------------------------------------------------------------------

    def get_top_successes(self, limit: int = 10) -> TopSuccessesResponse:
        """Return top-performing remediation outcomes."""
        now = _now_iso()
        rows = self._repo.get_top_successes(limit=limit)
        return TopSuccessesResponse(
            tenant_id=self._tenant_id,
            items=[self._outcome_to_response(r) for r in rows],
            generated_at=now,
        )

    # ------------------------------------------------------------------
    # Public: GET /remediation-effectiveness/failures
    # ------------------------------------------------------------------

    def get_failures(self) -> FailuresResponse:
        """Return failure and regression outcomes."""
        now = _now_iso()
        total_failures = self._repo.count_outcomes(
            outcome_classification=OutcomeClassification.FAILURE.value
        )
        total_regressions = self._repo.count_outcomes(
            outcome_classification=OutcomeClassification.REGRESSION.value
        )
        rows = self._repo.get_failures()
        return FailuresResponse(
            tenant_id=self._tenant_id,
            items=[self._outcome_to_response(r) for r in rows],
            total_failures=total_failures,
            total_regressions=total_regressions,
            generated_at=now,
        )

    # ------------------------------------------------------------------
    # Public: GET /remediation-effectiveness/cgin/snapshot
    # ------------------------------------------------------------------

    def cgin_snapshot(self) -> CGINRemediationSnapshot:
        """Return a CGIN benchmark-ready snapshot."""
        now = _now_iso()
        all_outcomes = self._repo.get_all_outcomes()
        total = len(all_outcomes)
        success_c = sum(
            1
            for o in all_outcomes
            if o.outcome_classification == OutcomeClassification.SUCCESS.value
        )
        success_rate = round(success_c / total, 4) if total > 0 else 0.0
        avg_delta = (
            round(sum(o.score_delta for o in all_outcomes) / total, 4)
            if total > 0
            else 0.0
        )
        avg_roi = (
            round(sum(o.roi_score for o in all_outcomes) / total, 4)
            if total > 0
            else 0.0
        )
        all_patterns = self._repo.get_patterns()
        return CGINRemediationSnapshot(
            tenant_fingerprint=fingerprint_tenant(self._tenant_id),
            total_remediations=total,
            success_rate=success_rate,
            average_score_delta=avg_delta,
            average_roi_score=avg_roi,
            patterns_detected=len(all_patterns),
            snapshot_at=now,
        )

    # ------------------------------------------------------------------
    # Public: POST /remediation-effectiveness/recalculate
    # ------------------------------------------------------------------

    def recalculate(self, control_id: Optional[str] = None) -> RecalculateResponse:
        """Recalculate patterns and learning aggregates.

        If control_id is provided, only re-detect patterns for that control.
        Otherwise, re-detect patterns for all controls that have outcomes.
        Learning aggregates are always fully rebuilt.
        """
        now = _now_iso()
        patterns_detected = 0

        if control_id is not None:
            # Re-detect for single control
            self._repo.delete_patterns_for_control(control_id)
            detected = self._detect_patterns_for_control(control_id)
            for p_dict in detected:
                row = FaRemediationPattern(
                    id=_new_id(),
                    tenant_id=self._tenant_id,
                    control_id=control_id,
                    **p_dict,
                )
                self._repo.upsert_pattern(row)
                patterns_detected += 1
        else:
            # Discover all distinct control IDs with outcomes
            all_outcomes = self._repo.get_all_outcomes()
            control_ids = list({o.control_id for o in all_outcomes})
            for cid in control_ids:
                self._repo.delete_patterns_for_control(cid)
                detected = self._detect_patterns_for_control(cid)
                for p_dict in detected:
                    row = FaRemediationPattern(
                        id=_new_id(),
                        tenant_id=self._tenant_id,
                        control_id=cid,
                        **p_dict,
                    )
                    self._repo.upsert_pattern(row)
                    patterns_detected += 1

        # Always rebuild learning
        learning_categories_updated = self._rebuild_learning()
        self._db.commit()

        return RecalculateResponse(
            tenant_id=self._tenant_id,
            patterns_detected=patterns_detected,
            learning_categories_updated=learning_categories_updated,
            generated_at=now,
        )

    # ------------------------------------------------------------------
    # Public: PATCH /remediation-effectiveness/{remediation_id}
    # ------------------------------------------------------------------

    def update_outcome_status(
        self, remediation_id: str, new_status: str
    ) -> Optional[RemediationOutcomeResponse]:
        """Update the status of an outcome. Returns None if not found."""
        updated = self._repo.update_outcome_status(remediation_id, new_status)
        if not updated:
            return None
        self._db.commit()
        row = self._repo.get_outcome(remediation_id)
        if row is None:
            return None
        return self._outcome_to_response(row)
