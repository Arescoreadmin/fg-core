"""services/control_effectiveness_explainability/engine.py

Explainability & Governance Action Engine.

Produces:
  - Per-component score contributions (on-the-fly)
  - Root cause analysis signals (on-the-fly)
  - Deterministic governance actions (on-the-fly)
  - Template-driven control health narrative (on-the-fly)
  - Change detection summary (on-the-fly)
  - Governance priority classification (on-the-fly)
  - Pre-computed rankings (stored in fa_control_ranking)
  - Executive intelligence dashboard (on-the-fly)
  - CGIN benchmark-ready snapshots (on-the-fly)

No AI. No LLMs. All outputs are deterministic and auditable.

PR 16.5.1 — Control Effectiveness Explainability & Governance Action Engine
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from api.db_models_control_effectiveness import FaControlEffectiveness
from api.db_models_control_effectiveness_explainability import FaControlRanking
from services.control_effectiveness.repository import ControlEffectivenessRepository
from services.control_effectiveness_explainability.models import (
    RISK_SEVERITY,
    RankType,
    classify_priority,
    compute_contributions,
    compute_governance_actions,
    compute_root_causes,
    detect_change,
    generate_narrative,
)
from services.control_effectiveness_explainability.repository import (
    ExplainabilityRepository,
)
from services.control_effectiveness_explainability.schemas import (
    ChangeDetectionSummary,
    ControlContributionSnapshot,
    ControlActionSnapshot,
    ControlExplainResponse,
    ControlPriorityItem,
    ControlPrioritySnapshot,
    ControlRiskSnapshot,
    ExecutiveDashboardResponse,
    GovernanceActionItem,
    GovernanceActionsResponse,
    PrioritiesResponse,
    RankingItem,
    RankingsResponse,
    RootCauseItem,
    ScoreContributionItem,
    ScoreContributorsResponse,
)

_RANK_LIMIT = 10


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


def _priority_rationale(
    effectiveness_score: float,
    effectiveness_level: str,
    trend_direction: Optional[str],
    exception_score: Optional[float],
    forecast_score: Optional[float],
) -> str:
    if effectiveness_level == "INEFFECTIVE" or effectiveness_score < 40:
        return "Control effectiveness is critically low and requires immediate remediation."
    if effectiveness_level == "WEAK" and trend_direction == "CRITICAL":
        return "Weak control with critically declining trend — escalation required."
    if effectiveness_score < 60:
        return "Control effectiveness is below acceptable threshold."
    if effectiveness_score < 75 and trend_direction in ("DEGRADING", "CRITICAL"):
        return "Moderate effectiveness with a declining trend — early intervention recommended."
    if exception_score is not None and exception_score < 60:
        return "Active governance exceptions are significantly weakening this control."
    if effectiveness_score < 75:
        return "Control effectiveness has room for improvement."
    if trend_direction == "DEGRADING":
        return "Effective control but trend is declining — monitor closely."
    if forecast_score is not None and forecast_score < 50:
        return "Current performance is adequate but forecast indicates risk of decline."
    return "Control is performing well with no immediate governance concerns."


class ExplainabilityEngine:
    """Derives governance intelligence from stored effectiveness data."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id
        self._ce_repo = ControlEffectivenessRepository(db, tenant_id)
        self._repo = ExplainabilityRepository(db, tenant_id)

    # ------------------------------------------------------------------
    # Internal: load effectiveness row
    # ------------------------------------------------------------------

    def _load_row(self, control_id: str) -> Optional[FaControlEffectiveness]:
        return self._ce_repo.get_effectiveness(control_id)

    # ------------------------------------------------------------------
    # Internal: derive all explainability artifacts from a single row
    # ------------------------------------------------------------------

    def _contributions_from_row(
        self, row: FaControlEffectiveness
    ) -> list[ScoreContributionItem]:
        items = compute_contributions(
            coverage_score=row.coverage_score,
            verification_score=row.verification_score,
            freshness_score=row.freshness_score,
            trend_score=row.trend_score,
            forecast_score=row.forecast_score,
            evidence_density_score=row.evidence_density_score,
            exception_score=row.exception_score,
        )
        return [ScoreContributionItem(**d) for d in items]

    def _root_causes_from_row(self, row: FaControlEffectiveness) -> list[RootCauseItem]:
        items = compute_root_causes(
            verification_score=row.verification_score,
            freshness_score=row.freshness_score,
            coverage_score=row.coverage_score,
            trend_direction=row.trend_direction,
            exception_score=row.exception_score,
            evidence_density_score=row.evidence_density_score,
            governance_health_score=row.governance_health_score,
            forecast_score=row.forecast_score,
        )
        return [RootCauseItem(**d) for d in items]

    def _actions_from_row(self, row: FaControlEffectiveness) -> list[GovernanceActionItem]:
        items = compute_governance_actions(
            verification_score=row.verification_score,
            freshness_score=row.freshness_score,
            coverage_score=row.coverage_score,
            exception_score=row.exception_score,
            governance_health_score=row.governance_health_score,
            trend_direction=row.trend_direction,
            forecast_score=row.forecast_score,
        )
        return [GovernanceActionItem(**d) for d in items]

    def _priority_from_row(self, row: FaControlEffectiveness) -> str:
        return classify_priority(
            effectiveness_score=row.effectiveness_score,
            effectiveness_level=row.effectiveness_level,
            trend_direction=row.trend_direction,
            forecast_score=row.forecast_score,
            exception_score=row.exception_score,
        ).value

    def _ranking_item_from_row(
        self, row: FaControlEffectiveness, rank_type: str, position: int
    ) -> RankingItem:
        return RankingItem(
            control_id=row.control_id,
            rank_position=position,
            effectiveness_score=row.effectiveness_score,
            effectiveness_level=row.effectiveness_level,
            effectiveness_risk=row.effectiveness_risk,
            rank_type=rank_type,
        )

    # ------------------------------------------------------------------
    # Public: GET /control-effectiveness/explain/{control_id}
    # ------------------------------------------------------------------

    def explain(self, control_id: str) -> Optional[ControlExplainResponse]:
        row = self._load_row(control_id)
        if row is None:
            return None
        now = _now_iso()
        contributions = self._contributions_from_row(row)
        root_causes = self._root_causes_from_row(row)
        actions = self._actions_from_row(row)
        priority = self._priority_from_row(row)
        narrative = generate_narrative(
            effectiveness_score=row.effectiveness_score,
            effectiveness_level=row.effectiveness_level,
            trend_direction=row.trend_direction,
            root_causes=[
                {"impact": rc.impact, "description": rc.description}
                for rc in root_causes
            ],
            actions=[
                {"description": a.description, "priority": a.priority} for a in actions
            ],
        )
        change = detect_change(
            score_delta_7d=row.score_delta_7d,
            score_delta_30d=row.score_delta_30d,
            score_delta_90d=row.score_delta_90d,
        )
        positives = [rc for rc in root_causes if rc.impact == "POSITIVE"]
        negatives = [rc for rc in root_causes if rc.impact == "NEGATIVE"]
        return ControlExplainResponse(
            tenant_id=self._tenant_id,
            control_id=control_id,
            effectiveness_score=row.effectiveness_score,
            effectiveness_level=row.effectiveness_level,
            effectiveness_risk=row.effectiveness_risk,
            governance_priority=priority,
            narrative=narrative,
            contributions=contributions,
            positive_signals=positives,
            negative_signals=negatives,
            actions=actions,
            change_detection=ChangeDetectionSummary(**change),
            generated_at=now,
        )

    # ------------------------------------------------------------------
    # Public: GET /control-effectiveness/contributors/{control_id}
    # ------------------------------------------------------------------

    def get_contributors(self, control_id: str) -> Optional[ScoreContributorsResponse]:
        row = self._load_row(control_id)
        if row is None:
            return None
        return ScoreContributorsResponse(
            tenant_id=self._tenant_id,
            control_id=control_id,
            effectiveness_score=row.effectiveness_score,
            effectiveness_level=row.effectiveness_level,
            contributions=self._contributions_from_row(row),
            generated_at=_now_iso(),
        )

    # ------------------------------------------------------------------
    # Public: GET /control-effectiveness/actions/{control_id}
    # ------------------------------------------------------------------

    def get_actions(self, control_id: str) -> Optional[GovernanceActionsResponse]:
        row = self._load_row(control_id)
        if row is None:
            return None
        priority = self._priority_from_row(row)
        actions = self._actions_from_row(row)
        return GovernanceActionsResponse(
            tenant_id=self._tenant_id,
            control_id=control_id,
            governance_priority=priority,
            actions=actions,
            generated_at=_now_iso(),
        )

    # ------------------------------------------------------------------
    # Public: GET /control-effectiveness/priorities
    # ------------------------------------------------------------------

    def get_priorities(
        self, limit: int, offset: int
    ) -> PrioritiesResponse:
        now = _now_iso()
        all_rows = self._ce_repo.list_all_effectiveness()

        def _item(row: FaControlEffectiveness) -> ControlPriorityItem:
            priority = classify_priority(
                effectiveness_score=row.effectiveness_score,
                effectiveness_level=row.effectiveness_level,
                trend_direction=row.trend_direction,
                forecast_score=row.forecast_score,
                exception_score=row.exception_score,
            )
            rationale = _priority_rationale(
                effectiveness_score=row.effectiveness_score,
                effectiveness_level=row.effectiveness_level,
                trend_direction=row.trend_direction,
                exception_score=row.exception_score,
                forecast_score=row.forecast_score,
            )
            return ControlPriorityItem(
                control_id=row.control_id,
                effectiveness_score=row.effectiveness_score,
                effectiveness_level=row.effectiveness_level,
                effectiveness_risk=row.effectiveness_risk,
                governance_priority=priority.value,
                trend_direction=row.trend_direction,
                priority_rationale=rationale,
            )

        items = [_item(r) for r in all_rows]
        # Sort: CRITICAL first, then HIGH, MEDIUM, LOW; within same priority by score asc
        from services.control_effectiveness_explainability.models import PRIORITY_ORDER

        items.sort(
            key=lambda x: (
                PRIORITY_ORDER[x.governance_priority],
                x.effectiveness_score,
            )
        )
        total = len(items)
        critical_count = sum(1 for i in items if i.governance_priority == "CRITICAL")
        high_count = sum(1 for i in items if i.governance_priority == "HIGH")
        medium_count = sum(1 for i in items if i.governance_priority == "MEDIUM")
        low_count = sum(1 for i in items if i.governance_priority == "LOW")
        page = items[offset : offset + limit]
        return PrioritiesResponse(
            tenant_id=self._tenant_id,
            items=page,
            total=total,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            generated_at=now,
        )

    # ------------------------------------------------------------------
    # Public: rankings refresh (called by recalculate_all)
    # ------------------------------------------------------------------

    def recalculate_rankings(self) -> None:
        """Compute and persist all ranking types for this tenant."""
        now = _now_iso()
        all_rows = self._ce_repo.list_all_effectiveness()
        if not all_rows:
            return

        def _rows_to_ranking(
            rows: list[FaControlEffectiveness], rank_type: str
        ) -> list[FaControlRanking]:
            result = []
            for pos, row in enumerate(rows[:_RANK_LIMIT], start=1):
                result.append(
                    FaControlRanking(
                        id=_new_id(),
                        tenant_id=self._tenant_id,
                        control_id=row.control_id,
                        rank_type=rank_type,
                        rank_position=pos,
                        effectiveness_score=row.effectiveness_score,
                        effectiveness_level=row.effectiveness_level,
                        effectiveness_risk=row.effectiveness_risk,
                        generated_at=now,
                    )
                )
            return result

        # TOP: highest effectiveness_score
        top = sorted(all_rows, key=lambda r: r.effectiveness_score, reverse=True)
        self._repo.replace_rankings(RankType.TOP.value, _rows_to_ranking(top, "TOP"))

        # WEAKEST: lowest effectiveness_score
        weakest = sorted(all_rows, key=lambda r: r.effectiveness_score)
        self._repo.replace_rankings(
            RankType.WEAKEST.value, _rows_to_ranking(weakest, "WEAKEST")
        )

        # FASTEST_IMPROVING: highest score_delta_30d (non-null)
        with_delta = [r for r in all_rows if r.score_delta_30d is not None]
        improving = sorted(
            with_delta, key=lambda r: r.score_delta_30d or 0.0, reverse=True
        )
        self._repo.replace_rankings(
            RankType.FASTEST_IMPROVING.value,
            _rows_to_ranking(improving, "FASTEST_IMPROVING"),
        )

        # FASTEST_DECLINING: lowest score_delta_30d (non-null)
        declining = sorted(with_delta, key=lambda r: r.score_delta_30d or 0.0)
        self._repo.replace_rankings(
            RankType.FASTEST_DECLINING.value,
            _rows_to_ranking(declining, "FASTEST_DECLINING"),
        )

        # HIGHEST_RISK: CRITICAL first, then HIGH; within same risk by score asc
        highest_risk = sorted(
            all_rows,
            key=lambda r: (
                RISK_SEVERITY.get(r.effectiveness_risk, 3),
                r.effectiveness_score,
            ),
        )
        self._repo.replace_rankings(
            RankType.HIGHEST_RISK.value,
            _rows_to_ranking(highest_risk, "HIGHEST_RISK"),
        )

        # MOST_FRAGILE: lowest governance_health_score (non-null)
        with_health = [r for r in all_rows if r.governance_health_score is not None]
        most_fragile = sorted(with_health, key=lambda r: r.governance_health_score or 100.0)
        self._repo.replace_rankings(
            RankType.MOST_FRAGILE.value,
            _rows_to_ranking(most_fragile, "MOST_FRAGILE"),
        )

        # MOST_VALUABLE: highest effectiveness_score among EFFECTIVE or HIGHLY_EFFECTIVE
        valuable = sorted(
            [
                r
                for r in all_rows
                if r.effectiveness_level in ("EFFECTIVE", "HIGHLY_EFFECTIVE")
            ],
            key=lambda r: r.effectiveness_score,
            reverse=True,
        )
        self._repo.replace_rankings(
            RankType.MOST_VALUABLE.value,
            _rows_to_ranking(valuable, "MOST_VALUABLE"),
        )

        self._db.commit()

    # ------------------------------------------------------------------
    # Public: GET /control-effectiveness/rankings
    # ------------------------------------------------------------------

    def get_rankings(self) -> RankingsResponse:
        now = _now_iso()

        def _to_items(rank_type: str) -> list[RankingItem]:
            rows = self._repo.get_rankings(rank_type)
            return [
                RankingItem(
                    control_id=r.control_id,
                    rank_position=r.rank_position,
                    effectiveness_score=r.effectiveness_score,
                    effectiveness_level=r.effectiveness_level,
                    effectiveness_risk=r.effectiveness_risk,
                    rank_type=r.rank_type,
                )
                for r in rows
            ]

        return RankingsResponse(
            tenant_id=self._tenant_id,
            top_controls=_to_items(RankType.TOP.value),
            weakest_controls=_to_items(RankType.WEAKEST.value),
            fastest_improving=_to_items(RankType.FASTEST_IMPROVING.value),
            fastest_declining=_to_items(RankType.FASTEST_DECLINING.value),
            highest_risk=_to_items(RankType.HIGHEST_RISK.value),
            most_fragile=_to_items(RankType.MOST_FRAGILE.value),
            most_valuable=_to_items(RankType.MOST_VALUABLE.value),
            generated_at=now,
        )

    # ------------------------------------------------------------------
    # Public: GET /control-effectiveness/executive-dashboard
    # ------------------------------------------------------------------

    def get_executive_dashboard(self) -> ExecutiveDashboardResponse:
        now = _now_iso()
        all_rows = self._ce_repo.list_all_effectiveness()
        total = len(all_rows)

        _empty_rankings: list[RankingItem] = []

        if total == 0:
            return ExecutiveDashboardResponse(
                tenant_id=self._tenant_id,
                total_controls=0,
                average_effectiveness_score=0.0,
                highly_effective_count=0,
                effective_count=0,
                adequate_count=0,
                weak_count=0,
                ineffective_count=0,
                critical_risk_count=0,
                high_risk_count=0,
                critical_priority_count=0,
                high_priority_count=0,
                medium_priority_count=0,
                low_priority_count=0,
                top_positive_signals=[],
                top_negative_signals=[],
                top_recommended_actions=[],
                top_controls=_empty_rankings,
                weakest_controls=_empty_rankings,
                highest_risk_controls=_empty_rankings,
                fastest_improving=_empty_rankings,
                fastest_declining=_empty_rankings,
                generated_at=now,
            )

        avg_score = round(sum(r.effectiveness_score for r in all_rows) / total, 2)

        level_counts: dict[str, int] = {
            k: 0
            for k in (
                "HIGHLY_EFFECTIVE",
                "EFFECTIVE",
                "ADEQUATE",
                "WEAK",
                "INEFFECTIVE",
            )
        }
        for r in all_rows:
            level_counts[r.effectiveness_level] = (
                level_counts.get(r.effectiveness_level, 0) + 1
            )

        critical_risk = sum(1 for r in all_rows if r.effectiveness_risk == "CRITICAL")
        high_risk = sum(1 for r in all_rows if r.effectiveness_risk == "HIGH")

        # Priority distribution
        from services.control_effectiveness_explainability.models import PRIORITY_ORDER

        prio_counts: dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }
        for r in all_rows:
            p = classify_priority(
                r.effectiveness_score,
                r.effectiveness_level,
                r.trend_direction,
                r.forecast_score,
                r.exception_score,
            ).value
            prio_counts[p] = prio_counts.get(p, 0) + 1

        # Aggregate signals across all controls (top 5 most common)
        signal_freq: dict[str, int] = {}
        action_freq: dict[str, int] = {}
        for r in all_rows:
            for rc in compute_root_causes(
                r.verification_score,
                r.freshness_score,
                r.coverage_score,
                r.trend_direction,
                r.exception_score,
                r.evidence_density_score,
                r.governance_health_score,
                r.forecast_score,
            ):
                if rc["impact"] in ("POSITIVE", "NEGATIVE"):
                    key = f"{rc['impact']}:{rc['root_cause_type']}"
                    signal_freq[key] = signal_freq.get(key, 0) + 1
            for act in compute_governance_actions(
                r.verification_score,
                r.freshness_score,
                r.coverage_score,
                r.exception_score,
                r.governance_health_score,
                r.trend_direction,
                r.forecast_score,
            ):
                action_freq[act["action_type"]] = (
                    action_freq.get(act["action_type"], 0) + 1
                )

        top_positive = sorted(
            [k.split(":", 1)[1] for k, _ in sorted(signal_freq.items(), key=lambda x: -x[1]) if k.startswith("POSITIVE:")],
            key=lambda t: -signal_freq.get(f"POSITIVE:{t}", 0),
        )[:5]
        top_negative = sorted(
            [k.split(":", 1)[1] for k, _ in sorted(signal_freq.items(), key=lambda x: -x[1]) if k.startswith("NEGATIVE:")],
            key=lambda t: -signal_freq.get(f"NEGATIVE:{t}", 0),
        )[:5]
        top_actions = sorted(action_freq, key=lambda t: -action_freq[t])[:5]

        # Rankings (use stored rankings if available, else derive on-the-fly)
        stored_top = self._repo.get_rankings(RankType.TOP.value)
        stored_weakest = self._repo.get_rankings(RankType.WEAKEST.value)
        stored_highest_risk = self._repo.get_rankings(RankType.HIGHEST_RISK.value)
        stored_improving = self._repo.get_rankings(RankType.FASTEST_IMPROVING.value)
        stored_declining = self._repo.get_rankings(RankType.FASTEST_DECLINING.value)

        def _stored_to_items(
            rows: list,
        ) -> list[RankingItem]:
            return [
                RankingItem(
                    control_id=r.control_id,
                    rank_position=r.rank_position,
                    effectiveness_score=r.effectiveness_score,
                    effectiveness_level=r.effectiveness_level,
                    effectiveness_risk=r.effectiveness_risk,
                    rank_type=r.rank_type,
                )
                for r in rows
            ][:5]

        def _derive_top() -> list[RankingItem]:
            rows = sorted(all_rows, key=lambda r: r.effectiveness_score, reverse=True)
            return [
                self._ranking_item_from_row(r, "TOP", i + 1)
                for i, r in enumerate(rows[:5])
            ]

        def _derive_weakest() -> list[RankingItem]:
            rows = sorted(all_rows, key=lambda r: r.effectiveness_score)
            return [
                self._ranking_item_from_row(r, "WEAKEST", i + 1)
                for i, r in enumerate(rows[:5])
            ]

        def _derive_highest_risk() -> list[RankingItem]:
            rows = sorted(
                all_rows,
                key=lambda r: (RISK_SEVERITY.get(r.effectiveness_risk, 3), r.effectiveness_score),
            )
            return [
                self._ranking_item_from_row(r, "HIGHEST_RISK", i + 1)
                for i, r in enumerate(rows[:5])
            ]

        def _derive_improving() -> list[RankingItem]:
            with_delta = [r for r in all_rows if r.score_delta_30d is not None]
            rows = sorted(with_delta, key=lambda r: r.score_delta_30d or 0.0, reverse=True)
            return [
                self._ranking_item_from_row(r, "FASTEST_IMPROVING", i + 1)
                for i, r in enumerate(rows[:5])
            ]

        def _derive_declining() -> list[RankingItem]:
            with_delta = [r for r in all_rows if r.score_delta_30d is not None]
            rows = sorted(with_delta, key=lambda r: r.score_delta_30d or 0.0)
            return [
                self._ranking_item_from_row(r, "FASTEST_DECLINING", i + 1)
                for i, r in enumerate(rows[:5])
            ]

        top_items = _stored_to_items(stored_top) if stored_top else _derive_top()
        weakest_items = (
            _stored_to_items(stored_weakest) if stored_weakest else _derive_weakest()
        )
        risk_items = (
            _stored_to_items(stored_highest_risk)
            if stored_highest_risk
            else _derive_highest_risk()
        )
        improving_items = (
            _stored_to_items(stored_improving) if stored_improving else _derive_improving()
        )
        declining_items = (
            _stored_to_items(stored_declining)
            if stored_declining
            else _derive_declining()
        )

        return ExecutiveDashboardResponse(
            tenant_id=self._tenant_id,
            total_controls=total,
            average_effectiveness_score=avg_score,
            highly_effective_count=level_counts["HIGHLY_EFFECTIVE"],
            effective_count=level_counts["EFFECTIVE"],
            adequate_count=level_counts["ADEQUATE"],
            weak_count=level_counts["WEAK"],
            ineffective_count=level_counts["INEFFECTIVE"],
            critical_risk_count=critical_risk,
            high_risk_count=high_risk,
            critical_priority_count=prio_counts["CRITICAL"],
            high_priority_count=prio_counts["HIGH"],
            medium_priority_count=prio_counts["MEDIUM"],
            low_priority_count=prio_counts["LOW"],
            top_positive_signals=top_positive,
            top_negative_signals=top_negative,
            top_recommended_actions=top_actions,
            top_controls=top_items,
            weakest_controls=weakest_items,
            highest_risk_controls=risk_items,
            fastest_improving=improving_items,
            fastest_declining=declining_items,
            generated_at=now,
        )

    # ------------------------------------------------------------------
    # CGIN benchmark-ready snapshot builders
    # ------------------------------------------------------------------

    def build_contribution_snapshot(
        self, control_id: str
    ) -> Optional[ControlContributionSnapshot]:
        row = self._load_row(control_id)
        if row is None:
            return None
        return ControlContributionSnapshot(
            tenant_id=self._tenant_id,
            control_id=control_id,
            effectiveness_score=row.effectiveness_score,
            contributions=self._contributions_from_row(row),
            snapshot_at=_now_iso(),
        )

    def build_risk_snapshot(self, control_id: str) -> Optional[ControlRiskSnapshot]:
        row = self._load_row(control_id)
        if row is None:
            return None
        return ControlRiskSnapshot(
            tenant_id=self._tenant_id,
            control_id=control_id,
            effectiveness_score=row.effectiveness_score,
            effectiveness_level=row.effectiveness_level,
            effectiveness_risk=row.effectiveness_risk,
            governance_priority=self._priority_from_row(row),
            trend_direction=row.trend_direction,
            snapshot_at=_now_iso(),
        )

    def build_action_snapshot(self, control_id: str) -> Optional[ControlActionSnapshot]:
        row = self._load_row(control_id)
        if row is None:
            return None
        return ControlActionSnapshot(
            tenant_id=self._tenant_id,
            control_id=control_id,
            governance_priority=self._priority_from_row(row),
            actions=self._actions_from_row(row),
            snapshot_at=_now_iso(),
        )

    def build_priority_snapshot(
        self, control_id: str
    ) -> Optional[ControlPrioritySnapshot]:
        row = self._load_row(control_id)
        if row is None:
            return None
        return ControlPrioritySnapshot(
            tenant_id=self._tenant_id,
            control_id=control_id,
            governance_priority=self._priority_from_row(row),
            effectiveness_score=row.effectiveness_score,
            effectiveness_level=row.effectiveness_level,
            trend_direction=row.trend_direction,
            snapshot_at=_now_iso(),
        )
