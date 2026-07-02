"""Engine for the Governance Intelligence Authority (PR 18.5).

Constructor takes (db: Session, tenant_id: str). Never commits — caller owns commit.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from services.governance_intelligence.benchmarking import (
    anonymize_benchmark,
    assign_tier,
    compute_percentile,
)
from services.governance_intelligence.confidence import (
    build_confidence_response,
    compute_overall_confidence,
)
from services.governance_intelligence.forecasting import build_forecast_response
from services.governance_intelligence.health import build_health
from services.governance_intelligence.models import (
    GOVERNANCE_INTELLIGENCE_SCHEMA_VERSION,
    SimulationState,
    TERMINAL_SIMULATION_STATES,
)
from services.governance_intelligence.policy_diff import (
    compute_governance_impact,
    diff_policy_data,
)
from services.governance_intelligence.policy_lifecycle import (
    is_mutable,
    validate_transition,
)
from services.governance_intelligence.repository import GovernanceIntelligenceRepository
from services.governance_intelligence.schemas import (
    BenchmarkListResponse,
    BenchmarkResponse,
    ConfidenceListResponse,
    ConfidenceResponse,
    CreateBenchmarkRequest,
    CreateIntelligencePolicyRequest,
    CreateSimulationRequest,
    DashboardResponse,
    ExplainabilityListResponse,
    ExplainabilityResponse,
    ExternalEventListResponse,
    ExternalEventResponse,
    ExternalEventRequest,
    FederationListResponse,
    FederationResponse,
    FederationSyncRequest,
    ForecastListResponse,
    ForecastResponse,
    GovernanceIntelligenceConflict,
    GovernanceIntelligenceNotFound,
    GovernanceIntelligencePolicyError,
    GovernanceIntelligenceSimulationError,
    GovernanceIntelligenceValidationError,
    HealthResponse,
    IntelligencePolicyListResponse,
    IntelligencePolicyResponse,
    PolicyDiffResponse,
    PolicyTransitionRequest,
    PolicyVersionListResponse,
    PolicyVersionResponse,
    RunSimulationRequest,
    SearchResponse,
    SimulationListResponse,
    SimulationResponse,
    StatisticsResponse,
    TimelineResponse,
    TrendListResponse,
    TrendResponse,
    UpdateIntelligencePolicyRequest,
    UpdateSimulationRequest,
)
from services.governance_intelligence.simulation import run_simulation as _run_sim
from services.governance_intelligence.timeline import build_timeline_event
from services.governance_intelligence.trend_analysis import build_trend_response
from services.canonical import utc_iso8601_z_now


def _loads(value: str | None) -> Any:
    if value is None:
        return {}
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return {}


def _loads_list(value: str | None) -> list[Any]:
    result = _loads(value)
    return result if isinstance(result, list) else []


class GovernanceIntelligenceEngine:
    """Business logic engine for the Governance Intelligence Authority."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id
        self._repo = GovernanceIntelligenceRepository(db, tenant_id)

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def get_health(self) -> HealthResponse:
        data = build_health(self._db, self._tenant_id)
        return HealthResponse(**data)

    def health(self) -> HealthResponse:
        return self.get_health()

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    def get_dashboard(self) -> DashboardResponse:
        total_sims = self._repo.count_simulations()
        active_sims = self._repo.count_simulations_by_state(SimulationState.RUNNING.value)
        total_policies = self._repo.count_policies()
        total_benchmarks = self._repo.count_benchmarks()

        # Simple governance score placeholder based on available data
        governance_score = round(
            min(1.0, (total_policies * 0.1 + total_benchmarks * 0.05)), 3
        )
        risk_level = "LOW" if governance_score >= 0.7 else "MEDIUM" if governance_score >= 0.4 else "HIGH"

        confidence = build_confidence_response(
            "dashboard",
            {
                "policy_coverage": min(1.0, total_policies * 0.1),
                "benchmark_coverage": min(1.0, total_benchmarks * 0.05),
            },
        )

        return DashboardResponse(
            tenant_id=self._tenant_id,
            governance_score=governance_score,
            risk_level=risk_level,
            trend="STABLE",
            top_findings=[],
            active_simulations=active_sims,
            benchmark_tier=None,
            confidence=confidence,
            generated_at=utc_iso8601_z_now(),
        )

    # ------------------------------------------------------------------
    # Simulations
    # ------------------------------------------------------------------

    def _row_to_simulation(self, row: Any) -> SimulationResponse:
        return SimulationResponse(
            id=row.id,
            tenant_id=row.tenant_id,
            name=row.name,
            description=row.description,
            scenario_type=row.scenario_type,
            parameters=_loads(row.parameters),
            state=row.state,
            result=_loads(row.result) if row.result else None,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    def create_simulation(
        self, req: CreateSimulationRequest, actor_id: str
    ) -> SimulationResponse:
        row = self._repo.create_simulation(
            name=req.name,
            description=req.description,
            scenario_type=req.scenario_type,
            parameters=req.parameters,
            state=SimulationState.DRAFT.value,
        )
        self._repo.append_simulation_history(
            simulation_id=row.id,
            state=SimulationState.DRAFT.value,
            actor_id=actor_id,
            data={"action": "created"},
        )
        self._repo.append_timeline(
            event_type="simulation.created",
            entity_id=row.id,
            entity_type="simulation",
            actor_id=actor_id,
            data={"name": req.name, "scenario_type": req.scenario_type},
        )
        return self._row_to_simulation(row)

    def get_simulation(self, simulation_id: str) -> SimulationResponse:
        row = self._repo.get_simulation(simulation_id)
        if row is None:
            raise GovernanceIntelligenceNotFound(
                f"Simulation '{simulation_id}' not found"
            )
        return self._row_to_simulation(row)

    def list_simulations(self, limit: int, offset: int) -> SimulationListResponse:
        items, total = self._repo.list_simulations(limit=limit, offset=offset)
        return SimulationListResponse(
            items=[self._row_to_simulation(r) for r in items],
            total=total,
        )

    def update_simulation(
        self,
        simulation_id: str,
        req: UpdateSimulationRequest,
        actor_id: str,
    ) -> SimulationResponse:
        row = self._repo.get_simulation(simulation_id)
        if row is None:
            raise GovernanceIntelligenceNotFound(
                f"Simulation '{simulation_id}' not found"
            )
        if SimulationState(row.state) in TERMINAL_SIMULATION_STATES:
            raise GovernanceIntelligenceSimulationError(
                f"Cannot update simulation in terminal state '{row.state}'"
            )
        if req.name is not None:
            row.name = req.name
        if req.description is not None:
            row.description = req.description
        if req.parameters is not None:
            row.parameters = json.dumps(req.parameters, sort_keys=True)
        self._repo.update_simulation(row)
        self._repo.append_simulation_history(
            simulation_id=row.id,
            state=row.state,
            actor_id=actor_id,
            data={"action": "updated"},
        )
        return self._row_to_simulation(row)

    def run_simulation(
        self,
        simulation_id: str,
        req: RunSimulationRequest,
        actor_id: str,
    ) -> SimulationResponse:
        row = self._repo.get_simulation(simulation_id)
        if row is None:
            raise GovernanceIntelligenceNotFound(
                f"Simulation '{simulation_id}' not found"
            )
        if SimulationState(row.state) in TERMINAL_SIMULATION_STATES:
            raise GovernanceIntelligenceSimulationError(
                f"Cannot run simulation in terminal state '{row.state}'"
            )

        try:
            params = _loads(row.parameters)
            result = _run_sim(row.scenario_type, params)
            if not req.dry_run:
                row.state = SimulationState.COMPLETE.value
                row.result = json.dumps(result, sort_keys=True)
                self._repo.update_simulation(row)
                self._repo.append_simulation_history(
                    simulation_id=row.id,
                    state=SimulationState.COMPLETE.value,
                    actor_id=actor_id,
                    data={"action": "run", "dry_run": False},
                )
        except GovernanceIntelligenceSimulationError:
            row.state = SimulationState.FAILED.value
            self._repo.update_simulation(row)
            self._repo.append_simulation_history(
                simulation_id=row.id,
                state=SimulationState.FAILED.value,
                actor_id=actor_id,
                data={"action": "run_failed"},
            )
            raise

        return self._row_to_simulation(row)

    def delete_simulation(self, simulation_id: str, actor_id: str) -> None:
        row = self._repo.get_simulation(simulation_id)
        if row is None:
            raise GovernanceIntelligenceNotFound(
                f"Simulation '{simulation_id}' not found"
            )
        self._repo.append_timeline(
            event_type="simulation.deleted",
            entity_id=simulation_id,
            entity_type="simulation",
            actor_id=actor_id,
            data={"name": row.name},
        )
        self._repo.delete_simulation(row)

    def archive_simulation(self, simulation_id: str, actor_id: str) -> SimulationResponse:
        row = self._repo.get_simulation(simulation_id)
        if row is None:
            raise GovernanceIntelligenceNotFound(
                f"Simulation '{simulation_id}' not found"
            )
        if row.state == SimulationState.ARCHIVED.value:
            raise GovernanceIntelligenceSimulationError(
                "Simulation is already archived"
            )
        row.state = SimulationState.ARCHIVED.value
        self._repo.update_simulation(row)
        self._repo.append_simulation_history(
            simulation_id=row.id,
            state=SimulationState.ARCHIVED.value,
            actor_id=actor_id,
            data={"action": "archived"},
        )
        return self._row_to_simulation(row)

    # ------------------------------------------------------------------
    # Explainability
    # ------------------------------------------------------------------

    def _row_to_explainability(self, row: Any) -> ExplainabilityResponse:
        return ExplainabilityResponse(
            id=row.id,
            tenant_id=row.tenant_id,
            decision_id=row.decision_id,
            trigger=row.trigger,
            policy_version=row.policy_version,
            evaluation=_loads(row.evaluation),
            decision=row.decision,
            authorities_invoked=_loads_list(row.authorities_invoked),
            expected_impact=_loads(row.expected_impact),
            observed_impact=_loads(row.observed_impact) if row.observed_impact else None,
            created_at=row.created_at,
        )

    def get_explainability(self, decision_id: str) -> ExplainabilityResponse:
        row = self._repo.get_explainability_by_decision(decision_id)
        if row is None:
            raise GovernanceIntelligenceNotFound(
                f"Explainability record for decision '{decision_id}' not found"
            )
        return self._row_to_explainability(row)

    def list_explainability(
        self, limit: int, offset: int
    ) -> ExplainabilityListResponse:
        items, total = self._repo.list_explainability(limit=limit, offset=offset)
        return ExplainabilityListResponse(
            items=[self._row_to_explainability(r) for r in items],
            total=total,
        )

    def create_explainability(
        self,
        decision_id: str,
        trigger: str,
        policy_version: str,
        evaluation: dict[str, Any],
        decision: str,
        authorities_invoked: list[str],
        expected_impact: dict[str, Any],
        actor_id: str,
    ) -> ExplainabilityResponse:
        row = self._repo.create_explainability(
            decision_id=decision_id,
            trigger=trigger,
            policy_version=policy_version,
            evaluation=evaluation,
            decision=decision,
            authorities_invoked=authorities_invoked,
            expected_impact=expected_impact,
        )
        self._repo.append_timeline(
            event_type="explainability.created",
            entity_id=decision_id,
            entity_type="explainability",
            actor_id=actor_id,
            data={"decision": decision, "trigger": trigger},
        )
        return self._row_to_explainability(row)

    # ------------------------------------------------------------------
    # Intelligence Policies
    # ------------------------------------------------------------------

    def _row_to_policy(self, row: Any) -> IntelligencePolicyResponse:
        return IntelligencePolicyResponse(
            id=row.id,
            tenant_id=row.tenant_id,
            name=row.name,
            description=row.description,
            policy_type=row.policy_type,
            policy_data=_loads(row.policy_data),
            framework=row.framework,
            lifecycle_state=row.lifecycle_state,
            version=row.version,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    def create_intelligence_policy(
        self, req: CreateIntelligencePolicyRequest, actor_id: str
    ) -> IntelligencePolicyResponse:
        row = self._repo.create_policy(
            name=req.name,
            description=req.description,
            policy_type=req.policy_type,
            policy_data=req.policy_data,
            framework=req.framework,
            lifecycle_state="DRAFT",
            version="1.0",
        )
        self._repo.append_policy_version(
            policy_id=row.id,
            version="1.0",
            policy_data=req.policy_data,
            changed_by=actor_id,
        )
        self._repo.append_timeline(
            event_type="policy.created",
            entity_id=row.id,
            entity_type="policy",
            actor_id=actor_id,
            data={"name": req.name, "policy_type": req.policy_type},
        )
        return self._row_to_policy(row)

    def get_intelligence_policy(self, policy_id: str) -> IntelligencePolicyResponse:
        row = self._repo.get_policy(policy_id)
        if row is None:
            raise GovernanceIntelligenceNotFound(
                f"Policy '{policy_id}' not found"
            )
        return self._row_to_policy(row)

    def list_intelligence_policies(
        self, limit: int, offset: int
    ) -> IntelligencePolicyListResponse:
        items, total = self._repo.list_policies(limit=limit, offset=offset)
        return IntelligencePolicyListResponse(
            items=[self._row_to_policy(r) for r in items],
            total=total,
        )

    def update_intelligence_policy(
        self,
        policy_id: str,
        req: UpdateIntelligencePolicyRequest,
        actor_id: str,
    ) -> IntelligencePolicyResponse:
        row = self._repo.get_policy(policy_id)
        if row is None:
            raise GovernanceIntelligenceNotFound(
                f"Policy '{policy_id}' not found"
            )
        if not is_mutable(row.lifecycle_state):
            raise GovernanceIntelligencePolicyError(
                f"Policy in state '{row.lifecycle_state}' is not editable"
            )
        if req.name is not None:
            row.name = req.name
        if req.description is not None:
            row.description = req.description
        if req.policy_data is not None:
            # Bump version
            parts = row.version.split(".")
            try:
                minor = int(parts[-1]) + 1
            except (ValueError, IndexError):
                minor = 1
            new_version = ".".join(parts[:-1] + [str(minor)]) if len(parts) > 1 else f"1.{minor}"
            row.version = new_version
            row.policy_data = json.dumps(req.policy_data, sort_keys=True)
            self._repo.append_policy_version(
                policy_id=row.id,
                version=new_version,
                policy_data=req.policy_data,
                changed_by=actor_id,
            )
        self._repo.update_policy(row)
        return self._row_to_policy(row)

    def transition_policy(
        self, policy_id: str, req: PolicyTransitionRequest
    ) -> IntelligencePolicyResponse:
        row = self._repo.get_policy(policy_id)
        if row is None:
            raise GovernanceIntelligenceNotFound(
                f"Policy '{policy_id}' not found"
            )
        validate_transition(row.lifecycle_state, req.target_state)
        row.lifecycle_state = req.target_state
        self._repo.update_policy(row)
        self._repo.append_timeline(
            event_type="policy.transitioned",
            entity_id=row.id,
            entity_type="policy",
            actor_id=req.actor_id,
            data={
                "from_state": row.lifecycle_state,
                "to_state": req.target_state,
                "reason": req.reason,
            },
        )
        return self._row_to_policy(row)

    def get_policy_versions(self, policy_id: str) -> PolicyVersionListResponse:
        row = self._repo.get_policy(policy_id)
        if row is None:
            raise GovernanceIntelligenceNotFound(
                f"Policy '{policy_id}' not found"
            )
        versions = self._repo.list_policy_versions(policy_id)
        return PolicyVersionListResponse(
            items=[
                PolicyVersionResponse(
                    id=v.id,
                    policy_id=v.policy_id,
                    version=v.version,
                    policy_data=_loads(v.policy_data),
                    changed_by=v.changed_by,
                    created_at=v.created_at,
                )
                for v in versions
            ],
            total=len(versions),
        )

    def get_policy_diff(
        self, policy_id: str, from_version: str, to_version: str
    ) -> PolicyDiffResponse:
        row = self._repo.get_policy(policy_id)
        if row is None:
            raise GovernanceIntelligenceNotFound(
                f"Policy '{policy_id}' not found"
            )
        versions = self._repo.list_policy_versions(policy_id)
        version_map = {v.version: _loads(v.policy_data) for v in versions}

        if from_version not in version_map:
            raise GovernanceIntelligenceNotFound(
                f"Policy version '{from_version}' not found"
            )
        if to_version not in version_map:
            raise GovernanceIntelligenceNotFound(
                f"Policy version '{to_version}' not found"
            )

        old_data = version_map[from_version]
        new_data = version_map[to_version]
        diff = diff_policy_data(old_data, new_data)
        impact = compute_governance_impact(diff)

        return PolicyDiffResponse(
            policy_id=policy_id,
            from_version=from_version,
            to_version=to_version,
            added_rules=diff["added_rules"],
            removed_rules=diff["removed_rules"],
            threshold_changes=diff["threshold_changes"],
            approval_changes=diff["approval_changes"],
            governance_impact=impact,
        )

    # ------------------------------------------------------------------
    # Benchmarks
    # ------------------------------------------------------------------

    def _row_to_benchmark(self, row: Any) -> BenchmarkResponse:
        return BenchmarkResponse(
            id=row.id,
            tenant_id=row.tenant_id,
            framework=row.framework,
            category=row.category,
            metric_key=row.metric_key,
            value=row.value,
            percentile=row.percentile,
            tier=row.tier,
            metadata=_loads(row.metadata),
            created_at=row.created_at,
        )

    def create_benchmark(
        self, req: CreateBenchmarkRequest, actor_id: str
    ) -> BenchmarkResponse:
        # Compute percentile and tier from existing benchmarks for this metric
        existing, _ = self._repo.list_benchmarks(limit=500, offset=0)
        existing_values = [r.value for r in existing if r.metric_key == req.metric_key]
        pct = compute_percentile(existing_values, req.value) if existing_values else None
        tier = assign_tier(pct) if pct is not None else None

        row = self._repo.create_benchmark(
            framework=req.framework,
            category=req.category,
            metric_key=req.metric_key,
            value=req.value,
            percentile=pct,
            tier=tier,
            metadata=req.metadata,
        )
        self._repo.append_timeline(
            event_type="benchmark.created",
            entity_id=row.id,
            entity_type="benchmark",
            actor_id=actor_id,
            data={"metric_key": req.metric_key, "value": req.value},
        )
        return self._row_to_benchmark(row)

    def list_benchmarks(
        self,
        framework: str | None,
        limit: int,
        offset: int,
    ) -> BenchmarkListResponse:
        items, total = self._repo.list_benchmarks(
            framework=framework, limit=limit, offset=offset
        )
        return BenchmarkListResponse(
            items=[self._row_to_benchmark(r) for r in items],
            total=total,
        )

    def get_benchmark_by_id(self, benchmark_id: str) -> BenchmarkResponse:
        row = self._repo.get_benchmark(benchmark_id)
        if row is None:
            raise GovernanceIntelligenceNotFound(
                f"Benchmark '{benchmark_id}' not found"
            )
        return self._row_to_benchmark(row)

    def delete_benchmark(self, benchmark_id: str, actor_id: str) -> None:
        row = self._repo.get_benchmark(benchmark_id)
        if row is None:
            raise GovernanceIntelligenceNotFound(
                f"Benchmark '{benchmark_id}' not found"
            )
        self._repo.append_timeline(
            event_type="benchmark.deleted",
            entity_id=benchmark_id,
            entity_type="benchmark",
            actor_id=actor_id,
            data={"metric_key": row.metric_key},
        )
        self._repo.delete_benchmark(row)

    # ------------------------------------------------------------------
    # Trends
    # ------------------------------------------------------------------

    def get_trends(self, metric_key: str, window_days: int) -> TrendResponse:
        benchmarks, _ = self._repo.list_benchmarks(limit=500, offset=0)
        data_points = [
            {"value": r.value, "created_at": r.created_at}
            for r in benchmarks
            if r.metric_key == metric_key
        ]
        trend_data = build_trend_response(metric_key, data_points, window_days)
        return TrendResponse(**trend_data)

    def list_trends(self, limit: int, offset: int) -> TrendListResponse:
        benchmarks, _ = self._repo.list_benchmarks(limit=500, offset=0)
        # Group by metric_key
        by_metric: dict[str, list[dict[str, Any]]] = {}
        for row in benchmarks:
            key = row.metric_key
            if key not in by_metric:
                by_metric[key] = []
            by_metric[key].append({"value": row.value, "created_at": row.created_at})

        all_trends = [
            TrendResponse(**build_trend_response(k, pts, 30))
            for k, pts in sorted(by_metric.items())
        ]
        total = len(all_trends)
        sliced = all_trends[offset : offset + limit]
        return TrendListResponse(items=sliced, total=total)

    # ------------------------------------------------------------------
    # Forecasts
    # ------------------------------------------------------------------

    def get_forecast(self, metric_key: str, horizon: str) -> ForecastResponse:
        benchmarks, _ = self._repo.list_benchmarks(limit=500, offset=0)
        historical = [r.value for r in benchmarks if r.metric_key == metric_key]
        forecast_data = build_forecast_response(metric_key, historical, horizon)
        return ForecastResponse(
            metric_key=forecast_data["metric_key"],
            horizon=forecast_data["horizon"],
            projected_values=forecast_data["projected_values"],
            confidence_level=forecast_data["confidence_level"],
            model_type=forecast_data["model_type"],
            computed_at=forecast_data["computed_at"],
        )

    def list_forecasts(self, limit: int, offset: int) -> ForecastListResponse:
        benchmarks, _ = self._repo.list_benchmarks(limit=500, offset=0)
        by_metric: dict[str, list[float]] = {}
        for row in benchmarks:
            key = row.metric_key
            if key not in by_metric:
                by_metric[key] = []
            by_metric[key].append(row.value)

        all_forecasts = [
            self.get_forecast(k, "DAYS_30")
            for k in sorted(by_metric.keys())
        ]
        total = len(all_forecasts)
        sliced = all_forecasts[offset : offset + limit]
        return ForecastListResponse(items=sliced, total=total)

    # ------------------------------------------------------------------
    # Confidence
    # ------------------------------------------------------------------

    def get_confidence(self, dimension: str) -> ConfidenceResponse:
        row = self._repo.get_latest_confidence(dimension)
        if row is not None:
            return ConfidenceResponse(
                dimension=row.dimension,
                score=row.score,
                level=row.level,
                factors=_loads(row.factors),
                computed_at=row.computed_at,
            )
        # Compute on demand
        resp = build_confidence_response(dimension, {"data_coverage": 0.0})
        return ConfidenceResponse(**resp)

    def list_confidence(self, limit: int, offset: int) -> ConfidenceListResponse:
        items, total = self._repo.list_confidence_history(limit=limit, offset=offset)
        return ConfidenceListResponse(
            items=[
                ConfidenceResponse(
                    dimension=r.dimension,
                    score=r.score,
                    level=r.level,
                    factors=_loads(r.factors),
                    computed_at=r.computed_at,
                )
                for r in items
            ],
            total=total,
        )

    # ------------------------------------------------------------------
    # External events
    # ------------------------------------------------------------------

    def _row_to_external_event(self, row: Any) -> ExternalEventResponse:
        return ExternalEventResponse(
            id=row.id,
            tenant_id=row.tenant_id,
            event_type=row.event_type,
            source=row.source,
            payload=_loads(row.payload),
            occurred_at=row.occurred_at,
            created_at=row.created_at,
        )

    def record_external_event(
        self, req: ExternalEventRequest, actor_id: str
    ) -> ExternalEventResponse:
        row = self._repo.append_external_event(
            event_type=req.event_type,
            source=req.source,
            payload=req.payload,
            occurred_at=req.occurred_at,
        )
        self._repo.append_timeline(
            event_type="external_event.recorded",
            entity_id=row.id,
            entity_type="external_event",
            actor_id=actor_id,
            data={"event_type": req.event_type, "source": req.source},
        )
        return self._row_to_external_event(row)

    def list_external_events(
        self, event_type: str | None, limit: int, offset: int
    ) -> ExternalEventListResponse:
        items, total = self._repo.list_external_events(
            event_type=event_type, limit=limit, offset=offset
        )
        return ExternalEventListResponse(
            items=[self._row_to_external_event(r) for r in items],
            total=total,
        )

    def get_external_event(self, event_id: str) -> ExternalEventResponse:
        row = self._repo.get_external_event(event_id)
        if row is None:
            raise GovernanceIntelligenceNotFound(
                f"External event '{event_id}' not found"
            )
        return self._row_to_external_event(row)

    # ------------------------------------------------------------------
    # Federation
    # ------------------------------------------------------------------

    def _row_to_federation(self, row: Any) -> FederationResponse:
        return FederationResponse(
            id=row.id,
            tenant_id=row.tenant_id,
            instance_id=row.instance_id,
            role=row.role,
            metadata=_loads(row.metadata),
            last_sync_at=row.last_sync_at,
            created_at=row.created_at,
        )

    def register_federation(
        self, req: FederationSyncRequest, actor_id: str
    ) -> FederationResponse:
        row = self._repo.create_federation(
            instance_id=req.instance_id,
            role=req.role,
            metadata=req.metadata,
        )
        self._repo.append_timeline(
            event_type="federation.registered",
            entity_id=row.id,
            entity_type="federation",
            actor_id=actor_id,
            data={"instance_id": req.instance_id, "role": req.role},
        )
        return self._row_to_federation(row)

    def list_federation(self, limit: int, offset: int) -> FederationListResponse:
        items, total = self._repo.list_federation(limit=limit, offset=offset)
        return FederationListResponse(
            items=[self._row_to_federation(r) for r in items],
            total=total,
        )

    def get_federation_by_id(self, federation_id: str) -> FederationResponse:
        row = self._repo.get_federation(federation_id)
        if row is None:
            raise GovernanceIntelligenceNotFound(
                f"Federation record '{federation_id}' not found"
            )
        return self._row_to_federation(row)

    def delete_federation(self, federation_id: str, actor_id: str) -> None:
        row = self._repo.get_federation(federation_id)
        if row is None:
            raise GovernanceIntelligenceNotFound(
                f"Federation record '{federation_id}' not found"
            )
        self._repo.append_timeline(
            event_type="federation.removed",
            entity_id=federation_id,
            entity_type="federation",
            actor_id=actor_id,
            data={"instance_id": row.instance_id},
        )
        self._repo.delete_federation(row)

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def search(self, query: str, limit: int) -> SearchResponse:
        q = query.lower().strip()
        results: list[dict[str, Any]] = []

        # Search simulations
        sims, _ = self._repo.list_simulations(limit=200, offset=0)
        for row in sims:
            if q in row.name.lower() or (row.description and q in row.description.lower()):
                results.append(
                    {
                        "type": "simulation",
                        "id": row.id,
                        "name": row.name,
                        "state": row.state,
                        "created_at": row.created_at,
                    }
                )

        # Search policies
        policies, _ = self._repo.list_policies(limit=200, offset=0)
        for policy_row in policies:
            if q in policy_row.name.lower() or (policy_row.description and q in policy_row.description.lower()):
                results.append(
                    {
                        "type": "policy",
                        "id": policy_row.id,
                        "name": policy_row.name,
                        "lifecycle_state": policy_row.lifecycle_state,
                        "created_at": policy_row.created_at,
                    }
                )

        results = results[:limit]
        return SearchResponse(results=results, total=len(results), query=query)

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_statistics(self) -> StatisticsResponse:
        return StatisticsResponse(
            tenant_id=self._tenant_id,
            total_simulations=self._repo.count_simulations(),
            total_policies=self._repo.count_policies(),
            total_benchmarks=self._repo.count_benchmarks(),
            total_external_events=self._repo.count_external_events(),
            computed_at=utc_iso8601_z_now(),
        )

    # ------------------------------------------------------------------
    # Timeline
    # ------------------------------------------------------------------

    def get_timeline(self, limit: int, offset: int) -> TimelineResponse:
        items, total = self._repo.list_timeline(limit=limit, offset=offset)
        return TimelineResponse(
            items=[
                {
                    "id": r.id,
                    "event_type": r.event_type,
                    "entity_id": r.entity_id,
                    "entity_type": r.entity_type,
                    "actor_id": r.actor_id,
                    "data": _loads(r.data),
                    "created_at": r.created_at,
                }
                for r in items
            ],
            total=total,
        )
