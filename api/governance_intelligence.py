# api/governance_intelligence.py
"""Governance Intelligence Authority API - PR 18.5.

All routes are tenant-scoped except ``/intelligence/health``.
Tenant is resolved from auth context only (never from request body).

Security invariants:
  - ``tenant_id`` always from ``require_bound_tenant(request)``.
  - Every handler calls ``set_tenant_context(db, tenant_id)`` immediately
    after opening the session so RLS is bound before any engine call.
  - No direct ORM access — everything routes through
    ``GovernanceIntelligenceEngine``.
  - Caller (this router) owns ``db.commit()``.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine, set_tenant_context
from services.governance_intelligence.engine import GovernanceIntelligenceEngine
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
    ExternalEventRequest,
    ExternalEventResponse,
    FederationListResponse,
    FederationResponse,
    FederationSyncRequest,
    ForecastListResponse,
    ForecastResponse,
    GovernanceIntelligenceConflict,
    GovernanceIntelligenceNotFound,
    GovernanceIntelligencePolicyError,
    GovernanceIntelligenceSimulationError,
    GovernanceIntelligenceTenantViolation,
    GovernanceIntelligenceValidationError,
    HealthResponse,
    IntelligencePolicyListResponse,
    IntelligencePolicyResponse,
    PolicyDiffResponse,
    PolicyTransitionRequest,
    PolicyVersionListResponse,
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


router = APIRouter(tags=["governance-intelligence"])

_ACTOR_UNKNOWN = "unknown"


def _actor(request: Request) -> str:
    return str(
        getattr(getattr(request, "state", None), "key_prefix", None) or _ACTOR_UNKNOWN
    )


def _map_domain_error(exc: Exception) -> HTTPException:
    if isinstance(exc, GovernanceIntelligenceNotFound):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, GovernanceIntelligenceTenantViolation):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, GovernanceIntelligenceSimulationError):
        return HTTPException(status_code=422, detail=str(exc))
    if isinstance(exc, GovernanceIntelligenceValidationError):
        return HTTPException(status_code=422, detail=str(exc))
    if isinstance(exc, GovernanceIntelligencePolicyError):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, GovernanceIntelligenceConflict):
        return HTTPException(status_code=409, detail=str(exc))
    from services.governance_intelligence.schemas import GovernanceIntelligenceError

    if isinstance(exc, GovernanceIntelligenceError):
        return HTTPException(status_code=500, detail=str(exc))
    return HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Health (public — no auth)
# ---------------------------------------------------------------------------


@router.get(
    "/intelligence/health",
    response_model=HealthResponse,
)
def intelligence_health() -> HealthResponse:
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, "__health__")
        svc = GovernanceIntelligenceEngine(db, tenant_id="__health__")
        return svc.get_health()


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


@router.get(
    "/intelligence/dashboard",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=DashboardResponse,
)
def get_dashboard(request: Request) -> DashboardResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_dashboard()
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/dashboard/executive",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=DashboardResponse,
)
def get_dashboard_executive(request: Request) -> DashboardResponse:
    """Executive summary variant of the intelligence dashboard."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_dashboard()
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/dashboard/auditor",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=DashboardResponse,
)
def get_dashboard_auditor(request: Request) -> DashboardResponse:
    """Auditor workspace view of the intelligence dashboard."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_dashboard()
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Explainability
# ---------------------------------------------------------------------------


@router.get(
    "/intelligence/explainability",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ExplainabilityListResponse,
)
def list_explainability(
    request: Request,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> ExplainabilityListResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_explainability(limit=limit, offset=offset)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/intelligence/explainability",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ExplainabilityResponse,
    status_code=201,
)
def create_explainability(
    body: dict[str, Any],
    request: Request,
) -> ExplainabilityResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_explainability(
                decision_id=body.get("decision_id", ""),
                trigger=body.get("trigger", ""),
                policy_version=body.get("policy_version", "1.0"),
                evaluation=body.get("evaluation", {}),
                decision=body.get("decision", ""),
                authorities_invoked=body.get("authorities_invoked", []),
                expected_impact=body.get("expected_impact", {}),
                actor_id=actor,
            )
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/explainability/{decision_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ExplainabilityResponse,
)
def get_explainability(
    decision_id: str,
    request: Request,
) -> ExplainabilityResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_explainability(decision_id)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/intelligence/explainability/{decision_id}/export",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ExplainabilityResponse,
)
def export_explainability(
    decision_id: str,
    request: Request,
) -> ExplainabilityResponse:
    """Export explanation — returns the same record as GET."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_explainability(decision_id)
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Simulations
# ---------------------------------------------------------------------------


@router.get(
    "/intelligence/simulations",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=SimulationListResponse,
)
def list_simulations(
    request: Request,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> SimulationListResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_simulations(limit=limit, offset=offset)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/intelligence/simulations",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=SimulationResponse,
    status_code=201,
)
def create_simulation(
    req: CreateSimulationRequest, request: Request
) -> SimulationResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_simulation(req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/simulations/{simulation_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=SimulationResponse,
)
def get_simulation(simulation_id: str, request: Request) -> SimulationResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_simulation(simulation_id)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.patch(
    "/intelligence/simulations/{simulation_id}",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=SimulationResponse,
)
def update_simulation(
    simulation_id: str,
    req: UpdateSimulationRequest,
    request: Request,
) -> SimulationResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.update_simulation(simulation_id, req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/intelligence/simulations/{simulation_id}/run",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=SimulationResponse,
)
def run_simulation(
    simulation_id: str,
    req: RunSimulationRequest,
    request: Request,
) -> SimulationResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.run_simulation(simulation_id, req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.delete(
    "/intelligence/simulations/{simulation_id}",
    dependencies=[Depends(require_scopes("governance:write"))],
    status_code=204,
)
def delete_simulation(simulation_id: str, request: Request) -> None:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            svc.delete_simulation(simulation_id, actor_id=actor)
            db.commit()
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/simulations/{simulation_id}/history",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=TimelineResponse,
)
def get_simulation_history(simulation_id: str, request: Request) -> TimelineResponse:
    """Return timeline events for this simulation."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            # Get full timeline filtered to this simulation
            timeline = svc.get_timeline(limit=500, offset=0)
            sim_items = [
                item
                for item in timeline.items
                if item.get("entity_id") == simulation_id
                and item.get("entity_type") == "simulation"
            ]
            return TimelineResponse(items=sim_items, total=len(sim_items))
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/intelligence/simulations/{simulation_id}/archive",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=SimulationResponse,
)
def archive_simulation(simulation_id: str, request: Request) -> SimulationResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.archive_simulation(simulation_id, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Intelligence Policies
# ---------------------------------------------------------------------------


@router.get(
    "/intelligence/policies",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=IntelligencePolicyListResponse,
)
def list_intelligence_policies(
    request: Request,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> IntelligencePolicyListResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_intelligence_policies(limit=limit, offset=offset)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/intelligence/policies",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=IntelligencePolicyResponse,
    status_code=201,
)
def create_intelligence_policy(
    req: CreateIntelligencePolicyRequest, request: Request
) -> IntelligencePolicyResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_intelligence_policy(req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/policies/{policy_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=IntelligencePolicyResponse,
)
def get_intelligence_policy(
    policy_id: str, request: Request
) -> IntelligencePolicyResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_intelligence_policy(policy_id)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.patch(
    "/intelligence/policies/{policy_id}",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=IntelligencePolicyResponse,
)
def update_intelligence_policy(
    policy_id: str,
    req: UpdateIntelligencePolicyRequest,
    request: Request,
) -> IntelligencePolicyResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.update_intelligence_policy(policy_id, req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/intelligence/policies/{policy_id}/transition",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=IntelligencePolicyResponse,
)
def transition_policy(
    policy_id: str,
    req: PolicyTransitionRequest,
    request: Request,
) -> IntelligencePolicyResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.transition_policy(policy_id, req)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/policies/{policy_id}/versions",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PolicyVersionListResponse,
)
def get_policy_versions(policy_id: str, request: Request) -> PolicyVersionListResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_policy_versions(policy_id)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/policies/{policy_id}/diff",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PolicyDiffResponse,
)
def get_policy_diff_by_last_two(policy_id: str, request: Request) -> PolicyDiffResponse:
    """Diff the last two versions of a policy."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            versions = svc.get_policy_versions(policy_id)
            if versions.total < 2:
                raise GovernanceIntelligenceNotFound(  # type: ignore[name-defined]
                    "Not enough versions to diff (need at least 2)"
                )
            items = versions.items
            return svc.get_policy_diff(
                policy_id,
                from_version=items[-2].version,
                to_version=items[-1].version,
            )
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Policy diff (query-param based)
# ---------------------------------------------------------------------------


@router.get(
    "/intelligence/policy-diff",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PolicyDiffResponse,
)
def get_policy_diff(
    request: Request,
    policy_id: str = Query(..., min_length=1),
    from_version: str = Query(..., min_length=1),
    to_version: str = Query(..., min_length=1),
) -> PolicyDiffResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_policy_diff(policy_id, from_version, to_version)
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------


@router.get(
    "/intelligence/benchmarks",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=BenchmarkListResponse,
)
def list_benchmarks(
    request: Request,
    framework: Optional[str] = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> BenchmarkListResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_benchmarks(framework=framework, limit=limit, offset=offset)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/intelligence/benchmarks",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=BenchmarkResponse,
    status_code=201,
)
def create_benchmark(
    req: CreateBenchmarkRequest, request: Request
) -> BenchmarkResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_benchmark(req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/benchmarks/{benchmark_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=BenchmarkResponse,
)
def get_benchmark(benchmark_id: str, request: Request) -> BenchmarkResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_benchmark_by_id(benchmark_id)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.delete(
    "/intelligence/benchmarks/{benchmark_id}",
    dependencies=[Depends(require_scopes("governance:write"))],
    status_code=204,
)
def delete_benchmark(benchmark_id: str, request: Request) -> None:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            svc.delete_benchmark(benchmark_id, actor_id=actor)
            db.commit()
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Trends
# ---------------------------------------------------------------------------


@router.get(
    "/intelligence/trends",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=TrendListResponse,
)
def list_trends(
    request: Request,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> TrendListResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_trends(limit=limit, offset=offset)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/trends/summary",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=TrendListResponse,
)
def get_trends_summary(
    request: Request,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=10, ge=1, le=500),
) -> TrendListResponse:
    """Trend summary across key metrics."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_trends(limit=limit, offset=offset)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/trends/{metric_key}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=TrendResponse,
)
def get_trend(
    metric_key: str,
    request: Request,
    window_days: int = Query(default=30, ge=1, le=365),
) -> TrendResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_trends(metric_key=metric_key, window_days=window_days)
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Forecasts
# ---------------------------------------------------------------------------


@router.get(
    "/intelligence/forecasts",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ForecastListResponse,
)
def list_forecasts(
    request: Request,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> ForecastListResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_forecasts(limit=limit, offset=offset)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/forecasts/summary",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ForecastListResponse,
)
def get_forecasts_summary(
    request: Request,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=10, ge=1, le=500),
) -> ForecastListResponse:
    """Forecast summary across key metrics."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_forecasts(limit=limit, offset=offset)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/forecasts/{metric_key}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ForecastResponse,
)
def get_forecast(
    metric_key: str,
    request: Request,
    horizon: str = Query(default="DAYS_30"),
) -> ForecastResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_forecast(metric_key=metric_key, horizon=horizon)
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Confidence
# ---------------------------------------------------------------------------


@router.get(
    "/intelligence/confidence",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ConfidenceListResponse,
)
def list_confidence(
    request: Request,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> ConfidenceListResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_confidence(limit=limit, offset=offset)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/confidence/summary",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ConfidenceResponse,
)
def get_confidence_summary(request: Request) -> ConfidenceResponse:
    """Return overall confidence across all dimensions."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_confidence("overall")
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/confidence/{dimension}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ConfidenceResponse,
)
def get_confidence(dimension: str, request: Request) -> ConfidenceResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_confidence(dimension)
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# External events
# ---------------------------------------------------------------------------


@router.get(
    "/intelligence/external-events",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ExternalEventListResponse,
)
def list_external_events(
    request: Request,
    event_type: Optional[str] = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> ExternalEventListResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_external_events(
                event_type=event_type, limit=limit, offset=offset
            )
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/intelligence/external-events",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ExternalEventResponse,
    status_code=201,
)
def record_external_event(
    req: ExternalEventRequest, request: Request
) -> ExternalEventResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.record_external_event(req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/external-events/{event_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ExternalEventResponse,
)
def get_external_event(event_id: str, request: Request) -> ExternalEventResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_external_event(event_id)
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Federation
# ---------------------------------------------------------------------------


@router.get(
    "/intelligence/federation",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=FederationListResponse,
)
def list_federation(
    request: Request,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> FederationListResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_federation(limit=limit, offset=offset)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/intelligence/federation",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=FederationResponse,
    status_code=201,
)
def register_federation(
    req: FederationSyncRequest, request: Request
) -> FederationResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.register_federation(req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/federation/{federation_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=FederationResponse,
)
def get_federation(federation_id: str, request: Request) -> FederationResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_federation_by_id(federation_id)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.delete(
    "/intelligence/federation/{federation_id}",
    dependencies=[Depends(require_scopes("governance:write"))],
    status_code=204,
)
def delete_federation(federation_id: str, request: Request) -> None:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            svc.delete_federation(federation_id, actor_id=actor)
            db.commit()
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


@router.get(
    "/intelligence/statistics",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=StatisticsResponse,
)
def get_statistics(request: Request) -> StatisticsResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_statistics()
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------


@router.get(
    "/intelligence/search",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=SearchResponse,
)
def search(
    request: Request,
    q: str = Query(..., min_length=1, max_length=512),
    limit: int = Query(default=50, ge=1, le=500),
) -> SearchResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.search(query=q, limit=limit)
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


@router.get(
    "/intelligence/timeline",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=TimelineResponse,
)
def get_timeline(
    request: Request,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> TimelineResponse:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_timeline(limit=limit, offset=offset)
        except Exception as exc:
            raise _map_domain_error(exc)
