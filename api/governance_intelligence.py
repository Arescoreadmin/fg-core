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

from api.actor_context import ActorContext
from api.auth_dispatch import require_permission
from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine, set_tenant_context
from services.governance_intelligence.engine import GovernanceIntelligenceEngine
from services.governance_intelligence.schemas import (
    BenchmarkConfidenceListResponse,
    BenchmarkConfidenceResponse,
    BenchmarkListResponse,
    BenchmarkResponse,
    CompareSimulationsRequest,
    ComputeBenchmarkConfidenceRequest,
    ComputeEvidenceImpactRequest,
    ComputeQualityScoreRequest,
    ComputeTimelineDiffRequest,
    ConfidenceListResponse,
    ConfidenceResponse,
    CounterfactualListResponse,
    CounterfactualResponse,
    CreateBenchmarkRequest,
    CreateCounterfactualRequest,
    CreateEvidenceMatrixRequest,
    CreateExportRequest,
    CreateIntelligencePolicyRequest,
    CreateProvenanceNodeRequest,
    CreateReplayRequest,
    CreateSimulationRequest,
    DashboardResponse,
    EvidenceImpactResponse,
    EvidenceMatrixListResponse,
    EvidenceMatrixResponse,
    ExplainabilityListResponse,
    ExplainabilityResponse,
    ExportListResponse,
    ExportPackageResponse,
    ExportProvenanceGraphRequest,
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
    ProvenanceGraphResponse,
    ProvenanceNodeListResponse,
    ProvenanceNodeResponse,
    QualityScoreListResponse,
    QualityScoreResponse,
    ReplayListResponse,
    ReplayResponse,
    RunSimulationRequest,
    SearchResponse,
    SimulationComparisonListResponse,
    SimulationComparisonResponse,
    SimulationListResponse,
    SimulationResponse,
    StatisticsResponse,
    TimelineDiffListResponse,
    TimelineDiffResponse,
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
def get_dashboard(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> DashboardResponse:
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
def get_dashboard_executive(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> DashboardResponse:
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
def get_dashboard_auditor(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> DashboardResponse:
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
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
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
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
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
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
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
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
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
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
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
    req: CreateSimulationRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
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
def get_simulation(
    simulation_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> SimulationResponse:
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
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
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
    actor_ctx: ActorContext = Depends(require_permission("scan.trigger")),
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
def delete_simulation(
    simulation_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> None:
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
def get_simulation_history(
    simulation_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> TimelineResponse:
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
def archive_simulation(
    simulation_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> SimulationResponse:
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
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
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
    req: CreateIntelligencePolicyRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
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
    policy_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
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
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
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
    actor_ctx: ActorContext = Depends(require_permission("governance.promote")),
) -> IntelligencePolicyResponse:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.transition_policy(policy_id, req, actor_id=actor)
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/policies/{policy_id}/versions",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PolicyVersionListResponse,
)
def get_policy_versions(
    policy_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> PolicyVersionListResponse:
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
def get_policy_diff_by_last_two(
    policy_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> PolicyDiffResponse:
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
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
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
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
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
    req: CreateBenchmarkRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
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
def get_benchmark(
    benchmark_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> BenchmarkResponse:
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
def delete_benchmark(
    benchmark_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> None:
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
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
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
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
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
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
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
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
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
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
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
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
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
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
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
def get_confidence_summary(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> ConfidenceResponse:
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
def get_confidence(
    dimension: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> ConfidenceResponse:
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
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
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
    req: ExternalEventRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
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
def get_external_event(
    event_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> ExternalEventResponse:
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
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
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
    req: FederationSyncRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("connector.manage")),
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
def get_federation(
    federation_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> FederationResponse:
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
def delete_federation(
    federation_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("connector.manage")),
) -> None:
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
def get_statistics(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> StatisticsResponse:
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
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
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
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
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


# ---------------------------------------------------------------------------
# PR 18.5A — Provenance (27 new routes total in this section)
# ---------------------------------------------------------------------------


@router.get(
    "/intelligence/provenance",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ProvenanceNodeListResponse,
)
def list_provenance_nodes(
    request: Request,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_provenance_nodes(limit=limit, offset=offset)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/intelligence/provenance",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ProvenanceNodeResponse,
    status_code=201,
)
def create_provenance_node(
    body: CreateProvenanceNodeRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_provenance_node(
                node_type=body.node_type,
                authority=body.authority,
                source_object_id=body.source_object_id,
                data=body.data,
                parent_ids=body.parent_ids,
                actor_id=actor,
            )
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/provenance/{node_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ProvenanceNodeResponse,
)
def get_provenance_node(
    node_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_provenance_node(node_id)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/provenance/{node_id}/ancestors",
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_provenance_ancestors(
    node_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return {"items": svc.get_node_ancestors(node_id)}
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/provenance/{node_id}/descendants",
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_provenance_descendants(
    node_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return {"items": svc.get_node_descendants(node_id)}
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/intelligence/provenance/graph",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ProvenanceGraphResponse,
)
def export_provenance_graph(
    body: ExportProvenanceGraphRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.export_provenance_graph(body.node_ids)
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# PR 18.5A — Evidence Matrix
# ---------------------------------------------------------------------------


@router.get(
    "/intelligence/evidence-matrix",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=EvidenceMatrixListResponse,
)
def list_evidence_matrices(
    request: Request,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    actor_ctx: ActorContext = Depends(require_permission("evidence.read")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_evidence_matrices(limit=limit, offset=offset)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/intelligence/evidence-matrix",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=EvidenceMatrixResponse,
    status_code=201,
)
def create_evidence_matrix(
    body: CreateEvidenceMatrixRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("evidence.upload")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_evidence_matrix(
                recommendation_id=body.recommendation_id,
                evidence_ids=body.evidence_ids,
                control_ids=body.control_ids,
                framework_ids=body.framework_ids,
                verification_ids=body.verification_ids,
                trust_refs=body.trust_refs,
                transparency_refs=body.transparency_refs,
                risk_factors=body.risk_factors,
                confidence=body.confidence,
                expected_improvement=body.expected_improvement,
                simulation_ids=body.simulation_ids,
                actor_id=actor,
            )
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/evidence-matrix/{matrix_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=EvidenceMatrixResponse,
)
def get_evidence_matrix(
    matrix_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("evidence.read")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_evidence_matrix(matrix_id)
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# PR 18.5A — Replay
# ---------------------------------------------------------------------------


@router.get(
    "/intelligence/replay",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ReplayListResponse,
)
def list_replays(
    request: Request,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_replays(limit=limit, offset=offset)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/intelligence/replay",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ReplayResponse,
    status_code=201,
)
def create_replay(
    body: CreateReplayRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_replay(
                policy_version=body.policy_version,
                evidence_snapshot=body.evidence_snapshot,
                trust_version=body.trust_version,
                transparency_snapshot=body.transparency_snapshot,
                time_window=body.time_window,
                actor_id=actor,
            )
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/replay/{replay_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ReplayResponse,
)
def get_replay(
    replay_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_replay(replay_id)
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# PR 18.5A — Counterfactual
# ---------------------------------------------------------------------------


@router.get(
    "/intelligence/counterfactual",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=CounterfactualListResponse,
)
def list_counterfactuals(
    request: Request,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_counterfactuals(limit=limit, offset=offset)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/intelligence/counterfactual",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=CounterfactualResponse,
    status_code=201,
)
def create_counterfactual(
    body: CreateCounterfactualRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_counterfactual(
                scenario=body.scenario,
                baseline=body.baseline,
                parameters=body.parameters,
                actor_id=actor,
            )
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/counterfactual/{cf_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=CounterfactualResponse,
)
def get_counterfactual(
    cf_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_counterfactual(cf_id)
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# PR 18.5A — Quality Score
# ---------------------------------------------------------------------------


@router.get(
    "/intelligence/quality-score",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=QualityScoreListResponse,
)
def list_quality_scores(
    request: Request,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_quality_scores(limit=limit, offset=offset)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/intelligence/quality-score",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=QualityScoreResponse,
    status_code=201,
)
def compute_quality_score(
    body: ComputeQualityScoreRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.compute_quality_score(
                entity_id=body.entity_id,
                entity_type=body.entity_type,
                inputs=body.inputs,
                actor_id=actor,
            )
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/quality-score/{entity_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=QualityScoreResponse,
)
def get_quality_score(
    entity_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_quality_score(entity_id)
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# PR 18.5A — Benchmark Confidence
# ---------------------------------------------------------------------------


@router.get(
    "/intelligence/benchmark-confidence",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=BenchmarkConfidenceListResponse,
)
def list_benchmark_confidence(
    request: Request,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_benchmark_confidence(limit=limit, offset=offset)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/intelligence/benchmark-confidence",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=BenchmarkConfidenceResponse,
    status_code=201,
)
def compute_benchmark_confidence(
    body: ComputeBenchmarkConfidenceRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.compute_benchmark_confidence_for_metric(
                metric_key=body.metric_key,
                values=body.values,
                cohort_size=body.cohort_size,
                data_recency_days=body.data_recency_days,
                actor_id=actor,
            )
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# PR 18.5A — Timeline Diff
# ---------------------------------------------------------------------------


@router.post(
    "/intelligence/timeline-diff",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=TimelineDiffResponse,
    status_code=201,
)
def compute_timeline_diff(
    body: ComputeTimelineDiffRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.compute_timeline_diff(
                period_a=body.period_a,
                period_b=body.period_b,
                window=body.window,
                actor_id=actor,
            )
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/timeline-diff",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=TimelineDiffListResponse,
)
def list_timeline_diffs(
    request: Request,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_timeline_diffs(limit=limit, offset=offset)
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# PR 18.5A — Simulation Compare
# ---------------------------------------------------------------------------


@router.post(
    "/intelligence/simulation-compare",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=SimulationComparisonResponse,
    status_code=201,
)
def compare_simulations(
    body: CompareSimulationsRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("governance.decision")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.compare_simulations_by_id(
                baseline_id=body.baseline_id,
                proposed_id=body.proposed_id,
                actor_id=actor,
            )
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


@router.get(
    "/intelligence/simulation-compare",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=SimulationComparisonListResponse,
)
def list_simulation_comparisons(
    request: Request,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    actor_ctx: ActorContext = Depends(require_permission("governance.read")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_simulation_comparisons(limit=limit, offset=offset)
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# PR 18.5A — Evidence Impact
# ---------------------------------------------------------------------------


@router.post(
    "/intelligence/evidence-impact",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=EvidenceImpactResponse,
    status_code=201,
)
def compute_evidence_impact(
    body: ComputeEvidenceImpactRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("evidence.upload")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.compute_evidence_impact(
                evidence_id=body.evidence_id,
                evidence_data=body.evidence_data,
                downstream_data=body.downstream_data,
                actor_id=actor,
            )
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)


# ---------------------------------------------------------------------------
# PR 18.5A — Export
# ---------------------------------------------------------------------------


@router.get(
    "/intelligence/export",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ExportListResponse,
)
def list_exports(
    request: Request,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    actor_ctx: ActorContext = Depends(require_permission("bundle.read")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            return svc.list_exports(limit=limit, offset=offset)
        except Exception as exc:
            raise _map_domain_error(exc)


@router.post(
    "/intelligence/export",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=ExportPackageResponse,
    status_code=201,
)
def create_export(
    body: CreateExportRequest,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("report.generate")),
) -> Any:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        set_tenant_context(db, tenant_id)
        svc = GovernanceIntelligenceEngine(db, tenant_id=tenant_id)
        try:
            result = svc.create_export_package(
                node_ids=body.node_ids,
                export_format=body.export_format,
                actor_id=actor,
            )
            db.commit()
            return result
        except Exception as exc:
            raise _map_domain_error(exc)
