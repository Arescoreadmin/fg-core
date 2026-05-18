"""Readiness Simulation API — deterministic governance scenario simulation endpoints.

Scope contract:
  POST /control-plane/readiness/simulation/runs requires control-plane:write
      (simulations create stored records — that is a write, not a read).
  GET  routes require control-plane:read.

Tenant isolation: tenant_id is always resolved from auth context, never from request body.

Routes:
  POST /control-plane/readiness/simulation/runs  [control-plane:write]
      Submit a simulation scenario (idempotent by simulation_id).
      Request body: SimulationRunRequest with scenario_type, scenario_parameters, etc.

  GET  /control-plane/readiness/simulation/runs  [control-plane:read]
      List simulation runs for the authenticated tenant. Supports scenario_type filter.

  GET  /control-plane/readiness/simulation/runs/{run_id}  [control-plane:read]
      Retrieve a single simulation run by its deterministic run_id.

Security invariants:
  - tenant_id resolved from auth context only — never from request body/query.
  - No secrets, credentials, raw evidence bodies, vectors, prompts, or PHI in responses.
  - All simulation runs are tenant-scoped; cross-tenant access returns 404.
  - projection_json stored internally; API exposes deserialized export-safe dict.
  - simulation_id IS the run_id stored in the DB (idempotency key).
  - Actor identity (created_by_actor_id, request_id, trace_id) persisted for audit lineage.
  - input_hash, projection_hash, contract_hash persisted for regulator-grade replay evidence.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.auth_scopes import require_scopes
from api.deps import auth_ctx_db_session
from api.error_contracts import api_error
from services.readiness.simulation import (
    SimulationEngine,
    SimulationRunNotFound,
    SimulationRunStore,
    SimulationRunTenantIsolationError,
    derive_simulation_id,
)
from services.readiness.simulation.models import SimulationInput, SimulationScenarioType
from services.readiness.simulation.serialization import (
    projection_from_json,
    projection_to_json,
)

logger = logging.getLogger("frostgate.api.readiness_simulation")

router = APIRouter(tags=["readiness"])

_sim_engine = SimulationEngine()
_simulation_store = SimulationRunStore()

SIMULATION_CONTRACT_VERSION = "1.0"
SIMULATION_ENGINE_VERSION = "1.0"


def _tenant_from_auth(request: Request) -> Optional[str]:
    auth = getattr(request.state, "auth", None) or getattr(
        request.state, "api_key", None
    )
    return getattr(getattr(request, "state", None), "tenant_id", None) or getattr(
        auth, "tenant_id", None
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class SimulationRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_type: str = Field(..., description="Scenario type to simulate.")
    scenario_parameters: dict[str, str] = Field(
        default_factory=dict,
        description="Scenario-specific parameters as key-value string pairs.",
    )
    assessment_id: Optional[str] = Field(
        None, description="Scope simulation to a specific assessment."
    )
    framework_id: Optional[str] = Field(
        None, description="Scope simulation to a specific framework."
    )
    simulation_contract_version: str = Field(
        "1.0", description="Contract version for replay compatibility."
    )


class SimulationRunResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    run_id: str
    tenant_id: str
    assessment_id: Optional[str]
    framework_id: Optional[str]
    scenario_type: str
    simulation_contract_version: str
    simulation_engine_version: str
    snapshot_id: str
    uncertainty: str
    total_warnings: int
    total_impacts: int
    total_critical_warnings: int
    simulated_at_iso: str
    projection: dict


class SimulationRunSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    run_id: str
    tenant_id: str
    scenario_type: str
    uncertainty: str
    total_warnings: int
    total_critical_warnings: int
    simulated_at_iso: str
    assessment_id: Optional[str]
    framework_id: Optional[str]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


_MAX_PARAM_KEYS = 20
_MAX_KEY_LEN = 128
_MAX_VALUE_LEN = 256


def _extract_actor(request: Request) -> dict:
    """Extract audit attribution fields from request auth context."""
    auth_ctx = getattr(getattr(request, "state", None), "auth", None) or getattr(
        getattr(request, "state", None), "api_key", None
    )
    actor_id = getattr(auth_ctx, "key_prefix", None) or getattr(
        auth_ctx, "subject", None
    )
    scopes = sorted(getattr(auth_ctx, "scopes", set()) or [])
    req_id = getattr(getattr(request, "state", None), "request_id", None)
    trace_id = request.headers.get("X-Trace-Id") or request.headers.get("X-Request-Id")
    return {
        "created_by_actor_id": str(actor_id)[:255] if actor_id else None,
        "actor_type": "api_key" if actor_id else "unknown",
        "request_id": str(req_id)[:128] if req_id else None,
        "trace_id": str(trace_id)[:128] if trace_id else None,
        "auth_scope_snapshot": json.dumps(scopes)[:512] if scopes else None,
    }


def _compute_hashes(
    scenario_parameters_json: str,
    scenario_type: str,
    contract_version: str,
    engine_version: str,
    projection_json: str,
) -> tuple[str, str, str]:
    """Return (input_hash, projection_hash, contract_hash) as SHA-256 hex strings."""
    input_payload = json.dumps(
        {
            "scenario_type": scenario_type,
            "scenario_parameters": scenario_parameters_json,
            "simulation_contract_version": contract_version,
        },
        sort_keys=True,
    )
    contract_payload = json.dumps(
        {
            "simulation_contract_version": contract_version,
            "simulation_engine_version": engine_version,
        },
        sort_keys=True,
    )
    return (
        hashlib.sha256(input_payload.encode()).hexdigest(),
        hashlib.sha256(projection_json.encode()).hexdigest(),
        hashlib.sha256(contract_payload.encode()).hexdigest(),
    )


@router.post(
    "/control-plane/readiness/simulation/runs",
    dependencies=[Depends(require_scopes("control-plane:write"))],
    response_model=SimulationRunResponse,
    status_code=201,
)
def create_simulation_run(
    body: SimulationRunRequest,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> SimulationRunResponse:
    """Submit a deterministic governance simulation scenario.

    Requires control-plane:write — simulations create stored records.
    Idempotent: submitting the same scenario inputs returns the stored result.
    simulation_id is derived deterministically from governance inputs and IS
    the run_id stored in the DB.
    """
    tenant_id = _tenant_from_auth(request)
    if not tenant_id:
        raise HTTPException(
            status_code=403,
            detail=api_error(
                "SIMULATION_NO_TENANT",
                "Tenant context required for simulation runs.",
            ),
        )

    # Validate scenario_type
    try:
        scenario_type_enum = SimulationScenarioType(body.scenario_type)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=api_error(
                "SIMULATION_INVALID_SCENARIO_TYPE",
                f"Invalid scenario_type: {body.scenario_type}. "
                f"Valid types: {[t.value for t in SimulationScenarioType]}",
            ),
        )

    # Validate and bound scenario_parameters
    params = body.scenario_parameters
    if len(params) > _MAX_PARAM_KEYS:
        raise HTTPException(
            status_code=400,
            detail=api_error(
                "SIMULATION_PARAMS_TOO_MANY_KEYS",
                f"scenario_parameters exceeds maximum of {_MAX_PARAM_KEYS} keys.",
            ),
        )
    for k, v in params.items():
        if len(k) > _MAX_KEY_LEN:
            raise HTTPException(
                status_code=400,
                detail=api_error(
                    "SIMULATION_PARAM_KEY_TOO_LONG",
                    f"Parameter key '{k[:32]}...' exceeds maximum length of {_MAX_KEY_LEN}.",
                ),
            )
        if len(v) > _MAX_VALUE_LEN:
            raise HTTPException(
                status_code=400,
                detail=api_error(
                    "SIMULATION_PARAM_VALUE_TOO_LONG",
                    f"Value for parameter '{k}' exceeds maximum length of {_MAX_VALUE_LEN}.",
                ),
            )

    # Convert scenario_parameters dict to sorted tuple of pairs
    scenario_parameters_sorted = tuple(sorted(body.scenario_parameters.items()))
    scenario_parameters_json = json.dumps(
        dict(scenario_parameters_sorted), sort_keys=True
    )

    # Derive the deterministic simulation_id (= run_id)
    simulation_id = derive_simulation_id(
        tenant_id=tenant_id,
        assessment_id=body.assessment_id or "",
        framework_id=body.framework_id or "",
        scenario_type=scenario_type_enum.value,
        scenario_parameters_json=scenario_parameters_json,
        simulation_contract_version=body.simulation_contract_version,
    )

    # Idempotency: return stored result if this simulation_id already exists.
    try:
        existing = _simulation_store.get_run(
            db, run_id=simulation_id, tenant_id=tenant_id
        )
        return _record_to_response(existing)
    except SimulationRunNotFound:
        pass

    # Build engine input
    now_iso = _now_iso()
    engine_input = SimulationInput(
        scenario_type=scenario_type_enum,
        scenario_parameters=scenario_parameters_sorted,
        tenant_id=tenant_id,
        assessment_id=body.assessment_id,
        framework_id=body.framework_id,
        simulation_contract_version=body.simulation_contract_version,
        simulation_engine_version=SIMULATION_ENGINE_VERSION,
        requested_at_iso=now_iso,
    )

    # Run the simulation
    projection = _sim_engine.simulate(simulation_id, engine_input)
    proj_json = projection_to_json(projection)

    # Count warnings and critical warnings
    total_warnings = len(projection.warnings)
    total_impacts = len(projection.impact_records)
    total_critical_warnings = sum(
        1 for w in projection.warnings if w.severity.value in ("critical", "blocking")
    )

    # Compute replay/hash integrity fields
    input_hash, projection_hash, contract_hash = _compute_hashes(
        scenario_parameters_json=scenario_parameters_json,
        scenario_type=scenario_type_enum.value,
        contract_version=body.simulation_contract_version,
        engine_version=SIMULATION_ENGINE_VERSION,
        projection_json=proj_json,
    )

    # Extract actor attribution
    actor_attrs = _extract_actor(request)

    try:
        record = _simulation_store.create_run(
            db,
            run_id=simulation_id,
            tenant_id=tenant_id,
            assessment_id=body.assessment_id,
            framework_id=body.framework_id,
            scenario_type=scenario_type_enum.value,
            simulation_contract_version=body.simulation_contract_version,
            simulation_engine_version=SIMULATION_ENGINE_VERSION,
            snapshot_id=projection.simulation_snapshot_id,
            projection_json=proj_json,
            uncertainty=projection.uncertainty.value,
            total_warnings=total_warnings,
            total_impacts=total_impacts,
            total_critical_warnings=total_critical_warnings,
            simulated_at_iso=projection.simulated_at_iso,
            completed=True,
            error_summary=None,
            input_hash=input_hash,
            projection_hash=projection_hash,
            contract_hash=contract_hash,
            **actor_attrs,
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = _simulation_store.get_run(
            db, run_id=simulation_id, tenant_id=tenant_id
        )
        return _record_to_response(existing)

    logger.info(
        "simulation_run_created run_id=%s tenant=%s scenario=%s "
        "warnings=%d impacts=%d critical=%d uncertainty=%s",
        simulation_id,
        tenant_id,
        scenario_type_enum.value,
        total_warnings,
        total_impacts,
        total_critical_warnings,
        projection.uncertainty.value,
    )

    return _record_to_response(record)


@router.get(
    "/control-plane/readiness/simulation/runs",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def list_simulation_runs(
    request: Request,
    scenario_type: Optional[str] = None,
    assessment_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(auth_ctx_db_session),
) -> list[SimulationRunSummaryResponse]:
    """List simulation runs for the authenticated tenant."""
    tenant_id = _tenant_from_auth(request)
    if not tenant_id:
        raise HTTPException(
            status_code=403,
            detail=api_error("SIMULATION_NO_TENANT", "Tenant context required."),
        )

    records = _simulation_store.list_runs(
        db,
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        scenario_type=scenario_type,
        limit=min(limit, 200),
        offset=offset,
    )
    return [
        SimulationRunSummaryResponse(
            run_id=r.run_id,
            tenant_id=r.tenant_id,
            scenario_type=r.scenario_type,
            uncertainty=r.uncertainty,
            total_warnings=r.total_warnings,
            total_critical_warnings=r.total_critical_warnings,
            simulated_at_iso=r.simulated_at_iso,
            assessment_id=r.assessment_id,
            framework_id=r.framework_id,
        )
        for r in records
    ]


@router.get(
    "/control-plane/readiness/simulation/runs/{run_id}",
    dependencies=[Depends(require_scopes("control-plane:read"))],
    response_model=SimulationRunResponse,
)
def get_simulation_run(
    run_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> SimulationRunResponse:
    """Retrieve a simulation run by its deterministic run_id."""
    tenant_id = _tenant_from_auth(request)
    if not tenant_id:
        raise HTTPException(
            status_code=403,
            detail=api_error("SIMULATION_NO_TENANT", "Tenant context required."),
        )

    try:
        record = _simulation_store.get_run(db, run_id=run_id, tenant_id=tenant_id)
    except SimulationRunNotFound:
        raise HTTPException(
            status_code=404,
            detail=api_error("SIMULATION_RUN_NOT_FOUND", "Simulation run not found."),
        )
    except SimulationRunTenantIsolationError:
        raise HTTPException(
            status_code=404,
            detail=api_error("SIMULATION_RUN_NOT_FOUND", "Simulation run not found."),
        )

    return _record_to_response(record)


def _record_to_response(record) -> SimulationRunResponse:  # type: ignore[no-untyped-def]
    """Convert a SimulationRunRecord to a SimulationRunResponse.

    projection_json is NEVER exposed directly — deserialized dict is returned.
    """
    projection_dict = projection_from_json(record.projection_json)
    return SimulationRunResponse(
        run_id=record.run_id,
        tenant_id=record.tenant_id,
        assessment_id=record.assessment_id,
        framework_id=record.framework_id,
        scenario_type=record.scenario_type,
        simulation_contract_version=record.simulation_contract_version,
        simulation_engine_version=record.simulation_engine_version,
        snapshot_id=record.snapshot_id,
        uncertainty=record.uncertainty,
        total_warnings=record.total_warnings,
        total_impacts=record.total_impacts,
        total_critical_warnings=record.total_critical_warnings,
        simulated_at_iso=record.simulated_at_iso,
        projection=projection_dict,
    )


# longitudinal_simulation_seam: GET /control-plane/readiness/simulation/runs/{run_id}/trajectory
# Multi-run drift trend analysis, readiness decay forecasting, governance volatility scoring,
# and chronic degradation detection extend from this boundary. The full simulation run history
# by (tenant_id, assessment_id) is the input; a longitudinal projection is the output.

# sovereignty_simulation_seam: POST /control-plane/readiness/simulation/sovereignty
# Residency-aware sovereign simulation for EU AI Act compliance, govcon boundary enforcement,
# and prohibited-region deployment governance. Extends SimulationProjection with a
# SovereigntyProjection sub-record covering residency compliance and export boundaries.

# autonomous_systems_seam: POST /control-plane/readiness/simulation/capability-governance
# Autonomous-systems capability governance simulation, bounded-authority enforcement,
# multi-agent delegation chain integrity, and escalation risk projection for AI systems
# operating with delegated authority. Extends CAPABILITY_GOVERNANCE_CHANGE with
# multi-agent authority attestation and cross-agent capability boundary governance.
