"""P0-11: Continuous Governance Control Tower (CGCT) API.

Aggregates from existing authority systems only — no new trust/cert/risk/evidence engines.

Routes (prefix: /control-tower):

  GET  /control-tower/posture          — latest governance posture snapshot
  POST /control-tower/posture/compute  — compute + persist posture + actions
  GET  /control-tower/health           — governance health summary
  GET  /control-tower/actions          — open action queue items
  GET  /control-tower/drift            — drift aggregation from TIM
  GET  /control-tower/risks            — risk rollup from TIM
  GET  /control-tower/evidence         — evidence coverage from verification bundles
  GET  /control-tower/timeline         — governance timeline events
  GET  /control-tower/decisions        — governance decision ledger
  GET  /control-tower/certifications   — certification state from CLM
  GET  /control-tower/executive        — 30-second executive summary
  GET  /control-tower/overview         — full governance overview
  GET  /control-tower/graph            — governance graph (nodes + edges)
  GET  /control-tower/authority-matrix — static authority matrix

NOTE: /control-tower/snapshot is in control_tower_snapshot.py — not duplicated here.

Capability gates (all ENTERPRISE tier):
  controltower.read          — posture, health, overview, graph, authority-matrix
  controltower.executive     — executive view
  controltower.risk          — risks
  controltower.certification — certifications
  controltower.evidence      — evidence
  controltower.timeline      — timeline
  controltower.decisions     — decisions
  controltower.drift         — drift
  controltower.operations    — actions
  controltower.admin         — posture/compute (write)
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from api.auth_scopes import require_scopes
from api.deps import auth_ctx_db_session
from api.entitlements import require_capability

log = logging.getLogger("frostgate.cgct.api")

router = APIRouter(
    prefix="/control-tower",
    tags=["control-tower-cgct"],
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _resolve_caller_tenant(request: Request) -> str:
    auth = getattr(getattr(request, "state", None), "auth", None)
    tenant_id = getattr(getattr(request, "state", None), "tenant_id", None) or getattr(
        auth, "tenant_id", None
    )
    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="tenant context required",
        )
    return str(tenant_id)


def _no_store_headers() -> dict[str, str]:
    return {"Cache-Control": "no-store"}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/posture",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("controltower.read")),
    ],
)
def get_posture_route(
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    engagement_id: str | None = Query(default=None),
) -> dict[str, Any]:
    """Return latest computed governance posture snapshot."""
    from fastapi.responses import JSONResponse  # noqa: PLC0415
    from services.cgct.posture import get_latest_posture  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)
    eid = engagement_id or ""
    posture = get_latest_posture(db, tenant_id=tenant_id, engagement_id=eid)
    if posture is None:
        return JSONResponse(
            content={
                "posture": None,
                "message": "no posture computed yet — POST /control-tower/posture/compute",
                "version": "CGCTv1",
            },
            headers=_no_store_headers(),
        )
    return JSONResponse(content=posture, headers=_no_store_headers())


@router.post(
    "/posture/compute",
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(require_scopes("governance:write")),
        Depends(require_capability("controltower.admin")),
    ],
)
def compute_posture_route(
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    engagement_id: str | None = Query(default=None),
    actor_type: str = Query(default="system"),
) -> dict[str, Any]:
    """Compute and persist governance posture + action queue."""
    from fastapi.responses import JSONResponse  # noqa: PLC0415
    from services.cgct.action_queue import compute_actions, store_actions  # noqa: PLC0415
    from services.cgct.posture import compute_posture  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)
    eid = engagement_id or ""

    posture = compute_posture(
        db, tenant_id=tenant_id, engagement_id=eid, actor=actor_type
    )
    actions = compute_actions(db, tenant_id=tenant_id, engagement_id=eid)
    stored_count = store_actions(
        db, tenant_id=tenant_id, engagement_id=eid, actions=actions
    )
    db.commit()

    result = {
        **posture,
        "actions_generated": len(actions),
        "actions_stored": stored_count,
    }
    return JSONResponse(content=result, headers=_no_store_headers())


@router.get(
    "/health",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("controltower.read")),
    ],
)
def get_health_route(
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    engagement_id: str | None = Query(default=None),
) -> dict[str, Any]:
    """Return governance health summary."""
    from fastapi.responses import JSONResponse  # noqa: PLC0415
    from services.cgct.posture import get_latest_posture  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)
    eid = engagement_id or ""
    posture = get_latest_posture(db, tenant_id=tenant_id, engagement_id=eid)

    health_data = {
        "governance_health": posture["governance_health"] if posture else "unknown",
        "overall_score": posture["overall_score"] if posture else 0,
        "last_computed_at": posture["computed_at"] if posture else None,
        "engagement_id": eid,
        "version": "CGCTv1",
    }
    return JSONResponse(content=health_data, headers=_no_store_headers())


@router.get(
    "/actions",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("controltower.operations")),
    ],
)
def get_actions_route(
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    engagement_id: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
) -> dict[str, Any]:
    """Return open action queue items."""
    from fastapi.responses import JSONResponse  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)
    eid = engagement_id or ""

    try:
        from api.db_models_cgct import FaCgctActionItem  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415

        q = select(FaCgctActionItem).where(
            FaCgctActionItem.tenant_id == tenant_id,
            FaCgctActionItem.engagement_id == eid,
        )
        if status_filter:
            q = q.where(FaCgctActionItem.status == status_filter)
        q = q.order_by(FaCgctActionItem.created_at.desc())
        rows = db.execute(q).scalars().all()
        actions = [
            {
                "action_id": r.id,
                "action_type": r.action_type,
                "action_title": r.action_title,
                "action_description": r.action_description,
                "priority": r.priority,
                "status": r.status,
                "source_system": r.source_system,
                "source_id": r.source_id,
                "created_at": r.created_at,
            }
            for r in rows
        ]
        result = {
            "actions": actions,
            "total": len(actions),
            "engagement_id": eid,
            "version": "CGCTv1",
        }
    except Exception:
        log.warning("cgct.api: get_actions_route failed", exc_info=True)
        result = {
            "actions": [],
            "total": 0,
            "engagement_id": eid,
            "version": "CGCTv1",
        }
    return JSONResponse(content=result, headers=_no_store_headers())


@router.get(
    "/drift",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("controltower.drift")),
    ],
)
def get_drift_route(
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    engagement_id: str | None = Query(default=None),
) -> dict[str, Any]:
    """Return drift aggregation from TIM."""
    from fastapi.responses import JSONResponse  # noqa: PLC0415
    from services.cgct.aggregators import aggregate_drift  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)
    eid = engagement_id or ""
    result = aggregate_drift(db, tenant_id=tenant_id, engagement_id=eid)
    return JSONResponse(content=result, headers=_no_store_headers())


@router.get(
    "/risks",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("controltower.risk")),
    ],
)
def get_risks_route(
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    engagement_id: str | None = Query(default=None),
) -> dict[str, Any]:
    """Return risk rollup from TIM trust snapshots."""
    from fastapi.responses import JSONResponse  # noqa: PLC0415
    from services.cgct.aggregators import aggregate_risk  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)
    eid = engagement_id or ""
    result = aggregate_risk(db, tenant_id=tenant_id, engagement_id=eid)
    return JSONResponse(content=result, headers=_no_store_headers())


@router.get(
    "/evidence",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("controltower.evidence")),
    ],
)
def get_evidence_route(
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    engagement_id: str | None = Query(default=None),
) -> dict[str, Any]:
    """Return evidence coverage from verification bundles."""
    from fastapi.responses import JSONResponse  # noqa: PLC0415
    from services.cgct.aggregators import aggregate_evidence  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)
    eid = engagement_id or ""
    result = aggregate_evidence(db, tenant_id=tenant_id, engagement_id=eid)
    return JSONResponse(content=result, headers=_no_store_headers())


@router.get(
    "/timeline",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("controltower.timeline")),
    ],
)
def get_timeline_route(
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    engagement_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    """Return governance timeline events."""
    from fastapi.responses import JSONResponse  # noqa: PLC0415
    from services.cgct.aggregators import aggregate_timeline  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)
    eid = engagement_id or ""
    result = aggregate_timeline(db, tenant_id=tenant_id, engagement_id=eid, limit=limit)
    return JSONResponse(content=result, headers=_no_store_headers())


@router.get(
    "/decisions",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("controltower.decisions")),
    ],
)
def get_decisions_route(
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    engagement_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
) -> dict[str, Any]:
    """Return governance decisions from decision ledger."""
    from fastapi.responses import JSONResponse  # noqa: PLC0415
    from services.cgct.aggregators import aggregate_decisions  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)
    eid = engagement_id or ""
    result = aggregate_decisions(
        db, tenant_id=tenant_id, engagement_id=eid, limit=limit
    )
    return JSONResponse(content=result, headers=_no_store_headers())


@router.get(
    "/certifications",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("controltower.certification")),
    ],
)
def get_certifications_route(
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    engagement_id: str | None = Query(default=None),
) -> dict[str, Any]:
    """Return certification state from CLM."""
    from fastapi.responses import JSONResponse  # noqa: PLC0415
    from services.cgct.aggregators import aggregate_certifications  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)
    eid = engagement_id or ""
    result = aggregate_certifications(db, tenant_id=tenant_id, engagement_id=eid)
    return JSONResponse(content=result, headers=_no_store_headers())


@router.get(
    "/executive",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("controltower.executive")),
    ],
)
def get_executive_route(
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    engagement_id: str | None = Query(default=None),
) -> dict[str, Any]:
    """Return 30-second executive governance summary."""
    from fastapi.responses import JSONResponse  # noqa: PLC0415
    from services.cgct.aggregators import get_executive_view  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)
    eid = engagement_id or ""
    result = get_executive_view(db, tenant_id=tenant_id, engagement_id=eid)
    return JSONResponse(content=result, headers=_no_store_headers())


@router.get(
    "/overview",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("controltower.read")),
    ],
)
def get_overview_route(
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    engagement_id: str | None = Query(default=None),
) -> dict[str, Any]:
    """Return full governance overview combining all aggregations."""
    from fastapi.responses import JSONResponse  # noqa: PLC0415
    from services.cgct.aggregators import (  # noqa: PLC0415
        aggregate_certifications,
        aggregate_drift,
        aggregate_evidence,
        aggregate_risk,
        get_executive_view,
    )
    from services.cgct.posture import get_latest_posture  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)
    eid = engagement_id or ""

    result = {
        "posture": get_latest_posture(db, tenant_id=tenant_id, engagement_id=eid),
        "executive": get_executive_view(db, tenant_id=tenant_id, engagement_id=eid),
        "risk": aggregate_risk(db, tenant_id=tenant_id, engagement_id=eid),
        "drift": aggregate_drift(db, tenant_id=tenant_id, engagement_id=eid),
        "evidence": aggregate_evidence(db, tenant_id=tenant_id, engagement_id=eid),
        "certifications": aggregate_certifications(
            db, tenant_id=tenant_id, engagement_id=eid
        ),
        "engagement_id": eid,
        "version": "CGCTv1",
    }
    return JSONResponse(content=result, headers=_no_store_headers())


@router.get(
    "/graph",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("controltower.read")),
    ],
)
def get_graph_route(
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Return governance graph nodes and edges."""
    from fastapi.responses import JSONResponse  # noqa: PLC0415
    from services.cgct.aggregators import get_governance_graph  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)
    result = get_governance_graph(db, tenant_id=tenant_id)
    return JSONResponse(content=result, headers=_no_store_headers())


@router.get(
    "/authority-matrix",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("controltower.read")),
    ],
)
def get_authority_matrix_route(
    request: Request,
) -> dict[str, Any]:
    """Return static authority matrix documenting all governance sources."""
    from fastapi.responses import JSONResponse  # noqa: PLC0415
    from services.cgct.aggregators import get_authority_matrix  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)
    result = get_authority_matrix(tenant_id)
    return JSONResponse(content=result, headers=_no_store_headers())
