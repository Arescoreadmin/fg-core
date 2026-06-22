"""P0-10: Certification Lifecycle Management (CLM) API.

Manages the full lifecycle of certifications sourced from existing
trust infrastructure.  No new trust engines.

Routes (prefix: /field-assessment):

  Per-engagement:
    POST .../certifications                    — create certification
    GET  .../certifications                    — list certifications
    GET  .../certifications/dashboard          — CLM health dashboard (ETCC)
    GET  .../certifications/{cert_id}          — full certification detail
    POST .../certifications/{cert_id}/transition — lifecycle transition
    POST .../certifications/{cert_id}/review     — add review
    POST .../certifications/{cert_id}/attest     — add attestation
    POST .../certifications/{cert_id}/renew      — initiate renewal
    GET  .../certifications/{cert_id}/lineage    — parent chain + family tree
    GET  .../certifications/{cert_id}/health     — health scoring
    GET  .../certifications/{cert_id}/impact     — trust impact
    GET  .../certifications/{cert_id}/manifest   — deterministic audit manifest
    GET  .../certifications/{cert_id}/history    — lifecycle event log

Capability gates (all ENTERPRISE tier):
  certification.read         — list, get, health, history
  certification.review       — add review
  certification.attest       — add attestation
  certification.approve      — lifecycle transition
  certification.renew        — initiate renewal
  certification.drilldown    — lineage, impact, manifest
  certification.executive.view — dashboard

All routes require governance:read scope minimum.
Mutation routes require governance:write scope.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.auth_scopes import require_scopes
from api.deps import auth_ctx_db_session
from api.entitlements import require_capability
from api.db_models_clm import (
    FaClmCert,
    FaClmCertManifest,
    FaClmLifecycleEvent,
)

log = logging.getLogger("frostgate.clm.api")

router = APIRouter(
    prefix="/field-assessment",
    tags=["certification-lifecycle"],
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


def _caller_actor(request: Request) -> str:
    auth = getattr(getattr(request, "state", None), "auth", None)
    return getattr(auth, "key_prefix", None) or "system"


def _cert_to_dict(row: FaClmCert) -> dict[str, Any]:
    return {
        "cert_id": row.id,
        "tenant_id": row.tenant_id,
        "engagement_id": row.engagement_id,
        "trust_arc_cert_id": row.trust_arc_cert_id,
        "cert_name": row.cert_name,
        "cert_type": row.cert_type,
        "framework": row.framework,
        "certification_level": row.certification_level,
        "lifecycle_status": row.lifecycle_status,
        "parent_cert_id": row.parent_cert_id,
        "family_id": row.family_id,
        "valid_from": row.valid_from,
        "valid_until": row.valid_until,
        "created_by": row.created_by,
        "created_at": row.created_at,
        "status_updated_by": row.status_updated_by,
        "status_updated_at": row.status_updated_at,
        "cert_hash": row.cert_hash,
        "actor_type": row.actor_type,
        "framework_version": row.framework_version,
        "certification_profile": row.certification_profile,
        "generation_version": row.generation_version,
        "authority_version": row.authority_version,
        "schema_version": row.schema_version,
    }


def _parse_json_list(val: str) -> list:
    try:
        return json.loads(val)
    except (ValueError, TypeError):
        return []


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "/engagements/{eid}/certifications",
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(require_scopes("governance:write")),
        Depends(require_capability("certification.admin")),
    ],
)
def create_certification_route(
    eid: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    cert_name: str = Query(default=""),
    trust_arc_cert_id: str | None = Query(default=None),
    cert_type: str = Query(default="standard"),
    framework: str | None = Query(default=None),
    certification_level: str | None = Query(default=None),
    valid_from: str | None = Query(default=None),
    valid_until: str | None = Query(default=None),
    parent_cert_id: str | None = Query(default=None),
    family_id: str | None = Query(default=None),
    actor_type: str = Query(default="human"),
    framework_version: str | None = Query(default=None),
    certification_profile: str | None = Query(default=None),
) -> dict[str, Any]:
    from services.clm.lifecycle_service import create_certification  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)
    actor = _caller_actor(request)

    result = create_certification(
        db,
        tenant_id=tenant_id,
        engagement_id=eid,
        trust_arc_cert_id=trust_arc_cert_id,
        cert_name=cert_name,
        cert_type=cert_type,
        framework=framework,
        certification_level=certification_level,
        valid_from=valid_from,
        valid_until=valid_until,
        created_by=actor,
        parent_cert_id=parent_cert_id,
        family_id=family_id,
        actor_type=actor_type,
        framework_version=framework_version,
        certification_profile=certification_profile,
    )
    if not result:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="certification creation failed",
        )
    db.commit()
    return result


@router.get(
    "/engagements/{eid}/certifications",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("certification.read")),
    ],
)
def list_certifications_route(
    eid: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    lifecycle_status: str | None = Query(default=None),
    cert_type: str | None = Query(default=None),
    framework: str | None = Query(default=None),
) -> dict[str, Any]:
    tenant_id = _resolve_caller_tenant(request)

    q = (
        select(FaClmCert)
        .where(
            FaClmCert.tenant_id == tenant_id,
            FaClmCert.engagement_id == eid,
        )
        .order_by(FaClmCert.created_at.desc())
    )
    if lifecycle_status:
        q = q.where(FaClmCert.lifecycle_status == lifecycle_status)
    if cert_type:
        q = q.where(FaClmCert.cert_type == cert_type)
    if framework:
        q = q.where(FaClmCert.framework == framework)

    rows = db.execute(q).scalars().all()
    return {
        "certifications": [_cert_to_dict(r) for r in rows],
        "total": len(rows),
    }


@router.get(
    "/engagements/{eid}/certifications/dashboard",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("certification.executive.view")),
    ],
)
def certification_dashboard_route(
    eid: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """CLM health summary for ETCC integration."""
    tenant_id = _resolve_caller_tenant(request)

    all_certs = (
        db.execute(
            select(FaClmCert)
            .where(
                FaClmCert.tenant_id == tenant_id,
                FaClmCert.engagement_id == eid,
            )
            .order_by(FaClmCert.created_at.desc())
        )
        .scalars()
        .all()
    )

    # Status distribution
    status_dist: dict[str, int] = {}
    for cert in all_certs:
        status_dist[cert.lifecycle_status] = (
            status_dist.get(cert.lifecycle_status, 0) + 1
        )

    # Expiring soon (within 90 days)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    from datetime import timedelta  # noqa: PLC0415

    ninety_days = (datetime.now(timezone.utc) + timedelta(days=90)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    expiring_soon = [
        c
        for c in all_certs
        if c.valid_until and now_str <= c.valid_until <= ninety_days
    ]

    # Renewal needed
    renewal_needed = [
        c for c in all_certs if c.lifecycle_status in ("renewal_due", "expired")
    ]

    # Recently created (last 5)
    recent = all_certs[:5]

    return {
        "engagement_id": eid,
        "total_certifications": len(all_certs),
        "status_distribution": status_dist,
        "expiring_soon_count": len(expiring_soon),
        "renewal_needed_count": len(renewal_needed),
        "recently_created": [_cert_to_dict(r) for r in recent],
    }


@router.get(
    "/engagements/{eid}/certifications/{cert_id}",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("certification.read")),
    ],
)
def get_certification_route(
    eid: str,
    cert_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _resolve_caller_tenant(request)

    cert = db.execute(
        select(FaClmCert).where(
            FaClmCert.id == cert_id,
            FaClmCert.tenant_id == tenant_id,
            FaClmCert.engagement_id == eid,
        )
    ).scalar_one_or_none()

    if cert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="cert not found"
        )

    return _cert_to_dict(cert)


@router.post(
    "/engagements/{eid}/certifications/{cert_id}/transition",
    dependencies=[
        Depends(require_scopes("governance:write")),
        Depends(require_capability("certification.approve")),
    ],
)
def transition_certification_route(
    eid: str,
    cert_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    to_status: str = Query(...),
    notes: str | None = Query(default=None),
) -> dict[str, Any]:
    from services.clm.lifecycle_service import transition_lifecycle  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)
    actor = _caller_actor(request)

    try:
        result = transition_lifecycle(
            db,
            cert_id=cert_id,
            tenant_id=tenant_id,
            engagement_id=eid,
            to_status=to_status,
            actor=actor,
            notes=notes,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    db.commit()
    return result


@router.post(
    "/engagements/{eid}/certifications/{cert_id}/review",
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(require_scopes("governance:write")),
        Depends(require_capability("certification.review")),
    ],
)
def add_review_route(
    eid: str,
    cert_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    reviewer_type: str = Query(default="human"),
    review_outcome: str = Query(...),
    notes: str | None = Query(default=None),
) -> dict[str, Any]:
    from services.clm.lifecycle_service import add_review  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)
    actor = _caller_actor(request)

    result = add_review(
        db,
        cert_id=cert_id,
        tenant_id=tenant_id,
        engagement_id=eid,
        reviewer=actor,
        reviewer_type=reviewer_type,
        review_outcome=review_outcome,
        notes=notes,
        evidence_refs=None,
    )
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="cert not found",
        )
    db.commit()
    return result


@router.post(
    "/engagements/{eid}/certifications/{cert_id}/attest",
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(require_scopes("governance:write")),
        Depends(require_capability("certification.attest")),
    ],
)
def add_attestation_route(
    eid: str,
    cert_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    attestation_type: str = Query(...),
    attester_type: str = Query(default="human"),
    attestation_data: str = Query(default="{}"),
) -> dict[str, Any]:
    from services.clm.lifecycle_service import add_attestation  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)
    actor = _caller_actor(request)

    try:
        data = json.loads(attestation_data)
    except (ValueError, TypeError):
        data = {}

    result = add_attestation(
        db,
        cert_id=cert_id,
        tenant_id=tenant_id,
        engagement_id=eid,
        attestation_type=attestation_type,
        attester=actor,
        attester_type=attester_type,
        attestation_data=data,
    )
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="cert not found",
        )
    db.commit()
    return result


@router.post(
    "/engagements/{eid}/certifications/{cert_id}/renew",
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(require_scopes("governance:write")),
        Depends(require_capability("certification.renew")),
    ],
)
def initiate_renewal_route(
    eid: str,
    cert_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    renewal_type: str = Query(default="routine"),
) -> dict[str, Any]:
    from services.clm.lifecycle_service import initiate_renewal  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)
    actor = _caller_actor(request)

    result = initiate_renewal(
        db,
        cert_id=cert_id,
        tenant_id=tenant_id,
        engagement_id=eid,
        renewal_type=renewal_type,
        initiated_by=actor,
    )
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="cert not found",
        )
    db.commit()
    return result


@router.get(
    "/engagements/{eid}/certifications/{cert_id}/lineage",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("certification.drilldown")),
    ],
)
def get_lineage_route(
    eid: str,
    cert_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    from services.clm.lifecycle_service import get_lineage  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)

    result = get_lineage(db, cert_id=cert_id, tenant_id=tenant_id, engagement_id=eid)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="cert not found"
        )
    return result


@router.get(
    "/engagements/{eid}/certifications/{cert_id}/health",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("certification.read")),
    ],
)
def get_health_route(
    eid: str,
    cert_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    from services.clm.lifecycle_service import get_certification_health  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)

    result = get_certification_health(
        db, cert_id=cert_id, tenant_id=tenant_id, engagement_id=eid
    )
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="cert not found"
        )
    return result


@router.get(
    "/engagements/{eid}/certifications/{cert_id}/impact",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("certification.drilldown")),
    ],
)
def get_impact_route(
    eid: str,
    cert_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    from services.clm.lifecycle_service import compute_trust_impact  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)

    result = compute_trust_impact(
        db, cert_id=cert_id, tenant_id=tenant_id, engagement_id=eid
    )
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="cert not found"
        )
    return result


@router.get(
    "/engagements/{eid}/certifications/{cert_id}/manifest",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("certification.drilldown")),
    ],
)
def get_manifest_route(
    eid: str,
    cert_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _resolve_caller_tenant(request)

    manifest = db.execute(
        select(FaClmCertManifest).where(
            FaClmCertManifest.cert_id == cert_id,
            FaClmCertManifest.tenant_id == tenant_id,
        )
    ).scalar_one_or_none()

    if manifest is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="manifest not found"
        )

    return {
        "manifest_id": manifest.id,
        "cert_id": manifest.cert_id,
        "trust_arc_cert_id": manifest.trust_arc_cert_id,
        "snapshot_ids": _parse_json_list(manifest.snapshot_ids),
        "bundle_ids": _parse_json_list(manifest.bundle_ids),
        "timeline_refs": _parse_json_list(manifest.timeline_refs),
        "decision_refs": _parse_json_list(manifest.decision_refs),
        "evidence_refs": _parse_json_list(manifest.evidence_refs),
        "manifest_hash": manifest.manifest_hash,
        "generated_at": manifest.generated_at,
        "schema_version": manifest.schema_version,
    }


@router.get(
    "/engagements/{eid}/certifications/{cert_id}/history",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("certification.read")),
    ],
)
def get_history_route(
    eid: str,
    cert_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = _resolve_caller_tenant(request)

    events = (
        db.execute(
            select(FaClmLifecycleEvent)
            .where(
                FaClmLifecycleEvent.cert_id == cert_id,
                FaClmLifecycleEvent.tenant_id == tenant_id,
            )
            .order_by(FaClmLifecycleEvent.occurred_at.asc())
        )
        .scalars()
        .all()
    )

    def _event_to_dict(e: FaClmLifecycleEvent) -> dict[str, Any]:
        try:
            data = json.loads(e.event_data)
        except (ValueError, TypeError):
            data = {}
        return {
            "event_id": e.id,
            "cert_id": e.cert_id,
            "event_type": e.event_type,
            "from_status": e.from_status,
            "to_status": e.to_status,
            "actor": e.actor,
            "actor_type": e.actor_type,
            "notes": e.notes,
            "event_data": data,
            "occurred_at": e.occurred_at,
            "schema_version": e.schema_version,
        }

    return {
        "cert_id": cert_id,
        "events": [_event_to_dict(e) for e in events],
        "total": len(events),
    }
