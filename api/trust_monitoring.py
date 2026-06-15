"""P0-7: Trust Intelligence Monitoring (TIM) API.

Executive dashboard routes for continuous trust monitoring.

Routes (all under /field-assessment/engagements/{engagement_id}/tim/):

  GET .../posture           — latest TIM trust snapshot (score, level, drift)
  GET .../timeline          — governance timeline events (trust_monitoring source)
  GET .../drift             — open drift events
  GET .../certification-status — latest certification with expiry metadata
  GET .../risks             — high+critical drift events as risk summary

Scopes:
  governance:read  — all GET routes
  continuous.monitoring — capability gate (ENTERPRISE tier)
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.auth_scopes import require_scopes
from api.deps import auth_ctx_db_session
from api.entitlements import require_capability
from api.db_models_tim import FaTimDriftEvent, FaTimTrustSnapshot
from api.db_models_trust_arc import FaTrustCertification

log = logging.getLogger("frostgate.trust_monitoring")

router = APIRouter(
    prefix="/field-assessment",
    tags=["trust-monitoring"],
)

_CAPABILITY = "continuous.monitoring"

_SEVERITY_WEIGHT: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 3,
    "high": 7,
    "critical": 15,
}

# ---------------------------------------------------------------------------
# Tenant resolution
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


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def _load_json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return value
    return value


def _risk_weight(severity: str) -> int:
    return _SEVERITY_WEIGHT.get(severity, 0)


def _tim_snapshot_to_dict(row: FaTimTrustSnapshot) -> dict[str, Any]:
    return {
        "snapshot_id": row.id,
        "tenant_id": row.tenant_id,
        "engagement_id": row.engagement_id,
        "posture_score": row.posture_score,
        "posture_level": row.posture_level,
        "risk_level": row.risk_level,
        "certification_level": row.certification_level,
        "composite_score": row.composite_score,
        "certification_valid_until": row.certification_valid_until,
        "drift_score": row.drift_score,
        "drift_direction": row.drift_direction,
        "open_drift_count": row.open_drift_count,
        "evidence_count": row.evidence_count,
        "replay_status": row.replay_status,
        "last_snapshot_id": row.last_snapshot_id,
        "last_certification_id": row.last_certification_id,
        "last_bundle_id": row.last_bundle_id,
        "source_fingerprint": row.source_fingerprint,
        "evaluated_at": row.evaluated_at,
        "schema_version": row.schema_version,
    }


def _drift_event_to_dict(row: FaTimDriftEvent) -> dict[str, Any]:
    return {
        "event_id": row.id,
        "tenant_id": row.tenant_id,
        "engagement_id": row.engagement_id,
        "drift_rule": row.drift_rule,
        "severity": row.severity,
        "status": row.status,
        "detected_at": row.detected_at,
        "resolved_at": row.resolved_at,
        "evidence": _load_json(row.evidence),
        "correlation_id": row.correlation_id,
        "actor_type": row.actor_type,
        "acknowledged_by": row.acknowledged_by,
        "acknowledged_at": row.acknowledged_at,
        "risk_score": _risk_weight(row.severity),
        "schema_version": row.schema_version,
    }


# ---------------------------------------------------------------------------
# Trust trend windows helper
# ---------------------------------------------------------------------------


def _compute_trend_windows(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
) -> dict[str, Any]:
    """Compute 7d / 30d / 90d posture trend windows from snapshot history."""
    try:
        now = datetime.now(timezone.utc)
        cutoff_90 = (now - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")

        rows = db.execute(
            select(FaTimTrustSnapshot.evaluated_at, FaTimTrustSnapshot.posture_score)
            .where(
                FaTimTrustSnapshot.tenant_id == tenant_id,
                FaTimTrustSnapshot.engagement_id == engagement_id,
                FaTimTrustSnapshot.evaluated_at >= cutoff_90,
            )
            .order_by(FaTimTrustSnapshot.evaluated_at.asc())
        ).all()

        def _window(days: int) -> dict[str, Any]:
            cutoff = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
            window_rows = [r for r in rows if r.evaluated_at >= cutoff]
            if len(window_rows) < 2:
                return {
                    "days": days,
                    "direction": "insufficient_data",
                    "data_points": len(window_rows),
                }
            start_score = window_rows[0].posture_score
            end_score = window_rows[-1].posture_score
            net_delta = end_score - start_score
            if net_delta >= 10:
                direction = "improving"
            elif net_delta <= -20:
                direction = "rapidly_degrading"
            elif net_delta <= -5:
                direction = "degrading"
            else:
                direction = "stable"
            return {
                "days": days,
                "start_score": start_score,
                "end_score": end_score,
                "net_delta": net_delta,
                "direction": direction,
                "data_points": len(window_rows),
            }

        return {"7d": _window(7), "30d": _window(30), "90d": _window(90)}
    except Exception:
        _insufficient = {"direction": "insufficient_data", "data_points": 0}
        return {
            "7d": {**_insufficient, "days": 7},
            "30d": {**_insufficient, "days": 30},
            "90d": {**_insufficient, "days": 90},
        }


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/tim/posture
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/tim/posture",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability(_CAPABILITY)),
    ],
    summary="Latest TIM trust posture snapshot",
)
def get_tim_posture(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Return the most recent TIM trust posture snapshot for an engagement.

    Includes posture score, certification state, drift direction, and
    open drift event count.  Evaluated continuously on every trust arc
    activation.
    """
    tenant_id = _resolve_caller_tenant(request)
    row = db.execute(
        select(FaTimTrustSnapshot)
        .where(
            FaTimTrustSnapshot.tenant_id == tenant_id,
            FaTimTrustSnapshot.engagement_id == engagement_id,
        )
        .order_by(FaTimTrustSnapshot.evaluated_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no TIM snapshot found for this engagement",
        )
    result = _tim_snapshot_to_dict(row)
    result["trend_windows"] = _compute_trend_windows(
        db, tenant_id=tenant_id, engagement_id=engagement_id
    )
    return result


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/tim/timeline
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/tim/timeline",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability(_CAPABILITY)),
    ],
    summary="Governance timeline events for TIM monitoring",
)
def get_tim_timeline(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    limit: int = 50,
) -> dict[str, Any]:
    """Return recent governance timeline events for trust monitoring.

    Filtered to source_type='trust_monitoring' events for this engagement.
    Ordered most-recent-first.  Max 200 events per call.
    """
    from api.db_models_timeline import TimelineEventRecord  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)
    limit = min(limit, 200)

    rows = (
        db.execute(
            select(TimelineEventRecord)
            .where(
                TimelineEventRecord.tenant_id == tenant_id,
                TimelineEventRecord.source_type == "trust_monitoring",
            )
            .filter(
                TimelineEventRecord.payload["engagement_id"].as_string()
                == engagement_id
            )
            .order_by(TimelineEventRecord.occurred_at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )

    events = [
        {
            "event_id": r.id,
            "source_type": r.source_type,
            "source_id": r.source_id,
            "event_type": r.event_type,
            "occurred_at": r.occurred_at,
            "recorded_at": r.recorded_at,
            "classification": r.classification,
            "replay_eligible": r.replay_eligible,
            "payload": r.payload
            if isinstance(r.payload, dict)
            else _load_json(r.payload),
        }
        for r in rows
    ]
    return {"engagement_id": engagement_id, "events": events, "count": len(events)}


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/tim/drift
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/tim/drift",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability(_CAPABILITY)),
    ],
    summary="Open drift events for an engagement",
)
def get_tim_drift(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    status_filter: str = "open",
    limit: int = 100,
) -> dict[str, Any]:
    """Return drift events for an engagement.

    Defaults to open events only.  Pass status_filter=all to include
    resolved events.  Ordered most-recent-first.  Max 500 per call.
    """
    tenant_id = _resolve_caller_tenant(request)
    limit = min(limit, 500)

    q = select(FaTimDriftEvent).where(
        FaTimDriftEvent.tenant_id == tenant_id,
        FaTimDriftEvent.engagement_id == engagement_id,
    )
    if status_filter != "all":
        q = q.where(FaTimDriftEvent.status == status_filter)
    if status_filter == "open":
        q = q.where(
            ~FaTimDriftEvent.id.in_(
                select(FaTimDriftEvent.correlation_id).where(
                    FaTimDriftEvent.tenant_id == tenant_id,
                    FaTimDriftEvent.engagement_id == engagement_id,
                    FaTimDriftEvent.status == "acknowledged",
                    FaTimDriftEvent.correlation_id.isnot(None),
                )
            )
        )
    q = q.order_by(FaTimDriftEvent.detected_at.desc()).limit(limit)

    rows = db.execute(q).scalars().all()
    return {
        "engagement_id": engagement_id,
        "status_filter": status_filter,
        "drift_events": [_drift_event_to_dict(r) for r in rows],
        "count": len(rows),
    }


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/tim/certification-status
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/tim/certification-status",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability(_CAPABILITY)),
    ],
    summary="Current trust certification with expiry metadata",
)
def get_tim_certification_status(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Return the active trust certification and its validity status.

    Includes days_remaining, expiry_status (valid/expiring_soon/expired),
    and the latest TIM snapshot certification fields for cross-reference.
    """
    tenant_id = _resolve_caller_tenant(request)

    cert = db.execute(
        select(FaTrustCertification)
        .where(
            FaTrustCertification.tenant_id == tenant_id,
            FaTrustCertification.engagement_id == engagement_id,
        )
        .order_by(FaTrustCertification.valid_from.desc())
        .limit(1)
    ).scalar_one_or_none()

    if cert is None:
        return {
            "engagement_id": engagement_id,
            "certification_level": "not_certified",
            "expiry_status": "not_certified",
            "days_remaining": None,
            "certification": None,
        }

    now = datetime.now(timezone.utc)
    try:
        expiry = datetime.fromisoformat(cert.valid_until.replace("Z", "+00:00"))
        days_left = (expiry - now).days
        if days_left < 0:
            expiry_status = "expired"
        elif days_left <= 3:
            expiry_status = "expiring_soon"
        elif days_left <= 14:
            expiry_status = "expiring_soon"
        else:
            expiry_status = "valid"
    except (ValueError, AttributeError):
        days_left = None
        expiry_status = "unknown"

    return {
        "engagement_id": engagement_id,
        "certification_level": cert.certification_level,
        "expiry_status": expiry_status,
        "days_remaining": days_left,
        "certification": {
            "certification_id": cert.id,
            "certification_level": cert.certification_level,
            "composite_score": cert.composite_score,
            "trust_score": cert.trust_score,
            "confidence_score": cert.confidence_score,
            "valid_from": cert.valid_from,
            "valid_until": cert.valid_until,
            "authority_version": cert.authority_version,
            "schema_version": cert.schema_version,
        },
    }


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/tim/risks
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/tim/risks",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability(_CAPABILITY)),
    ],
    summary="High and critical trust drift risks",
)
def get_tim_risks(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Return open high/critical drift events as an executive risk summary.

    Only surfaces the most actionable signals: severity=high or critical,
    status=open.  Ordered by detected_at descending.
    """
    tenant_id = _resolve_caller_tenant(request)

    rows = (
        db.execute(
            select(FaTimDriftEvent)
            .where(
                FaTimDriftEvent.tenant_id == tenant_id,
                FaTimDriftEvent.engagement_id == engagement_id,
                FaTimDriftEvent.status == "open",
                FaTimDriftEvent.severity.in_(["high", "critical"]),
            )
            .order_by(FaTimDriftEvent.detected_at.desc())
            .limit(100)
        )
        .scalars()
        .all()
    )

    all_open_rows = (
        db.execute(
            select(FaTimDriftEvent).where(
                FaTimDriftEvent.tenant_id == tenant_id,
                FaTimDriftEvent.engagement_id == engagement_id,
                FaTimDriftEvent.status == "open",
            )
        )
        .scalars()
        .all()
    )

    engagement_risk_score = sum(_risk_weight(r.severity) for r in all_open_rows)

    risks = [_drift_event_to_dict(r) for r in rows]
    return {
        "engagement_id": engagement_id,
        "risks": risks,
        "risk_count": len(risks),
        "has_critical": any(r["severity"] == "critical" for r in risks),
        "has_high": any(r["severity"] == "high" for r in risks),
        "engagement_risk_score": engagement_risk_score,
    }


# ---------------------------------------------------------------------------
# POST /engagements/{engagement_id}/tim/drift/{event_id}/acknowledge
# ---------------------------------------------------------------------------


@router.post(
    "/engagements/{engagement_id}/tim/drift/{event_id}/acknowledge",
    dependencies=[
        Depends(require_scopes("governance:write")),
        Depends(require_capability(_CAPABILITY)),
    ],
    summary="Acknowledge a drift event (append-only governance audit trail)",
)
def acknowledge_tim_drift(
    engagement_id: str,
    event_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    actor_id: str = Query(...),
) -> dict[str, Any]:
    """Create an acknowledgement row for an existing drift event.

    Append-only: the original event row is unchanged (DB trigger prevents
    UPDATE/DELETE).  This creates a new row with status='acknowledged'
    and links back via correlation_id.
    """
    tenant_id = _resolve_caller_tenant(request)

    original = db.execute(
        select(FaTimDriftEvent).where(
            FaTimDriftEvent.tenant_id == tenant_id,
            FaTimDriftEvent.engagement_id == engagement_id,
            FaTimDriftEvent.id == event_id,
        )
    ).scalar_one_or_none()

    if original is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="drift event not found",
        )

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    new_row = FaTimDriftEvent(
        id=uuid.uuid4().hex,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        drift_rule=original.drift_rule,
        severity=original.severity,
        evidence=original.evidence,
        status="acknowledged",
        detected_at=now_iso,
        correlation_id=original.id,
        actor_type="human",
        acknowledged_by=actor_id,
        acknowledged_at=now_iso,
        schema_version="1.0",
    )
    db.add(new_row)
    db.flush()

    return _drift_event_to_dict(new_row)
