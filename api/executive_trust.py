"""P0-8: Executive Trust Command Center (ETCC) API.

Single command center for executive, auditor, and regulator trust governance.
All data sourced from existing TIM (P0-7) and Trust Arc (P0-6A/B) tables.
No new trust engines.  No synthetic scoring.  No AI.

Routes (prefix: /field-assessment):

  Tenant-level:
    GET  /etcc/overview                                — all engagements at a glance

  Per-engagement (all under /engagements/{engagement_id}/etcc/):
    GET  .../posture                                   — full executive trust posture
    GET  .../trends                                    — 7d/30d/90d trend windows
    GET  .../risks                                     — all open drift events + risk rollup
    GET  .../certification                             — certification health + expiry
    GET  .../certification/history                     — full certification history
    GET  .../monitoring                                — TIM evaluation health
    GET  .../timeline                                  — unified activity feed (filterable)
    GET  .../decisions                                 — trust decision memory
    GET  .../drilldown/drift/{event_id}                — drift event → evidence → snapshot
    GET  .../drilldown/certification/{cert_id}         — certification → proof → bundle

  Executive reporting (APIs only — no PDF):
    GET  .../reports/summary                           — executive trust summary
    GET  .../reports/quarterly                         — quarterly trust summary (date range)
    GET  .../reports/drift                             — drift history + statistics
    GET  .../reports/risk                              — risk posture breakdown

Capability gates:
  trust.executive.dashboard   — posture, trends, overview
  trust.executive.drilldown   — drilldown/drift and drilldown/certification
  trust.risk                  — risks endpoint
  trust.certification         — certification routes
  continuous.monitoring       — monitoring health route
  trust.timeline              — activity feed
  trust.memory                — decision memory
  trust.reporting             — all /reports/* routes

All routes require governance:read scope and ENTERPRISE tier.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.auth_scopes import require_scopes
from api.deps import auth_ctx_db_session
from api.entitlements import require_capability
from api.db_models_tim import FaTimDriftEvent, FaTimTrustSnapshot
from api.db_models_trust_arc import (
    FaChainOfCustodyRecord,
    FaDecisionReconstructionRecord,
    FaTrustCertification,
    FaTrustDecisionMemory,
    FaTrustIntelligenceLedger,
)

log = logging.getLogger("frostgate.etcc")

router = APIRouter(
    prefix="/field-assessment",
    tags=["executive-trust-command-center"],
)

_SEVERITY_WEIGHT: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 3,
    "high": 7,
    "critical": 15,
}

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


def _load_json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return value
    return value


def _risk_weight(severity: str) -> int:
    return _SEVERITY_WEIGHT.get(severity, 0)


def _cert_expiry_status(valid_until: str | None) -> tuple[str, int | None]:
    if not valid_until:
        return "not_certified", None
    try:
        expiry = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
        days_left = (expiry - datetime.now(timezone.utc)).days
        if days_left < 0:
            return "expired", days_left
        if days_left <= 14:
            return "expiring_soon", days_left
        return "valid", days_left
    except (ValueError, AttributeError):
        return "unknown", None


def _ack_subq(tenant_id: str, engagement_id: str) -> Any:
    """Subquery returning correlation_ids of acknowledged events (exclusion filter)."""
    return select(FaTimDriftEvent.correlation_id).where(
        FaTimDriftEvent.tenant_id == tenant_id,
        FaTimDriftEvent.engagement_id == engagement_id,
        FaTimDriftEvent.status == "acknowledged",
        FaTimDriftEvent.correlation_id.isnot(None),
    )


def _drift_to_dict(row: FaTimDriftEvent) -> dict[str, Any]:
    return {
        "event_id": row.id,
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
    }


def _cert_to_dict(row: FaTrustCertification) -> dict[str, Any]:
    expiry_status, days_remaining = _cert_expiry_status(row.valid_until)
    return {
        "certification_id": row.id,
        "certification_level": row.certification_level,
        "composite_score": row.composite_score,
        "trust_score": row.trust_score,
        "confidence_score": row.confidence_score,
        "scored_by": row.scored_by,
        "valid_from": row.valid_from,
        "valid_until": row.valid_until,
        "expiry_status": expiry_status,
        "days_remaining": days_remaining,
        "authority_version": row.authority_version,
        "schema_version": row.schema_version,
    }


def _snap_to_dict(row: FaTimTrustSnapshot) -> dict[str, Any]:
    return {
        "snapshot_id": row.id,
        "posture_score": row.posture_score,
        "posture_level": row.posture_level,
        "risk_level": row.risk_level,
        "certification_level": row.certification_level,
        "composite_score": row.composite_score,
        "drift_score": row.drift_score,
        "drift_direction": row.drift_direction,
        "open_drift_count": row.open_drift_count,
        "evidence_count": row.evidence_count,
        "replay_status": row.replay_status,
        "source_fingerprint": row.source_fingerprint,
        "last_snapshot_id": row.last_snapshot_id,
        "last_certification_id": row.last_certification_id,
        "last_bundle_id": row.last_bundle_id,
        "evaluated_at": row.evaluated_at,
    }


def _compute_trend_windows(
    db: Any, *, tenant_id: str, engagement_id: str
) -> dict[str, Any]:
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
            wrows = [r for r in rows if r.evaluated_at >= cutoff]
            if len(wrows) < 2:
                return {
                    "days": days,
                    "direction": "insufficient_data",
                    "data_points": len(wrows),
                }
            s, e = wrows[0].posture_score, wrows[-1].posture_score
            delta = e - s
            if delta >= 10:
                direction = "improving"
            elif delta <= -20:
                direction = "rapidly_degrading"
            elif delta <= -5:
                direction = "degrading"
            else:
                direction = "stable"
            return {
                "days": days,
                "start_score": s,
                "end_score": e,
                "net_delta": delta,
                "direction": direction,
                "data_points": len(wrows),
            }

        return {"7d": _window(7), "30d": _window(30), "90d": _window(90)}
    except Exception:
        _ins = {"direction": "insufficient_data", "data_points": 0}
        return {
            "7d": {**_ins, "days": 7},
            "30d": {**_ins, "days": 30},
            "90d": {**_ins, "days": 90},
        }


# ---------------------------------------------------------------------------
# Tenant-level: GET /etcc/overview
# ---------------------------------------------------------------------------


@router.get(
    "/etcc/overview",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.executive.dashboard")),
    ],
    summary="Tenant-level overview of all engagement trust postures",
)
def get_etcc_overview(
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    limit: int = Query(default=50, le=200),
) -> dict[str, Any]:
    """Return the latest TIM posture snapshot for every engagement in the tenant.

    Ordered by posture_score ascending (lowest — most at-risk — first).
    Enables an executive to immediately see which engagements need attention.
    """
    from services.executive_trust.posture_service import get_tenant_overview  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)
    engagements = get_tenant_overview(db, tenant_id=tenant_id, limit=limit)
    return {
        "tenant_id": tenant_id,
        "engagements": engagements,
        "count": len(engagements),
    }


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/etcc/posture
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/etcc/posture",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.executive.dashboard")),
    ],
    summary="Full executive trust posture for an engagement",
)
def get_etcc_posture(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Return a single unified executive posture view for this engagement.

    Aggregates: current trust posture, certification health, risk summary,
    monitoring state, and 7d/30d/90d trend windows.  No synthesis — all
    values trace back to TIM snapshots, certifications, and drift events.
    """
    from services.executive_trust.posture_service import get_executive_posture  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)
    posture = get_executive_posture(
        db, tenant_id=tenant_id, engagement_id=engagement_id
    )
    if not posture:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no TIM data found for this engagement",
        )
    return posture


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/etcc/trends
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/etcc/trends",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.executive.dashboard")),
    ],
    summary="Trust trend windows (7d / 30d / 90d) from TIM snapshot history",
)
def get_etcc_trends(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Return posture trend windows derived from TIM snapshot history.

    Each window reports: start_score, end_score, net_delta, direction,
    and data_points.  Direction: improving / stable / degrading /
    rapidly_degrading / insufficient_data.
    """
    tenant_id = _resolve_caller_tenant(request)
    windows = _compute_trend_windows(
        db, tenant_id=tenant_id, engagement_id=engagement_id
    )
    return {"engagement_id": engagement_id, "trend_windows": windows}


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/etcc/risks
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/etcc/risks",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.risk")),
    ],
    summary="Executive risk surface — all open drift events with risk rollup",
)
def get_etcc_risks(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    min_severity: str = Query(
        default="info",
        description="Minimum severity filter (info/low/medium/high/critical)",
    ),
    limit: int = Query(default=100, le=500),
) -> dict[str, Any]:
    """Return all open unacknowledged drift events plus an executive risk rollup.

    Every event links to evidence and the TIM snapshot that triggered it,
    enabling full trace from risk → evidence without leaving the API.
    """
    tenant_id = _resolve_caller_tenant(request)

    _severity_order = ["info", "low", "medium", "high", "critical"]
    min_idx = (
        _severity_order.index(min_severity) if min_severity in _severity_order else 0
    )
    included_severities = _severity_order[min_idx:]

    ack_sq = _ack_subq(tenant_id, engagement_id)
    rows = (
        db.execute(
            select(FaTimDriftEvent)
            .where(
                FaTimDriftEvent.tenant_id == tenant_id,
                FaTimDriftEvent.engagement_id == engagement_id,
                FaTimDriftEvent.status == "open",
                FaTimDriftEvent.severity.in_(included_severities),
                ~FaTimDriftEvent.id.in_(ack_sq),
            )
            .order_by(FaTimDriftEvent.detected_at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )

    # Risk rollup across ALL open unacknowledged events (not just the page)
    all_open = (
        db.execute(
            select(FaTimDriftEvent).where(
                FaTimDriftEvent.tenant_id == tenant_id,
                FaTimDriftEvent.engagement_id == engagement_id,
                FaTimDriftEvent.status == "open",
                ~FaTimDriftEvent.id.in_(ack_sq),
            )
        )
        .scalars()
        .all()
    )
    risk_score = sum(_risk_weight(e.severity) for e in all_open)

    severity_counts: dict[str, int] = {}
    for e in all_open:
        severity_counts[e.severity] = severity_counts.get(e.severity, 0) + 1

    return {
        "engagement_id": engagement_id,
        "min_severity": min_severity,
        "risk_events": [_drift_to_dict(r) for r in rows],
        "risk_event_count": len(rows),
        "engagement_risk_score": risk_score,
        "total_open_count": len(all_open),
        "critical_count": severity_counts.get("critical", 0),
        "high_count": severity_counts.get("high", 0),
        "medium_count": severity_counts.get("medium", 0),
        "low_count": severity_counts.get("low", 0),
        "info_count": severity_counts.get("info", 0),
        "has_critical": severity_counts.get("critical", 0) > 0,
        "has_high": severity_counts.get("high", 0) > 0,
    }


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/etcc/certification
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/etcc/certification",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.certification")),
    ],
    summary="Active trust certification with expiry metadata and evidence linkage",
)
def get_etcc_certification(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Return the active trust certification with expiry status and ledger linkage.

    Links to the trust intelligence ledger entry for auditor verification.
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
            "ledger_entry": None,
        }

    cert_dict = _cert_to_dict(cert)

    # Ledger entry linked to the certification's trust intelligence snapshot
    ledger = db.execute(
        select(FaTrustIntelligenceLedger)
        .where(
            FaTrustIntelligenceLedger.tenant_id == tenant_id,
            FaTrustIntelligenceLedger.engagement_id == engagement_id,
        )
        .order_by(FaTrustIntelligenceLedger.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    ledger_entry = (
        {
            "ledger_id": ledger.id,
            "snapshot_id": ledger.snapshot_id,
            "snapshot_hash": ledger.snapshot_hash,
            "posture_level": ledger.posture_level,
            "posture_score": ledger.posture_score,
            "ledger_entry_hash": ledger.ledger_entry_hash,
            "timestamp": ledger.timestamp,
        }
        if ledger
        else None
    )

    return {
        "engagement_id": engagement_id,
        "certification_level": cert.certification_level,
        "expiry_status": cert_dict["expiry_status"],
        "days_remaining": cert_dict["days_remaining"],
        "certification": cert_dict,
        "ledger_entry": ledger_entry,
    }


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/etcc/certification/history
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/etcc/certification/history",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.certification")),
    ],
    summary="Full trust certification history (append-only audit trail)",
)
def get_etcc_certification_history(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    limit: int = Query(default=20, le=100),
) -> dict[str, Any]:
    """Return the full certification history for an engagement, newest first.

    Each row is an immutable certification record — never mutated, never deleted.
    """
    tenant_id = _resolve_caller_tenant(request)

    rows = (
        db.execute(
            select(FaTrustCertification)
            .where(
                FaTrustCertification.tenant_id == tenant_id,
                FaTrustCertification.engagement_id == engagement_id,
            )
            .order_by(FaTrustCertification.valid_from.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )

    return {
        "engagement_id": engagement_id,
        "certifications": [_cert_to_dict(r) for r in rows],
        "count": len(rows),
    }


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/etcc/monitoring
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/etcc/monitoring",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("continuous.monitoring")),
    ],
    summary="TIM monitoring health — last evaluation, failures, coverage",
)
def get_etcc_monitoring(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    limit: int = Query(default=10, le=50),
) -> dict[str, Any]:
    """Return TIM monitoring health for an engagement.

    Includes last evaluation, replay status, evaluation failures from the
    governance timeline, and recent snapshot history.
    """
    from api.db_models_timeline import TimelineEventRecord  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)

    latest_snap = db.execute(
        select(FaTimTrustSnapshot)
        .where(
            FaTimTrustSnapshot.tenant_id == tenant_id,
            FaTimTrustSnapshot.engagement_id == engagement_id,
        )
        .order_by(FaTimTrustSnapshot.evaluated_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    # Recent evaluation history
    recent_snaps = db.execute(
        select(
            FaTimTrustSnapshot.id,
            FaTimTrustSnapshot.evaluated_at,
            FaTimTrustSnapshot.posture_score,
            FaTimTrustSnapshot.drift_direction,
            FaTimTrustSnapshot.open_drift_count,
            FaTimTrustSnapshot.replay_status,
        )
        .where(
            FaTimTrustSnapshot.tenant_id == tenant_id,
            FaTimTrustSnapshot.engagement_id == engagement_id,
        )
        .order_by(FaTimTrustSnapshot.evaluated_at.desc())
        .limit(limit)
    ).all()

    # Evaluation failures from timeline: total count + limited detail list
    _failure_where = [
        TimelineEventRecord.tenant_id == tenant_id,
        TimelineEventRecord.source_type == "trust_monitoring",
        TimelineEventRecord.event_type == "tim_evaluation_failed",
    ]
    _failure_filter = (
        TimelineEventRecord.payload["engagement_id"].as_string() == engagement_id
    )
    total_failure_count = (
        db.execute(
            select(func.count())
            .select_from(TimelineEventRecord)
            .where(*_failure_where)
            .filter(_failure_filter)
        ).scalar()
        or 0
    )
    failure_events = (
        db.execute(
            select(TimelineEventRecord)
            .where(*_failure_where)
            .filter(_failure_filter)
            .order_by(TimelineEventRecord.occurred_at.desc())
            .limit(5)
        )
        .scalars()
        .all()
    )

    # Latest reconstruction record
    reconstruction = db.execute(
        select(FaDecisionReconstructionRecord)
        .where(
            FaDecisionReconstructionRecord.tenant_id == tenant_id,
            FaDecisionReconstructionRecord.engagement_id == engagement_id,
        )
        .order_by(FaDecisionReconstructionRecord.generated_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    return {
        "engagement_id": engagement_id,
        "health": {
            "last_evaluated_at": latest_snap.evaluated_at if latest_snap else None,
            "replay_status": latest_snap.replay_status if latest_snap else "no_chain",
            "last_posture_score": latest_snap.posture_score if latest_snap else None,
            "last_drift_direction": latest_snap.drift_direction
            if latest_snap
            else None,
            "open_drift_count": latest_snap.open_drift_count if latest_snap else 0,
            "evidence_count": latest_snap.evidence_count if latest_snap else 0,
            "evaluation_failure_count": total_failure_count,
            "has_failures": total_failure_count > 0,
        },
        "reconstruction": {
            "record_id": reconstruction.id if reconstruction else None,
            "replay_valid": reconstruction.replay_valid if reconstruction else None,
            "total_decisions": reconstruction.total_decisions if reconstruction else 0,
            "generated_at": reconstruction.generated_at if reconstruction else None,
        },
        "recent_evaluations": [
            {
                "snapshot_id": r.id,
                "evaluated_at": r.evaluated_at,
                "posture_score": r.posture_score,
                "drift_direction": r.drift_direction,
                "open_drift_count": r.open_drift_count,
                "replay_status": r.replay_status,
            }
            for r in recent_snaps
        ],
        "evaluation_failures": [
            {
                "event_id": e.id,
                "occurred_at": e.occurred_at,
                "payload": e.payload
                if isinstance(e.payload, dict)
                else _load_json(e.payload),
            }
            for e in failure_events
        ],
    }


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/etcc/timeline
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/etcc/timeline",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.executive.dashboard")),
        Depends(require_capability("trust.timeline")),
    ],
    summary="Unified trust governance activity feed (filterable, chronological)",
)
def get_etcc_timeline(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    source_type: str | None = Query(
        default=None,
        description="Filter by source_type (trust_arc, trust_monitoring, verification_bundle)",
    ),
    event_type: str | None = Query(default=None, description="Filter by event_type"),
    since: str | None = Query(
        default=None, description="ISO timestamp — return events after this date"
    ),
    limit: int = Query(default=50, le=200),
) -> dict[str, Any]:
    """Return the governance timeline for an engagement.

    Answers: What changed? When? Why? Who?

    Sources: trust_arc, trust_monitoring, verification_bundle.
    Actor types: human | agent | system | workflow — all supported by schema.
    Filter with source_type, event_type, or since for targeted drilldowns.
    """
    from api.db_models_timeline import TimelineEventRecord  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)

    q = (
        select(TimelineEventRecord)
        .where(TimelineEventRecord.tenant_id == tenant_id)
        .filter(
            TimelineEventRecord.payload["engagement_id"].as_string() == engagement_id
        )
    )
    if source_type:
        q = q.where(TimelineEventRecord.source_type == source_type)
    if event_type:
        q = q.where(TimelineEventRecord.event_type == event_type)
    if since:
        q = q.where(TimelineEventRecord.occurred_at >= since)
    q = q.order_by(TimelineEventRecord.occurred_at.desc()).limit(limit)

    rows = db.execute(q).scalars().all()

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
    return {
        "engagement_id": engagement_id,
        "filters": {
            "source_type": source_type,
            "event_type": event_type,
            "since": since,
        },
        "events": events,
        "count": len(events),
    }


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/etcc/decisions
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/etcc/decisions",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.memory")),
    ],
    summary="Trust decision memory — governance decisions with full reasoning",
)
def get_etcc_decisions(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    entity_type: str | None = Query(
        default=None,
        description="Filter by entity_type (human, agent, autonomous_system, agi)",
    ),
    limit: int = Query(default=50, le=200),
) -> dict[str, Any]:
    """Return trust decision memory records for an engagement.

    Each record contains decision reasoning, supporting intelligence, and
    supporting evidence — enabling full auditability of every governance
    decision without re-running analysis.

    entity_type values: human | agent | autonomous_system | agi
    (schema supports future governed entity types without code changes).
    """
    tenant_id = _resolve_caller_tenant(request)

    q = select(FaTrustDecisionMemory).where(
        FaTrustDecisionMemory.tenant_id == tenant_id,
        FaTrustDecisionMemory.engagement_id == engagement_id,
    )
    if entity_type:
        q = q.where(FaTrustDecisionMemory.entity_type == entity_type)
    q = q.order_by(FaTrustDecisionMemory.created_at.desc()).limit(limit)

    rows = db.execute(q).scalars().all()

    decisions = [
        {
            "decision_id": r.id,
            "decision_type": r.decision_type,
            "entity_type": r.entity_type,
            "decision_reasoning": _load_json(r.decision_reasoning),
            "supporting_intelligence": _load_json(r.supporting_intelligence),
            "supporting_evidence": _load_json(r.supporting_evidence),
            "authority_version": r.authority_version,
            "created_at": r.created_at,
            "schema_version": r.schema_version,
        }
        for r in rows
    ]
    return {
        "engagement_id": engagement_id,
        "entity_type_filter": entity_type,
        "decisions": decisions,
        "count": len(decisions),
    }


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/etcc/drilldown/drift/{event_id}
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/etcc/drilldown/drift/{event_id}",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.executive.drilldown")),
    ],
    summary="Drilldown: drift event → evidence → linked TIM snapshot",
)
def get_etcc_drilldown_drift(
    engagement_id: str,
    event_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Full drilldown path for a drift event.

    Returns the drift event, its structured evidence, and the TIM trust
    snapshot at the time of detection.  Enables the trace:

      Risk → Drift Event → Evidence → Trust Snapshot → Certification
    """
    tenant_id = _resolve_caller_tenant(request)

    event = db.execute(
        select(FaTimDriftEvent).where(
            FaTimDriftEvent.tenant_id == tenant_id,
            FaTimDriftEvent.engagement_id == engagement_id,
            FaTimDriftEvent.id == event_id,
        )
    ).scalar_one_or_none()

    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="drift event not found",
        )

    # TIM snapshot at time of detection (nearest snapshot before/at detected_at)
    source_snap = None
    if event.correlation_id:
        source_snap = db.execute(
            select(FaTimTrustSnapshot).where(
                FaTimTrustSnapshot.tenant_id == tenant_id,
                FaTimTrustSnapshot.id == event.correlation_id,
            )
        ).scalar_one_or_none()

    # If no direct link, find the snapshot evaluated just before detected_at
    if source_snap is None:
        source_snap = db.execute(
            select(FaTimTrustSnapshot)
            .where(
                FaTimTrustSnapshot.tenant_id == tenant_id,
                FaTimTrustSnapshot.engagement_id == engagement_id,
                FaTimTrustSnapshot.evaluated_at <= event.detected_at,
            )
            .order_by(FaTimTrustSnapshot.evaluated_at.desc())
            .limit(1)
        ).scalar_one_or_none()

    return {
        "engagement_id": engagement_id,
        "drift_event": _drift_to_dict(event),
        "source_snapshot": _snap_to_dict(source_snap) if source_snap else None,
        "trace": {
            "rule": event.drift_rule,
            "evidence": _load_json(event.evidence),
            "detected_at": event.detected_at,
            "snapshot_id": source_snap.id if source_snap else None,
            "snapshot_evaluated_at": source_snap.evaluated_at if source_snap else None,
        },
    }


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/etcc/drilldown/certification/{cert_id}
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/etcc/drilldown/certification/{cert_id}",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.executive.drilldown")),
    ],
    summary="Drilldown: certification → chain of custody → reconstruction record",
)
def get_etcc_drilldown_certification(
    engagement_id: str,
    cert_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Full drilldown path for a trust certification.

    Returns the certification, associated ledger entry, latest chain of
    custody record, and the decision reconstruction record.

      Certification → Ledger Entry → Chain of Custody → Reconstruction
    """
    tenant_id = _resolve_caller_tenant(request)

    cert = db.execute(
        select(FaTrustCertification).where(
            FaTrustCertification.tenant_id == tenant_id,
            FaTrustCertification.engagement_id == engagement_id,
            FaTrustCertification.id == cert_id,
        )
    ).scalar_one_or_none()

    if cert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="certification not found",
        )

    # Latest ledger entry as of certification valid_from
    ledger = db.execute(
        select(FaTrustIntelligenceLedger)
        .where(
            FaTrustIntelligenceLedger.tenant_id == tenant_id,
            FaTrustIntelligenceLedger.engagement_id == engagement_id,
            FaTrustIntelligenceLedger.timestamp <= cert.valid_from,
        )
        .order_by(FaTrustIntelligenceLedger.timestamp.desc())
        .limit(1)
    ).scalar_one_or_none()

    # Latest chain of custody
    custody = db.execute(
        select(FaChainOfCustodyRecord)
        .where(
            FaChainOfCustodyRecord.tenant_id == tenant_id,
            FaChainOfCustodyRecord.engagement_id == engagement_id,
        )
        .order_by(FaChainOfCustodyRecord.sequence.desc())
        .limit(1)
    ).scalar_one_or_none()

    # Decision reconstruction record
    reconstruction = db.execute(
        select(FaDecisionReconstructionRecord)
        .where(
            FaDecisionReconstructionRecord.tenant_id == tenant_id,
            FaDecisionReconstructionRecord.engagement_id == engagement_id,
        )
        .order_by(FaDecisionReconstructionRecord.generated_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    return {
        "engagement_id": engagement_id,
        "certification": _cert_to_dict(cert),
        "ledger_entry": (
            {
                "ledger_id": ledger.id,
                "snapshot_id": ledger.snapshot_id,
                "snapshot_hash": ledger.snapshot_hash,
                "ledger_entry_hash": ledger.ledger_entry_hash,
                "posture_level": ledger.posture_level,
                "posture_score": ledger.posture_score,
                "timestamp": ledger.timestamp,
            }
            if ledger
            else None
        ),
        "chain_of_custody": (
            {
                "record_id": custody.id,
                "sequence": custody.sequence,
                "event_type": custody.event_type,
                "entity_type": custody.entity_type,
                "description": custody.description,
                "timestamp": custody.timestamp,
                "custody_hash": custody.custody_hash,
            }
            if custody
            else None
        ),
        "reconstruction": (
            {
                "record_id": reconstruction.id,
                "replay_valid": reconstruction.replay_valid,
                "total_decisions": reconstruction.total_decisions,
                "generated_at": reconstruction.generated_at,
            }
            if reconstruction
            else None
        ),
    }


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/etcc/reports/summary
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/etcc/reports/summary",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.reporting")),
    ],
    summary="Executive trust summary report (P0-9 reporting foundation)",
)
def get_etcc_report_summary(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Return a comprehensive executive trust summary.

    Aggregates: posture, certification, risk rollup, trend windows, monitoring
    health, and drift rule breakdown.  Designed to answer board-level questions
    about trust posture without requiring technical navigation.

    This API becomes the data source for P0-9 Quarterly Trust Briefs.
    """
    from services.executive_trust.posture_service import get_executive_posture  # noqa: PLC0415

    tenant_id = _resolve_caller_tenant(request)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    posture = get_executive_posture(
        db, tenant_id=tenant_id, engagement_id=engagement_id
    )

    # Drift rule breakdown across all open unacknowledged events
    ack_sq = _ack_subq(tenant_id, engagement_id)
    all_open = (
        db.execute(
            select(FaTimDriftEvent).where(
                FaTimDriftEvent.tenant_id == tenant_id,
                FaTimDriftEvent.engagement_id == engagement_id,
                FaTimDriftEvent.status == "open",
                ~FaTimDriftEvent.id.in_(ack_sq),
            )
        )
        .scalars()
        .all()
    )
    rule_breakdown: dict[str, int] = {}
    for e in all_open:
        rule_breakdown[e.drift_rule] = rule_breakdown.get(e.drift_rule, 0) + 1

    # Snapshot count (depth of monitoring history)
    snap_count = (
        db.execute(
            select(func.count()).where(
                FaTimTrustSnapshot.tenant_id == tenant_id,
                FaTimTrustSnapshot.engagement_id == engagement_id,
            )
        ).scalar()
        or 0
    )

    return {
        "report_type": "executive_trust_summary",
        "engagement_id": engagement_id,
        "generated_at": now_iso,
        "posture": posture.get("trust_posture", {}),
        "certification": posture.get("certification", {}),
        "risk": posture.get("risk", {}),
        "monitoring": posture.get("monitoring", {}),
        "trend_windows": posture.get("trend_windows", {}),
        "drift_rule_breakdown": rule_breakdown,
        "monitoring_depth": {
            "total_snapshots": snap_count,
        },
        "governance_readiness": {
            "actor_types": ["human", "agent", "workflow", "system"],
            "append_only": True,
            "rls_enforced": True,
            "replay_eligible": True,
        },
    }


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/etcc/reports/quarterly
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/etcc/reports/quarterly",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.reporting")),
    ],
    summary="Quarterly trust summary (date-bounded — P0-9 foundation)",
)
def get_etcc_report_quarterly(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    year: int = Query(..., description="Year (e.g. 2026)"),
    quarter: int = Query(..., ge=1, le=4, description="Quarter (1–4)"),
) -> dict[str, Any]:
    """Return a date-bounded trust summary for a calendar quarter.

    Computes: posture range (min/max/avg score), drift events generated,
    certifications issued, and trend direction within the quarter window.

    This API is the data foundation for P0-9 Quarterly Trust Briefs.
    """
    tenant_id = _resolve_caller_tenant(request)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    q_start_month = (quarter - 1) * 3 + 1
    period_start = f"{year}-{q_start_month:02d}-01T00:00:00Z"
    if quarter == 4:
        period_end = f"{year + 1}-01-01T00:00:00Z"
    else:
        end_month = q_start_month + 3
        period_end = f"{year}-{end_month:02d}-01T00:00:00Z"

    # Snapshots in window
    snaps = (
        db.execute(
            select(FaTimTrustSnapshot)
            .where(
                FaTimTrustSnapshot.tenant_id == tenant_id,
                FaTimTrustSnapshot.engagement_id == engagement_id,
                FaTimTrustSnapshot.evaluated_at >= period_start,
                FaTimTrustSnapshot.evaluated_at < period_end,
            )
            .order_by(FaTimTrustSnapshot.evaluated_at.asc())
        )
        .scalars()
        .all()
    )

    scores = [s.posture_score for s in snaps]
    directions = [s.drift_direction for s in snaps]

    # Drift events in window
    drift_events = (
        db.execute(
            select(FaTimDriftEvent).where(
                FaTimDriftEvent.tenant_id == tenant_id,
                FaTimDriftEvent.engagement_id == engagement_id,
                FaTimDriftEvent.detected_at >= period_start,
                FaTimDriftEvent.detected_at < period_end,
                FaTimDriftEvent.status == "open",
            )
        )
        .scalars()
        .all()
    )

    # Certifications issued in window
    certs = (
        db.execute(
            select(FaTrustCertification).where(
                FaTrustCertification.tenant_id == tenant_id,
                FaTrustCertification.engagement_id == engagement_id,
                FaTrustCertification.valid_from >= period_start,
                FaTrustCertification.valid_from < period_end,
            )
        )
        .scalars()
        .all()
    )

    severity_counts: dict[str, int] = {}
    for e in drift_events:
        severity_counts[e.severity] = severity_counts.get(e.severity, 0) + 1

    return {
        "report_type": "quarterly_trust_summary",
        "engagement_id": engagement_id,
        "period": {
            "year": year,
            "quarter": quarter,
            "start": period_start,
            "end": period_end,
        },
        "generated_at": now_iso,
        "posture": {
            "snapshots_evaluated": len(snaps),
            "min_score": min(scores) if scores else None,
            "max_score": max(scores) if scores else None,
            "avg_score": round(sum(scores) / len(scores), 1) if scores else None,
            "start_score": scores[0] if scores else None,
            "end_score": scores[-1] if scores else None,
            "net_delta": (scores[-1] - scores[0]) if len(scores) >= 2 else None,
            "degrading_snapshots": sum(
                1 for d in directions if d in {"degrading", "rapidly_degrading"}
            ),
            "improving_snapshots": sum(1 for d in directions if d == "improving"),
        },
        "drift": {
            "total_events": len(drift_events),
            "by_severity": severity_counts,
            "critical_count": severity_counts.get("critical", 0),
            "high_count": severity_counts.get("high", 0),
        },
        "certification": {
            "certifications_issued": len(certs),
            "levels_issued": [c.certification_level for c in certs],
        },
    }


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/etcc/reports/drift
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/etcc/reports/drift",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.reporting")),
    ],
    summary="Drift history report with rule breakdown and statistics",
)
def get_etcc_report_drift(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    limit: int = Query(default=100, le=500),
) -> dict[str, Any]:
    """Return the full drift event history with rule and severity statistics.

    Covers all drift events (open + resolved + acknowledged) for complete
    audit trail.  Rule breakdown shows which conditions fire most frequently.
    """
    tenant_id = _resolve_caller_tenant(request)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    _base_where = [
        FaTimDriftEvent.tenant_id == tenant_id,
        FaTimDriftEvent.engagement_id == engagement_id,
    ]

    # Aggregate stats over the full dataset (not the paginated slice)
    total_count = db.execute(select(func.count()).where(*_base_where)).scalar() or 0

    rule_rows = db.execute(
        select(FaTimDriftEvent.drift_rule, func.count().label("cnt"))
        .where(*_base_where)
        .group_by(FaTimDriftEvent.drift_rule)
    ).all()
    rule_counts = {r.drift_rule: r.cnt for r in rule_rows}

    severity_rows = db.execute(
        select(FaTimDriftEvent.severity, func.count().label("cnt"))
        .where(*_base_where)
        .group_by(FaTimDriftEvent.severity)
    ).all()
    severity_counts = {r.severity: r.cnt for r in severity_rows}

    status_rows = db.execute(
        select(FaTimDriftEvent.status, func.count().label("cnt"))
        .where(*_base_where)
        .group_by(FaTimDriftEvent.status)
    ).all()
    status_counts = {r.status: r.cnt for r in status_rows}

    # Paginated event list (newest first)
    rows = (
        db.execute(
            select(FaTimDriftEvent)
            .where(*_base_where)
            .order_by(FaTimDriftEvent.detected_at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )

    return {
        "report_type": "drift_history",
        "engagement_id": engagement_id,
        "generated_at": now_iso,
        "total_events": total_count,
        "by_rule": rule_counts,
        "by_severity": severity_counts,
        "by_status": status_counts,
        "events": [_drift_to_dict(r) for r in rows],
    }


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/etcc/reports/risk
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/etcc/reports/risk",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.reporting")),
    ],
    summary="Risk posture breakdown report",
)
def get_etcc_report_risk(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Return a structured risk posture report for executive and board review.

    Computes: engagement_risk_score, severity breakdown, rule breakdown,
    and acknowledgement status across all open drift events.

    engagement_risk_score = sum of severity weights across open unacknowledged events.
    Weights: info=0, low=1, medium=3, high=7, critical=15.
    """
    tenant_id = _resolve_caller_tenant(request)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    ack_sq = _ack_subq(tenant_id, engagement_id)

    open_events = (
        db.execute(
            select(FaTimDriftEvent).where(
                FaTimDriftEvent.tenant_id == tenant_id,
                FaTimDriftEvent.engagement_id == engagement_id,
                FaTimDriftEvent.status == "open",
                ~FaTimDriftEvent.id.in_(ack_sq),
            )
        )
        .scalars()
        .all()
    )

    acked_count = (
        db.execute(
            select(func.count()).where(
                FaTimDriftEvent.tenant_id == tenant_id,
                FaTimDriftEvent.engagement_id == engagement_id,
                FaTimDriftEvent.status == "acknowledged",
            )
        ).scalar()
        or 0
    )

    risk_score = sum(_risk_weight(e.severity) for e in open_events)
    severity_counts: dict[str, int] = {}
    rule_counts: dict[str, int] = {}
    for e in open_events:
        severity_counts[e.severity] = severity_counts.get(e.severity, 0) + 1
        rule_counts[e.drift_rule] = rule_counts.get(e.drift_rule, 0) + 1

    return {
        "report_type": "risk_posture",
        "engagement_id": engagement_id,
        "generated_at": now_iso,
        "engagement_risk_score": risk_score,
        "open_event_count": len(open_events),
        "acknowledged_count": acked_count,
        "by_severity": severity_counts,
        "by_rule": rule_counts,
        "has_critical": severity_counts.get("critical", 0) > 0,
        "has_high": severity_counts.get("high", 0) > 0,
        "severity_weights": _SEVERITY_WEIGHT,
        "open_events": [_drift_to_dict(e) for e in open_events],
    }
