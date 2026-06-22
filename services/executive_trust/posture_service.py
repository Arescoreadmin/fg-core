"""P0-8: Executive Trust Posture Service.

Aggregates existing TIM and Trust Arc data sources into executive-facing
views.  All reads are from existing append-only tables.  No new trust
engines.  No synthetic scoring.  No AI.

Callers own the DB session.  All functions return empty structures on error.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

log = logging.getLogger("frostgate.etcc.posture")

_SEVERITY_WEIGHT: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 3,
    "high": 7,
    "critical": 15,
}


def _load_json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return {}
    return value or {}


def _cert_expiry_status(valid_until: str | None) -> tuple[str, int | None]:
    """Return (expiry_status, days_remaining) from a valid_until ISO string."""
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


def _open_unacknowledged_events(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
) -> list[Any]:
    from api.db_models_tim import FaTimDriftEvent  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

    ack_subq = select(FaTimDriftEvent.correlation_id).where(
        FaTimDriftEvent.tenant_id == tenant_id,
        FaTimDriftEvent.engagement_id == engagement_id,
        FaTimDriftEvent.status == "acknowledged",
        FaTimDriftEvent.correlation_id.isnot(None),
    )
    return (
        db.execute(
            select(FaTimDriftEvent).where(
                FaTimDriftEvent.tenant_id == tenant_id,
                FaTimDriftEvent.engagement_id == engagement_id,
                FaTimDriftEvent.status == "open",
                ~FaTimDriftEvent.id.in_(ack_subq),
            )
        )
        .scalars()
        .all()
    )


def _trend_windows(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
) -> dict[str, Any]:
    """Compute 7d/30d/90d posture trend windows from TIM snapshot history."""
    from api.db_models_tim import FaTimTrustSnapshot  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

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


def get_executive_posture(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
) -> dict[str, Any]:
    """Aggregate full executive trust posture for one engagement.

    Reads: FaTimTrustSnapshot (latest), FaTimDriftEvent (open unacknowledged),
    FaTrustCertification (latest).  Pure read.  Returns empty dict on error.
    """
    from api.db_models_tim import FaTimTrustSnapshot  # noqa: PLC0415
    from api.db_models_trust_arc import FaTrustCertification  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

    try:
        snap = db.execute(
            select(FaTimTrustSnapshot)
            .where(
                FaTimTrustSnapshot.tenant_id == tenant_id,
                FaTimTrustSnapshot.engagement_id == engagement_id,
            )
            .order_by(FaTimTrustSnapshot.evaluated_at.desc())
            .limit(1)
        ).scalar_one_or_none()

        cert = db.execute(
            select(FaTrustCertification)
            .where(
                FaTrustCertification.tenant_id == tenant_id,
                FaTrustCertification.engagement_id == engagement_id,
            )
            .order_by(FaTrustCertification.valid_from.desc())
            .limit(1)
        ).scalar_one_or_none()

        open_events = _open_unacknowledged_events(
            db, tenant_id=tenant_id, engagement_id=engagement_id
        )

        risk_score = sum(_SEVERITY_WEIGHT.get(e.severity, 0) for e in open_events)
        severity_counts: dict[str, int] = {}
        for e in open_events:
            severity_counts[e.severity] = severity_counts.get(e.severity, 0) + 1

        cert_expiry_status, days_remaining = _cert_expiry_status(
            cert.valid_until if cert else None
        )

        trend_windows = _trend_windows(
            db, tenant_id=tenant_id, engagement_id=engagement_id
        )

        return {
            "engagement_id": engagement_id,
            "trust_posture": {
                "posture_score": snap.posture_score if snap else 0,
                "posture_level": snap.posture_level if snap else "unknown",
                "risk_level": snap.risk_level if snap else "unknown",
                "drift_score": snap.drift_score if snap else 0,
                "drift_direction": snap.drift_direction if snap else "stable",
                "open_drift_count": len(open_events),
                "evidence_count": snap.evidence_count if snap else 0,
                "replay_status": snap.replay_status if snap else "no_chain",
                "evaluated_at": snap.evaluated_at if snap else None,
                "source_fingerprint": snap.source_fingerprint if snap else None,
                "last_snapshot_id": snap.last_snapshot_id if snap else None,
            },
            "certification": {
                "certification_level": (
                    cert.certification_level if cert else "not_certified"
                ),
                "composite_score": cert.composite_score if cert else 0,
                "trust_score": cert.trust_score if cert else 0,
                "confidence_score": cert.confidence_score if cert else 0,
                "expiry_status": cert_expiry_status,
                "days_remaining": days_remaining,
                "valid_from": cert.valid_from if cert else None,
                "valid_until": cert.valid_until if cert else None,
                "authority_version": cert.authority_version if cert else None,
                "certification_id": cert.id if cert else None,
            },
            "risk": {
                "engagement_risk_score": risk_score,
                "open_event_count": len(open_events),
                "critical_count": severity_counts.get("critical", 0),
                "high_count": severity_counts.get("high", 0),
                "medium_count": severity_counts.get("medium", 0),
                "low_count": severity_counts.get("low", 0),
                "info_count": severity_counts.get("info", 0),
                "has_critical": severity_counts.get("critical", 0) > 0,
                "has_high": severity_counts.get("high", 0) > 0,
            },
            "monitoring": {
                "last_evaluated_at": snap.evaluated_at if snap else None,
                "last_snapshot_id": snap.id if snap else None,
                "last_certification_id": snap.last_certification_id if snap else None,
                "last_bundle_id": snap.last_bundle_id if snap else None,
            },
            "trend_windows": trend_windows,
        }
    except Exception:
        log.exception(
            "etcc.posture: failed tenant=%s engagement=%s",
            tenant_id,
            engagement_id,
        )
        return {}


def get_tenant_overview(
    db: Any,
    *,
    tenant_id: str,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Return a posture summary row for each engagement the tenant has TIM data for.

    Ordered by posture_score ascending (highest risk first).
    Returns empty list on error.
    """
    from api.db_models_tim import FaTimTrustSnapshot  # noqa: PLC0415
    from sqlalchemy import select, func  # noqa: PLC0415

    try:
        # Subquery: latest evaluated_at + max id (tie-breaker) per engagement
        latest_subq = (
            select(
                FaTimTrustSnapshot.engagement_id,
                func.max(FaTimTrustSnapshot.evaluated_at).label("max_eval"),
                func.max(FaTimTrustSnapshot.id).label("max_id"),
            )
            .where(FaTimTrustSnapshot.tenant_id == tenant_id)
            .group_by(FaTimTrustSnapshot.engagement_id)
            .subquery()
        )

        rows = (
            db.execute(
                select(FaTimTrustSnapshot)
                .join(
                    latest_subq,
                    (FaTimTrustSnapshot.engagement_id == latest_subq.c.engagement_id)
                    & (FaTimTrustSnapshot.evaluated_at == latest_subq.c.max_eval)
                    & (FaTimTrustSnapshot.id == latest_subq.c.max_id),
                )
                .where(FaTimTrustSnapshot.tenant_id == tenant_id)
                .order_by(FaTimTrustSnapshot.posture_score.asc())
                .limit(limit)
            )
            .scalars()
            .all()
        )

        return [
            {
                "engagement_id": r.engagement_id,
                "posture_score": r.posture_score,
                "posture_level": r.posture_level,
                "risk_level": r.risk_level,
                "certification_level": r.certification_level,
                "drift_direction": r.drift_direction,
                "open_drift_count": r.open_drift_count,
                "replay_status": r.replay_status,
                "evaluated_at": r.evaluated_at,
            }
            for r in rows
        ]
    except Exception:
        log.exception("etcc.overview: failed tenant=%s", tenant_id)
        return []
