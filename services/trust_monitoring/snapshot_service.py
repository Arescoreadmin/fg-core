"""P0-7: TIM trust snapshot computation and persistence.

Aggregates the current trust state from existing Trust Arc sources
(FaTrustIntelligenceSnapshot, FaTrustCertification, FaEvidenceProvenance,
FaVerificationBundle) into a single FaTimTrustSnapshot row.

Append-only: each call creates a new row.  The most recent row per
(tenant_id, engagement_id) by evaluated_at is the live state.

Callers own the DB transaction; this module calls db.add() only.
Non-blocking: any error returns an empty dict.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("frostgate.tim.snapshot")

_TREND_DEGRADING = {"degrading", "rapidly_degrading"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _snap_id() -> str:
    return uuid.uuid4().hex


def _drift_direction(current: int, previous: int | None) -> str:
    if previous is None:
        return "stable"
    delta = current - previous
    if delta >= 10:
        return "improving"
    if delta <= -20:
        return "rapidly_degrading"
    if delta <= -5:
        return "degrading"
    return "stable"


def _drift_score(current: int, previous: int | None) -> int:
    if previous is None:
        return 0
    return max(0, previous - current)


def _open_drift_count(db: Any, *, tenant_id: str, engagement_id: str) -> int:
    from api.db_models_tim import FaTimDriftEvent  # noqa: PLC0415
    from sqlalchemy import func, select  # noqa: PLC0415

    try:
        result = db.execute(
            select(func.count()).where(
                FaTimDriftEvent.tenant_id == tenant_id,
                FaTimDriftEvent.engagement_id == engagement_id,
                FaTimDriftEvent.status == "open",
            )
        )
        return result.scalar() or 0
    except Exception:
        return 0


def _latest_trust_snapshot(db: Any, *, tenant_id: str, engagement_id: str) -> Any:
    from api.db_models_trust_arc import FaTrustIntelligenceSnapshot  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

    return db.execute(
        select(FaTrustIntelligenceSnapshot)
        .where(
            FaTrustIntelligenceSnapshot.tenant_id == tenant_id,
            FaTrustIntelligenceSnapshot.engagement_id == engagement_id,
        )
        .order_by(FaTrustIntelligenceSnapshot.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def _latest_certification(db: Any, *, tenant_id: str, engagement_id: str) -> Any:
    from api.db_models_trust_arc import FaTrustCertification  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

    return db.execute(
        select(FaTrustCertification)
        .where(
            FaTrustCertification.tenant_id == tenant_id,
            FaTrustCertification.engagement_id == engagement_id,
        )
        .order_by(FaTrustCertification.valid_from.desc())
        .limit(1)
    ).scalar_one_or_none()


def _evidence_count(db: Any, *, tenant_id: str, engagement_id: str) -> int:
    from api.db_models_field_assessment import FaEvidenceProvenance  # noqa: PLC0415
    from sqlalchemy import func, select  # noqa: PLC0415

    try:
        result = db.execute(
            select(func.count()).where(
                FaEvidenceProvenance.tenant_id == tenant_id,
                FaEvidenceProvenance.engagement_id == engagement_id,
            )
        )
        return result.scalar() or 0
    except Exception:
        return 0


def _last_evidence_at(db: Any, *, tenant_id: str, engagement_id: str) -> str | None:
    from api.db_models_field_assessment import FaEvidenceProvenance  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

    try:
        row = db.execute(
            select(FaEvidenceProvenance.created_at)
            .where(
                FaEvidenceProvenance.tenant_id == tenant_id,
                FaEvidenceProvenance.engagement_id == engagement_id,
            )
            .order_by(FaEvidenceProvenance.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        return row
    except Exception:
        return None


def _last_bundle_at(db: Any, *, tenant_id: str, engagement_id: str) -> str | None:
    from api.db_models_verification_bundle import FaVerificationBundle  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

    try:
        row = db.execute(
            select(FaVerificationBundle.generated_at)
            .where(
                FaVerificationBundle.tenant_id == tenant_id,
                FaVerificationBundle.engagement_id == engagement_id,
            )
            .order_by(FaVerificationBundle.generated_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        return row
    except Exception:
        return None


def _last_bundle_id(db: Any, *, tenant_id: str, engagement_id: str) -> str | None:
    from api.db_models_verification_bundle import FaVerificationBundle  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

    try:
        row = db.execute(
            select(FaVerificationBundle.id)
            .where(
                FaVerificationBundle.tenant_id == tenant_id,
                FaVerificationBundle.engagement_id == engagement_id,
            )
            .order_by(FaVerificationBundle.generated_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        return row
    except Exception:
        return None


def _compute_source_fingerprint(
    snapshot_id: str | None,
    cert_id: str | None,
    bundle_id: str | None,
) -> str:
    raw = json.dumps(
        {
            "snapshot_id": snapshot_id or "",
            "cert_id": cert_id or "",
            "bundle_id": bundle_id or "",
        },
        sort_keys=True,
    ).encode()
    return hashlib.sha256(raw).hexdigest()


def _previous_tim_snapshot(db: Any, *, tenant_id: str, engagement_id: str) -> Any:
    from api.db_models_tim import FaTimTrustSnapshot  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

    return db.execute(
        select(FaTimTrustSnapshot)
        .where(
            FaTimTrustSnapshot.tenant_id == tenant_id,
            FaTimTrustSnapshot.engagement_id == engagement_id,
        )
        .order_by(FaTimTrustSnapshot.evaluated_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def _recent_trend_directions(
    db: Any, *, tenant_id: str, engagement_id: str, limit: int = 5
) -> list[str]:
    from api.db_models_tim import FaTimTrustSnapshot  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

    try:
        rows = (
            db.execute(
                select(FaTimTrustSnapshot.drift_direction)
                .where(
                    FaTimTrustSnapshot.tenant_id == tenant_id,
                    FaTimTrustSnapshot.engagement_id == engagement_id,
                )
                .order_by(FaTimTrustSnapshot.evaluated_at.desc())
                .limit(limit)
            )
            .scalars()
            .all()
        )
        return list(reversed(rows))
    except Exception:
        return []


def compute_and_persist_tim_snapshot(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
) -> dict[str, Any]:
    """Aggregate current trust state into a FaTimTrustSnapshot row.

    Queries existing Trust Arc tables — does not compute any trust scores
    itself.  Returns dict with snapshot fields, or empty dict on error.
    """
    from api.db_models_tim import FaTimTrustSnapshot  # noqa: PLC0415

    try:
        trust_snap = _latest_trust_snapshot(
            db, tenant_id=tenant_id, engagement_id=engagement_id
        )
        cert = _latest_certification(
            db, tenant_id=tenant_id, engagement_id=engagement_id
        )
        prev_tim = _previous_tim_snapshot(
            db, tenant_id=tenant_id, engagement_id=engagement_id
        )

        posture_score = trust_snap.posture_score if trust_snap else 0
        posture_level = trust_snap.posture_level if trust_snap else "unknown"
        risk_level = trust_snap.risk_level if trust_snap else "unknown"
        replay_status = "no_chain"

        cert_level = cert.certification_level if cert else "not_certified"
        composite_score = cert.composite_score if cert else 0
        cert_valid_until = cert.valid_until if cert else None
        cert_id = cert.id if cert else None

        prev_score = prev_tim.posture_score if prev_tim else None

        direction = _drift_direction(posture_score, prev_score)
        score_delta = _drift_score(posture_score, prev_score)
        open_count = _open_drift_count(
            db, tenant_id=tenant_id, engagement_id=engagement_id
        )
        ev_count = _evidence_count(db, tenant_id=tenant_id, engagement_id=engagement_id)

        snap_id = _snap_id()
        now = _utc_now()
        bundle_id = _last_bundle_id(
            db, tenant_id=tenant_id, engagement_id=engagement_id
        )
        source_fp = _compute_source_fingerprint(
            trust_snap.id if trust_snap else None,
            cert_id,
            bundle_id,
        )

        record = FaTimTrustSnapshot(
            id=snap_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            posture_score=posture_score,
            posture_level=posture_level,
            risk_level=risk_level,
            certification_level=cert_level,
            composite_score=composite_score,
            certification_valid_until=cert_valid_until,
            drift_score=score_delta,
            drift_direction=direction,
            open_drift_count=open_count,
            evidence_count=ev_count,
            replay_status=replay_status,
            last_snapshot_id=trust_snap.id if trust_snap else None,
            last_certification_id=cert_id,
            last_bundle_id=bundle_id,
            source_fingerprint=source_fp,
            evaluated_at=now,
            schema_version="1.0",
        )
        db.add(record)

        result = {
            "id": snap_id,
            "tenant_id": tenant_id,
            "engagement_id": engagement_id,
            "posture_score": posture_score,
            "posture_level": posture_level,
            "risk_level": risk_level,
            "certification_level": cert_level,
            "composite_score": composite_score,
            "certification_valid_until": cert_valid_until,
            "drift_score": score_delta,
            "drift_direction": direction,
            "open_drift_count": open_count,
            "evidence_count": ev_count,
            "replay_status": replay_status,
            "last_snapshot_id": trust_snap.id if trust_snap else None,
            "last_certification_id": cert_id,
            "last_bundle_id": bundle_id,
            "source_fingerprint": source_fp,
            "evaluated_at": now,
            # passed downstream to drift_service
            "_previous_score": prev_score,
            "_cert_valid_until": cert_valid_until,
            "_cert_level": cert_level,
            "_cert_id": cert_id,
            "_last_evidence_at": _last_evidence_at(
                db, tenant_id=tenant_id, engagement_id=engagement_id
            ),
            "_last_bundle_at": _last_bundle_at(
                db, tenant_id=tenant_id, engagement_id=engagement_id
            ),
            "_recent_trend_directions": _recent_trend_directions(
                db, tenant_id=tenant_id, engagement_id=engagement_id
            ),
        }
        log.info(
            "tim.snapshot: persisted score=%s level=%s direction=%s tenant=%s engagement=%s",
            posture_score,
            posture_level,
            direction,
            tenant_id,
            engagement_id,
        )
        return result
    except Exception:
        log.exception(
            "tim.snapshot: failed tenant=%s engagement=%s",
            tenant_id,
            engagement_id,
        )
        return {}
