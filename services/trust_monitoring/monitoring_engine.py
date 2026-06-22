"""P0-7: TIM monitoring engine.

Single entry point: evaluate_and_persist_tim().

Orchestrates:
  1. compute_and_persist_tim_snapshot() — aggregate current trust state
  2. detect_and_persist_drift()         — run deterministic drift rules
  3. emit_tim_snapshot_evaluated()      — write timeline event

Callers own the DB transaction.  Non-blocking: any error is logged and
swallowed so TIM failures never interrupt host workflows.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("frostgate.tim.engine")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def evaluate_and_persist_tim(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
) -> dict[str, Any]:
    """Run the full TIM evaluation cycle for one engagement.

    Returns a summary dict with snapshot_id, drift_events list, and
    timeline_emitted flag.  Returns empty dict on any error.
    """
    from services.trust_monitoring.snapshot_service import (  # noqa: PLC0415
        compute_and_persist_tim_snapshot,
    )
    from services.trust_monitoring.drift_service import (  # noqa: PLC0415
        detect_and_persist_drift,
    )
    from services.trust_monitoring.timeline_emitter import (  # noqa: PLC0415
        emit_tim_snapshot_evaluated,
    )

    try:
        snap = compute_and_persist_tim_snapshot(
            db, tenant_id=tenant_id, engagement_id=engagement_id
        )
        if not snap:
            return {}

        drift_events = detect_and_persist_drift(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            current_score=snap["posture_score"],
            previous_score=snap["_previous_score"],
            cert_valid_until=snap["_cert_valid_until"],
            cert_level=snap["_cert_level"],
            cert_id=snap["_cert_id"],
            last_evidence_at=snap["_last_evidence_at"],
            evidence_count=snap["evidence_count"],
            replay_status=snap["replay_status"],
            last_bundle_at=snap["_last_bundle_at"],
            recent_trend_directions=snap["_recent_trend_directions"],
            snapshot_id=snap["id"],
        )

        open_drift_count = snap["open_drift_count"] + len(drift_events)

        orm_record = snap.get("_orm_record")
        if orm_record is not None:
            orm_record.open_drift_count = open_drift_count

        emit_tim_snapshot_evaluated(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            tim_snapshot_id=snap["id"],
            posture_score=snap["posture_score"],
            certification_level=snap["certification_level"],
            drift_direction=snap["drift_direction"],
            open_drift_count=open_drift_count,
            occurred_at=snap["evaluated_at"],
        )

        log.info(
            "tim.engine: evaluated tenant=%s engagement=%s snapshot=%s drift_events=%d",
            tenant_id,
            engagement_id,
            snap["id"],
            len(drift_events),
        )
        return {
            "snapshot_id": snap["id"],
            "posture_score": snap["posture_score"],
            "drift_direction": snap["drift_direction"],
            "drift_events": drift_events,
            "open_drift_count": open_drift_count,
            "evaluated_at": snap["evaluated_at"],
        }
    except Exception as e:
        log.exception(
            "tim.engine: evaluation failed tenant=%s engagement=%s",
            tenant_id,
            engagement_id,
        )
        try:
            from services.trust_monitoring.timeline_emitter import (  # noqa: PLC0415
                emit_tim_evaluation_failed,
            )

            emit_tim_evaluation_failed(
                db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                error_type=type(e).__name__,
                occurred_at=_utc_now(),
            )
        except Exception:
            pass
        return {}
