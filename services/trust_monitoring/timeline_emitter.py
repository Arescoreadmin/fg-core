"""P0-7: TIM timeline emitter.

Emits normalized trust arc events into governance_timeline_events.
All events are tenant-scoped, append-only, and replay-eligible.

Event source_type values:
  trust_arc            — snapshot, certification, decision memory
  trust_monitoring     — TIM state snapshots, drift detections
  verification_bundle  — bundle generation events

Event type vocabulary (governance_timeline_events.event_type):
  trust_snapshot_generated
  trust_certification_issued
  trust_certification_expiration_warning
  trust_certification_expired
  governance_decision_recorded
  verification_bundle_generated
  trust_replay_completed
  tim_snapshot_evaluated
  tim_drift_detected

Callers own the DB transaction; this module only calls db.add().
Non-blocking: emitter errors are logged and swallowed — timeline
failures must never interrupt host workflows.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("frostgate.tim.timeline")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _event_id(source_type: str, source_id: str, event_type: str) -> str:
    raw = f"{source_type}:{source_id}:{event_type}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32] + uuid.uuid4().hex[:32]


def _emit(
    db: Any,
    *,
    tenant_id: str,
    source_type: str,
    source_id: str,
    event_type: str,
    occurred_at: str,
    payload: dict[str, Any],
    replay_eligible: bool = True,
    classification: str = "internal",
) -> None:
    from api.db_models_timeline import TimelineEventRecord  # noqa: PLC0415

    record = TimelineEventRecord(
        id=_event_id(source_type, source_id, event_type),
        tenant_id=tenant_id,
        source_type=source_type,
        source_id=source_id,
        event_type=event_type,
        occurred_at=occurred_at,
        recorded_at=_utc_now(),
        payload=payload,
        classification=classification,
        replay_eligible=replay_eligible,
        schema_version="1.0",
    )
    db.add(record)


def emit_trust_snapshot_generated(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
    snapshot_id: str,
    posture_score: int,
    posture_level: str,
    risk_level: str,
    trend_direction: str,
    occurred_at: str,
) -> None:
    try:
        _emit(
            db,
            tenant_id=tenant_id,
            source_type="trust_arc",
            source_id=snapshot_id,
            event_type="trust_snapshot_generated",
            occurred_at=occurred_at,
            payload={
                "engagement_id": engagement_id,
                "snapshot_id": snapshot_id,
                "posture_score": posture_score,
                "posture_level": posture_level,
                "risk_level": risk_level,
                "trend_direction": trend_direction,
                "actor_type": "system",
            },
        )
    except Exception:
        log.exception(
            "tim.timeline: failed to emit trust_snapshot_generated snapshot=%s",
            snapshot_id,
        )


def emit_trust_certification_issued(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
    certification_id: str,
    certification_level: str,
    composite_score: int,
    valid_until: str,
    occurred_at: str,
) -> None:
    try:
        _emit(
            db,
            tenant_id=tenant_id,
            source_type="trust_arc",
            source_id=certification_id,
            event_type="trust_certification_issued",
            occurred_at=occurred_at,
            payload={
                "engagement_id": engagement_id,
                "certification_id": certification_id,
                "certification_level": certification_level,
                "composite_score": composite_score,
                "valid_until": valid_until,
                "actor_type": "system",
            },
        )
    except Exception:
        log.exception(
            "tim.timeline: failed to emit trust_certification_issued cert=%s",
            certification_id,
        )


def emit_governance_decision_recorded(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
    decision_id: str,
    decision_type: str,
    entity_type: str,
    occurred_at: str,
) -> None:
    try:
        _emit(
            db,
            tenant_id=tenant_id,
            source_type="trust_arc",
            source_id=decision_id,
            event_type="governance_decision_recorded",
            occurred_at=occurred_at,
            payload={
                "engagement_id": engagement_id,
                "decision_id": decision_id,
                "decision_type": decision_type,
                "entity_type": entity_type,
                "actor_type": entity_type,
            },
        )
    except Exception:
        log.exception(
            "tim.timeline: failed to emit governance_decision_recorded decision=%s",
            decision_id,
        )


def emit_verification_bundle_generated(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
    bundle_id: str,
    verification_status: str,
    coverage_status: str,
    occurred_at: str,
) -> None:
    try:
        _emit(
            db,
            tenant_id=tenant_id,
            source_type="verification_bundle",
            source_id=bundle_id,
            event_type="verification_bundle_generated",
            occurred_at=occurred_at,
            payload={
                "engagement_id": engagement_id,
                "bundle_id": bundle_id,
                "verification_status": verification_status,
                "coverage_status": coverage_status,
                "actor_type": "system",
            },
        )
    except Exception:
        log.exception(
            "tim.timeline: failed to emit verification_bundle_generated bundle=%s",
            bundle_id,
        )


def emit_tim_drift_detected(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
    drift_event_id: str,
    drift_rule: str,
    severity: str,
    evidence: dict[str, Any],
    occurred_at: str,
) -> None:
    try:
        _emit(
            db,
            tenant_id=tenant_id,
            source_type="trust_monitoring",
            source_id=drift_event_id,
            event_type="tim_drift_detected",
            occurred_at=occurred_at,
            payload={
                "engagement_id": engagement_id,
                "drift_event_id": drift_event_id,
                "drift_rule": drift_rule,
                "severity": severity,
                "evidence": json.dumps(evidence),
                "actor_type": "system",
            },
        )
    except Exception:
        log.exception(
            "tim.timeline: failed to emit tim_drift_detected rule=%s",
            drift_rule,
        )


def emit_tim_snapshot_evaluated(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
    tim_snapshot_id: str,
    posture_score: int,
    certification_level: str,
    drift_direction: str,
    open_drift_count: int,
    occurred_at: str,
) -> None:
    try:
        _emit(
            db,
            tenant_id=tenant_id,
            source_type="trust_monitoring",
            source_id=tim_snapshot_id,
            event_type="tim_snapshot_evaluated",
            occurred_at=occurred_at,
            payload={
                "engagement_id": engagement_id,
                "tim_snapshot_id": tim_snapshot_id,
                "posture_score": posture_score,
                "certification_level": certification_level,
                "drift_direction": drift_direction,
                "open_drift_count": open_drift_count,
                "actor_type": "system",
            },
        )
    except Exception:
        log.exception(
            "tim.timeline: failed to emit tim_snapshot_evaluated snap=%s",
            tim_snapshot_id,
        )


def emit_tim_evaluation_failed(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
    error_type: str,
    occurred_at: str,
) -> None:
    try:
        _emit(
            db,
            tenant_id=tenant_id,
            source_type="trust_monitoring",
            source_id=f"{engagement_id}:{occurred_at}",
            event_type="tim_evaluation_failed",
            occurred_at=occurred_at,
            payload={
                "engagement_id": engagement_id,
                "error_type": error_type,
                "actor_type": "system",
            },
            replay_eligible=False,
        )
    except Exception:
        log.exception(
            "tim.timeline: failed to emit tim_evaluation_failed engagement=%s",
            engagement_id,
        )
