"""P0-7: TIM drift detection service.

All drift rules are deterministic — no AI, no heuristics.
Each rule produces a severity level (info/low/medium/high/critical)
and structured evidence dict describing what triggered the drift.

Rules:
  score_degradation       — posture_score drop >= threshold vs. previous snapshot
  cert_expiration         — certification expires within warning window
  cert_expired            — certification past valid_until
  evidence_staleness      — no new evidence in > threshold days
  replay_failure          — chain_replay_score == 0 or < 50
  missing_bundle          — no verification bundle in > threshold days
  consecutive_degradation — 3+ consecutive snapshots with degrading trend

Callers own the DB transaction; drift_service calls db.add() only.
Non-blocking: any error returns an empty list.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("frostgate.tim.drift")

# ---------------------------------------------------------------------------
# Severity constants
# ---------------------------------------------------------------------------
INFO = "info"
LOW = "low"
MEDIUM = "medium"
HIGH = "high"
CRITICAL = "critical"

# ---------------------------------------------------------------------------
# Score degradation thresholds
# ---------------------------------------------------------------------------
_SCORE_DEGRADATION_MEDIUM = 10
_SCORE_DEGRADATION_HIGH = 20
_SCORE_DEGRADATION_CRITICAL = 30

# ---------------------------------------------------------------------------
# Certification expiration warning windows (days)
# ---------------------------------------------------------------------------
_CERT_EXPIRY_LOW_DAYS = 14
_CERT_EXPIRY_MEDIUM_DAYS = 7
_CERT_EXPIRY_HIGH_DAYS = 3

# ---------------------------------------------------------------------------
# Evidence staleness thresholds (days)
# ---------------------------------------------------------------------------
_EVIDENCE_STALE_LOW_DAYS = 30
_EVIDENCE_STALE_MEDIUM_DAYS = 60
_EVIDENCE_STALE_HIGH_DAYS = 90

# ---------------------------------------------------------------------------
# Missing bundle thresholds (days)
# ---------------------------------------------------------------------------
_BUNDLE_MISSING_LOW_DAYS = 14
_BUNDLE_MISSING_MEDIUM_DAYS = 30

# ---------------------------------------------------------------------------
# Deduplication: persistent-state rules that should not fire again while an
# open (unacknowledged) event for the same rule already exists.
# score_degradation is excluded — each delta is a discrete point-in-time event.
# ---------------------------------------------------------------------------
_DEDUP_RULES: frozenset[str] = frozenset(
    {
        "cert_expiration",
        "cert_expired",
        "evidence_staleness",
        "replay_failure",
        "missing_bundle",
        "consecutive_degradation",
    }
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _drift_id() -> str:
    return uuid.uuid4().hex


def _has_open_unacknowledged_event(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
    drift_rule: str,
) -> bool:
    from api.db_models_tim import FaTimDriftEvent  # noqa: PLC0415
    from sqlalchemy import func, select  # noqa: PLC0415

    try:
        ack_subq = select(FaTimDriftEvent.correlation_id).where(
            FaTimDriftEvent.tenant_id == tenant_id,
            FaTimDriftEvent.engagement_id == engagement_id,
            FaTimDriftEvent.status == "acknowledged",
            FaTimDriftEvent.correlation_id.isnot(None),
        )
        count = db.execute(
            select(func.count()).where(
                FaTimDriftEvent.tenant_id == tenant_id,
                FaTimDriftEvent.engagement_id == engagement_id,
                FaTimDriftEvent.drift_rule == drift_rule,
                FaTimDriftEvent.status == "open",
                ~FaTimDriftEvent.id.in_(ack_subq),
            )
        ).scalar()
        return (count or 0) > 0
    except Exception:
        return False


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Drift rule evaluators — each returns list[dict] of detected events
# ---------------------------------------------------------------------------


def _check_score_degradation(
    current_score: int,
    previous_score: int | None,
    *,
    correlation_id: str | None,
    now_iso: str,
) -> list[dict[str, Any]]:
    if previous_score is None:
        return []
    delta = previous_score - current_score
    if delta < _SCORE_DEGRADATION_MEDIUM:
        return []
    if delta >= _SCORE_DEGRADATION_CRITICAL:
        severity = CRITICAL
    elif delta >= _SCORE_DEGRADATION_HIGH:
        severity = HIGH
    else:
        severity = MEDIUM
    return [
        {
            "drift_rule": "score_degradation",
            "severity": severity,
            "evidence": {
                "before_score": previous_score,
                "after_score": current_score,
                "delta": delta,
                "threshold": _SCORE_DEGRADATION_MEDIUM,
            },
            "correlation_id": correlation_id,
            "detected_at": now_iso,
        }
    ]


def _check_cert_expiration(
    cert_valid_until: str | None,
    cert_level: str,
    *,
    cert_id: str | None,
    now: datetime,
    now_iso: str,
) -> list[dict[str, Any]]:
    if not cert_valid_until or cert_level == "not_certified":
        return []
    try:
        expiry = datetime.fromisoformat(cert_valid_until.replace("Z", "+00:00"))
    except ValueError:
        return []

    days_left = (expiry - now).days
    if days_left < 0:
        return [
            {
                "drift_rule": "cert_expired",
                "severity": CRITICAL,
                "evidence": {
                    "cert_level": cert_level,
                    "valid_until": cert_valid_until,
                    "days_overdue": abs(days_left),
                },
                "correlation_id": cert_id,
                "detected_at": now_iso,
            }
        ]
    if days_left <= _CERT_EXPIRY_HIGH_DAYS:
        severity = HIGH
    elif days_left <= _CERT_EXPIRY_MEDIUM_DAYS:
        severity = MEDIUM
    elif days_left <= _CERT_EXPIRY_LOW_DAYS:
        severity = LOW
    else:
        return []
    return [
        {
            "drift_rule": "cert_expiration",
            "severity": severity,
            "evidence": {
                "cert_level": cert_level,
                "valid_until": cert_valid_until,
                "days_remaining": days_left,
            },
            "correlation_id": cert_id,
            "detected_at": now_iso,
        }
    ]


def _check_evidence_staleness(
    last_evidence_at: str | None,
    evidence_count: int,
    *,
    now: datetime,
    now_iso: str,
) -> list[dict[str, Any]]:
    if not last_evidence_at or evidence_count == 0:
        return [
            {
                "drift_rule": "evidence_staleness",
                "severity": LOW,
                "evidence": {
                    "evidence_count": evidence_count,
                    "last_evidence_at": None,
                },
                "correlation_id": None,
                "detected_at": now_iso,
            }
        ]
    try:
        last = datetime.fromisoformat(last_evidence_at.replace("Z", "+00:00"))
    except ValueError:
        return []
    days_stale = (now - last).days
    if days_stale >= _EVIDENCE_STALE_HIGH_DAYS:
        severity = HIGH
    elif days_stale >= _EVIDENCE_STALE_MEDIUM_DAYS:
        severity = MEDIUM
    elif days_stale >= _EVIDENCE_STALE_LOW_DAYS:
        severity = LOW
    else:
        return []
    return [
        {
            "drift_rule": "evidence_staleness",
            "severity": severity,
            "evidence": {
                "last_evidence_at": last_evidence_at,
                "days_stale": days_stale,
                "evidence_count": evidence_count,
                "threshold_days": _EVIDENCE_STALE_LOW_DAYS,
            },
            "correlation_id": None,
            "detected_at": now_iso,
        }
    ]


def _check_replay_failure(
    replay_status: str,
    *,
    snapshot_id: str | None,
    now_iso: str,
) -> list[dict[str, Any]]:
    if replay_status == "ok":
        return []
    severity = CRITICAL if replay_status == "failed" else LOW
    return [
        {
            "drift_rule": "replay_failure",
            "severity": severity,
            "evidence": {"replay_status": replay_status},
            "correlation_id": snapshot_id,
            "detected_at": now_iso,
        }
    ]


def _check_missing_bundle(
    last_bundle_at: str | None,
    *,
    now: datetime,
    now_iso: str,
) -> list[dict[str, Any]]:
    if not last_bundle_at:
        return [
            {
                "drift_rule": "missing_bundle",
                "severity": LOW,
                "evidence": {"last_bundle_at": None},
                "correlation_id": None,
                "detected_at": now_iso,
            }
        ]
    try:
        last = datetime.fromisoformat(last_bundle_at.replace("Z", "+00:00"))
    except ValueError:
        return []
    days_missing = (now - last).days
    if days_missing >= _BUNDLE_MISSING_MEDIUM_DAYS:
        severity = MEDIUM
    elif days_missing >= _BUNDLE_MISSING_LOW_DAYS:
        severity = LOW
    else:
        return []
    return [
        {
            "drift_rule": "missing_bundle",
            "severity": severity,
            "evidence": {
                "last_bundle_at": last_bundle_at,
                "days_since_bundle": days_missing,
            },
            "correlation_id": None,
            "detected_at": now_iso,
        }
    ]


def _check_consecutive_degradation(
    recent_directions: list[str],
    *,
    snapshot_id: str | None,
    now_iso: str,
) -> list[dict[str, Any]]:
    degrading = {"degrading", "rapidly_degrading"}
    if len(recent_directions) < 3:
        return []
    last_three = recent_directions[-3:]
    if all(d in degrading for d in last_three):
        return [
            {
                "drift_rule": "consecutive_degradation",
                "severity": MEDIUM,
                "evidence": {
                    "recent_directions": last_three,
                    "consecutive_count": 3,
                },
                "correlation_id": snapshot_id,
                "detected_at": now_iso,
            }
        ]
    return []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_and_persist_drift(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
    current_score: int,
    previous_score: int | None,
    cert_valid_until: str | None,
    cert_level: str,
    cert_id: str | None,
    last_evidence_at: str | None,
    evidence_count: int,
    replay_status: str,
    last_bundle_at: str | None,
    recent_trend_directions: list[str],
    snapshot_id: str | None,
) -> list[dict[str, Any]]:
    """Evaluate all drift rules and persist detected events.

    Returns list of persisted drift event dicts (may be empty).
    Non-blocking: any error returns empty list.
    """
    from api.db_models_tim import FaTimDriftEvent  # noqa: PLC0415
    from services.trust_monitoring.timeline_emitter import (  # noqa: PLC0415
        emit_tim_drift_detected,
    )

    try:
        now = _utc_now()
        now_iso = _iso(now)
        detected: list[dict[str, Any]] = []

        detected.extend(
            _check_score_degradation(
                current_score,
                previous_score,
                correlation_id=snapshot_id,
                now_iso=now_iso,
            )
        )
        detected.extend(
            _check_cert_expiration(
                cert_valid_until,
                cert_level,
                cert_id=cert_id,
                now=now,
                now_iso=now_iso,
            )
        )
        detected.extend(
            _check_evidence_staleness(
                last_evidence_at,
                evidence_count,
                now=now,
                now_iso=now_iso,
            )
        )
        detected.extend(
            _check_replay_failure(
                replay_status,
                snapshot_id=snapshot_id,
                now_iso=now_iso,
            )
        )
        detected.extend(
            _check_missing_bundle(
                last_bundle_at,
                now=now,
                now_iso=now_iso,
            )
        )
        detected.extend(
            _check_consecutive_degradation(
                recent_trend_directions,
                snapshot_id=snapshot_id,
                now_iso=now_iso,
            )
        )

        persisted: list[dict[str, Any]] = []
        for event in detected:
            if event["drift_rule"] in _DEDUP_RULES and _has_open_unacknowledged_event(
                db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                drift_rule=event["drift_rule"],
            ):
                continue
            event_id = _drift_id()
            record = FaTimDriftEvent(
                id=event_id,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                drift_rule=event["drift_rule"],
                severity=event["severity"],
                status="open",
                detected_at=event["detected_at"],
                resolved_at=None,
                evidence=json.dumps(event["evidence"]),
                correlation_id=event.get("correlation_id"),
                actor_type="system",
                schema_version="1.0",
            )
            db.add(record)
            emit_tim_drift_detected(
                db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                drift_event_id=event_id,
                drift_rule=event["drift_rule"],
                severity=event["severity"],
                evidence=event["evidence"],
                occurred_at=event["detected_at"],
            )
            log.info(
                "tim.drift: detected rule=%s severity=%s tenant=%s engagement=%s",
                event["drift_rule"],
                event["severity"],
                tenant_id,
                engagement_id,
            )
            persisted.append({"id": event_id, **event})

        return persisted
    except Exception:
        log.exception(
            "tim.drift: detection failed tenant=%s engagement=%s",
            tenant_id,
            engagement_id,
        )
        return []
