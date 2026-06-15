"""P0-7: Unit tests for TIM drift_service and snapshot_service.

Tests are pure-unit — no DB, no network, no signing keys required.
All DB-touching functions are patched with lightweight fakes.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _days_ago(n: int) -> str:
    return _iso(datetime.now(timezone.utc) - timedelta(days=n))


def _days_ahead(n: int) -> str:
    return _iso(datetime.now(timezone.utc) + timedelta(days=n))


# ---------------------------------------------------------------------------
# drift_service — internal rule functions
# ---------------------------------------------------------------------------


class TestCheckScoreDegradation:
    from services.trust_monitoring import drift_service as _ds

    def setup_method(self) -> None:
        from services.trust_monitoring import drift_service as ds

        self.ds = ds

    def test_no_previous_returns_empty(self) -> None:
        result = self.ds._check_score_degradation(
            50, None, correlation_id=None, now_iso="2026-06-14T00:00:00Z"
        )
        assert result == []

    def test_below_threshold_returns_empty(self) -> None:
        result = self.ds._check_score_degradation(
            85, 90, correlation_id=None, now_iso="2026-06-14T00:00:00Z"
        )
        assert result == []

    def test_medium_severity(self) -> None:
        events = self.ds._check_score_degradation(
            70, 85, correlation_id=None, now_iso="2026-06-14T00:00:00Z"
        )
        assert len(events) == 1
        assert events[0]["severity"] == "medium"
        assert events[0]["evidence"]["delta"] == 15

    def test_high_severity(self) -> None:
        events = self.ds._check_score_degradation(
            65, 90, correlation_id=None, now_iso="2026-06-14T00:00:00Z"
        )
        assert len(events) == 1
        assert events[0]["severity"] == "high"

    def test_critical_severity(self) -> None:
        events = self.ds._check_score_degradation(
            55, 90, correlation_id=None, now_iso="2026-06-14T00:00:00Z"
        )
        assert len(events) == 1
        assert events[0]["severity"] == "critical"

    def test_improvement_returns_empty(self) -> None:
        result = self.ds._check_score_degradation(
            90, 70, correlation_id=None, now_iso="2026-06-14T00:00:00Z"
        )
        assert result == []


class TestCheckCertExpiration:
    def setup_method(self) -> None:
        from services.trust_monitoring import drift_service as ds

        self.ds = ds

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def test_not_certified_skipped(self) -> None:
        result = self.ds._check_cert_expiration(
            _days_ahead(5),
            "not_certified",
            cert_id=None,
            now=self._now(),
            now_iso="2026-06-14T00:00:00Z",
        )
        assert result == []

    def test_no_valid_until_skipped(self) -> None:
        result = self.ds._check_cert_expiration(
            None,
            "silver",
            cert_id=None,
            now=self._now(),
            now_iso="2026-06-14T00:00:00Z",
        )
        assert result == []

    def test_expired_is_critical(self) -> None:
        events = self.ds._check_cert_expiration(
            _days_ago(2),
            "gold",
            cert_id="cert-1",
            now=self._now(),
            now_iso="2026-06-14T00:00:00Z",
        )
        assert len(events) == 1
        assert events[0]["drift_rule"] == "cert_expired"
        assert events[0]["severity"] == "critical"

    def test_expiring_soon_high(self) -> None:
        events = self.ds._check_cert_expiration(
            _days_ahead(2),
            "gold",
            cert_id="cert-1",
            now=self._now(),
            now_iso="2026-06-14T00:00:00Z",
        )
        assert len(events) == 1
        assert events[0]["severity"] == "high"

    def test_expiring_medium(self) -> None:
        events = self.ds._check_cert_expiration(
            _days_ahead(5),
            "gold",
            cert_id="cert-1",
            now=self._now(),
            now_iso="2026-06-14T00:00:00Z",
        )
        assert len(events) == 1
        assert events[0]["severity"] == "medium"

    def test_expiring_low(self) -> None:
        events = self.ds._check_cert_expiration(
            _days_ahead(10),
            "gold",
            cert_id="cert-1",
            now=self._now(),
            now_iso="2026-06-14T00:00:00Z",
        )
        assert len(events) == 1
        assert events[0]["severity"] == "low"

    def test_plenty_of_time_returns_empty(self) -> None:
        result = self.ds._check_cert_expiration(
            _days_ahead(60),
            "gold",
            cert_id="cert-1",
            now=self._now(),
            now_iso="2026-06-14T00:00:00Z",
        )
        assert result == []


class TestCheckEvidenceStaleness:
    def setup_method(self) -> None:
        from services.trust_monitoring import drift_service as ds

        self.ds = ds

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def test_no_evidence_returns_low(self) -> None:
        events = self.ds._check_evidence_staleness(
            None, 0, now=self._now(), now_iso="2026-06-14T00:00:00Z"
        )
        assert len(events) == 1
        assert events[0]["severity"] == "low"

    def test_zero_count_returns_low(self) -> None:
        events = self.ds._check_evidence_staleness(
            _days_ago(5), 0, now=self._now(), now_iso="2026-06-14T00:00:00Z"
        )
        assert len(events) == 1
        assert events[0]["severity"] == "low"

    def test_fresh_evidence_returns_empty(self) -> None:
        result = self.ds._check_evidence_staleness(
            _days_ago(5), 10, now=self._now(), now_iso="2026-06-14T00:00:00Z"
        )
        assert result == []

    def test_stale_low(self) -> None:
        events = self.ds._check_evidence_staleness(
            _days_ago(35), 5, now=self._now(), now_iso="2026-06-14T00:00:00Z"
        )
        assert len(events) == 1
        assert events[0]["severity"] == "low"

    def test_stale_medium(self) -> None:
        events = self.ds._check_evidence_staleness(
            _days_ago(65), 5, now=self._now(), now_iso="2026-06-14T00:00:00Z"
        )
        assert len(events) == 1
        assert events[0]["severity"] == "medium"

    def test_stale_high(self) -> None:
        events = self.ds._check_evidence_staleness(
            _days_ago(95), 5, now=self._now(), now_iso="2026-06-14T00:00:00Z"
        )
        assert len(events) == 1
        assert events[0]["severity"] == "high"


class TestCheckReplayFailure:
    def setup_method(self) -> None:
        from services.trust_monitoring import drift_service as ds

        self.ds = ds

    def test_ok_returns_empty(self) -> None:
        assert (
            self.ds._check_replay_failure(
                "ok", snapshot_id=None, now_iso="2026-06-14T00:00:00Z"
            )
            == []
        )

    def test_failed_is_critical(self) -> None:
        events = self.ds._check_replay_failure(
            "failed", snapshot_id="snap-1", now_iso="2026-06-14T00:00:00Z"
        )
        assert events[0]["severity"] == "critical"

    def test_no_chain_is_low(self) -> None:
        events = self.ds._check_replay_failure(
            "no_chain", snapshot_id=None, now_iso="2026-06-14T00:00:00Z"
        )
        assert events[0]["severity"] == "low"


class TestCheckMissingBundle:
    def setup_method(self) -> None:
        from services.trust_monitoring import drift_service as ds

        self.ds = ds

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def test_no_bundle_at_all_returns_low(self) -> None:
        events = self.ds._check_missing_bundle(
            None, now=self._now(), now_iso="2026-06-14T00:00:00Z"
        )
        assert len(events) == 1
        assert events[0]["severity"] == "low"

    def test_recent_bundle_returns_empty(self) -> None:
        result = self.ds._check_missing_bundle(
            _days_ago(5), now=self._now(), now_iso="2026-06-14T00:00:00Z"
        )
        assert result == []

    def test_14_days_is_low(self) -> None:
        events = self.ds._check_missing_bundle(
            _days_ago(15), now=self._now(), now_iso="2026-06-14T00:00:00Z"
        )
        assert len(events) == 1
        assert events[0]["severity"] == "low"

    def test_30_days_is_medium(self) -> None:
        events = self.ds._check_missing_bundle(
            _days_ago(35), now=self._now(), now_iso="2026-06-14T00:00:00Z"
        )
        assert len(events) == 1
        assert events[0]["severity"] == "medium"


class TestCheckConsecutiveDegradation:
    def setup_method(self) -> None:
        from services.trust_monitoring import drift_service as ds

        self.ds = ds

    def test_fewer_than_three_directions_empty(self) -> None:
        result = self.ds._check_consecutive_degradation(
            ["degrading", "degrading"],
            snapshot_id=None,
            now_iso="2026-06-14T00:00:00Z",
        )
        assert result == []

    def test_mixed_directions_empty(self) -> None:
        result = self.ds._check_consecutive_degradation(
            ["stable", "degrading", "degrading"],
            snapshot_id=None,
            now_iso="2026-06-14T00:00:00Z",
        )
        assert result == []

    def test_three_degrading_fires_medium(self) -> None:
        events = self.ds._check_consecutive_degradation(
            ["stable", "degrading", "degrading", "rapidly_degrading"],
            snapshot_id="snap-1",
            now_iso="2026-06-14T00:00:00Z",
        )
        assert len(events) == 1
        assert events[0]["severity"] == "medium"
        assert events[0]["drift_rule"] == "consecutive_degradation"

    def test_rapidly_degrading_qualifies(self) -> None:
        events = self.ds._check_consecutive_degradation(
            ["rapidly_degrading", "rapidly_degrading", "rapidly_degrading"],
            snapshot_id=None,
            now_iso="2026-06-14T00:00:00Z",
        )
        assert len(events) == 1


# ---------------------------------------------------------------------------
# drift_service — detect_and_persist_drift (integration surface)
# ---------------------------------------------------------------------------


class TestDetectAndPersistDrift:
    def _make_db(self) -> MagicMock:
        db = MagicMock()
        db.add = MagicMock()
        return db

    def _run(self, db: Any, **kwargs: Any) -> list[dict]:
        from services.trust_monitoring.drift_service import detect_and_persist_drift

        defaults: dict[str, Any] = {
            "tenant_id": "t1",
            "engagement_id": "e1",
            "current_score": 80,
            "previous_score": None,
            "cert_valid_until": _days_ahead(60),
            "cert_level": "gold",
            "cert_id": "cert-1",
            "last_evidence_at": _days_ago(5),
            "evidence_count": 10,
            "replay_status": "ok",
            "last_bundle_at": _days_ago(5),
            "recent_trend_directions": [],
            "snapshot_id": "snap-1",
        }
        defaults.update(kwargs)
        with (
            patch("api.db_models_tim.FaTimDriftEvent", MagicMock()),
            patch(
                "services.trust_monitoring.timeline_emitter.emit_tim_drift_detected",
                MagicMock(),
            ),
        ):
            return detect_and_persist_drift(db, **defaults)

    def test_no_drift_in_happy_path(self) -> None:
        db = self._make_db()
        events = self._run(db)
        assert isinstance(events, list)

    def test_returns_empty_on_exception(self) -> None:
        db = MagicMock()
        db.add.side_effect = RuntimeError("db exploded")
        # Should not raise — non-blocking
        from services.trust_monitoring.drift_service import detect_and_persist_drift

        with (
            patch("api.db_models_tim.FaTimDriftEvent", MagicMock()),
            patch(
                "services.trust_monitoring.timeline_emitter.emit_tim_drift_detected",
                MagicMock(),
            ),
        ):
            result = detect_and_persist_drift(
                db,
                tenant_id="t1",
                engagement_id="e1",
                current_score=80,
                previous_score=None,
                cert_valid_until=None,
                cert_level="not_certified",
                cert_id=None,
                last_evidence_at=None,
                evidence_count=0,
                replay_status="ok",
                last_bundle_at=None,
                recent_trend_directions=[],
                snapshot_id=None,
            )
        assert result == []


# ---------------------------------------------------------------------------
# snapshot_service — drift_direction helper
# ---------------------------------------------------------------------------


class TestDriftDirection:
    def setup_method(self) -> None:
        from services.trust_monitoring import snapshot_service as ss

        self.ss = ss

    def test_no_previous_is_stable(self) -> None:
        assert self.ss._drift_direction(80, None) == "stable"

    def test_improvement(self) -> None:
        assert self.ss._drift_direction(90, 70) == "improving"

    def test_degrading(self) -> None:
        assert self.ss._drift_direction(75, 85) == "degrading"

    def test_rapidly_degrading(self) -> None:
        assert self.ss._drift_direction(60, 85) == "rapidly_degrading"

    def test_minor_drop_is_stable(self) -> None:
        assert self.ss._drift_direction(83, 85) == "stable"


class TestDriftScore:
    def setup_method(self) -> None:
        from services.trust_monitoring import snapshot_service as ss

        self.ss = ss

    def test_no_previous_is_zero(self) -> None:
        assert self.ss._drift_score(80, None) == 0

    def test_improvement_clamped_to_zero(self) -> None:
        assert self.ss._drift_score(90, 70) == 0

    def test_degradation_is_positive(self) -> None:
        assert self.ss._drift_score(70, 90) == 20


# ---------------------------------------------------------------------------
# Enhancement 1: Snapshot provenance hash (_compute_source_fingerprint)
# ---------------------------------------------------------------------------


class TestSourceFingerprint:
    def setup_method(self) -> None:
        from services.trust_monitoring.snapshot_service import (
            _compute_source_fingerprint,
        )

        self.fn = _compute_source_fingerprint

    def test_deterministic(self) -> None:
        h1 = self.fn("snap-1", "cert-1", "bundle-1")
        h2 = self.fn("snap-1", "cert-1", "bundle-1")
        assert h1 == h2

    def test_different_inputs_differ(self) -> None:
        h1 = self.fn("snap-1", "cert-1", "bundle-1")
        h2 = self.fn("snap-2", "cert-1", "bundle-1")
        assert h1 != h2

    def test_none_inputs_produce_valid_hex(self) -> None:
        result = self.fn(None, None, None)
        assert isinstance(result, str)
        assert len(result) == 64
        int(result, 16)  # must be valid hex

    def test_partial_nones(self) -> None:
        h_with_none = self.fn("snap-1", None, "bundle-1")
        h_with_empty = self.fn("snap-1", "", "bundle-1")
        # None and "" are treated the same (both map to "")
        assert h_with_none == h_with_empty


# ---------------------------------------------------------------------------
# Enhancement 5: Risk weight
# ---------------------------------------------------------------------------


class TestRiskWeight:
    def setup_method(self) -> None:
        from api.trust_monitoring import _risk_weight

        self.fn = _risk_weight

    def test_info_is_zero(self) -> None:
        assert self.fn("info") == 0

    def test_low(self) -> None:
        assert self.fn("low") == 1

    def test_medium(self) -> None:
        assert self.fn("medium") == 3

    def test_high(self) -> None:
        assert self.fn("high") == 7

    def test_critical(self) -> None:
        assert self.fn("critical") == 15

    def test_unknown_is_zero(self) -> None:
        assert self.fn("unknown_severity") == 0

    def test_empty_string_is_zero(self) -> None:
        assert self.fn("") == 0


# ---------------------------------------------------------------------------
# Enhancement 2: Drift acknowledgement dict fields
# ---------------------------------------------------------------------------


class TestDriftAcknowledgementDict:
    def _make_row(self, acknowledged_by: Any, acknowledged_at: Any) -> MagicMock:
        row = MagicMock()
        row.id = "evt-1"
        row.tenant_id = "t1"
        row.engagement_id = "e1"
        row.drift_rule = "score_degradation"
        row.severity = "high"
        row.status = "open"
        row.detected_at = "2026-06-15T00:00:00Z"
        row.resolved_at = None
        row.evidence = "{}"
        row.correlation_id = None
        row.actor_type = "system"
        row.acknowledged_by = acknowledged_by
        row.acknowledged_at = acknowledged_at
        return row

    def test_acknowledged_fields_present_when_none(self) -> None:
        from api.trust_monitoring import _drift_event_to_dict

        row = self._make_row(None, None)
        d = _drift_event_to_dict(row)
        assert "acknowledged_by" in d
        assert "acknowledged_at" in d
        assert d["acknowledged_by"] is None
        assert d["acknowledged_at"] is None

    def test_acknowledged_fields_present_with_values(self) -> None:
        from api.trust_monitoring import _drift_event_to_dict

        row = self._make_row("user-42", "2026-06-15T12:00:00Z")
        d = _drift_event_to_dict(row)
        assert d["acknowledged_by"] == "user-42"
        assert d["acknowledged_at"] == "2026-06-15T12:00:00Z"

    def test_risk_score_in_dict(self) -> None:
        from api.trust_monitoring import _drift_event_to_dict

        row = self._make_row(None, None)
        d = _drift_event_to_dict(row)
        assert "risk_score" in d
        assert d["risk_score"] == 7  # high → 7
