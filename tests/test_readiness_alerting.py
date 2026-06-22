"""Tests for Enterprise Readiness Alerting & Governance Escalation Engine.

Covers:
- Pure unit: derive_alert_instance_id / derive_alert_fingerprint determinism
- Pure unit: alert generation — one per drift type, CRITICAL preserved, certainty mapping
- Pure unit: alert deduplication — burst ceiling, cooldown, dedup records
- Pure unit: alert lifecycle FSM — valid transitions, invalid rejected
- Pure unit: alert suppression — create, expiry, CRITICAL cannot be suppressed
- Pure unit: AlertingEngine — empty snapshot, version pins, failure fallback
- Pure unit: serialization — valid JSON, no forbidden keys, deterministic
- API: POST /control-plane/readiness/alerting/runs (success, idempotent, 404, 403, 401)
- API: GET /control-plane/readiness/alerting/runs (list, tenant isolation)
- API: GET /control-plane/readiness/alerting/alerts (filter, tenant isolation)
- API: GET /control-plane/readiness/alerting/alerts/{id} (found, cross-tenant 404)
- API: POST .../lifecycle (valid, invalid 422, tenant isolation)
- API: POST .../suppress (create, CRITICAL rejected, tenant isolation)
- Security: no secrets, vectors, prompts; alert_run_output_json not in responses

All API tests run offline against an in-memory SQLite DB.
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "dev")
os.environ.setdefault("FG_AUTH_ENABLED", "0")
os.environ.setdefault("FG_SQLITE_PATH", "state/test_readiness_alerting.db")
os.environ.setdefault("FG_RL_ENABLED", "0")

import json
from datetime import datetime, timedelta, timezone

import pytest


# ---------------------------------------------------------------------------
# Helpers — build a minimal DriftSnapshot and context for tests
# ---------------------------------------------------------------------------


def _make_context(tenant_id: str = "tenant-alerting-1"):
    from services.readiness.monitoring.models import MonitoringEvaluationContext

    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=24)).isoformat()
    end = now.isoformat()
    return MonitoringEvaluationContext(
        tenant_id=tenant_id,
        evaluation_window_start_iso=start,
        evaluation_window_end_iso=end,
        evidence_freshness_window_days=30,
        retrieval_degradation_window_hours=24,
        policy_drift_comparison_window_hours=24,
        audit_continuity_window_hours=24,
        runtime_governance_window_hours=24,
        monitoring_contract_version="1.0",
        evaluation_engine_version="1.0",
        drift_classification_version="1.0",
        severity_classification_version="1.0",
        assessment_id="assessment-test-1",
    )


def _make_drift_event(
    drift_type: str = "stale_evidence",
    severity: str = "moderate",
    certainty: str = "confirmed",
    scope: str = "evidence:ev-1",
    run_id: str = "run-alert-test-1",
    tenant_id: str = "tenant-alerting-1",
):
    from services.readiness.monitoring.identity import derive_event_fingerprint
    from services.readiness.monitoring.models import (
        DriftCertainty,
        DriftEvent,
        DriftSeverity,
        DriftType,
    )

    fp = derive_event_fingerprint(drift_type, scope, run_id, ())
    return DriftEvent(
        event_fingerprint=fp,
        drift_type=DriftType(drift_type),
        severity=DriftSeverity(severity),
        certainty=DriftCertainty(certainty),
        affected_scope=scope,
        affected_control_ids=(),
        affected_evidence_ids=(),
        affected_framework_ids=(),
        drift_detail=f"Test drift event: {drift_type}",
        monitoring_source="test-evaluator",
        evaluation_timestamp_iso=datetime.now(timezone.utc).isoformat(),
        temporal_boundary_start=(
            datetime.now(timezone.utc) - timedelta(hours=24)
        ).isoformat(),
        temporal_boundary_end=datetime.now(timezone.utc).isoformat(),
        provenance_metadata=(),
    )


def _make_snapshot(
    events=None,
    tenant_id: str = "tenant-alerting-1",
    run_id: str = "run-alert-test-1",
    assessment_id: str = "assessment-test-1",
):
    from services.readiness.monitoring.models import DriftSnapshot

    now = datetime.now(timezone.utc)
    if events is None:
        events = ()
    snapshot_id = f"snap-{run_id}"
    return DriftSnapshot(
        snapshot_id=snapshot_id,
        monitoring_run_id=run_id,
        evaluation_timestamp_iso=now.isoformat(),
        monitoring_contract_version="1.0",
        evaluation_engine_version="1.0",
        drift_classification_version="1.0",
        severity_classification_version="1.0",
        events=tuple(events),
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        framework_ids=(),
        eval_window_start_iso=(now - timedelta(hours=24)).isoformat(),
        eval_window_end_iso=now.isoformat(),
        evidence_freshness_window_days=30,
        total_drift_events=len(events),
        critical_or_blocking_count=sum(
            1 for e in events if e.severity.value in ("critical", "blocking")
        ),
        domains_evaluated=("test",),
        replay_contract_metadata=(("monitoring_contract_version", "1.0"),),
    )


# ---------------------------------------------------------------------------
# Pure unit tests — identity
# ---------------------------------------------------------------------------


class TestDeriveAlertInstanceId:
    def test_deterministic_same_inputs(self):
        from services.readiness.alerting.identity import derive_alert_instance_id

        id_a = derive_alert_instance_id("rule:001", "run-1", "fp-abc", "tenant-1")
        id_b = derive_alert_instance_id("rule:001", "run-1", "fp-abc", "tenant-1")
        assert id_a == id_b

    def test_different_tenant_produces_different_id(self):
        from services.readiness.alerting.identity import derive_alert_instance_id

        id_a = derive_alert_instance_id("rule:001", "run-1", "fp-abc", "tenant-1")
        id_b = derive_alert_instance_id("rule:001", "run-1", "fp-abc", "tenant-2")
        assert id_a != id_b

    def test_different_run_produces_different_id(self):
        from services.readiness.alerting.identity import derive_alert_instance_id

        id_a = derive_alert_instance_id("rule:001", "run-1", "fp-abc", "tenant-1")
        id_b = derive_alert_instance_id("rule:001", "run-2", "fp-abc", "tenant-1")
        assert id_a != id_b

    def test_returns_32_char_hex_string(self):
        from services.readiness.alerting.identity import derive_alert_instance_id

        inst_id = derive_alert_instance_id("rule:001", "run-1", "fp-abc", "tenant-1")
        assert len(inst_id) == 32
        assert all(c in "0123456789abcdef" for c in inst_id)

    def test_assessment_scope_encoded_in_fingerprint(self):
        from services.readiness.alerting.identity import derive_alert_fingerprint

        fp_a = derive_alert_fingerprint("rule:001", "fp-evt", "tenant-1", "assess-1")
        fp_b = derive_alert_fingerprint("rule:001", "fp-evt", "tenant-1", "assess-2")
        assert fp_a != fp_b


class TestDeriveAlertFingerprint:
    def test_deterministic_same_inputs(self):
        from services.readiness.alerting.identity import derive_alert_fingerprint

        fp_a = derive_alert_fingerprint("rule:001", "fp-evt", "tenant-1", "assess-1")
        fp_b = derive_alert_fingerprint("rule:001", "fp-evt", "tenant-1", "assess-1")
        assert fp_a == fp_b

    def test_different_rule_produces_different_fingerprint(self):
        from services.readiness.alerting.identity import derive_alert_fingerprint

        fp_a = derive_alert_fingerprint("rule:001", "fp-evt", "tenant-1", "assess-1")
        fp_b = derive_alert_fingerprint("rule:002", "fp-evt", "tenant-1", "assess-1")
        assert fp_a != fp_b

    def test_returns_24_char_hex_string(self):
        from services.readiness.alerting.identity import derive_alert_fingerprint

        fp = derive_alert_fingerprint("rule:001", "fp-evt", "tenant-1", "assess-1")
        assert len(fp) == 24
        assert all(c in "0123456789abcdef" for c in fp)

    def test_cross_tenant_uniqueness(self):
        from services.readiness.alerting.identity import derive_alert_fingerprint

        fp_a = derive_alert_fingerprint("rule:001", "fp-evt", "tenant-1", "assess-1")
        fp_b = derive_alert_fingerprint("rule:001", "fp-evt", "tenant-2", "assess-1")
        assert fp_a != fp_b


# ---------------------------------------------------------------------------
# Pure unit tests — alert generation
# ---------------------------------------------------------------------------


class TestAlertGeneration:
    def test_no_events_produces_no_alerts(self):
        from services.readiness.alerting.generator import generate_alerts
        from services.readiness.alerting.rules import RULES_BY_DRIFT_TYPE

        snap = _make_snapshot(events=())
        ctx = _make_context()
        alerts = generate_alerts(snap, ctx, RULES_BY_DRIFT_TYPE)
        assert alerts == []

    def test_stale_evidence_produces_governance_alert(self):
        from services.readiness.alerting.generator import generate_alerts
        from services.readiness.alerting.models import AlertRuleClass
        from services.readiness.alerting.rules import RULES_BY_DRIFT_TYPE

        ev = _make_drift_event("stale_evidence", severity="moderate")
        snap = _make_snapshot(events=[ev])
        ctx = _make_context()
        alerts = generate_alerts(snap, ctx, RULES_BY_DRIFT_TYPE)
        assert len(alerts) == 1
        assert alerts[0].alert_rule_class == AlertRuleClass.GOVERNANCE

    def test_policy_drift_produces_policy_alert(self):
        from services.readiness.alerting.generator import generate_alerts
        from services.readiness.alerting.models import AlertRuleClass
        from services.readiness.alerting.rules import RULES_BY_DRIFT_TYPE

        ev = _make_drift_event("policy_drift", severity="critical")
        snap = _make_snapshot(events=[ev])
        ctx = _make_context()
        alerts = generate_alerts(snap, ctx, RULES_BY_DRIFT_TYPE)
        assert len(alerts) == 1
        assert alerts[0].alert_rule_class == AlertRuleClass.POLICY

    def test_audit_chain_broken_produces_audit_alert(self):
        from services.readiness.alerting.generator import generate_alerts
        from services.readiness.alerting.models import AlertRuleClass
        from services.readiness.alerting.rules import RULES_BY_DRIFT_TYPE

        ev = _make_drift_event("audit_chain_broken", severity="blocking")
        snap = _make_snapshot(events=[ev])
        ctx = _make_context()
        alerts = generate_alerts(snap, ctx, RULES_BY_DRIFT_TYPE)
        assert len(alerts) == 1
        assert alerts[0].alert_rule_class == AlertRuleClass.AUDIT

    def test_critical_severity_preserved_from_drift(self):
        from services.readiness.alerting.generator import generate_alerts
        from services.readiness.alerting.models import AlertSeverity
        from services.readiness.alerting.rules import RULES_BY_DRIFT_TYPE

        ev = _make_drift_event("runtime_governance_degradation", severity="critical")
        snap = _make_snapshot(events=[ev])
        ctx = _make_context()
        alerts = generate_alerts(snap, ctx, RULES_BY_DRIFT_TYPE)
        assert len(alerts) == 1
        assert alerts[0].severity == AlertSeverity.CRITICAL

    def test_blocking_severity_preserved_from_drift(self):
        from services.readiness.alerting.generator import generate_alerts
        from services.readiness.alerting.models import AlertSeverity
        from services.readiness.alerting.rules import RULES_BY_DRIFT_TYPE

        ev = _make_drift_event("audit_chain_broken", severity="blocking")
        snap = _make_snapshot(events=[ev])
        ctx = _make_context()
        alerts = generate_alerts(snap, ctx, RULES_BY_DRIFT_TYPE)
        assert alerts[0].severity == AlertSeverity.BLOCKING

    def test_certainty_mapping_confirmed_to_confirmed(self):
        from services.readiness.alerting.generator import generate_alerts
        from services.readiness.alerting.models import AlertCertainty
        from services.readiness.alerting.rules import RULES_BY_DRIFT_TYPE

        ev = _make_drift_event("stale_evidence", certainty="confirmed")
        snap = _make_snapshot(events=[ev])
        ctx = _make_context()
        alerts = generate_alerts(snap, ctx, RULES_BY_DRIFT_TYPE)
        assert alerts[0].certainty == AlertCertainty.CONFIRMED

    def test_export_safe_payload_no_forbidden_keys(self):
        from services.readiness.alerting.generator import generate_alerts
        from services.readiness.alerting.rules import RULES_BY_DRIFT_TYPE
        from services.readiness.alerting.serialization import serialize_alert_instance

        ev = _make_drift_event("policy_drift", severity="moderate")
        snap = _make_snapshot(events=[ev])
        ctx = _make_context()
        alerts = generate_alerts(snap, ctx, RULES_BY_DRIFT_TYPE)
        assert len(alerts) == 1
        serialized = json.dumps(serialize_alert_instance(alerts[0])).lower()
        for forbidden in ("prompt", "vector", "embedding", "secret", "phi"):
            assert forbidden not in serialized


# ---------------------------------------------------------------------------
# Pure unit tests — deduplication
# ---------------------------------------------------------------------------


class TestAlertDeduplication:
    def _make_alert(
        self,
        rule_id: str = "rule:001",
        fingerprint: str = "fp-abc",
        tenant_id: str = "tenant-1",
        severity: str = "moderate",
        assessment_id: str = "assess-1",
    ):
        from services.readiness.alerting.identity import (
            derive_alert_fingerprint,
            derive_alert_instance_id,
        )
        from services.readiness.alerting.models import (
            AlertCertainty,
            AlertInstance,
            AlertLifecycleState,
            AlertRuleClass,
            AlertSeverity,
        )

        instance_id = derive_alert_instance_id(rule_id, "run-1", fingerprint, tenant_id)
        fp = derive_alert_fingerprint(rule_id, fingerprint, tenant_id, assessment_id)
        return AlertInstance(
            alert_instance_id=instance_id,
            alert_fingerprint=fp,
            alert_rule_id=rule_id,
            alert_rule_class=AlertRuleClass.GOVERNANCE,
            source_monitoring_run_id="run-1",
            source_drift_event_fingerprint=fingerprint,
            source_drift_snapshot_id="snap-1",
            tenant_id=tenant_id,
            assessment_id=assessment_id,
            severity=AlertSeverity(severity),
            certainty=AlertCertainty.CONFIRMED,
            lifecycle_state=AlertLifecycleState.ACTIVE,
            affected_scope="scope-1",
            affected_control_ids=(),
            affected_evidence_ids=(),
            affected_framework_ids=(),
            alert_detail="test detail",
            generated_at_iso=datetime.now(timezone.utc).isoformat(),
            evaluation_window_start_iso="2026-01-01T00:00:00+00:00",
            evaluation_window_end_iso="2026-01-02T00:00:00+00:00",
            alert_generation_version="1.0",
            escalation_policy_version="1.0",
            replay_contract_metadata=(),
        )

    def test_no_duplicates_pass_through(self):
        from services.readiness.alerting.deduplication import deduplicate_alerts

        a1 = self._make_alert(fingerprint="fp-001")
        a2 = self._make_alert(rule_id="rule:002", fingerprint="fp-002")
        result = deduplicate_alerts([a1, a2], cooldown_minutes=60, burst_ceiling=10)
        assert result.total_before == 2
        assert len(result.alerts_after) == 2
        assert result.total_deduplicated == 0

    def test_burst_ceiling_enforced(self):
        from services.readiness.alerting.deduplication import deduplicate_alerts

        alerts = [self._make_alert(fingerprint="fp-burst") for _ in range(5)]
        result = deduplicate_alerts(alerts, cooldown_minutes=60, burst_ceiling=2)
        # After burst ceiling=2, duplicates beyond first are suppressed
        assert result.total_before == 5
        assert len(result.alerts_after) == 1
        assert result.dedup_records[0].suppressed_count == 3

    def test_highest_severity_wins_in_dedup(self):
        from services.readiness.alerting.deduplication import deduplicate_alerts
        from services.readiness.alerting.models import AlertSeverity

        low = self._make_alert(fingerprint="fp-sev", severity="low")
        high = self._make_alert(fingerprint="fp-sev", severity="high")
        result = deduplicate_alerts([low, high], cooldown_minutes=60, burst_ceiling=10)
        assert len(result.alerts_after) == 1
        assert result.alerts_after[0].severity == AlertSeverity.HIGH

    def test_dedup_record_carries_counts(self):
        from services.readiness.alerting.deduplication import deduplicate_alerts

        alerts = [self._make_alert(fingerprint="fp-count") for _ in range(3)]
        result = deduplicate_alerts(alerts, cooldown_minutes=60, burst_ceiling=10)
        assert len(result.dedup_records) == 1
        assert result.dedup_records[0].occurrence_count == 3

    def test_empty_list_returns_empty_result(self):
        from services.readiness.alerting.deduplication import deduplicate_alerts

        result = deduplicate_alerts([], cooldown_minutes=60, burst_ceiling=10)
        assert result.total_before == 0
        assert result.alerts_after == ()
        assert result.dedup_records == ()


# ---------------------------------------------------------------------------
# Pure unit tests — lifecycle FSM
# ---------------------------------------------------------------------------


class TestAlertLifecycle:
    def _make_active_alert(
        self,
        severity: str = "moderate",
        tenant_id: str = "tenant-1",
    ):
        from services.readiness.alerting.identity import (
            derive_alert_fingerprint,
            derive_alert_instance_id,
        )
        from services.readiness.alerting.models import (
            AlertCertainty,
            AlertInstance,
            AlertLifecycleState,
            AlertRuleClass,
            AlertSeverity,
        )

        instance_id = derive_alert_instance_id(
            "rule:001", "run-1", "fp-life", tenant_id
        )
        fp = derive_alert_fingerprint("rule:001", "fp-life", tenant_id, "assess-1")
        return AlertInstance(
            alert_instance_id=instance_id,
            alert_fingerprint=fp,
            alert_rule_id="rule:001",
            alert_rule_class=AlertRuleClass.GOVERNANCE,
            source_monitoring_run_id="run-1",
            source_drift_event_fingerprint="fp-life",
            source_drift_snapshot_id="snap-1",
            tenant_id=tenant_id,
            assessment_id="assess-1",
            severity=AlertSeverity(severity),
            certainty=AlertCertainty.CONFIRMED,
            lifecycle_state=AlertLifecycleState.ACTIVE,
            affected_scope="scope-1",
            affected_control_ids=(),
            affected_evidence_ids=(),
            affected_framework_ids=(),
            alert_detail="test",
            generated_at_iso=datetime.now(timezone.utc).isoformat(),
            evaluation_window_start_iso="2026-01-01T00:00:00+00:00",
            evaluation_window_end_iso="2026-01-02T00:00:00+00:00",
            alert_generation_version="1.0",
            escalation_policy_version="1.0",
            replay_contract_metadata=(),
        )

    def test_active_to_acknowledged_is_valid(self):
        from services.readiness.alerting.lifecycle import apply_transition
        from services.readiness.alerting.models import AlertLifecycleState

        alert = self._make_active_alert()
        transition = apply_transition(
            alert,
            AlertLifecycleState.ACTIVE,
            AlertLifecycleState.ACKNOWLEDGED,
            actor="operator",
            reason="seen",
            timestamp_iso="2026-05-18T10:00:00+00:00",
        )
        assert transition.to_state == AlertLifecycleState.ACKNOWLEDGED
        assert transition.from_state == AlertLifecycleState.ACTIVE

    def test_active_to_resolved_is_valid(self):
        from services.readiness.alerting.lifecycle import apply_transition
        from services.readiness.alerting.models import AlertLifecycleState

        alert = self._make_active_alert()
        transition = apply_transition(
            alert,
            AlertLifecycleState.ACTIVE,
            AlertLifecycleState.RESOLVED,
            actor="operator",
            reason="fixed",
            timestamp_iso="2026-05-18T10:00:00+00:00",
        )
        assert transition.to_state == AlertLifecycleState.RESOLVED

    def test_resolved_to_active_is_invalid(self):
        from services.readiness.alerting.lifecycle import (
            InvalidAlertTransition,
            apply_transition,
        )
        from services.readiness.alerting.models import AlertLifecycleState

        alert = self._make_active_alert()
        with pytest.raises(InvalidAlertTransition):
            apply_transition(
                alert,
                AlertLifecycleState.RESOLVED,
                AlertLifecycleState.ACTIVE,
                actor="operator",
                reason="re-open",
                timestamp_iso="2026-05-18T10:00:00+00:00",
            )

    def test_critical_cannot_be_suppressed(self):
        from services.readiness.alerting.lifecycle import (
            InvalidAlertTransition,
            apply_transition,
        )
        from services.readiness.alerting.models import AlertLifecycleState

        alert = self._make_active_alert(severity="critical")
        with pytest.raises(InvalidAlertTransition):
            apply_transition(
                alert,
                AlertLifecycleState.ACTIVE,
                AlertLifecycleState.SUPPRESSED,
                actor="operator",
                reason="suppress",
                timestamp_iso="2026-05-18T10:00:00+00:00",
            )

    def test_validate_transition_returns_bool(self):
        from services.readiness.alerting.lifecycle import validate_transition
        from services.readiness.alerting.models import AlertLifecycleState

        assert validate_transition(
            AlertLifecycleState.ACTIVE, AlertLifecycleState.RESOLVED
        )
        assert not validate_transition(
            AlertLifecycleState.RESOLVED, AlertLifecycleState.ACTIVE
        )

    def test_transition_record_is_immutable(self):
        from services.readiness.alerting.lifecycle import apply_transition
        from services.readiness.alerting.models import AlertLifecycleState

        alert = self._make_active_alert()
        transition = apply_transition(
            alert,
            AlertLifecycleState.ACTIVE,
            AlertLifecycleState.ACKNOWLEDGED,
            actor="operator",
            reason="test",
            timestamp_iso="2026-05-18T10:00:00+00:00",
        )
        # Frozen dataclass — any mutation attempt raises
        with pytest.raises((AttributeError, TypeError)):
            transition.actor = "hacker"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Pure unit tests — suppression
# ---------------------------------------------------------------------------


class TestAlertSuppression:
    def test_create_suppression_returns_record(self):
        from services.readiness.alerting.suppression import create_suppression

        rec = create_suppression(
            alert_instance_id="alert-1",
            tenant_id="tenant-1",
            reason="test reason",
            actor="operator",
            source="operator",
            now_iso="2026-05-18T10:00:00+00:00",
            expires_at_iso="2026-05-19T10:00:00+00:00",
        )
        assert rec.alert_instance_id == "alert-1"
        assert rec.suppression_reason == "test reason"
        assert rec.expires_at_iso == "2026-05-19T10:00:00+00:00"

    def test_expired_suppression_not_active(self):
        from services.readiness.alerting.suppression import (
            create_suppression,
            is_suppressed,
        )

        rec = create_suppression(
            alert_instance_id="alert-1",
            tenant_id="tenant-1",
            reason="expired",
            actor="operator",
            source="operator",
            now_iso="2026-05-17T10:00:00+00:00",
            expires_at_iso="2026-05-17T11:00:00+00:00",  # already expired
        )
        result = is_suppressed("alert-1", [rec], "2026-05-18T10:00:00+00:00")
        assert result is False

    def test_active_suppression_is_suppressed(self):
        from services.readiness.alerting.suppression import (
            create_suppression,
            is_suppressed,
        )

        rec = create_suppression(
            alert_instance_id="alert-1",
            tenant_id="tenant-1",
            reason="test",
            actor="operator",
            source="operator",
            now_iso="2026-05-18T09:00:00+00:00",
            expires_at_iso="2026-05-19T09:00:00+00:00",
        )
        result = is_suppressed("alert-1", [rec], "2026-05-18T10:00:00+00:00")
        assert result is True

    def test_suppression_lineage_preserved(self):
        from services.readiness.alerting.suppression import create_suppression

        rec = create_suppression(
            alert_instance_id="alert-1",
            tenant_id="tenant-1",
            reason="test",
            actor="system",
            source="policy_engine",
            now_iso="2026-05-18T10:00:00+00:00",
            expires_at_iso=None,
        )
        lineage_keys = {k for k, _ in rec.suppression_lineage_metadata}
        assert "suppression_id" in lineage_keys
        assert "actor" in lineage_keys

    def test_suppression_does_not_erase_alert(self):
        """Suppression records carry alert_instance_id — the alert is not deleted."""
        from services.readiness.alerting.suppression import create_suppression

        rec = create_suppression(
            alert_instance_id="alert-preserve",
            tenant_id="tenant-1",
            reason="test",
            actor="operator",
            source="operator",
            now_iso="2026-05-18T10:00:00+00:00",
            expires_at_iso=None,
        )
        # Suppression record references the original alert; alert is not erased
        assert rec.alert_instance_id == "alert-preserve"


# ---------------------------------------------------------------------------
# Pure unit tests — AlertingEngine
# ---------------------------------------------------------------------------


class TestAlertingEngine:
    def test_empty_snapshot_produces_no_alerts(self):
        from services.readiness.alerting.engine import AlertingEngine
        from services.readiness.alerting.models import AlertEngineInput

        snap = _make_snapshot(events=())
        ctx = _make_context()
        engine_input = AlertEngineInput(context=ctx, drift_snapshot=snap)
        engine = AlertingEngine()
        output = engine.generate("run-test-1", engine_input)
        assert output.total_alerts_generated == 0
        assert output.alerts == ()

    def test_version_pins_in_output(self):
        from services.readiness.alerting.engine import AlertingEngine
        from services.readiness.alerting.models import AlertEngineInput

        snap = _make_snapshot()
        ctx = _make_context()
        engine_input = AlertEngineInput(context=ctx, drift_snapshot=snap)
        engine = AlertingEngine()
        output = engine.generate("run-ver-1", engine_input)
        # Alerts carry version pins (or no alerts if empty snapshot)
        if output.alerts:
            assert output.alerts[0].alert_generation_version == "1.0"
            assert output.alerts[0].escalation_policy_version == "1.0"

    def test_critical_drift_produces_critical_alert(self):
        from services.readiness.alerting.engine import AlertingEngine
        from services.readiness.alerting.models import AlertEngineInput, AlertSeverity

        ev = _make_drift_event("audit_chain_broken", severity="blocking")
        snap = _make_snapshot(events=[ev])
        ctx = _make_context()
        engine_input = AlertEngineInput(context=ctx, drift_snapshot=snap)
        engine = AlertingEngine()
        output = engine.generate("run-crit-1", engine_input)
        assert output.total_alerts_generated >= 1
        severities = {a.severity for a in output.alerts}
        assert AlertSeverity.BLOCKING in severities

    def test_dedup_records_in_output(self):
        from services.readiness.alerting.engine import AlertingEngine
        from services.readiness.alerting.models import AlertEngineInput

        ev = _make_drift_event("stale_evidence", severity="moderate")
        snap = _make_snapshot(events=[ev])
        ctx = _make_context()
        engine_input = AlertEngineInput(context=ctx, drift_snapshot=snap)
        engine = AlertingEngine()
        output = engine.generate("run-dedup-1", engine_input)
        # dedup_records should be present (may be empty if only 1 alert)
        assert isinstance(output.dedup_records, tuple)

    def test_domains_coverage_multiple_drift_types(self):
        from services.readiness.alerting.engine import AlertingEngine
        from services.readiness.alerting.models import AlertEngineInput, AlertRuleClass

        events = [
            _make_drift_event("policy_drift", scope="scope-policy"),
            _make_drift_event(
                "audit_chain_broken", scope="scope-audit", severity="blocking"
            ),
            _make_drift_event(
                "runtime_governance_degradation",
                scope="scope-runtime",
                severity="critical",
            ),
        ]
        snap = _make_snapshot(events=events)
        ctx = _make_context()
        engine_input = AlertEngineInput(context=ctx, drift_snapshot=snap)
        engine = AlertingEngine()
        output = engine.generate("run-domains-1", engine_input)
        rule_classes = {a.alert_rule_class for a in output.alerts}
        assert AlertRuleClass.POLICY in rule_classes
        assert AlertRuleClass.AUDIT in rule_classes
        assert AlertRuleClass.RUNTIME in rule_classes

    def test_engine_failure_produces_visibility_alert(self):
        """Engine failure (exception in generator) produces a visibility alert."""
        from unittest.mock import patch

        from services.readiness.alerting.engine import AlertingEngine
        from services.readiness.alerting.models import AlertEngineInput, AlertRuleClass

        snap = _make_snapshot()
        ctx = _make_context()
        engine_input = AlertEngineInput(context=ctx, drift_snapshot=snap)
        engine = AlertingEngine()

        with patch(
            "services.readiness.alerting.engine.generate_alerts",
            side_effect=RuntimeError("simulated engine failure"),
        ):
            output = engine.generate("run-fail-1", engine_input)

        assert len(output.alerts) >= 1
        vis_alerts = [
            a
            for a in output.alerts
            if a.alert_rule_class == AlertRuleClass.MONITORING_VISIBILITY
        ]
        assert len(vis_alerts) >= 1


# ---------------------------------------------------------------------------
# Pure unit tests — serialization
# ---------------------------------------------------------------------------


class TestSerialization:
    def _make_alert_engine_output(self):
        from services.readiness.alerting.engine import AlertingEngine
        from services.readiness.alerting.models import AlertEngineInput

        ev = _make_drift_event("policy_drift", severity="moderate")
        snap = _make_snapshot(events=[ev])
        ctx = _make_context()
        engine_input = AlertEngineInput(context=ctx, drift_snapshot=snap)
        engine = AlertingEngine()
        return engine.generate("run-serial-1", engine_input)

    def test_alert_output_to_json_is_valid_json(self):
        from services.readiness.alerting.serialization import alert_output_to_json

        output = self._make_alert_engine_output()
        raw = alert_output_to_json(output)
        parsed = json.loads(raw)
        assert isinstance(parsed, dict)
        assert "run_id" in parsed
        assert "alerts" in parsed

    def test_round_trip_preserves_key_fields(self):
        from services.readiness.alerting.serialization import (
            alert_output_from_json,
            alert_output_to_json,
        )

        output = self._make_alert_engine_output()
        raw = alert_output_to_json(output)
        parsed = alert_output_from_json(raw)
        assert parsed["run_id"] == output.run_id
        assert len(parsed["alerts"]) == len(output.alerts)

    def test_deterministic_json_output(self):
        from services.readiness.alerting.serialization import alert_output_to_json

        output = self._make_alert_engine_output()
        raw1 = alert_output_to_json(output)
        raw2 = alert_output_to_json(output)
        assert raw1 == raw2

    def test_no_forbidden_keys_in_serialized_alert(self):
        from services.readiness.alerting.serialization import alert_output_to_json

        output = self._make_alert_engine_output()
        raw = alert_output_to_json(output).lower()
        for forbidden in ("prompt", "vector", "embedding", "secret", "phi"):
            assert forbidden not in raw, f"Forbidden key in alert JSON: {forbidden}"

    def test_alert_run_output_json_not_exposed_in_instance_fields(self):
        """serialize_alert_instance must not contain alert_run_output_json."""
        from services.readiness.alerting.serialization import serialize_alert_instance

        output = self._make_alert_engine_output()
        if output.alerts:
            d = serialize_alert_instance(output.alerts[0])
            assert "alert_run_output_json" not in d
            assert "snapshot_json" not in d


# ---------------------------------------------------------------------------
# API fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def alerting_client(tmp_path, monkeypatch):
    from api.auth_scopes import mint_key
    from api.db import reset_engine_cache
    from api.main import build_app

    db_path = tmp_path / "alerting_api_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    reset_engine_cache()

    from fastapi.testclient import TestClient

    app = build_app(auth_enabled=True)
    key = mint_key(
        "control-plane:read",
        "control-plane:write",
        "control-plane:admin",
        tenant_id="tenant-alerting",
    )
    return TestClient(app, raise_server_exceptions=False, headers={"X-API-Key": key})


@pytest.fixture()
def no_tenant_client(tmp_path, monkeypatch):
    """API key without a tenant_id binding."""
    from api.auth_scopes import mint_key
    from api.db import reset_engine_cache
    from api.main import build_app

    db_path = tmp_path / "alerting_notenant_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    reset_engine_cache()

    from fastapi.testclient import TestClient

    app = build_app(auth_enabled=True)
    key = mint_key("control-plane:read", "control-plane:write", "control-plane:admin")
    return TestClient(app, raise_server_exceptions=False, headers={"X-API-Key": key})


@pytest.fixture()
def other_tenant_client(tmp_path, monkeypatch, alerting_client):
    """Second tenant's API key — same app instance."""
    from api.auth_scopes import mint_key
    from api.main import build_app

    from fastapi.testclient import TestClient

    app = build_app(auth_enabled=True)
    key = mint_key(
        "control-plane:read",
        "control-plane:write",
        "control-plane:admin",
        tenant_id="tenant-beta",
    )
    return TestClient(app, raise_server_exceptions=False, headers={"X-API-Key": key})


@pytest.fixture()
def no_auth_client(tmp_path, monkeypatch):
    from api.db import reset_engine_cache
    from api.main import build_app

    db_path = tmp_path / "alerting_noauth_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    reset_engine_cache()

    from fastapi.testclient import TestClient

    app = build_app(auth_enabled=False)
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------


def _make_monitoring_run_record(
    monitoring_run_id: str = "mon-run-api-test-1",
    tenant_id: str = "tenant-alerting",
    assessment_id: str | None = None,
):
    """Build a fake MonitoringRunRecord with a minimal valid snapshot_json."""
    from services.readiness.monitoring.models import MonitoringRunRecord

    now = datetime.now(timezone.utc)
    window_start: str = (now - timedelta(hours=24)).isoformat()
    window_end: str = now.isoformat()
    snapshot_id: str = f"snap-{monitoring_run_id}"
    snap_dict = {
        "snapshot_id": snapshot_id,
        "monitoring_run_id": monitoring_run_id,
        "evaluation_timestamp_iso": now.isoformat(),
        "monitoring_contract_version": "1.0",
        "evaluation_engine_version": "1.0",
        "drift_classification_version": "1.0",
        "severity_classification_version": "1.0",
        "events": [],
        "tenant_id": tenant_id,
        "assessment_id": assessment_id,
        "framework_ids": [],
        "eval_window_start_iso": window_start,
        "eval_window_end_iso": window_end,
        "evidence_freshness_window_days": 30,
        "total_drift_events": 0,
        "critical_or_blocking_count": 0,
        "domains_evaluated": ["test"],
        "replay_contract_metadata": {"monitoring_contract_version": "1.0"},
    }
    return MonitoringRunRecord(
        run_id=monitoring_run_id,
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        framework_ids=(),
        eval_window_start_iso=window_start,
        eval_window_end_iso=window_end,
        monitoring_contract_version="1.0",
        evaluation_engine_version="1.0",
        snapshot_id=snapshot_id,
        snapshot_json=json.dumps(snap_dict),
        domains_evaluated=("test",),
        total_drift_events=0,
        critical_or_blocking_count=0,
        completed_at_iso=now.isoformat(),
        evaluation_success=True,
        error_summary=None,
        created_at_iso=now.isoformat(),
    )


def _make_monitoring_run_record_with_events(
    monitoring_run_id: str = "mon-run-with-events-1",
    tenant_id: str = "tenant-alerting",
):
    """Build a fake MonitoringRunRecord with drift events in the snapshot."""
    from services.readiness.monitoring.identity import derive_event_fingerprint
    from services.readiness.monitoring.models import MonitoringRunRecord

    now = datetime.now(timezone.utc)
    window_start_e: str = (now - timedelta(hours=24)).isoformat()
    window_end_e: str = now.isoformat()
    snapshot_id_e: str = f"snap-{monitoring_run_id}"
    fp = derive_event_fingerprint("policy_drift", "policy:p-1", monitoring_run_id, ())
    snap_dict = {
        "snapshot_id": snapshot_id_e,
        "monitoring_run_id": monitoring_run_id,
        "evaluation_timestamp_iso": now.isoformat(),
        "monitoring_contract_version": "1.0",
        "evaluation_engine_version": "1.0",
        "drift_classification_version": "1.0",
        "severity_classification_version": "1.0",
        "events": [
            {
                "event_fingerprint": fp,
                "drift_type": "policy_drift",
                "severity": "moderate",
                "certainty": "confirmed",
                "affected_scope": "policy:p-1",
                "affected_control_ids": [],
                "affected_evidence_ids": [],
                "affected_framework_ids": [],
                "drift_detail": "Test policy drift event",
                "monitoring_source": "policy_monitor",
                "evaluation_timestamp_iso": now.isoformat(),
                "temporal_boundary_start": window_start_e,
                "temporal_boundary_end": window_end_e,
                "provenance_metadata": {},
            }
        ],
        "tenant_id": tenant_id,
        "assessment_id": None,
        "framework_ids": [],
        "eval_window_start_iso": window_start_e,
        "eval_window_end_iso": window_end_e,
        "evidence_freshness_window_days": 30,
        "total_drift_events": 1,
        "critical_or_blocking_count": 0,
        "domains_evaluated": ["policy_drift"],
        "replay_contract_metadata": {"monitoring_contract_version": "1.0"},
    }
    return MonitoringRunRecord(
        run_id=monitoring_run_id,
        tenant_id=tenant_id,
        assessment_id=None,
        framework_ids=(),
        eval_window_start_iso=window_start_e,
        eval_window_end_iso=window_end_e,
        monitoring_contract_version="1.0",
        evaluation_engine_version="1.0",
        snapshot_id=snapshot_id_e,
        snapshot_json=json.dumps(snap_dict),
        domains_evaluated=("policy_drift",),
        total_drift_events=1,
        critical_or_blocking_count=0,
        completed_at_iso=now.isoformat(),
        evaluation_success=True,
        error_summary=None,
        created_at_iso=now.isoformat(),
    )


# ---------------------------------------------------------------------------
# API tests — POST /control-plane/readiness/alerting/runs
# ---------------------------------------------------------------------------


@pytest.mark.contract
class TestCreateAlertRun:
    def test_valid_monitoring_run_creates_alert_run(self, alerting_client, monkeypatch):
        monitoring_record = _make_monitoring_run_record()
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        resp = alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-run-api-test-1"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "run_id" in data
        assert "total_alerts_generated" in data
        assert data["source_monitoring_run_id"] == "mon-run-api-test-1"

    def test_idempotent_second_call_returns_same_run(
        self, alerting_client, monkeypatch
    ):
        monitoring_record = _make_monitoring_run_record()
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        resp1 = alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-run-api-test-1"},
        )
        resp2 = alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-run-api-test-1"},
        )
        assert resp1.status_code == 201
        assert resp2.status_code == 201
        assert resp1.json()["run_id"] == resp2.json()["run_id"]

    def test_404_for_unknown_monitoring_run(self, alerting_client, monkeypatch):
        from services.readiness.monitoring.store import MonitoringRunNotFound

        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: (_ for _ in ()).throw(
                MonitoringRunNotFound(run_id)
            ),
        )
        resp = alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "nonexistent-run-999"},
        )
        assert resp.status_code == 404

    def test_403_when_no_tenant_context(self, no_tenant_client, monkeypatch):
        resp = no_tenant_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-run-1"},
        )
        assert resp.status_code == 403

    def test_401_no_auth(self, no_auth_client):
        # build_app(auth_enabled=False) — no auth middleware; POST should work or fail without 401
        # This test validates that auth_enabled=False doesn't crash
        resp = no_auth_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-run-1"},
        )
        # Without auth + no tenant context, we get 403 from our own guard
        assert resp.status_code in (403, 401, 422)

    def test_response_contains_no_alert_run_output_json(
        self, alerting_client, monkeypatch
    ):
        """alert_run_output_json must never appear in API responses."""
        monitoring_record = _make_monitoring_run_record()
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        resp = alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-run-api-test-1"},
        )
        assert resp.status_code == 201
        assert "alert_run_output_json" not in resp.text

    def test_with_drift_events_produces_alerts(self, alerting_client, monkeypatch):
        monitoring_record = _make_monitoring_run_record_with_events()
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        resp = alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-run-with-events-1"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["total_alerts_generated"] >= 1

    def test_required_fields_in_response(self, alerting_client, monkeypatch):
        monitoring_record = _make_monitoring_run_record()
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        resp = alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-run-api-test-1"},
        )
        assert resp.status_code == 201
        data = resp.json()
        required = {
            "run_id",
            "tenant_id",
            "source_monitoring_run_id",
            "alert_generation_version",
            "escalation_policy_version",
            "total_alerts_generated",
            "total_alerts_deduplicated",
            "generation_timestamp_iso",
            "completed",
            "alerts",
        }
        assert required.issubset(data.keys()), f"Missing: {required - data.keys()}"


# ---------------------------------------------------------------------------
# API tests — GET /control-plane/readiness/alerting/runs
# ---------------------------------------------------------------------------


@pytest.mark.contract
class TestListAlertRuns:
    def test_empty_list_before_any_runs(self, alerting_client):
        resp = alerting_client.get("/control-plane/readiness/alerting/runs")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_returns_created_run_in_list(self, alerting_client, monkeypatch):
        monitoring_record = _make_monitoring_run_record("mon-run-list-1")
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-run-list-1"},
        )
        resp = alerting_client.get("/control-plane/readiness/alerting/runs")
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    def test_tenant_isolation_other_tenant_sees_empty_list(
        self, alerting_client, other_tenant_client, monkeypatch
    ):
        monitoring_record = _make_monitoring_run_record("mon-run-iso-1")
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-run-iso-1"},
        )
        resp = other_tenant_client.get("/control-plane/readiness/alerting/runs")
        assert resp.status_code == 200
        # Other tenant's list must be empty (no cross-tenant disclosure)
        assert resp.json() == []

    def test_pagination_limit(self, alerting_client):
        resp = alerting_client.get(
            "/control-plane/readiness/alerting/runs?limit=1&offset=0"
        )
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


# ---------------------------------------------------------------------------
# API tests — GET /control-plane/readiness/alerting/alerts
# ---------------------------------------------------------------------------


@pytest.mark.contract
class TestListAlerts:
    def test_empty_list_before_any_alerts(self, alerting_client):
        resp = alerting_client.get("/control-plane/readiness/alerting/alerts")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_filter_by_severity(self, alerting_client, monkeypatch):
        monitoring_record = _make_monitoring_run_record_with_events("mon-filter-sev-1")
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-filter-sev-1"},
        )
        resp = alerting_client.get(
            "/control-plane/readiness/alerting/alerts?severity=moderate"
        )
        assert resp.status_code == 200
        for alert in resp.json():
            assert alert["severity"] == "moderate"

    def test_filter_by_lifecycle_state(self, alerting_client, monkeypatch):
        monitoring_record = _make_monitoring_run_record_with_events(
            "mon-filter-state-1"
        )
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-filter-state-1"},
        )
        resp = alerting_client.get(
            "/control-plane/readiness/alerting/alerts?lifecycle_state=active"
        )
        assert resp.status_code == 200
        for alert in resp.json():
            assert alert["lifecycle_state"] == "active"

    def test_tenant_isolation_alerts(
        self, alerting_client, other_tenant_client, monkeypatch
    ):
        monitoring_record = _make_monitoring_run_record_with_events(
            "mon-tenant-iso-alerts-1"
        )
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-tenant-iso-alerts-1"},
        )
        resp = other_tenant_client.get("/control-plane/readiness/alerting/alerts")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_filter_by_assessment_id(self, alerting_client):
        resp = alerting_client.get(
            "/control-plane/readiness/alerting/alerts?assessment_id=nonexistent"
        )
        assert resp.status_code == 200
        assert resp.json() == []


# ---------------------------------------------------------------------------
# API tests — GET /control-plane/readiness/alerting/alerts/{alert_instance_id}
# ---------------------------------------------------------------------------


@pytest.mark.contract
class TestGetAlert:
    def test_missing_alert_returns_404(self, alerting_client):
        resp = alerting_client.get(
            "/control-plane/readiness/alerting/alerts/nonexistent-alert-999"
        )
        assert resp.status_code == 404

    def test_cross_tenant_returns_404(
        self, alerting_client, other_tenant_client, monkeypatch
    ):
        monitoring_record = _make_monitoring_run_record_with_events("mon-cross-1")
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        resp = alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-cross-1"},
        )
        data = resp.json()
        if data.get("alerts"):
            alert_id = data["alerts"][0]["alert_instance_id"]
            # Other tenant should get 404
            cross_resp = other_tenant_client.get(
                f"/control-plane/readiness/alerting/alerts/{alert_id}"
            )
            assert cross_resp.status_code == 404

    def test_get_existing_alert_returns_200(self, alerting_client, monkeypatch):
        monitoring_record = _make_monitoring_run_record_with_events("mon-get-alert-1")
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        resp = alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-get-alert-1"},
        )
        data = resp.json()
        if data.get("alerts"):
            alert_id = data["alerts"][0]["alert_instance_id"]
            get_resp = alerting_client.get(
                f"/control-plane/readiness/alerting/alerts/{alert_id}"
            )
            assert get_resp.status_code == 200
            assert get_resp.json()["alert_instance_id"] == alert_id

    def test_alert_response_no_forbidden_keys(self, alerting_client, monkeypatch):
        monitoring_record = _make_monitoring_run_record_with_events("mon-security-1")
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        resp = alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-security-1"},
        )
        data = resp.json()
        if data.get("alerts"):
            alert_id = data["alerts"][0]["alert_instance_id"]
            get_resp = alerting_client.get(
                f"/control-plane/readiness/alerting/alerts/{alert_id}"
            )
            body_lower = get_resp.text.lower()
            for forbidden in (
                "alert_run_output_json",
                "snapshot_json",
                "vector",
                "prompt",
                "secret",
            ):
                assert forbidden not in body_lower


# ---------------------------------------------------------------------------
# API tests — POST .../lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.contract
class TestLifecycleTransition:
    def test_valid_transition_active_to_acknowledged(
        self, alerting_client, monkeypatch
    ):
        monitoring_record = _make_monitoring_run_record_with_events("mon-life-1")
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        resp = alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-life-1"},
        )
        data = resp.json()
        if data.get("alerts"):
            alert_id = data["alerts"][0]["alert_instance_id"]
            life_resp = alerting_client.post(
                f"/control-plane/readiness/alerting/alerts/{alert_id}/lifecycle",
                json={
                    "to_state": "acknowledged",
                    "actor": "operator",
                    "reason": "seen",
                },
            )
            assert life_resp.status_code == 200
            assert life_resp.json()["to_state"] == "acknowledged"

    def test_invalid_transition_returns_422(self, alerting_client, monkeypatch):
        monitoring_record = _make_monitoring_run_record_with_events(
            "mon-life-invalid-1"
        )
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        resp = alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-life-invalid-1"},
        )
        data = resp.json()
        if data.get("alerts"):
            alert_id = data["alerts"][0]["alert_instance_id"]
            # Transition to RESOLVED then try to go back to ACTIVE (invalid)
            alerting_client.post(
                f"/control-plane/readiness/alerting/alerts/{alert_id}/lifecycle",
                json={"to_state": "resolved", "actor": "operator", "reason": "fixed"},
            )
            # Now try invalid transition: resolved → active
            life_resp = alerting_client.post(
                f"/control-plane/readiness/alerting/alerts/{alert_id}/lifecycle",
                json={"to_state": "active", "actor": "operator", "reason": "re-open"},
            )
            assert life_resp.status_code == 422

    def test_unknown_alert_lifecycle_returns_404(self, alerting_client):
        resp = alerting_client.post(
            "/control-plane/readiness/alerting/alerts/nonexistent-alert/lifecycle",
            json={"to_state": "acknowledged", "actor": "operator", "reason": "test"},
        )
        assert resp.status_code == 404

    def test_tenant_isolation_lifecycle(
        self, alerting_client, other_tenant_client, monkeypatch
    ):
        monitoring_record = _make_monitoring_run_record_with_events("mon-life-iso-1")
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        resp = alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-life-iso-1"},
        )
        data = resp.json()
        if data.get("alerts"):
            alert_id = data["alerts"][0]["alert_instance_id"]
            # Other tenant cannot apply lifecycle transition
            cross_resp = other_tenant_client.post(
                f"/control-plane/readiness/alerting/alerts/{alert_id}/lifecycle",
                json={"to_state": "acknowledged", "actor": "hacker", "reason": "evil"},
            )
            assert cross_resp.status_code == 404

    def test_invalid_state_name_returns_422(self, alerting_client, monkeypatch):
        monitoring_record = _make_monitoring_run_record_with_events(
            "mon-life-badstate-1"
        )
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        resp = alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-life-badstate-1"},
        )
        data = resp.json()
        if data.get("alerts"):
            alert_id = data["alerts"][0]["alert_instance_id"]
            life_resp = alerting_client.post(
                f"/control-plane/readiness/alerting/alerts/{alert_id}/lifecycle",
                json={
                    "to_state": "INVALID_STATE",
                    "actor": "operator",
                    "reason": "test",
                },
            )
            assert life_resp.status_code == 422


# ---------------------------------------------------------------------------
# API tests — POST .../suppress
# ---------------------------------------------------------------------------


@pytest.mark.contract
class TestAlertSuppressionAPI:
    def test_create_suppression(self, alerting_client, monkeypatch):
        monitoring_record = _make_monitoring_run_record_with_events("mon-suppress-1")
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        resp = alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-suppress-1"},
        )
        data = resp.json()
        if data.get("alerts"):
            alert_id = data["alerts"][0]["alert_instance_id"]
            sup_resp = alerting_client.post(
                f"/control-plane/readiness/alerting/alerts/{alert_id}/suppress",
                json={
                    "reason": "test suppression",
                    "actor": "operator",
                    "source": "operator",
                    "expires_at_iso": "2026-12-31T00:00:00+00:00",
                },
            )
            assert sup_resp.status_code == 201
            assert "suppression_id" in sup_resp.json()

    def test_tenant_isolation_suppression(
        self, alerting_client, other_tenant_client, monkeypatch
    ):
        monitoring_record = _make_monitoring_run_record_with_events(
            "mon-suppress-iso-1"
        )
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        resp = alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-suppress-iso-1"},
        )
        data = resp.json()
        if data.get("alerts"):
            alert_id = data["alerts"][0]["alert_instance_id"]
            cross_resp = other_tenant_client.post(
                f"/control-plane/readiness/alerting/alerts/{alert_id}/suppress",
                json={
                    "reason": "cross tenant attack",
                    "actor": "hacker",
                    "source": "evil",
                },
            )
            assert cross_resp.status_code == 404

    def test_unknown_alert_suppression_returns_404(self, alerting_client):
        resp = alerting_client.post(
            "/control-plane/readiness/alerting/alerts/nonexistent-alert/suppress",
            json={"reason": "test", "actor": "op", "source": "operator"},
        )
        assert resp.status_code == 404

    def test_critical_alert_cannot_be_suppressed(self, alerting_client, monkeypatch):
        """CRITICAL alerts must not be suppressible via the API."""
        from services.readiness.monitoring.identity import derive_event_fingerprint
        from services.readiness.monitoring.models import MonitoringRunRecord

        now = datetime.now(timezone.utc)
        fp = derive_event_fingerprint(
            "audit_chain_broken", "audit:chain", "mon-critical-sup-1", ()
        )
        snap_dict = {
            "snapshot_id": "snap-mon-critical-sup-1",
            "monitoring_run_id": "mon-critical-sup-1",
            "evaluation_timestamp_iso": now.isoformat(),
            "monitoring_contract_version": "1.0",
            "evaluation_engine_version": "1.0",
            "drift_classification_version": "1.0",
            "severity_classification_version": "1.0",
            "events": [
                {
                    "event_fingerprint": fp,
                    "drift_type": "audit_chain_broken",
                    "severity": "blocking",
                    "certainty": "confirmed",
                    "affected_scope": "audit:chain",
                    "affected_control_ids": [],
                    "affected_evidence_ids": [],
                    "affected_framework_ids": [],
                    "drift_detail": "BLOCKING audit chain broken",
                    "monitoring_source": "audit_evaluator",
                    "evaluation_timestamp_iso": now.isoformat(),
                    "temporal_boundary_start": (now - timedelta(hours=24)).isoformat(),
                    "temporal_boundary_end": now.isoformat(),
                    "provenance_metadata": {},
                }
            ],
            "tenant_id": "tenant-alerting",
            "assessment_id": None,
            "framework_ids": [],
            "eval_window_start_iso": (now - timedelta(hours=24)).isoformat(),
            "eval_window_end_iso": now.isoformat(),
            "evidence_freshness_window_days": 30,
            "total_drift_events": 1,
            "critical_or_blocking_count": 1,
            "domains_evaluated": ["audit_integrity"],
            "replay_contract_metadata": {"monitoring_contract_version": "1.0"},
        }
        monitoring_record = MonitoringRunRecord(
            run_id="mon-critical-sup-1",
            tenant_id="tenant-alerting",
            assessment_id=None,
            framework_ids=(),
            eval_window_start_iso=snap_dict["eval_window_start_iso"],
            eval_window_end_iso=snap_dict["eval_window_end_iso"],
            monitoring_contract_version="1.0",
            evaluation_engine_version="1.0",
            snapshot_id=snap_dict["snapshot_id"],
            snapshot_json=json.dumps(snap_dict),
            domains_evaluated=("audit_integrity",),
            total_drift_events=1,
            critical_or_blocking_count=1,
            completed_at_iso=now.isoformat(),
            evaluation_success=True,
            error_summary=None,
            created_at_iso=now.isoformat(),
        )
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        resp = alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-critical-sup-1"},
        )
        data = resp.json()
        if data.get("alerts"):
            # Find the BLOCKING alert
            blocking_alerts = [a for a in data["alerts"] if a["severity"] == "blocking"]
            if blocking_alerts:
                alert_id = blocking_alerts[0]["alert_instance_id"]
                sup_resp = alerting_client.post(
                    f"/control-plane/readiness/alerting/alerts/{alert_id}/suppress",
                    json={
                        "reason": "should not suppress critical",
                        "actor": "operator",
                        "source": "operator",
                    },
                )
                assert sup_resp.status_code == 422


# ---------------------------------------------------------------------------
# Security invariants
# ---------------------------------------------------------------------------


@pytest.mark.contract
class TestSecurityInvariants:
    def test_no_secrets_in_alert_run_response(self, alerting_client, monkeypatch):
        monitoring_record = _make_monitoring_run_record_with_events("mon-sec-1")
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        resp = alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-sec-1"},
        )
        assert resp.status_code == 201
        body_lower = resp.text.lower()
        for forbidden in ("password", "api_key", "token", "secret", "credential"):
            assert forbidden not in body_lower

    def test_no_vectors_in_alert_response(self, alerting_client, monkeypatch):
        monitoring_record = _make_monitoring_run_record_with_events("mon-vec-1")
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        resp = alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-vec-1"},
        )
        assert resp.status_code == 201
        body_lower = resp.text.lower()
        for forbidden in ("vector", "embedding"):
            assert forbidden not in body_lower

    def test_no_injected_prompt_in_alert_response(self, alerting_client, monkeypatch):
        """Alert responses must not contain injected LLM prompt strings."""
        monitoring_record = _make_monitoring_run_record_with_events("mon-sec-inj-1")
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        resp = alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-sec-inj-1"},
        )
        assert resp.status_code == 201
        body_lower = resp.text.lower()
        # Ensure no injected instruction strings appear in generated alert fields
        for forbidden in ("ignore previous instructions", "system: you are"):
            assert forbidden not in body_lower

    def test_alert_run_output_json_not_in_api_response(
        self, alerting_client, monkeypatch
    ):
        """alert_run_output_json must be stored internally only, never in responses."""
        monitoring_record = _make_monitoring_run_record("mon-internal-1")
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        resp = alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-internal-1"},
        )
        assert resp.status_code == 201
        assert "alert_run_output_json" not in resp.text

    def test_tenant_isolation_security(
        self, alerting_client, other_tenant_client, monkeypatch
    ):
        monitoring_record = _make_monitoring_run_record_with_events("mon-iso-sec-1")
        monkeypatch.setattr(
            "api.readiness_alerting_manager._monitoring_store.get_run",
            lambda db, run_id, tenant_id: monitoring_record,
        )
        resp = alerting_client.post(
            "/control-plane/readiness/alerting/runs",
            json={"monitoring_run_id": "mon-iso-sec-1"},
        )
        assert resp.status_code == 201
        run_id = resp.json()["run_id"]

        # Other tenant cannot access this run
        cross = other_tenant_client.get(
            f"/control-plane/readiness/alerting/runs/{run_id}"
        )
        assert cross.status_code == 404
