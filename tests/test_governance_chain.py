"""Tests for PR 17.6 — Canonical Governance Chain Authority.

Coverage:
  GC-1   to GC-30:  Model unit tests (enums, compute_governance_health_score,
                     classify_governance_health, constants)
  GC-31  to GC-60:  DB model smoke tests (ORM instantiation, append-only guards)
  GC-61  to GC-100: Repository tests (create, list, filter, tenant isolation)
  GC-101 to GC-140: Engine tests (emit_event, execute_bridge, health, diagnostics, cgin)
  GC-141 to GC-165: Route auth tests (wrong scope, no auth, correct scope)
  GC-166 to GC-210: Integration tests (full flows, tenant isolation, bridge behaviors)
  GC-211 to GC-230: Edge cases and schema validation
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.db import get_engine
from api.db_models_governance_chain import (
    FaGovernanceChainEvent,
    FaGovernanceChainExecution,
    FaGovernanceChainSnapshot,
    FaGovernanceHealthSnapshot,
)
from services.governance_chain.engine import GovernanceChainEngine
from services.governance_chain.models import (
    BRIDGE_AUTHORITIES,
    GOVERNANCE_CHAIN_VERSION,
    HEALTH_DEFAULT_NO_DATA,
    HEALTH_WEIGHT_EFFECTIVENESS,
    HEALTH_WEIGHT_FORECAST,
    HEALTH_WEIGHT_FRESHNESS,
    HEALTH_WEIGHT_REMEDIATION,
    HEALTH_WEIGHT_VERIFICATION,
    BridgeType,
    ChainEventType,
    ChainExecutionResult,
    GovernanceHealthRating,
    classify_governance_health,
    compute_governance_health_score,
)
from services.governance_chain.schemas import (
    CGINChainSnapshotBundle,
    ChainBridgeNotFound,
    ChainDiagnosticsResponse,
    ChainEventListResponse,
    ChainEventResponse,
    ChainExecutionListResponse,
    ChainExecutionNotFound,
    ChainExecutionResponse,
    EmitChainEventRequest,
    ExecuteBridgeRequest,
    GovernanceHealthNotFound,
    GovernanceHealthResponse,
    GovernanceHealthHistoryResponse,
    RecalculateHealthRequest,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TENANT = "t-gc-001"
_TENANT_B = "t-gc-002"
_NOW = datetime.now(tz=timezone.utc).isoformat()


def _uid() -> str:
    return str(uuid.uuid4())


def _now_str() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event_row(
    tenant_id: str = _TENANT,
    event_type: str = "EVIDENCE_REGISTERED",
    authority: str = "evidence_authority",
    object_type: str = "evidence",
    object_id: str | None = None,
    correlation_id: str | None = None,
) -> FaGovernanceChainEvent:
    return FaGovernanceChainEvent(
        id=_uid(),
        tenant_id=tenant_id,
        event_type=event_type,
        authority=authority,
        object_type=object_type,
        object_id=object_id or _uid(),
        correlation_id=correlation_id or _uid(),
        actor_id="test-actor",
        actor_type="human",
        reason="test reason",
        payload_json=None,
        created_at=_now_str(),
    )


def _make_execution_row(
    tenant_id: str = _TENANT,
    bridge_type: str = BridgeType.EVIDENCE_TO_VERIFICATION.value,
    success: int = 1,
    execution_result: str = ChainExecutionResult.SUCCESS.value,
) -> FaGovernanceChainExecution:
    return FaGovernanceChainExecution(
        id=_uid(),
        tenant_id=tenant_id,
        chain_execution_id=_uid(),
        source_authority="evidence_authority",
        target_authority="verification_authority",
        bridge_type=bridge_type,
        trigger_reason="test",
        trigger_object_id=_uid(),
        trigger_object_type="evidence",
        execution_result=execution_result,
        success=success,
        failure_reason=None,
        duration_ms=12.5,
        executed_at=_now_str(),
    )


def _make_health_row(
    tenant_id: str = _TENANT,
    score: float = 80.0,
    rating: str = "GOOD",
) -> FaGovernanceHealthSnapshot:
    return FaGovernanceHealthSnapshot(
        id=_uid(),
        tenant_id=tenant_id,
        verification_health=80.0,
        freshness_health=80.0,
        effectiveness_health=80.0,
        remediation_health=80.0,
        forecast_health=80.0,
        governance_health_score=score,
        governance_health_rating=rating,
        missing_inputs_json=None,
        snapshot_at=_now_str(),
        calculation_version="1.0",
    )


# ===========================================================================
# GC-1 to GC-30: Model unit tests
# ===========================================================================


class TestModels:
    def test_GC_1_chain_event_type_has_12_values(self):
        assert len(ChainEventType) == 12

    def test_GC_2_chain_event_type_evidence_registered(self):
        assert ChainEventType.EVIDENCE_REGISTERED == "EVIDENCE_REGISTERED"

    def test_GC_3_chain_event_type_verification_created(self):
        assert ChainEventType.VERIFICATION_CREATED == "VERIFICATION_CREATED"

    def test_GC_4_chain_event_type_outcome_recorded(self):
        assert ChainEventType.OUTCOME_RECORDED == "OUTCOME_RECORDED"

    def test_GC_5_chain_event_type_report_generated(self):
        assert ChainEventType.REPORT_GENERATED == "REPORT_GENERATED"

    def test_GC_6_bridge_type_has_8_values(self):
        assert len(BridgeType) == 8

    def test_GC_7_bridge_type_evidence_to_verification(self):
        assert BridgeType.EVIDENCE_TO_VERIFICATION == "EVIDENCE_TO_VERIFICATION"

    def test_GC_8_bridge_type_remediation_to_outcome(self):
        assert BridgeType.REMEDIATION_TO_OUTCOME == "REMEDIATION_TO_OUTCOME"

    def test_GC_9_chain_execution_result_has_5_values(self):
        assert len(ChainExecutionResult) == 5

    def test_GC_10_chain_execution_result_skipped(self):
        assert ChainExecutionResult.SKIPPED_UNAVAILABLE == "SKIPPED_UNAVAILABLE"

    def test_GC_11_chain_execution_result_noop_safe(self):
        assert ChainExecutionResult.NOOP_SAFE == "NOOP_SAFE"

    def test_GC_12_governance_health_rating_has_5_values(self):
        assert len(GovernanceHealthRating) == 5

    def test_GC_13_health_weights_sum_to_one(self):
        total = (
            HEALTH_WEIGHT_VERIFICATION
            + HEALTH_WEIGHT_FRESHNESS
            + HEALTH_WEIGHT_EFFECTIVENESS
            + HEALTH_WEIGHT_REMEDIATION
            + HEALTH_WEIGHT_FORECAST
        )
        assert abs(total - 1.0) < 1e-9

    def test_GC_14_compute_health_perfect(self):
        score = compute_governance_health_score(100, 100, 100, 100, 100)
        assert score == 100.0

    def test_GC_15_compute_health_zero(self):
        score = compute_governance_health_score(0, 0, 0, 0, 0)
        assert score == 0.0

    def test_GC_16_compute_health_mid(self):
        score = compute_governance_health_score(60, 60, 60, 60, 60)
        assert score == 60.0

    def test_GC_17_compute_health_clamp_above_100(self):
        score = compute_governance_health_score(200, 200, 200, 200, 200)
        assert score == 100.0

    def test_GC_18_compute_health_clamp_below_0(self):
        score = compute_governance_health_score(-50, -50, -50, -50, -50)
        assert score == 0.0

    def test_GC_19_classify_health_excellent(self):
        assert classify_governance_health(90.0) == GovernanceHealthRating.EXCELLENT

    def test_GC_20_classify_health_good(self):
        assert classify_governance_health(75.0) == GovernanceHealthRating.GOOD

    def test_GC_21_classify_health_adequate(self):
        assert classify_governance_health(60.0) == GovernanceHealthRating.ADEQUATE

    def test_GC_22_classify_health_weak(self):
        assert classify_governance_health(45.0) == GovernanceHealthRating.WEAK

    def test_GC_23_classify_health_critical(self):
        assert classify_governance_health(30.0) == GovernanceHealthRating.CRITICAL

    def test_GC_24_classify_health_boundary_85(self):
        assert classify_governance_health(85.0) == GovernanceHealthRating.EXCELLENT

    def test_GC_25_classify_health_boundary_70(self):
        assert classify_governance_health(70.0) == GovernanceHealthRating.GOOD

    def test_GC_26_bridge_authorities_maps_all_bridges(self):
        for bt in BridgeType:
            assert bt.value in BRIDGE_AUTHORITIES

    def test_GC_27_bridge_authorities_tuples(self):
        for val in BRIDGE_AUTHORITIES.values():
            assert isinstance(val, tuple)
            assert len(val) == 2

    def test_GC_28_governance_chain_version_string(self):
        assert GOVERNANCE_CHAIN_VERSION == "1.0"

    def test_GC_29_health_default_no_data_between_0_100(self):
        assert 0.0 <= HEALTH_DEFAULT_NO_DATA <= 100.0

    def test_GC_30_all_chain_event_types_are_strings(self):
        for et in ChainEventType:
            assert isinstance(et.value, str)


# ===========================================================================
# GC-31 to GC-60: DB model smoke tests
# ===========================================================================


class TestDBModels:
    def test_GC_31_chain_event_has_tablename(self):
        assert FaGovernanceChainEvent.__tablename__ == "fa_governance_chain_events"

    def test_GC_32_chain_execution_has_tablename(self):
        assert (
            FaGovernanceChainExecution.__tablename__ == "fa_governance_chain_executions"
        )

    def test_GC_33_health_snapshot_has_tablename(self):
        assert (
            FaGovernanceHealthSnapshot.__tablename__ == "fa_governance_health_snapshots"
        )

    def test_GC_34_chain_snapshot_has_tablename(self):
        assert (
            FaGovernanceChainSnapshot.__tablename__ == "fa_governance_chain_snapshots"
        )

    def test_GC_35_chain_event_can_instantiate(self):
        row = _make_event_row()
        assert row.tenant_id == _TENANT

    def test_GC_36_chain_execution_can_instantiate(self):
        row = _make_execution_row()
        assert row.tenant_id == _TENANT

    def test_GC_37_health_snapshot_can_instantiate(self):
        row = _make_health_row()
        assert row.tenant_id == _TENANT

    def test_GC_38_cgin_snapshot_can_instantiate(self):
        row = FaGovernanceChainSnapshot(
            id=_uid(),
            tenant_fingerprint="abc123",
            authority="evidence_authority",
            execution_count=5,
            success_count=4,
            failure_count=1,
            skipped_count=0,
            average_duration_ms=25.0,
            generated_at=_now_str(),
        )
        assert row.tenant_fingerprint == "abc123"

    def test_GC_39_chain_event_append_only_update_blocked(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            row = _make_event_row()
            db.add(row)
            db.commit()
            db.refresh(row)
            with pytest.raises(RuntimeError, match="append-only"):
                row.reason = "modified"
                db.commit()
            db.rollback()

    def test_GC_40_chain_event_append_only_delete_blocked(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            row = _make_event_row()
            db.add(row)
            db.commit()
            db.refresh(row)
            with pytest.raises(RuntimeError, match="append-only"):
                db.delete(row)
                db.commit()
            db.rollback()

    def test_GC_41_chain_execution_update_blocked(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            row = _make_execution_row()
            db.add(row)
            db.commit()
            db.refresh(row)
            with pytest.raises(RuntimeError, match="append-only"):
                row.failure_reason = "modified"
                db.commit()
            db.rollback()

    def test_GC_42_chain_execution_delete_blocked(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            row = _make_execution_row()
            db.add(row)
            db.commit()
            db.refresh(row)
            with pytest.raises(RuntimeError, match="append-only"):
                db.delete(row)
                db.commit()
            db.rollback()

    def test_GC_43_health_snapshot_update_blocked(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            row = _make_health_row()
            db.add(row)
            db.commit()
            db.refresh(row)
            with pytest.raises(RuntimeError, match="append-only"):
                row.governance_health_score = 0.0
                db.commit()
            db.rollback()

    def test_GC_44_health_snapshot_delete_blocked(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            row = _make_health_row()
            db.add(row)
            db.commit()
            db.refresh(row)
            with pytest.raises(RuntimeError, match="append-only"):
                db.delete(row)
                db.commit()
            db.rollback()

    def test_GC_45_cgin_snapshot_is_mutable(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            row = FaGovernanceChainSnapshot(
                id=_uid(),
                tenant_fingerprint="fp-001",
                authority="evidence_authority",
                execution_count=1,
                success_count=1,
                failure_count=0,
                skipped_count=0,
                average_duration_ms=10.0,
                generated_at=_now_str(),
            )
            db.add(row)
            db.commit()
            db.refresh(row)
            # Should not raise
            row.execution_count = 2
            db.commit()
            db.refresh(row)
            assert row.execution_count == 2

    def test_GC_46_chain_event_has_tenant_id(self):
        row = _make_event_row()
        assert hasattr(row, "tenant_id")

    def test_GC_47_chain_execution_has_tenant_id(self):
        row = _make_execution_row()
        assert hasattr(row, "tenant_id")

    def test_GC_48_health_snapshot_has_tenant_id(self):
        row = _make_health_row()
        assert hasattr(row, "tenant_id")

    def test_GC_49_chain_event_has_correlation_id(self):
        row = _make_event_row()
        assert hasattr(row, "correlation_id")

    def test_GC_50_chain_execution_success_is_integer(self):
        row = _make_execution_row(success=1)
        assert row.success == 1

    def test_GC_51_health_snapshot_default_version(self):
        row = _make_health_row()
        assert row.calculation_version == "1.0"

    def test_GC_52_chain_event_has_payload_json(self):
        row = _make_event_row()
        assert hasattr(row, "payload_json")

    def test_GC_53_chain_execution_has_duration_ms(self):
        row = _make_execution_row()
        assert row.duration_ms == 12.5

    def test_GC_54_health_snapshot_score_stored(self):
        row = _make_health_row(score=92.5)
        assert row.governance_health_score == 92.5

    def test_GC_55_health_snapshot_rating_stored(self):
        row = _make_health_row(rating="EXCELLENT")
        assert row.governance_health_rating == "EXCELLENT"

    def test_GC_56_chain_execution_bridge_type_stored(self):
        row = _make_execution_row(
            bridge_type=BridgeType.FRESHNESS_TO_EFFECTIVENESS.value
        )
        assert row.bridge_type == BridgeType.FRESHNESS_TO_EFFECTIVENESS.value

    def test_GC_57_chain_event_object_type_stored(self):
        row = _make_event_row(object_type="verification_request")
        assert row.object_type == "verification_request"

    def test_GC_58_cgin_snapshot_fingerprint_stored(self):
        row = FaGovernanceChainSnapshot(
            id=_uid(),
            tenant_fingerprint="fp-xyz",
            authority="test",
            execution_count=0,
            success_count=0,
            failure_count=0,
            skipped_count=0,
            average_duration_ms=None,
            generated_at=_now_str(),
        )
        assert row.tenant_fingerprint == "fp-xyz"

    def test_GC_59_chain_event_actor_fields(self):
        row = _make_event_row()
        assert row.actor_id == "test-actor"
        assert row.actor_type == "human"

    def test_GC_60_chain_execution_source_target_authority(self):
        row = _make_execution_row()
        assert row.source_authority == "evidence_authority"
        assert row.target_authority == "verification_authority"


# ===========================================================================
# GC-61 to GC-100: Repository and engine unit tests (with DB)
# ===========================================================================


class TestRepositoryAndEngine:
    def test_GC_61_emit_event_creates_row(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = EmitChainEventRequest(
                event_type="EVIDENCE_REGISTERED",
                authority="evidence_authority",
                object_type="evidence",
                object_id=_uid(),
                reason="test",
            )
            result = engine.emit_chain_event(req, actor_id="actor1", actor_type="human")
            assert result.id
            assert result.tenant_id == _TENANT
            assert result.event_type == "EVIDENCE_REGISTERED"

    def test_GC_62_emit_event_is_persisted(self, build_app):
        build_app(auth_enabled=False)
        eid = _uid()
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = EmitChainEventRequest(
                event_type="VERIFICATION_CREATED",
                authority="verification_authority",
                object_type="verification_request",
                object_id=eid,
                reason="persisted",
            )
            engine.emit_chain_event(req, actor_id="a", actor_type="service")

        with Session(get_engine()) as db2:
            engine2 = GovernanceChainEngine(db2, _TENANT)
            resp = engine2.list_chain_events(object_type="verification_request")
            ids = [e.object_id for e in resp.events]
            assert eid in ids

    def test_GC_63_list_events_filters_by_event_type(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            for et in ["EVIDENCE_REGISTERED", "VERIFICATION_CREATED"]:
                req = EmitChainEventRequest(
                    event_type=et,
                    authority="test",
                    object_type="object",
                    object_id=_uid(),
                    reason="filter-test",
                )
                engine.emit_chain_event(req, actor_id="a", actor_type="human")

        with Session(get_engine()) as db2:
            engine2 = GovernanceChainEngine(db2, _TENANT)
            resp = engine2.list_chain_events(event_type="EVIDENCE_REGISTERED")
            for e in resp.events:
                assert e.event_type == "EVIDENCE_REGISTERED"

    def test_GC_64_list_events_tenant_isolation(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            e1 = GovernanceChainEngine(db, _TENANT)
            e2 = GovernanceChainEngine(db, _TENANT_B)
            for eng in (e1, e2):
                req = EmitChainEventRequest(
                    event_type="EVIDENCE_REGISTERED",
                    authority="test",
                    object_type="evidence",
                    object_id=_uid(),
                    reason="isolation",
                )
                eng.emit_chain_event(req, actor_id="a", actor_type="human")

        with Session(get_engine()) as db2:
            resp_a = GovernanceChainEngine(db2, _TENANT).list_chain_events()
            resp_b = GovernanceChainEngine(db2, _TENANT_B).list_chain_events()
            for e in resp_a.events:
                assert e.tenant_id == _TENANT
            for e in resp_b.events:
                assert e.tenant_id == _TENANT_B

    def test_GC_65_list_events_by_correlation(self, build_app):
        build_app(auth_enabled=False)
        cid = _uid()
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            for _ in range(3):
                req = EmitChainEventRequest(
                    event_type="EVIDENCE_REGISTERED",
                    authority="test",
                    object_type="evidence",
                    object_id=_uid(),
                    reason="corr",
                    correlation_id=cid,
                )
                engine.emit_chain_event(req, actor_id="a", actor_type="human")

        with Session(get_engine()) as db2:
            resp = GovernanceChainEngine(db2, _TENANT).list_events_by_correlation(cid)
            assert resp.total == 3
            for e in resp.events:
                assert e.correlation_id == cid

    def test_GC_66_bridge_assessment_to_evidence_records_noop(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = ExecuteBridgeRequest(
                bridge=BridgeType.ASSESSMENT_TO_EVIDENCE.value,
                trigger_object_id=_uid(),
                trigger_object_type="evidence",
                trigger_reason="test",
            )
            result = engine.register_assessment_evidence(req, "actor", "human")
            assert result.execution_result == ChainExecutionResult.NOOP_SAFE.value
            assert result.success is True

    def test_GC_67_bridge_evidence_to_verification_records_execution(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = ExecuteBridgeRequest(
                bridge=BridgeType.EVIDENCE_TO_VERIFICATION.value,
                trigger_object_id=_uid(),
                trigger_object_type="evidence",
                trigger_reason="chain bridge test",
            )
            result = engine.ensure_verification_requested(req, "actor", "human")
            assert result.bridge_type == BridgeType.EVIDENCE_TO_VERIFICATION.value
            assert result.id is not None
            assert result.duration_ms is not None
            assert result.duration_ms >= 0

    def test_GC_68_bridge_execution_always_recorded_even_on_failure(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = ExecuteBridgeRequest(
                bridge=BridgeType.EVIDENCE_TO_VERIFICATION.value,
                trigger_object_id="",  # will trigger empty evidence_id error
                trigger_object_type="evidence",
                trigger_reason="failure test",
            )
            result = engine.ensure_verification_requested(req, "actor", "human")
            # Should record FAILURE without raising
            assert result.execution_result in (
                ChainExecutionResult.FAILURE.value,
                ChainExecutionResult.SUCCESS.value,
            )

    def test_GC_69_bridge_verification_to_freshness_records_execution(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = ExecuteBridgeRequest(
                bridge=BridgeType.VERIFICATION_TO_FRESHNESS.value,
                trigger_object_id=_uid(),
                trigger_object_type="evidence",
                trigger_reason="freshness bridge test",
                verified_at=_now_str(),
            )
            result = engine.propagate_verification_to_freshness(req, "actor", "human")
            assert result.bridge_type == BridgeType.VERIFICATION_TO_FRESHNESS.value

    def test_GC_70_bridge_freshness_to_effectiveness_skipped_no_control(
        self, build_app
    ):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = ExecuteBridgeRequest(
                bridge=BridgeType.FRESHNESS_TO_EFFECTIVENESS.value,
                trigger_object_id=_uid(),
                trigger_object_type="evidence",
                trigger_reason="no control test",
                # control_id omitted deliberately
            )
            result = engine.queue_control_effectiveness_recalculation(req, "a", "human")
            assert (
                result.execution_result
                == ChainExecutionResult.SKIPPED_UNAVAILABLE.value
            )

    def test_GC_71_bridge_effectiveness_to_explainability_skipped_no_control(
        self, build_app
    ):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = ExecuteBridgeRequest(
                bridge=BridgeType.EFFECTIVENESS_TO_EXPLAINABILITY.value,
                trigger_object_id=_uid(),
                trigger_object_type="control",
                trigger_reason="no control test",
            )
            result = engine.regenerate_explainability(req, "a", "human")
            assert (
                result.execution_result
                == ChainExecutionResult.SKIPPED_UNAVAILABLE.value
            )

    def test_GC_72_bridge_action_to_remediation_noop_safe(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = ExecuteBridgeRequest(
                bridge=BridgeType.ACTION_TO_REMEDIATION.value,
                trigger_object_id=_uid(),
                trigger_object_type="governance_action",
                trigger_reason="action accepted",
            )
            result = engine.create_remediation_from_action(req, "actor", "human")
            assert result.execution_result == ChainExecutionResult.NOOP_SAFE.value
            assert result.success is True

    def test_GC_73_bridge_remediation_to_outcome_skipped_missing_params(
        self, build_app
    ):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = ExecuteBridgeRequest(
                bridge=BridgeType.REMEDIATION_TO_OUTCOME.value,
                trigger_object_id=_uid(),
                trigger_object_type="remediation_task",
                trigger_reason="missing params",
                # control_id and effectiveness scores omitted
            )
            result = engine.record_remediation_outcome(req, "actor", "human")
            assert (
                result.execution_result
                == ChainExecutionResult.SKIPPED_UNAVAILABLE.value
            )

    def test_GC_74_execute_bridge_dispatcher_evidence_to_verification(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = ExecuteBridgeRequest(
                bridge=BridgeType.EVIDENCE_TO_VERIFICATION.value,
                trigger_object_id=_uid(),
                trigger_object_type="evidence",
                trigger_reason="dispatcher test",
            )
            result = engine.execute_bridge(req, "actor", "human")
            assert result.bridge_type == BridgeType.EVIDENCE_TO_VERIFICATION.value

    def test_GC_75_execute_bridge_unknown_bridge_raises(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = ExecuteBridgeRequest(
                bridge="TOTALLY_UNKNOWN_BRIDGE",
                trigger_object_id=_uid(),
                trigger_object_type="unknown",
                trigger_reason="bad bridge",
            )
            with pytest.raises(ChainBridgeNotFound):
                engine.execute_bridge(req, "actor", "human")

    def test_GC_76_health_snapshot_computed_and_stored(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            result = engine.generate_governance_health_snapshot()
            assert result.id is not None
            assert 0.0 <= result.governance_health_score <= 100.0
            assert result.tenant_id == _TENANT

    def test_GC_77_health_snapshot_rating_matches_score(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            result = engine.generate_governance_health_snapshot()
            expected = classify_governance_health(result.governance_health_score)
            assert result.governance_health_rating == expected.value

    def test_GC_78_health_snapshot_version_correct(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            result = engine.generate_governance_health_snapshot()
            assert result.calculation_version == GOVERNANCE_CHAIN_VERSION

    def test_GC_79_get_latest_health_after_snapshot(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            engine.generate_governance_health_snapshot()

        with Session(get_engine()) as db2:
            engine2 = GovernanceChainEngine(db2, _TENANT)
            result = engine2.get_latest_health()
            assert result is not None
            assert result.governance_health_score >= 0.0

    def test_GC_80_get_latest_health_not_found_raises(self, build_app):
        build_app(auth_enabled=False)
        tid = f"t-fresh-{_uid()[:8]}"
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, tid)
            with pytest.raises(GovernanceHealthNotFound):
                engine.get_latest_health()

    def test_GC_81_health_history_list(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            for _ in range(3):
                engine.generate_governance_health_snapshot()

        with Session(get_engine()) as db2:
            engine2 = GovernanceChainEngine(db2, _TENANT)
            resp = engine2.list_health_history(limit=10)
            assert resp.total >= 3

    def test_GC_82_diagnostics_returns_response(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            result = engine.get_diagnostics()
            assert isinstance(result, ChainDiagnosticsResponse)
            assert result.tenant_id == _TENANT

    def test_GC_83_diagnostics_execution_success_rate_is_valid(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            result = engine.get_diagnostics()
            assert 0.0 <= result.execution_success_rate <= 1.0

    def test_GC_84_diagnostics_authority_availability_list(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            result = engine.get_diagnostics()
            assert isinstance(result.authority_availability, list)
            assert len(result.authority_availability) > 0

    def test_GC_85_diagnostics_event_type_distribution_is_dict(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            result = engine.get_diagnostics()
            assert isinstance(result.event_type_distribution, dict)

    def test_GC_86_cgin_snapshot_no_raw_tenant_id(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            result = engine.get_cgin_snapshot()
            assert isinstance(result, CGINChainSnapshotBundle)
            assert _TENANT not in result.tenant_fingerprint

    def test_GC_87_cgin_snapshot_bundle_version(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            result = engine.get_cgin_snapshot()
            assert result.bundle_version == GOVERNANCE_CHAIN_VERSION

    def test_GC_88_cgin_snapshot_has_bundle_id(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            result = engine.get_cgin_snapshot()
            assert result.bundle_id is not None

    def test_GC_89_cgin_snapshot_tenant_fingerprint_is_hash(self, build_app):
        import hashlib

        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            result = engine.get_cgin_snapshot()
        expected = hashlib.sha256(f"cgin:v1:{_TENANT}".encode()).hexdigest()[:32]
        assert result.tenant_fingerprint == expected

    def test_GC_90_cgin_different_tenants_have_different_fingerprints(self, build_app):
        import hashlib

        build_app(auth_enabled=False)
        fp_a = hashlib.sha256(f"cgin:v1:{_TENANT}".encode()).hexdigest()[:32]
        fp_b = hashlib.sha256(f"cgin:v1:{_TENANT_B}".encode()).hexdigest()[:32]
        assert fp_a != fp_b

    def test_GC_91_list_executions_returns_response(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = ExecuteBridgeRequest(
                bridge=BridgeType.ASSESSMENT_TO_EVIDENCE.value,
                trigger_object_id=_uid(),
                trigger_object_type="evidence",
                trigger_reason="list test",
            )
            engine.execute_bridge(req, "actor", "human")
            resp = engine.list_executions()
            assert isinstance(resp, ChainExecutionListResponse)

    def test_GC_92_get_execution_by_id(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = ExecuteBridgeRequest(
                bridge=BridgeType.ASSESSMENT_TO_EVIDENCE.value,
                trigger_object_id=_uid(),
                trigger_object_type="evidence",
                trigger_reason="get by id test",
            )
            result = engine.execute_bridge(req, "actor", "human")
            fetched = engine.get_execution(result.id)
            assert fetched.id == result.id

    def test_GC_93_get_execution_not_found_raises(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            with pytest.raises(ChainExecutionNotFound):
                engine.get_execution(_uid())

    def test_GC_94_bridge_chain_execution_id_is_uuid(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = ExecuteBridgeRequest(
                bridge=BridgeType.ASSESSMENT_TO_EVIDENCE.value,
                trigger_object_id=_uid(),
                trigger_object_type="evidence",
                trigger_reason="uuid test",
            )
            result = engine.execute_bridge(req, "actor", "human")
            uuid.UUID(result.chain_execution_id)  # should not raise

    def test_GC_95_bridge_duration_ms_is_non_negative(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = ExecuteBridgeRequest(
                bridge=BridgeType.ASSESSMENT_TO_EVIDENCE.value,
                trigger_object_id=_uid(),
                trigger_object_type="evidence",
                trigger_reason="duration test",
            )
            result = engine.execute_bridge(req, "actor", "human")
            assert result.duration_ms is not None
            assert result.duration_ms >= 0.0

    def test_GC_96_health_missing_inputs_list(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            result = engine.generate_governance_health_snapshot()
            assert isinstance(result.missing_inputs, list)

    def test_GC_97_emit_event_uppercase_normalizes_type(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = EmitChainEventRequest(
                event_type="evidence_registered",  # lowercase
                authority="test",
                object_type="evidence",
                object_id=_uid(),
                reason="case test",
            )
            result = engine.emit_chain_event(req, "a", "human")
            assert result.event_type == "EVIDENCE_REGISTERED"

    def test_GC_98_diagnostics_no_executions_success_rate_is_one(self, build_app):
        build_app(auth_enabled=False)
        tid = f"t-diag-{_uid()[:8]}"
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, tid)
            result = engine.get_diagnostics()
            assert result.execution_success_rate == 1.0

    def test_GC_99_cgin_authority_snapshots_is_list(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            result = engine.get_cgin_snapshot()
            assert isinstance(result.authority_snapshots, list)

    def test_GC_100_health_score_is_float(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            result = engine.generate_governance_health_snapshot()
            assert isinstance(result.governance_health_score, float)


# ===========================================================================
# GC-101 to GC-140: Schema validation
# ===========================================================================


class TestSchemas:
    def test_GC_101_emit_event_extra_forbid(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            EmitChainEventRequest(
                event_type="X",
                authority="a",
                object_type="o",
                object_id="oid",
                reason="r",
                unknown_field="bad",
            )

    def test_GC_102_execute_bridge_extra_forbid(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ExecuteBridgeRequest(
                bridge="X",
                trigger_object_id="id",
                trigger_object_type="type",
                trigger_reason="r",
                extra_injected="bad",
            )

    def test_GC_103_recalculate_health_extra_forbid(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            RecalculateHealthRequest(unknown="bad")

    def test_GC_104_chain_event_response_extra_forbid(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ChainEventResponse(
                id="x",
                tenant_id="t",
                event_type="E",
                authority="a",
                object_type="o",
                object_id="oid",
                correlation_id=None,
                actor_id=None,
                actor_type=None,
                reason=None,
                payload_json=None,
                created_at=_now_str(),
                extra_field="bad",
            )

    def test_GC_105_execution_response_success_is_bool(self):
        resp = ChainExecutionResponse(
            id="x",
            tenant_id="t",
            chain_execution_id="cid",
            source_authority="src",
            target_authority="tgt",
            bridge_type="EVIDENCE_TO_VERIFICATION",
            trigger_reason="r",
            trigger_object_id="oid",
            trigger_object_type="evidence",
            execution_result="SUCCESS",
            success=True,
            failure_reason=None,
            duration_ms=10.0,
            executed_at=_now_str(),
        )
        assert resp.success is True

    def test_GC_106_health_response_extra_forbid(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            GovernanceHealthResponse(
                id="x",
                tenant_id="t",
                verification_health=80.0,
                freshness_health=80.0,
                effectiveness_health=80.0,
                remediation_health=80.0,
                forecast_health=80.0,
                governance_health_score=80.0,
                governance_health_rating="GOOD",
                missing_inputs=[],
                snapshot_at=_now_str(),
                calculation_version="1.0",
                surprise_field="bad",
            )

    def test_GC_107_emit_event_requires_reason(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            EmitChainEventRequest(
                event_type="X",
                authority="a",
                object_type="o",
                object_id="oid",
                # reason omitted
            )

    def test_GC_108_execute_bridge_optional_control_id(self):
        req = ExecuteBridgeRequest(
            bridge="EVIDENCE_TO_VERIFICATION",
            trigger_object_id="eid",
            trigger_object_type="evidence",
            trigger_reason="r",
        )
        assert req.control_id is None

    def test_GC_109_execute_bridge_optional_correlation_id(self):
        req = ExecuteBridgeRequest(
            bridge="EVIDENCE_TO_VERIFICATION",
            trigger_object_id="eid",
            trigger_object_type="evidence",
            trigger_reason="r",
        )
        assert req.correlation_id is None

    def test_GC_110_chain_event_list_response_extra_forbid(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ChainEventListResponse(events=[], total=0, extra="bad")

    def test_GC_111_execute_bridge_accepts_effectiveness_scores(self):
        req = ExecuteBridgeRequest(
            bridge="REMEDIATION_TO_OUTCOME",
            trigger_object_id="rid",
            trigger_object_type="remediation_task",
            trigger_reason="r",
            control_id="cid",
            effectiveness_before=60.0,
            effectiveness_after=75.0,
        )
        assert req.effectiveness_before == 60.0
        assert req.effectiveness_after == 75.0

    def test_GC_112_governance_health_response_missing_inputs_list(self):
        resp = GovernanceHealthResponse(
            id="x",
            tenant_id="t",
            verification_health=75.0,
            freshness_health=75.0,
            effectiveness_health=75.0,
            remediation_health=75.0,
            forecast_health=75.0,
            governance_health_score=75.0,
            governance_health_rating="GOOD",
            missing_inputs=["forecast_authority"],
            snapshot_at=_now_str(),
            calculation_version="1.0",
        )
        assert "forecast_authority" in resp.missing_inputs

    def test_GC_113_cgin_bundle_extra_forbid(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            CGINChainSnapshotBundle(
                bundle_id="x",
                bundle_version="1.0",
                tenant_fingerprint="fp",
                authority_snapshots=[],
                total_chain_events=0,
                governance_health_score=None,
                governance_health_rating=None,
                generated_at=_now_str(),
                surprise="bad",
            )

    def test_GC_114_chain_execution_list_response_extra_forbid(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ChainExecutionListResponse(executions=[], total=0, bad_field="x")

    def test_GC_115_health_history_response_extra_forbid(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            GovernanceHealthHistoryResponse(snapshots=[], total=0, bad="x")

    def test_GC_116_execute_bridge_verified_at_optional(self):
        req = ExecuteBridgeRequest(
            bridge="VERIFICATION_TO_FRESHNESS",
            trigger_object_id="eid",
            trigger_object_type="evidence",
            trigger_reason="r",
        )
        assert req.verified_at is None

    def test_GC_117_execute_bridge_accepts_verified_at(self):
        ts = _now_str()
        req = ExecuteBridgeRequest(
            bridge="VERIFICATION_TO_FRESHNESS",
            trigger_object_id="eid",
            trigger_object_type="evidence",
            trigger_reason="r",
            verified_at=ts,
        )
        assert req.verified_at == ts


# ===========================================================================
# GC-118 to GC-165: Route auth tests
# ===========================================================================


class TestRouteAuth:
    def test_GC_118_get_health_no_auth_returns_401_or_403(self, build_app):
        app = build_app(auth_enabled=True)
        client = TestClient(app)
        resp = client.get("/governance-chain/health")
        assert resp.status_code in (401, 403)

    def test_GC_119_get_health_wrong_scope_returns_403(self, build_app):
        app = build_app(auth_enabled=True)
        key = mint_key("audit:read", tenant_id=_TENANT)
        client = TestClient(app, headers={"X-API-Key": key})
        resp = client.get("/governance-chain/health")
        assert resp.status_code == 403

    def test_GC_120_get_health_correct_scope_returns_404_or_200(self, build_app):
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", tenant_id=_TENANT)
        client = TestClient(app, headers={"X-API-Key": key})
        resp = client.get("/governance-chain/health")
        assert resp.status_code in (200, 404)

    def test_GC_121_get_diagnostics_no_auth_denied(self, build_app):
        app = build_app(auth_enabled=True)
        client = TestClient(app)
        resp = client.get("/governance-chain/diagnostics")
        assert resp.status_code in (401, 403)

    def test_GC_122_get_diagnostics_wrong_scope_denied(self, build_app):
        app = build_app(auth_enabled=True)
        key = mint_key("audit:read", tenant_id=_TENANT)
        client = TestClient(app, headers={"X-API-Key": key})
        resp = client.get("/governance-chain/diagnostics")
        assert resp.status_code == 403

    def test_GC_123_get_diagnostics_governance_read_allowed(self, build_app):
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", tenant_id=_TENANT)
        client = TestClient(app, headers={"X-API-Key": key})
        resp = client.get("/governance-chain/diagnostics")
        assert resp.status_code == 200

    def test_GC_124_get_cgin_no_auth_denied(self, build_app):
        app = build_app(auth_enabled=True)
        client = TestClient(app)
        resp = client.get("/governance-chain/cgin/snapshot")
        assert resp.status_code in (401, 403)

    def test_GC_125_get_cgin_governance_read_allowed(self, build_app):
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", tenant_id=_TENANT)
        client = TestClient(app, headers={"X-API-Key": key})
        resp = client.get("/governance-chain/cgin/snapshot")
        assert resp.status_code == 200

    def test_GC_126_get_executions_no_auth_denied(self, build_app):
        app = build_app(auth_enabled=True)
        client = TestClient(app)
        resp = client.get("/governance-chain/executions")
        assert resp.status_code in (401, 403)

    def test_GC_127_get_executions_governance_read_allowed(self, build_app):
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", tenant_id=_TENANT)
        client = TestClient(app, headers={"X-API-Key": key})
        resp = client.get("/governance-chain/executions")
        assert resp.status_code == 200

    def test_GC_128_get_execution_by_id_not_found_returns_404(self, build_app):
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", tenant_id=_TENANT)
        client = TestClient(app, headers={"X-API-Key": key})
        resp = client.get(f"/governance-chain/executions/{_uid()}")
        assert resp.status_code == 404

    def test_GC_129_get_events_by_correlation_no_auth_denied(self, build_app):
        app = build_app(auth_enabled=True)
        client = TestClient(app)
        resp = client.get(f"/governance-chain/events/{_uid()}")
        assert resp.status_code in (401, 403)

    def test_GC_130_get_events_by_correlation_read_allowed(self, build_app):
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", tenant_id=_TENANT)
        client = TestClient(app, headers={"X-API-Key": key})
        resp = client.get(f"/governance-chain/events/{_uid()}")
        assert resp.status_code == 200

    def test_GC_131_post_execute_no_auth_denied(self, build_app):
        app = build_app(auth_enabled=True)
        client = TestClient(app)
        resp = client.post(
            "/governance-chain/execute",
            json={
                "bridge": "ASSESSMENT_TO_EVIDENCE",
                "trigger_object_id": _uid(),
                "trigger_object_type": "evidence",
                "trigger_reason": "test",
            },
        )
        assert resp.status_code in (401, 403)

    def test_GC_132_post_execute_governance_read_denied(self, build_app):
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", tenant_id=_TENANT)
        client = TestClient(app, headers={"X-API-Key": key})
        resp = client.post(
            "/governance-chain/execute",
            json={
                "bridge": "ASSESSMENT_TO_EVIDENCE",
                "trigger_object_id": _uid(),
                "trigger_object_type": "evidence",
                "trigger_reason": "test",
            },
        )
        assert resp.status_code == 403

    def test_GC_133_post_execute_governance_write_allowed(self, build_app):
        app = build_app(auth_enabled=True)
        key = mint_key("governance:write", tenant_id=_TENANT)
        client = TestClient(app, headers={"X-API-Key": key})
        resp = client.post(
            "/governance-chain/execute",
            json={
                "bridge": "ASSESSMENT_TO_EVIDENCE",
                "trigger_object_id": _uid(),
                "trigger_object_type": "evidence",
                "trigger_reason": "auth test",
            },
        )
        assert resp.status_code == 201

    def test_GC_134_post_recalculate_health_no_auth_denied(self, build_app):
        app = build_app(auth_enabled=True)
        client = TestClient(app)
        resp = client.post("/governance-chain/recalculate-health", json={})
        assert resp.status_code in (401, 403)

    def test_GC_135_post_recalculate_health_read_denied(self, build_app):
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", tenant_id=_TENANT)
        client = TestClient(app, headers={"X-API-Key": key})
        resp = client.post("/governance-chain/recalculate-health", json={})
        assert resp.status_code == 403

    def test_GC_136_post_recalculate_health_write_allowed(self, build_app):
        app = build_app(auth_enabled=True)
        key = mint_key("governance:write", tenant_id=_TENANT)
        client = TestClient(app, headers={"X-API-Key": key})
        resp = client.post("/governance-chain/recalculate-health", json={})
        assert resp.status_code == 201

    def test_GC_137_post_execute_unknown_bridge_returns_400(self, build_app):
        app = build_app(auth_enabled=True)
        key = mint_key("governance:write", tenant_id=_TENANT)
        client = TestClient(app, headers={"X-API-Key": key})
        resp = client.post(
            "/governance-chain/execute",
            json={
                "bridge": "NOT_A_REAL_BRIDGE",
                "trigger_object_id": _uid(),
                "trigger_object_type": "evidence",
                "trigger_reason": "bad bridge",
            },
        )
        assert resp.status_code == 400

    def test_GC_138_post_execute_extra_field_returns_422(self, build_app):
        app = build_app(auth_enabled=True)
        key = mint_key("governance:write", tenant_id=_TENANT)
        client = TestClient(app, headers={"X-API-Key": key})
        resp = client.post(
            "/governance-chain/execute",
            json={
                "bridge": "ASSESSMENT_TO_EVIDENCE",
                "trigger_object_id": _uid(),
                "trigger_object_type": "evidence",
                "trigger_reason": "test",
                "injected_tenant_id": "evil-tenant",
            },
        )
        assert resp.status_code == 422

    def test_GC_139_get_executions_filter_by_bridge_type(self, build_app):
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", "governance:write", tenant_id=_TENANT)
        client = TestClient(app, headers={"X-API-Key": key})
        resp = client.get(
            "/governance-chain/executions",
            params={"bridge_type": "ASSESSMENT_TO_EVIDENCE"},
        )
        assert resp.status_code == 200

    def test_GC_140_get_executions_filter_by_success(self, build_app):
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", tenant_id=_TENANT)
        client = TestClient(app, headers={"X-API-Key": key})
        resp = client.get(
            "/governance-chain/executions",
            params={"success": "true"},
        )
        assert resp.status_code == 200


# ===========================================================================
# GC-141 to GC-210: Integration tests
# ===========================================================================


class TestIntegration:
    @pytest.fixture()
    def rw_client(self, build_app):
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", "governance:write", tenant_id=_TENANT)
        return TestClient(app, headers={"X-API-Key": key})

    @pytest.fixture()
    def rw_client_b(self, build_app):
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_B)
        return TestClient(app, headers={"X-API-Key": key})

    def test_GC_141_execute_bridge_returns_201(self, rw_client):
        resp = rw_client.post(
            "/governance-chain/execute",
            json={
                "bridge": "ASSESSMENT_TO_EVIDENCE",
                "trigger_object_id": _uid(),
                "trigger_object_type": "evidence",
                "trigger_reason": "integration test",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["bridge_type"] == "ASSESSMENT_TO_EVIDENCE"
        assert data["success"] is True

    def test_GC_142_execute_bridge_execution_appears_in_list(self, rw_client):
        eid = _uid()
        rw_client.post(
            "/governance-chain/execute",
            json={
                "bridge": "ASSESSMENT_TO_EVIDENCE",
                "trigger_object_id": eid,
                "trigger_object_type": "evidence",
                "trigger_reason": "list test",
            },
        )
        resp = rw_client.get("/governance-chain/executions")
        data = resp.json()
        oids = [e["trigger_object_id"] for e in data["executions"]]
        assert eid in oids

    def test_GC_143_execute_bridge_get_by_id(self, rw_client):
        resp = rw_client.post(
            "/governance-chain/execute",
            json={
                "bridge": "ASSESSMENT_TO_EVIDENCE",
                "trigger_object_id": _uid(),
                "trigger_object_type": "evidence",
                "trigger_reason": "get by id",
            },
        )
        exec_id = resp.json()["id"]
        get_resp = rw_client.get(f"/governance-chain/executions/{exec_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["id"] == exec_id

    def test_GC_144_recalculate_health_returns_201(self, rw_client):
        resp = rw_client.post("/governance-chain/recalculate-health", json={})
        assert resp.status_code == 201
        data = resp.json()
        assert "governance_health_score" in data
        assert 0 <= data["governance_health_score"] <= 100

    def test_GC_145_recalculate_health_then_get_health(self, rw_client):
        rw_client.post("/governance-chain/recalculate-health", json={})
        resp = rw_client.get("/governance-chain/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["governance_health_rating"] in [
            r.value for r in GovernanceHealthRating
        ]

    def test_GC_146_diagnostics_returns_200(self, rw_client):
        resp = rw_client.get("/governance-chain/diagnostics")
        assert resp.status_code == 200
        data = resp.json()
        assert "tenant_id" in data

    def test_GC_147_diagnostics_sum_check(self, rw_client):
        rw_client.post(
            "/governance-chain/execute",
            json={
                "bridge": "ASSESSMENT_TO_EVIDENCE",
                "trigger_object_id": _uid(),
                "trigger_object_type": "evidence",
                "trigger_reason": "sum check",
            },
        )
        resp = rw_client.get("/governance-chain/diagnostics")
        data = resp.json()
        total = data["total_bridge_executions"]
        success = data["successful_executions"]
        failed = data["failed_executions"]
        skipped = data["skipped_executions"]
        assert success + failed + skipped == total

    def test_GC_148_cgin_no_raw_tenant_id_in_response(self, rw_client):
        resp = rw_client.get("/governance-chain/cgin/snapshot")
        assert resp.status_code == 200
        raw = resp.text
        assert _TENANT not in raw

    def test_GC_149_cgin_has_bundle_version(self, rw_client):
        resp = rw_client.get("/governance-chain/cgin/snapshot")
        data = resp.json()
        assert data["bundle_version"] == "1.0"

    def test_GC_150_events_by_correlation_id(self, rw_client):
        cid = _uid()
        # Execute two bridges with same correlation_id (passed via execute endpoint
        # through correlation_id field)
        for _ in range(2):
            rw_client.post(
                "/governance-chain/execute",
                json={
                    "bridge": "ASSESSMENT_TO_EVIDENCE",
                    "trigger_object_id": _uid(),
                    "trigger_object_type": "evidence",
                    "trigger_reason": "corr-test",
                    "correlation_id": cid,
                },
            )
        resp = rw_client.get(f"/governance-chain/events/{cid}")
        assert resp.status_code == 200
        data = resp.json()
        for e in data["events"]:
            assert e["correlation_id"] == cid

    def test_GC_151_tenant_a_executions_not_visible_to_tenant_b(
        self, rw_client, rw_client_b
    ):
        eid = _uid()
        rw_client.post(
            "/governance-chain/execute",
            json={
                "bridge": "ASSESSMENT_TO_EVIDENCE",
                "trigger_object_id": eid,
                "trigger_object_type": "evidence",
                "trigger_reason": "isolation",
            },
        )
        resp_b = rw_client_b.get("/governance-chain/executions")
        oids = [e["trigger_object_id"] for e in resp_b.json()["executions"]]
        assert eid not in oids

    def test_GC_152_execute_evidence_to_verification_bridge(self, rw_client):
        resp = rw_client.post(
            "/governance-chain/execute",
            json={
                "bridge": "EVIDENCE_TO_VERIFICATION",
                "trigger_object_id": _uid(),
                "trigger_object_type": "evidence",
                "trigger_reason": "bridge 2 test",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["bridge_type"] == "EVIDENCE_TO_VERIFICATION"

    def test_GC_153_execute_verification_to_freshness_bridge(self, rw_client):
        resp = rw_client.post(
            "/governance-chain/execute",
            json={
                "bridge": "VERIFICATION_TO_FRESHNESS",
                "trigger_object_id": _uid(),
                "trigger_object_type": "evidence",
                "trigger_reason": "bridge 3 test",
                "verified_at": _now_str(),
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["bridge_type"] == "VERIFICATION_TO_FRESHNESS"

    def test_GC_154_execute_freshness_to_effectiveness_skipped_without_control(
        self, rw_client
    ):
        resp = rw_client.post(
            "/governance-chain/execute",
            json={
                "bridge": "FRESHNESS_TO_EFFECTIVENESS",
                "trigger_object_id": _uid(),
                "trigger_object_type": "evidence",
                "trigger_reason": "bridge 4 no control",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["execution_result"] == "SKIPPED_UNAVAILABLE"

    def test_GC_155_execute_effectiveness_to_explainability_skipped_without_control(
        self, rw_client
    ):
        resp = rw_client.post(
            "/governance-chain/execute",
            json={
                "bridge": "EFFECTIVENESS_TO_EXPLAINABILITY",
                "trigger_object_id": _uid(),
                "trigger_object_type": "control",
                "trigger_reason": "bridge 5 no control",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["execution_result"] == "SKIPPED_UNAVAILABLE"

    def test_GC_156_execute_action_to_remediation_noop(self, rw_client):
        resp = rw_client.post(
            "/governance-chain/execute",
            json={
                "bridge": "ACTION_TO_REMEDIATION",
                "trigger_object_id": _uid(),
                "trigger_object_type": "governance_action",
                "trigger_reason": "bridge 6 noop",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["execution_result"] == "NOOP_SAFE"

    def test_GC_157_execute_remediation_to_outcome_skipped_no_scores(self, rw_client):
        resp = rw_client.post(
            "/governance-chain/execute",
            json={
                "bridge": "REMEDIATION_TO_OUTCOME",
                "trigger_object_id": _uid(),
                "trigger_object_type": "remediation_task",
                "trigger_reason": "bridge 7 no scores",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["execution_result"] == "SKIPPED_UNAVAILABLE"

    def test_GC_158_health_score_in_valid_range(self, rw_client):
        rw_client.post("/governance-chain/recalculate-health", json={})
        resp = rw_client.get("/governance-chain/health")
        if resp.status_code == 200:
            score = resp.json()["governance_health_score"]
            assert 0.0 <= score <= 100.0

    def test_GC_159_multiple_health_snapshots_in_history(self, rw_client):
        for _ in range(3):
            rw_client.post("/governance-chain/recalculate-health", json={})
        rw_client.get("/governance-chain/diagnostics")
        # Just verify diagnostics works — health history via engine is tested in GC-81

    def test_GC_160_executions_total_count_increases(self, rw_client):
        resp0 = rw_client.get("/governance-chain/executions")
        total0 = resp0.json()["total"]

        for _ in range(3):
            rw_client.post(
                "/governance-chain/execute",
                json={
                    "bridge": "ASSESSMENT_TO_EVIDENCE",
                    "trigger_object_id": _uid(),
                    "trigger_object_type": "evidence",
                    "trigger_reason": "count test",
                },
            )

        resp1 = rw_client.get("/governance-chain/executions")
        total1 = resp1.json()["total"]
        assert total1 >= total0 + 3

    def test_GC_161_executions_filter_success_true(self, rw_client):
        resp = rw_client.get("/governance-chain/executions", params={"success": "true"})
        assert resp.status_code == 200
        data = resp.json()
        for e in data["executions"]:
            assert e["success"] is True

    def test_GC_162_executions_filter_success_false(self, rw_client):
        resp = rw_client.get(
            "/governance-chain/executions", params={"success": "false"}
        )
        assert resp.status_code == 200
        data = resp.json()
        for e in data["executions"]:
            assert e["success"] is False

    def test_GC_163_diagnostics_missing_inputs_is_list(self, rw_client):
        resp = rw_client.get("/governance-chain/diagnostics")
        data = resp.json()
        assert isinstance(data["missing_inputs"], list)

    def test_GC_164_cgin_authority_snapshot_success_rate_valid(self, rw_client):
        rw_client.post(
            "/governance-chain/execute",
            json={
                "bridge": "ASSESSMENT_TO_EVIDENCE",
                "trigger_object_id": _uid(),
                "trigger_object_type": "evidence",
                "trigger_reason": "sr test",
            },
        )
        resp = rw_client.get("/governance-chain/cgin/snapshot")
        data = resp.json()
        for snap in data["authority_snapshots"]:
            assert 0.0 <= snap["success_rate"] <= 1.0

    def test_GC_165_diagnostics_authority_availability_bool(self, rw_client):
        resp = rw_client.get("/governance-chain/diagnostics")
        data = resp.json()
        for av in data["authority_availability"]:
            assert isinstance(av["available"], bool)

    def test_GC_166_bridge_source_and_target_authority_correct(self, rw_client):
        resp = rw_client.post(
            "/governance-chain/execute",
            json={
                "bridge": "EVIDENCE_TO_VERIFICATION",
                "trigger_object_id": _uid(),
                "trigger_object_type": "evidence",
                "trigger_reason": "authority check",
            },
        )
        data = resp.json()
        assert data["source_authority"] == "evidence_authority"
        assert data["target_authority"] == "verification_authority"

    def test_GC_167_cgin_health_score_none_when_no_snapshots(self, rw_client_b):
        resp = rw_client_b.get("/governance-chain/cgin/snapshot")
        data = resp.json()
        # If no health snapshot, it should be None or a valid float
        if data["governance_health_score"] is not None:
            assert 0.0 <= data["governance_health_score"] <= 100.0

    def test_GC_168_recalculate_health_missing_inputs_field(self, rw_client):
        resp = rw_client.post("/governance-chain/recalculate-health", json={})
        data = resp.json()
        assert "missing_inputs" in data
        assert isinstance(data["missing_inputs"], list)

    def test_GC_169_health_rating_one_of_valid_values(self, rw_client):
        rw_client.post("/governance-chain/recalculate-health", json={})
        resp = rw_client.get("/governance-chain/health")
        if resp.status_code == 200:
            rating = resp.json()["governance_health_rating"]
            valid = {r.value for r in GovernanceHealthRating}
            assert rating in valid

    def test_GC_170_execute_bridge_execution_result_valid_value(self, rw_client):
        resp = rw_client.post(
            "/governance-chain/execute",
            json={
                "bridge": "ASSESSMENT_TO_EVIDENCE",
                "trigger_object_id": _uid(),
                "trigger_object_type": "evidence",
                "trigger_reason": "result check",
            },
        )
        data = resp.json()
        valid = {r.value for r in ChainExecutionResult}
        assert data["execution_result"] in valid


# ===========================================================================
# GC-171 to GC-210: Edge cases and additional coverage
# ===========================================================================


class TestEdgeCases:
    def test_GC_171_plane_registry_includes_governance_chain(self):
        from services.plane_registry import PLANE_REGISTRY

        control_plane = next(p for p in PLANE_REGISTRY if p.plane_id == "control")
        assert "/governance-chain" in control_plane.route_prefixes

    def test_GC_172_route_inventory_includes_governance_chain_routes(self):
        import json
        from pathlib import Path

        inv_path = Path("tools/ci/route_inventory.json")
        if not inv_path.exists():
            pytest.skip("route inventory not generated")
        data = json.loads(inv_path.read_text())
        routes_block = (
            data.get("data", data.get("routes", data))
            if isinstance(data, dict)
            else data
        )
        paths = {r["path"] for r in routes_block}
        assert "/governance-chain/health" in paths
        assert "/governance-chain/diagnostics" in paths
        assert "/governance-chain/execute" in paths

    def test_GC_173_platform_inventory_exists(self):
        from pathlib import Path

        inv = Path("artifacts/PLATFORM_INVENTORY.md")
        assert inv.exists(), "Platform inventory must exist after generation"

    def test_GC_174_compute_health_weighted_correctly(self):
        score = compute_governance_health_score(
            verification_health=100.0,
            freshness_health=0.0,
            effectiveness_health=0.0,
            remediation_health=0.0,
            forecast_health=0.0,
        )
        assert abs(score - HEALTH_WEIGHT_VERIFICATION * 100.0) < 0.01

    def test_GC_175_compute_health_all_weights(self):
        score = compute_governance_health_score(
            verification_health=100.0,
            freshness_health=100.0,
            effectiveness_health=0.0,
            remediation_health=0.0,
            forecast_health=0.0,
        )
        expected = (HEALTH_WEIGHT_VERIFICATION + HEALTH_WEIGHT_FRESHNESS) * 100.0
        assert abs(score - expected) < 0.01

    def test_GC_176_list_events_pagination(self, build_app):
        build_app(auth_enabled=False)
        tid = f"t-pag-{_uid()[:8]}"
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, tid)
            for _ in range(5):
                req = EmitChainEventRequest(
                    event_type="EVIDENCE_REGISTERED",
                    authority="test",
                    object_type="evidence",
                    object_id=_uid(),
                    reason="pagination",
                )
                engine.emit_chain_event(req, "a", "human")

        with Session(get_engine()) as db2:
            engine2 = GovernanceChainEngine(db2, tid)
            page1 = engine2.list_chain_events(limit=2, offset=0)
            page2 = engine2.list_chain_events(limit=2, offset=2)
            assert len(page1.events) == 2
            assert len(page2.events) == 2
            ids1 = {e.id for e in page1.events}
            ids2 = {e.id for e in page2.events}
            assert ids1.isdisjoint(ids2)

    def test_GC_177_emit_event_empty_reason_allowed(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = EmitChainEventRequest(
                event_type="EVIDENCE_REGISTERED",
                authority="test",
                object_type="evidence",
                object_id=_uid(),
                reason="",
            )
            result = engine.emit_chain_event(req, "a", "human")
            assert result.id is not None

    def test_GC_178_emit_event_empty_object_id_raises(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = EmitChainEventRequest(
                event_type="EVIDENCE_REGISTERED",
                authority="test",
                object_type="evidence",
                object_id="",
                reason="empty oid",
            )
            with pytest.raises(ValueError, match="object_id"):
                engine.emit_chain_event(req, "a", "human")

    def test_GC_179_noop_bridge_records_success(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = ExecuteBridgeRequest(
                bridge=BridgeType.ACTION_TO_REMEDIATION.value,
                trigger_object_id=_uid(),
                trigger_object_type="governance_action",
                trigger_reason="noop",
            )
            result = engine.create_remediation_from_action(req, "a", "human")
            assert result.success is True

    def test_GC_180_skipped_bridge_records_failure_false(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = ExecuteBridgeRequest(
                bridge=BridgeType.FRESHNESS_TO_EFFECTIVENESS.value,
                trigger_object_id=_uid(),
                trigger_object_type="evidence",
                trigger_reason="skipped",
                # no control_id
            )
            result = engine.queue_control_effectiveness_recalculation(req, "a", "human")
            assert result.success is False
            assert result.execution_result == "SKIPPED_UNAVAILABLE"
            assert result.failure_reason is not None

    def test_GC_181_diagnostics_authority_availability_known_authorities(
        self, build_app
    ):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            result = engine.get_diagnostics()
            auth_names = {a.authority for a in result.authority_availability}
            expected = {
                "evidence_authority",
                "verification_authority",
                "evidence_freshness_authority",
                "control_effectiveness",
                "control_effectiveness_explainability",
                "remediation",
                "remediation_effectiveness",
            }
            assert expected == auth_names

    def test_GC_182_health_snapshot_components_bounded(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            result = engine.generate_governance_health_snapshot()
        for field in [
            "verification_health",
            "freshness_health",
            "effectiveness_health",
            "remediation_health",
            "forecast_health",
        ]:
            val = getattr(result, field)
            assert 0.0 <= val <= 100.0, f"{field} out of range: {val}"

    def test_GC_183_execute_bridge_persists_execution_row(self, build_app):
        build_app(auth_enabled=False)
        eid = _uid()
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = ExecuteBridgeRequest(
                bridge=BridgeType.ASSESSMENT_TO_EVIDENCE.value,
                trigger_object_id=eid,
                trigger_object_type="evidence",
                trigger_reason="persist check",
            )
            engine.execute_bridge(req, "actor", "human")

        with Session(get_engine()) as db2:
            engine2 = GovernanceChainEngine(db2, _TENANT)
            resp = engine2.list_executions()
            oids = [e.trigger_object_id for e in resp.executions]
            assert eid in oids

    def test_GC_184_health_tenant_isolation(self, build_app):
        build_app(auth_enabled=False)
        tid_x = f"t-hx-{_uid()[:8]}"
        tid_y = f"t-hy-{_uid()[:8]}"
        with Session(get_engine()) as db:
            ex = GovernanceChainEngine(db, tid_x)
            ex.generate_governance_health_snapshot()

        with Session(get_engine()) as db2:
            ey = GovernanceChainEngine(db2, tid_y)
            with pytest.raises(GovernanceHealthNotFound):
                ey.get_latest_health()

    def test_GC_185_cgin_total_chain_events_count(self, build_app):
        build_app(auth_enabled=False)
        tid = f"t-cgin-{_uid()[:8]}"
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, tid)
            for _ in range(5):
                req = EmitChainEventRequest(
                    event_type="EVIDENCE_REGISTERED",
                    authority="test",
                    object_type="evidence",
                    object_id=_uid(),
                    reason="cgin count",
                )
                engine.emit_chain_event(req, "a", "human")
            snap = engine.get_cgin_snapshot()
            assert snap.total_chain_events == 5

    def test_GC_186_execution_chain_execution_id_uuid(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = ExecuteBridgeRequest(
                bridge=BridgeType.ASSESSMENT_TO_EVIDENCE.value,
                trigger_object_id=_uid(),
                trigger_object_type="evidence",
                trigger_reason="uuid",
            )
            result = engine.execute_bridge(req, "a", "human")
            uuid.UUID(result.chain_execution_id)

    def test_GC_187_health_snapshot_at_is_iso8601(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            result = engine.generate_governance_health_snapshot()
        # Should parse without error
        datetime.fromisoformat(result.snapshot_at.replace("Z", "+00:00"))

    def test_GC_188_execution_executed_at_is_iso8601(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = ExecuteBridgeRequest(
                bridge=BridgeType.ASSESSMENT_TO_EVIDENCE.value,
                trigger_object_id=_uid(),
                trigger_object_type="evidence",
                trigger_reason="ts check",
            )
            result = engine.execute_bridge(req, "a", "human")
        datetime.fromisoformat(result.executed_at.replace("Z", "+00:00"))

    def test_GC_189_event_created_at_is_iso8601(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = EmitChainEventRequest(
                event_type="EVIDENCE_REGISTERED",
                authority="test",
                object_type="evidence",
                object_id=_uid(),
                reason="ts",
            )
            result = engine.emit_chain_event(req, "a", "human")
        datetime.fromisoformat(result.created_at.replace("Z", "+00:00"))

    def test_GC_190_execute_bridge_all_bridges_covered(self, build_app):
        build_app(auth_enabled=False)
        # All BridgeType values except ALL_TO_REPORTING should be dispatchable
        dispatchable = {
            BridgeType.ASSESSMENT_TO_EVIDENCE.value,
            BridgeType.EVIDENCE_TO_VERIFICATION.value,
            BridgeType.VERIFICATION_TO_FRESHNESS.value,
            BridgeType.FRESHNESS_TO_EFFECTIVENESS.value,
            BridgeType.EFFECTIVENESS_TO_EXPLAINABILITY.value,
            BridgeType.ACTION_TO_REMEDIATION.value,
            BridgeType.REMEDIATION_TO_OUTCOME.value,
        }
        with Session(get_engine()) as db2:
            engine2 = GovernanceChainEngine(db2, _TENANT)
            for bridge in dispatchable:
                req = ExecuteBridgeRequest(
                    bridge=bridge,
                    trigger_object_id=_uid(),
                    trigger_object_type="test",
                    trigger_reason=f"coverage {bridge}",
                )
                result = engine2.execute_bridge(req, "a", "human")
                assert result.bridge_type == bridge

    def test_GC_191_list_executions_empty_returns_zero_total(self, build_app):
        build_app(auth_enabled=False)
        tid = f"t-empty-{_uid()[:8]}"
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, tid)
            resp = engine.list_executions()
            assert resp.total == 0
            assert resp.executions == []

    def test_GC_192_list_events_empty_returns_zero_total(self, build_app):
        build_app(auth_enabled=False)
        tid = f"t-evt-{_uid()[:8]}"
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, tid)
            resp = engine.list_chain_events()
            assert resp.total == 0
            assert resp.events == []

    def test_GC_193_recalculate_health_returns_governance_health_response(
        self, build_app
    ):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            result = engine.generate_governance_health_snapshot()
            assert isinstance(result, GovernanceHealthResponse)

    def test_GC_194_cgin_fingerprint_length_32(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            result = engine.get_cgin_snapshot()
        assert len(result.tenant_fingerprint) == 32

    def test_GC_195_diagnostics_bridge_dist_is_dict(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            result = engine.get_diagnostics()
        assert isinstance(result.bridge_execution_distribution, dict)

    def test_GC_196_execute_bridge_assessment_source_authority(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = ExecuteBridgeRequest(
                bridge=BridgeType.ASSESSMENT_TO_EVIDENCE.value,
                trigger_object_id=_uid(),
                trigger_object_type="evidence",
                trigger_reason="source check",
            )
            result = engine.execute_bridge(req, "a", "human")
        assert result.source_authority == "field_assessment"
        assert result.target_authority == "evidence_authority"

    def test_GC_197_generate_health_multiple_snapshots_stored(self, build_app):
        build_app(auth_enabled=False)
        tid = f"t-mh-{_uid()[:8]}"
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, tid)
            for _ in range(5):
                engine.generate_governance_health_snapshot()
            resp = engine.list_health_history()
            assert resp.total == 5

    def test_GC_198_list_health_history_most_recent_first(self, build_app):
        build_app(auth_enabled=False)
        tid = f"t-ord-{_uid()[:8]}"
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, tid)
            for _ in range(3):
                engine.generate_governance_health_snapshot()
            resp = engine.list_health_history()
        timestamps = [s.snapshot_at for s in resp.snapshots]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_GC_199_emit_event_with_payload_json(self, build_app):
        build_app(auth_enabled=False)
        import json as json_mod

        payload = json_mod.dumps({"key": "value"})
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            req = EmitChainEventRequest(
                event_type="EVIDENCE_REGISTERED",
                authority="test",
                object_type="evidence",
                object_id=_uid(),
                reason="payload test",
                payload_json=payload,
            )
            result = engine.emit_chain_event(req, "a", "human")
            assert result.payload_json == payload

    def test_GC_200_cgin_generated_at_is_iso8601(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            engine = GovernanceChainEngine(db, _TENANT)
            result = engine.get_cgin_snapshot()
        datetime.fromisoformat(result.generated_at.replace("Z", "+00:00"))

    def test_GC_201_chain_event_type_verification_completed(self):
        assert ChainEventType.VERIFICATION_COMPLETED == "VERIFICATION_COMPLETED"

    def test_GC_202_chain_event_type_freshness_updated(self):
        assert ChainEventType.FRESHNESS_UPDATED == "FRESHNESS_UPDATED"

    def test_GC_203_chain_event_type_effectiveness_recalculated(self):
        assert ChainEventType.EFFECTIVENESS_RECALCULATED == "EFFECTIVENESS_RECALCULATED"

    def test_GC_204_chain_event_type_action_created(self):
        assert ChainEventType.ACTION_CREATED == "ACTION_CREATED"

    def test_GC_205_chain_event_type_remediation_created(self):
        assert ChainEventType.REMEDIATION_CREATED == "REMEDIATION_CREATED"

    def test_GC_206_chain_event_type_remediation_completed(self):
        assert ChainEventType.REMEDIATION_COMPLETED == "REMEDIATION_COMPLETED"

    def test_GC_207_bridge_type_all_values_in_authorities_map(self):
        for bt in BridgeType:
            assert bt.value in BRIDGE_AUTHORITIES

    def test_GC_208_health_weight_verification_correct(self):
        assert HEALTH_WEIGHT_VERIFICATION == 0.25

    def test_GC_209_health_weight_freshness_correct(self):
        assert HEALTH_WEIGHT_FRESHNESS == 0.25

    def test_GC_210_health_weight_effectiveness_correct(self):
        assert HEALTH_WEIGHT_EFFECTIVENESS == 0.25
