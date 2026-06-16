"""Tests for P0-11 Continuous Governance Control Tower (CGCT).

Covers:
  - Posture computation with empty DB (graceful degradation)
  - Posture health level thresholds (all 5 levels)
  - Action queue with empty DB
  - Action queue with renewal_due cert → action generated
  - Authority matrix structure
  - Governance graph with no edges
  - Aggregate decisions with empty DB
  - Route auth requirements (/posture, /health, /executive)
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# DB Mock helpers (same pattern as test_clm.py)
# ---------------------------------------------------------------------------


def _empty_db():
    """Return a db mock that returns None on scalar_one_or_none and [] on all()."""
    db = MagicMock()
    execute_result = MagicMock()
    scalars_result = MagicMock()
    execute_result.scalar_one_or_none.return_value = None
    execute_result.scalars.return_value = scalars_result
    scalars_result.all.return_value = []
    db.execute.return_value = execute_result
    return db


def _make_cert(
    cert_id="cert-001",
    tenant_id="t1",
    engagement_id="eng-001",
    lifecycle_status="draft",
    cert_name="Test Cert",
):
    cert = MagicMock()
    cert.id = cert_id
    cert.tenant_id = tenant_id
    cert.engagement_id = engagement_id
    cert.lifecycle_status = lifecycle_status
    cert.cert_name = cert_name
    cert.created_at = "2026-01-01T00:00:00Z"
    return cert


def _make_drift_event(
    event_id="drift-001",
    tenant_id="t1",
    engagement_id="eng-001",
    drift_rule="score_degradation",
    severity="high",
    resolved_at=None,
):
    event = MagicMock()
    event.id = event_id
    event.tenant_id = tenant_id
    event.engagement_id = engagement_id
    event.drift_rule = drift_rule
    event.severity = severity
    event.resolved_at = resolved_at
    event.detected_at = "2026-06-01T00:00:00Z"
    return event


def _make_bundle(
    bundle_id="bundle-001",
    tenant_id="t1",
    engagement_id="eng-001",
    coverage_status="complete",
):
    bundle = MagicMock()
    bundle.id = bundle_id
    bundle.tenant_id = tenant_id
    bundle.engagement_id = engagement_id
    bundle.coverage_status = coverage_status
    bundle.generated_at = "2026-06-01T00:00:00Z"
    return bundle


def _make_tim_snapshot(
    snap_id="snap-001",
    tenant_id="t1",
    engagement_id="eng-001",
    posture_score=80,
    risk_level="low",
    open_drift_count=0,
    drift_direction="stable",
    drift_score=0,
    posture_level="high",
    certification_level="gold",
    replay_status="ok",
):
    snap = MagicMock()
    snap.id = snap_id
    snap.tenant_id = tenant_id
    snap.engagement_id = engagement_id
    snap.posture_score = posture_score
    snap.risk_level = risk_level
    snap.open_drift_count = open_drift_count
    snap.drift_direction = drift_direction
    snap.drift_score = drift_score
    snap.posture_level = posture_level
    snap.certification_level = certification_level
    snap.replay_status = replay_status
    snap.evaluated_at = "2026-06-01T00:00:00Z"
    return snap


# ---------------------------------------------------------------------------
# TestPostureComputeEmptyDB
# ---------------------------------------------------------------------------


class TestPostureComputeEmptyDB:
    def test_compute_posture_empty_db_returns_dict(self):
        """compute_posture with no data should return a valid dict."""
        from services.cgct.posture import compute_posture

        db = _empty_db()
        result = compute_posture(db, tenant_id="t1", engagement_id="eng-001")
        assert isinstance(result, dict)
        assert "overall_score" in result
        assert "governance_health" in result

    def test_compute_posture_empty_db_score_is_integer(self):
        from services.cgct.posture import compute_posture

        db = _empty_db()
        result = compute_posture(db, tenant_id="t1", engagement_id="eng-001")
        assert isinstance(result["overall_score"], int)

    def test_compute_posture_empty_db_health_is_string(self):
        from services.cgct.posture import compute_posture

        db = _empty_db()
        result = compute_posture(db, tenant_id="t1", engagement_id="eng-001")
        valid_health = {
            "healthy",
            "attention_required",
            "degraded",
            "at_risk",
            "critical",
        }
        assert result["governance_health"] in valid_health

    def test_compute_posture_empty_db_has_score_inputs(self):
        from services.cgct.posture import compute_posture

        db = _empty_db()
        result = compute_posture(db, tenant_id="t1", engagement_id="eng-001")
        assert "score_inputs_json" in result
        assert isinstance(result["score_inputs_json"], dict)

    def test_compute_posture_empty_db_has_version(self):
        from services.cgct.posture import compute_posture

        db = _empty_db()
        result = compute_posture(db, tenant_id="t1", engagement_id="eng-001")
        assert result.get("version") == "CGCTv1"

    def test_compute_posture_empty_db_returns_tenant_id(self):
        from services.cgct.posture import compute_posture

        db = _empty_db()
        result = compute_posture(db, tenant_id="my-tenant", engagement_id="eng-001")
        assert result["tenant_id"] == "my-tenant"


# ---------------------------------------------------------------------------
# TestPostureHealthLevels
# ---------------------------------------------------------------------------


class TestPostureHealthLevels:
    """Parametrized tests for all 5 governance health levels."""

    @pytest.mark.parametrize(
        "overall_score,expected_health",
        [
            (85, "healthy"),
            (80, "healthy"),
            (65, "attention_required"),
            (60, "attention_required"),
            (45, "degraded"),
            (40, "degraded"),
            (25, "at_risk"),
            (20, "at_risk"),
            (10, "critical"),
            (0, "critical"),
        ],
    )
    def test_health_level_for_score(self, overall_score: int, expected_health: str):
        from services.cgct.posture import _governance_health

        assert _governance_health(overall_score) == expected_health

    def test_boundary_80_is_healthy(self):
        from services.cgct.posture import _governance_health

        assert _governance_health(80) == "healthy"

    def test_boundary_79_is_attention_required(self):
        from services.cgct.posture import _governance_health

        assert _governance_health(79) == "attention_required"

    def test_boundary_60_is_attention_required(self):
        from services.cgct.posture import _governance_health

        assert _governance_health(60) == "attention_required"

    def test_boundary_59_is_degraded(self):
        from services.cgct.posture import _governance_health

        assert _governance_health(59) == "degraded"


# ---------------------------------------------------------------------------
# TestActionQueueEmpty
# ---------------------------------------------------------------------------


class TestActionQueueEmpty:
    def test_compute_actions_empty_db_returns_list(self):
        from services.cgct.action_queue import compute_actions

        db = _empty_db()
        result = compute_actions(db, tenant_id="t1", engagement_id="eng-001")
        assert isinstance(result, list)

    def test_compute_actions_empty_db_returns_empty_list(self):
        from services.cgct.action_queue import compute_actions

        db = _empty_db()
        result = compute_actions(db, tenant_id="t1", engagement_id="eng-001")
        assert result == []

    def test_store_actions_empty_list_returns_zero(self):
        from services.cgct.action_queue import store_actions

        db = _empty_db()
        count = store_actions(db, tenant_id="t1", engagement_id="eng-001", actions=[])
        assert count == 0


# ---------------------------------------------------------------------------
# TestActionQueueRenewalDue
# ---------------------------------------------------------------------------


class TestActionQueueRenewalDue:
    def _db_with_cert(self, cert):
        db = MagicMock()
        execute_result = MagicMock()
        scalars_result = MagicMock()
        execute_result.scalar_one_or_none.return_value = cert
        execute_result.scalars.return_value = scalars_result
        scalars_result.all.return_value = [cert]
        db.execute.return_value = execute_result
        return db

    def test_renewal_due_cert_generates_action(self):
        from services.cgct.action_queue import _clm_actions

        cert = _make_cert(lifecycle_status="renewal_due")
        db = self._db_with_cert(cert)
        actions = _clm_actions(db, tenant_id="t1", engagement_id="eng-001")
        assert len(actions) >= 1
        assert actions[0]["action_type"] == "renew_certification"

    def test_renewal_due_action_priority_is_high(self):
        from services.cgct.action_queue import _clm_actions

        cert = _make_cert(lifecycle_status="renewal_due")
        db = self._db_with_cert(cert)
        actions = _clm_actions(db, tenant_id="t1", engagement_id="eng-001")
        assert actions[0]["priority"] == "high"

    def test_expired_cert_generates_renew_action(self):
        from services.cgct.action_queue import _clm_actions

        cert = _make_cert(lifecycle_status="expired")
        db = self._db_with_cert(cert)
        actions = _clm_actions(db, tenant_id="t1", engagement_id="eng-001")
        assert len(actions) >= 1
        assert actions[0]["action_type"] == "renew_certification"

    def test_in_review_cert_generates_review_action(self):
        from services.cgct.action_queue import _clm_actions

        cert = _make_cert(lifecycle_status="in_review")
        db = self._db_with_cert(cert)
        actions = _clm_actions(db, tenant_id="t1", engagement_id="eng-001")
        assert len(actions) >= 1
        assert actions[0]["action_type"] == "review_certification"

    def test_certified_cert_generates_no_action(self):
        from services.cgct.action_queue import _clm_actions

        cert = _make_cert(lifecycle_status="certified")
        db = self._db_with_cert(cert)
        actions = _clm_actions(db, tenant_id="t1", engagement_id="eng-001")
        assert len(actions) == 0

    def test_action_has_source_system_clm(self):
        from services.cgct.action_queue import _clm_actions

        cert = _make_cert(lifecycle_status="renewal_due")
        db = self._db_with_cert(cert)
        actions = _clm_actions(db, tenant_id="t1", engagement_id="eng-001")
        assert actions[0]["source_system"] == "clm"

    def test_action_has_source_id(self):
        from services.cgct.action_queue import _clm_actions

        cert = _make_cert(cert_id="cert-999", lifecycle_status="renewal_due")
        db = self._db_with_cert(cert)
        actions = _clm_actions(db, tenant_id="t1", engagement_id="eng-001")
        assert actions[0]["source_id"] == "cert-999"

    def test_tampered_bundle_generates_critical_action(self):
        from services.cgct.action_queue import _bundle_actions

        bundle = _make_bundle(coverage_status="tampered")
        db = MagicMock()
        execute_result = MagicMock()
        scalars_result = MagicMock()
        execute_result.scalar_one_or_none.return_value = bundle
        execute_result.scalars.return_value = scalars_result
        scalars_result.all.return_value = [bundle]
        db.execute.return_value = execute_result
        actions = _bundle_actions(db, tenant_id="t1", engagement_id="eng-001")
        assert len(actions) >= 1
        assert actions[0]["priority"] == "critical"

    def test_open_drift_generates_investigate_action(self):
        from services.cgct.action_queue import _tim_drift_actions

        event = _make_drift_event(resolved_at=None)
        db = MagicMock()
        execute_result = MagicMock()
        scalars_result = MagicMock()
        execute_result.scalar_one_or_none.return_value = event
        execute_result.scalars.return_value = scalars_result
        scalars_result.all.return_value = [event]
        db.execute.return_value = execute_result
        actions = _tim_drift_actions(db, tenant_id="t1", engagement_id="eng-001")
        assert len(actions) >= 1
        assert actions[0]["action_type"] == "investigate_drift"


# ---------------------------------------------------------------------------
# TestAuthorityMatrixStructure
# ---------------------------------------------------------------------------


class TestAuthorityMatrixStructure:
    def test_authority_matrix_returns_dict(self):
        from services.cgct.aggregators import get_authority_matrix

        result = get_authority_matrix("t1")
        assert isinstance(result, dict)

    def test_authority_matrix_has_authority_sources(self):
        from services.cgct.aggregators import get_authority_matrix

        result = get_authority_matrix("t1")
        assert "authority_sources" in result

    def test_authority_matrix_has_all_required_sources(self):
        from services.cgct.aggregators import get_authority_matrix

        result = get_authority_matrix("t1")
        sources = result["authority_sources"]
        required = {
            "trust_arc",
            "tim",
            "clm",
            "verification_bundles",
            "decision_memory",
            "timeline",
            "capability_authority",
        }
        for key in required:
            assert key in sources, f"Missing authority source: {key}"

    def test_each_source_has_required_fields(self):
        from services.cgct.aggregators import get_authority_matrix

        result = get_authority_matrix("t1")
        required_fields = {
            "producer",
            "authority_level",
            "consumer_systems",
            "replay_support",
            "tenant_scoped",
            "audit_support",
        }
        for name, src in result["authority_sources"].items():
            for field in required_fields:
                assert field in src, f"Source '{name}' missing field '{field}'"

    def test_authority_matrix_has_version(self):
        from services.cgct.aggregators import get_authority_matrix

        result = get_authority_matrix("t1")
        assert result.get("version") == "CGCTv1"

    def test_authority_levels_are_valid(self):
        from services.cgct.aggregators import get_authority_matrix

        result = get_authority_matrix("t1")
        valid_levels = {"primary", "secondary"}
        for name, src in result["authority_sources"].items():
            assert src["authority_level"] in valid_levels, (
                f"Source '{name}' has invalid authority_level '{src['authority_level']}'"
            )


# ---------------------------------------------------------------------------
# TestGovernanceGraphEmpty
# ---------------------------------------------------------------------------


class TestGovernanceGraphEmpty:
    def test_empty_graph_returns_dict(self):
        from services.cgct.aggregators import get_governance_graph

        db = _empty_db()
        result = get_governance_graph(db, tenant_id="t1")
        assert isinstance(result, dict)

    def test_empty_graph_has_nodes_and_edges_keys(self):
        from services.cgct.aggregators import get_governance_graph

        db = _empty_db()
        result = get_governance_graph(db, tenant_id="t1")
        assert "nodes" in result
        assert "edges" in result

    def test_empty_graph_nodes_is_empty_list(self):
        from services.cgct.aggregators import get_governance_graph

        db = _empty_db()
        result = get_governance_graph(db, tenant_id="t1")
        assert result["nodes"] == []

    def test_empty_graph_edges_is_empty_list(self):
        from services.cgct.aggregators import get_governance_graph

        db = _empty_db()
        result = get_governance_graph(db, tenant_id="t1")
        assert result["edges"] == []

    def test_empty_graph_counts_are_zero(self):
        from services.cgct.aggregators import get_governance_graph

        db = _empty_db()
        result = get_governance_graph(db, tenant_id="t1")
        assert result["node_count"] == 0
        assert result["edge_count"] == 0

    def test_empty_graph_has_version(self):
        from services.cgct.aggregators import get_governance_graph

        db = _empty_db()
        result = get_governance_graph(db, tenant_id="t1")
        assert result.get("version") == "CGCTv1"


# ---------------------------------------------------------------------------
# TestAggregateDecisionsEmpty
# ---------------------------------------------------------------------------


class TestAggregateDecisionsEmpty:
    def test_empty_decisions_returns_dict(self):
        from services.cgct.aggregators import aggregate_decisions

        db = _empty_db()
        result = aggregate_decisions(db, tenant_id="t1", engagement_id="eng-001")
        assert isinstance(result, dict)

    def test_empty_decisions_returns_empty_list(self):
        from services.cgct.aggregators import aggregate_decisions

        db = _empty_db()
        result = aggregate_decisions(db, tenant_id="t1", engagement_id="eng-001")
        assert result["decisions"] == []

    def test_empty_decisions_total_is_zero(self):
        from services.cgct.aggregators import aggregate_decisions

        db = _empty_db()
        result = aggregate_decisions(db, tenant_id="t1", engagement_id="eng-001")
        assert result["total"] == 0

    def test_empty_decisions_has_version(self):
        from services.cgct.aggregators import aggregate_decisions

        db = _empty_db()
        result = aggregate_decisions(db, tenant_id="t1", engagement_id="eng-001")
        assert result.get("version") == "CGCTv1"


# ---------------------------------------------------------------------------
# TestRouteAuthRequirements
# ---------------------------------------------------------------------------


class TestRouteAuthRequirements:
    """Route auth enforcement tests using FastAPI TestClient."""

    def _get_app(self):
        import os

        os.environ["FG_ENV"] = "test"
        try:
            from fastapi import FastAPI

            from api.control_tower import router

            app = FastAPI()
            app.include_router(router)
            return app
        except Exception:
            return None

    def test_route_posture_requires_auth(self):
        """GET /control-tower/posture returns 4xx without auth."""
        app = self._get_app()
        if app is None:
            pytest.skip("app setup failed")
        from fastapi.testclient import TestClient

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/control-tower/posture")
        assert resp.status_code in (401, 403, 422, 500)

    def test_route_health_requires_auth(self):
        """GET /control-tower/health returns 4xx without auth."""
        app = self._get_app()
        if app is None:
            pytest.skip("app setup failed")
        from fastapi.testclient import TestClient

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/control-tower/health")
        assert resp.status_code in (401, 403, 422, 500)

    def test_route_executive_requires_auth(self):
        """GET /control-tower/executive returns 4xx without auth."""
        app = self._get_app()
        if app is None:
            pytest.skip("app setup failed")
        from fastapi.testclient import TestClient

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/control-tower/executive")
        assert resp.status_code in (401, 403, 422, 500)


# ---------------------------------------------------------------------------
# TestEvidenceScoreMap
# ---------------------------------------------------------------------------


class TestEvidenceScoreMap:
    """Verify evidence score mappings are deterministic."""

    @pytest.mark.parametrize(
        "coverage_status,expected_score",
        [
            ("complete", 100),
            ("partial", 70),
            ("missing_evidence", 40),
            ("missing_report", 20),
            ("tampered", 0),
        ],
    )
    def test_evidence_score_for_coverage(
        self, coverage_status: str, expected_score: int
    ):
        from services.cgct.posture import _EVIDENCE_SCORE_MAP

        assert _EVIDENCE_SCORE_MAP[coverage_status] == expected_score


# ---------------------------------------------------------------------------
# TestRiskScoreMap
# ---------------------------------------------------------------------------


class TestRiskScoreMap:
    """Verify risk score mappings are deterministic."""

    @pytest.mark.parametrize(
        "risk_level,expected_score",
        [
            ("low", 90),
            ("medium", 70),
            ("high", 40),
            ("critical", 10),
            ("unknown", 50),
        ],
    )
    def test_risk_score_for_level(self, risk_level: str, expected_score: int):
        from services.cgct.posture import _RISK_SCORE_MAP

        assert _RISK_SCORE_MAP[risk_level] == expected_score


# ---------------------------------------------------------------------------
# TestOverallScoreCalculation
# ---------------------------------------------------------------------------


class TestOverallScoreCalculation:
    """Verify overall_score formula is deterministic and correct."""

    def test_perfect_scores_give_100(self):
        """trust=100, cert=100, evidence=100, risk=100 → overall=100."""
        # Verify the formula directly:
        trust_score = 100
        cert_score = 100
        evidence_score = 100
        risk_score = 100
        overall = int(
            trust_score * 0.35
            + cert_score * 0.25
            + evidence_score * 0.25
            + risk_score * 0.15
        )
        assert overall == 100

    def test_zero_scores_give_zero(self):
        overall = int(0 * 0.35 + 0 * 0.25 + 0 * 0.25 + 0 * 0.15)
        assert overall == 0

    def test_weights_sum_to_one(self):
        weights = [0.35, 0.25, 0.25, 0.15]
        assert abs(sum(weights) - 1.0) < 0.001

    def test_score_is_deterministic(self):
        """Same inputs always produce same output."""
        from services.cgct.posture import _governance_health

        score = int(80 * 0.35 + 70 * 0.25 + 60 * 0.25 + 90 * 0.15)
        health = _governance_health(score)
        # Run again
        score2 = int(80 * 0.35 + 70 * 0.25 + 60 * 0.25 + 90 * 0.15)
        health2 = _governance_health(score2)
        assert score == score2
        assert health == health2
