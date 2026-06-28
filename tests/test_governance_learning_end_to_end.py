"""End-to-end tests for PR 17.6B — Governance Learning Loop Authority.

TestGovernanceLearningE2E covers:
1. Full ingestion loop: ingest → record exists → aggregate updated → recommendations → CGIN no tenant_id
2. Idempotency: ingest same source_outcome_id twice → only one record
3. Momentum from multiple outcomes: ingest 3 positive outcomes → ACCELERATING or STABLE
4. Failure detection: ingest 3 failure outcomes → HIGH_FAILURE_RATE signal detected
5. Recalculate: ingest → corrupt aggregate → recalculate → aggregate correct
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.db import get_engine
from services.governance_learning.models import LearningSignal, MomentumClass


def _uid() -> str:
    return str(uuid.uuid4())


def _tid() -> str:
    return f"t-gle-{uuid.uuid4().hex[:8]}"


class TestGovernanceLearningE2E:
    @pytest.fixture()
    def client_and_tenant(self, build_app):
        """Return (TestClient, tenant_id) with full governance r/w access."""
        tenant = _tid()
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", "governance:write", tenant_id=tenant)
        client = TestClient(app, headers={"X-API-Key": key})
        return client, tenant

    def _ingest_body(
        self,
        outcome_classification: str = "SUCCESS",
        score_delta: float = 15.0,
        remediation_category: str = "VERIFICATION",
        source_outcome_id: str | None = None,
        health_before: float = 60.0,
        health_after: float = 75.0,
        effectiveness_before: float = 50.0,
        effectiveness_after: float = 65.0,
    ) -> dict:
        return {
            "source_outcome_id": source_outcome_id or _uid(),
            "control_id": "ctrl-e2e-001",
            "outcome_classification": outcome_classification,
            "score_delta": score_delta,
            "remediation_category": remediation_category,
            "health_before": health_before,
            "health_after": health_after,
            "effectiveness_before": effectiveness_before,
            "effectiveness_after": effectiveness_after,
        }

    # -----------------------------------------------------------------------
    # E2E-1: Full ingestion loop
    # -----------------------------------------------------------------------

    def test_E2E_1_full_ingestion_loop(self, client_and_tenant):
        client, tenant = client_and_tenant

        # 1. Ingest an outcome
        body = self._ingest_body(outcome_classification="SUCCESS", score_delta=20.0)
        resp = client.post("/governance-learning/ingest-outcome", json=body)
        assert resp.status_code == 201
        record_id = resp.json()["id"]
        assert record_id is not None

        # 2. Check the learning record exists
        resp_records = client.get("/governance-learning/learning-records")
        assert resp_records.status_code == 200
        data = resp_records.json()
        assert data["total"] == 1
        assert data["records"][0]["id"] == record_id

        # 3. Check the aggregate was updated
        resp_agg = client.get("/governance-learning/aggregates")
        assert resp_agg.status_code == 200
        agg_data = resp_agg.json()
        assert agg_data["total"] == 1
        agg = agg_data["aggregates"][0]
        assert agg["success_count"] == 1
        assert agg["remediation_category"] == "VERIFICATION"

        # 4. Get recommendations (should suggest COLLECT_MORE_OUTCOME_DATA at low count)
        resp_recs = client.get("/governance-learning/recommendations")
        assert resp_recs.status_code == 200
        recs = resp_recs.json()
        assert recs["total"] >= 1

        # 5. CGIN snapshot must not contain raw tenant_id
        resp_cgin = client.get("/governance-learning/cgin/snapshot")
        assert resp_cgin.status_code == 200
        cgin_data = resp_cgin.json()
        assert tenant not in str(cgin_data)
        assert "tenant_fingerprint" in cgin_data
        assert len(cgin_data["tenant_fingerprint"]) == 32

    # -----------------------------------------------------------------------
    # E2E-2: Idempotency
    # -----------------------------------------------------------------------

    def test_E2E_2_idempotency(self, client_and_tenant):
        client, tenant = client_and_tenant

        oid = _uid()
        body = self._ingest_body(source_outcome_id=oid)

        resp1 = client.post("/governance-learning/ingest-outcome", json=body)
        assert resp1.status_code == 201
        id1 = resp1.json()["id"]

        resp2 = client.post("/governance-learning/ingest-outcome", json=body)
        assert resp2.status_code == 201
        id2 = resp2.json()["id"]

        assert id1 == id2

        # Only one record should exist
        resp_records = client.get("/governance-learning/learning-records")
        data = resp_records.json()
        assert data["total"] == 1

    # -----------------------------------------------------------------------
    # E2E-3: Momentum from multiple positive outcomes
    # -----------------------------------------------------------------------

    def test_E2E_3_momentum_from_positive_outcomes(self, client_and_tenant):
        client, tenant = client_and_tenant

        # Ingest 3 outcomes with high positive health deltas
        for _ in range(3):
            body = self._ingest_body(
                outcome_classification="SUCCESS",
                score_delta=20.0,
                health_before=50.0,
                health_after=65.0,  # delta = 15
                effectiveness_before=40.0,
                effectiveness_after=55.0,  # delta = 15
            )
            client.post("/governance-learning/ingest-outcome", json=body)

        resp = client.get("/governance-learning/momentum")
        assert resp.status_code == 200
        data = resp.json()
        assert data["momentum_class"] in [
            MomentumClass.ACCELERATING.value,
            MomentumClass.STABLE.value,
        ]
        assert data["total_learning_records"] == 3
        assert data["total_successful"] == 3

    # -----------------------------------------------------------------------
    # E2E-4: Failure detection signals
    # -----------------------------------------------------------------------

    def test_E2E_4_failure_detection(self, client_and_tenant):
        client, tenant = client_and_tenant

        # Ingest 3 failure outcomes
        for _ in range(3):
            body = self._ingest_body(
                outcome_classification="FAILURE",
                score_delta=-5.0,
                remediation_category="FRESHNESS",
            )
            client.post("/governance-learning/ingest-outcome", json=body)

        # Check aggregates for HIGH_FAILURE_RATE signal
        resp = client.get("/governance-learning/aggregates")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        freshness_agg = next(
            (a for a in data["aggregates"] if a["remediation_category"] == "FRESHNESS"),
            None,
        )
        assert freshness_agg is not None
        assert LearningSignal.HIGH_FAILURE_RATE.value in freshness_agg["signals"]

        # Also verify ESCALATE_OR_REVIEW recommendation appears
        resp_recs = client.get("/governance-learning/recommendations")
        recs_data = resp_recs.json()
        actions = [r["recommended_next_action"] for r in recs_data["recommendations"]]
        assert "ESCALATE_OR_REVIEW" in actions

    # -----------------------------------------------------------------------
    # E2E-5: Recalculate correctness
    # -----------------------------------------------------------------------

    def test_E2E_5_recalculate_fixes_corrupt_aggregate(
        self, client_and_tenant, build_app
    ):
        client, tenant = client_and_tenant

        # 1. Ingest an outcome
        body = self._ingest_body(outcome_classification="SUCCESS")
        resp = client.post("/governance-learning/ingest-outcome", json=body)
        assert resp.status_code == 201

        # 2. Manually corrupt the aggregate via direct DB access
        from services.governance_learning.repository import GovernanceLearningRepository

        with Session(get_engine()) as db:
            repo = GovernanceLearningRepository(db, tenant)
            agg = repo.get_aggregate("VERIFICATION")
            assert agg is not None
            agg.success_count = 9999
            db.commit()

        # Verify corruption
        resp_agg = client.get("/governance-learning/aggregates")
        agg_data = resp_agg.json()
        ver_agg = next(
            (
                a
                for a in agg_data["aggregates"]
                if a["remediation_category"] == "VERIFICATION"
            ),
            None,
        )
        assert ver_agg is not None
        assert ver_agg["success_count"] == 9999

        # 3. Recalculate
        resp_calc = client.post("/governance-learning/recalculate", json={})
        assert resp_calc.status_code == 200
        calc_data = resp_calc.json()
        assert calc_data["categories_recalculated"] >= 1

        # 4. Verify aggregate is now correct
        resp_agg2 = client.get("/governance-learning/aggregates")
        agg_data2 = resp_agg2.json()
        ver_agg2 = next(
            (
                a
                for a in agg_data2["aggregates"]
                if a["remediation_category"] == "VERIFICATION"
            ),
            None,
        )
        assert ver_agg2 is not None
        assert ver_agg2["success_count"] == 1
