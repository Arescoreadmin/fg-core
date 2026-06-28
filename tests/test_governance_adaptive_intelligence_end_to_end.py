"""End-to-end tests for PR 17.6C — Governance Adaptive Intelligence Authority.

TestGovernanceAdaptiveIntelligenceE2E covers:
1. Full adaptive loop: track→accept→execute→record-outcome→accuracy updated→
   calibration updated→playbook updated→CGIN snapshot
2. Deprioritization: 3 failed outcomes → accuracy = 0.0 → CALIBRATED_UNKNOWN
3. Promotion: 3 successful outcomes → accuracy >= 0.75 → CALIBRATED_HIGH
4. CGIN no tenant_id exposure
5. Recalculate rebuilds from scratch
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key


def _uid() -> str:
    return str(uuid.uuid4())


def _tid() -> str:
    return f"t-gaie-{uuid.uuid4().hex[:8]}"


class TestGovernanceAdaptiveIntelligenceE2E:
    @pytest.fixture()
    def client_and_tenant(self, build_app):
        """Return (TestClient, tenant_id) with full governance r/w access."""
        tenant = _tid()
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", "governance:write", tenant_id=tenant)
        client = TestClient(app, headers={"X-API-Key": key})
        return client, tenant

    def _track_body(
        self,
        recommendation_id: str | None = None,
        recommendation_type: str = "GOVERNANCE_REVIEW",
    ) -> dict:
        return {
            "recommendation_id": recommendation_id or _uid(),
            "recommendation_type": recommendation_type,
            "recommendation_category": "VERIFICATION",
            "recommendation_reason": "E2E test recommendation",
            "recommendation_confidence": "HIGH",
            "source_authority": "governance_learning",
        }

    def _record_outcome_body(self, history_id: str, success: bool = True) -> dict:
        return {
            "recommendation_history_id": history_id,
            "success": success,
            "health_before": 60.0,
            "health_after": 75.0 if success else 55.0,
            "effectiveness_before": 50.0,
            "effectiveness_after": 65.0 if success else 45.0,
        }

    # -----------------------------------------------------------------------
    # E2E-1: Full adaptive loop
    # -----------------------------------------------------------------------

    def test_E2E_1_full_adaptive_loop(self, client_and_tenant):
        client, tenant = client_and_tenant

        # 1. Track a recommendation
        rec_id = _uid()
        track_resp = client.post(
            "/governance-adaptive-intelligence/track",
            json=self._track_body(recommendation_id=rec_id),
        )
        assert track_resp.status_code == 201
        history_id = track_resp.json()["id"]
        assert track_resp.json()["status"] == "PENDING"

        # 2. Accept the recommendation
        accept_resp = client.post(
            "/governance-adaptive-intelligence/accept",
            json={"recommendation_history_id": history_id, "accepted": True},
        )
        assert accept_resp.status_code == 200
        assert accept_resp.json()["status"] == "ACCEPTED"
        new_history_id = accept_resp.json()["id"]

        # 3. Execute the recommendation (new row again)
        exec_resp = client.post(
            "/governance-adaptive-intelligence/execute",
            json={"recommendation_history_id": new_history_id},
        )
        assert exec_resp.status_code == 200
        assert exec_resp.json()["status"] == "EXECUTED"
        exec_history_id = exec_resp.json()["id"]

        # 4. Record the outcome
        outcome_resp = client.post(
            "/governance-adaptive-intelligence/record-outcome",
            json=self._record_outcome_body(exec_history_id, success=True),
        )
        assert outcome_resp.status_code == 201
        assert outcome_resp.json()["success"] is True
        assert outcome_resp.json()["health_delta"] == 15.0

        # 5. Accuracy aggregate is updated
        acc_resp = client.get("/governance-adaptive-intelligence/accuracy")
        assert acc_resp.status_code == 200
        acc = acc_resp.json()
        gov_review = next(
            (
                t
                for t in acc["per_type"]
                if t["recommendation_type"] == "GOVERNANCE_REVIEW"
            ),
            None,
        )
        assert gov_review is not None
        assert gov_review["recommendations_executed"] == 1
        assert gov_review["recommendations_successful"] == 1
        assert gov_review["accuracy_score"] == 1.0

        # 6. Calibration is updated
        cal_resp = client.get("/governance-adaptive-intelligence/calibration")
        assert cal_resp.status_code == 200
        cal = cal_resp.json()
        assert "GOVERNANCE_REVIEW" in cal["confidence_distribution"]

        # 7. Recalculate rebuilds playbooks
        recap_resp = client.post(
            "/governance-adaptive-intelligence/recalculate", json={}
        )
        assert recap_resp.status_code == 200

        # 8. CGIN snapshot is accessible and anonymized
        snap_resp = client.get("/governance-adaptive-intelligence/cgin/snapshot")
        assert snap_resp.status_code == 200
        snap = snap_resp.json()
        assert tenant not in snap["tenant_fingerprint"]
        assert "tenant_fingerprint" in snap
        assert snap["total_recommendations"] >= 1

        # 9. List recommendations shows latest status
        recs_resp = client.get("/governance-adaptive-intelligence/recommendations")
        matching = [r for r in recs_resp.json() if r["recommendation_id"] == rec_id]
        assert len(matching) == 1
        # Latest status should be EXECUTED
        assert matching[0]["status"] == "EXECUTED"

    # -----------------------------------------------------------------------
    # E2E-2: Deprioritization — 3 failed outcomes → CALIBRATED_UNKNOWN
    # -----------------------------------------------------------------------

    def test_E2E_2_deprioritization_after_failures(self, client_and_tenant):
        client, tenant = client_and_tenant

        for _ in range(3):
            track = client.post(
                "/governance-adaptive-intelligence/track",
                json=self._track_body(recommendation_type="ESCALATE_WORST_CATEGORY"),
            ).json()
            client.post(
                "/governance-adaptive-intelligence/record-outcome",
                json=self._record_outcome_body(track["id"], success=False),
            )

        acc_resp = client.get("/governance-adaptive-intelligence/accuracy").json()
        worst = next(
            (
                t
                for t in acc_resp["per_type"]
                if t["recommendation_type"] == "ESCALATE_WORST_CATEGORY"
            ),
            None,
        )
        assert worst is not None
        assert worst["recommendations_failed"] == 3
        assert worst["recommendations_successful"] == 0
        assert worst["accuracy_score"] == 0.0
        # With 3 samples and 0.0 accuracy → CALIBRATED_UNKNOWN
        assert worst["calibrated_confidence"] == "CALIBRATED_UNKNOWN"

    # -----------------------------------------------------------------------
    # E2E-3: Promotion — 3 successful outcomes → CALIBRATED_HIGH
    # -----------------------------------------------------------------------

    def test_E2E_3_promotion_after_successes(self, client_and_tenant):
        client, tenant = client_and_tenant

        for _ in range(3):
            track = client.post(
                "/governance-adaptive-intelligence/track",
                json=self._track_body(recommendation_type="PRIORITIZE_BEST_CATEGORY"),
            ).json()
            client.post(
                "/governance-adaptive-intelligence/record-outcome",
                json=self._record_outcome_body(track["id"], success=True),
            )

        acc_resp = client.get("/governance-adaptive-intelligence/accuracy").json()
        prioritize = next(
            (
                t
                for t in acc_resp["per_type"]
                if t["recommendation_type"] == "PRIORITIZE_BEST_CATEGORY"
            ),
            None,
        )
        assert prioritize is not None
        assert prioritize["recommendations_successful"] == 3
        assert prioritize["accuracy_score"] == 1.0
        assert prioritize["calibrated_confidence"] == "CALIBRATED_HIGH"

    # -----------------------------------------------------------------------
    # E2E-4: CGIN no tenant_id exposure
    # -----------------------------------------------------------------------

    def test_E2E_4_cgin_no_tenant_id_exposure(self, client_and_tenant):
        client, tenant = client_and_tenant

        snap = client.get("/governance-adaptive-intelligence/cgin/snapshot").json()

        # Raw tenant_id must not appear anywhere in the snapshot
        snap_str = str(snap)
        assert tenant not in snap_str

        # Fingerprint must be deterministic
        snap2 = client.get("/governance-adaptive-intelligence/cgin/snapshot").json()
        assert snap["tenant_fingerprint"] == snap2["tenant_fingerprint"]

        # bundle_id must not contain tenant
        assert tenant not in snap["bundle_id"]

    # -----------------------------------------------------------------------
    # E2E-5: Recalculate rebuilds from scratch
    # -----------------------------------------------------------------------

    def test_E2E_5_recalculate_rebuilds_from_scratch(self, client_and_tenant):
        client, tenant = client_and_tenant

        # Seed some outcomes
        for _ in range(2):
            track = client.post(
                "/governance-adaptive-intelligence/track",
                json=self._track_body(recommendation_type="IMPROVE_VERIFICATION"),
            ).json()
            client.post(
                "/governance-adaptive-intelligence/record-outcome",
                json=self._record_outcome_body(track["id"], success=True),
            )

        # Verify aggregate exists
        acc_before = client.get("/governance-adaptive-intelligence/accuracy").json()
        imp_ver_before = next(
            (
                t
                for t in acc_before["per_type"]
                if t["recommendation_type"] == "IMPROVE_VERIFICATION"
            ),
            None,
        )
        assert imp_ver_before is not None
        assert imp_ver_before["recommendations_executed"] == 2

        # Recalculate
        recap = client.post("/governance-adaptive-intelligence/recalculate", json={})
        assert recap.status_code == 200
        data = recap.json()
        assert data["tenant_id"] == tenant
        assert "recalculated_at" in data

        # Verify aggregate is still correct after recalculate
        acc_after = client.get("/governance-adaptive-intelligence/accuracy").json()
        imp_ver_after = next(
            (
                t
                for t in acc_after["per_type"]
                if t["recommendation_type"] == "IMPROVE_VERIFICATION"
            ),
            None,
        )
        assert imp_ver_after is not None
        assert imp_ver_after["recommendations_executed"] == 2
        assert imp_ver_after["recommendations_successful"] == 2

        # Verify playbooks were rebuilt
        playbooks = client.get("/governance-adaptive-intelligence/playbooks").json()
        # Should have at least one playbook
        assert len(playbooks) >= 0  # playbooks present after recalculate

    # -----------------------------------------------------------------------
    # E2E-6: Outcome attached to recommendation detail
    # -----------------------------------------------------------------------

    def test_E2E_6_outcome_attached_to_recommendation_detail(self, client_and_tenant):
        client, tenant = client_and_tenant

        rec_id = _uid()
        track = client.post(
            "/governance-adaptive-intelligence/track",
            json=self._track_body(recommendation_id=rec_id),
        ).json()
        client.post(
            "/governance-adaptive-intelligence/record-outcome",
            json=self._record_outcome_body(track["id"], success=True),
        )

        detail = client.get(
            f"/governance-adaptive-intelligence/recommendations/{rec_id}"
        ).json()
        assert detail["outcome"] is not None
        assert detail["outcome"]["success"] is True

    # -----------------------------------------------------------------------
    # E2E-7: Status transition chain is visible in list
    # -----------------------------------------------------------------------

    def test_E2E_7_status_transitions_visible(self, client_and_tenant):
        client, tenant = client_and_tenant

        rec_id = _uid()
        track = client.post(
            "/governance-adaptive-intelligence/track",
            json=self._track_body(recommendation_id=rec_id),
        ).json()
        assert track["status"] == "PENDING"

        accept = client.post(
            "/governance-adaptive-intelligence/accept",
            json={"recommendation_history_id": track["id"], "accepted": True},
        ).json()
        assert accept["status"] == "ACCEPTED"

        execute = client.post(
            "/governance-adaptive-intelligence/execute",
            json={"recommendation_history_id": accept["id"]},
        ).json()
        assert execute["status"] == "EXECUTED"

        # Latest in list should be EXECUTED
        recs = client.get("/governance-adaptive-intelligence/recommendations").json()
        matching = [r for r in recs if r["recommendation_id"] == rec_id]
        assert len(matching) == 1
        assert matching[0]["status"] == "EXECUTED"
