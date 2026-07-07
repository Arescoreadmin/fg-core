"""Tests for the governance promotion service and admin retry route.

Covers:
  - promote_engagement_to_governance() creates workflow per finding with finding_id
  - promote_engagement_to_governance() promotes detected asset candidates
  - Promotion record status=completed on success
  - Idempotent: second call returns same record without re-running steps
  - Retry: re-runs steps when promotion status=failed
  - Admin retry route returns 409 when engagement not delivered
  - Admin retry route returns 200 with completed promotion for delivered engagement
  - Admin retry route is idempotent for already-completed promotion
"""

from __future__ import annotations

from typing import Any
import os
from unittest.mock import patch

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from api.db_models import Base
import api.db_models_field_assessment  # noqa: F401
import api.db_models_drift  # noqa: F401
import api.db_models_governance_report  # noqa: F401
import api.db_models_governance_workflows  # noqa: F401
import api.db_models_governance_assets  # noqa: F401
import api.db_models_governance_asset_candidates  # noqa: F401
import api.db_models_governance_promotion  # noqa: F401
import api.db_models_timeline  # noqa: F401


from api.db_models_governance_asset_candidates import GaAssetCandidate
from api.db_models_governance_assets import GaAsset
from api.db_models_governance_workflows import GovernanceWorkflow
from services.canonical import utc_iso8601_z_now
from services.field_assessment.models import PromotionAlreadyExists
from services.field_assessment.promotion import promote_engagement_to_governance
from services.field_assessment.promotion_store import (
    create_promotion,
    fail_promotion,
    get_promotion,
)
from services.field_assessment.store import (
    create_document_analysis,
    create_engagement,
    create_observation,
    create_scan_result,
)
from services.field_assessment.normalizer import normalize_scan_findings

_TENANT = "tenant-promotion-test"
_ENGAGEMENT = "eng-promo-001"
_GATE_SNAPSHOT = {
    "gates_evaluated": ["scan.microsoft_graph.required"],
    "gates_passed": ["scan.microsoft_graph.required"],
    "readiness_score": 82,
}


@pytest.fixture()
def engine():
    import api.signed_artifacts  # noqa: F401

    os.environ.setdefault("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
    os.environ.setdefault(
        "FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    )
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def db(engine):
    with Session(engine) as session:
        yield session


def _make_delivered_engagement(db: Session, suffix: str = "a") -> Any:
    eng = create_engagement(
        db,
        tenant_id=_TENANT,
        client_name=f"Promo Corp {suffix}",
        client_domain=None,
        assessor_id="assessor-promo",
        assessment_type="ai_governance",
        scheduled_date=None,
        engagement_metadata={},
        actor="test",
    )
    # Force status to delivered directly — in the simplified status model
    # in_progress → delivered is auto-advance only (via qa-approve), not a
    # manual transition.
    eng.status = "delivered"
    db.flush()
    return eng


def _add_finding(db: Session, eng_id: str, scan_id_suffix: str = "x") -> Any:
    scan = create_scan_result(
        db,
        tenant_id=_TENANT,
        engagement_id=eng_id,
        source_type="microsoft_graph",
        schema_version="1.0",
        collected_at=utc_iso8601_z_now(),
        raw_payload={"users": []},
        normalized_payload=None,
        object_count=0,
        evidence_hash=f"hash-promo-{scan_id_suffix}",
    )
    findings = normalize_scan_findings(
        db,
        tenant_id=_TENANT,
        engagement_id=eng_id,
        scan_result=scan,
        normalized_payload={
            "findings": [
                {
                    "finding_type": "ai_governance",
                    "title": "Missing AI policy",
                    "severity": "high",
                    "description": "No policy found.",
                }
            ]
        },
    )
    return findings[0]


def _add_candidate(
    db: Session, eng_id: str, scan_result_id: str, suffix: str = "a"
) -> GaAssetCandidate:
    now = utc_iso8601_z_now()
    c = GaAssetCandidate(
        candidate_id=f"cand-{suffix}",
        tenant_id=_TENANT,
        engagement_id=eng_id,
        scan_result_id=scan_result_id,
        source_type="microsoft_graph",
        candidate_type="ai_application",
        risk_signal=f"risk-signal-{suffix}",
        suggested_name=f"App {suffix}",
        suggested_asset_type="ai_application",
        confidence=90,
        peak_confidence=90,
        status="detected",
        last_manifest_hash=f"mhash-{suffix}",
        evidence_ref_ids=[],
        detection_count=1,
        first_detected_at=now,
        last_detected_at=now,
        created_at=now,
        updated_at=now,
    )
    db.add(c)
    db.flush()
    return c


def _add_document(db: Session, eng_id: str, suffix: str = "a") -> Any:
    return create_document_analysis(
        db,
        tenant_id=_TENANT,
        engagement_id=eng_id,
        document_name=f"AI Policy {suffix}",
        document_classification="ai_policy",
        document_hash=None,
        version_label=None,
        approved_by=None,
        approval_date=None,
        freshness_date=None,
        analysis_findings=[],
        gaps_identified=[],
    )


def _add_observation(db: Session, eng_id: str, suffix: str = "a") -> Any:
    return create_observation(
        db,
        tenant_id=_TENANT,
        engagement_id=eng_id,
        domain="ai_governance",
        observation_type="gap",
        severity="medium",
        title=f"AI governance gap {suffix}",
        description=f"Policy review revealed gap {suffix}.",
        interview_role=None,
        structured_evidence={},
        linked_finding_ids=[],
        assessor_id="assessor-promo",
    )


class TestPromotionServiceDirect:
    def test_creates_workflow_per_finding(self, db: Session) -> None:
        eng = _make_delivered_engagement(db, "b")
        _add_finding(db, eng.id, "b1")

        promote_engagement_to_governance(
            db,
            tenant_id=_TENANT,
            engagement_id=eng.id,
            gate_snapshot=_GATE_SNAPSHOT,
            baseline_readiness_score=82,
        )

        workflows = (
            db.query(GovernanceWorkflow)
            .filter_by(tenant_id=_TENANT, engagement_id=eng.id)
            .all()
        )
        assert len(workflows) == 1

    def test_workflow_has_finding_id_set(self, db: Session) -> None:
        eng = _make_delivered_engagement(db, "c")
        finding = _add_finding(db, eng.id, "c1")

        promote_engagement_to_governance(
            db,
            tenant_id=_TENANT,
            engagement_id=eng.id,
            gate_snapshot=_GATE_SNAPSHOT,
            baseline_readiness_score=82,
        )

        wf = (
            db.query(GovernanceWorkflow)
            .filter_by(tenant_id=_TENANT, engagement_id=eng.id)
            .first()
        )
        assert wf is not None
        assert wf.finding_id == finding.id

    def test_promotion_record_status_completed(self, db: Session) -> None:
        eng = _make_delivered_engagement(db, "d")
        promote_engagement_to_governance(
            db,
            tenant_id=_TENANT,
            engagement_id=eng.id,
            gate_snapshot=_GATE_SNAPSHOT,
            baseline_readiness_score=82,
        )
        promo = get_promotion(db, tenant_id=_TENANT, engagement_id=eng.id)
        assert promo is not None
        assert promo.status == "completed"

    def test_baseline_readiness_score_stored(self, db: Session) -> None:
        eng = _make_delivered_engagement(db, "e")
        promote_engagement_to_governance(
            db,
            tenant_id=_TENANT,
            engagement_id=eng.id,
            gate_snapshot=_GATE_SNAPSHOT,
            baseline_readiness_score=82,
        )
        promo = get_promotion(db, tenant_id=_TENANT, engagement_id=eng.id)
        assert promo is not None
        assert promo.baseline_readiness_score == 82

    def test_workflow_count_matches_findings(self, db: Session) -> None:
        eng = _make_delivered_engagement(db, "f")
        _add_finding(db, eng.id, "f1")
        _add_finding(db, eng.id, "f2")

        promo = promote_engagement_to_governance(
            db,
            tenant_id=_TENANT,
            engagement_id=eng.id,
            gate_snapshot=_GATE_SNAPSHOT,
            baseline_readiness_score=75,
        )
        assert promo.workflow_count == 2

    def test_asset_candidate_promoted_to_governance_asset(self, db: Session) -> None:
        eng = _make_delivered_engagement(db, "g")
        scan = create_scan_result(
            db,
            tenant_id=_TENANT,
            engagement_id=eng.id,
            source_type="microsoft_graph",
            schema_version="1.0",
            collected_at=utc_iso8601_z_now(),
            raw_payload={},
            normalized_payload=None,
            object_count=0,
            evidence_hash="hash-g1",
        )
        _add_candidate(db, eng.id, scan.id, "g1")

        promo = promote_engagement_to_governance(
            db,
            tenant_id=_TENANT,
            engagement_id=eng.id,
            gate_snapshot=_GATE_SNAPSHOT,
            baseline_readiness_score=80,
        )

        assert promo.asset_count == 1
        asset = (
            db.query(GaAsset).filter_by(tenant_id=_TENANT, asset_id="cand-g1").first()
        )
        assert asset is not None
        assert asset.source_engagement_id == eng.id
        assert asset.source_scan_result_id == scan.id

    def test_asset_candidate_marked_promoted(self, db: Session) -> None:
        eng = _make_delivered_engagement(db, "h")
        scan = create_scan_result(
            db,
            tenant_id=_TENANT,
            engagement_id=eng.id,
            source_type="microsoft_graph",
            schema_version="1.0",
            collected_at=utc_iso8601_z_now(),
            raw_payload={},
            normalized_payload=None,
            object_count=0,
            evidence_hash="hash-h1",
        )
        candidate = _add_candidate(db, eng.id, scan.id, "h1")

        promote_engagement_to_governance(
            db,
            tenant_id=_TENANT,
            engagement_id=eng.id,
            gate_snapshot=_GATE_SNAPSHOT,
            baseline_readiness_score=80,
        )

        db.refresh(candidate)
        assert candidate.status == "promoted"
        assert candidate.auto_promoted is True
        assert candidate.promoted_asset_id == candidate.candidate_id

    def test_idempotent_second_call_returns_same_record(self, db: Session) -> None:
        eng = _make_delivered_engagement(db, "i")
        _add_finding(db, eng.id, "i1")

        p1 = promote_engagement_to_governance(
            db,
            tenant_id=_TENANT,
            engagement_id=eng.id,
            gate_snapshot=_GATE_SNAPSHOT,
            baseline_readiness_score=82,
        )
        p2 = promote_engagement_to_governance(
            db,
            tenant_id=_TENANT,
            engagement_id=eng.id,
            gate_snapshot=_GATE_SNAPSHOT,
            baseline_readiness_score=82,
        )
        assert p1.id == p2.id
        # No duplicate workflows
        workflows = (
            db.query(GovernanceWorkflow)
            .filter_by(tenant_id=_TENANT, engagement_id=eng.id)
            .all()
        )
        assert len(workflows) == 1

    def test_failed_promotion_retried_on_second_call(self, db: Session) -> None:
        eng = _make_delivered_engagement(db, "j")
        _add_finding(db, eng.id, "j1")

        promo = promote_engagement_to_governance(
            db,
            tenant_id=_TENANT,
            engagement_id=eng.id,
            gate_snapshot=_GATE_SNAPSHOT,
            baseline_readiness_score=82,
        )
        # Simulate a failure
        fail_promotion(db, promotion=promo, error_detail="simulated failure")

        promo2 = promote_engagement_to_governance(
            db,
            tenant_id=_TENANT,
            engagement_id=eng.id,
            gate_snapshot=_GATE_SNAPSHOT,
            baseline_readiness_score=82,
        )
        assert promo2.id == promo.id
        assert promo2.status == "completed"
        assert promo2.error_detail is None


def _make_admin_client(app, tenant_id: str):
    """Mint a key with tenant_admin role (has governance.promote) for the promote route."""
    from sqlalchemy import text as sa_text
    from api.auth_scopes import mint_key
    from api.db import get_sessionmaker
    from api.tenant_rbac import assign_role
    from fastapi.testclient import TestClient

    key = mint_key("governance:read", "governance:write", tenant_id=tenant_id)
    SM = get_sessionmaker()
    db = SM()
    try:
        key_id = db.execute(
            sa_text(
                "SELECT id FROM api_keys WHERE tenant_id = :t ORDER BY id DESC LIMIT 1"
            ),
            {"t": tenant_id},
        ).scalar_one()
        assign_role(
            db,
            tenant_id=tenant_id,
            actor_key_prefix="pytest",
            target_key_id=int(key_id),
            role_name="tenant_admin",
        )
    finally:
        db.close()
    return TestClient(app, headers={"X-API-Key": key})


class TestPromotionAdminRoute:
    def test_promote_route_returns_409_for_non_delivered(self, build_app) -> None:
        from api.auth_scopes import mint_key
        from fastapi.testclient import TestClient

        app = build_app(auth_enabled=True)
        # Assessor key creates the engagement; admin key (tenant_admin) calls promote.
        assessor_key = mint_key(
            "governance:read", "governance:write", tenant_id=_TENANT
        )
        assessor = TestClient(app, headers={"X-API-Key": assessor_key})
        admin = _make_admin_client(app, _TENANT)

        eng = assessor.post(
            "/field-assessment/engagements",
            json={
                "client_name": "Retry Corp",
                "assessor_id": "assessor-retry",
                "assessment_type": "ai_governance",
            },
        )
        assert eng.status_code == 201
        eng_id = eng.json()["id"]

        resp = admin.post(f"/field-assessment/engagements/{eng_id}/promote")
        assert resp.status_code == 409
        assert resp.json()["detail"]["code"] == "ENGAGEMENT_NOT_DELIVERED"

    def test_promote_route_returns_404_for_unknown_engagement(self, build_app) -> None:
        app = build_app(auth_enabled=True)
        admin = _make_admin_client(app, _TENANT)

        resp = admin.post("/field-assessment/engagements/ghost-eng/promote")
        assert resp.status_code == 404


_TENANT2 = "tenant-promotion-test-other"


class TestPromotionRaceAndIntegrity:
    def test_create_race_returns_existing_pending_promotion(self, db: Session) -> None:
        eng = _make_delivered_engagement(db, "race-p")
        existing = create_promotion(
            db,
            tenant_id=_TENANT,
            engagement_id=eng.id,
            gate_snapshot=_GATE_SNAPSHOT,
            baseline_readiness_score=82,
        )
        assert existing.status == "pending"

        with patch(
            "services.field_assessment.promotion.create_promotion",
            side_effect=PromotionAlreadyExists("race"),
        ):
            result = promote_engagement_to_governance(
                db,
                tenant_id=_TENANT,
                engagement_id=eng.id,
                gate_snapshot=_GATE_SNAPSHOT,
                baseline_readiness_score=82,
            )

        assert result.id == existing.id
        assert result.status == "pending"

    def test_create_race_returns_existing_completed_promotion(
        self, db: Session
    ) -> None:
        eng = _make_delivered_engagement(db, "race-c")

        p1 = promote_engagement_to_governance(
            db,
            tenant_id=_TENANT,
            engagement_id=eng.id,
            gate_snapshot=_GATE_SNAPSHOT,
            baseline_readiness_score=82,
        )
        assert p1.status == "completed"

        with patch(
            "services.field_assessment.promotion.create_promotion",
            side_effect=PromotionAlreadyExists("race"),
        ):
            result = promote_engagement_to_governance(
                db,
                tenant_id=_TENANT,
                engagement_id=eng.id,
                gate_snapshot=_GATE_SNAPSHOT,
                baseline_readiness_score=82,
            )

        assert result.id == p1.id
        assert result.status == "completed"

    def test_duplicate_asset_insert_is_skipped_idempotently(self, db: Session) -> None:
        eng = _make_delivered_engagement(db, "dup-asset")
        scan = create_scan_result(
            db,
            tenant_id=_TENANT,
            engagement_id=eng.id,
            source_type="microsoft_graph",
            schema_version="1.0",
            collected_at=utc_iso8601_z_now(),
            raw_payload={},
            normalized_payload=None,
            object_count=0,
            evidence_hash="hash-dup-asset",
        )
        _add_candidate(db, eng.id, scan.id, "dup-a1")

        # First promotion succeeds
        p1 = promote_engagement_to_governance(
            db,
            tenant_id=_TENANT,
            engagement_id=eng.id,
            gate_snapshot=_GATE_SNAPSHOT,
            baseline_readiness_score=80,
        )
        assert p1.status == "completed"
        assert p1.asset_count == 1

        # Reset to failed so retry logic re-runs asset promotion
        fail_promotion(db, promotion=p1, error_detail="forced retry")

        # Add a second candidate; the first asset already exists in GaAsset
        _add_candidate(db, eng.id, scan.id, "dup-a2")
        # Un-promote the first candidate so it gets selected again
        from sqlalchemy import update as sa_update
        from api.db_models_governance_asset_candidates import GaAssetCandidate as _C

        db.execute(
            sa_update(_C)
            .where(_C.candidate_id == "cand-dup-a1")
            .values(
                status="detected",
                promoted_asset_id=None,
                promoted_at=None,
                auto_promoted=False,
            )
        )
        db.flush()

        p2 = promote_engagement_to_governance(
            db,
            tenant_id=_TENANT,
            engagement_id=eng.id,
            gate_snapshot=_GATE_SNAPSHOT,
            baseline_readiness_score=80,
        )
        # Promotion completes: dup-a1 duplicate is skipped, dup-a2 is new
        assert p2.status == "completed"
        assert p2.asset_count == 1  # only the new candidate counted

    def test_non_duplicate_asset_insert_failure_fails_promotion(
        self, db: Session
    ) -> None:
        eng = _make_delivered_engagement(db, "non-dup-fail")
        scan = create_scan_result(
            db,
            tenant_id=_TENANT,
            engagement_id=eng.id,
            source_type="microsoft_graph",
            schema_version="1.0",
            collected_at=utc_iso8601_z_now(),
            raw_payload={},
            normalized_payload=None,
            object_count=0,
            evidence_hash="hash-non-dup",
        )
        _add_candidate(db, eng.id, scan.id, "nd-a1")

        original_begin_nested = db.begin_nested

        call_count = [0]

        def patched_begin_nested():
            call_count[0] += 1
            ctx = original_begin_nested()
            if call_count[0] == 2:
                # Simulate non-duplicate failure on the first asset insert savepoint
                class _FailCtx:
                    def __enter__(self):
                        return ctx.__enter__()

                    def __exit__(self, exc_type, exc_val, exc_tb):
                        ctx.__exit__(exc_type, exc_val, exc_tb)
                        if exc_type is None:
                            raise RuntimeError("simulated non-integrity DB failure")
                        return False

                return _FailCtx()
            return ctx

        with patch.object(db, "begin_nested", patched_begin_nested):
            promo = promote_engagement_to_governance(
                db,
                tenant_id=_TENANT,
                engagement_id=eng.id,
                gate_snapshot=_GATE_SNAPSHOT,
                baseline_readiness_score=80,
            )

        # Failure is caught by the outer handler and recorded
        assert promo.status == "failed"

    def test_tenant_isolation_create_race(self, db: Session) -> None:
        eng_t1 = _make_delivered_engagement(db, "iso-t1")
        eng_t2 = _make_delivered_engagement(db, "iso-t2")

        p1 = promote_engagement_to_governance(
            db,
            tenant_id=_TENANT,
            engagement_id=eng_t1.id,
            gate_snapshot=_GATE_SNAPSHOT,
            baseline_readiness_score=82,
        )

        p2 = promote_engagement_to_governance(
            db,
            tenant_id=_TENANT,
            engagement_id=eng_t2.id,
            gate_snapshot=_GATE_SNAPSHOT,
            baseline_readiness_score=75,
        )

        assert p1.id != p2.id
        assert p1.tenant_id == _TENANT
        assert p2.tenant_id == _TENANT
        assert p1.engagement_id == eng_t1.id
        assert p2.engagement_id == eng_t2.id


class TestEvidenceContinuity:
    def test_corpus_entries_added_reflects_finding_count(self, db: Session) -> None:
        eng = _make_delivered_engagement(db, "corp-1")
        _add_finding(db, eng.id, "corp-1a")
        _add_finding(db, eng.id, "corp-1b")

        promo = promote_engagement_to_governance(
            db,
            tenant_id=_TENANT,
            engagement_id=eng.id,
            gate_snapshot=_GATE_SNAPSHOT,
            baseline_readiness_score=82,
        )

        db.refresh(promo)
        assert promo.status == "completed"
        assert promo.corpus_entries_added == 2

    def test_corpus_entries_zero_when_no_findings(self, db: Session) -> None:
        eng = _make_delivered_engagement(db, "corp-2")

        promo = promote_engagement_to_governance(
            db,
            tenant_id=_TENANT,
            engagement_id=eng.id,
            gate_snapshot=_GATE_SNAPSHOT,
            baseline_readiness_score=82,
        )

        db.refresh(promo)
        assert promo.status == "completed"
        assert promo.corpus_entries_added == 0

    def test_promotion_timeline_event_emitted(self, db: Session) -> None:
        from api.db_models_timeline import TimelineEventRecord as TimelineEvent

        eng = _make_delivered_engagement(db, "corp-3")
        _add_finding(db, eng.id, "corp-3a")

        promote_engagement_to_governance(
            db,
            tenant_id=_TENANT,
            engagement_id=eng.id,
            gate_snapshot=_GATE_SNAPSHOT,
            baseline_readiness_score=80,
        )

        event = (
            db.query(TimelineEvent)
            .filter_by(
                tenant_id=_TENANT,
                source_id=eng.id,
                event_type="field_assessment.engagement.promoted",
            )
            .first()
        )
        assert event is not None
        assert event.payload["workflow_count"] == 1
        assert event.payload["baseline_readiness_score"] == 80

    def test_corpus_feed_failure_does_not_affect_promotion_status(
        self, db: Session
    ) -> None:
        eng = _make_delivered_engagement(db, "corp-4")
        _add_finding(db, eng.id, "corp-4a")

        with patch(
            "services.field_assessment.promotion.ingest_corpus",
            side_effect=RuntimeError("simulated corpus failure"),
        ):
            promo = promote_engagement_to_governance(
                db,
                tenant_id=_TENANT,
                engagement_id=eng.id,
                gate_snapshot=_GATE_SNAPSHOT,
                baseline_readiness_score=82,
            )

        assert promo.status == "completed"
        db.refresh(promo)
        assert promo.corpus_entries_added == 0

    def test_timeline_event_failure_does_not_affect_promotion_status(
        self, db: Session
    ) -> None:
        eng = _make_delivered_engagement(db, "corp-5")

        with patch(
            "services.field_assessment.promotion.emit_fa_timeline_event",
            side_effect=RuntimeError("simulated timeline failure"),
        ):
            promo = promote_engagement_to_governance(
                db,
                tenant_id=_TENANT,
                engagement_id=eng.id,
                gate_snapshot=_GATE_SNAPSHOT,
                baseline_readiness_score=82,
            )

        assert promo.status == "completed"

    def test_corpus_feed_paginates_beyond_max_findings(self, db: Session) -> None:
        eng = _make_delivered_engagement(db, "corp-pag")
        for i in range(5):
            _add_finding(db, eng.id, f"corp-pag-{i}")

        with patch("services.field_assessment.promotion._MAX_FINDINGS", 3):
            promo = promote_engagement_to_governance(
                db,
                tenant_id=_TENANT,
                engagement_id=eng.id,
                gate_snapshot=_GATE_SNAPSHOT,
                baseline_readiness_score=82,
            )

        db.refresh(promo)
        assert promo.status == "completed"
        assert promo.corpus_entries_added == 5

    def test_corpus_feed_retry_does_not_duplicate(self, db: Session) -> None:
        eng = _make_delivered_engagement(db, "corp-retry")
        _add_finding(db, eng.id, "corp-retry-1")
        _add_finding(db, eng.id, "corp-retry-2")

        p1 = promote_engagement_to_governance(
            db,
            tenant_id=_TENANT,
            engagement_id=eng.id,
            gate_snapshot=_GATE_SNAPSHOT,
            baseline_readiness_score=82,
        )
        db.refresh(p1)
        assert p1.corpus_entries_added == 2

        fail_promotion(db, promotion=p1, error_detail="forced")

        p2 = promote_engagement_to_governance(
            db,
            tenant_id=_TENANT,
            engagement_id=eng.id,
            gate_snapshot=_GATE_SNAPSHOT,
            baseline_readiness_score=82,
        )
        db.refresh(p2)
        assert p2.id == p1.id
        assert p2.status == "completed"
        assert p2.corpus_entries_added == 2

    def test_corpus_feed_ordering_is_stable(self, db: Session) -> None:
        from api.db_models_field_assessment import FaNormalizedFinding
        from sqlalchemy import select as sa_select

        eng = _make_delivered_engagement(db, "corp-ord")
        for i in range(4):
            _add_finding(db, eng.id, f"corp-ord-{i}")

        # Determine the expected stable order (created_at ASC, id ASC)
        rows = (
            db.execute(
                sa_select(FaNormalizedFinding)
                .where(
                    FaNormalizedFinding.engagement_id == eng.id,
                    FaNormalizedFinding.tenant_id == _TENANT,
                )
                .order_by(
                    FaNormalizedFinding.created_at.asc(), FaNormalizedFinding.id.asc()
                )
            )
            .scalars()
            .all()
        )
        expected_ids = [f"fa:{eng.id}:finding:{f.id}" for f in rows]

        seen_ids: list[str] = []
        original_ingest = __import__(
            "api.rag.ingest", fromlist=["ingest_corpus"]
        ).ingest_corpus

        def _capture_ingest(request, *, trusted_tenant_id):
            for doc in request.documents:
                seen_ids.append(doc.source_id)
            return original_ingest(request, trusted_tenant_id=trusted_tenant_id)

        with patch(
            "services.field_assessment.promotion.ingest_corpus",
            side_effect=_capture_ingest,
        ):
            promote_engagement_to_governance(
                db,
                tenant_id=_TENANT,
                engagement_id=eng.id,
                gate_snapshot=_GATE_SNAPSHOT,
                baseline_readiness_score=82,
            )

        assert seen_ids == expected_ids
        assert len(seen_ids) == 4

    def test_corpus_feed_excludes_other_tenant_findings(self, db: Session) -> None:
        _TENANT_OTHER = "tenant-other-corp"
        eng_a = _make_delivered_engagement(db, "corp-iso-a")

        _add_finding(db, eng_a.id, "corp-iso-a1")

        from api.db_models_field_assessment import FaNormalizedFinding

        other_scan = create_scan_result(
            db,
            tenant_id=_TENANT_OTHER,
            engagement_id="eng-other-xyz",
            source_type="microsoft_graph",
            schema_version="1.0",
            collected_at=utc_iso8601_z_now(),
            raw_payload={},
            normalized_payload=None,
            object_count=0,
            evidence_hash="hash-iso-other",
        )
        other_finding = FaNormalizedFinding(
            id="other-finding-id",
            tenant_id=_TENANT_OTHER,
            engagement_id=eng_a.id,
            finding_type="ai_governance",
            findings_hash="hash-other-xyz",
            severity="low",
            status="open",
            title="Cross-tenant finding",
            description="Should not appear in tenant-a corpus.",
            source_attribution=other_scan.id,
            confidence_score=80,
            framework_mappings=[],
            nist_ai_rmf_mappings=[],
            evidence_ref_ids=[],
            schema_version="1.0",
            created_at=utc_iso8601_z_now(),
            updated_at=utc_iso8601_z_now(),
        )
        db.add(other_finding)
        db.flush()

        ingested_source_ids: list[str] = []
        original_ingest = __import__(
            "api.rag.ingest", fromlist=["ingest_corpus"]
        ).ingest_corpus

        def _capture(request, *, trusted_tenant_id):
            ingested_source_ids.extend(d.source_id for d in request.documents)
            return original_ingest(request, trusted_tenant_id=trusted_tenant_id)

        with patch(
            "services.field_assessment.promotion.ingest_corpus", side_effect=_capture
        ):
            promote_engagement_to_governance(
                db,
                tenant_id=_TENANT,
                engagement_id=eng_a.id,
                gate_snapshot=_GATE_SNAPSHOT,
                baseline_readiness_score=82,
            )

        assert all(_TENANT_OTHER not in sid for sid in ingested_source_ids)
        assert len(ingested_source_ids) == 1


class TestCorpusFeedPI12:
    """PI12 — corpus feed covers findings, document analyses, and observations."""

    def _promote(self, db: Session, eng_id: str) -> list[str]:
        ingested: list[str] = []
        original_ingest = __import__(
            "api.rag.ingest", fromlist=["ingest_corpus"]
        ).ingest_corpus

        def _capture(request, *, trusted_tenant_id):
            ingested.extend(d.source_id for d in request.documents)
            return original_ingest(request, trusted_tenant_id=trusted_tenant_id)

        with patch(
            "services.field_assessment.promotion.ingest_corpus", side_effect=_capture
        ):
            promote_engagement_to_governance(
                db,
                tenant_id=_TENANT,
                engagement_id=eng_id,
                gate_snapshot=_GATE_SNAPSHOT,
                baseline_readiness_score=75,
            )
        return ingested

    def test_corpus_includes_findings(self, db: Session) -> None:
        eng = _make_delivered_engagement(db, "pi12-f")
        _add_finding(db, eng.id, "pi12-f1")

        source_ids = self._promote(db, eng.id)

        finding_ids = [s for s in source_ids if ":finding:" in s]
        assert len(finding_ids) == 1
        assert finding_ids[0].startswith(f"fa:{eng.id}:finding:")

    def test_corpus_includes_document_analyses(self, db: Session) -> None:
        eng = _make_delivered_engagement(db, "pi12-d")
        doc = _add_document(db, eng.id, "pi12-d1")

        source_ids = self._promote(db, eng.id)

        doc_ids = [s for s in source_ids if ":document:" in s]
        assert len(doc_ids) == 1
        assert doc_ids[0] == f"fa:{eng.id}:document:{doc.id}"

    def test_corpus_includes_observations(self, db: Session) -> None:
        eng = _make_delivered_engagement(db, "pi12-o")
        obs = _add_observation(db, eng.id, "pi12-o1")

        source_ids = self._promote(db, eng.id)

        obs_ids = [s for s in source_ids if ":observation:" in s]
        assert len(obs_ids) == 1
        assert obs_ids[0] == f"fa:{eng.id}:observation:{obs.id}"

    def test_corpus_count_reflects_all_entity_types(self, db: Session) -> None:
        eng = _make_delivered_engagement(db, "pi12-all")
        _add_finding(db, eng.id, "pi12-all-f")
        _add_document(db, eng.id, "pi12-all-d")
        _add_observation(db, eng.id, "pi12-all-o")

        source_ids = self._promote(db, eng.id)

        assert any(":finding:" in s for s in source_ids)
        assert any(":document:" in s for s in source_ids)
        assert any(":observation:" in s for s in source_ids)
        assert len(source_ids) == 3

    def test_corpus_excludes_soft_deleted_observations(self, db: Session) -> None:
        eng = _make_delivered_engagement(db, "pi12-del")
        live_obs = _add_observation(db, eng.id, "pi12-del-live")
        deleted_obs = _add_observation(db, eng.id, "pi12-del-gone")
        deleted_obs.deleted_at = utc_iso8601_z_now()
        db.flush()

        source_ids = self._promote(db, eng.id)

        obs_ids = [s for s in source_ids if ":observation:" in s]
        assert len(obs_ids) == 1
        assert obs_ids[0] == f"fa:{eng.id}:observation:{live_obs.id}"

    def test_corpus_promoted_count_stored_on_promotion_record(
        self, db: Session
    ) -> None:
        eng = _make_delivered_engagement(db, "pi12-cnt")
        _add_finding(db, eng.id, "pi12-cnt-f")
        _add_document(db, eng.id, "pi12-cnt-d")
        _add_observation(db, eng.id, "pi12-cnt-o")

        self._promote(db, eng.id)

        promo = get_promotion(db, tenant_id=_TENANT, engagement_id=eng.id)
        assert promo is not None
        assert promo.corpus_entries_added == 3
