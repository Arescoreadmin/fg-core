"""Tests for candidate promotion engine."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

from api.db_models import Base
import api.db_models_governance_asset_candidates  # noqa: F401
import api.db_models_governance_assets  # noqa: F401
import api.db_models_field_assessment  # noqa: F401

from api.db_models_governance_asset_candidates import AUTO_PROMOTE_CONFIDENCE_THRESHOLD
from services.governance_asset_registry.candidates import (
    mark_promoted,
    upsert_candidate,
)
from services.governance_asset_registry.promotion import (
    auto_promote_if_eligible,
    compute_open_findings_weight,
    link_findings_to_asset,
    promote_candidate_to_asset,
)


@pytest.fixture()
def engine():
    import api.signed_artifacts  # noqa: F401 — must be imported before create_all

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


_TENANT = "tenant-promo-test"
_ACTOR = "test@example.com"


def _make_candidate(
    db: Session, *, risk_signal: str = "shadow_ai", confidence: int = 90
):
    candidate, _ = upsert_candidate(
        db,
        tenant_id=_TENANT,
        source_type="microsoft_graph",
        candidate_type="ai_application",
        risk_signal=risk_signal,
        suggested_name="Shadow AI App",
        suggested_asset_type="ai_application",
        confidence=confidence,
        manifest_hash="a" * 64,
        evidence_ref_ids=[],
    )
    return candidate


class TestPromoteCandidateToAsset:
    def test_creates_ga_asset(self, db: Session) -> None:
        candidate = _make_candidate(db)
        asset = promote_candidate_to_asset(db, candidate=candidate, actor_email=_ACTOR)
        assert asset is not None
        assert asset.tenant_id == _TENANT

    def test_candidate_status_becomes_promoted(self, db: Session) -> None:
        candidate = _make_candidate(db)
        asset = promote_candidate_to_asset(db, candidate=candidate, actor_email=_ACTOR)
        db.refresh(candidate)
        assert candidate.status == "promoted"
        assert candidate.promoted_asset_id == asset.asset_id

    def test_idempotent_same_signal(self, db: Session) -> None:
        candidate = _make_candidate(db)
        asset1 = promote_candidate_to_asset(db, candidate=candidate, actor_email=_ACTOR)

        candidate2 = _make_candidate(db, risk_signal="shadow_ai")
        asset2 = promote_candidate_to_asset(
            db, candidate=candidate2, actor_email=_ACTOR
        )

        assert asset1.asset_id == asset2.asset_id

    def test_already_promoted_returns_existing_asset(self, db: Session) -> None:
        candidate = _make_candidate(db)
        asset1 = promote_candidate_to_asset(db, candidate=candidate, actor_email=_ACTOR)
        db.refresh(candidate)

        asset2 = promote_candidate_to_asset(db, candidate=candidate, actor_email=_ACTOR)
        assert asset1.asset_id == asset2.asset_id

    def test_auto_promoted_flag_set(self, db: Session) -> None:
        candidate = _make_candidate(db)
        promote_candidate_to_asset(
            db, candidate=candidate, actor_email=_ACTOR, auto_promoted=True
        )
        db.refresh(candidate)
        assert candidate.auto_promoted is True

    def test_different_signals_create_different_assets(self, db: Session) -> None:
        c1 = _make_candidate(db, risk_signal="shadow_ai")
        c2 = _make_candidate(db, risk_signal="critical_risky_scopes")
        a1 = promote_candidate_to_asset(db, candidate=c1, actor_email=_ACTOR)
        a2 = promote_candidate_to_asset(db, candidate=c2, actor_email=_ACTOR)
        assert a1.asset_id != a2.asset_id


class TestAutoPromoteIfEligible:
    def test_high_confidence_triggers_promotion(self, db: Session) -> None:
        candidate = _make_candidate(db, confidence=AUTO_PROMOTE_CONFIDENCE_THRESHOLD)
        asset = auto_promote_if_eligible(db, candidate=candidate)
        assert asset is not None
        db.refresh(candidate)
        assert candidate.status == "promoted"
        assert candidate.auto_promoted is True

    def test_low_confidence_does_not_promote(self, db: Session) -> None:
        candidate = _make_candidate(
            db, confidence=AUTO_PROMOTE_CONFIDENCE_THRESHOLD - 1
        )
        result = auto_promote_if_eligible(db, candidate=candidate)
        assert result is None
        assert candidate.status == "detected"

    def test_already_promoted_is_noop(self, db: Session) -> None:
        candidate = _make_candidate(db, confidence=99)
        mark_promoted(
            db,
            tenant_id=_TENANT,
            candidate_id=candidate.candidate_id,
            promoted_asset_id="existing-asset",
        )
        db.refresh(candidate)
        result = auto_promote_if_eligible(db, candidate=candidate)
        assert result is None


class TestLinkFindingsToAsset:
    def test_links_open_findings(self, db: Session) -> None:
        from api.db_models_field_assessment import FaNormalizedFinding
        from services.canonical import utc_iso8601_z_now

        now = utc_iso8601_z_now()
        finding = FaNormalizedFinding(
            id="finding-001",
            tenant_id=_TENANT,
            engagement_id="eng-001",
            finding_type="ai_governance",
            findings_hash="h" * 64,
            severity="high",
            status="open",
            title="Test Finding",
            description="A test finding",
            source_attribution="microsoft_graph",
            confidence_score=80,
            framework_mappings=[],
            nist_ai_rmf_mappings=[],
            evidence_ref_ids=[],
            schema_version="1.0",
            created_at=now,
            updated_at=now,
        )
        db.add(finding)
        db.flush()

        count = link_findings_to_asset(
            db,
            tenant_id=_TENANT,
            asset_id="asset-abc",
            engagement_id="eng-001",
            source_attribution="microsoft_graph",
        )
        assert count == 1
        db.refresh(finding)
        assert finding.asset_id == "asset-abc"

    def test_does_not_link_closed_findings(self, db: Session) -> None:
        from api.db_models_field_assessment import FaNormalizedFinding
        from services.canonical import utc_iso8601_z_now

        now = utc_iso8601_z_now()
        finding = FaNormalizedFinding(
            id="finding-002",
            tenant_id=_TENANT,
            engagement_id="eng-002",
            finding_type="ai_governance",
            findings_hash="x" * 64,
            severity="high",
            status="closed",
            title="Closed Finding",
            description="Already remediated",
            source_attribution="microsoft_graph",
            confidence_score=80,
            framework_mappings=[],
            nist_ai_rmf_mappings=[],
            evidence_ref_ids=[],
            schema_version="1.0",
            created_at=now,
            updated_at=now,
        )
        db.add(finding)
        db.flush()

        count = link_findings_to_asset(
            db,
            tenant_id=_TENANT,
            asset_id="asset-abc",
            engagement_id="eng-002",
            source_attribution="microsoft_graph",
        )
        assert count == 0


class TestComputeOpenFindingsWeight:
    def test_zero_when_no_linked_findings(self, db: Session) -> None:
        weight = compute_open_findings_weight(
            db, tenant_id=_TENANT, asset_id="nonexistent"
        )
        assert weight == 0

    def test_critical_contributes_30(self, db: Session) -> None:
        from api.db_models_field_assessment import FaNormalizedFinding
        from services.canonical import utc_iso8601_z_now

        now = utc_iso8601_z_now()
        finding = FaNormalizedFinding(
            id="wf-crit-001",
            tenant_id=_TENANT,
            engagement_id="eng-w",
            finding_type="ai_governance",
            findings_hash="c" * 64,
            severity="critical",
            status="open",
            title="Critical",
            description="crit",
            source_attribution="microsoft_graph",
            confidence_score=90,
            framework_mappings=[],
            nist_ai_rmf_mappings=[],
            evidence_ref_ids=[],
            asset_id="asset-weight-test",
            schema_version="1.0",
            created_at=now,
            updated_at=now,
        )
        db.add(finding)
        db.flush()

        weight = compute_open_findings_weight(
            db, tenant_id=_TENANT, asset_id="asset-weight-test"
        )
        assert weight == 30

    def test_weight_capped_at_150(self, db: Session) -> None:
        from api.db_models_field_assessment import FaNormalizedFinding
        from services.canonical import utc_iso8601_z_now

        now = utc_iso8601_z_now()
        for i in range(10):
            db.add(
                FaNormalizedFinding(
                    id=f"wf-cap-{i:03d}",
                    tenant_id=_TENANT,
                    engagement_id="eng-cap",
                    finding_type="ai_governance",
                    findings_hash=f"cap{i:062d}",
                    severity="critical",
                    status="open",
                    title=f"Critical {i}",
                    description="crit",
                    source_attribution="microsoft_graph",
                    confidence_score=90,
                    framework_mappings=[],
                    nist_ai_rmf_mappings=[],
                    evidence_ref_ids=[],
                    asset_id="asset-cap-test",
                    schema_version="1.0",
                    created_at=now,
                    updated_at=now,
                )
            )
        db.flush()

        weight = compute_open_findings_weight(
            db, tenant_id=_TENANT, asset_id="asset-cap-test"
        )
        assert weight == 150  # 10 * 30 = 300, capped at 150
