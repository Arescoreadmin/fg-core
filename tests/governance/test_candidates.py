"""Tests for governance asset candidate upsert and lifecycle."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from api.db_models import Base
import api.db_models_governance_asset_candidates  # noqa: F401 — registers model
import api.db_models_governance_assets  # noqa: F401 — registers GaAsset
import api.db_models_field_assessment  # noqa: F401 — registers FaNormalizedFinding

from api.db_models_governance_asset_candidates import (
    AUTO_PROMOTE_CONFIDENCE_THRESHOLD,
)
from services.governance_asset_registry.candidates import (
    _derive_candidate_id,
    candidate_to_dict,
    get_candidate,
    get_inbox,
    is_auto_promote_eligible,
    list_candidates,
    mark_promoted,
    mark_rejected,
    mark_under_review,
    upsert_candidate,
)


@pytest.fixture()
def engine():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def db(engine):
    with Session(engine) as session:
        yield session


_TENANT = "tenant-cand-test"


def _upsert(db, *, risk_signal="shadow_ai", confidence=90, **kw):
    return upsert_candidate(
        db,
        tenant_id=_TENANT,
        source_type="microsoft_graph",
        candidate_type="ai_application",
        risk_signal=risk_signal,
        suggested_name="Shadow AI App",
        suggested_asset_type="ai_application",
        confidence=confidence,
        manifest_hash="a" * 64,
        evidence_ref_ids=["ref-001"],
        **kw,
    )


class TestCandidateId:
    def test_deterministic(self) -> None:
        id1 = _derive_candidate_id("t1", "src", "type", "signal")
        id2 = _derive_candidate_id("t1", "src", "type", "signal")
        assert id1 == id2

    def test_different_signals_produce_different_ids(self) -> None:
        id1 = _derive_candidate_id("t1", "src", "type", "signal_a")
        id2 = _derive_candidate_id("t1", "src", "type", "signal_b")
        assert id1 != id2

    def test_different_tenants_produce_different_ids(self) -> None:
        id1 = _derive_candidate_id("tenant_a", "src", "type", "signal")
        id2 = _derive_candidate_id("tenant_b", "src", "type", "signal")
        assert id1 != id2


class TestUpsertCandidate:
    def test_insert_creates_row(self, db: Session) -> None:
        candidate, is_new = _upsert(db)
        assert is_new is True
        assert candidate.status == "detected"
        assert candidate.detection_count == 1
        assert candidate.confidence == 90
        assert candidate.peak_confidence == 90

    def test_same_signal_returns_existing(self, db: Session) -> None:
        c1, _ = _upsert(db, confidence=80)
        c2, is_new = _upsert(db, confidence=80)
        assert is_new is False
        assert c1.candidate_id == c2.candidate_id

    def test_rescan_increments_detection_count(self, db: Session) -> None:
        _upsert(db, confidence=80)
        candidate, _ = _upsert(db, confidence=82)
        assert candidate.detection_count == 2

    def test_rescan_updates_peak_confidence(self, db: Session) -> None:
        _upsert(db, confidence=80)
        candidate, _ = _upsert(db, confidence=95)
        assert candidate.peak_confidence == 95
        assert candidate.confidence == 95

    def test_peak_confidence_does_not_decrease(self, db: Session) -> None:
        _upsert(db, confidence=95)
        candidate, _ = _upsert(db, confidence=70)
        assert candidate.peak_confidence == 95
        assert candidate.confidence == 70

    def test_rescan_merges_evidence_refs(self, db: Session) -> None:
        upsert_candidate(
            db,
            tenant_id=_TENANT,
            source_type="microsoft_graph",
            candidate_type="ai_application",
            risk_signal="shadow_ai",
            suggested_name="Shadow AI",
            suggested_asset_type="ai_application",
            confidence=90,
            manifest_hash="a" * 64,
            evidence_ref_ids=["ref-001"],
        )
        candidate, _ = upsert_candidate(
            db,
            tenant_id=_TENANT,
            source_type="microsoft_graph",
            candidate_type="ai_application",
            risk_signal="shadow_ai",
            suggested_name="Shadow AI",
            suggested_asset_type="ai_application",
            confidence=90,
            manifest_hash="b" * 64,
            evidence_ref_ids=["ref-002"],
        )
        assert "ref-001" in candidate.evidence_ref_ids
        assert "ref-002" in candidate.evidence_ref_ids

    def test_different_signals_create_separate_rows(self, db: Session) -> None:
        c1, _ = _upsert(db, risk_signal="shadow_ai")
        c2, _ = _upsert(db, risk_signal="critical_risky_scopes")
        assert c1.candidate_id != c2.candidate_id


class TestCandidateQueries:
    def test_get_candidate_returns_row(self, db: Session) -> None:
        candidate, _ = _upsert(db)
        fetched = get_candidate(db, tenant_id=_TENANT, candidate_id=candidate.candidate_id)
        assert fetched is not None
        assert fetched.candidate_id == candidate.candidate_id

    def test_get_candidate_tenant_isolated(self, db: Session) -> None:
        candidate, _ = _upsert(db)
        fetched = get_candidate(
            db, tenant_id="other-tenant", candidate_id=candidate.candidate_id
        )
        assert fetched is None

    def test_list_candidates_filtered_by_status(self, db: Session) -> None:
        _upsert(db, risk_signal="shadow_ai")
        _upsert(db, risk_signal="unapproved_ai")
        rows = list_candidates(db, tenant_id=_TENANT, status="detected")
        assert len(rows) == 2

    def test_get_inbox_excludes_promoted(self, db: Session) -> None:
        candidate, _ = _upsert(db, risk_signal="shadow_ai")
        mark_promoted(
            db,
            tenant_id=_TENANT,
            candidate_id=candidate.candidate_id,
            promoted_asset_id="asset-999",
        )
        _upsert(db, risk_signal="unapproved_ai")
        inbox = get_inbox(db, tenant_id=_TENANT)
        assert all(r.status in ("detected", "under_review") for r in inbox)
        assert len(inbox) == 1


class TestCandidateLifecycle:
    def test_mark_under_review(self, db: Session) -> None:
        candidate, _ = _upsert(db)
        updated = mark_under_review(
            db,
            tenant_id=_TENANT,
            candidate_id=candidate.candidate_id,
            reviewed_by="alice@example.com",
        )
        assert updated is not None
        assert updated.status == "under_review"
        assert updated.reviewed_by == "alice@example.com"

    def test_mark_promoted(self, db: Session) -> None:
        candidate, _ = _upsert(db)
        mark_promoted(
            db,
            tenant_id=_TENANT,
            candidate_id=candidate.candidate_id,
            promoted_asset_id="asset-abc",
        )
        db.refresh(candidate)
        assert candidate.status == "promoted"
        assert candidate.promoted_asset_id == "asset-abc"
        assert candidate.promoted_at is not None

    def test_mark_rejected(self, db: Session) -> None:
        candidate, _ = _upsert(db)
        mark_rejected(
            db,
            tenant_id=_TENANT,
            candidate_id=candidate.candidate_id,
            reason="Not a real shadow AI app",
            reviewed_by="bob@example.com",
        )
        db.refresh(candidate)
        assert candidate.status == "rejected"
        assert candidate.rejected_reason == "Not a real shadow AI app"

    def test_cannot_reject_promoted_candidate(self, db: Session) -> None:
        candidate, _ = _upsert(db)
        mark_promoted(
            db,
            tenant_id=_TENANT,
            candidate_id=candidate.candidate_id,
            promoted_asset_id="asset-xyz",
        )
        result = mark_rejected(
            db,
            tenant_id=_TENANT,
            candidate_id=candidate.candidate_id,
            reason="too late",
            reviewed_by="alice@example.com",
        )
        # mark_rejected returns the candidate but does not change status if promoted
        assert result is not None
        assert result.status == "promoted"


class TestAutoPromoteEligibility:
    def test_high_confidence_is_eligible(self, db: Session) -> None:
        candidate, _ = _upsert(db, confidence=AUTO_PROMOTE_CONFIDENCE_THRESHOLD)
        assert is_auto_promote_eligible(candidate) is True

    def test_low_confidence_is_not_eligible(self, db: Session) -> None:
        candidate, _ = _upsert(db, confidence=AUTO_PROMOTE_CONFIDENCE_THRESHOLD - 1)
        assert is_auto_promote_eligible(candidate) is False

    def test_already_promoted_skips_even_if_confidence_high(self, db: Session) -> None:
        candidate, _ = _upsert(db, confidence=99)
        mark_promoted(
            db,
            tenant_id=_TENANT,
            candidate_id=candidate.candidate_id,
            promoted_asset_id="asset-already",
        )
        db.refresh(candidate)
        # Eligibility check is purely on confidence — callers gate on status
        assert is_auto_promote_eligible(candidate) is True


class TestCandidateToDict:
    def test_serializes_all_fields(self, db: Session) -> None:
        candidate, _ = _upsert(db)
        d = candidate_to_dict(candidate)
        assert d["candidate_id"] == candidate.candidate_id
        assert d["confidence"] == candidate.confidence
        assert d["status"] == "detected"
        assert isinstance(d["evidence_ref_ids"], list)
