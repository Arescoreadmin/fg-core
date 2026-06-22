"""Tests for drift velocity computation."""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from api.db_models import Base
import api.db_models_field_assessment  # noqa: F401
import api.db_models_drift  # noqa: F401

from api.db_models_field_assessment import (
    FaEvidenceLink,
    FaNormalizedFinding,
    FaScanResult,
)
from services.canonical import utc_iso8601_z_now
from services.connectors.drift.velocity import compute_drift_velocity

_TENANT = "tenant-velocity-test"
_ENGAGEMENT = "eng-vel-001"


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


def _make_scan(
    db: Session, scan_id: str, collected_at: str, finding_count: int = 0
) -> FaScanResult:
    row = FaScanResult(
        id=scan_id,
        tenant_id=_TENANT,
        engagement_id=_ENGAGEMENT,
        source_type="microsoft_graph",
        collected_at=collected_at,
        evidence_hash=scan_id + "-hash",
        raw_payload={},
        normalized_payload={},
        object_count=0,
        finding_count=finding_count,
        created_at=utc_iso8601_z_now(),
    )
    db.add(row)
    db.flush()
    return row


def _make_finding(db: Session, fid: str) -> FaNormalizedFinding:
    now = utc_iso8601_z_now()
    row = FaNormalizedFinding(
        id=fid,
        tenant_id=_TENANT,
        engagement_id=_ENGAGEMENT,
        finding_type="ai_governance",
        findings_hash=fid + "-hash",
        severity="high",
        status="open",
        title=f"Finding {fid}",
        description="test",
        source_attribution="microsoft_graph",
        confidence_score=80,
        framework_mappings=[],
        nist_ai_rmf_mappings=[],
        evidence_ref_ids=[],
        schema_version="1.0",
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    db.flush()
    return row


def _link(db: Session, finding_id: str, scan_id: str) -> None:
    row = FaEvidenceLink(
        id=f"link-{finding_id}-{scan_id}",
        tenant_id=_TENANT,
        engagement_id=_ENGAGEMENT,
        source_entity_type="finding",
        source_entity_id=finding_id,
        evidence_entity_type="scan_result",
        evidence_entity_id=scan_id,
        link_metadata={},
        created_at=utc_iso8601_z_now(),
        schema_version="1.0",
    )
    db.add(row)
    db.flush()


class TestComputeDriftVelocity:
    def test_returns_none_with_no_scans(self, db: Session) -> None:
        result = compute_drift_velocity(
            db, tenant_id=_TENANT, engagement_id=_ENGAGEMENT
        )
        assert result is None

    def test_returns_none_with_single_scan(self, db: Session) -> None:
        _make_scan(db, "v-s1", "2026-01-01T00:00:00Z", finding_count=3)
        result = compute_drift_velocity(
            db, tenant_id=_TENANT, engagement_id=_ENGAGEMENT
        )
        assert result is None

    def test_basic_two_scan_velocity(self, db: Session) -> None:
        _make_scan(db, "v-s2a", "2026-01-01T00:00:00Z", finding_count=0)
        _make_scan(db, "v-s2b", "2026-01-11T00:00:00Z", finding_count=5)
        result = compute_drift_velocity(
            db, tenant_id=_TENANT, engagement_id=_ENGAGEMENT
        )
        assert result is not None
        assert result.scans_analyzed == 2
        assert result.new_per_day > 0

    def test_zero_new_findings(self, db: Session) -> None:
        _make_scan(db, "v-s3a", "2026-02-01T00:00:00Z", finding_count=5)
        _make_scan(db, "v-s3b", "2026-02-11T00:00:00Z", finding_count=5)
        result = compute_drift_velocity(
            db, tenant_id=_TENANT, engagement_id=_ENGAGEMENT
        )
        assert result is not None
        assert result.new_per_day == 0.0

    def test_window_start_end_correct(self, db: Session) -> None:
        _make_scan(db, "v-s4a", "2026-03-01T00:00:00Z", finding_count=1)
        _make_scan(db, "v-s4b", "2026-03-15T00:00:00Z", finding_count=2)
        result = compute_drift_velocity(
            db, tenant_id=_TENANT, engagement_id=_ENGAGEMENT
        )
        assert result is not None
        assert result.window_start == "2026-03-01T00:00:00Z"
        assert result.window_end == "2026-03-15T00:00:00Z"

    def test_n_scans_limits_history(self, db: Session) -> None:
        for i in range(5):
            _make_scan(
                db,
                f"v-s5-{i}",
                f"2026-04-{i + 1:02d}T00:00:00Z",
                finding_count=i,
            )
        result = compute_drift_velocity(
            db, tenant_id=_TENANT, engagement_id=_ENGAGEMENT, n_scans=3
        )
        assert result is not None
        assert result.scans_analyzed <= 3

    def test_mttr_none_when_no_resolutions(self, db: Session) -> None:
        _make_scan(db, "v-s6a", "2026-05-01T00:00:00Z", finding_count=0)
        s2 = _make_scan(db, "v-s6b", "2026-05-11T00:00:00Z", finding_count=1)
        f = _make_finding(db, "v-f6")
        _link(db, f.id, s2.id)
        result = compute_drift_velocity(
            db, tenant_id=_TENANT, engagement_id=_ENGAGEMENT
        )
        assert result is not None
        assert result.mttr_days is None

    def test_regression_rate_detected(self, db: Session) -> None:
        s1 = _make_scan(db, "v-s7a", "2026-06-01T00:00:00Z", finding_count=1)
        _make_scan(db, "v-s7b", "2026-06-11T00:00:00Z", finding_count=0)
        s3 = _make_scan(db, "v-s7c", "2026-06-21T00:00:00Z", finding_count=1)
        f = _make_finding(db, "v-f7-regress")
        _link(db, f.id, s1.id)
        _link(db, f.id, s3.id)
        result = compute_drift_velocity(
            db, tenant_id=_TENANT, engagement_id=_ENGAGEMENT
        )
        assert result is not None
        assert result.regression_rate > 0
