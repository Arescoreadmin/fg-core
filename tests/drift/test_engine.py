"""Tests for the connector-agnostic drift detection engine."""

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
from services.connectors.drift.engine import compute_drift
from services.canonical import utc_iso8601_z_now

_TENANT = "tenant-drift-engine-test"
_ENGAGEMENT = "eng-drift-001"


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


def _make_scan(db: Session, scan_id: str, collected_at: str) -> FaScanResult:
    now = utc_iso8601_z_now()
    row = FaScanResult(
        id=scan_id,
        tenant_id=_TENANT,
        engagement_id=_ENGAGEMENT,
        source_type="microsoft_graph",
        collected_at=collected_at,
        evidence_hash=scan_id + "hash",
        raw_payload={},
        normalized_payload={"findings": []},
        object_count=0,
        created_at=now,
    )
    db.add(row)
    db.flush()
    return row


def _make_finding(
    db: Session,
    finding_id: str,
    severity: str,
    created_at: str,
) -> FaNormalizedFinding:
    now = utc_iso8601_z_now()
    row = FaNormalizedFinding(
        id=finding_id,
        tenant_id=_TENANT,
        engagement_id=_ENGAGEMENT,
        finding_type="ai_governance",
        findings_hash=finding_id + "hash",
        severity=severity,
        status="open",
        title=f"Finding {finding_id}",
        description="test",
        source_attribution="microsoft_graph",
        confidence_score=80,
        framework_mappings=[],
        nist_ai_rmf_mappings=[],
        evidence_ref_ids=[],
        schema_version="1.0",
        created_at=created_at,
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


class TestComputeDrift:
    def test_new_finding_classified(self, db: Session) -> None:
        _make_scan(db, "scan-base", "2026-01-01T00:00:00Z")
        _make_scan(db, "scan-curr", "2026-02-01T00:00:00Z")
        _make_finding(db, "f-new", "high", "2026-01-15T00:00:00Z")
        _link(db, "f-new", "scan-curr")

        result = compute_drift(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            baseline_scan_id="scan-base",
            current_scan_id="scan-curr",
        )
        assert result.counts.get("new") == 1
        assert result.findings[0].delta_class == "new"

    def test_persisted_finding_classified(self, db: Session) -> None:
        _make_scan(db, "scan-base", "2026-01-01T00:00:00Z")
        _make_scan(db, "scan-curr", "2026-02-01T00:00:00Z")
        _make_finding(db, "f-persist", "medium", "2026-01-01T00:00:00Z")
        _link(db, "f-persist", "scan-base")
        _link(db, "f-persist", "scan-curr")

        result = compute_drift(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            baseline_scan_id="scan-base",
            current_scan_id="scan-curr",
        )
        assert result.counts.get("persisted") == 1

    def test_resolved_finding_classified(self, db: Session) -> None:
        _make_scan(db, "scan-base", "2026-01-01T00:00:00Z")
        _make_scan(db, "scan-curr", "2026-02-01T00:00:00Z")
        _make_finding(db, "f-resolved", "low", "2025-12-01T00:00:00Z")
        _link(db, "f-resolved", "scan-base")
        # NOT linked to current scan

        result = compute_drift(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            baseline_scan_id="scan-base",
            current_scan_id="scan-curr",
        )
        assert result.counts.get("resolved") == 1

    def test_regressed_finding_classified(self, db: Session) -> None:
        # Regressed: finding appears in an early scan (before baseline), is absent
        # from the baseline scan itself, then returns in the current scan.
        # The engine detects regression by querying earlier scans, not by created_at.
        _make_scan(db, "scan-early", "2025-12-01T00:00:00Z")
        _make_scan(db, "scan-base-reg", "2026-01-10T00:00:00Z")
        _make_scan(db, "scan-curr-reg", "2026-02-01T00:00:00Z")

        # Row in early scan (same finding_type+title as current-scan row = same stable key)
        _make_finding(db, "f-regress-early", "critical", "2025-12-01T00:00:00Z")
        _link(db, "f-regress-early", "scan-early")

        # Different row ID, same logical finding (same finding_type+title) in current scan
        now = utc_iso8601_z_now()
        from api.db_models_field_assessment import FaNormalizedFinding

        curr_row = FaNormalizedFinding(
            id="f-regress-curr",
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            finding_type="ai_governance",  # same as f-regress-early
            findings_hash="f-regress-curr-hash",
            severity="critical",
            status="open",
            title="Finding f-regress-early",  # same title → same stable key
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
        db.add(curr_row)
        db.flush()
        _link(db, "f-regress-curr", "scan-curr-reg")
        # NOT linked to baseline scan

        result = compute_drift(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            baseline_scan_id="scan-base-reg",
            current_scan_id="scan-curr-reg",
        )
        assert result.counts.get("regressed") == 1
        assert result.has_critical_regression is True

    def test_escalated_finding_detected(self, db: Session) -> None:
        # Escalated: same logical finding (same finding_type+title = same stable key)
        # in both scans but with different severity. The engine reads severity directly
        # from each scan's row — no normalized_payload injection needed.
        _make_scan(db, "scan-esc-base", "2026-01-01T00:00:00Z")
        _make_scan(db, "scan-esc-curr", "2026-02-01T00:00:00Z")

        now = utc_iso8601_z_now()
        from api.db_models_field_assessment import FaNormalizedFinding

        # Baseline row: severity=medium
        base_row = FaNormalizedFinding(
            id="f-esc-base",
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            finding_type="ai_governance",
            findings_hash="f-esc-base-hash",
            severity="medium",
            status="open",
            title="Escalation Finding",
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
        # Current row: same finding_type+title (same stable key), severity=critical
        curr_row = FaNormalizedFinding(
            id="f-esc-curr",
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            finding_type="ai_governance",
            findings_hash="f-esc-curr-hash",
            severity="critical",
            status="open",
            title="Escalation Finding",  # same stable key
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
        db.add(base_row)
        db.add(curr_row)
        db.flush()
        _link(db, "f-esc-base", "scan-esc-base")
        _link(db, "f-esc-curr", "scan-esc-curr")

        result = compute_drift(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            baseline_scan_id="scan-esc-base",
            current_scan_id="scan-esc-curr",
        )
        assert result.counts.get("escalated") == 1
        rec = next(f for f in result.findings if f.delta_class == "escalated")
        assert rec.baseline_severity == "medium"
        assert rec.severity == "critical"

    def test_de_escalated_finding_detected(self, db: Session) -> None:
        _make_scan(db, "scan-de-base", "2026-01-01T00:00:00Z")
        _make_scan(db, "scan-de-curr", "2026-02-01T00:00:00Z")

        now = utc_iso8601_z_now()
        from api.db_models_field_assessment import FaNormalizedFinding

        base_row = FaNormalizedFinding(
            id="f-de-base",
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            finding_type="ai_governance",
            findings_hash="f-de-base-hash",
            severity="critical",
            status="open",
            title="De-escalation Finding",
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
        curr_row = FaNormalizedFinding(
            id="f-de-curr",
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            finding_type="ai_governance",
            findings_hash="f-de-curr-hash",
            severity="medium",
            status="open",
            title="De-escalation Finding",  # same stable key
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
        db.add(base_row)
        db.add(curr_row)
        db.flush()
        _link(db, "f-de-base", "scan-de-base")
        _link(db, "f-de-curr", "scan-de-curr")

        result = compute_drift(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            baseline_scan_id="scan-de-base",
            current_scan_id="scan-de-curr",
        )
        assert result.counts.get("de_escalated") == 1

    def test_missing_baseline_scan_raises(self, db: Session) -> None:
        _make_scan(db, "scan-only", "2026-02-01T00:00:00Z")
        with pytest.raises(ValueError, match="baseline scan"):
            compute_drift(
                db,
                tenant_id=_TENANT,
                engagement_id=_ENGAGEMENT,
                baseline_scan_id="nonexistent-baseline",
                current_scan_id="scan-only",
            )

    def test_empty_scans_return_empty_result(self, db: Session) -> None:
        _make_scan(db, "scan-empty-base", "2026-01-01T00:00:00Z")
        _make_scan(db, "scan-empty-curr", "2026-02-01T00:00:00Z")

        result = compute_drift(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            baseline_scan_id="scan-empty-base",
            current_scan_id="scan-empty-curr",
        )
        assert result.findings == []
        assert result.counts == {}
