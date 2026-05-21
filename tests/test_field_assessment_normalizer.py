"""Tests for the shared finding normalizer service.

Covers:
  - Findings extracted from normalized_payload["findings"]
  - Idempotency: re-ingesting same payload returns same findings
  - Malformed entries (missing fields, bad severity) are skipped with warnings
  - finding_count is set on the scan result
  - Evidence links created for each finding
  - Empty or absent "findings" key returns empty list
  - Manual scan ingest route normalizes findings when normalized_payload provided
"""

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
import api.db_models_governance_report  # noqa: F401

from api.db_models_field_assessment import (
    FaEvidenceLink,
    FaNormalizedFinding,
    FaScanResult,
)
from services.canonical import utc_iso8601_z_now
from services.field_assessment.normalizer import normalize_scan_findings
from services.field_assessment.store import create_scan_result

_TENANT = "tenant-normalizer-test"
_ENGAGEMENT = "eng-norm-001"


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


def _make_scan(db: Session, scan_id_suffix: str = "a") -> FaScanResult:
    return create_scan_result(
        db,
        tenant_id=_TENANT,
        engagement_id=_ENGAGEMENT,
        source_type="microsoft_graph",
        schema_version="1.0",
        collected_at=utc_iso8601_z_now(),
        raw_payload={"users": []},
        normalized_payload=None,
        object_count=0,
        evidence_hash=f"hash-norm-{scan_id_suffix}",
    )


_FINDING_PAYLOAD = {
    "findings": [
        {
            "finding_type": "ai_governance",
            "title": "Missing AI policy",
            "severity": "high",
            "description": "No AI usage policy was found.",
            "nist_ai_rmf_mappings": [],
            "framework_mappings": [],
            "remediation_hint": "Draft and approve an AI usage policy.",
        }
    ]
}


class TestNormalizeFindings:
    def test_returns_empty_for_no_findings_key(self, db: Session) -> None:
        scan = _make_scan(db, "b")
        result = normalize_scan_findings(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            scan_result=scan,
            normalized_payload={},
        )
        assert result == []

    def test_returns_empty_for_empty_findings_list(self, db: Session) -> None:
        scan = _make_scan(db, "c")
        result = normalize_scan_findings(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            scan_result=scan,
            normalized_payload={"findings": []},
        )
        assert result == []

    def test_extracts_one_finding(self, db: Session) -> None:
        scan = _make_scan(db, "d")
        result = normalize_scan_findings(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            scan_result=scan,
            normalized_payload=_FINDING_PAYLOAD,
        )
        assert len(result) == 1
        assert isinstance(result[0], FaNormalizedFinding)
        assert result[0].title == "Missing AI policy"
        assert result[0].severity == "high"

    def test_sets_finding_count_on_scan(self, db: Session) -> None:
        scan = _make_scan(db, "e")
        normalize_scan_findings(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            scan_result=scan,
            normalized_payload=_FINDING_PAYLOAD,
        )
        assert scan.finding_count == 1

    def test_creates_evidence_link(self, db: Session) -> None:
        scan = _make_scan(db, "f")
        findings = normalize_scan_findings(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            scan_result=scan,
            normalized_payload=_FINDING_PAYLOAD,
        )
        link = (
            db.query(FaEvidenceLink)
            .filter_by(
                source_entity_id=findings[0].id,
                evidence_entity_id=scan.id,
            )
            .first()
        )
        assert link is not None
        assert link.source_entity_type == "finding"
        assert link.evidence_entity_type == "scan_result"

    def test_idempotent_on_repeated_call(self, db: Session) -> None:
        scan = _make_scan(db, "g")
        r1 = normalize_scan_findings(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            scan_result=scan,
            normalized_payload=_FINDING_PAYLOAD,
        )
        r2 = normalize_scan_findings(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            scan_result=scan,
            normalized_payload=_FINDING_PAYLOAD,
        )
        assert r1[0].id == r2[0].id

    def test_skips_entry_missing_required_fields(self, db: Session) -> None:
        scan = _make_scan(db, "h")
        payload = {
            "findings": [
                {"finding_type": "ai_governance"},  # missing title and description
                {
                    "finding_type": "ai_governance",
                    "title": "Good finding",
                    "description": "Complete entry.",
                    "severity": "low",
                },
            ]
        }
        result = normalize_scan_findings(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            scan_result=scan,
            normalized_payload=payload,
        )
        assert len(result) == 1
        assert result[0].title == "Good finding"

    def test_normalizes_unknown_severity_to_medium(self, db: Session) -> None:
        scan = _make_scan(db, "i")
        payload = {
            "findings": [
                {
                    "finding_type": "ai_governance",
                    "title": "Weird severity",
                    "description": "Bad severity value.",
                    "severity": "extreme",
                }
            ]
        }
        result = normalize_scan_findings(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            scan_result=scan,
            normalized_payload=payload,
        )
        assert result[0].severity == "medium"

    def test_multiple_findings_all_extracted(self, db: Session) -> None:
        scan = _make_scan(db, "j")
        payload = {
            "findings": [
                {
                    "finding_type": "ai_governance",
                    "title": f"Finding {i}",
                    "description": f"Description {i}",
                    "severity": "high",
                }
                for i in range(3)
            ]
        }
        result = normalize_scan_findings(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            scan_result=scan,
            normalized_payload=payload,
        )
        assert len(result) == 3
        assert scan.finding_count == 3

    def test_source_attribution_set(self, db: Session) -> None:
        scan = _make_scan(db, "k")
        result = normalize_scan_findings(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            scan_result=scan,
            normalized_payload=_FINDING_PAYLOAD,
            source_attribution="okta:import",
        )
        assert result[0].source_attribution == "okta:import"


class TestManualScanIngestWithNormalizedPayload:
    """Integration: the scan ingest API route triggers normalization."""

    def test_scan_ingest_with_findings_creates_normalized_findings(
        self, build_app
    ) -> None:
        from api.auth_scopes import mint_key

        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", "governance:write", tenant_id=_TENANT)
        from fastapi.testclient import TestClient

        c = TestClient(app, headers={"X-API-Key": key})

        eng = c.post(
            "/field-assessment/engagements",
            json={
                "client_name": "Normalizer Corp",
                "assessor_id": "assessor-norm",
                "assessment_type": "ai_governance",
            },
        )
        assert eng.status_code == 201
        eng_id = eng.json()["id"]

        resp = c.post(
            f"/field-assessment/engagements/{eng_id}/scan-results",
            json={
                "source_type": "microsoft_graph",
                "schema_version": "1.0",
                "collected_at": "2026-05-21T00:00:00Z",
                "raw_payload": {"users": []},
                "object_count": 0,
                "normalized_payload": {
                    "findings": [
                        {
                            "finding_type": "ai_governance",
                            "title": "API-level finding",
                            "severity": "high",
                            "description": "Found via API ingest.",
                        }
                    ]
                },
            },
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["finding_count"] == 1

    def test_scan_ingest_without_normalized_payload_creates_no_findings(
        self, build_app
    ) -> None:
        from api.auth_scopes import mint_key

        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", "governance:write", tenant_id=_TENANT)
        from fastapi.testclient import TestClient

        c = TestClient(app, headers={"X-API-Key": key})

        eng = c.post(
            "/field-assessment/engagements",
            json={
                "client_name": "No Norm Corp",
                "assessor_id": "assessor-no-norm",
                "assessment_type": "ai_governance",
            },
        )
        eng_id = eng.json()["id"]

        resp = c.post(
            f"/field-assessment/engagements/{eng_id}/scan-results",
            json={
                "source_type": "microsoft_graph",
                "schema_version": "1.0",
                "collected_at": "2026-05-21T00:00:00Z",
                "raw_payload": {"users": []},
                "object_count": 0,
            },
        )
        assert resp.status_code == 201
        assert resp.json()["finding_count"] == 0
