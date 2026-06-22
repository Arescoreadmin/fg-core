"""Tests for PR 1.1 — Evidence Provenance Foundation.

Covers:
  - Model/schema shape (required columns present)
  - create_evidence_provenance: fields written, event_hash computed
  - sanitize_provenance_payload: forbidden keys stripped
  - Tenant isolation: wrong-tenant reads return nothing
  - mark_provenance_reviewed: creates new row, invalid status rejected
  - verify_provenance_chain: valid chain passes, tampered hash fails
  - Legacy compatibility: evidence without provenance does not crash
  - Report usage: used_in_report_ids can be recorded
"""

from __future__ import annotations

from typing import Any

import pytest
import sqlalchemy
from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaEvidenceProvenance

TENANT_A = "provenance-tenant-a"
TENANT_B = "provenance-tenant-b"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_provenance(db: Session, **kwargs) -> FaEvidenceProvenance:
    from services.field_assessment.evidence_provenance import create_evidence_provenance

    defaults: dict[str, Any] = dict(
        tenant_id=TENANT_A,
        engagement_id="eng-prov-001",
        evidence_id="ev-001",
        source_type="scan_result",
        collected_by_type="connector",
        collected_by_id="ms_graph_connector",
        collection_method="scan_connector",
    )
    defaults.update(kwargs)
    return create_evidence_provenance(db, **defaults)


# ---------------------------------------------------------------------------
# Model shape
# ---------------------------------------------------------------------------


def test_fa_evidence_provenance_has_required_columns():
    cols = {c.key for c in FaEvidenceProvenance.__mapper__.columns}
    required = {
        "id",
        "tenant_id",
        "engagement_id",
        "evidence_id",
        "finding_id",
        "source_type",
        "source_system",
        "source_reference",
        "source_uri_hash",
        "artifact_hash",
        "collected_by_type",
        "collected_by_id",
        "collected_at",
        "collection_method",
        "collection_context_json",
        "classification",
        "retention_policy",
        "freshness_at_collection",
        "trust_level",
        "review_status",
        "reviewed_by",
        "reviewed_at",
        "review_notes",
        "chain_status",
        "used_in_report_ids",
        "previous_hash",
        "event_hash",
        "created_at",
        "schema_version",
    }
    missing = required - cols
    assert not missing, f"FaEvidenceProvenance missing columns: {missing}"


def test_fa_evidence_provenance_nullable_columns():
    nullable = {
        "evidence_id",
        "finding_id",
        "source_system",
        "source_reference",
        "source_uri_hash",
        "artifact_hash",
        "collected_by_id",
        "classification",
        "retention_policy",
        "freshness_at_collection",
        "reviewed_by",
        "reviewed_at",
        "review_notes",
        "previous_hash",
    }
    for col_name in nullable:
        col = FaEvidenceProvenance.__mapper__.columns[col_name]
        assert col.nullable, f"Column {col_name} should be nullable"


def test_fa_evidence_provenance_not_nullable_columns():
    not_nullable = {
        "id",
        "tenant_id",
        "engagement_id",
        "source_type",
        "collected_by_type",
        "collected_at",
        "collection_method",
        "event_hash",
        "created_at",
    }
    for col_name in not_nullable:
        col = FaEvidenceProvenance.__mapper__.columns[col_name]
        assert not col.nullable, f"Column {col_name} should NOT be nullable"


# ---------------------------------------------------------------------------
# Create provenance
# ---------------------------------------------------------------------------


def test_create_evidence_provenance_writes_all_fields(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, artifact_hash="a" * 64)
        db.commit()

        stored = db.get(FaEvidenceProvenance, record.id)
        assert stored is not None
        assert stored.tenant_id == TENANT_A
        assert stored.engagement_id == "eng-prov-001"
        assert stored.evidence_id == "ev-001"
        assert stored.source_type == "scan_result"
        assert stored.collected_by_type == "connector"
        assert stored.collection_method == "scan_connector"
        assert stored.artifact_hash == "a" * 64
        assert stored.review_status == "pending"
        assert stored.chain_status == "active"
        assert stored.trust_level == "unverified"
        assert stored.schema_version == "1.0"
        assert stored.used_in_report_ids == []
        assert stored.previous_hash is None


def test_create_evidence_provenance_computes_event_hash(build_app):
    from api.db import get_engine
    from services.field_assessment.evidence_provenance import (
        _hash_payload,
        compute_provenance_hash,
    )

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, artifact_hash="b" * 64)
        db.commit()

        stored = db.get(FaEvidenceProvenance, record.id)
        expected_payload = _hash_payload(
            tenant_id=stored.tenant_id,
            engagement_id=stored.engagement_id,
            evidence_id=stored.evidence_id,
            finding_id=stored.finding_id,
            source_type=stored.source_type,
            collection_method=stored.collection_method,
            collected_by_type=stored.collected_by_type,
            collected_by_id=stored.collected_by_id,
            collected_at=stored.collected_at,
            artifact_hash=stored.artifact_hash,
            previous_hash=stored.previous_hash,
            created_at=stored.created_at,
        )
        assert stored.event_hash == compute_provenance_hash(expected_payload)
        assert len(stored.event_hash) == 64


# ---------------------------------------------------------------------------
# sanitize_provenance_payload
# ---------------------------------------------------------------------------


def test_sanitize_strips_forbidden_keys():
    from services.field_assessment.evidence_provenance import (
        sanitize_provenance_payload,
    )

    dirty = {
        "scan_job_id": "job-123",
        "token": "super-secret-bearer",
        "api_key": "sk-abc",
        "secret": "mysecret",
        "result_count": 42,
        "authorization": "Bearer xyz",
    }
    clean = sanitize_provenance_payload(dirty)
    assert "token" not in clean
    assert "api_key" not in clean
    assert "secret" not in clean
    assert "authorization" not in clean
    assert clean["scan_job_id"] == "job-123"
    assert clean["result_count"] == 42


def test_sanitize_empty_context_returns_empty():
    from services.field_assessment.evidence_provenance import (
        sanitize_provenance_payload,
    )

    assert sanitize_provenance_payload({}) == {}


def test_create_provenance_strips_secrets_from_context(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db,
            engagement_id="eng-sanitize-001",
            collection_context={
                "scan_job_id": "job-001",
                "token": "should-be-stripped",
                "result_count": 5,
            },
        )
        db.commit()
        stored = db.get(FaEvidenceProvenance, record.id)
        assert "token" not in stored.collection_context_json
        assert stored.collection_context_json.get("scan_job_id") == "job-001"
        assert stored.collection_context_json.get("result_count") == 5


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


def test_get_provenance_wrong_tenant_returns_none(build_app):
    from api.db import get_engine
    from services.field_assessment.evidence_provenance import get_evidence_provenance

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-iso-get-001")
        db.commit()

        result = get_evidence_provenance(
            db, provenance_id=record.id, tenant_id=TENANT_B
        )
        assert result is None


def test_list_provenance_wrong_tenant_returns_empty(build_app):
    from api.db import get_engine
    from services.field_assessment.evidence_provenance import (
        list_evidence_provenance_for_engagement,
    )

    build_app()
    with Session(get_engine()) as db:
        _make_provenance(db, engagement_id="eng-iso-list-001")
        db.commit()

        results = list_evidence_provenance_for_engagement(
            db,
            tenant_id=TENANT_B,
            engagement_id="eng-iso-list-001",
        )
        assert results == []


def test_list_provenance_for_finding_wrong_tenant_returns_empty(build_app):
    from api.db import get_engine
    from services.field_assessment.evidence_provenance import (
        list_evidence_provenance_for_finding,
    )

    build_app()
    with Session(get_engine()) as db:
        _make_provenance(db, engagement_id="eng-find-iso-001", finding_id="finding-xyz")
        db.commit()

        results = list_evidence_provenance_for_finding(
            db,
            tenant_id=TENANT_B,
            engagement_id="eng-find-iso-001",
            finding_id="finding-xyz",
        )
        assert results == []


# ---------------------------------------------------------------------------
# Review workflow
# ---------------------------------------------------------------------------


def test_mark_provenance_reviewed_creates_new_row(build_app):
    from api.db import get_engine
    from services.field_assessment.evidence_provenance import (
        list_evidence_provenance_for_engagement,
        mark_provenance_reviewed,
    )

    build_app()
    with Session(get_engine()) as db:
        original = _make_provenance(db, engagement_id="eng-review-001")
        db.commit()
        original_id = original.id
        original_hash = original.event_hash

        reviewed = mark_provenance_reviewed(
            db,
            tenant_id=TENANT_A,
            provenance_id=original_id,
            reviewed_by="qa-reviewer-1",
            new_status="approved",
            review_notes="Looks good.",
        )
        db.commit()

        assert reviewed.id != original_id
        assert reviewed.review_status == "approved"
        assert reviewed.reviewed_by == "qa-reviewer-1"
        assert reviewed.review_notes == "Looks good."
        assert reviewed.reviewed_at is not None
        assert reviewed.previous_hash == original_hash
        assert reviewed.chain_status == "active"

        orig_stored = db.get(FaEvidenceProvenance, original_id)
        assert orig_stored.review_status == "pending"

        all_records = list_evidence_provenance_for_engagement(
            db, tenant_id=TENANT_A, engagement_id="eng-review-001"
        )
        assert len(all_records) == 2


def test_mark_provenance_reviewed_invalid_status_raises(build_app):
    from api.db import get_engine
    from services.field_assessment.evidence_provenance import mark_provenance_reviewed

    build_app()
    with Session(get_engine()) as db:
        original = _make_provenance(db, engagement_id="eng-review-bad")
        db.commit()

        with pytest.raises(ValueError, match="invalid review status"):
            mark_provenance_reviewed(
                db,
                tenant_id=TENANT_A,
                provenance_id=original.id,
                reviewed_by="qa-reviewer",
                new_status="pending",
            )


def test_mark_provenance_reviewed_wrong_tenant_raises(build_app):
    from api.db import get_engine
    from services.field_assessment.evidence_provenance import mark_provenance_reviewed

    build_app()
    with Session(get_engine()) as db:
        original = _make_provenance(db, engagement_id="eng-review-xten")
        db.commit()

        with pytest.raises(ValueError, match="not found for tenant"):
            mark_provenance_reviewed(
                db,
                tenant_id=TENANT_B,
                provenance_id=original.id,
                reviewed_by="attacker",
                new_status="approved",
            )


# ---------------------------------------------------------------------------
# Hash verification
# ---------------------------------------------------------------------------


def test_verify_provenance_chain_valid(build_app):
    from api.db import get_engine
    from services.field_assessment.evidence_provenance import verify_provenance_chain

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, artifact_hash="c" * 64, engagement_id="eng-verify-ok"
        )
        db.commit()

        result = verify_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=record.id
        )
        assert result["valid"] is True
        assert result["reason"] == "ok"


def test_verify_provenance_chain_tampered_hash_fails(build_app):
    from api.db import get_engine
    from services.field_assessment.evidence_provenance import verify_provenance_chain

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-tamper-001")
        db.commit()

        db.execute(
            sqlalchemy.text(
                "UPDATE fa_evidence_provenance SET event_hash = :bad WHERE id = :id"
            ),
            {"bad": "0" * 64, "id": record.id},
        )
        db.commit()

        result = verify_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=record.id
        )
        assert result["valid"] is False
        assert result["reason"] == "hash_mismatch"


def test_verify_provenance_chain_not_found(build_app):
    from api.db import get_engine
    from services.field_assessment.evidence_provenance import verify_provenance_chain

    build_app()
    with Session(get_engine()) as db:
        result = verify_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id="nonexistent-id"
        )
        assert result["valid"] is False
        assert result["reason"] == "not_found"


# ---------------------------------------------------------------------------
# Legacy compatibility
# ---------------------------------------------------------------------------


def test_legacy_evidence_without_provenance_does_not_crash(build_app):
    """Evidence that predates provenance must not fail queries."""
    from api.db import get_engine
    from services.field_assessment.evidence_provenance import (
        list_evidence_provenance_for_engagement,
    )

    build_app()
    with Session(get_engine()) as db:
        results = list_evidence_provenance_for_engagement(
            db,
            tenant_id=TENANT_A,
            engagement_id="eng-legacy-no-provenance",
        )
        assert results == []


def test_list_provenance_empty_for_engagement_without_records(build_app):
    from api.db import get_engine
    from services.field_assessment.evidence_provenance import (
        list_evidence_provenance_for_engagement,
    )

    build_app()
    with Session(get_engine()) as db:
        results = list_evidence_provenance_for_engagement(
            db, tenant_id=TENANT_A, engagement_id="eng-does-not-exist"
        )
        assert isinstance(results, list)
        assert len(results) == 0


# ---------------------------------------------------------------------------
# Report usage
# ---------------------------------------------------------------------------


def test_provenance_records_report_usage(build_app):
    """used_in_report_ids is a safe list of opaque IDs, no report content."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-report-use-001")
        db.commit()

        stored = db.get(FaEvidenceProvenance, record.id)
        assert stored.used_in_report_ids == []
        assert isinstance(stored.used_in_report_ids, list)


def test_provenance_create_with_empty_report_ids(build_app):
    from api.db import get_engine
    from services.field_assessment.evidence_provenance import create_evidence_provenance

    build_app()
    with Session(get_engine()) as db:
        record = create_evidence_provenance(
            db,
            tenant_id=TENANT_A,
            engagement_id="eng-report-ref-001",
            source_type="scan_result",
            collected_by_type="connector",
            collection_method="scan_connector",
        )
        db.commit()

        stored = db.get(FaEvidenceProvenance, record.id)
        assert isinstance(stored.used_in_report_ids, list)
        assert stored.used_in_report_ids == []


# ---------------------------------------------------------------------------
# Hash determinism
# ---------------------------------------------------------------------------


def test_compute_provenance_hash_is_deterministic():
    from services.field_assessment.evidence_provenance import (
        _hash_payload,
        compute_provenance_hash,
    )

    payload = _hash_payload(
        tenant_id="t1",
        engagement_id="e1",
        evidence_id="ev1",
        finding_id=None,
        source_type="scan_result",
        collection_method="scan_connector",
        collected_by_type="connector",
        collected_by_id="ms_graph",
        collected_at="2026-06-10T00:00:00Z",
        artifact_hash="a" * 64,
        previous_hash=None,
        created_at="2026-06-10T00:00:00Z",
    )
    h1 = compute_provenance_hash(payload)
    h2 = compute_provenance_hash(payload)
    assert h1 == h2
    assert len(h1) == 64
