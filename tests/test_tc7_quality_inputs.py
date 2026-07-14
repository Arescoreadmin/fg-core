"""TC-7: services/report_authority/quality_inputs.py

Acceptance criteria:
  QI-1  evidence_coverage = 0.0 when no evidence links exist
  QI-2  evidence_coverage > 0.0 when evidence links present
  QI-3  verification_coverage = 0.0 when no provenance exists
  QI-4  verification_coverage > 0.0 when approved provenance exists
  QI-5  freshness = 0.0 when no provenance exists
  QI-6  freshness is close to 1.0 for just-collected evidence (< 1 day old)
  QI-7  confidence = 0.0 when no findings exist
  QI-8  confidence reflects avg(finding.confidence_score) / 100
  QI-9  completeness = 0.0 when no evidence links exist
  QI-10 completeness > 0.0 when evidence links present
  QI-11 generate_report no longer produces quality_score == placeholder 0.5-derived value
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy.orm import Session

from api.db import get_engine
from api.db_models_field_assessment import (
    FaEngagement,
    FaEvidenceLink,
    FaEvidenceProvenance,
    FaNormalizedFinding,
)
from services.report_authority.quality_inputs import compute_quality_inputs

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TENANT = "t-qi-001"
_ENG = "eng-qi-main"


def _uid() -> str:
    return str(uuid.uuid4())


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db(build_app):
    build_app(auth_enabled=False)
    engine = get_engine()
    with Session(engine) as session:
        yield session


@pytest.fixture()
def seeded_db(db: Session):
    """DB with one engagement, 2 findings, 2 evidence links, 1 approved provenance."""
    now = _now_iso()
    _add_engagement(db, _ENG, now)
    f1 = _add_finding(db, _ENG, confidence=80, now=now)
    f2 = _add_finding(db, _ENG, confidence=60, now=now)
    _add_evidence_link(db, _ENG, source_id=f1)
    _add_evidence_link(db, _ENG, source_id=f2)
    _add_provenance(db, _ENG, review_status="approved", collected_at=now)
    db.commit()
    return db


# ---------------------------------------------------------------------------
# Row helpers
# ---------------------------------------------------------------------------


def _add_engagement(db: Session, eng_id: str, now: str) -> None:
    db.add(
        FaEngagement(
            id=eng_id,
            tenant_id=_TENANT,
            client_name="QI Test Client",
            assessor_id="assessor-qi",
            assessment_type="ai_governance",
            status="in_progress",
            engagement_metadata={},
            schema_version="1.0",
            created_at=now,
            updated_at=now,
        )
    )


def _add_finding(db: Session, eng_id: str, *, confidence: int, now: str) -> str:
    fid = _uid()
    db.add(
        FaNormalizedFinding(
            id=fid,
            tenant_id=_TENANT,
            engagement_id=eng_id,
            finding_type="gap",
            findings_hash=hashlib.sha256((fid + eng_id).encode()).hexdigest(),
            severity="high",
            status="open",
            title="QI Test Finding",
            description="Quality inputs test",
            source_attribution="test",
            confidence_score=confidence,
            framework_mappings=[],
            nist_ai_rmf_mappings=[],
            evidence_ref_ids=[],
            schema_version="1.0",
            created_at=now,
            updated_at=now,
        )
    )
    return fid


def _add_evidence_link(db: Session, eng_id: str, *, source_id: str) -> str:
    lid = _uid()
    db.add(
        FaEvidenceLink(
            id=lid,
            tenant_id=_TENANT,
            engagement_id=eng_id,
            source_entity_type="finding",
            source_entity_id=source_id,
            evidence_entity_type="document_analysis",
            evidence_entity_id=_uid(),
            link_metadata={},
            created_at=_now_iso(),
            schema_version="1.0",
            lifecycle_state="collected",
        )
    )
    return lid


def _add_provenance(
    db: Session,
    eng_id: str,
    *,
    review_status: str,
    collected_at: str,
) -> str:
    pid = _uid()
    db.add(
        FaEvidenceProvenance(
            id=pid,
            tenant_id=_TENANT,
            engagement_id=eng_id,
            source_type="document",
            collected_by_type="assessor",
            collected_at=collected_at,
            collection_method="manual",
            collection_context_json={},
            trust_level="unverified",
            review_status=review_status,
            chain_status="active",
            used_in_report_ids=[],
            event_hash=hashlib.sha256(pid.encode()).hexdigest(),
            created_at=_now_iso(),
            schema_version="1.0",
        )
    )
    return pid


# ---------------------------------------------------------------------------
# QI-1: evidence_coverage = 0.0 when no evidence links
# ---------------------------------------------------------------------------


def test_QI_1_evidence_coverage_zero_when_no_links(db: Session):
    cov, _, _, _, _ = compute_quality_inputs(db, tenant_id=_TENANT, engagement_id=_ENG)
    assert cov == 0.0


# ---------------------------------------------------------------------------
# QI-2: evidence_coverage > 0.0 when links present
# ---------------------------------------------------------------------------


def test_QI_2_evidence_coverage_positive_when_links_present(seeded_db: Session):
    # 2 findings, 2 distinct source links → 2/2 = 1.0
    cov, _, _, _, _ = compute_quality_inputs(
        seeded_db, tenant_id=_TENANT, engagement_id=_ENG
    )
    assert cov > 0.0


def test_QI_2c_evidence_coverage_ignores_non_finding_links(db: Session):
    """A workflow link must not inflate evidence_coverage for an unevidenced finding.

    attach_workflow_evidence stores links with source_entity_type='workflow'.
    One workflow link + one finding with no evidence should give coverage = 0.0,
    not 1/1 = 1.0.
    """
    now = _now_iso()
    _add_engagement(db, _ENG, now)
    _add_finding(db, _ENG, confidence=80, now=now)

    # Workflow link — source is a workflow entity, not a finding
    lid = _uid()
    db.add(
        FaEvidenceLink(
            id=lid,
            tenant_id=_TENANT,
            engagement_id=_ENG,
            source_entity_type="workflow",
            source_entity_id=_uid(),
            evidence_entity_type="document_analysis",
            evidence_entity_id=_uid(),
            link_metadata={},
            created_at=now,
            schema_version="1.0",
            lifecycle_state="collected",
        )
    )
    db.commit()

    cov, _, _, _, _ = compute_quality_inputs(db, tenant_id=_TENANT, engagement_id=_ENG)
    assert cov == 0.0


# ---------------------------------------------------------------------------
# QI-3: verification_coverage = 0.0 when no provenance
# ---------------------------------------------------------------------------


def test_QI_3_verification_coverage_zero_when_no_provenance(db: Session):
    _, vc, _, _, _ = compute_quality_inputs(db, tenant_id=_TENANT, engagement_id=_ENG)
    assert vc == 0.0


# ---------------------------------------------------------------------------
# QI-4: verification_coverage > 0.0 when approved provenance exists
# ---------------------------------------------------------------------------


def test_QI_4_verification_coverage_positive_when_approved(seeded_db: Session):
    # 1 approved provenance → 1/1 = 1.0
    _, vc, _, _, _ = compute_quality_inputs(
        seeded_db, tenant_id=_TENANT, engagement_id=_ENG
    )
    assert vc > 0.0


def test_QI_4b_verification_coverage_zero_when_only_pending(db: Session):
    now = _now_iso()
    _add_engagement(db, _ENG, now)
    _add_provenance(db, _ENG, review_status="pending", collected_at=now)
    db.commit()

    _, vc, _, _, _ = compute_quality_inputs(db, tenant_id=_TENANT, engagement_id=_ENG)
    assert vc == 0.0


def test_QI_4c_verification_coverage_counts_chain_not_rows(db: Session):
    """A pending→approved chain (2 rows) is 1 head record, not 2.

    mark_provenance_reviewed appends an approved row with previous_hash set to
    the prior event_hash. Without the head-record filter, coverage would be
    reported as 1/2 (0.5) instead of 1/1 (1.0).
    """
    import hashlib as _hl

    now = _now_iso()
    _add_engagement(db, _ENG, now)

    # Row 1: pending (chain root)
    pid1 = _uid()
    h1 = _hl.sha256(pid1.encode()).hexdigest()
    db.add(
        FaEvidenceProvenance(
            id=pid1,
            tenant_id=_TENANT,
            engagement_id=_ENG,
            source_type="document",
            collected_by_type="assessor",
            collected_at=now,
            collection_method="manual",
            collection_context_json={},
            trust_level="unverified",
            review_status="pending",
            chain_status="active",
            used_in_report_ids=[],
            previous_hash=None,
            event_hash=h1,
            created_at=now,
            schema_version="1.0",
        )
    )

    # Row 2: approved (child of row 1, as mark_provenance_reviewed would produce)
    pid2 = _uid()
    h2 = _hl.sha256(pid2.encode()).hexdigest()
    db.add(
        FaEvidenceProvenance(
            id=pid2,
            tenant_id=_TENANT,
            engagement_id=_ENG,
            source_type="document",
            collected_by_type="assessor",
            collected_at=now,
            collection_method="manual",
            collection_context_json={},
            trust_level="unverified",
            review_status="approved",
            chain_status="active",
            used_in_report_ids=[],
            previous_hash=h1,  # links back to row 1
            event_hash=h2,
            created_at=now,
            schema_version="1.0",
        )
    )
    db.commit()

    _, vc, _, _, _ = compute_quality_inputs(db, tenant_id=_TENANT, engagement_id=_ENG)
    # Head record count = 1 (row 2 only); approved head count = 1 → vc = 1.0
    assert vc == 1.0


# ---------------------------------------------------------------------------
# QI-5: freshness = 0.0 when no provenance
# ---------------------------------------------------------------------------


def test_QI_5_freshness_zero_when_no_provenance(db: Session):
    _, _, fr, _, _ = compute_quality_inputs(db, tenant_id=_TENANT, engagement_id=_ENG)
    assert fr == 0.0


# ---------------------------------------------------------------------------
# QI-6: freshness close to 1.0 for just-collected evidence
# ---------------------------------------------------------------------------


def test_QI_6_freshness_near_one_for_fresh_evidence(db: Session):
    now = _now_iso()
    _add_engagement(db, _ENG, now)
    _add_provenance(db, _ENG, review_status="pending", collected_at=now)
    db.commit()

    _, _, fr, _, _ = compute_quality_inputs(db, tenant_id=_TENANT, engagement_id=_ENG)
    assert fr >= 0.99


# ---------------------------------------------------------------------------
# QI-7: confidence = 0.0 when no findings exist
# ---------------------------------------------------------------------------


def test_QI_7_confidence_zero_when_no_findings(db: Session):
    _, _, _, conf, _ = compute_quality_inputs(db, tenant_id=_TENANT, engagement_id=_ENG)
    assert conf == 0.0


# ---------------------------------------------------------------------------
# QI-8: confidence reflects avg(confidence_score) / 100
# ---------------------------------------------------------------------------


def test_QI_8_confidence_reflects_average_normalised(seeded_db: Session):
    # Findings: confidence_score 80 and 60 → avg=70 → 0.70
    _, _, _, conf, _ = compute_quality_inputs(
        seeded_db, tenant_id=_TENANT, engagement_id=_ENG
    )
    assert abs(conf - 0.70) < 0.01


def test_QI_8b_single_finding_confidence(db: Session):
    now = _now_iso()
    _add_engagement(db, _ENG, now)
    _add_finding(db, _ENG, confidence=90, now=now)
    db.commit()

    _, _, _, conf, _ = compute_quality_inputs(db, tenant_id=_TENANT, engagement_id=_ENG)
    assert abs(conf - 0.90) < 0.01


# ---------------------------------------------------------------------------
# QI-9: completeness = 0.0 when no evidence links
# ---------------------------------------------------------------------------


def test_QI_9_completeness_zero_when_no_evidence_links(db: Session):
    now = _now_iso()
    _add_engagement(db, _ENG, now)
    _add_finding(db, _ENG, confidence=80, now=now)
    db.commit()

    _, _, _, _, comp = compute_quality_inputs(db, tenant_id=_TENANT, engagement_id=_ENG)
    assert comp == 0.0


# ---------------------------------------------------------------------------
# QI-10: completeness > 0.0 when evidence links present
# ---------------------------------------------------------------------------


def test_QI_10_completeness_positive_when_links_present(seeded_db: Session):
    # 2 links, 2 findings → 2/(2*2) = 0.5
    _, _, _, _, comp = compute_quality_inputs(
        seeded_db, tenant_id=_TENANT, engagement_id=_ENG
    )
    assert comp > 0.0


# ---------------------------------------------------------------------------
# QI-11: generate_report uses real quality inputs (not 0.5 placeholder)
# ---------------------------------------------------------------------------


def test_QI_11_generate_report_uses_real_quality_inputs(db: Session):
    """An empty engagement now produces quality_score = 0.0, not 0.5.

    The old _PLACEHOLDER_COVERAGE = 0.5 fed compute_quality_score() which
    produced 0.5 for all inputs. An empty engagement now correctly yields 0.0.
    """
    from services.report_authority.engine import ReportAuthorityEngine
    from services.report_authority.models import ReportType
    from services.report_authority.schemas import GenerateReportRequest

    eng = ReportAuthorityEngine(db, tenant_id=_TENANT)
    req = GenerateReportRequest(
        assessment_id=_ENG,
        report_type=ReportType.EXECUTIVE,
        title="TC-7 Integration Test",
        scope="empty engagement",
        objectives="verify live quality inputs",
        assessor_id="assessor-qi",
        reviewer_id="reviewer-qi",
    )
    resp = eng.generate_report(req, actor_id="test", actor_type="human")
    # Old placeholder gave 0.5; real empty engagement gives 0.0
    assert resp.quality_score == 0.0
