"""Measure scoped engagement-list queries at representative tenant sizes."""

from __future__ import annotations

from time import perf_counter

from sqlalchemy.orm import Session

from api.db import get_engine
from api.db_models_field_assessment import FaEngagement, FaNormalizedFinding
from api.db_models_governance_report import GovernanceReportRecord
from services.governance.report.versioning import list_versions
from services.field_assessment.store import list_findings
from services.field_assessment.store import list_engagements


def test_scoped_engagement_list_filters_before_limit(build_app) -> None:
    build_app(auth_enabled=False)
    rows: list[FaEngagement] = []
    scoped_ids: dict[int, str] = {}
    for size in (1, 100, 1000):
        tenant_id = f"portal-scale-{size}"
        for index in range(size):
            engagement_id = f"{tenant_id}-{index}"
            if index == size - 1:
                scoped_ids[size] = engagement_id
            rows.append(
                FaEngagement(
                    id=engagement_id,
                    tenant_id=tenant_id,
                    client_name=f"Synthetic {index}",
                    client_domain=None,
                    assessor_id="synthetic-assessor",
                    assessment_type="comprehensive",
                    status="in_progress",
                    scheduled_date=None,
                    engagement_metadata={},
                    schema_version="1.0",
                    created_at=f"2026-01-{(index % 28) + 1:02d}T00:00:00Z",
                    updated_at="2026-01-01T00:00:00Z",
                )
            )

    with Session(get_engine()) as db:
        db.bulk_save_objects(rows)
        db.commit()
        for size in (1, 100, 1000):
            tenant_id = f"portal-scale-{size}"
            allowed = {scoped_ids[size]}
            started = perf_counter()
            result = []
            for _ in range(20):
                result = list_engagements(
                    db,
                    tenant_id=tenant_id,
                    status_filter=None,
                    limit=100,
                    cursor=None,
                    engagement_ids=allowed,
                )
            elapsed_ms = (perf_counter() - started) * 1000 / 20
            assert [row.id for row in result] == [scoped_ids[size]]
            print(f"scoped_list tenant_rows={size} avg_query_ms={elapsed_ms:.3f}")

        perf_engagement = FaEngagement(
            id="portal-scale-findings-engagement",
            tenant_id="portal-scale-findings",
            client_name="Synthetic findings scale",
            client_domain=None,
            assessor_id="synthetic-assessor",
            assessment_type="comprehensive",
            status="in_progress",
            scheduled_date=None,
            engagement_metadata={},
            schema_version="1.0",
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-01-01T00:00:00Z",
        )
        db.add(perf_engagement)
        db.bulk_save_objects(
            [
                FaNormalizedFinding(
                    id=f"portal-scale-finding-{index}",
                    tenant_id="portal-scale-findings",
                    engagement_id=perf_engagement.id,
                    finding_type="synthetic_scale",
                    findings_hash=f"portal-scale-finding-hash-{index}",
                    severity="high",
                    status="open",
                    title=f"Synthetic finding {index}",
                    description="synthetic performance fixture",
                    source_attribution="synthetic fixture",
                    confidence_score=80,
                    framework_mappings=[],
                    nist_ai_rmf_mappings=[],
                    evidence_ref_ids=[],
                    remediation_hint=None,
                    schema_version="1.0",
                    created_at=f"2026-01-01T00:{index // 60:02d}:{index % 60:02d}Z",
                    updated_at="2026-01-01T00:00:00Z",
                )
                for index in range(500)
            ]
        )
        db.bulk_save_objects(
            [
                GovernanceReportRecord(
                    id=f"portal-scale-report-{index}",
                    assessment_id=perf_engagement.id,
                    tenant_id="portal-scale-findings",
                    engagement_id=perf_engagement.id,
                    version=index + 1,
                    schema_version="1.0",
                    report_type="full_assessment",
                    compiled_by=None,
                    manifest_hash=f"portal-scale-manifest-{index}",
                    report_json={},
                    section_hashes={},
                    signature=None,
                    generated_at=f"2026-01-01T00:{index // 60:02d}:{index % 60:02d}Z",
                    is_finalized=False,
                )
                for index in range(25)
            ]
        )
        db.commit()

        started = perf_counter()
        for _ in range(20):
            finding_page = list_findings(
                db,
                engagement_id=perf_engagement.id,
                tenant_id="portal-scale-findings",
                severity_filter=None,
                status_filter="open",
                limit=100,
                offset=400,
            )
        findings_ms = (perf_counter() - started) * 1000 / 20
        assert len(finding_page) == 100
        print(f"finding_page findings=500 page_size=100 avg_query_ms={findings_ms:.3f}")

        started = perf_counter()
        for _ in range(20):
            versions = list_versions(
                db,
                tenant_id="portal-scale-findings",
                engagement_id=perf_engagement.id,
            )
        versions_ms = (perf_counter() - started) * 1000 / 20
        assert [report.version for report in versions] == list(range(1, 26))
        print(f"report_versions revisions=25 avg_query_ms={versions_ms:.3f}")
