from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models_governance_report import GovernanceReportRecord
from tests.fa_forensic_helpers import TENANT_A, create_engagement, make_context


def test_tampered_report_sections_fail_signature_verification(
    build_app: object, monkeypatch
) -> None:
    """Direct DB tampering inside signed report JSON must make verification return valid=false."""
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", "a1" * 32)
    ctx = make_context(build_app)
    engagement = create_engagement(ctx.client_a)
    created = ctx.client_a.post(
        f"/field-assessment/engagements/{engagement['id']}/reports",
        json={"report_type": "full_assessment"},
    )
    assert created.status_code == 201, created.text
    with Session(ctx.engine) as session:
        record = session.scalar(
            select(GovernanceReportRecord).where(
                GovernanceReportRecord.tenant_id == TENANT_A,
                GovernanceReportRecord.engagement_id == engagement["id"],
                GovernanceReportRecord.version == created.json()["version"],
            )
        )
        assert record is not None
        report_json = dict(record.report_json)
        report_json["tampered"] = True
        record.report_json = report_json
        session.commit()
    verified = ctx.client_a.post(
        f"/field-assessment/engagements/{engagement['id']}/reports/{created.json()['version']}/verify"
    )
    assert verified.status_code == 200, verified.text
    assert verified.json()["valid"] is False
