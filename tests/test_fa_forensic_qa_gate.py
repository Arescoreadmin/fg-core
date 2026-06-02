from __future__ import annotations

from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaEngagement
from tests.fa_forensic_helpers import create_engagement, make_context


def test_qa_approve_unknown_report_fails_without_delivering_engagement(
    build_app: object,
) -> None:
    """QA approval must not advance delivery when the referenced report does not exist."""
    ctx = make_context(build_app)
    engagement = create_engagement(ctx.client_a)
    response = ctx.client_a.post(
        f"/field-assessment/engagements/{engagement['id']}/reports/missing-report/qa-approve",
        json={"reviewer_display_name": "Forensic Reviewer"},
    )
    assert response.status_code in {404, 422}, response.text
    with Session(ctx.engine) as session:
        row = session.get(FaEngagement, engagement["id"])
        assert row is not None
        assert row.status == "in_progress"
