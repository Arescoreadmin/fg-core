from __future__ import annotations

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.db_models_field_assessment import (
    FaDocumentAnalysis,
    FaEngagement,
    FaFieldObservation,
    FaScanResult,
)
from tests.fa_forensic_helpers import (
    DOC_BODY,
    OBSERVATION_BODY,
    SCAN_BODY,
    create_engagement,
    make_context,
)


@pytest.mark.parametrize("terminal_status", ["delivered", "cancelled"])
def test_terminal_engagement_rejects_evidence_mutations(
    build_app: object, terminal_status: str
) -> None:
    """Delivered and cancelled engagements must reject new scans, documents, and observations without inserts."""
    ctx = make_context(build_app)
    engagement = create_engagement(ctx.client_a)
    with Session(ctx.engine) as session:
        row = session.get(FaEngagement, engagement["id"])
        assert row is not None
        row.status = terminal_status
        session.commit()

    responses = [
        ctx.client_a.post(
            f"/field-assessment/engagements/{engagement['id']}/scan-results",
            json=SCAN_BODY,
        ),
        ctx.client_a.post(
            f"/field-assessment/engagements/{engagement['id']}/document-analyses",
            json=DOC_BODY,
        ),
        ctx.client_a.post(
            f"/field-assessment/engagements/{engagement['id']}/observations",
            json=OBSERVATION_BODY,
        ),
    ]
    assert [response.status_code for response in responses] == [409, 409, 409]
    with Session(ctx.engine) as session:
        assert session.scalar(select(func.count(FaScanResult.id))) == 0
        assert session.scalar(select(func.count(FaDocumentAnalysis.id))) == 0
        assert session.scalar(select(func.count(FaFieldObservation.id))) == 0


def test_second_cancel_transition_is_rejected_without_second_state_change(
    build_app: object,
) -> None:
    """Only the first in_progress-to-cancelled transition may succeed."""
    ctx = make_context(build_app)
    engagement = create_engagement(ctx.client_a)
    url = f"/field-assessment/engagements/{engagement['id']}/status"
    first = ctx.client_a.patch(
        url, json={"new_status": "cancelled", "reason": "auditor race request one"}
    )
    second = ctx.client_a.patch(
        url, json={"new_status": "cancelled", "reason": "auditor race request two"}
    )
    assert first.status_code == 200, first.text
    assert second.status_code == 409, second.text
    with Session(ctx.engine) as session:
        row = session.get(FaEngagement, engagement["id"])
        assert row is not None
        assert row.status == "cancelled"
