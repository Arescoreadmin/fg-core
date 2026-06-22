from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaEngagement, FaScanResult
from tests.fa_forensic_helpers import SCAN_BODY, create_engagement, make_context


def test_delivered_engagement_lock_applies_to_connector_equivalent_scan_ingest(
    build_app: object,
) -> None:
    """Delivered engagements must not accept connector-equivalent scan evidence after delivery."""
    ctx = make_context(build_app)
    engagement = create_engagement(ctx.client_a)
    with Session(ctx.engine) as session:
        row = session.get(FaEngagement, engagement["id"])
        assert row is not None
        row.status = "delivered"
        session.commit()
    response = ctx.client_a.post(
        f"/field-assessment/engagements/{engagement['id']}/scan-results", json=SCAN_BODY
    )
    assert response.status_code == 409, response.text
    with Session(ctx.engine) as session:
        assert session.scalar(select(func.count(FaScanResult.id))) == 0
