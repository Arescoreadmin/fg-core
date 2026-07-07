from __future__ import annotations

from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaEngagement
from api.db_models_governance_promotion import GovernancePromotion
from services.canonical import utc_iso8601_z_now
from services.field_assessment.promotion_drift import detect_readiness_drift
from tests.fa_forensic_helpers import TENANT_A, create_engagement, make_context


def test_drift_detection_reports_degraded_delta_against_prior_completed_promotion(
    build_app: object,
) -> None:
    """A lower reassessment score must produce an exact degraded delta against the prior completed promotion."""
    ctx = make_context(build_app)
    prior = create_engagement(ctx.client_a)
    current = create_engagement(ctx.client_a, client_name="Reassessment Corp")
    with Session(ctx.engine) as session:
        session.add(
            GovernancePromotion(
                id="prior-promotion",
                tenant_id=TENANT_A,
                engagement_id=prior["id"],
                status="completed",
                promoted_at=utc_iso8601_z_now(),
                completed_at=utc_iso8601_z_now(),
                baseline_readiness_score=80,
                gate_snapshot_json={},
            )
        )
        session.commit()
        drift = detect_readiness_drift(
            session, tenant_id=TENANT_A, engagement_id=current["id"], new_score=65
        )
        assert drift is not None
        assert drift.direction == "degraded"
        assert drift.delta == -15


def test_admin_promote_route_rejects_non_delivered_engagement_without_record(
    build_app: object,
) -> None:
    """Operator retry promotion must reject in-progress engagements without creating promotion state."""
    ctx = make_context(build_app)
    engagement = create_engagement(ctx.client_a)
    response = ctx.promote_client_a.post(
        f"/field-assessment/engagements/{engagement['id']}/promote"
    )
    assert response.status_code == 409, response.text
    with Session(ctx.engine) as session:
        assert session.query(GovernancePromotion).count() == 0
        stored_engagement = session.get(FaEngagement, engagement["id"])
        assert stored_engagement is not None
        assert stored_engagement.status == "in_progress"
