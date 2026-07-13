from __future__ import annotations

from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaEngagementAuditEvent
from tests.fa_forensic_helpers import (
    create_engagement,
    create_observation,
    make_context,
)


def test_audit_events_accumulate_and_observation_diff_is_specific(
    build_app: object,
) -> None:
    """Distinct writes must append audit rows and preserve the observation title diff."""
    ctx = make_context(build_app)
    engagement = create_engagement(ctx.client_a)
    observation = create_observation(ctx.client_a, engagement["id"])
    patch = ctx.client_a.patch(
        f"/field-assessment/engagements/{engagement['id']}/observations/{observation['id']}",
        json={"title": "Changed under audit"},
    )
    deleted = ctx.client_a.delete(
        f"/field-assessment/engagements/{engagement['id']}/observations/{observation['id']}"
    )
    events = ctx.client_a.get(
        f"/field-assessment/engagements/{engagement['id']}/audit-events"
    )
    assert patch.status_code == 200, patch.text
    assert deleted.status_code == 204, deleted.text
    assert events.status_code == 200, events.text
    payload = events.json()
    event_types = [event["event_type"] for event in payload]

    assert len(payload) == 5
    assert set(event_types) == {
        "engagement.created",
        "trust_validation_warning",
        "observation.captured",
        "observation.updated",
        "observation.deleted",
    }
    assert all(
        event["event_type"] and event["actor"] and event["created_at"]
        for event in events.json()
    )
    updated = next(
        event for event in events.json() if event["event_type"] == "observation.updated"
    )
    assert updated["payload"]["before"]["title"] == observation["title"]
    assert updated["payload"]["after"]["title"] == "Changed under audit"
    with Session(ctx.engine) as session:
        assert session.query(FaEngagementAuditEvent).count() == 5
