from __future__ import annotations

from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaFieldObservation
from tests.fa_forensic_helpers import (
    create_engagement,
    create_observation,
    make_context,
)


def test_soft_deleted_observation_remains_in_db_but_leaves_lists_and_summary(
    build_app: object,
) -> None:
    """Soft deletion must preserve the row while removing it from active API projections."""
    ctx = make_context(build_app)
    engagement = create_engagement(ctx.client_a)
    observation = create_observation(ctx.client_a, engagement["id"])
    before = ctx.client_a.get(
        f"/field-assessment/engagements/{engagement['id']}/summary"
    )
    deleted = ctx.client_a.delete(
        f"/field-assessment/engagements/{engagement['id']}/observations/{observation['id']}"
    )
    after = ctx.client_a.get(
        f"/field-assessment/engagements/{engagement['id']}/summary"
    )
    listed = ctx.client_a.get(
        f"/field-assessment/engagements/{engagement['id']}/observations"
    )
    assert before.status_code == 200 and before.json()["total_observations"] == 1
    assert deleted.status_code == 204, deleted.text
    assert after.status_code == 200 and after.json()["total_observations"] == 0
    assert listed.status_code == 200 and listed.json() == []
    with Session(ctx.engine) as session:
        row = session.get(FaFieldObservation, observation["id"])
        assert row is not None
        assert row.deleted_at is not None


def test_observation_patch_round_trips_structured_audio_and_audits_diff(
    build_app: object,
) -> None:
    """Observation PATCH must persist structured audio fields and audit old/new title values."""
    ctx = make_context(build_app)
    engagement = create_engagement(ctx.client_a)
    observation = create_observation(ctx.client_a, engagement["id"])
    evidence = {
        "_audio_url": "https://example.com/audio.webm",
        "_audio_hash": "abc",
        "_audio_duration_sec": 45,
        "_audio_size_kb": 1200,
    }
    patched = ctx.client_a.patch(
        f"/field-assessment/engagements/{engagement['id']}/observations/{observation['id']}",
        json={"title": "Audited title", "structured_evidence": evidence},
    )
    events = ctx.client_a.get(
        f"/field-assessment/engagements/{engagement['id']}/audit-events"
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["structured_evidence"] == evidence
    assert events.status_code == 200, events.text
    updated = next(
        event for event in events.json() if event["event_type"] == "observation.updated"
    )
    assert updated["payload"]["before"]["title"] == observation["title"]
    assert updated["payload"]["after"]["title"] == "Audited title"
