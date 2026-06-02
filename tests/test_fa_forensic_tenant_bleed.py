from __future__ import annotations

from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaEngagement, FaFieldObservation
from tests.fa_forensic_helpers import (
    OBSERVATION_BODY,
    TENANT_A,
    create_engagement,
    create_observation,
    make_context,
)


def test_cross_tenant_engagement_patch_cannot_change_metadata(
    build_app: object,
) -> None:
    """A tenant-B metadata patch must return 404 and preserve every mutable engagement field."""
    ctx = make_context(build_app)
    engagement = create_engagement(ctx.client_a)
    with Session(ctx.engine) as session:
        before = session.get(FaEngagement, engagement["id"])
        assert before is not None
        snapshot = (
            before.client_name,
            before.client_domain,
            before.status,
            before.engagement_metadata,
        )

    response = ctx.client_b.patch(
        f"/field-assessment/engagements/{engagement['id']}",
        json={"engagement_metadata": {"case": "tampered"}},
    )
    assert response.status_code == 404, response.text
    with Session(ctx.engine) as session:
        after = session.get(FaEngagement, engagement["id"])
        assert after is not None
        assert (
            after.client_name,
            after.client_domain,
            after.status,
            after.engagement_metadata,
        ) == snapshot


def test_cross_tenant_observation_update_and_delete_preserve_row(
    build_app: object,
) -> None:
    """Tenant-B cannot edit or soft-delete tenant-A observations."""
    ctx = make_context(build_app)
    engagement = create_engagement(ctx.client_a)
    observation = create_observation(ctx.client_a, engagement["id"])
    patch = ctx.client_b.patch(
        f"/field-assessment/engagements/{engagement['id']}/observations/{observation['id']}",
        json={"title": "tampered"},
    )
    delete = ctx.client_b.delete(
        f"/field-assessment/engagements/{engagement['id']}/observations/{observation['id']}"
    )
    assert patch.status_code == 404, patch.text
    assert delete.status_code == 404, delete.text
    with Session(ctx.engine) as session:
        row = session.get(FaFieldObservation, observation["id"])
        assert row is not None
        assert row.title == OBSERVATION_BODY["title"]
        assert row.deleted_at is None


def test_cross_tenant_finding_remediation_patch_preserves_hint(
    build_app: object,
) -> None:
    """Tenant-B remediation writes must not mutate tenant-A findings."""
    from tests.fa_forensic_helpers import insert_finding

    ctx = make_context(build_app)
    engagement = create_engagement(ctx.client_a)
    with Session(ctx.engine) as session:
        finding = insert_finding(
            session,
            tenant_id=TENANT_A,
            engagement_id=engagement["id"],
            marker="tenant-a",
        )
        finding_id = finding.id
    response = ctx.client_b.patch(
        f"/field-assessment/engagements/{engagement['id']}/findings/{finding_id}/remediation",
        json={"remediation_hint": "tampered"},
    )
    assert response.status_code == 404, response.text
    with Session(ctx.engine) as session:
        stored_finding = session.get(type(finding), finding_id)
        assert stored_finding is not None
        assert stored_finding.remediation_hint is None
