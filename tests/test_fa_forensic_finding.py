from __future__ import annotations

from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaNormalizedFinding
from tests.fa_forensic_helpers import (
    TENANT_A,
    create_engagement,
    insert_finding,
    make_context,
)


def test_finding_filters_return_only_the_requested_intersection(
    build_app: object,
) -> None:
    """Severity and status filters must return the exact persisted intersection."""
    ctx = make_context(build_app)
    engagement = create_engagement(ctx.client_a)
    with Session(ctx.engine) as session:
        expected = insert_finding(
            session,
            tenant_id=TENANT_A,
            engagement_id=engagement["id"],
            marker="critical-open",
            severity="critical",
        )
        expected_id = expected.id
        insert_finding(
            session,
            tenant_id=TENANT_A,
            engagement_id=engagement["id"],
            marker="critical-closed",
            severity="critical",
            status="closed",
        )
        insert_finding(
            session,
            tenant_id=TENANT_A,
            engagement_id=engagement["id"],
            marker="high-open",
            severity="high",
        )
    response = ctx.client_a.get(
        f"/field-assessment/engagements/{engagement['id']}/findings",
        params={"severity": "critical", "status": "open"},
    )
    assert response.status_code == 200, response.text
    assert [item["id"] for item in response.json()["items"]] == [expected_id]


def test_finding_remediation_hint_patch_persists_to_db(build_app: object) -> None:
    """Remediation PATCH must persist the exact hint instead of acknowledging and dropping it."""
    ctx = make_context(build_app)
    engagement = create_engagement(ctx.client_a)
    with Session(ctx.engine) as session:
        finding = insert_finding(
            session, tenant_id=TENANT_A, engagement_id=engagement["id"], marker="hint"
        )
        finding_id = finding.id
    response = ctx.client_a.patch(
        f"/field-assessment/engagements/{engagement['id']}/findings/{finding_id}/remediation",
        json={
            "remediation_hint": "Patch identity policy and retain approval evidence."
        },
    )
    assert response.status_code == 200, response.text
    with Session(ctx.engine) as session:
        row = session.get(FaNormalizedFinding, finding_id)
        assert row is not None
        assert (
            row.remediation_hint
            == "Patch identity policy and retain approval evidence."
        )
