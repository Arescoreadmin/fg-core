from __future__ import annotations

from sqlalchemy.orm import Session

from tests.fa_forensic_helpers import (
    TENANT_A,
    create_engagement,
    insert_finding,
    make_context,
)


def test_roadmap_excludes_resolved_findings_and_is_deterministic(
    build_app: object,
) -> None:
    """The remediation roadmap must be deterministic and exclude findings already marked closed."""
    ctx = make_context(build_app)
    engagement = create_engagement(ctx.client_a)
    with Session(ctx.engine) as session:
        active = insert_finding(
            session,
            tenant_id=TENANT_A,
            engagement_id=engagement["id"],
            marker="active",
            severity="critical",
        )
        resolved = insert_finding(
            session,
            tenant_id=TENANT_A,
            engagement_id=engagement["id"],
            marker="resolved",
            severity="high",
            status="closed",
        )
        active_id = active.id
        resolved_id = resolved.id
    url = f"/field-assessment/engagements/{engagement['id']}/remediation-roadmap"
    first = ctx.client_a.get(url)
    second = ctx.client_a.get(url)
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert first.json() == second.json()
    roadmap_ids = {
        finding["finding_id"]
        for phase in first.json()["phases"]
        for finding in phase["findings"]
    }
    assert active_id in roadmap_ids
    assert resolved_id not in roadmap_ids
    assert all(phase["findings"] for phase in first.json()["phases"])
