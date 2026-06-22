from __future__ import annotations

from sqlalchemy.orm import Session

from tests.fa_forensic_helpers import (
    TENANT_A,
    create_engagement,
    insert_finding,
    make_context,
)


def test_findings_offset_pages_cover_exactly_all_rows(build_app: object) -> None:
    """Offset pagination must return 110 distinct findings with no silent truncation or duplication."""
    ctx = make_context(build_app)
    engagement = create_engagement(ctx.client_a)
    with Session(ctx.engine) as session:
        for index in range(110):
            insert_finding(
                session,
                tenant_id=TENANT_A,
                engagement_id=engagement["id"],
                marker=f"page-{index:03d}",
            )
    ids: list[str] = []
    for offset in (0, 50, 100):
        response = ctx.client_a.get(
            f"/field-assessment/engagements/{engagement['id']}/findings",
            params={"limit": 50, "offset": offset},
        )
        assert response.status_code == 200, response.text
        ids.extend(item["id"] for item in response.json()["items"])
    assert len(ids) == 110
    assert len(set(ids)) == 110


def test_findings_invalid_limit_is_rejected_and_boundary_page_is_empty(
    build_app: object,
) -> None:
    """Invalid limits must fail validation while a valid out-of-range offset returns an empty page."""
    ctx = make_context(build_app)
    engagement = create_engagement(ctx.client_a)
    zero = ctx.client_a.get(
        f"/field-assessment/engagements/{engagement['id']}/findings",
        params={"limit": 0},
    )
    negative = ctx.client_a.get(
        f"/field-assessment/engagements/{engagement['id']}/findings",
        params={"limit": -1},
    )
    boundary = ctx.client_a.get(
        f"/field-assessment/engagements/{engagement['id']}/findings",
        params={"offset": 1000},
    )
    assert zero.status_code == 422, zero.text
    assert negative.status_code == 422, negative.text
    assert boundary.status_code == 200, boundary.text
    assert boundary.json()["items"] == []
