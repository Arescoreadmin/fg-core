"""CZ-17 — explicit backend policy for unreleased report content."""

from __future__ import annotations

from sqlalchemy import select

from tests.test_assessment_assurance.conftest import code, export, human, qa_reject
from tests.test_customer_zero_e2e import _northstar as N
from tests.test_customer_zero_e2e.test_customer_zero_journey import PORTAL


def _portal_customer(platform, eid: str):
    assessor = platform.client("assessor")
    grant = assessor.post(
        f"/field-assessment/engagements/{eid}/portal-grants", json={"ttl_days": 14}
    ).json()
    session = (
        platform.client("portal_bff")
        .post("/portal/authenticate", json={"secret": grant["raw_secret"]})
        .json()["session_id"]
    )
    return (
        platform.client("portal_bff", **PORTAL, **{"X-FG-Portal-Session": session}),
        grant,
    )


def _enable_customer_draft_review(platform, eid: str) -> None:
    r = platform.client("assessor").patch(
        f"/field-assessment/engagements/{eid}",
        json={
            "engagement_metadata": {
                "report_access_policy": {"customer_draft_review": True}
            }
        },
    )
    assert r.status_code == 200, r.text


def test_cz17_customer_cannot_download_unapproved_draft(platform, northstar):
    eid, v = northstar["eid"], northstar["report"]["version"]
    cust, _ = _portal_customer(platform, eid)
    for fmt in ("pdf", "json"):
        r = export(cust, eid, v, fmt)
        assert r.status_code == 403 and code(r) == "REPORT_DRAFT_ACCESS_DENIED"
        assert r.headers.get("cache-control") == "no-store"
    doc = cust.get(f"/field-assessment/engagements/{eid}/reports/{v}")
    assert doc.status_code == 403 and code(doc) == "REPORT_DRAFT_ACCESS_DENIED"
    # Listing metadata (no content) remains available to the customer.
    assert cust.get(f"/field-assessment/engagements/{eid}/reports").status_code == 200


def test_customer_roles_without_portal_header_are_still_denied(platform, northstar):
    eid, v = northstar["eid"], northstar["report"]["version"]
    for persona in ("customer_executive", "customer_security_admin", "portal_bff"):
        r = export(platform.client(persona), eid, v, "pdf")
        assert r.status_code == 403 and code(r) == "REPORT_DRAFT_ACCESS_DENIED", persona


def test_internal_assessment_team_can_review_marked_drafts(platform, northstar):
    eid, v = northstar["eid"], northstar["report"]["version"]
    for c in (platform.client("assessor"), human(platform)):
        r = export(c, eid, v, "pdf")
        assert r.status_code == 200, r.text
        assert r.headers["X-Report-State"] == "DRAFT_SYNTHETIC"
        assert "draft-synthetic" in r.headers["Content-Disposition"]
        assert "no-store" in r.headers["Cache-Control"]
        assert r.content.startswith(b"%PDF") and b"%%EOF" in r.content[-1024:]
        j = export(c, eid, v, "json").json()["report_state"]
        assert j["marking"] == N_SYNTH and j["access_basis"] == "INTERNAL_DRAFT_REVIEW"


N_SYNTH = "DRAFT — SYNTHETIC DATA — NOT VERIFIED"


def test_internal_draft_access_does_not_extend_through_the_portal(platform, northstar):
    """A portal-origin request is customer access even with an assessor key."""
    eid, v = northstar["eid"], northstar["report"]["version"]
    r = export(platform.client("assessor", **PORTAL), eid, v, "pdf")
    assert r.status_code in (403,)


def test_engagement_policy_can_permit_customer_draft_review(platform, northstar):
    eid, v = northstar["eid"], northstar["report"]["version"]
    # The customer cannot grant itself draft access.
    self_grant = platform.client("customer_security_admin").patch(
        f"/field-assessment/engagements/{eid}",
        json={
            "engagement_metadata": {
                "report_access_policy": {"customer_draft_review": True}
            }
        },
    )
    assert self_grant.status_code == 403
    _enable_customer_draft_review(platform, eid)
    cust, _ = _portal_customer(platform, eid)
    r = export(cust, eid, v, "pdf")
    assert r.status_code == 200, r.text
    assert r.headers["X-Report-State"] == "DRAFT_SYNTHETIC"  # never relabelled
    assert r.headers["X-Report-Version"] == str(v)
    listing = cust.get(f"/field-assessment/engagements/{eid}/reports").json()
    canonical = next(item for item in listing["items"] if item["version"] == v)
    assert r.headers["X-Report-ID"] == canonical["report_id"]
    assert r.headers["X-Manifest-Hash"] == canonical["manifest_hash"]
    st = export(cust, eid, v, "json").json()["report_state"]
    assert st["access_basis"] == "CUSTOMER_DRAFT_REVIEW_PERMITTED" and st["is_draft"]


def test_rejected_report_is_never_shown_to_customers(platform, northstar):
    eid, rep = northstar["eid"], northstar["report"]
    _enable_customer_draft_review(platform, eid)
    assert qa_reject(human(platform), eid, rep["report_id"]).status_code == 200
    cust, _ = _portal_customer(platform, eid)
    r = export(cust, eid, rep["version"], "pdf")
    assert r.status_code == 403 and code(r) == "REPORT_DRAFT_ACCESS_DENIED"


def test_revoked_grant_and_session_cannot_retrieve_drafts(platform, northstar):
    eid, v = northstar["eid"], northstar["report"]["version"]
    _enable_customer_draft_review(platform, eid)
    cust, grant = _portal_customer(platform, eid)
    assert export(cust, eid, v, "pdf").status_code == 200
    platform.client("assessor").delete(
        f"/field-assessment/engagements/{eid}/portal-grants/{grant['grant']['id']}"
    )
    assert export(cust, eid, v, "pdf").status_code == 403


def test_cross_tenant_and_cross_engagement_draft_access_denied(platform, northstar):
    from tests.test_customer_zero_e2e.test_customer_zero_journey import provision

    eid, v = northstar["eid"], northstar["report"]["version"]
    provision(platform, None, N.OTHER_TENANT, "Contoso Other (synthetic)")
    other = human(platform, "auth0|other-qa", tenant_id=N.OTHER_TENANT)
    assert export(other, eid, v, "pdf").status_code == 404
    # A grant for a different engagement does not open this one.
    other_eid = (
        platform.client("assessor")
        .post(
            "/field-assessment/engagements",
            json={
                "client_name": "Second (synthetic)",
                "assessor_id": "x",
                "assessment_type": "comprehensive",
            },
        )
        .json()["id"]
    )
    cust, _ = _portal_customer(platform, other_eid)
    assert export(cust, eid, v, "pdf").status_code == 403


def test_access_decisions_are_audited(platform, northstar):
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaEngagementAuditEvent

    eid, v = northstar["eid"], northstar["report"]["version"]
    cust, _ = _portal_customer(platform, eid)
    export(cust, eid, v, "pdf")
    export(platform.client("assessor"), eid, v, "pdf")
    db = get_sessionmaker()()
    try:
        rows = {
            r.event_type: r
            for r in db.execute(
                select(FaEngagementAuditEvent).where(
                    FaEngagementAuditEvent.engagement_id == eid,
                    FaEngagementAuditEvent.event_type.in_(
                        ["report.access_denied", "report.content_accessed"]
                    ),
                )
            ).scalars()
        }
        assert rows["report.access_denied"].payload["portal_origin"] is True
        assert rows["report.access_denied"].reason_code == "DRAFT_ACCESS_NOT_PERMITTED"
        assert (
            rows["report.content_accessed"].payload["access_basis"]
            == "INTERNAL_DRAFT_REVIEW"
        )
        assert "X-FG-Portal-Session" not in str(rows["report.access_denied"].payload)
    finally:
        db.close()
