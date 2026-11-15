"""MSP-002 — read-only multi-client portfolio, relationship views and history.

Every tenant, principal, credential and record here is synthetic. The actor
transport is the same as MSP-001 (tests/security/test_msp_001_foundation.py):
an API key bound to the actor's tenant plus an ActorContext override. Every
authority decision under test is DB-canonical. The console's real transport
(admin gateway + HMAC delegation proof) is covered separately in
tests/security/test_msp_002_console_transport.py.

Scenario numbers refer to the MSP-002 mission (Phase 12).
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from sqlalchemy import text
from starlette.testclient import TestClient

from tests.security.test_msp_001_foundation import (
    CUST_1,
    CUST_2,
    CUST_3,
    MSP_A,
    READ_CAPS,
    World,
    _now,
)

ASSESS_CAPS = ["assessment.read", "finding.read", "evidence.read"]


@pytest.fixture
def app(build_app):
    return build_app(auth_enabled=True, api_key="")


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


@pytest.fixture
def engine(app):
    from api.db import get_engine

    return get_engine()


@pytest.fixture
def w(app, client, engine) -> World:
    return World(app, client, engine)


# ---------------------------------------------------------------------------
# Synthetic customer assessment data (field-assessment substrate)
# ---------------------------------------------------------------------------


def _seed_engagement(engine, tenant: str, status: str, updated_at: str) -> str:
    eid = f"eng-{uuid.uuid4().hex[:12]}"
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO fa_engagements (id, tenant_id, client_name, assessor_id,"
                " assessment_type, status, engagement_metadata, schema_version,"
                " created_at, updated_at) VALUES (:id, :t, :name, 'assessor-x',"
                " 'ai_governance', :s, '{}', '1.0', :u, :u)"
            ),
            {
                "id": eid,
                "t": tenant,
                "name": f"SECRET-NAME-{tenant}",
                "s": status,
                "u": updated_at,
            },
        )
    return eid


def _seed_finding(
    engine, tenant: str, engagement_id: str, severity: str, status: str, updated_at: str
) -> None:
    fid = f"fnd-{uuid.uuid4().hex[:12]}"
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO fa_normalized_findings (id, tenant_id, engagement_id,"
                " finding_type, findings_hash, severity, status, title, description,"
                " source_attribution, confidence_score, framework_mappings,"
                " nist_ai_rmf_mappings, evidence_ref_ids, schema_version, created_at,"
                " updated_at) VALUES (:id, :t, :e, 'policy_gap', :h, :sev, :st,"
                " :title, 'SECRET-DESCRIPTION', 'synthetic', 80, '[]', '[]', '[]',"
                " '1.0', :u, :u)"
            ),
            {
                "id": fid,
                "t": tenant,
                "e": engagement_id,
                "h": uuid.uuid4().hex,
                "sev": severity,
                "st": status,
                "title": f"SECRET-TITLE-{tenant}",
                "u": updated_at,
            },
        )


def _seed_customer_one(w: World) -> None:
    e1 = _seed_engagement(w.engine, CUST_1, "in_progress", "2026-11-10T10:00:00Z")
    _seed_engagement(w.engine, CUST_1, "delivered", "2026-11-11T09:00:00Z")
    _seed_finding(w.engine, CUST_1, e1, "high", "open", "2026-11-12T08:00:00Z")
    _seed_finding(w.engine, CUST_1, e1, "low", "acknowledged", "2026-11-12T07:00:00Z")
    _seed_finding(w.engine, CUST_1, e1, "critical", "closed", "2026-11-09T07:00:00Z")


def _seed_customer_two(w: World) -> None:
    e = _seed_engagement(w.engine, CUST_2, "remediation", "2026-11-01T10:00:00Z")
    for _ in range(4):
        _seed_finding(w.engine, CUST_2, e, "critical", "open", "2026-11-02T10:00:00Z")


def _portfolio(w: World, who, **params):
    query = "&".join(f"{k}={v}" for k, v in params.items())
    return w.call(who, "GET", "/admin/msp/portfolio" + (f"?{query}" if query else ""))


def _items(resp) -> dict[str, dict]:
    assert resp.status_code == 200, resp.text
    return {i["customer_tenant_id"]: i for i in resp.json()["items"]}


def _expire(w: World, rid: str) -> None:
    from api.db import get_sessionmaker
    from api.db_models_msp import MspServiceRelationship

    db = get_sessionmaker()()
    try:
        row = db.get(MspServiceRelationship, rid)
        row.effective_at = _now() - timedelta(days=3)
        row.expires_at = _now() - timedelta(days=1)
        db.commit()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 1-5. Only approved customers appear; nothing for pending or foreign
# ---------------------------------------------------------------------------


def test_01_03_05_portfolio_lists_only_customer_approved_relationships(w):
    w.establish(w.msp_a_admin, w.c1_admin, req=ASSESS_CAPS, auth=ASSESS_CAPS)
    pending = w.propose(w.msp_a_admin, CUST_2, ASSESS_CAPS)
    assert pending.status_code == 200
    _seed_customer_one(w)
    _seed_customer_two(w)

    items = _items(_portfolio(w, w.msp_a_admin))
    assert list(items) == [CUST_1]  # pending CUST_2 is not authorized
    item = items[CUST_1]
    assert item["relationship_status"] == "active"
    assert item["display_name"] == f"Synthetic {CUST_1}"
    assert item["effective_permissions"] == sorted(ASSESS_CAPS)
    assert item["expires_at"]


def test_02_msp_cannot_see_another_msps_customers(w):
    w.establish(w.msp_a_admin, w.c1_admin, req=ASSESS_CAPS, auth=ASSESS_CAPS)
    _seed_customer_one(w)
    assert _items(_portfolio(w, w.msp_b_admin)) == {}
    assert _items(_portfolio(w, w.msp_b_staff)) == {}


def test_customer_tenant_is_not_an_msp_portfolio(w):
    w.establish(w.msp_a_admin, w.c1_admin, req=ASSESS_CAPS, auth=ASSESS_CAPS)
    resp = _portfolio(w, w.c1_admin)
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"] == {"code": "MSP_ACCESS_DENIED"}


# ---------------------------------------------------------------------------
# 4, 14, 32. Summaries are gated per customer, per capability
# ---------------------------------------------------------------------------


def test_04_14_32_summary_sections_follow_delegated_capabilities(w):
    w.establish(w.msp_a_admin, w.c1_admin, req=ASSESS_CAPS, auth=["evidence.read"])
    w.establish(w.msp_a_admin, w.c2_admin, req=ASSESS_CAPS, auth=["assessment.read"])
    _seed_customer_one(w)
    _seed_customer_two(w)

    items = _items(_portfolio(w, w.msp_a_admin))
    c1, c2 = items[CUST_1], items[CUST_2]
    # Listed (relationship metadata) but no posture without the capability.
    assert c1["assessment"] == {"state": "not_authorized"}
    assert c1["findings"] == {"state": "not_authorized"}
    assert c2["assessment"]["state"] == "available"
    assert c2["findings"] == {"state": "not_authorized"}
    assert "governance" not in c1 and "governance" not in c2


def test_summary_counts_come_from_the_assessment_substrate(w):
    w.establish(w.msp_a_admin, w.c1_admin, req=ASSESS_CAPS, auth=ASSESS_CAPS)
    _seed_customer_one(w)

    c1 = _items(_portfolio(w, w.msp_a_admin))[CUST_1]
    assert c1["assessment"] == {
        "state": "available",
        "engagements_by_status": {"delivered": 1, "in_progress": 1},
        "observed": 2,
        "truncated": False,
        "last_activity_at": "2026-11-11T09:00:00Z",
    }
    assert c1["findings"] == {
        "state": "available",
        "outstanding_by_severity": {"high": 1, "low": 1},
        "outstanding_total": 2,
        "observed": 3,
        "truncated": False,
        "last_activity_at": "2026-11-12T08:00:00Z",
    }


def test_absent_data_is_not_configured_never_zero(w):
    w.establish(w.msp_a_admin, w.c1_admin, req=ASSESS_CAPS, auth=ASSESS_CAPS)
    c1 = _items(_portfolio(w, w.msp_a_admin))[CUST_1]
    assert c1["assessment"] == {"state": "not_configured"}
    assert c1["findings"] == {"state": "not_configured"}


def test_summaries_never_carry_customer_records(w):
    w.establish(w.msp_a_admin, w.c1_admin, req=ASSESS_CAPS, auth=ASSESS_CAPS)
    _seed_customer_one(w)
    resp = _portfolio(w, w.msp_a_admin)
    assert resp.status_code == 200, resp.text
    assert resp.json()["items"][0]["findings"]["state"] == "available"
    body = resp.text
    for secret in ("SECRET-TITLE", "SECRET-DESCRIPTION", "SECRET-NAME", "eng-", "fnd-"):
        assert secret not in body, secret


# ---------------------------------------------------------------------------
# 13, 33. No cross-customer aggregation or reuse
# ---------------------------------------------------------------------------


def test_13_33_each_customer_summary_is_its_own_tenants_data(w):
    w.establish(w.msp_a_admin, w.c1_admin, req=ASSESS_CAPS, auth=ASSESS_CAPS)
    w.establish(w.msp_b_admin, w.c2_admin, req=ASSESS_CAPS, auth=ASSESS_CAPS)
    _seed_customer_one(w)
    _seed_customer_two(w)

    a = _items(_portfolio(w, w.msp_a_admin))
    b = _items(_portfolio(w, w.msp_b_admin))
    assert list(a) == [CUST_1] and list(b) == [CUST_2]
    assert a[CUST_1]["findings"]["outstanding_by_severity"] == {"high": 1, "low": 1}
    assert b[CUST_2]["findings"]["outstanding_by_severity"] == {"critical": 4}
    # A second MSP-A request after MSP-B's sees exactly the same (no reuse).
    assert _items(_portfolio(w, w.msp_a_admin)) == a


# ---------------------------------------------------------------------------
# 6-10, 33. Every way access ends removes the customer on the next request
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "end",
    ["suspend", "revoke_customer", "revoke_msp", "expire", "remove_member", "partner"],
)
def test_06_10_portfolio_drops_customer_on_the_next_request(w, end):
    rid = w.establish(w.msp_a_admin, w.c1_admin, req=ASSESS_CAPS, auth=ASSESS_CAPS)
    _seed_customer_one(w)
    assert list(_items(_portfolio(w, w.msp_a_staff))) == [CUST_1]

    if end == "suspend":
        assert w.act(w.c1_admin, rid, "suspend").status_code == 200
    elif end == "revoke_customer":
        assert w.act(w.c1_admin, rid, "revoke").status_code == 200
    elif end == "revoke_msp":
        assert w.act(w.msp_a_admin, rid, "revoke").status_code == 200
    elif end == "expire":
        _expire(w, rid)
    elif end == "remove_member":
        w.sql(
            "UPDATE tenant_users SET active = 0 WHERE id = :id",
            id=w.msp_a_staff.membership_id,
        )
    elif end == "partner":
        assert w.designate(MSP_A, "suspended").status_code == 200

    resp = _portfolio(w, w.msp_a_staff)
    if end in ("remove_member", "partner"):
        assert resp.status_code in (403, 404), resp.text
    else:
        assert _items(resp) == {}
    assert w.context(w.msp_a_staff, CUST_1).status_code in (403, 404)


# ---------------------------------------------------------------------------
# 11-12. Context selection and tenant headers cannot change authority
# ---------------------------------------------------------------------------


def test_11_context_selection_grants_nothing_beyond_the_portfolio(w):
    w.establish(w.msp_a_admin, w.c1_admin, req=ASSESS_CAPS, auth=["assessment.read"])
    before = _items(_portfolio(w, w.msp_a_staff))[CUST_1]
    ctx = w.context(w.msp_a_staff, CUST_1)
    assert ctx.status_code == 200
    assert ctx.json()["effective_permissions"] == before["effective_permissions"]
    after = _items(_portfolio(w, w.msp_a_staff))[CUST_1]
    assert after["effective_permissions"] == ["assessment.read"]
    assert after["findings"] == {"state": "not_authorized"}


def test_12_tenant_header_and_query_cannot_select_the_caller(w):
    w.establish(w.msp_a_admin, w.c1_admin, req=ASSESS_CAPS, auth=ASSESS_CAPS)
    spoofed = w.call(
        w.msp_b_admin,
        "GET",
        f"/admin/msp/portfolio?tenant_id={MSP_A}",
        extra_headers={"X-Tenant-Id": MSP_A},
    )
    assert spoofed.status_code in (400, 403, 422) or _items(spoofed) == {}
    assert CUST_1 not in spoofed.text


# ---------------------------------------------------------------------------
# 15. Pagination
# ---------------------------------------------------------------------------


def test_15_pagination_is_stable_and_bounded(w):
    for admin in (w.c3_admin, w.c1_admin, w.c2_admin):
        w.establish(w.msp_a_admin, admin, req=ASSESS_CAPS, auth=ASSESS_CAPS)

    first = _portfolio(w, w.msp_a_admin, limit=2, offset=0).json()
    second = _portfolio(w, w.msp_a_admin, limit=2, offset=2).json()
    assert [i["customer_tenant_id"] for i in first["items"]] == [CUST_1, CUST_2]
    assert [i["customer_tenant_id"] for i in second["items"]] == [CUST_3]
    assert first["total"] == second["total"] == 3
    assert first["next_offset"] == 2 and second["next_offset"] is None
    for bad in ({"limit": 0}, {"limit": 51}, {"offset": -1}):
        assert _portfolio(w, w.msp_a_admin, **bad).status_code == 422


# ---------------------------------------------------------------------------
# 16. A failing source for one customer never affects another
# ---------------------------------------------------------------------------


def test_16_partial_failure_is_isolated_per_customer(w, monkeypatch):
    w.establish(w.msp_a_admin, w.c1_admin, req=ASSESS_CAPS, auth=ASSESS_CAPS)
    w.establish(w.msp_a_admin, w.c2_admin, req=ASSESS_CAPS, auth=ASSESS_CAPS)
    _seed_customer_one(w)
    _seed_customer_two(w)

    import services.field_assessment.store as store

    real = store.list_engagements

    def _flaky(db, *, tenant_id, **kwargs):
        if tenant_id == CUST_1:
            raise RuntimeError("synthetic outage")
        return real(db, tenant_id=tenant_id, **kwargs)

    monkeypatch.setattr(store, "list_engagements", _flaky)
    resp = _portfolio(w, w.msp_a_admin)
    items = _items(resp)
    assert items[CUST_1]["assessment"] == {"state": "unavailable"}
    assert items[CUST_1]["findings"]["outstanding_by_severity"] == {"high": 1, "low": 1}
    assert items[CUST_2]["assessment"]["engagements_by_status"] == {"remediation": 1}
    assert "synthetic outage" not in resp.text


# ---------------------------------------------------------------------------
# 25. Portfolio reads are attributable in the customer's own chain
# ---------------------------------------------------------------------------


def test_25_portfolio_reads_are_audited_on_customer_chains(w):
    from api.db import get_sessionmaker, set_tenant_context
    from api.identity.store import verify_identity_audit_chain

    w.establish(w.msp_a_admin, w.c1_admin, req=ASSESS_CAPS, auth=ASSESS_CAPS)
    w.establish(w.msp_a_admin, w.c2_admin, req=ASSESS_CAPS, auth=["evidence.read"])
    _seed_customer_one(w)
    assert _portfolio(w, w.msp_a_staff).status_code == 200

    rows = w.sql(
        "SELECT tenant_id, actor_user_id, membership_id, details_json FROM"
        " tenant_identity_audit_events WHERE event_type ="
        " 'tenant.msp.portfolio_summary_accessed'"
    ).fetchall()
    # CUST_2 delegated no summary capability, so nothing was read or logged.
    assert [r.tenant_id for r in rows] == [CUST_1]
    row = rows[0]
    assert row.actor_user_id == w.msp_a_staff.subject
    assert row.membership_id == w.msp_a_staff.membership_id
    import json

    details = (
        json.loads(row.details_json)
        if isinstance(row.details_json, str)
        else row.details_json
    )
    assert details["msp_tenant_id"] == MSP_A
    assert details["operation"] == "portfolio.summary"
    assert details["capabilities"] == ["assessment.read", "finding.read"]

    db = get_sessionmaker()()
    try:
        for tenant in (CUST_1, MSP_A):
            set_tenant_context(db, tenant)
            assert verify_identity_audit_chain(db, tenant)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 24. Revocation leaves customer records intact
# ---------------------------------------------------------------------------


def test_24_revocation_leaves_customer_assessment_records(w):
    rid = w.establish(w.msp_a_admin, w.c1_admin, req=ASSESS_CAPS, auth=ASSESS_CAPS)
    _seed_customer_one(w)
    assert w.act(w.c1_admin, rid, "revoke").status_code == 200
    counts = w.sql(
        "SELECT (SELECT COUNT(*) FROM fa_engagements WHERE tenant_id = :t),"
        " (SELECT COUNT(*) FROM fa_normalized_findings WHERE tenant_id = :t)",
        t=CUST_1,
    ).fetchone()
    assert tuple(counts) == (2, 3)


# ---------------------------------------------------------------------------
# 26. Legacy control-plane delegation records grant nothing
# ---------------------------------------------------------------------------


def test_26_legacy_delegation_records_grant_no_msp_authority(w):
    from api.db import get_sessionmaker
    from api.db_models_cp_v2 import ControlPlaneMSPDelegation

    db = get_sessionmaker()()
    try:
        db.add(
            ControlPlaneMSPDelegation(
                delegator_id=w.c3_admin.subject,
                delegatee_id=w.msp_a_staff.subject,
                target_tenant=CUST_3,
                scope="control-plane:read",
                expires_at=_now() + timedelta(hours=1),
                revoked=False,
            )
        )
        db.commit()
    finally:
        db.close()
    assert _items(_portfolio(w, w.msp_a_staff)) == {}
    resp = w.context(w.msp_a_staff, CUST_3)
    assert resp.status_code == 404
    assert resp.json()["detail"] == {"code": "MSP_CUSTOMER_NOT_FOUND"}


# ---------------------------------------------------------------------------
# 31, 34. Relationship list: counterparty names and paging
# ---------------------------------------------------------------------------


def _relationships(w: World, who, **params):
    query = "&".join(f"{k}={v}" for k, v in params.items())
    resp = w.call(
        who, "GET", "/admin/msp/relationships" + (f"?{query}" if query else "")
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_31_msp_never_learns_an_unapproved_customers_name(w):
    rid = w.propose(w.msp_a_admin, CUST_1, ASSESS_CAPS).json()["relationship_id"]

    msp_view = _relationships(w, w.msp_a_admin)["items"][0]
    assert msp_view["counterparty_display_name"] is None
    assert f"Synthetic {CUST_1}" not in str(msp_view)

    cust_view = _relationships(w, w.c1_admin)["items"][0]
    assert cust_view["party"] == "customer"
    assert cust_view["counterparty_display_name"] == f"Synthetic {MSP_A}"

    assert w.approve(w.c1_admin, rid, ASSESS_CAPS).status_code == 200
    msp_view = _relationships(w, w.msp_a_admin)["items"][0]
    assert msp_view["counterparty_display_name"] == f"Synthetic {CUST_1}"


def test_organization_id_is_an_identifier_not_a_credential(w):
    """Founder decision (MSP-002 closure): /partners shows a customer's own
    organization id so it can be shared with an MSP. Knowing that id must not
    bypass customer approval, disclose tenant details, or grant access."""
    customer_name = f"Synthetic {CUST_1}"

    # An organization that is not a designated MSP gets nothing from the id.
    stranger = w.propose(w.c2_admin, CUST_1, ASSESS_CAPS)
    assert stranger.status_code == 403, stranger.text
    # MSP staff without tenant_admin cannot use it either.
    assert w.propose(w.msp_a_staff, CUST_1, ASSESS_CAPS).status_code == 403
    assert _relationships(w, w.c1_admin)["total"] == 0

    # A designated MSP admin can only ask; the request carries no authority
    # and no customer details.
    proposed = w.propose(w.msp_a_admin, CUST_1, ASSESS_CAPS)
    assert proposed.status_code == 200, proposed.text
    body = proposed.json()
    assert body["status"] == "proposed"
    assert body["authorized_capabilities"] == []
    assert customer_name not in proposed.text
    rid = body["relationship_id"]

    # Until the customer approves, the id opens nothing, and the denial is
    # indistinguishable from an id that does not exist.
    unknown = w.context(w.msp_a_admin, "no-such-tenant")
    for who in (w.msp_a_admin, w.msp_a_staff):
        denied = w.context(who, CUST_1)
        assert denied.status_code == 404
        assert denied.json() == unknown.json()
    assert CUST_1 not in w.customer_ids(w.msp_a_admin)
    page = w.call(w.msp_a_admin, "GET", "/admin/msp/portfolio")
    assert page.status_code == 200, page.text
    assert page.json()["items"] == []
    assert customer_name not in page.text
    # Presenting the id as the caller's tenant is refused outright.
    spoofed = w.call(
        w.msp_a_admin,
        "GET",
        "/admin/msp/portfolio",
        extra_headers={"X-Tenant-ID": CUST_1},
    )
    assert spoofed.status_code == 403
    assert customer_name not in spoofed.text
    msp_view = _relationships(w, w.msp_a_admin)["items"][0]
    assert msp_view["counterparty_display_name"] is None

    # Holding the id never lets the MSP side approve its own request.
    for who in (w.msp_a_admin, w.msp_a_staff):
        assert w.approve(who, rid, ASSESS_CAPS).status_code == 403
    assert _relationships(w, w.c1_admin)["items"][0]["status"] == "proposed"


def test_34_customer_admin_reaches_its_own_queue_and_others_do_not(w):
    w.propose(w.msp_a_admin, CUST_1, ASSESS_CAPS)
    w.propose(w.msp_b_admin, CUST_1, ASSESS_CAPS)
    assert _relationships(w, w.c1_admin)["total"] == 2
    assert _relationships(w, w.c2_admin)["total"] == 0
    resp = w.call(w.c1_member, "GET", "/admin/msp/relationships")
    assert resp.status_code == 403


def test_relationship_list_paging_is_bounded(w):
    for admin in (w.msp_a_admin, w.msp_b_admin):
        w.propose(admin, CUST_1, ASSESS_CAPS)
    page = _relationships(w, w.c1_admin, limit=1, offset=0)
    assert len(page["items"]) == 1 and page["total"] == 2 and page["next_offset"] == 1
    assert _relationships(w, w.c1_admin, limit=1, offset=1)["next_offset"] is None
    for bad in ({"limit": 0}, {"limit": 201}, {"offset": -1}):
        q = "&".join(f"{k}={v}" for k, v in bad.items())
        assert (
            w.call(w.c1_admin, "GET", f"/admin/msp/relationships?{q}").status_code
            == 422
        )


# ---------------------------------------------------------------------------
# 25, 31. Relationship history from the caller's own chain
# ---------------------------------------------------------------------------


def _events(w: World, who, rid: str):
    return w.call(who, "GET", f"/admin/msp/relationships/{rid}/events")


def test_history_shows_lifecycle_without_the_other_partys_subjects(w):
    rid = w.establish(w.msp_a_admin, w.c1_admin, req=ASSESS_CAPS, auth=ASSESS_CAPS)
    assert w.context(w.msp_a_staff, CUST_1).status_code == 200
    assert w.act(w.c1_admin, rid, "suspend").status_code == 200

    cust = _events(w, w.c1_admin, rid)
    assert cust.status_code == 200, cust.text
    body = cust.json()
    assert body["chain_verified"] is True
    ops = [e["operation"] for e in body["items"]]
    assert ops == [
        "relationship.suspend",
        "context.resolve",
        "relationship.approve",
        "relationship.propose",
    ]
    by_op = {e["operation"]: e for e in body["items"]}
    assert by_op["relationship.propose"]["actor_party"] == "msp"
    assert by_op["relationship.propose"]["actor_subject"] is None
    assert by_op["relationship.approve"]["actor_party"] == "customer"
    assert by_op["relationship.approve"]["actor_subject"] == w.c1_admin.subject
    assert w.msp_a_admin.subject not in cust.text
    assert w.msp_a_staff.subject not in cust.text

    msp = _events(w, w.msp_a_admin, rid).json()
    assert w.c1_admin.subject not in str(msp)
    assert {e["operation"] for e in msp["items"]} >= {
        "relationship.propose",
        "relationship.approve",
    }


def test_history_filters_by_relationship_before_paging(w):
    """Unrelated MSP events on the chain never push a relationship's history out."""
    from api.db import get_sessionmaker
    from api.msp_authority import emit_msp_audit

    rid = w.establish(w.msp_a_admin, w.c1_admin, req=ASSESS_CAPS, auth=ASSESS_CAPS)
    # More newer unrelated events than the old 2,000-row scan window.
    with get_sessionmaker()() as db:
        for _ in range(2001):
            emit_msp_audit(
                db,
                chains=(CUST_1,),
                restore_tenant=CUST_1,
                event_type="tenant.msp.portfolio_summary_accessed",
                actor_subject="synthetic-other",
                membership_id=None,
                reason_code="MSP_PORTFOLIO_SUMMARY_ACCESSED",
                msp_tenant_id="synthetic-msp",
                customer_tenant_id=CUST_1,
                relationship_id="synthetic-other-relationship",
                operation="portfolio.summary",
            )
        db.commit()

    full = _events(w, w.c1_admin, rid)
    assert full.status_code == 200, full.text
    body = full.json()
    assert [e["operation"] for e in body["items"]] == [
        "relationship.approve",
        "relationship.propose",
    ]
    assert body["total"] == 2 and body["next_offset"] is None
    assert "synthetic" not in full.text


def test_history_pages_reach_the_oldest_event(w):
    rid = w.establish(w.msp_a_admin, w.c1_admin, req=ASSESS_CAPS, auth=ASSESS_CAPS)
    assert w.context(w.msp_a_staff, CUST_1).status_code == 200
    assert w.act(w.c1_admin, rid, "suspend").status_code == 200
    whole = _events(w, w.c1_admin, rid).json()["items"]

    paged, offset = [], 0
    while offset is not None:
        resp = w.call(
            w.c1_admin,
            "GET",
            f"/admin/msp/relationships/{rid}/events?limit=1&offset={offset}",
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["total"] == 4 and len(body["items"]) == 1
        paged += body["items"]
        offset = body["next_offset"]
    assert paged == whole
    assert paged[-1]["operation"] == "relationship.propose"
    for bad in ("limit=0", "limit=201", "offset=-1"):
        assert (
            w.call(
                w.c1_admin, "GET", f"/admin/msp/relationships/{rid}/events?{bad}"
            ).status_code
            == 422
        )


def test_history_is_party_only(w):
    rid = w.establish(w.msp_a_admin, w.c1_admin, req=ASSESS_CAPS, auth=ASSESS_CAPS)
    for outsider in (w.c2_admin, w.msp_b_admin):
        resp = _events(w, outsider, rid)
        assert resp.status_code == 404
        assert resp.json()["detail"] == {"code": "MSP_RELATIONSHIP_NOT_FOUND"}
    assert _events(w, w.c1_member, rid).status_code == 403


# ---------------------------------------------------------------------------
# 18-23, 35. Approval semantics are MSP-001's, unchanged
# ---------------------------------------------------------------------------


def test_18_23_approval_rules_are_unchanged_by_msp_002(w):
    rid = w.propose(w.msp_a_admin, CUST_1, READ_CAPS).json()["relationship_id"]
    assert w.approve(w.msp_a_admin, rid).status_code == 403  # 18
    assert w.approve(w.c1_member, rid).status_code == 403  # 19
    bad = w.approve(w.c1_admin, rid, ["key.manage"])  # 21
    assert bad.status_code in (403, 422)
    too_long = w.approve(
        w.c1_admin, rid, expires_at=(_now() + timedelta(days=400)).isoformat()
    )
    assert too_long.status_code == 422  # 22
    assert w.approve(w.c1_admin, rid).status_code == 200  # 20
    assert w.approve(w.c1_admin, rid).status_code == 409  # 23
    assert w.act(w.c1_admin, rid, "revoke").json()["changed"] is True
    assert w.act(w.c1_admin, rid, "revoke").json()["changed"] is False
