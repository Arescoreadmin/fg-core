"""MSP-003 — partner-guided onboarding and assessment orchestration.

Numbered tests follow the MSP-003 acceptance matrix (``tNN`` in each name).
Every tenant, person, price and engagement is synthetic. There are no network
calls and no live billing. Postgres RLS proof is in
tests/test_migrations_postgres_replay.py (CI Migrations Replay job).

Authority model under test: an MSP-initiated assessment needs every one of

  MSP designation active  ∩  actor is the MSP's canonical tenant_admin
  ∩ MSP-001 relationship active  ∩  a customer-approved, unexpired, unused
  assessment grant  ∩  customer tenant active  ∩  MSP-006 payer resolves

at the moment of the call. Scope comes only from the grant.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from starlette.testclient import TestClient

from api.actor_context import ROLE_PERMISSIONS, ActorContext
from api.auth_scopes import mint_key
from tests.security.test_msp_001_foundation import (
    CUST_1,
    CUST_2,
    CUST_3,
    MSP_A,
    MSP_B,
    READ_CAPS,
    Person,
    World,
    _seed_person,
    _seed_tenant,
)
from tests.security.test_msp_006_billing import (
    _assign,
    _produce,
    _seed_agreement,
    _seed_meter,
    _seed_price,
    _usage_rows,
)

CAPS = sorted(READ_CAPS + ["assessment.read"])
GRANTS = "/admin/msp/assessments/grants"
ONBOARD = "/admin/msp/onboarding/requests"
PLATFORM_ONBOARD = "/admin/msp/platform/onboarding"


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


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _session():
    from api.db import get_sessionmaker

    return get_sessionmaker()()


# ---------------------------------------------------------------------------
# Flows
# ---------------------------------------------------------------------------


def _relate(w: World, msp_admin=None, cust_admin=None) -> str:
    return w.establish(
        msp_admin or w.msp_a_admin, cust_admin or w.c1_admin, req=CAPS, auth=CAPS
    )


def _entitle(w: World, rid: str, customer: str = CUST_1) -> None:
    """MSP-006 commercial authority: an MSP-paid payer assignment."""
    agreement = _seed_agreement(MSP_A)
    _seed_price(MSP_A)
    _seed_meter()
    resp = _assign(w, rid, agreement=agreement, customer=customer)
    assert resp.status_code == 200, resp.text


def _request(
    w: World,
    who=None,
    *,
    customer: str = CUST_1,
    key: str | None = None,
    assessment_type: str = "ai_governance",
    assessor_id: str = "assessor-msp-alpha-1",
    days: int = 30,
):
    return w.call(
        who or w.msp_a_admin,
        "POST",
        GRANTS,
        {
            "customer_tenant_id": customer,
            "request_key": key or f"req-{uuid.uuid4().hex[:12]}",
            "assessment_type": assessment_type,
            "assessor_id": assessor_id,
            "expires_at": (_now() + timedelta(days=days)).isoformat(),
        },
    )


def _decide(w: World, who, grant: dict, action: str, **extra):
    return w.call(
        who,
        "POST",
        f"{GRANTS}/{grant['grant_id']}/{action}",
        {"expected_version": grant["version"], **extra},
    )


def _initiate(w: World, grant_id: str, who=None):
    return w.call(who or w.msp_a_admin, "POST", f"{GRANTS}/{grant_id}/initiate", {})


def _approved_grant(w: World, *, entitle: bool = True) -> tuple[str, dict]:
    rid = _relate(w)
    if entitle:
        _entitle(w, rid)
    req = _request(w)
    assert req.status_code == 200, req.text
    ok = _decide(w, w.c1_admin, req.json(), "approve")
    assert ok.status_code == 200, ok.text
    return rid, ok.json()


def _grants(w: World, who, **params) -> list[dict]:
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    resp = w.call(who, "GET", f"{GRANTS}{'?' + qs if qs else ''}")
    assert resp.status_code == 200, resp.text
    return resp.json()["items"]


def _engagements(tenant: str) -> list[tuple[str, str]]:
    with _session() as db:
        rows = db.execute(
            text("SELECT id, status FROM fa_engagements WHERE tenant_id = :t"),
            {"t": tenant},
        ).fetchall()
    return [(r[0], r[1]) for r in rows]


def _set_grant(grant_id: str, **values) -> None:
    from api.db_models_msp import MspAssessmentGrant

    with _session() as db:
        db.query(MspAssessmentGrant).filter(MspAssessmentGrant.id == grant_id).update(
            values, synchronize_session=False
        )
        db.commit()


def _fa(w: World, who: Person, method: str, path: str, json=None, *, tenant=None):
    """A Field Assessment call with governance scopes, optionally forging the
    target tenant through X-Tenant-ID."""
    from api.auth_dispatch import get_actor_context

    def _actor() -> ActorContext:
        return ActorContext(
            subject=who.subject,
            email=f"{who.subject}@example.invalid",
            name=who.subject,
            permissions=ROLE_PERMISSIONS.get(who.role, frozenset()),
            roles=[who.role],
            auth_source="oidc_auth0",
            tenant_id=who.tenant,
            membership_id=who.membership_id or None,
        )

    w.app.dependency_overrides[get_actor_context] = _actor
    headers = {
        "x-api-key": mint_key(
            "governance:read", "governance:write", tenant_id=who.tenant
        )
    }
    if tenant:
        headers["X-Tenant-ID"] = tenant
    try:
        return w.client.request(method, path, json=json, headers=headers)
    finally:
        w.app.dependency_overrides.pop(get_actor_context, None)


def _code(resp) -> str:
    detail = resp.json().get("detail")
    if not isinstance(detail, dict):
        return str(detail)
    code = detail.get("code")
    # An error body without a string code is itself a contract failure.
    assert isinstance(code, str), detail
    return code


def _deliver_canonically(tenant: str, engagement_id: str) -> None:
    """What the QA-approval auto-advance writes when every gate has passed
    (qa_approve_report_route): status ``delivered`` and the canonical
    ``engagement.status_transitioned`` event. The full QA path is covered by
    the Field Assessment suites and MSP-006 test 17b."""
    from api.db_models_field_assessment import FaEngagement, FaEngagementAuditEvent

    stamp = (_now() + timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    with _session() as db:
        db.query(FaEngagement).filter(FaEngagement.id == engagement_id).update(
            {"status": "delivered", "updated_at": stamp}, synchronize_session=False
        )
        db.add(
            FaEngagementAuditEvent(
                id=uuid.uuid4().hex,
                tenant_id=tenant,
                engagement_id=engagement_id,
                event_type="engagement.status_transitioned",
                actor="synthetic-qa",
                reason_code="AUTO_ADVANCE_QA_APPROVED",
                payload={"new_status": "delivered"},
                created_at=stamp,
            )
        )
        db.commit()


def _chain_events(tenant: str, prefix: str = "tenant.msp.assessment") -> list:
    from api.db_models_identity import TenantIdentityAuditEvent

    with _session() as db:
        rows = (
            db.query(TenantIdentityAuditEvent)
            .filter(
                TenantIdentityAuditEvent.tenant_id == tenant,
                TenantIdentityAuditEvent.event_type.like(f"{prefix}%"),
            )
            .all()
        )
        return [
            (r.event_type, dict(r.details_json or {}), r.actor_user_id) for r in rows
        ]


# ---------------------------------------------------------------------------
# t01-t02. Direct customers are unchanged
# ---------------------------------------------------------------------------


def test_t01_direct_customer_lifecycle_and_relationships_unchanged(w):
    # A direct customer (no MSP) sees no grants and no onboarding records, and
    # the canonical platform-only invitation route still refuses an MSP admin.
    assert _grants(w, w.c3_admin) == []
    invite = w.call(
        w.msp_a_admin,
        "POST",
        f"/admin/tenants/{CUST_3}/invite-initial-admin",
        {"email": "x@example.invalid"},
    )
    assert invite.status_code in (403, 404)
    lifecycle = w.call(w.c3_admin, "GET", f"/admin/tenants/{CUST_3}/lifecycle")
    assert lifecycle.status_code != 500


def test_t02_direct_customer_creates_assessments_through_the_canonical_route(w, engine):
    assessor = _seed_person(engine, CUST_3, "c3-assessor", "assessor")
    resp = _fa(
        w,
        assessor,
        "POST",
        "/field-assessment/engagements",
        {
            "client_name": "Direct Co",
            "assessor_id": "assessor-direct",
            "assessment_type": "soc2",
        },
    )
    assert resp.status_code == 201, resp.text
    eid = resp.json()["id"]
    assert resp.json()["status"] == "in_progress"
    from api.db_models_field_assessment import FaEngagementAuditEvent

    with _session() as db:
        events = (
            db.query(FaEngagementAuditEvent)
            .filter(FaEngagementAuditEvent.engagement_id == eid)
            .all()
        )
        assert [e.event_type for e in events] == ["engagement.created"]
        assert "msp" not in events[0].payload


# ---------------------------------------------------------------------------
# t03-t06. Onboarding requests (new customers)
# ---------------------------------------------------------------------------


def _onboard(w, who=None, key="onb-1", name="Prospect Co", email="it@prospect.invalid"):
    return w.call(
        who or w.msp_a_admin,
        "POST",
        ONBOARD,
        {
            "request_key": key,
            "organization_name": name,
            "contact_email": email,
            "requested_capabilities": CAPS,
        },
    )


def test_t03_msp_can_request_onboarding(w):
    resp = _onboard(w)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["created"] is True
    assert body["status"] == "requested" and body["stage"] == "requested"
    assert body["customer_tenant_id"] is None
    listed = w.call(w.msp_a_admin, "GET", ONBOARD).json()["items"]
    assert [i["onboarding_request_id"] for i in listed] == [
        body["onboarding_request_id"]
    ]
    # Other MSPs and customers see nothing.
    assert w.call(w.msp_b_admin, "GET", ONBOARD).json()["items"] == []
    # Non-admin MSP staff cannot request.
    assert _onboard(w, w.msp_a_staff, key="onb-2").status_code == 403


def test_t04_msp_cannot_activate_or_link_a_customer(w):
    rid = _onboard(w).json()["onboarding_request_id"]
    # The MSP has no link, reject or provisioning route.
    for path in (
        f"{PLATFORM_ONBOARD}/{rid}/link",
        f"{PLATFORM_ONBOARD}/{rid}/reject",
    ):
        resp = w.call(
            w.msp_a_admin,
            "POST",
            path,
            {"msp_tenant_id": MSP_A, "customer_tenant_id": CUST_3},
        )
        assert resp.status_code == 403, resp.text
    create = w.call(
        w.msp_a_admin, "POST", "/admin/tenants", {"tenant_id": "msp-made-tenant"}
    )
    assert create.status_code in (403, 404, 422)
    # A suspended MSP cannot request onboarding at all.
    assert w.designate(MSP_A, "suspended").status_code == 200
    assert _onboard(w, key="onb-x").status_code == 403


def test_t05_customer_invitation_requires_canonical_platform_authority(w):
    rid = _onboard(w).json()["onboarding_request_id"]
    # The platform links only an existing, active customer tenant; the link
    # grants nothing and sends nothing.
    bad = w.call(
        w.platform,
        "POST",
        f"{PLATFORM_ONBOARD}/{rid}/link",
        {"msp_tenant_id": MSP_A, "customer_tenant_id": "no-such-tenant"},
    )
    assert bad.status_code == 404, bad.text
    ok = w.call(
        w.platform,
        "POST",
        f"{PLATFORM_ONBOARD}/{rid}/link",
        {"msp_tenant_id": MSP_A, "customer_tenant_id": CUST_3},
    )
    assert ok.status_code == 200, ok.text
    item = w.call(w.msp_a_admin, "GET", ONBOARD).json()["items"][0]
    assert item["status"] == "linked" and item["customer_tenant_id"] == CUST_3
    # CUST_3 has a bound admin, so the canonical lifecycle says accepted; no
    # relationship exists yet, so the MSP's next step is the MSP-001 proposal.
    assert item["stage"] == "customer_accepted"
    assert {"owner": "msp", "code": "PROPOSE_RELATIONSHIP"} in item["next_actions"]
    # Linking created no relationship and no grant.
    assert w.customer_ids(w.msp_a_admin) == []
    assert w.propose(w.msp_a_admin, CUST_3, CAPS).status_code == 200
    item = w.call(w.msp_a_admin, "GET", ONBOARD).json()["items"][0]
    assert item["stage"] == "awaiting_customer_approval"


def test_t06_onboarding_replay_is_idempotent(w):
    first = _onboard(w).json()
    again = _onboard(w)
    assert again.status_code == 200
    assert again.json()["onboarding_request_id"] == first["onboarding_request_id"]
    assert again.json()["created"] is False
    conflict = _onboard(w, name="Different Co")
    assert conflict.status_code == 409
    assert _code(conflict) == "MSP_ONBOARDING_REQUEST_CONFLICT"
    assert len(w.call(w.msp_a_admin, "GET", ONBOARD).json()["items"]) == 1


def test_t06b_onboarding_cancel_reject_and_terminal_states(w):
    a = _onboard(w, key="a").json()
    b = _onboard(w, key="b").json()
    cancel = w.call(
        w.msp_a_admin,
        "POST",
        f"{ONBOARD}/{a['onboarding_request_id']}/cancel",
        {"expected_version": a["version"]},
    )
    assert cancel.status_code == 200 and cancel.json()["status"] == "canceled"
    rej = w.call(
        w.platform,
        "POST",
        f"{PLATFORM_ONBOARD}/{b['onboarding_request_id']}/reject",
        {"msp_tenant_id": MSP_A},
    )
    assert rej.status_code == 200 and rej.json()["status"] == "rejected"
    # Terminal states never move again.
    relink = w.call(
        w.platform,
        "POST",
        f"{PLATFORM_ONBOARD}/{b['onboarding_request_id']}/link",
        {"msp_tenant_id": MSP_A, "customer_tenant_id": CUST_3},
    )
    assert relink.status_code == 409
    # The platform review queue is per MSP and platform-only.
    queue = w.call(w.platform, "GET", f"{PLATFORM_ONBOARD}?msp_tenant_id={MSP_A}")
    assert queue.status_code == 200 and len(queue.json()["items"]) == 2
    denied = w.call(w.msp_a_admin, "GET", f"{PLATFORM_ONBOARD}?msp_tenant_id={MSP_A}")
    assert denied.status_code == 403


# ---------------------------------------------------------------------------
# t07-t10. Delegation
# ---------------------------------------------------------------------------


def test_t07_pending_relationship_grants_no_assessment_write(w):
    assert w.propose(w.msp_a_admin, CUST_1, CAPS).status_code == 200
    resp = _request(w)
    assert resp.status_code == 404 and _code(resp) == "MSP_CUSTOMER_NOT_FOUND"
    # The MSP-001 read ceiling never contains a write permission.
    from api.msp_authority import MSP_DELEGABLE_PERMISSIONS

    assert "assessment.create" not in MSP_DELEGABLE_PERMISSIONS
    approve_write = w.call(
        w.c1_admin,
        "POST",
        "/admin/msp/relationships/x/approve",
        {"authorized_capabilities": ["assessment.create"]},
    )
    assert approve_write.status_code in (404, 422)


def test_t08_customer_approval_enables_only_the_exact_scope(w):
    _rid, grant = _approved_grant(w)
    assert grant["status"] == "approved"
    assert grant["capabilities"] == ["assessment.create"]
    assert grant["scope"] == {
        "assessment_type": "ai_governance",
        "assessor_id": "assessor-msp-alpha-1",
    }
    resp = _initiate(w, grant["grant_id"])
    assert resp.status_code == 200, resp.text
    eid = resp.json()["engagement_id"]
    with _session() as db:
        row = db.execute(
            text(
                "SELECT tenant_id, assessment_type, assessor_id, client_name, status"
                " FROM fa_engagements WHERE id = :id"
            ),
            {"id": eid},
        ).fetchone()
    # Owned by the customer, scope from the grant, name from the registry.
    assert tuple(row) == (
        CUST_1,
        "ai_governance",
        "assessor-msp-alpha-1",
        f"Synthetic {CUST_1}",
        "in_progress",
    )
    # The grant body accepts no other scope fields.
    extra = w.call(
        w.msp_a_admin,
        "POST",
        GRANTS,
        {
            "customer_tenant_id": CUST_1,
            "request_key": "k-extra",
            "assessment_type": "soc2",
            "assessor_id": "a",
            "expires_at": (_now() + timedelta(days=5)).isoformat(),
            "client_name": "Override",
        },
    )
    assert extra.status_code == 422


def test_t09_customer_rejection_prevents_initiation(w):
    _relate(w)
    req = _request(w).json()
    rej = _decide(w, w.c1_admin, req, "reject")
    assert rej.status_code == 200 and rej.json()["status"] == "rejected"
    resp = _initiate(w, req["grant_id"])
    assert resp.status_code == 409
    assert _code(resp) == "MSP_ASSESSMENT_GRANT_INVALID_TRANSITION"
    assert _engagements(CUST_1) == []


def test_t10_msp_cannot_approve_its_own_delegation(w, engine):
    _relate(w)
    req = _request(w).json()
    # The MSP party is not the customer.
    own = _decide(w, w.msp_a_admin, req, "approve")
    assert own.status_code == 403 and _code(own) == "MSP_APPROVAL_REQUIRES_CUSTOMER"
    # A customer admin who is also an MSP member is not independent.
    dual = _seed_person(
        engine,
        CUST_1,
        "dual-admin",
        "tenant_admin",
        principal_id=w.msp_a_staff.principal_id,
    )
    resp = _decide(w, dual, req, "approve")
    assert resp.status_code == 403 and _code(resp) == "MSP_SELF_APPROVAL_DENIED"
    # Non-admin customer members cannot approve either.
    member = _decide(w, w.c1_member, req, "approve")
    assert member.status_code == 403
    assert _grants(w, w.c1_admin)[0]["status"] == "requested"


# ---------------------------------------------------------------------------
# t11-t16. Every authority dimension blocks initiation
# ---------------------------------------------------------------------------


def test_t11_expired_delegation_blocks_initiation(w):
    _rid, grant = _approved_grant(w)
    _set_grant(
        grant["grant_id"],
        requested_at=_now() - timedelta(days=2),
        expires_at=_now() - timedelta(seconds=5),
    )
    resp = _initiate(w, grant["grant_id"])
    assert resp.status_code == 409 and _code(resp) == "MSP_ASSESSMENT_GRANT_EXPIRED"
    [view] = _grants(w, w.msp_a_admin)
    assert view["effective_status"] == "expired"
    assert "GRANT_EXPIRED" in view["blockers"]


def test_t12_delegation_revocation_blocks_initiation(w):
    _rid, grant = _approved_grant(w)
    rev = _decide(w, w.c1_admin, grant, "revoke")
    assert rev.status_code == 200 and rev.json()["status"] == "revoked"
    resp = _initiate(w, grant["grant_id"])
    assert resp.status_code == 409
    assert _engagements(CUST_1) == []


def test_t13_missing_msp_membership_blocks_initiation(w, engine):
    _rid, grant = _approved_grant(w)
    w.sql(
        "UPDATE tenant_users SET active = 0 WHERE id = :id",
        id=w.msp_a_admin.membership_id,
    )
    resp = _initiate(w, grant["grant_id"])
    assert resp.status_code == 403
    # MSP staff without the tenant_admin role cannot initiate either.
    w.sql(
        "UPDATE tenant_users SET active = 1 WHERE id = :id",
        id=w.msp_a_admin.membership_id,
    )
    assert _initiate(w, grant["grant_id"], w.msp_a_staff).status_code == 403
    assert _engagements(CUST_1) == []


def test_t14_suspended_msp_blocks_initiation(w):
    _rid, grant = _approved_grant(w)
    assert w.designate(MSP_A, "suspended").status_code == 200
    resp = _initiate(w, grant["grant_id"])
    assert resp.status_code == 403 and _code(resp) == "MSP_ORGANIZATION_INACTIVE"
    assert _engagements(CUST_1) == []


def test_t15_inactive_customer_tenant_blocks_initiation(w):
    _rid, grant = _approved_grant(w)
    w.sql(
        "UPDATE tenants SET lifecycle_state = 'suspended' WHERE tenant_id = :t",
        t=CUST_1,
    )
    resp = _initiate(w, grant["grant_id"])
    assert resp.status_code == 409 and _code(resp) == "MSP_CUSTOMER_TENANT_INACTIVE"
    assert _engagements(CUST_1) == []


def test_t16_missing_entitlement_blocks_initiation(w):
    _rid, grant = _approved_grant(w, entitle=False)
    resp = _initiate(w, grant["grant_id"])
    assert resp.status_code == 409 and _code(resp) == "MSP_ASSESSMENT_NOT_ENTITLED"
    [view] = _grants(w, w.msp_a_admin)
    assert "NOT_ENTITLED" in view["blockers"]
    assert _engagements(CUST_1) == []


def test_t16b_relationship_suspension_blocks_initiation(w):
    rid, grant = _approved_grant(w)
    assert w.act(w.c1_admin, rid, "suspend").status_code == 200
    resp = _initiate(w, grant["grant_id"])
    assert resp.status_code == 409 and _code(resp) == "MSP_RELATIONSHIP_INACTIVE"
    assert _engagements(CUST_1) == []


# ---------------------------------------------------------------------------
# t17-t21. Cross-tenant
# ---------------------------------------------------------------------------


def test_t17_t18_msp_b_cannot_request_or_initiate_for_msp_a_customers(w):
    _rid, grant = _approved_grant(w)
    # MSP B has no relationship with CUST_1.
    req = _request(w, w.msp_b_admin)
    assert req.status_code == 404 and _code(req) == "MSP_CUSTOMER_NOT_FOUND"
    # MSP A's grant id is unknown to MSP B.
    resp = _initiate(w, grant["grant_id"], w.msp_b_admin)
    assert resp.status_code == 404 and _code(resp) == "MSP_ASSESSMENT_GRANT_NOT_FOUND"
    assert _grants(w, w.msp_b_admin) == []
    assert _grants(w, w.c2_admin) == []
    # MSP A cannot request for a customer it has no relationship with.
    assert _request(w, customer=CUST_2).status_code == 404
    assert _engagements(CUST_1) == [] and _engagements(CUST_2) == []


def test_t19_msp_cannot_impersonate_customer_admin(w):
    _relate(w)
    req = _request(w).json()
    forged = w.call(
        w.msp_a_admin,
        "POST",
        f"{GRANTS}/{req['grant_id']}/approve",
        {"expected_version": req["version"]},
        extra_headers={"X-Tenant-ID": CUST_1},
    )
    assert forged.status_code in (403, 404)
    assert _grants(w, w.c1_admin)[0]["status"] == "requested"


def test_t20_forged_tenant_context_is_rejected(w):
    _rid, grant = _approved_grant(w)
    forged = w.call(
        w.msp_b_admin,
        "POST",
        f"{GRANTS}/{grant['grant_id']}/initiate",
        {},
        extra_headers={"X-Tenant-ID": MSP_A},
    )
    assert forged.status_code in (403, 404)
    listing = w.call(
        w.msp_b_admin, "GET", GRANTS, extra_headers={"X-Tenant-ID": CUST_1}
    )
    assert listing.status_code in (403, 404) or listing.json()["items"] == []
    assert _engagements(CUST_1) == []


def test_t21_forged_engagement_and_grant_ids_are_rejected(w):
    _relate(w)
    for gid in ("does-not-exist", str(uuid.uuid4()), "../" + str(uuid.uuid4())):
        resp = _initiate(w, gid)
        assert resp.status_code == 404
    # An engagement id is never accepted as input to initiation.
    _rid2, grant = _approved_grant_existing(w)
    bad = w.call(
        w.msp_a_admin,
        "POST",
        f"{GRANTS}/{grant['grant_id']}/initiate",
        {"engagement_id": "eng-forged"},
    )
    assert bad.status_code == 422


def _approved_grant_existing(w: World) -> tuple[None, dict]:
    """Request + approve on an already-active MSP_A/CUST_1 relationship."""
    rel = [
        r
        for r in w.call(w.msp_a_admin, "GET", "/admin/msp/relationships").json()[
            "items"
        ]
        if r["customer_tenant_id"] == CUST_1
    ]
    _entitle(w, rel[0]["relationship_id"])
    req = _request(w).json()
    ok = _decide(w, w.c1_admin, req, "approve")
    assert ok.status_code == 200, ok.text
    return None, ok.json()


# ---------------------------------------------------------------------------
# t22-t24. Idempotency, concurrency, transitions
# ---------------------------------------------------------------------------


def test_t22_duplicate_initiation_produces_one_engagement(w):
    _rid, grant = _approved_grant(w)
    first = _initiate(w, grant["grant_id"])
    second = _initiate(w, grant["grant_id"])
    assert first.status_code == second.status_code == 200
    assert first.json()["created"] is True and second.json()["created"] is False
    assert first.json()["engagement_id"] == second.json()["engagement_id"]
    assert len(_engagements(CUST_1)) == 1
    # Replaying a grant request returns the same grant.
    key = "same-key"
    a = _request(w, key=key).json()
    b = _request(w, key=key)
    assert b.status_code == 200 and b.json()["grant_id"] == a["grant_id"]
    assert b.json()["created"] is False
    conflict = _request(w, key=key, assessment_type="soc2")
    assert conflict.status_code == 409
    assert _code(conflict) == "MSP_ASSESSMENT_GRANT_CONFLICT"


def test_t23_concurrent_initiation_is_idempotent(w):
    """Two initiations that both read the grant as approved: the one that
    loses the compare-and-set rolls back its engagement and returns the
    winner's."""
    from api.msp_orchestration import initiate_grant

    _rid, grant = _approved_grant(w)
    from api.db_models_msp import MspAssessmentGrant

    with _session() as db1, _session() as db2:
        from api.db import set_tenant_context

        for db in (db1, db2):
            set_tenant_context(db, MSP_A)
        stale = db2.get(MspAssessmentGrant, grant["grant_id"])
        assert stale.status == "approved"
        won = initiate_grant(
            db1,
            grant_id=grant["grant_id"],
            msp_tenant_id=MSP_A,
            actor_subject=w.msp_a_admin.subject,
            membership_id=w.msp_a_admin.membership_id,
            correlation=None,
        )
        db1.commit()
        lost = initiate_grant(
            db2,
            grant_id=grant["grant_id"],
            msp_tenant_id=MSP_A,
            actor_subject=w.msp_a_admin.subject,
            membership_id=w.msp_a_admin.membership_id,
            correlation=None,
            preloaded=stale,
        )
        db2.commit()
    assert won.created is True and lost.created is False
    assert won.engagement_id == lost.engagement_id
    assert len(_engagements(CUST_1)) == 1


def test_t24_invalid_workflow_transitions_are_rejected(w):
    _relate(w)
    req = _request(w).json()
    # Cannot initiate before approval.
    assert _initiate(w, req["grant_id"]).status_code == 409
    # Stale version loses.
    stale = w.call(
        w.c1_admin,
        "POST",
        f"{GRANTS}/{req['grant_id']}/approve",
        {"expected_version": req["version"] + 7},
    )
    assert stale.status_code == 409
    ok = _decide(w, w.c1_admin, req, "approve").json()
    # Approval replay is refused, not re-applied.
    replay = _decide(w, w.c1_admin, req, "approve")
    assert replay.status_code == 409
    # The MSP cannot withdraw an approved grant; it can only be revoked.
    assert _decide(w, w.msp_a_admin, ok, "withdraw").status_code == 409
    # The customer cannot reject an approved grant.
    assert _decide(w, w.c1_admin, ok, "reject").status_code == 409
    # Approval may shorten but never extend the requested expiry.
    req2 = _request(w, days=10).json()
    longer = _decide(
        w,
        w.c1_admin,
        req2,
        "approve",
        expires_at=(_now() + timedelta(days=40)).isoformat(),
    )
    assert longer.status_code == 422 and _code(longer) == "MSP_APPROVAL_WINDOW_INVALID"
    # Requests are bounded: at most 90 days.
    assert _request(w, days=120).status_code == 422
    # Unknown assessment types are rejected.
    assert _request(w, assessment_type="pentest").status_code == 422


# ---------------------------------------------------------------------------
# t25-t31. Customer control and MSP read scope
# ---------------------------------------------------------------------------


def test_t25_customer_actions_remain_customer_authorized(w):
    _rid, grant = _approved_grant(w)
    eid = _initiate(w, grant["grant_id"]).json()["engagement_id"]
    # The MSP cannot cancel or transition the customer's engagement.
    for who in (w.msp_a_admin,):
        resp = _fa(
            w,
            who,
            "PATCH",
            f"/field-assessment/engagements/{eid}/status",
            {"new_status": "cancelled", "reason": "msp attempt"},
            tenant=CUST_1,
        )
        assert resp.status_code in (403, 404), resp.text
    assert _engagements(CUST_1) == [(eid, "in_progress")]
    # The MSP-003 API has no engagement mutation at all.
    from api.msp_orchestration import router

    paths = {r.path for r in router.routes}
    assert not any("status" in p or "cancel" in p for p in paths if "grants" in p)


def test_t26_msp_progress_reads_obey_delegated_scope(w):
    rid, grant = _approved_grant(w)
    eid = _initiate(w, grant["grant_id"]).json()["engagement_id"]
    [view] = _grants(w, w.msp_a_admin)
    assert view["engagement_id"] == eid
    assert view["progress"]["state"] == "available"
    assert view["progress"]["engagement_status"] == "in_progress"
    # Without assessment.read in the relationship, progress is not readable.
    w.sql(
        "UPDATE msp_service_relationships SET authorized_capabilities = :c WHERE id = :id",
        c='["finding.read"]',
        id=rid,
    )
    [view] = _grants(w, w.msp_a_admin)
    assert view["progress"] == {"state": "not_authorized"}
    # The customer always sees the canonical status of its own engagement.
    [cview] = _grants(w, w.c1_admin)
    assert cview["progress"]["engagement_status"] == "in_progress"


def test_t27_msp_cannot_read_customer_evidence_outside_permission(w):
    _rid, grant = _approved_grant(w)
    eid = _initiate(w, grant["grant_id"]).json()["engagement_id"]
    for path in (
        f"/field-assessment/engagements/{eid}",
        f"/field-assessment/engagements/{eid}/evidence",
        "/field-assessment/engagements",
    ):
        resp = _fa(w, w.msp_a_admin, "GET", path, tenant=CUST_1)
        assert resp.status_code in (403, 404), (path, resp.status_code)
        assert eid not in resp.text or resp.status_code in (403, 404)


def test_t28_customer_can_inspect_msp_requests(w):
    rid = _relate(w)
    _request(w).json()
    [view] = _grants(w, w.c1_admin)
    assert view["party"] == "customer"
    assert view["msp_tenant_id"] == MSP_A and view["relationship_id"] == rid
    assert view["capabilities"] == ["assessment.create"]
    assert view["scope"]["assessment_type"] == "ai_governance"
    assert view["expires_at"] is not None
    assert {"owner": "customer", "code": "REVIEW_ASSESSMENT_REQUEST"} in view[
        "next_actions"
    ]
    # The MSP's requester identity is not disclosed to the customer.
    assert w.msp_a_admin.subject not in str(view)
    # The request appears in the relationship's existing audit history.
    hist = w.call(w.c1_admin, "GET", f"/admin/msp/relationships/{rid}/events")
    ops = [i["operation"] for i in hist.json()["items"]]
    assert "assessment_grant.request" in ops
    party = {i["operation"]: i["actor_party"] for i in hist.json()["items"]}
    assert party["assessment_grant.request"] == "msp"


def test_t29_t30_t31_revocation_blocks_new_work_and_preserves_history(w):
    rid, grant = _approved_grant(w)
    eid = _initiate(w, grant["grant_id"]).json()["engagement_id"]
    [g] = _grants(w, w.c1_admin)
    rev = _decide(w, w.c1_admin, g, "revoke")
    assert rev.status_code == 200 and rev.json()["status"] == "revoked"
    # The engagement continues; it is never silently cancelled.
    assert _engagements(CUST_1) == [(eid, "in_progress")]
    # The MSP loses progress visibility for the revoked grant.
    [mview] = _grants(w, w.msp_a_admin)
    assert mview["progress"] == {"state": "not_authorized"}
    # Revoking the relationship blocks every new request.
    assert w.act(w.c1_admin, rid, "revoke").status_code == 200
    assert _request(w).status_code == 404
    # History stays: the grant row and both audit chains are intact.
    [cview] = _grants(w, w.c1_admin)
    assert cview["engagement_id"] == eid and cview["status"] == "revoked"
    ops = [d["operation"] for _t, d, _a in _chain_events(CUST_1)]
    assert {
        "assessment_grant.request",
        "assessment_grant.approve",
        "assessment.initiate",
        "assessment_grant.revoke",
    } <= set(ops)


# ---------------------------------------------------------------------------
# t32-t36. Assessment integrity
# ---------------------------------------------------------------------------


def test_t32_cancellation_cannot_bypass_lifecycle_rules(w):
    _rid, grant = _approved_grant(w)
    eid = _initiate(w, grant["grant_id"]).json()["engagement_id"]
    # The MSP can withdraw only a pending request; an initiated grant cannot
    # be withdrawn and its engagement is untouched.
    [g] = _grants(w, w.msp_a_admin)
    assert _decide(w, w.msp_a_admin, g, "withdraw").status_code == 409
    # The customer cancels through the canonical Field Assessment route.
    assessor = _seed_person(w.engine, CUST_1, "c1-assessor", "assessor")
    resp = _fa(
        w,
        assessor,
        "PATCH",
        f"/field-assessment/engagements/{eid}/status",
        {"new_status": "cancelled", "reason": "customer decision"},
    )
    assert resp.status_code == 200, resp.text
    assert _engagements(CUST_1) == [(eid, "cancelled")]
    # A cancelled engagement is not delivered and is never billed.
    out = _produce(CUST_1, eid)
    assert out.status in ("not_applicable", "not_billable")
    assert _usage_rows() == []


@pytest.mark.parametrize(
    "method,path_tpl,body",
    [
        (
            "PATCH",
            "/field-assessment/engagements/{eid}/status",
            {"new_status": "delivered", "reason": "x"},
        ),
        ("POST", "/field-assessment/engagements/{eid}/reports/r-1/qa-approve", {}),
        (
            "PATCH",
            "/field-assessment/engagements/{eid}",
            {"engagement_metadata": {"x": 1}},
        ),
    ],
)
def test_t33_t36_msp_cannot_drive_gated_assessment_transitions(
    w, method, path_tpl, body
):
    """Readiness, QA approval, production qualification and governed delivery
    all run under the customer tenant's own authority. No MSP credential
    reaches them, with or without a forged tenant header."""
    _rid, grant = _approved_grant(w)
    eid = _initiate(w, grant["grant_id"]).json()["engagement_id"]
    for tenant in (None, CUST_1):
        resp = _fa(
            w, w.msp_a_admin, method, path_tpl.format(eid=eid), body, tenant=tenant
        )
        assert resp.status_code in (403, 404, 422), resp.text
        assert resp.status_code != 200
    assert _engagements(CUST_1) == [(eid, "in_progress")]


# ---------------------------------------------------------------------------
# t37-t39. Billing
# ---------------------------------------------------------------------------


def test_t37_no_billing_event_at_initiation(w):
    _rid, grant = _approved_grant(w)
    _initiate(w, grant["grant_id"])
    assert _usage_rows() == []
    with _session() as db:
        n = db.execute(text("SELECT COUNT(*) FROM billing_event_ledger")).scalar()
    assert n == 0


def test_t38_t39_only_the_qualifying_delivery_bills_and_only_once(w):
    _rid, grant = _approved_grant(w)
    eid = _initiate(w, grant["grant_id"]).json()["engagement_id"]
    # In progress: not billable.
    early = _produce(CUST_1, eid)
    assert early.status in ("not_applicable", "not_billable")
    assert _usage_rows() == []
    _deliver_canonically(CUST_1, eid)
    assert _produce(CUST_1, eid).status == "recorded"
    assert _produce(CUST_1, eid).status == "duplicate"
    rows = _usage_rows(MSP_A)
    assert len(rows) == 1
    _id, payer, meta, status = rows[0]
    assert payer == MSP_A and status == "pending"
    assert meta["source_event_id"] == eid and meta["relationship_id"] == _rid


# ---------------------------------------------------------------------------
# t41-t43. Audit and safe denial
# ---------------------------------------------------------------------------


def test_t41_t42_audit_is_isolated_attributed_and_verifiable(w):
    from api.identity.store import verify_identity_audit_chain

    rid, grant = _approved_grant(w)
    eid = _initiate(w, grant["grant_id"]).json()["engagement_id"]
    for chain in (CUST_1, MSP_A):
        events = {t: (d, a) for t, d, a in _chain_events(chain)}
        d, actor = events["tenant.msp.assessment_initiated"]
        assert actor == w.msp_a_admin.subject
        assert d["msp_tenant_id"] == MSP_A and d["customer_tenant_id"] == CUST_1
        assert d["relationship_id"] == rid and d["grant_id"] == grant["grant_id"]
        assert d["engagement_id"] == eid
        assert d["previous_state"] == "approved" and d["new_state"] == "initiated"
        approved_by = events["tenant.msp.assessment_grant_approved"][1]
        assert approved_by == w.c1_admin.subject
    for outsider in (CUST_2, CUST_3, MSP_B):
        assert _chain_events(outsider) == []
    with _session() as db:
        for chain in (CUST_1, MSP_A):
            from api.db import set_tenant_context

            set_tenant_context(db, chain)
            assert verify_identity_audit_chain(db, chain)
    # The canonical engagement audit marks the MSP origin.
    from api.db_models_field_assessment import FaEngagementAuditEvent

    with _session() as db:
        [created] = (
            db.query(FaEngagementAuditEvent)
            .filter(FaEngagementAuditEvent.engagement_id == eid)
            .all()
        )
        assert created.event_type == "engagement.created"
        assert created.payload["msp"] == {
            "msp_tenant_id": MSP_A,
            "relationship_id": rid,
            "grant_id": grant["grant_id"],
        }


def test_t43_unknown_and_foreign_ids_have_identical_denials(w):
    _rid, grant = _approved_grant(w)
    unknown = _initiate(w, str(uuid.uuid4()), w.msp_b_admin)
    foreign = _initiate(w, grant["grant_id"], w.msp_b_admin)
    assert unknown.status_code == foreign.status_code == 404
    assert unknown.json() == foreign.json()
    for action in ("approve", "reject", "revoke", "withdraw"):
        a = w.call(
            w.c2_admin,
            "POST",
            f"{GRANTS}/{grant['grant_id']}/{action}",
            {"expected_version": 1},
        )
        b = w.call(
            w.c2_admin,
            "POST",
            f"{GRANTS}/{uuid.uuid4()}/{action}",
            {"expected_version": 1},
        )
        assert a.status_code == b.status_code == 404 and a.json() == b.json()
    # Requesting for an unknown vs an unrelated customer is indistinguishable.
    x = _request(w, w.msp_b_admin, customer="no-such-customer")
    y = _request(w, w.msp_b_admin, customer=CUST_1)
    assert x.status_code == y.status_code == 404 and x.json() == y.json()


# ---------------------------------------------------------------------------
# t44-t46. Surfaces that are not authorities
# ---------------------------------------------------------------------------


def test_t44_direct_customers_see_no_msp_workflow(w):
    _approved_grant(w)
    assert _grants(w, w.c3_admin) == []
    assert _grants(w, w.c2_admin) == []
    resp = w.call(w.c3_admin, "GET", ONBOARD)
    assert resp.status_code in (200, 403)
    if resp.status_code == 200:
        assert resp.json()["items"] == []


def test_t45_t46_read_only_and_portal_credentials_cannot_mutate(w):
    from api.auth_dispatch import get_actor_context

    _relate(w)
    req = _request(w).json()

    def _actor() -> ActorContext:
        return ActorContext(
            subject=w.c1_admin.subject,
            email="x@example.invalid",
            name="x",
            permissions=ROLE_PERMISSIONS["tenant_admin"],
            roles=["tenant_admin"],
            auth_source="oidc_auth0",
            tenant_id=CUST_1,
            membership_id=w.c1_admin.membership_id,
        )

    w.app.dependency_overrides[get_actor_context] = _actor
    try:
        for scopes in (("admin:read",), ("governance:read", "governance:write")):
            resp = w.client.post(
                f"{GRANTS}/{req['grant_id']}/approve",
                json={"expected_version": req["version"]},
                headers={"x-api-key": mint_key(*scopes, tenant_id=CUST_1)},
            )
            assert resp.status_code == 403, (scopes, resp.text)
    finally:
        w.app.dependency_overrides.pop(get_actor_context, None)
    assert _grants(w, w.c1_admin)[0]["status"] == "requested"


# ---------------------------------------------------------------------------
# Synthetic end-to-end demonstration
# ---------------------------------------------------------------------------


def test_first_partner_guided_assessment_demonstration(w, engine):
    from api.identity.store import verify_identity_audit_chain

    # MSP Alpha (MSP_A) refers a prospect; the platform provisions it through
    # canonical routes (here: a seeded tenant with a bound admin) and links it.
    onb = _onboard(w, key="demo").json()
    _seed_tenant(engine, "customer-one")
    one_admin = _seed_person(engine, "customer-one", "one-admin", "tenant_admin")
    link = w.call(
        w.platform,
        "POST",
        f"{PLATFORM_ONBOARD}/{onb['onboarding_request_id']}/link",
        {"msp_tenant_id": MSP_A, "customer_tenant_id": "customer-one"},
    )
    assert link.status_code == 200, link.text

    # Relationship: MSP proposes, Customer One approves.
    rid = w.establish(w.msp_a_admin, one_admin, req=CAPS, auth=CAPS)
    [o] = w.call(w.msp_a_admin, "GET", ONBOARD).json()["items"]
    assert o["stage"] == "active"
    _entitle(w, rid, customer="customer-one")

    # Narrow assessment authority: requested, then approved exactly.
    req = _request(w, customer="customer-one").json()
    assert req["status"] == "requested"
    approved = _decide(w, one_admin, req, "approve").json()
    assert approved["status"] == "approved"

    # One initiation; a repeat creates nothing new.
    first = _initiate(w, approved["grant_id"]).json()
    again = _initiate(w, approved["grant_id"]).json()
    eid = first["engagement_id"]
    assert again["engagement_id"] == eid and again["created"] is False
    assert len(_engagements("customer-one")) == 1
    assert _usage_rows() == []  # initiation is not billable

    # Progress through the MSP view, owned by the customer.
    [view] = _grants(w, w.msp_a_admin, customer_tenant_id="customer-one")
    assert view["progress"]["engagement_status"] == "in_progress"
    assert _engagements("customer-one")[0][0] == eid

    # An unauthorized MSP sees nothing.
    assert _grants(w, w.msp_b_admin) == []
    assert _initiate(w, approved["grant_id"], w.msp_b_admin).status_code == 404

    # Delivery happens only through the canonical QA auto-advance; MSP-006
    # then records exactly one attributed charge.
    _deliver_canonically("customer-one", eid)
    assert _produce("customer-one", eid).status == "recorded"
    assert _produce("customer-one", eid).status == "duplicate"
    [(_uid, payer, meta, status)] = _usage_rows()
    assert payer == MSP_A and meta["source_event_id"] == eid and status == "pending"

    # Customer One revokes; the MSP can no longer initiate or see progress,
    # and the history remains.
    [g] = _grants(w, one_admin)
    assert _decide(w, one_admin, g, "revoke").status_code == 200
    req2 = _request(w, customer="customer-one").json()
    assert _initiate(w, req2["grant_id"]).status_code == 409  # not approved
    revoked = [
        g
        for g in _grants(w, w.msp_a_admin, customer_tenant_id="customer-one")
        if g["grant_id"] == approved["grant_id"]
    ]
    assert revoked[0]["status"] == "revoked"
    assert revoked[0]["progress"] == {"state": "not_authorized"}
    assert w.act(one_admin, rid, "revoke").status_code == 200
    assert _request(w, customer="customer-one").status_code == 404
    assert _engagements("customer-one") == [(eid, "delivered")]
    assert len(_usage_rows()) == 1

    with _session() as db:
        from api.db import set_tenant_context

        for chain in ("customer-one", MSP_A):
            set_tenant_context(db, chain)
            assert verify_identity_audit_chain(db, chain)


# ---------------------------------------------------------------------------
# Invariants C, E, G, H (final-validation review)
# ---------------------------------------------------------------------------


def test_inv_c_grant_is_bound_to_its_own_relationship(w):
    """A grant approved under one relationship is dead once that relationship
    ends, even if the same MSP and customer later establish a new one."""
    rid, grant = _approved_grant(w)
    assert w.act(w.c1_admin, rid, "revoke").status_code == 200
    new_rid = _relate(w)
    assert new_rid != rid
    resp = _initiate(w, grant["grant_id"])
    assert resp.status_code == 409 and _code(resp) == "MSP_RELATIONSHIP_INACTIVE"
    assert _engagements(CUST_1) == []
    # The grant cannot be re-pointed: its relationship is fixed at request.
    [view] = [
        g for g in _grants(w, w.msp_a_admin) if g["grant_id"] == grant["grant_id"]
    ]
    assert view["relationship_id"] == rid
    assert "RELATIONSHIP_INACTIVE" in view["blockers"]


def test_inv_e_referrals_do_not_disclose_existing_tenants(w):
    """Referring an organization that already exists on FrostGate (same
    display name, same admin email domain) looks exactly like referring an
    unknown one: no tenant id, no match signal."""
    existing = _onboard(
        w,
        key="ref-existing",
        name=f"Synthetic {CUST_2}",
        email=f"c2-admin@{CUST_2}.example.invalid",
    )
    unknown = _onboard(
        w, key="ref-unknown", name="Nobody Co", email="it@nobody.invalid"
    )
    assert existing.status_code == unknown.status_code == 200
    a, b = existing.json(), unknown.json()
    assert a["customer_tenant_id"] is None and b["customer_tenant_id"] is None
    assert a["stage"] == b["stage"] == "requested"
    assert set(a) == set(b)
    # Apart from the MSP's own echoed input, nothing names the tenant.
    echoed = {"organization_name", "contact_email", "request_key"}
    assert CUST_2 not in str({k: v for k, v in a.items() if k not in echoed})
    # Nothing was linked, proposed or written to the other tenant's chain.
    assert _chain_events(CUST_2, "tenant.msp.") == []


def test_inv_g_h_payer_assignment_and_grant_are_independent_authorities(w, engine):
    """G: a payer assignment grants no assessment authority. H: an approved
    grant establishes no payment liability."""
    # G — commercial authority alone: no grant, no initiation path, no
    # engagement, and the relationship's read-only ceiling is unchanged.
    rid = _relate(w)
    _entitle(w, rid)
    assert _grants(w, w.msp_a_admin) == []
    for gid in (str(uuid.uuid4()),):
        assert _initiate(w, gid).status_code == 404
    from api.msp_authority import MSP_DELEGABLE_PERMISSIONS

    assert "assessment.create" not in MSP_DELEGABLE_PERMISSIONS
    resp = _fa(
        w,
        w.msp_a_admin,
        "POST",
        "/field-assessment/engagements",
        {"client_name": "x", "assessor_id": "a", "assessment_type": "soc2"},
        tenant=CUST_1,
    )
    assert resp.status_code in (403, 404)
    assert _engagements(CUST_1) == []

    # H — a grant approved for a customer with no payer creates no payer
    # assignment, no usage and no ledger entry, and cannot be started.
    w.establish(w.msp_a_admin, w.c2_admin, req=CAPS, auth=CAPS)
    req = _request(w, customer=CUST_2).json()
    ok = _decide(w, w.c2_admin, req, "approve")
    assert ok.status_code == 200
    with _session() as db:
        assert (
            db.execute(
                text("SELECT COUNT(*) FROM msp_payer_assignments WHERE tenant_id = :t"),
                {"t": CUST_2},
            ).scalar()
            == 0
        )
        assert (
            db.execute(text("SELECT COUNT(*) FROM billing_event_ledger")).scalar() == 0
        )
    assert _usage_rows() == []
    blocked = _initiate(w, req["grant_id"])
    assert (
        blocked.status_code == 409 and _code(blocked) == "MSP_ASSESSMENT_NOT_ENTITLED"
    )


def test_inv_msp_creation_matches_the_canonical_route(w, engine):
    """MSP initiation and the direct create route produce the same canonical
    record, audit event and timeline event; the MSP path only adds its
    ``msp`` provenance block. Guards drift between the route (which keeps its
    inline audit calls for tools/ci/check_audit_coverage.py) and
    create_engagement_with_audit."""
    from api.db_models_field_assessment import FaEngagementAuditEvent

    def _shape(eid: str) -> tuple:
        with _session() as db:
            eng = db.execute(
                text(
                    "SELECT status, schema_version, assessment_type, assessor_id"
                    " FROM fa_engagements WHERE id = :id"
                ),
                {"id": eid},
            ).fetchone()
            events = (
                db.query(FaEngagementAuditEvent)
                .filter(FaEngagementAuditEvent.engagement_id == eid)
                .all()
            )
            timeline = db.execute(
                text(
                    "SELECT event_type FROM governance_timeline_events"
                    " WHERE source_id = :id"
                ),
                {"id": eid},
            ).fetchall()
        [ev] = events
        payload = {k: v for k, v in (ev.payload or {}).items() if k != "msp"}
        return (
            tuple(eng),
            (ev.event_type, ev.reason_code, sorted(payload)),
            sorted(r[0] for r in timeline),
        )

    # Both paths must actually write a timeline event, not just match on none.

    assessor = _seed_person(engine, CUST_1, "c1-assessor", "assessor")
    direct = _fa(
        w,
        assessor,
        "POST",
        "/field-assessment/engagements",
        {
            "client_name": "Direct",
            "assessor_id": "assessor-msp-alpha-1",
            "assessment_type": "ai_governance",
        },
    )
    assert direct.status_code == 201, direct.text
    _rid, grant = _approved_grant(w)
    mspid = _initiate(w, grant["grant_id"]).json()["engagement_id"]
    direct_shape = _shape(direct.json()["id"])
    assert direct_shape[2] == ["field_assessment.engagement.created"]
    assert direct_shape == _shape(mspid)


def test_review_msp_entitlement_gates_orchestration_mutations(w, monkeypatch):
    """PR #877 review (P2): losing the msp.multi_tenant entitlement stops every
    MSP-003 mutation that creates or expands MSP activity, exactly like the
    MSP-001 relationship proposal. Retracting the MSP's own pending request
    stays possible."""
    import api.entitlements as ent
    from services.capability_bundles.resolver import invalidate_cache

    _rid, grant = _approved_grant(w)
    pending = _request(w).json()
    onb = _onboard(w, key="before-revocation").json()

    monkeypatch.setenv("FG_ENTITLEMENT_ENFORCEMENT", "true")
    monkeypatch.setattr(ent, "ENFORCEMENT_STRICT", True)
    invalidate_cache(MSP_A)

    for resp in (
        _request(w),
        _initiate(w, grant["grant_id"]),
        _onboard(w, key="after-revocation"),
    ):
        assert resp.status_code == 403, resp.text
        assert resp.json()["detail"]["code"] == "CAPABILITY_DENIED"
    assert _engagements(CUST_1) == []

    # Retraction only reduces activity, so it is not entitlement-gated.
    assert _decide(w, w.msp_a_admin, pending, "withdraw").status_code == 200
    cancel = w.call(
        w.msp_a_admin,
        "POST",
        f"{ONBOARD}/{onb['onboarding_request_id']}/cancel",
        {"expected_version": onb["version"]},
    )
    assert cancel.status_code == 200
