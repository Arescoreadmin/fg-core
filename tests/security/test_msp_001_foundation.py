"""MSP-001 — MSP organizations, customer-approved relationships, delegated authority.

Every tenant, principal, membership, credential and record here is synthetic.

Actors are installed the same way as tests/test_tenant_admin_001.py: an API key
bound to the actor's tenant satisfies ``require_scopes``; an ActorContext
override supplies the subject and membership. Every authority decision under
test is DB-canonical (``tenant_users``, ``msp_organizations``,
``msp_service_relationships``); the JWT-style role on the override is
deliberately ignored, and one test proves it.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from starlette.testclient import TestClient

from api.actor_context import ROLE_PERMISSIONS, ActorContext
from api.auth_scopes import mint_key

MSP_A = "msp-a"
MSP_B = "msp-b"
CUST_1 = "cust-1"
CUST_2 = "cust-2"
CUST_3 = "cust-3"
INTERNAL = "internal-ops"

READ_CAPS = ["evidence.read", "finding.read", "report.read"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# World
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Person:
    subject: str
    tenant: str
    membership_id: str
    principal_id: str
    role: str


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


def _seed_tenant(engine, tenant_id: str, kind: str = "customer") -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO tenants (tenant_id, display_name, lifecycle_state, "
                "tenant_kind, created_at, updated_at) VALUES "
                "(:t, :n, 'active', :k, :now, :now)"
            ),
            {"t": tenant_id, "n": f"Synthetic {tenant_id}", "k": kind, "now": "x"},
        )


def _seed_person(
    engine,
    tenant: str,
    name: str,
    role: str,
    *,
    principal_id: str | None = None,
) -> Person:
    pid = principal_id or str(uuid.uuid4())
    uid = str(uuid.uuid4())
    subject = f"auth0|{name}"
    now = _now().isoformat()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO fg_principals (id, principal_type, "
                "lifecycle_state, mfa_verified, authority_version, created_at, "
                "updated_at) VALUES (:id, 'human', 'active', 0, 1, :now, :now)"
            ),
            {"id": pid, "now": now},
        )
        conn.execute(
            text(
                "INSERT INTO tenant_users (id, tenant_id, email, display_name, role, "
                "active, identity_subject, identity_provider, "
                "identity_binding_status, principal_id, created_at, updated_at) "
                "VALUES (:id, :t, :e, :e, :role, 1, :s, 'auth0', 'bound', :pid, "
                ":now, :now)"
            ),
            {
                "id": uid,
                "t": tenant,
                "e": f"{name}@{tenant}.example.invalid",
                "role": role,
                "s": subject,
                "pid": pid,
                "now": now,
            },
        )
    return Person(subject, tenant, uid, pid, role)


class World:
    def __init__(self, app, client, engine):
        self.app = app
        self.client = client
        self.engine = engine
        for t in (MSP_A, MSP_B, CUST_1, CUST_2, CUST_3):
            _seed_tenant(engine, t)
        _seed_tenant(engine, INTERNAL, kind="internal_platform")
        self.msp_a_admin = _seed_person(engine, MSP_A, "msp-a-admin", "tenant_admin")
        self.msp_a_staff = _seed_person(engine, MSP_A, "msp-a-staff", "viewer")
        self.msp_b_admin = _seed_person(engine, MSP_B, "msp-b-admin", "tenant_admin")
        self.msp_b_staff = _seed_person(engine, MSP_B, "msp-b-staff", "viewer")
        self.c1_admin = _seed_person(engine, CUST_1, "c1-admin", "tenant_admin")
        self.c1_member = _seed_person(engine, CUST_1, "c1-member", "client_read_only")
        self.c2_admin = _seed_person(engine, CUST_2, "c2-admin", "tenant_admin")
        self.c3_admin = _seed_person(engine, CUST_3, "c3-admin", "tenant_admin")
        self.platform = Person("auth0|platform-op", MSP_A, "", "", "platform_admin")
        assert self.designate(MSP_A).status_code == 200
        assert self.designate(MSP_B).status_code == 200

    # -- transport ---------------------------------------------------------

    def call(
        self,
        who: Person,
        method: str,
        path: str,
        json: dict | None = None,
        *,
        jwt_role: str | None = None,
        extra_headers: dict | None = None,
    ):
        from api.auth_dispatch import get_actor_context

        role = jwt_role or who.role

        def _actor() -> ActorContext:
            return ActorContext(
                subject=who.subject,
                email=f"{who.subject}@example.invalid",
                name=who.subject,
                permissions=ROLE_PERMISSIONS.get(role, frozenset()),
                roles=[role],
                auth_source="oidc_auth0",
                tenant_id=who.tenant,
                membership_id=who.membership_id or None,
            )

        self.app.dependency_overrides[get_actor_context] = _actor
        headers = {
            "x-api-key": mint_key("admin:read", "admin:write", tenant_id=who.tenant)
        }
        headers.update(extra_headers or {})
        try:
            return self.client.request(method, path, json=json, headers=headers)
        finally:
            self.app.dependency_overrides.pop(get_actor_context, None)

    # -- flows -------------------------------------------------------------

    def designate(self, tenant: str, status: str = "active"):
        return self.call(
            self.platform,
            "PUT",
            f"/admin/msp/organizations/{tenant}",
            {"status": status},
        )

    def propose(self, msp_admin: Person, customer: str, caps=READ_CAPS):
        return self.call(
            msp_admin,
            "POST",
            "/admin/msp/relationships",
            {"customer_tenant_id": customer, "requested_capabilities": caps},
        )

    def approve(self, cust_admin: Person, rid: str, caps=READ_CAPS, **window):
        return self.call(
            cust_admin,
            "POST",
            f"/admin/msp/relationships/{rid}/approve",
            {"authorized_capabilities": caps, **window},
        )

    def establish(self, msp_admin, cust_admin, req=READ_CAPS, auth=READ_CAPS) -> str:
        proposed = self.propose(msp_admin, cust_admin.tenant, req)
        assert proposed.status_code == 200, proposed.text
        rid = proposed.json()["relationship_id"]
        approved = self.approve(cust_admin, rid, auth)
        assert approved.status_code == 200, approved.text
        return rid

    def customers(self, who: Person):
        return self.call(who, "GET", "/admin/msp/customers")

    def context(self, who: Person, customer: str):
        return self.call(who, "POST", f"/admin/msp/customers/{customer}/context")

    def act(self, who: Person, rid: str, action: str):
        return self.call(who, "POST", f"/admin/msp/relationships/{rid}/{action}")

    def customer_ids(self, who: Person) -> list[str]:
        resp = self.customers(who)
        assert resp.status_code == 200, resp.text
        return [i["customer_tenant_id"] for i in resp.json()["items"]]

    def sql(self, statement: str, **params):
        with self.engine.begin() as conn:
            return conn.execute(text(statement), params)


@pytest.fixture
def w(app, client, engine) -> World:
    return World(app, client, engine)


def _not_found(resp) -> None:
    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"] == {"code": "MSP_CUSTOMER_NOT_FOUND"}


# ---------------------------------------------------------------------------
# 1-3. Discovery and context resolution
# ---------------------------------------------------------------------------


def test_01_msp_lists_only_authorized_customers(w):
    w.establish(w.msp_a_admin, w.c1_admin)
    assert w.propose(w.msp_a_admin, CUST_2).status_code == 200  # pending only

    assert w.customer_ids(w.msp_a_staff) == [CUST_1]
    item = w.customers(w.msp_a_staff).json()["items"][0]
    assert item["effective_permissions"] == sorted(READ_CAPS)


def test_02_msp_cannot_list_or_resolve_another_msps_customers(w):
    w.establish(w.msp_a_admin, w.c1_admin)
    w.establish(w.msp_b_admin, w.c3_admin)

    assert w.customer_ids(w.msp_a_staff) == [CUST_1]
    assert w.customer_ids(w.msp_b_staff) == [CUST_3]
    _not_found(w.context(w.msp_a_staff, CUST_3))
    _not_found(w.context(w.msp_b_staff, CUST_1))


def test_03_unapproved_customer_is_denied(w):
    assert w.propose(w.msp_a_admin, CUST_1).status_code == 200

    _not_found(w.context(w.msp_a_staff, CUST_1))
    _not_found(w.context(w.msp_a_staff, CUST_2))  # no relationship at all
    _not_found(w.context(w.msp_a_staff, "no-such-tenant"))


# ---------------------------------------------------------------------------
# 4-6. Approval authority
# ---------------------------------------------------------------------------


def test_04_msp_cannot_approve_its_own_relationship(w):
    rid = w.propose(w.msp_a_admin, CUST_1).json()["relationship_id"]

    resp = w.approve(w.msp_a_admin, rid)
    assert resp.status_code == 403
    assert resp.json()["detail"] == {"code": "MSP_APPROVAL_REQUIRES_CUSTOMER"}

    # A customer admin who is also a member of the MSP is not independent.
    dual = _seed_person(
        w.engine,
        CUST_1,
        "dual-admin",
        "tenant_admin",
        principal_id=w.msp_a_staff.principal_id,
    )
    resp = w.approve(dual, rid)
    assert resp.status_code == 403
    assert resp.json()["detail"] == {"code": "MSP_SELF_APPROVAL_DENIED"}
    _not_found(w.context(w.msp_a_staff, CUST_1))


def test_05_customer_approval_creates_bounded_authority(w):
    rid = w.establish(w.msp_a_admin, w.c1_admin, req=READ_CAPS, auth=["evidence.read"])

    ctx = w.context(w.msp_a_staff, CUST_1)
    assert ctx.status_code == 200, ctx.text
    body = ctx.json()
    assert body["relationship_id"] == rid
    assert body["effective_permissions"] == ["evidence.read"]
    assert body["revalidation"] == "every_request"
    valid_until = datetime.fromisoformat(body["valid_until"])
    assert valid_until <= _now() + timedelta(days=367)


def test_06_unauthorized_customer_principals_cannot_approve(w):
    rid = w.propose(w.msp_a_admin, CUST_1).json()["relationship_id"]

    not_admin = w.approve(w.c1_member, rid)
    assert not_admin.status_code == 403
    # Even when the token claims tenant_admin, the DB-canonical check refuses.
    claimed = w.call(
        w.c1_member,
        "POST",
        f"/admin/msp/relationships/{rid}/approve",
        {"authorized_capabilities": READ_CAPS},
        jwt_role="tenant_admin",
    )
    assert claimed.status_code == 403
    assert claimed.json()["detail"]["code"] == "TENANT_ADMIN_DENIED"

    other_customer = w.approve(w.c2_admin, rid)
    assert other_customer.status_code == 404
    assert other_customer.json()["detail"] == {"code": "MSP_RELATIONSHIP_NOT_FOUND"}
    _not_found(w.context(w.msp_a_staff, CUST_1))


# ---------------------------------------------------------------------------
# 7-10. Suspension, revocation, expiry, membership and partner removal
# ---------------------------------------------------------------------------


def test_07_suspended_relationship_denies_access(w):
    rid = w.establish(w.msp_a_admin, w.c1_admin)

    assert w.act(w.c1_admin, rid, "suspend").status_code == 200
    _not_found(w.context(w.msp_a_staff, CUST_1))
    assert w.customer_ids(w.msp_a_staff) == []

    assert w.act(w.c1_admin, rid, "resume").status_code == 200
    assert w.context(w.msp_a_staff, CUST_1).status_code == 200


def test_08_revoked_relationship_denies_access_permanently(w):
    rid = w.establish(w.msp_a_admin, w.c1_admin)

    revoked = w.act(w.c1_admin, rid, "revoke")
    assert revoked.status_code == 200 and revoked.json()["changed"] is True
    assert revoked.json()["revoked_by_party"] == "customer"
    _not_found(w.context(w.msp_a_staff, CUST_1))
    assert w.customer_ids(w.msp_a_staff) == []
    assert w.act(w.c1_admin, rid, "resume").status_code == 409


def test_08b_msp_may_end_its_own_access(w):
    rid = w.establish(w.msp_a_admin, w.c1_admin)

    resp = w.act(w.msp_a_admin, rid, "revoke")
    assert resp.status_code == 200 and resp.json()["revoked_by_party"] == "msp"
    _not_found(w.context(w.msp_a_staff, CUST_1))


def test_09_expired_relationship_denies_access(w):
    from api.db import get_sessionmaker
    from api.db_models_msp import MspServiceRelationship

    rid = w.establish(w.msp_a_admin, w.c1_admin)
    past = _now() - timedelta(days=2)
    with get_sessionmaker()() as db:
        row = db.get(MspServiceRelationship, rid)
        row.effective_at = past - timedelta(days=1)
        row.expires_at = past
        db.commit()

    _not_found(w.context(w.msp_a_staff, CUST_1))
    assert w.customer_ids(w.msp_a_staff) == []
    listed = w.call(w.c1_admin, "GET", "/admin/msp/relationships").json()["items"]
    assert listed[0]["status"] == "expired"


def test_09b_approval_window_is_bounded(w):
    rid = w.propose(w.msp_a_admin, CUST_1).json()["relationship_id"]
    too_long = (_now() + timedelta(days=400)).isoformat()
    in_past = (_now() - timedelta(days=1)).isoformat()

    for window in ({"expires_at": too_long}, {"effective_at": in_past}):
        resp = w.approve(w.c1_admin, rid, **window)
        assert resp.status_code == 422
        assert resp.json()["detail"] == {"code": "MSP_APPROVAL_WINDOW_INVALID"}


def test_10_msp_membership_or_partner_removal_denies_access(w):
    w.establish(w.msp_a_admin, w.c1_admin)
    assert w.context(w.msp_a_staff, CUST_1).status_code == 200

    w.sql(
        "UPDATE tenant_users SET active = 0 WHERE id = :id",
        id=w.msp_a_staff.membership_id,
    )
    resp = w.context(w.msp_a_staff, CUST_1)
    assert resp.status_code == 403
    assert resp.json()["detail"] == {"code": "MSP_ACCESS_DENIED"}

    # Platform kill switch: suspending the MSP organization denies everyone.
    assert w.context(w.msp_a_admin, CUST_1).status_code == 200
    assert w.designate(MSP_A, "suspended").status_code == 200
    assert w.context(w.msp_a_admin, CUST_1).status_code == 403
    assert w.propose(w.msp_a_admin, CUST_2).status_code == 403


# ---------------------------------------------------------------------------
# 11. Delegation ceiling and intersection
# ---------------------------------------------------------------------------


def test_11_permissions_never_exceed_customer_delegation(w):
    # The MSP cannot ask for, and the customer cannot grant, non-delegable authority.
    for caps in (["key.manage"], ["platform.admin"], ["evidence.read", "user.invite"]):
        resp = w.propose(w.msp_a_admin, CUST_1, caps)
        assert resp.status_code == 422, caps
        assert resp.json()["detail"] == {"code": "MSP_CAPABILITY_NOT_DELEGABLE"}

    rid = w.propose(w.msp_a_admin, CUST_1, ["evidence.read"]).json()["relationship_id"]
    widened = w.approve(w.c1_admin, rid, ["evidence.read", "report.read"])
    assert widened.status_code == 422  # customer may narrow, never widen

    w.approve(w.c1_admin, rid, ["evidence.read"])
    # A member whose DB role grants nothing gets nothing, whatever its token says.
    nobody = _seed_person(w.engine, MSP_A, "msp-a-nobody", "user")
    resp = w.call(
        nobody,
        "POST",
        f"/admin/msp/customers/{CUST_1}/context",
        jwt_role="platform_admin",
    )
    _not_found(resp)
    assert (
        w.call(nobody, "GET", "/admin/msp/customers", jwt_role="platform_admin").json()[
            "items"
        ]
        == []
    )


def test_11b_effective_permissions_are_an_intersection(w, app):
    from api.db import get_sessionmaker
    from api.msp_authority import resolve_actor_access

    w.establish(w.msp_a_admin, w.c1_admin, req=READ_CAPS, auth=["evidence.read"])
    actor = ActorContext(
        subject=w.msp_a_admin.subject,
        email="",
        name="",
        permissions=frozenset(),
        roles=["tenant_admin"],
        auth_source="oidc_auth0",
        tenant_id=MSP_A,
        membership_id=w.msp_a_admin.membership_id,
    )
    with get_sessionmaker()() as db:
        _, access = resolve_actor_access(
            db, actor_ctx=actor, msp_tenant_id=MSP_A, customer_tenant_id=CUST_1
        )
    # tenant_admin holds key.manage, user.invite, etc. — none leak through.
    assert access.effective_permissions == frozenset({"evidence.read"})


# ---------------------------------------------------------------------------
# 12-15. Existing isolation is unchanged; no new path into customer data
# ---------------------------------------------------------------------------


def test_12_direct_customer_access_is_unchanged(w):
    w.establish(w.msp_a_admin, w.c1_admin)

    resp = w.call(w.c1_admin, "GET", f"/admin/tenants/{CUST_1}/users")
    assert resp.status_code == 200, resp.text
    assert w.c1_admin.membership_id in {u["user_id"] for u in resp.json()["items"]}


def test_13_msp_cannot_read_customer_data_through_existing_routes(w):
    w.establish(w.msp_a_admin, w.c1_admin)

    resp = w.call(w.msp_a_admin, "GET", f"/admin/tenants/{CUST_1}/users")
    assert resp.status_code in (401, 403, 404), resp.text
    assert w.c1_admin.subject not in resp.text


def test_14_msp_cannot_write_customer_data_or_customer_controls(w):
    rid = w.establish(w.msp_a_admin, w.c1_admin)

    invite = w.call(
        w.msp_a_admin,
        "POST",
        f"/admin/tenants/{CUST_1}/users/invite",
        {"email": "x@cust-1.example.invalid", "display_name": "x", "role": "user"},
    )
    assert invite.status_code in (401, 403, 404), invite.text
    with w.engine.connect() as conn:
        n = conn.execute(
            text("SELECT COUNT(*) FROM tenant_users WHERE email LIKE 'x@cust-1%'")
        ).scalar()
    assert n == 0
    for action in ("suspend", "resume"):
        resp = w.act(w.msp_a_admin, rid, action)
        assert resp.status_code == 403, (action, resp.text)


def test_15_tenant_header_cannot_select_caller_identity(w):
    rid = w.propose(w.msp_a_admin, CUST_1).json()["relationship_id"]

    spoof = {"X-Tenant-Id": CUST_1}
    approve = w.call(
        w.msp_a_admin,
        "POST",
        f"/admin/msp/relationships/{rid}/approve",
        {"authorized_capabilities": READ_CAPS},
        extra_headers=spoof,
    )
    assert approve.status_code in (400, 403), approve.text
    ctx = w.call(
        w.msp_a_staff,
        "POST",
        f"/admin/msp/customers/{CUST_1}/context",
        extra_headers=spoof,
    )
    assert ctx.status_code in (400, 403, 404), ctx.text
    row = w.sql("SELECT status FROM msp_service_relationships WHERE id=:id", id=rid)
    assert row.scalar() == "proposed"


# ---------------------------------------------------------------------------
# 16. No cached authority; per-customer isolation of resolved context
# ---------------------------------------------------------------------------


def test_16_authority_is_rechecked_and_never_shared_between_customers(w):
    from api.db import get_sessionmaker
    from api.msp_authority import resolve_credential_access

    rid1 = w.establish(w.msp_a_admin, w.c1_admin, auth=["evidence.read"])
    w.establish(w.msp_a_admin, w.c2_admin, auth=["report.read"])

    with get_sessionmaker()() as db:
        a1 = resolve_credential_access(
            db, msp_tenant_id=MSP_A, customer_tenant_id=CUST_1, required="evidence.read"
        )
        a2 = resolve_credential_access(
            db, msp_tenant_id=MSP_A, customer_tenant_id=CUST_2, required="report.read"
        )
    assert a1.effective_permissions == {"evidence.read"}
    assert a2.effective_permissions == {"report.read"}
    assert (a1.customer_tenant_id, a2.customer_tenant_id) == (CUST_1, CUST_2)

    # A job that captured a1 earlier must re-check; the re-check fails at once.
    assert w.act(w.c1_admin, rid1, "revoke").status_code == 200
    from fastapi import HTTPException

    with get_sessionmaker()() as db, pytest.raises(HTTPException) as exc:
        resolve_credential_access(
            db, msp_tenant_id=MSP_A, customer_tenant_id=CUST_1, required="evidence.read"
        )
    assert exc.value.status_code == 404


# ---------------------------------------------------------------------------
# 17-18. Lifecycle transitions and idempotency
# ---------------------------------------------------------------------------


def test_17_invalid_lifecycle_transitions_are_rejected(w):
    rid = w.propose(w.msp_a_admin, CUST_1).json()["relationship_id"]

    assert w.act(w.c1_admin, rid, "suspend").status_code == 409  # not approved
    assert w.act(w.c1_admin, rid, "resume").status_code == 409
    assert w.approve(w.c1_admin, rid).status_code == 200
    second = w.approve(w.c1_admin, rid)
    assert second.status_code == 409
    assert second.json()["detail"] == {"code": "MSP_RELATIONSHIP_INVALID_TRANSITION"}
    assert w.act(w.c1_admin, rid, "resume").status_code == 409  # not suspended


def test_17b_no_self_relationship_and_no_non_customer_targets(w):
    for target in (MSP_A, INTERNAL, "no-such-tenant"):
        resp = w.propose(w.msp_a_admin, target)
        assert resp.status_code == 404, target
        assert resp.json()["detail"] == {"code": "MSP_CUSTOMER_NOT_FOUND"}


def test_18_idempotency_rules(w):
    first = w.propose(w.msp_a_admin, CUST_1)
    again = w.propose(w.msp_a_admin, CUST_1)
    assert first.json()["created"] is True and again.json()["created"] is False
    assert first.json()["relationship_id"] == again.json()["relationship_id"]
    different = w.propose(w.msp_a_admin, CUST_1, ["evidence.read"])
    assert different.status_code == 409
    assert different.json()["detail"] == {"code": "MSP_RELATIONSHIP_EXISTS"}

    rid = first.json()["relationship_id"]
    assert w.act(w.c1_admin, rid, "revoke").json()["changed"] is True
    assert w.act(w.c1_admin, rid, "revoke").json()["changed"] is False
    assert w.designate(MSP_A).json()["changed"] is False

    # After revocation a new relationship may be proposed.
    assert w.propose(w.msp_a_admin, CUST_1).json()["created"] is True


# ---------------------------------------------------------------------------
# 19-20. Attribution and offboarding
# ---------------------------------------------------------------------------


def _events(engine, tenant: str) -> list:
    with engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT event_type, actor_user_id, membership_id, reason_code, "
                "details_json, correlation_id FROM tenant_identity_audit_events "
                "WHERE tenant_id = :t AND event_type LIKE 'tenant.msp.%' "
                "ORDER BY created_at"
            ),
            {"t": tenant},
        ).fetchall()


def test_19_audit_events_bind_actor_msp_and_customer(w):
    import json

    from api.db import get_sessionmaker
    from api.identity.store import verify_identity_audit_chain

    rid = w.establish(w.msp_a_admin, w.c1_admin, auth=["evidence.read"])
    assert w.context(w.msp_a_staff, CUST_1).status_code == 200

    cust = _events(w.engine, CUST_1)
    msp = _events(w.engine, MSP_A)
    expected = [
        "tenant.msp.relationship_proposed",
        "tenant.msp.relationship_approved",
        "tenant.msp.context_resolved",
    ]
    assert [e.event_type for e in cust] == expected
    assert [e.event_type for e in msp][-3:] == expected

    by_type = {e.event_type: e for e in cust}
    approved = by_type["tenant.msp.relationship_approved"]
    assert approved.actor_user_id == w.c1_admin.subject
    assert approved.membership_id == w.c1_admin.membership_id
    resolved = by_type["tenant.msp.context_resolved"]
    assert resolved.actor_user_id == w.msp_a_staff.subject
    details = json.loads(resolved.details_json)
    assert details == {
        "msp_tenant_id": MSP_A,
        "customer_tenant_id": CUST_1,
        "relationship_id": rid,
        "operation": "context.resolve",
        "capabilities": ["evidence.read"],
        "result": "success",
    }
    with get_sessionmaker()() as db:
        assert verify_identity_audit_chain(db, CUST_1)
        assert verify_identity_audit_chain(db, MSP_A)


def test_20_offboarding_preserves_customer_evidence_and_history(
    w, tmp_path, monkeypatch
):
    from api.db import get_sessionmaker
    from api.identity.store import verify_identity_audit_chain
    from tests.decision_evidence_helpers import emit_synthetic_decision_evidence

    monkeypatch.setenv("FG_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    path, sha = emit_synthetic_decision_evidence(CUST_1, 1)
    rid = w.establish(w.msp_a_admin, w.c1_admin)
    before = len(_events(w.engine, CUST_1))

    assert w.act(w.c1_admin, rid, "revoke").status_code == 200

    assert path.exists()
    with w.engine.connect() as conn:
        owned = conn.execute(
            text(
                "SELECT evidence_sha256 FROM decision_evidence_artifacts "
                "WHERE tenant_id = :t"
            ),
            {"t": CUST_1},
        ).scalar()
    assert owned == sha
    assert len(_events(w.engine, CUST_1)) == before + 1
    with get_sessionmaker()() as db:
        assert verify_identity_audit_chain(db, CUST_1)
    listed = w.call(w.c1_admin, "GET", "/admin/msp/relationships").json()["items"]
    assert [(i["relationship_id"], i["status"]) for i in listed] == [(rid, "revoked")]


# ---------------------------------------------------------------------------
# 21. Platform authority is governed and limited
# ---------------------------------------------------------------------------


def test_21_platform_designation_is_governed_and_grants_nothing(w, monkeypatch):
    # A tenant admin cannot make its own tenant an MSP.
    resp = w.call(
        w.c1_admin, "PUT", f"/admin/msp/organizations/{CUST_1}", {"status": "active"}
    )
    assert resp.status_code == 403
    assert w.designate(INTERNAL).status_code == 404  # not a customer tenant

    # Undesignated tenants cannot ask customers for access.
    w.designate(CUST_2)  # CUST_2 becomes an MSP, but has no relationships
    c2_staff = _seed_person(w.engine, CUST_2, "c2-staff", "viewer")
    assert w.customer_ids(c2_staff) == []

    # The platform operator holds no customer membership, so cannot approve.
    rid = w.propose(w.msp_a_admin, CUST_1).json()["relationship_id"]
    platform_in_c1 = Person("auth0|platform-op", CUST_1, "", "", "platform_admin")
    assert w.approve(platform_in_c1, rid).status_code == 403

    # Once the internal gateway secret is configured, the gateway is required.
    monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", "synthetic-internal-secret")
    resp = w.designate(MSP_B, "suspended")
    assert resp.status_code in (401, 403), resp.text


def test_21b_entitlement_gates_msp_operations(w, monkeypatch):
    import api.entitlements as ent
    from services.capability_bundles.resolver import invalidate_cache

    monkeypatch.setenv("FG_ENTITLEMENT_ENFORCEMENT", "true")
    monkeypatch.setattr(ent, "ENFORCEMENT_STRICT", True)
    invalidate_cache(MSP_A)

    resp = w.propose(w.msp_a_admin, CUST_1)
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "CAPABILITY_DENIED"


# ---------------------------------------------------------------------------
# 24. Concurrency
# ---------------------------------------------------------------------------


def test_24_one_open_relationship_per_pair_is_a_database_invariant(w):
    from api.db import get_sessionmaker
    from api.db_models_msp import MspServiceRelationship

    w.propose(w.msp_a_admin, CUST_1)
    now = _now()
    with get_sessionmaker()() as db:
        db.add(
            MspServiceRelationship(
                id=str(uuid.uuid4()),
                msp_tenant_id=MSP_A,
                tenant_id=CUST_1,
                status="proposed",
                requested_capabilities='["evidence.read"]',
                proposed_by_subject="race",
                proposed_at=now,
                version=1,
                created_at=now,
                updated_at=now,
            )
        )
        with pytest.raises(IntegrityError):
            db.flush()


def test_24b_stale_writer_loses_compare_and_set(w):
    from fastapi import HTTPException

    from api.db import get_sessionmaker
    from api.msp import _transition
    from api.msp_authority import load_relationship

    rid = w.establish(w.msp_a_admin, w.c1_admin)
    with get_sessionmaker()() as stale_db:
        stale = load_relationship(stale_db, rid)
        assert stale.status == "approved"
        # Meanwhile the customer revokes through the API.
        assert w.act(w.c1_admin, rid, "revoke").status_code == 200
        with pytest.raises(HTTPException) as exc:
            _transition(
                stale_db,
                stale,
                expected=("approved",),
                values={"status": "suspended", "suspended_at": _now()},
            )
    assert exc.value.status_code == 409
    status = w.sql("SELECT status FROM msp_service_relationships WHERE id=:id", id=rid)
    assert status.scalar() == "revoked"


def test_24c_self_relationship_is_a_database_invariant(w):
    from api.db import get_sessionmaker
    from api.db_models_msp import MspServiceRelationship

    now = _now()
    with get_sessionmaker()() as db:
        db.add(
            MspServiceRelationship(
                id=str(uuid.uuid4()),
                msp_tenant_id=MSP_A,
                tenant_id=MSP_A,
                status="proposed",
                requested_capabilities='["evidence.read"]',
                proposed_by_subject="x",
                proposed_at=now,
                version=1,
                created_at=now,
                updated_at=now,
            )
        )
        with pytest.raises(IntegrityError):
            db.flush()


# ---------------------------------------------------------------------------
# Legacy control-plane v2 MSP scope: a gate, no longer an authority
# ---------------------------------------------------------------------------


def _cp_get(w, path: str, tenant: str):
    key = mint_key(
        "control-plane:read",
        "control-plane:audit:read",
        "control-plane:msp:read",
        tenant_id=tenant,
    )
    return w.client.get(path, headers={"x-api-key": key})


def test_cp_msp_scope_alone_cannot_read_another_tenant(w):
    resp = _cp_get(w, f"/control-plane/v2/ledger?tenant_id={CUST_1}", MSP_A)
    assert resp.status_code == 404, resp.text


def test_cp_msp_scope_with_approved_relationship_reads_customer(w):
    w.establish(
        w.msp_a_admin, w.c1_admin, req=["governance.read"], auth=["governance.read"]
    )

    resp = _cp_get(w, f"/control-plane/v2/ledger?tenant_id={CUST_1}", MSP_A)
    assert resp.status_code == 200, resp.text
    assert resp.json()["tenant_scope"] == CUST_1
    # Another MSP's credential still cannot.
    assert (
        _cp_get(w, f"/control-plane/v2/ledger?tenant_id={CUST_1}", MSP_B).status_code
        == 404
    )


def test_cp_msp_scope_requires_the_delegated_capability(w):
    w.establish(
        w.msp_a_admin, w.c1_admin, req=["evidence.read"], auth=["evidence.read"]
    )

    resp = _cp_get(w, f"/control-plane/v2/ledger?tenant_id={CUST_1}", MSP_A)
    assert resp.status_code == 404, resp.text


def test_cp_msp_scope_without_filter_is_not_global(w):
    resp = _cp_get(w, "/control-plane/v2/ledger", MSP_A)
    assert resp.status_code == 200, resp.text
    assert resp.json()["tenant_scope"] == MSP_A


def test_cp_legacy_delegation_record_grants_nothing(w):
    from api.db import get_sessionmaker
    from services.cp_ledger import get_ledger
    from services.cp_msp_delegation import get_delegation_service

    with get_sessionmaker()() as db:
        get_delegation_service().create_delegation(
            db_session=db,
            ledger=get_ledger(),
            delegator_id="msp-a-key",
            delegatee_id="msp-a-key",
            target_tenant=CUST_1,
            scope="control-plane:read,control-plane:msp:read",
        )
        db.commit()
    resp = _cp_get(w, f"/control-plane/v2/ledger?tenant_id={CUST_1}", MSP_A)
    assert resp.status_code == 404, resp.text
