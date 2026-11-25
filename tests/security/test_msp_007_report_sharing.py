"""MSP-007 — customer-controlled, version-bound report sharing.

Numbered tests follow the MSP-007 acceptance matrix (``tNN`` in each name).
Every tenant, person, report and engagement is synthetic. There are no network
calls and no live billing. Postgres RLS proof is in
tests/test_migrations_postgres_replay.py (CI Migrations Replay job).

Released reports are produced through the canonical path only: Field
Assessment report generation, a named independent human QA approval, report
version approval, and the existing qualification fixture
(``tests.test_governed_delivery._inject_qualification``, the same test-only
QUALIFIED decision the release and governed-delivery suites use). Nothing
here forges a FINAL state.

Authority model under test: an MSP read of shared report content needs

  MSP designation active  ∩  bound MSP membership with report.read
  ∩ msp.multi_tenant  ∩  MSP-001 relationship active and delegating report.read
  ∩ customer-approved share, active and unexpired  ∩  customer tenant active
  ∩ same report id, version and fingerprint  ∩  FINAL now  ∩  integrity verifies
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from starlette.testclient import TestClient

from api.auth_scopes import mint_key
from tests._assurance_actors import install_human_actors, reviewer
from tests.security.test_msp_001_foundation import (
    CUST_1,
    CUST_2,
    MSP_A,
    MSP_B,
    READ_CAPS,
    World,
    _seed_person,
)
from tests.test_report_proof import _synthetic as S

SHARES = "/admin/msp/report-shares"
SHAREABLE = "/admin/msp/reports/shareable"
QA_SUBJECT = "auth0|msp7-independent-qa"


# ---------------------------------------------------------------------------
# World
# ---------------------------------------------------------------------------


@pytest.fixture
def app(build_app, module_app_cache, monkeypatch):
    monkeypatch.setenv("FG_REPORT_SIGNING_KEY", S.SIGNING_KEY_HEX)
    return build_app(auth_enabled=True, api_key="", reuse_from=module_app_cache)


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


class W7(World):
    """MSP-001 world that keeps the test-only named-human QA resolver."""

    def call(self, *args, **kwargs):  # type: ignore[override]
        try:
            return super().call(*args, **kwargs)
        finally:
            install_human_actors(self.app)


@pytest.fixture
def w(app, client) -> W7:
    from api.db import get_engine

    world = W7(app, client, get_engine())
    install_human_actors(app)
    return world


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _in(days: float) -> str:
    return (_now() + timedelta(days=days)).isoformat()


def _session():
    from api.db import get_sessionmaker

    return get_sessionmaker()()


def _code(resp) -> str:
    detail = resp.json().get("detail")
    return detail.get("code", "") if isinstance(detail, dict) else str(detail)


def _blockers(resp) -> list[str]:
    detail = resp.json().get("detail")
    return list(detail.get("blockers") or []) if isinstance(detail, dict) else []


# ---------------------------------------------------------------------------
# Canonical reports
# ---------------------------------------------------------------------------


def _fa_clients(app, tenant: str) -> tuple[TestClient, TestClient]:
    key = mint_key(
        "governance:read", "governance:write", "governance:qa_approve", tenant_id=tenant
    )
    author = TestClient(app, headers={"X-API-Key": key})
    qa = TestClient(app, headers={"X-API-Key": key, **reviewer(QA_SUBJECT)})
    return author, qa


def _engagement(app, tenant: str = CUST_1) -> str:
    author, _ = _fa_clients(app, tenant)
    return S.create_engagement(author, f"MSP-007 synthetic {tenant}")


def _report(
    app, tenant: str = CUST_1, eid: str | None = None, *, qa=True, qualify=True
) -> dict:
    """A report through the canonical lifecycle, to the requested stage."""
    from tests.test_governed_delivery import _inject_qualification

    author, qa_client = _fa_clients(app, tenant)
    eid = eid or S.create_engagement(author, f"MSP-007 synthetic {tenant}")
    S.seed(
        eid,
        synthetic=False,
        tamper=False,
        failed_job=False,
        tenant=tenant,
        proof_level="TEST_FIXTURE_ONLY",
    )
    rep = S.generate_report(author, eid)
    rid = rep["report_id"]
    if qa:
        vid = author.post(
            f"/field-assessment/engagements/{eid}/reports/{rid}/versions"
        ).json()["id"]
        author.post(
            f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}"
            "/submit-for-review"
        )
        ok = qa_client.post(
            f"/field-assessment/engagements/{eid}/reports/{rid}/qa-approve",
            json={"reviewer_name": "display only"},
        )
        assert ok.status_code == 200, ok.text
        ok = qa_client.post(
            f"/field-assessment/engagements/{eid}/reports/{rid}/versions/{vid}/approve",
            json={"reviewer_name": "QA", "reviewer_role": "QA Lead"},
        )
        assert ok.status_code == 200, ok.text
        if qualify:
            _inject_qualification(tenant, eid, rid, vid)
    with _session() as db:
        mh = db.execute(
            text("SELECT manifest_hash FROM governance_reports WHERE id = :i"),
            {"i": rid},
        ).scalar_one()
    return {"eid": eid, "rid": rid, "version": rep["version"], "hash": mh}


def _relate(w: W7, caps=None, msp_admin=None, cust_admin=None) -> str:
    return w.establish(
        msp_admin or w.msp_a_admin,
        cust_admin or w.c1_admin,
        req=caps or READ_CAPS,
        auth=caps or READ_CAPS,
    )


def _share(w: W7, rid_rel: str, rep: dict, who=None, *, key=None, days=30, **over):
    body = {
        "relationship_id": rid_rel,
        "report_id": rep["rid"],
        "manifest_hash": rep["hash"],
        "expires_at": _in(days),
        "request_key": key or f"share-{uuid.uuid4().hex[:10]}",
        **over,
    }
    return w.call(who or w.c1_admin, "POST", SHARES, body)


def _shared(w: W7, rep: dict | None = None) -> tuple[str, dict, dict]:
    rel = _relate(w)
    rep = rep or _report(w.app)
    resp = _share(w, rel, rep)
    assert resp.status_code == 200, resp.text
    return rel, rep, resp.json()


def _verify(w: W7, share_id: str, who=None):
    return w.call(who or w.msp_a_admin, "GET", f"{SHARES}/{share_id}/verify")


def _download(w: W7, share_id: str, who=None):
    return w.call(who or w.msp_a_admin, "GET", f"{SHARES}/{share_id}/download")


def _list(w: W7, who, party: str, **params):
    qs = "&".join([f"party={party}"] + [f"{k}={v}" for k, v in params.items()])
    resp = w.call(who, "GET", f"{SHARES}?{qs}")
    assert resp.status_code == 200, resp.text
    return resp.json()


def _decide(w: W7, who, share: dict, action: str, **extra):
    return w.call(
        who,
        "POST",
        f"{SHARES}/{share['share_id']}/{action}",
        {"expected_version": share["version"], **extra},
    )


def _events(tenant: str, prefix: str = "tenant.msp.report") -> list:
    from api.db_models_identity import TenantIdentityAuditEvent

    with _session() as db:
        from api.db import set_tenant_context

        set_tenant_context(db, tenant)
        rows = (
            db.query(TenantIdentityAuditEvent)
            .filter(
                TenantIdentityAuditEvent.tenant_id == tenant,
                TenantIdentityAuditEvent.event_type.like(f"{prefix}%"),
            )
            .order_by(TenantIdentityAuditEvent.created_at.asc())
            .all()
        )
        return [
            (r.event_type, dict(r.details_json or {}), r.actor_user_id) for r in rows
        ]


def _engagement_events(tenant: str, eid: str) -> list[tuple[str, dict]]:
    from api.db import set_tenant_context
    from api.db_models_field_assessment import FaEngagementAuditEvent

    with _session() as db:
        set_tenant_context(db, tenant)
        rows = (
            db.query(FaEngagementAuditEvent)
            .filter(
                FaEngagementAuditEvent.tenant_id == tenant,
                FaEngagementAuditEvent.engagement_id == eid,
            )
            .all()
        )
        return [(r.event_type, dict(r.payload or {})) for r in rows]


def _set_share(share_id: str, **values) -> None:
    from api.db_models_msp import MspReportShare

    with _session() as db:
        db.query(MspReportShare).filter(MspReportShare.id == share_id).update(
            values, synchronize_session=False
        )
        db.commit()


def _ts(dt: datetime) -> str:
    """A naive UTC timestamp string for raw SQL (no deprecated adapter)."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def _sql(statement: str, **params) -> None:
    with _session() as db:
        db.execute(text(statement), params)
        db.commit()


# ---------------------------------------------------------------------------
# 1–2. Direct customers and existing routes are unchanged
# ---------------------------------------------------------------------------


def test_t01_direct_customer_reports_remain_accessible_without_any_msp(w):
    rep = _report(w.app, CUST_2)
    author, _ = _fa_clients(w.app, CUST_2)
    exp = author.get(
        f"/field-assessment/engagements/{rep['eid']}/reports/{rep['version']}/export"
    )
    assert exp.status_code == 200 and exp.json()["report_state"]["state"] == "FINAL"
    # The direct customer's shareable view works and it has no shares at all.
    listing = w.call(w.c2_admin, "GET", SHAREABLE)
    assert listing.status_code == 200, listing.text
    item = next(i for i in listing.json()["items"] if i["report_id"] == rep["rid"])
    assert item["lifecycle"]["state"] == "FINAL" and item["share_eligible"] is True
    assert _list(w, w.c2_admin, "customer")["items"] == []


def test_t02_canonical_verify_route_and_shared_integrity_agree(w):
    _, rep, share = _shared(w)
    author, _ = _fa_clients(w.app, CUST_1)
    canonical = author.post(
        f"/field-assessment/engagements/{rep['eid']}/reports/{rep['version']}/verify"
    )
    assert canonical.status_code == 200, canonical.text
    assert canonical.json()["valid"] is True
    msp = _verify(w, share["share_id"])
    assert msp.status_code == 200, msp.text
    assert msp.json()["manifest_hash"] == canonical.json()["manifest_hash"]
    assert msp.json()["integrity"]["content"] == "HASH_VERIFIED"
    assert msp.json()["integrity"]["signature"] == "SIGNATURE_VERIFIED"


# ---------------------------------------------------------------------------
# 3–5. Nothing but an exact share grants report access
# ---------------------------------------------------------------------------


def test_t03_relationship_alone_grants_no_report_access(w):
    _relate(w)
    rep = _report(w.app)
    assert _list(w, w.msp_a_admin, "msp")["items"] == []
    # The MSP cannot read the customer's reports through Field Assessment,
    # with or without a forged tenant header.
    msp_key = mint_key("governance:read", tenant_id=MSP_A)
    c = TestClient(w.app, headers={"X-API-Key": msp_key})
    for headers in ({}, {"X-Tenant-ID": CUST_1}):
        r = c.get(
            f"/field-assessment/engagements/{rep['eid']}/reports/{rep['version']}",
            headers=headers,
        )
        assert r.status_code in (403, 404), r.text


def test_t04_payer_assignment_alone_grants_no_report_access(w):
    from tests.security.test_msp_003_orchestration import _entitle

    rel = _relate(w)
    _entitle(w, rel)
    _report(w.app)
    assert _list(w, w.msp_a_admin, "msp")["items"] == []


def _initiated(w: W7) -> tuple[str, dict, str]:
    """MSP-003: approved grant, initiated engagement (canonical path)."""
    from tests.security.test_msp_003_orchestration import (
        CAPS,
        _decide as grant_decide,
        _entitle,
        _initiate,
        _request,
    )

    rel = w.establish(w.msp_a_admin, w.c1_admin, req=CAPS, auth=CAPS)
    _entitle(w, rel)
    req = _request(w)
    assert req.status_code == 200, req.text
    ok = grant_decide(w, w.c1_admin, req.json(), "approve")
    assert ok.status_code == 200, ok.text
    init = _initiate(w, ok.json()["grant_id"])
    assert init.status_code == 200, init.text
    return rel, ok.json(), init.json()["engagement_id"]


def _request_share(w: W7, grant_id: str, who=None, key=None):
    return w.call(
        who or w.msp_a_admin,
        "POST",
        f"{SHARES}/requests",
        {"grant_id": grant_id, "request_key": key or f"rq-{uuid.uuid4().hex[:8]}"},
    )


def test_t05_assessment_grant_alone_grants_no_report_access(w):
    _, grant, eid = _initiated(w)
    _report(w.app, CUST_1, eid)
    req = _request_share(w, grant["grant_id"])
    assert req.status_code == 200, req.text
    share = req.json()
    assert share["status"] == "requested" and share["report_id"] is None
    assert share["access"]["blockers"] == ["SHARE_PENDING_CUSTOMER"]
    resp = _download(w, share["share_id"])
    assert resp.status_code == 409
    assert _blockers(resp) == ["SHARE_PENDING_CUSTOMER"]
    assert "report" not in resp.json()


# ---------------------------------------------------------------------------
# 6–11. Customer approval of an exact, released version
# ---------------------------------------------------------------------------


def test_t06_customer_approves_an_exact_report_version(w):
    _, rep, share = _shared(w)
    assert share["status"] == "active" and share["created"] is True
    assert (share["report_id"], share["report_version"], share["manifest_hash"]) == (
        rep["rid"],
        rep["version"],
        rep["hash"],
    )
    dl = _download(w, share["share_id"])
    assert dl.status_code == 200, dl.text
    doc = dl.json()
    assert (doc["report_id"], doc["version"], doc["manifest_hash"]) == (
        rep["rid"],
        rep["version"],
        rep["hash"],
    )
    assert doc["lifecycle"]["state"] == "FINAL"


def test_t06b_msp_request_is_answered_with_an_exact_version(w):
    _, grant, eid = _initiated(w)
    rep = _report(w.app, CUST_1, eid)
    share = _request_share(w, grant["grant_id"]).json()
    ok = _decide(
        w,
        w.c1_admin,
        share,
        "approve",
        report_id=rep["rid"],
        manifest_hash=rep["hash"],
        expires_at=_in(14),
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["status"] == "active"
    assert _download(w, share["share_id"]).status_code == 200


def test_t07_customer_cannot_share_another_tenants_report(w):
    rel = _relate(w)
    foreign = _report(w.app, CUST_2)
    resp = _share(w, rel, foreign)
    assert resp.status_code == 404 and _code(resp) == "MSP_REPORT_NOT_FOUND"
    unknown = _share(w, rel, {**foreign, "rid": "no-such-report"})
    assert unknown.status_code == 404 and _code(unknown) == "MSP_REPORT_NOT_FOUND"


def test_t08_msp_cannot_approve_its_own_sharing_access(w):
    _, grant, eid = _initiated(w)
    rep = _report(w.app, CUST_1, eid)
    share = _request_share(w, grant["grant_id"]).json()
    body = dict(report_id=rep["rid"], manifest_hash=rep["hash"], expires_at=_in(7))
    resp = _decide(w, w.msp_a_admin, share, "approve", **body)
    assert resp.status_code == 403 and _code(resp) == "MSP_APPROVAL_REQUIRES_CUSTOMER"
    # The customer route cannot be used by the MSP for its own relationship.
    rel = _list(w, w.msp_a_admin, "msp")["items"][0]["relationship_id"]
    resp = _share(w, rel, rep, who=w.msp_a_admin)
    assert resp.status_code in (403, 404)
    # A customer admin who is also an MSP member cannot approve.
    dual = _seed_person(
        w.engine, CUST_1, "dual-admin", "tenant_admin", principal_id=str(uuid.uuid4())
    )
    _seed_person(
        w.engine, MSP_A, "dual-staff", "viewer", principal_id=dual.principal_id
    )
    resp = _decide(w, dual, share, "approve", **body)
    assert resp.status_code == 403 and _code(resp) == "MSP_SELF_APPROVAL_DENIED"
    resp = _share(w, rel, rep, who=dual)
    assert resp.status_code == 403 and _code(resp) == "MSP_SELF_APPROVAL_DENIED"


def test_t09_report_without_qa_cannot_be_shared(w):
    rel = _relate(w)
    rep = _report(w.app, qa=False)
    resp = _share(w, rel, rep)
    assert resp.status_code == 409 and _code(resp) == "MSP_REPORT_NOT_SHAREABLE"
    assert "REPORT_NOT_RELEASED" in _blockers(resp)


def test_t10_draft_report_cannot_be_shared(w):
    rel = _relate(w)
    rep = _report(w.app, qa=False)
    item = next(
        i
        for i in w.call(w.c1_admin, "GET", SHAREABLE).json()["items"]
        if i["report_id"] == rep["rid"]
    )
    assert item["lifecycle"]["state"] != "FINAL" and item["share_eligible"] is False
    assert _share(w, rel, rep).status_code == 409


def test_t11_qa_approved_but_unqualified_report_cannot_be_shared(w):
    rel = _relate(w)
    rep = _report(w.app, qualify=False)
    item = next(
        i
        for i in w.call(w.c1_admin, "GET", SHAREABLE).json()["items"]
        if i["report_id"] == rep["rid"]
    )
    # QA-approved is a separate fact from released.
    assert item["lifecycle"]["qa_approved"] is True
    assert item["lifecycle"]["released"] is False
    resp = _share(w, rel, rep)
    assert resp.status_code == 409 and "REPORT_NOT_RELEASED" in _blockers(resp)


def test_t11b_fingerprint_the_customer_reviewed_must_match(w):
    rel = _relate(w)
    rep = _report(w.app)
    resp = _share(w, rel, rep, manifest_hash="0" * 64)
    assert resp.status_code == 409 and _code(resp) == "MSP_REPORT_FINGERPRINT_MISMATCH"


def test_t11c_share_window_is_bounded(w):
    rel = _relate(w)
    rep = _report(w.app)
    assert _share(w, rel, rep, days=91).status_code == 422
    assert _share(w, rel, rep, days=-1).status_code == 422


def test_t11d_relationship_must_delegate_report_read(w):
    rel = _relate(w, caps=["finding.read"])
    rep = _report(w.app)
    resp = _share(w, rel, rep)
    assert resp.status_code == 409 and _code(resp) == "MSP_REPORT_READ_NOT_DELEGATED"


# ---------------------------------------------------------------------------
# 12–17. Revocation, expiry and every authority input
# ---------------------------------------------------------------------------


def test_t12_revoked_share_denies_every_later_read(w):
    _, _, share = _shared(w)
    assert _download(w, share["share_id"]).status_code == 200
    ok = _decide(w, w.c1_admin, share, "revoke")
    assert ok.status_code == 200 and ok.json()["status"] == "revoked"
    for call in (_verify, _download):
        resp = call(w, share["share_id"])
        assert resp.status_code == 409 and _blockers(resp) == ["SHARE_REVOKED"]
    # The row and its history remain.
    hist = w.call(w.c1_admin, "GET", f"{SHARES}/{share['share_id']}/events")
    ops = [e["operation"] for e in hist.json()["items"]]
    assert "report.download" in ops and "report_share.revoke" in ops


def test_t13_expired_share_denies_access(w):
    _, _, share = _shared(w)
    _set_share(
        share["share_id"],
        decided_at=_now() - timedelta(days=2),
        expires_at=_now() - timedelta(minutes=1),
    )
    resp = _download(w, share["share_id"])
    assert resp.status_code == 409 and _blockers(resp) == ["SHARE_EXPIRED"]
    row = _list(w, w.c1_admin, "customer")["items"][0]
    assert row["status"] == "expired"
    assert row["next_actions"] == [{"owner": "customer", "code": "RENEW_REPORT_SHARE"}]


def test_t14_removed_entitlement_blocks_access(w, monkeypatch):
    import api.entitlements as ent
    from services.capability_bundles.resolver import invalidate_cache

    _, _, share = _shared(w)
    monkeypatch.setenv("FG_ENTITLEMENT_ENFORCEMENT", "true")
    monkeypatch.setattr(ent, "ENFORCEMENT_STRICT", True)
    invalidate_cache(MSP_A)
    for call in (_verify, _download):
        resp = call(w, share["share_id"])
        assert resp.status_code == 403 and _code(resp) == "CAPABILITY_DENIED"


def test_t15_suspended_msp_cannot_access_shared_reports(w):
    _, _, share = _shared(w)
    assert w.designate(MSP_A, "suspended").status_code == 200
    for call in (_verify, _download):
        assert call(w, share["share_id"]).status_code == 403


def test_t16_removed_msp_membership_blocks_access(w):
    _, _, share = _shared(w)
    w.sql(
        "UPDATE tenant_users SET active = 0 WHERE id = :m",
        m=w.msp_a_admin.membership_id,
    )
    for call in (_verify, _download):
        assert call(w, share["share_id"]).status_code == 403


def test_t17_customer_suspension_blocks_access(w):
    _, _, share = _shared(w)
    w.sql(
        "UPDATE tenants SET lifecycle_state = 'suspended' WHERE tenant_id = :t",
        t=CUST_1,
    )
    resp = _download(w, share["share_id"])
    assert resp.status_code == 409
    assert _blockers(resp) in (
        ["CUSTOMER_TENANT_INACTIVE"],
        ["RELATIONSHIP_NOT_DELEGATING_REPORT_READ"],
    )


def test_t17b_relationship_suspension_blocks_access(w):
    rel, _, share = _shared(w)
    assert w.act(w.c1_admin, rel, "suspend").status_code == 200
    resp = _download(w, share["share_id"])
    assert resp.status_code == 409
    assert _blockers(resp) == ["RELATIONSHIP_NOT_DELEGATING_REPORT_READ"]


# ---------------------------------------------------------------------------
# 18–22. Isolation, idempotency and concurrency
# ---------------------------------------------------------------------------


def test_t18_msp_b_cannot_read_msp_a_shares(w):
    _, _, share = _shared(w)
    for call in (_verify, _download):
        resp = call(w, share["share_id"], who=w.msp_b_admin)
        assert resp.status_code == 404 and _code(resp) == "MSP_REPORT_SHARE_NOT_FOUND"
    assert _list(w, w.msp_b_admin, "msp")["items"] == []
    events = w.call(w.msp_b_admin, "GET", f"{SHARES}/{share['share_id']}/events")
    assert events.status_code == 404


def test_t19_customer_b_cannot_see_customer_a_shares(w):
    _, _, share = _shared(w)
    assert _list(w, w.c2_admin, "customer")["items"] == []
    for action in ("revoke", "reject"):
        resp = _decide(w, w.c2_admin, share, action)
        assert resp.status_code == 404
    listing = w.call(w.c2_admin, "GET", SHAREABLE).json()["items"]
    assert all(i["report_id"] != share["report_id"] for i in listing)


def test_t20_pagination_is_isolated_per_party_and_customer(w):
    rel1 = _relate(w)
    rel2 = w.establish(w.msp_a_admin, w.c2_admin)
    reps1 = [_report(w.app, CUST_1) for _ in range(3)]
    rep2 = _report(w.app, CUST_2)
    for rep in reps1:
        assert _share(w, rel1, rep).status_code == 200
    assert _share(w, rel2, rep2, who=w.c2_admin).status_code == 200
    seen: list[str] = []
    page = _list(w, w.msp_a_admin, "msp", customer_tenant_id=CUST_1, limit=2)
    seen += [i["share_id"] for i in page["items"]]
    assert page["total"] == 3 and page["next_offset"] == 2
    page = _list(w, w.msp_a_admin, "msp", customer_tenant_id=CUST_1, limit=2, offset=2)
    seen += [i["share_id"] for i in page["items"]]
    assert len(set(seen)) == 3 and page["next_offset"] is None
    assert {
        i["customer_tenant_id"] for i in _list(w, w.msp_a_admin, "msp")["items"]
    } == {
        CUST_1,
        CUST_2,
    }
    assert _list(w, w.c2_admin, "customer")["total"] == 1


def test_t21_repeated_approval_is_idempotent(w):
    rel = _relate(w)
    rep = _report(w.app)
    first = _share(w, rel, rep, key="same-key")
    again = _share(w, rel, rep, key="same-key")
    assert first.status_code == again.status_code == 200
    assert again.json()["share_id"] == first.json()["share_id"]
    assert again.json()["created"] is False
    other = _report(w.app)
    resp = _share(w, rel, other, key="same-key")
    assert resp.status_code == 409 and _code(resp) == "MSP_REPORT_SHARE_CONFLICT"
    # A stale decision version loses.
    stale = {**first.json(), "version": first.json()["version"] + 5}
    assert _decide(w, w.c1_admin, stale, "revoke").status_code == 409


def test_t22_concurrent_second_active_share_is_refused_by_the_database(w):
    rel = _relate(w)
    rep = _report(w.app)
    assert _share(w, rel, rep).status_code == 200
    resp = _share(w, rel, rep)
    assert resp.status_code == 409 and _code(resp) == "MSP_REPORT_SHARE_CONFLICT"
    # The invariant is the database's, not only the route's.
    from sqlalchemy.exc import IntegrityError

    now = _now()
    with pytest.raises(IntegrityError):
        _sql(
            "INSERT INTO msp_report_shares (id, tenant_id, msp_tenant_id, "
            "relationship_id, origin, request_key, engagement_id, report_id, "
            "report_version, manifest_hash, status, requested_by_subject, "
            "requested_at, decided_by_subject, decided_at, expires_at, version, "
            "created_at, updated_at) VALUES (:id, :t, :m, :r, 'customer', 'raw', "
            ":e, :rid, 1, :h, 'active', 's', :now, 's', :now, :exp, 1, :now, :now)",
            id=str(uuid.uuid4()),
            t=CUST_1,
            m=MSP_A,
            r=rel,
            e=rep["eid"],
            rid=rep["rid"],
            h=rep["hash"],
            now=_ts(now),
            exp=_ts(now + timedelta(days=1)),
        )


def test_t22b_stale_writer_loses_compare_and_set(w):
    _, grant, eid = _initiated(w)
    rep = _report(w.app, CUST_1, eid)
    share = _request_share(w, grant["grant_id"]).json()
    body = dict(report_id=rep["rid"], manifest_hash=rep["hash"], expires_at=_in(7))
    assert _decide(w, w.c1_admin, share, "approve", **body).status_code == 200
    # Second writer holding the same version: approve or reject both lose.
    assert _decide(w, w.c1_admin, share, "approve", **body).status_code == 409
    assert _decide(w, w.c1_admin, share, "reject").status_code == 409


def test_t22c_share_without_bound_report_is_a_database_violation(w):
    from sqlalchemy.exc import IntegrityError

    rel = _relate(w)
    now = _now()
    with pytest.raises(IntegrityError):
        _sql(
            "INSERT INTO msp_report_shares (id, tenant_id, msp_tenant_id, "
            "relationship_id, origin, request_key, engagement_id, status, "
            "requested_by_subject, requested_at, version, created_at, updated_at) "
            "VALUES (:id, :t, :m, :r, 'customer', 'raw2', 'e', 'active', 's', :now, "
            "1, :now, :now)",
            id=str(uuid.uuid4()),
            t=CUST_1,
            m=MSP_A,
            r=rel,
            now=_ts(now),
        )


# ---------------------------------------------------------------------------
# 23–29. Audit, verification and version binding
# ---------------------------------------------------------------------------


def test_t23_access_events_are_written_to_both_parties_chains(w):
    _, rep, share = _shared(w)
    assert _verify(w, share["share_id"]).status_code == 200
    for tenant in (CUST_1, MSP_A):
        types = [e[0] for e in _events(tenant)]
        assert "tenant.msp.report_share_approved" in types
        assert "tenant.msp.report_verified" in types
        approved = next(
            d for t, d, _ in _events(tenant) if t == "tenant.msp.report_share_approved"
        )
        assert approved["share_id"] == share["share_id"]
        assert approved["report_id"] == rep["rid"]
        assert approved["manifest_hash"] == rep["hash"]
        assert approved["relationship_id"] == share["relationship_id"]
    # Unrelated tenants receive nothing.
    assert _events(CUST_2) == [] and _events(MSP_B) == []


def test_t24_download_is_audited_in_the_customer_engagement_trail(w):
    _, rep, share = _shared(w)
    assert _download(w, share["share_id"]).status_code == 200
    trail = _engagement_events(CUST_1, rep["eid"])
    accessed = [
        p
        for t, p in trail
        if t == "report.content_accessed" and p.get("channel") == "msp_share:download"
    ]
    assert len(accessed) == 1
    assert accessed[0]["share_id"] == share["share_id"]
    assert accessed[0]["msp_tenant_id"] == MSP_A
    assert "tenant.msp.report_downloaded" in [e[0] for e in _events(MSP_A)]


def test_t25_verification_matches_canonical_hashes(w):
    from api.db import set_tenant_context
    from api.db_models_governance_report import GovernanceReportRecord
    from api.field_assessment import _derive_manifest_hash_from_report_json

    _, rep, share = _shared(w)
    body = _verify(w, share["share_id"]).json()
    with _session() as db:
        set_tenant_context(db, CUST_1)
        record = db.get(GovernanceReportRecord, rep["rid"])
        assert _derive_manifest_hash_from_report_json(record.report_json) == rep["hash"]
    assert body["manifest_hash"] == rep["hash"]
    assert body["integrity"]["content"] == "HASH_VERIFIED"
    assert body["integrity"]["evidence_chain"] in (
        "AUDIT_CHAIN_VERIFIED",
        "VERIFICATION_UNAVAILABLE",
    )
    # A hash is never presented as a signature.
    assert body["integrity"]["signature_kind"] in ("trust_binding", "legacy_ed25519")


def _tamper(rid: str) -> None:
    from api.db import set_tenant_context
    from api.db_models_governance_report import GovernanceReportRecord

    with _session() as db:
        set_tenant_context(db, CUST_1)
        record = db.get(GovernanceReportRecord, rid)
        doc = dict(record.report_json)
        doc["executive_summary"] = {"tampered": True}
        record.report_json = doc
        db.commit()


def test_t26_hash_mismatch_fails_closed_without_leaking_content(w):
    _, rep, share = _shared(w)
    _tamper(rep["rid"])
    for call in (_verify, _download):
        resp = call(w, share["share_id"])
        assert resp.status_code == 409
        assert "REPORT_INTEGRITY_FAILED" in _blockers(resp)
        assert set(resp.json()["detail"]) == {"code", "blockers"}
        assert "tampered" not in resp.text
    assert "tenant.msp.report_integrity_failed" in [e[0] for e in _events(CUST_1)]
    denied = [
        p
        for t, p in _engagement_events(CUST_1, rep["eid"])
        if t == "report.access_denied" and p.get("share_id") == share["share_id"]
    ]
    assert denied


def test_t27_missing_report_record_fails_closed(w):
    _, rep, share = _shared(w)
    _sql("UPDATE governance_reports SET tenant_id = 'gone' WHERE id = :i", i=rep["rid"])
    resp = _download(w, share["share_id"])
    assert resp.status_code == 409 and _blockers(resp) == ["REPORT_UNAVAILABLE"]


def test_t28_a_new_report_version_does_not_widen_the_share(w):
    _, rep, share = _shared(w)
    newer = _report(w.app, CUST_1, rep["eid"])
    assert newer["rid"] != rep["rid"]
    doc = _download(w, share["share_id"]).json()
    assert doc["report_id"] == rep["rid"] and doc["version"] == rep["version"]
    shares = _list(w, w.msp_a_admin, "msp")["items"]
    assert [s["report_id"] for s in shares] == [rep["rid"]]


def test_t29_exact_fingerprint_stays_bound(w):
    _, rep, share = _shared(w)
    _sql(
        "UPDATE governance_reports SET manifest_hash = :h WHERE id = :i",
        h="f" * 64,
        i=rep["rid"],
    )
    resp = _download(w, share["share_id"])
    assert resp.status_code == 409 and _blockers(resp) == ["REPORT_VERSION_CHANGED"]


# ---------------------------------------------------------------------------
# 30–36. Request hygiene
# ---------------------------------------------------------------------------


def test_t30_customer_selection_and_tenant_headers_authorize_nothing(w):
    _, _, share = _shared(w)
    # Filtering by another customer never widens the MSP's rows.
    assert _list(w, w.msp_a_admin, "msp", customer_tenant_id=CUST_2)["items"] == []
    # A forged tenant header does not select another caller identity.
    resp = w.call(
        w.msp_b_admin,
        "GET",
        f"{SHARES}/{share['share_id']}/download",
        extra_headers={"X-Tenant-ID": MSP_A},
    )
    assert resp.status_code in (403, 404)


def test_t32_predictable_ids_are_indistinguishable_from_foreign_ones(w):
    _, _, share = _shared(w)
    unknown = _download(w, str(uuid.uuid4()), who=w.msp_b_admin)
    foreign = _download(w, share["share_id"], who=w.msp_b_admin)
    assert unknown.status_code == foreign.status_code == 404
    assert unknown.json() == foreign.json()


def test_t33_unsafe_identifiers_are_rejected(w):
    rel = _relate(w)
    rep = _report(w.app)
    for bad in ("../etc/passwd", "a/b", "x" * 300, "id with space"):
        resp = _share(w, rel, {**rep, "rid": bad})
        assert resp.status_code == 422, bad
    resp = w.call(w.msp_a_admin, "GET", f"{SHARES}/..%2F..%2Fsecret/download")
    assert resp.status_code in (404, 422)


def test_t34_refusals_carry_codes_only(w):
    _, rep, share = _shared(w)
    _decide(w, w.c1_admin, share, "revoke")
    resp = _download(w, share["share_id"])
    assert set(resp.json()["detail"]) == {"code", "blockers"}
    assert rep["hash"] not in resp.text


def test_t35_download_exposes_no_storage_credentials_or_urls(w):
    _, _, share = _shared(w)
    resp = _download(w, share["share_id"])
    assert resp.status_code == 200
    assert resp.headers["Cache-Control"] == "no-store, private"
    assert resp.headers["Content-Disposition"].startswith("attachment;")
    names = {k.lower() for k in resp.headers}
    assert not names & {"location", "set-cookie", "x-amz-security-token"}
    assert not any("token" in n or "presign" in n for n in names)
    values = " ".join(resp.headers.values()).lower()
    assert "://" not in values and "x-amz-" not in values
    assert set(resp.json()) == {
        "share_id",
        "customer_tenant_id",
        "report_id",
        "engagement_id",
        "version",
        "report_type",
        "schema_version",
        "manifest_hash",
        "signature",
        "signature_kind",
        "integrity",
        "lifecycle",
        "report",
    }


def test_t36_download_size_is_bounded(w, monkeypatch):
    import api.msp_reporting as mr

    _, _, share = _shared(w)
    monkeypatch.setattr(mr, "MAX_DOWNLOAD_BYTES", 64)
    resp = _download(w, share["share_id"])
    assert resp.status_code == 409 and _blockers(resp) == ["REPORT_TOO_LARGE"]


# ---------------------------------------------------------------------------
# 37–45. Canonical gates, other milestones and provenance
# ---------------------------------------------------------------------------


def test_t37_canonical_release_decision_is_re_evaluated_on_every_read(w):
    """Out-of-band evidence tampering after sharing: the canonical provenance
    decision stops being VERIFIED, the report is no longer FINAL, and the
    share stops working — no MSP-007 state is consulted for that."""
    _, rep, share = _shared(w)
    assert _download(w, share["share_id"]).status_code == 200
    S.tamper_host(S.persisted_scan_id(rep["eid"], "network_scan", tenant=CUST_1))
    resp = _download(w, share["share_id"])
    assert resp.status_code == 409
    assert "REPORT_NOT_RELEASED" in _blockers(resp)


def test_t37b_approved_reports_cannot_be_qa_rejected_into_a_hidden_state(w):
    """The canonical QA rule is unchanged: an approved report cannot be
    rejected (it is superseded instead), so sharing cannot race QA."""
    _, rep, share = _shared(w)
    _, qa = _fa_clients(w.app, CUST_1)
    rej = qa.post(
        f"/field-assessment/engagements/{rep['eid']}/reports/{rep['rid']}/qa-reject",
        json={
            "reason_code": "FINDING_INACCURATE",
            "explanation": "Synthetic rejection after sharing to prove the gate holds.",
        },
    )
    assert rej.status_code == 409 and _code(rej) == "REPORT_ALREADY_APPROVED"
    assert _download(w, share["share_id"]).status_code == 200


def test_t38_sharing_and_reading_record_no_billing_usage(w):
    from tests.security.test_msp_003_orchestration import _entitle

    rel = _relate(w)
    _entitle(w, rel)
    rep = _report(w.app)
    share = _share(w, rel, rep).json()
    _verify(w, share["share_id"])
    _download(w, share["share_id"])
    with _session() as db:
        count = db.execute(text("SELECT COUNT(*) FROM usage_events")).scalar_one()
    assert count == 0


def test_t39_grant_revocation_does_not_touch_an_active_share(w):
    from tests.security.test_msp_003_orchestration import _decide as grant_decide

    _, grant, eid = _initiated(w)
    rep = _report(w.app, CUST_1, eid)
    share = _request_share(w, grant["grant_id"]).json()
    body = dict(report_id=rep["rid"], manifest_hash=rep["hash"], expires_at=_in(7))
    assert _decide(w, w.c1_admin, share, "approve", **body).status_code == 200
    current = next(
        g
        for g in w.call(w.c1_admin, "GET", "/admin/msp/assessments/grants").json()[
            "items"
        ]
        if g["grant_id"] == grant["grant_id"]
    )
    assert grant_decide(w, w.c1_admin, current, "revoke").status_code == 200
    # The share is the customer's separate decision.
    assert _download(w, share["share_id"]).status_code == 200
    # A revoked grant cannot start a new request.
    resp = _request_share(w, grant["grant_id"])
    assert resp.status_code == 409


def test_t39b_request_requires_the_msps_own_initiated_grant(w):
    _, grant, _ = _initiated(w)
    assert _request_share(w, grant["grant_id"], who=w.msp_b_admin).status_code == 404
    assert _request_share(w, str(uuid.uuid4())).status_code == 404


def test_t40_share_events_appear_in_relationship_history_attributed(w):
    rel, _, share = _shared(w)
    _verify(w, share["share_id"])
    hist = w.call(w.c1_admin, "GET", f"/admin/msp/relationships/{rel}/events").json()
    parties = {e["operation"]: e["actor_party"] for e in hist["items"]}
    assert parties["report_share.approve"] == "customer"
    assert parties["report.verify"] == "msp"
    # MSP-002 portfolio still lists the customer.
    assert CUST_1 in w.customer_ids(w.msp_a_admin)


def test_t40b_customer_sees_who_read_its_evidence(w):
    _, _, share = _shared(w)
    _download(w, share["share_id"])
    hist = w.call(w.c1_admin, "GET", f"{SHARES}/{share['share_id']}/events").json()
    reads = [e for e in hist["items"] if e["operation"] == "report.download"]
    assert reads and reads[0]["actor_subject"] == w.msp_a_admin.subject
    # The MSP does not learn the customer's deciding people.
    msp_hist = w.call(w.msp_a_admin, "GET", f"{SHARES}/{share['share_id']}/events")
    approve = [
        e for e in msp_hist.json()["items"] if e["operation"] == "report_share.approve"
    ]
    assert approve and approve[0]["actor_subject"] is None
    msp_row = _list(w, w.msp_a_admin, "msp")["items"][0]
    assert "decided_by_subject" not in msp_row


def test_t43_audit_chains_remain_verifiable(w):
    from api.db import set_tenant_context
    from api.identity.store import verify_identity_audit_chain

    _, _, share = _shared(w)
    _verify(w, share["share_id"])
    _download(w, share["share_id"])
    _decide(w, w.c1_admin, _list(w, w.c1_admin, "customer")["items"][0], "revoke")
    _download(w, share["share_id"])
    for tenant in (CUST_1, MSP_A):
        with _session() as db:
            set_tenant_context(db, tenant)
            assert verify_identity_audit_chain(db, tenant)
    hist = w.call(w.c1_admin, "GET", f"{SHARES}/{share['share_id']}/events").json()
    assert hist["chain_verified"] is True


def test_t44_report_index_contains_no_fabricated_metrics(w):
    _report(w.app)
    items = w.call(w.c1_admin, "GET", SHAREABLE).json()["items"]
    banned = {"score", "readiness_score", "compliance_score", "percent", "grade"}

    def keys(obj) -> set[str]:
        if isinstance(obj, dict):
            out = set(obj)
            for v in obj.values():
                out |= keys(v)
            return out
        if isinstance(obj, list):
            return set().union(*(keys(v) for v in obj)) if obj else set()
        return set()

    assert not (keys(items) & banned)
    lifecycle = items[0]["lifecycle"]
    for fact in (
        "exists",
        "qa_approved",
        "independent_qa",
        "production_qualified",
        "released",
        "delivery_authorized",
        "delivered",
    ):
        assert isinstance(lifecycle[fact], bool)


def test_t45_every_share_traces_to_canonical_records(w):
    _, rep, share = _shared(w)
    with _session() as db:
        from api.db import set_tenant_context

        set_tenant_context(db, CUST_1)
        row = db.execute(
            text(
                "SELECT s.report_id, s.report_version, s.manifest_hash, "
                "s.engagement_id, g.version, g.manifest_hash, g.engagement_id "
                "FROM msp_report_shares s JOIN governance_reports g "
                "ON g.id = s.report_id WHERE s.id = :i"
            ),
            {"i": share["share_id"]},
        ).one()
    assert row[0] == rep["rid"]
    assert (row[1], row[2], row[3]) == (row[4], row[5], row[6])


def test_t46_msp_withdraws_only_its_own_pending_request(w):
    _, grant, _ = _initiated(w)
    share = _request_share(w, grant["grant_id"]).json()
    assert _decide(w, w.c1_admin, share, "withdraw").status_code == 403
    ok = _decide(w, w.msp_a_admin, share, "withdraw")
    assert ok.status_code == 200 and ok.json()["status"] == "withdrawn"
    assert "tenant.msp.report_share_withdrawn" in [e[0] for e in _events(CUST_1)]


def test_t47_customer_rejects_a_request(w):
    _, grant, _ = _initiated(w)
    share = _request_share(w, grant["grant_id"]).json()
    ok = _decide(w, w.c1_admin, share, "reject")
    assert ok.status_code == 200 and ok.json()["status"] == "rejected"
    assert _blockers(_download(w, share["share_id"])) == ["SHARE_REJECTED"]


def test_t48_read_only_credentials_cannot_decide(w):
    _, _, share = _shared(w)
    resp = w.call(
        w.c1_member,
        "POST",
        f"{SHARES}/{share['share_id']}/revoke",
        {"expected_version": share["version"]},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Synthetic end-to-end demonstration (MSP-007 section 19)
# ---------------------------------------------------------------------------


def test_demo_customer_controlled_evidence_sharing_end_to_end(w):
    """MSP Alpha (msp-a), Customer One (cust-1), Customer Two (cust-2), MSP
    Beta (msp-b). Synthetic records only; the qualification step is the
    existing test fixture, documented as the test boundary."""
    # 1-2. Relationship and an MSP-003 initiated assessment.
    _, grant, eid = _initiated(w)
    # 3. Canonical readiness to release: report, independent QA, qualification.
    rep = _report(w.app, CUST_1, eid)
    unrelated = _report(w.app, CUST_1)
    # 4-5. Customer One approves one finalized version for MSP Alpha.
    share = _request_share(w, grant["grant_id"]).json()
    approved = _decide(
        w,
        w.c1_admin,
        share,
        "approve",
        report_id=rep["rid"],
        manifest_hash=rep["hash"],
        expires_at=_in(30),
    )
    assert approved.status_code == 200, approved.text
    # 6-7. MSP Alpha inspects and verifies provenance.
    summary = _verify(w, share["share_id"]).json()
    assert summary["lifecycle"]["state"] == "FINAL"
    assert summary["integrity"]["content"] == "HASH_VERIFIED"
    # 8. Downloads only the authorized artifact.
    doc = _download(w, share["share_id"]).json()
    assert doc["report_id"] == rep["rid"] != unrelated["rid"]
    # 9-11. MSP Beta, Customer Two and unrelated reports stay out of reach.
    assert _download(w, share["share_id"], who=w.msp_b_admin).status_code == 404
    assert _list(w, w.c2_admin, "customer")["items"] == []
    assert [s["report_id"] for s in _list(w, w.msp_a_admin, "msp")["items"]] == [
        rep["rid"]
    ]
    # 12-13. Revocation stops later access.
    current = _list(w, w.c1_admin, "customer")["items"][0]
    assert _decide(w, w.c1_admin, current, "revoke").status_code == 200
    assert _download(w, share["share_id"]).status_code == 409
    # 14. History survives revocation.
    hist = w.call(w.c1_admin, "GET", f"{SHARES}/{share['share_id']}/events").json()
    ops = {e["operation"] for e in hist["items"]}
    assert {
        "report_share.request",
        "report_share.approve",
        "report.verify",
        "report.download",
        "report_share.revoke",
    } <= ops
    assert hist["chain_verified"] is True
    # 15. Integrity still verifies for the owner through the canonical route.
    author, _ = _fa_clients(w.app, CUST_1)
    v = author.post(
        f"/field-assessment/engagements/{eid}/reports/{rep['version']}/verify"
    )
    assert v.json()["valid"] is True
    # 16-17. Sharing charged nothing (delivery remains the only producer).
    with _session() as db:
        assert db.execute(text("SELECT COUNT(*) FROM usage_events")).scalar_one() == 0


# ---------------------------------------------------------------------------
# Review fixes (Codex review of PR #892)
# ---------------------------------------------------------------------------


def test_review_no_report_or_share_row_is_reloaded_after_commit(w):
    """Forced RLS hides governance_reports and msp_report_shares rows once
    commit clears the transaction-local tenant context, so any post-commit
    reload of an expired row fails on Postgres (ObjectDeletedError). SQLite
    has no RLS, so every post-commit reload is treated as that failure."""
    from sqlalchemy import event
    from sqlalchemy.orm import Session, object_session

    from api.db_models_governance_report import GovernanceReportRecord
    from api.db_models_msp import MspReportShare

    _, grant, eid = _initiated(w)
    rep = _report(w.app, CUST_1, eid)
    committed: set[int] = set()
    reloads: list[str] = []

    def _after_commit(session) -> None:
        committed.add(id(session))

    def _on_refresh(target, context, attrs) -> None:
        sess = object_session(target)
        if sess is not None and id(sess) in committed:
            reloads.append(f"{type(target).__name__}:{target.id}")

    event.listen(Session, "after_commit", _after_commit)
    for model in (GovernanceReportRecord, MspReportShare):
        event.listen(model, "refresh", _on_refresh, propagate=True)
    try:
        share = _request_share(w, grant["grant_id"]).json()
        body = dict(report_id=rep["rid"], manifest_hash=rep["hash"], expires_at=_in(7))
        assert _decide(w, w.c1_admin, share, "approve", **body).status_code == 200
        assert _verify(w, share["share_id"]).status_code == 200
        assert _download(w, share["share_id"]).status_code == 200
        current = _list(w, w.c1_admin, "customer")["items"][0]
        assert _decide(w, w.c1_admin, current, "revoke").status_code == 200
        assert _download(w, share["share_id"]).status_code == 409
    finally:
        for model in (GovernanceReportRecord, MspReportShare):
            event.remove(model, "refresh", _on_refresh)
        event.remove(Session, "after_commit", _after_commit)
    assert reloads == [], f"rows reloaded after commit: {reloads}"


def test_review_an_expired_share_can_be_renewed_and_keeps_its_history(w):
    rel, rep, share = _shared(w)
    assert _download(w, share["share_id"]).status_code == 200
    _set_share(
        share["share_id"],
        decided_at=_now() - timedelta(days=2),
        expires_at=_now() - timedelta(minutes=1),
    )
    # Renewing the same report for the same partner is allowed.
    renewed = _share(w, rel, rep)
    assert renewed.status_code == 200, renewed.text
    assert renewed.json()["status"] == "active"
    assert renewed.json()["share_id"] != share["share_id"]
    assert _download(w, renewed.json()["share_id"]).status_code == 200
    # The expired authorization is retired, not deleted, and stays unusable.
    rows = {r["share_id"]: r for r in _list(w, w.c1_admin, "customer")["items"]}
    assert rows[share["share_id"]]["status"] == "expired"
    assert _blockers(_download(w, share["share_id"])) == ["SHARE_EXPIRED"]
    hist = w.call(w.c1_admin, "GET", f"{SHARES}/{share['share_id']}/events").json()
    ops = [e["operation"] for e in hist["items"]]
    assert "report_share.expire" in ops and "report.download" in ops
    assert "tenant.msp.report_share_expired" in [e[0] for e in _events(MSP_A)]


def test_review_an_expired_share_does_not_block_approving_a_new_request(w):
    _, grant, eid = _initiated(w)
    rep = _report(w.app, CUST_1, eid)
    first = _request_share(w, grant["grant_id"]).json()
    body = dict(report_id=rep["rid"], manifest_hash=rep["hash"], expires_at=_in(7))
    assert _decide(w, w.c1_admin, first, "approve", **body).status_code == 200
    _set_share(
        first["share_id"],
        decided_at=_now() - timedelta(days=2),
        expires_at=_now() - timedelta(minutes=1),
    )
    second = _request_share(w, grant["grant_id"]).json()
    ok = _decide(w, w.c1_admin, second, "approve", **body)
    assert ok.status_code == 200, ok.text
    # An active, unexpired share still blocks a duplicate.
    third = _request_share(w, grant["grant_id"]).json()
    assert _decide(w, w.c1_admin, third, "approve", **body).status_code == 409
