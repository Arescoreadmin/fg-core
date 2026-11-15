"""MSP-002 — the console's real transport, and the first-client demonstration.

The console BFF never holds a tenant key for these routes. It sends the admin
gateway machine credential plus an HMAC delegation proof (v3) that binds the
request id, the session's own tenant, the method, the path, the named Auth0
subject and the authority class (``tenant_human``). Core verifies the proof,
then requires that subject to be the unique active bound ``tenant_admin`` of
that tenant, and builds the actor from DB roles, never from the gateway key.

These tests drive exactly those headers (built with the shared
``tests/admin_gateway_delegation.py`` helper, which mirrors the BFF's
``createDelegationProof``). Every tenant, person and record is synthetic.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from tests.admin_gateway_delegation import configure_delegation_env, delegation_headers
from tests.security.test_msp_001_foundation import Person, _seed_person, _seed_tenant

TOKEN = "test-admin-gateway-token"
MSP_ALPHA = "msp-alpha"
CUSTOMER_ONE = "customer-one"
CUSTOMER_TWO = "customer-two"


@pytest.fixture
def gw(tmp_path, monkeypatch):
    db_path = tmp_path / "msp_002_console.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AUTH_ENABLED", "1")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", TOKEN)
    monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", TOKEN)
    monkeypatch.setenv("FG_ENTITLEMENT_ENFORCEMENT", "false")
    configure_delegation_env(monkeypatch)

    from api.db import get_engine, init_db, reset_engine_cache
    from api.main import build_app

    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    client = TestClient(build_app(auth_enabled=True), raise_server_exceptions=False)
    engine = get_engine()
    for t in (MSP_ALPHA, CUSTOMER_ONE, CUSTOMER_TWO):
        _seed_tenant(engine, t)
    people = {
        "alpha_admin": _seed_person(engine, MSP_ALPHA, "alpha-admin", "tenant_admin"),
        "alpha_staff": _seed_person(engine, MSP_ALPHA, "alpha-staff", "viewer"),
        "one_admin": _seed_person(engine, CUSTOMER_ONE, "one-admin", "tenant_admin"),
        "two_admin": _seed_person(engine, CUSTOMER_TWO, "two-admin", "tenant_admin"),
    }
    yield client, engine, people
    reset_engine_cache()


def _console(client, who: Person, method: str, path: str, json=None, *, tenant=None):
    """One request exactly as the console BFF sends it for a tenant admin."""
    tenant = tenant or who.tenant
    request_id = f"req-{uuid.uuid4().hex}"
    headers = {
        "X-API-Key": TOKEN,
        "X-FG-Internal-Token": TOKEN,
        "X-Admin-Gateway-Internal": "true",
        "X-Tenant-ID": tenant,
        "X-Request-ID": request_id,
        **delegation_headers(
            tenant_id=tenant,
            method=method,
            path=path.split("?", 1)[0],
            request_id=request_id,
            actor_subject=who.subject,
            actor_authority="tenant_human",
        ),
    }
    return client.request(method, path, json=json, headers=headers)


def _platform_designate(client, tenant: str):
    """The platform operator path: internal gateway machine credential only."""
    return client.put(
        f"/admin/msp/organizations/{tenant}",
        json={"status": "active"},
        headers={
            "X-API-Key": TOKEN,
            "X-FG-Internal-Token": TOKEN,
            "X-Admin-Gateway-Internal": "true",
        },
    )


def _seed_assessment(engine, tenant: str) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO fa_engagements (id, tenant_id, client_name, assessor_id,"
                " assessment_type, status, engagement_metadata, schema_version,"
                " created_at, updated_at) VALUES (:id, :t, 'Synthetic', 'assessor-x',"
                " 'ai_governance', 'delivered', '{}', '1.0', :u, :u)"
            ),
            {"id": f"eng-{tenant}", "t": tenant, "u": "2026-11-10T10:00:00Z"},
        )
        conn.execute(
            text(
                "INSERT INTO fa_normalized_findings (id, tenant_id, engagement_id,"
                " finding_type, findings_hash, severity, status, title, description,"
                " source_attribution, confidence_score, framework_mappings,"
                " nist_ai_rmf_mappings, evidence_ref_ids, schema_version, created_at,"
                " updated_at) VALUES (:id, :t, :e, 'policy_gap', :h, 'high', 'open',"
                " 'Synthetic finding', 'Synthetic', 'synthetic', 80, '[]', '[]',"
                " '[]', '1.0', :u, :u)"
            ),
            {
                "id": f"fnd-{tenant}",
                "t": tenant,
                "e": f"eng-{tenant}",
                "h": uuid.uuid4().hex,
                "u": "2026-11-11T10:00:00Z",
            },
        )


# ---------------------------------------------------------------------------
# Transport invariants
# ---------------------------------------------------------------------------


def test_console_actor_cannot_select_another_tenant(gw):
    client, _, people = gw
    assert _platform_designate(client, MSP_ALPHA).status_code == 200
    # The MSP admin's proof names CUSTOMER_ONE as the tenant: the human is not
    # that tenant's admin, so Core refuses before any MSP route logic runs.
    spoof = _console(
        client,
        people["alpha_admin"],
        "GET",
        "/admin/msp/relationships",
        tenant=CUSTOMER_ONE,
    )
    assert spoof.status_code == 403, spoof.text


def test_console_proof_is_bound_to_the_path(gw):
    client, _, people = gw
    assert _platform_designate(client, MSP_ALPHA).status_code == 200
    who = people["alpha_admin"]
    request_id = "req-path-bound"
    headers = {
        "X-API-Key": TOKEN,
        "X-FG-Internal-Token": TOKEN,
        "X-Admin-Gateway-Internal": "true",
        "X-Tenant-ID": MSP_ALPHA,
        "X-Request-ID": request_id,
        **delegation_headers(
            tenant_id=MSP_ALPHA,
            method="GET",
            path="/admin/msp/customers",
            request_id=request_id,
            actor_subject=who.subject,
            actor_authority="tenant_human",
        ),
    }
    resp = client.get("/admin/msp/portfolio", headers=headers)
    assert resp.status_code == 403, resp.text


def test_console_non_admin_msp_staff_is_refused(gw):
    """Documented MSP-002 limit: console delegation is tenant_admin only."""
    client, _, people = gw
    assert _platform_designate(client, MSP_ALPHA).status_code == 200
    resp = _console(client, people["alpha_staff"], "GET", "/admin/msp/portfolio")
    assert resp.status_code == 403, resp.text


# ---------------------------------------------------------------------------
# Phase 18 — first-client acceptance demonstration (deterministic)
# ---------------------------------------------------------------------------


def test_first_client_demonstration(gw):
    from api.db import get_sessionmaker, set_tenant_context
    from api.identity.store import verify_identity_audit_chain

    client, engine, people = gw
    alpha, one = people["alpha_admin"], people["one_admin"]
    _seed_assessment(engine, CUSTOMER_ONE)
    _seed_assessment(engine, CUSTOMER_TWO)

    # STEP 1 — the platform designates MSP Alpha.
    assert _platform_designate(client, MSP_ALPHA).status_code == 200

    # STEP 2 — MSP Alpha proposes a relationship to Customer One.
    proposed = _console(
        client,
        alpha,
        "POST",
        "/admin/msp/relationships",
        {
            "customer_tenant_id": CUSTOMER_ONE,
            "requested_capabilities": [
                "assessment.read",
                "finding.read",
                "evidence.read",
            ],
        },
    )
    assert proposed.status_code == 200, proposed.text
    rid = proposed.json()["relationship_id"]
    assert proposed.json()["status"] == "proposed"

    # Before approval MSP Alpha has no portfolio and no customer name.
    assert _console(client, alpha, "GET", "/admin/msp/portfolio").json()["items"] == []
    msp_rel = _console(client, alpha, "GET", "/admin/msp/relationships").json()
    assert msp_rel["items"][0]["counterparty_display_name"] is None

    # STEP 3 — Customer One's administrator reviews the request.
    queue = _console(client, one, "GET", "/admin/msp/relationships")
    assert queue.status_code == 200, queue.text
    request = queue.json()["items"][0]
    assert request["status"] == "proposed" and request["party"] == "customer"
    assert request["counterparty_display_name"] == f"Synthetic {MSP_ALPHA}"
    assert request["requested_capabilities"] == [
        "assessment.read",
        "evidence.read",
        "finding.read",
    ]

    # STEP 4 — Customer One approves specific read-only capabilities (narrowed).
    approved = _console(
        client,
        one,
        "POST",
        f"/admin/msp/relationships/{rid}/approve",
        {"authorized_capabilities": ["assessment.read", "finding.read"]},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["authorized_capabilities"] == [
        "assessment.read",
        "finding.read",
    ]

    # STEP 5 — MSP Alpha sees Customer One in its authorized portfolio.
    portfolio = _console(client, alpha, "GET", "/admin/msp/portfolio")
    assert portfolio.status_code == 200, portfolio.text
    items = portfolio.json()["items"]
    assert [i["customer_tenant_id"] for i in items] == [CUSTOMER_ONE]

    # STEP 6 — only the permitted summaries; evidence was not approved.
    item = items[0]
    assert item["effective_permissions"] == ["assessment.read", "finding.read"]
    assert item["assessment"]["engagements_by_status"] == {"delivered": 1}
    assert item["findings"]["outstanding_by_severity"] == {"high": 1}
    assert "governance" not in item
    ctx = _console(
        client, alpha, "POST", f"/admin/msp/customers/{CUSTOMER_ONE}/context"
    )
    assert ctx.status_code == 200 and ctx.json()["revalidation"] == "every_request"

    # STEP 7 — MSP Alpha is denied the unapproved Customer Two.
    denied = _console(
        client, alpha, "POST", f"/admin/msp/customers/{CUSTOMER_TWO}/context"
    )
    assert denied.status_code == 404
    assert denied.json()["detail"] == {"code": "MSP_CUSTOMER_NOT_FOUND"}
    spoof = _console(client, alpha, "GET", "/admin/msp/portfolio", tenant=CUSTOMER_TWO)
    assert spoof.status_code == 403

    # STEP 8 — Customer One revokes.
    revoked = _console(client, one, "POST", f"/admin/msp/relationships/{rid}/revoke")
    assert revoked.status_code == 200 and revoked.json()["status"] == "revoked"

    # STEP 9 — MSP Alpha loses access on the very next request.
    assert _console(client, alpha, "GET", "/admin/msp/portfolio").json()["items"] == []
    gone = _console(
        client, alpha, "POST", f"/admin/msp/customers/{CUSTOMER_ONE}/context"
    )
    assert gone.status_code == 404

    # STEP 10 — Customer One's records and audit chain are intact.
    with engine.begin() as conn:
        counts = conn.execute(
            text(
                "SELECT (SELECT COUNT(*) FROM fa_engagements WHERE tenant_id = :t),"
                " (SELECT COUNT(*) FROM fa_normalized_findings WHERE tenant_id = :t)"
            ),
            {"t": CUSTOMER_ONE},
        ).fetchone()
    assert tuple(counts) == (1, 1)
    db = get_sessionmaker()()
    try:
        for tenant in (CUSTOMER_ONE, MSP_ALPHA):
            set_tenant_context(db, tenant)
            assert verify_identity_audit_chain(db, tenant), tenant
    finally:
        db.close()

    # STEP 11 — the customer's own chain proves the whole lifecycle.
    history = _console(client, one, "GET", f"/admin/msp/relationships/{rid}/events")
    assert history.status_code == 200, history.text
    body = history.json()
    assert body["chain_verified"] is True
    assert [e["operation"] for e in reversed(body["items"])] == [
        "relationship.propose",
        "relationship.approve",
        "portfolio.summary",
        "context.resolve",
        "relationship.revoke.customer",
    ]
    assert alpha.subject not in history.text
