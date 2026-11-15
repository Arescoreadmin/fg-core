"""MSP-006 — partner billing, payer assignment and usage attribution.

Numbered tests follow the MSP-006 acceptance matrix. Synthetic tenants, prices
and processor identifiers only; no live Stripe credentials and no real money.
Postgres RLS proof is in tests/test_migrations_postgres_replay.py (CI).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from starlette.testclient import TestClient

from tests.security.test_msp_001_foundation import (
    CUST_1,
    CUST_2,
    MSP_A,
    MSP_B,
    READ_CAPS,
    World,
)

PRODUCT = "assessment.delivered"
METER = "msp.assessment_delivered"
RATE = 125_000  # USD 1,250.00 in minor units


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
# Synthetic commercial fixtures (existing authorities only)
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _session():
    from api.db import get_sessionmaker

    return get_sessionmaker()()


def _seed_meter(active: str = "1") -> None:
    from api.db_models_billing import UsageMeter

    with _session() as db:
        if db.query(UsageMeter).filter(UsageMeter.meter_code == METER).first():
            return
        db.add(
            UsageMeter(
                meter_code=METER,
                display_name="Assessment delivered (MSP)",
                unit="assessment",
                aggregation_mode="sum",
                billing_category="msp",
                active=active,
            )
        )
        db.commit()


def _seed_agreement(payer: str, status: str = "active") -> str:
    """The payer's commercial agreement in the subscription authority."""
    from api.db_models_subscriptions import SubscriptionContract

    cid = f"sc-{uuid.uuid4().hex[:10]}"
    with _session() as db:
        db.add(
            SubscriptionContract(
                id=cid,
                tenant_id=payer,
                contract_ref=f"SYN-{cid}",
                sku_package="msp_partner",
                sku_metadata={},
                status=status,
                starts_at=_now() - timedelta(days=30),
                created_by="synthetic",
            )
        )
        db.commit()
    return cid


def _seed_price(
    payer: str,
    *,
    rate=None,
    currency: str = "USD",
    start: datetime | None = None,
    tamper_hash: bool = False,
) -> str:
    """A hash-pinned price list and the payer's contract that binds it."""
    from api.billing import _canonical_contract_hash
    from api.db_models import PricingVersion, TenantContract
    from api.msp_billing import pricing_version_hash

    pvid = f"pv-{uuid.uuid4().hex[:10]}"
    entry = (
        rate
        if isinstance(rate, dict)
        else {"unit_amount_minor": RATE if rate is None else rate, "currency": currency}
    )
    rates = {PRODUCT: entry}
    with _session() as db:
        db.add(
            PricingVersion(
                pricing_version_id=pvid,
                effective_at=_now() - timedelta(days=30),
                rates_json=rates,
                sha256_hash=("0" * 64)
                if tamper_hash
                else pricing_version_hash(pvid, rates),
            )
        )
        db.flush()
        contract = TenantContract(
            tenant_id=payer,
            contract_id=f"tc-{pvid}",
            pricing_version_id=pvid,
            discount_rules_json={},
            commitment_minimum=0.0,
            start_at=start or (_now() - timedelta(days=30)),
            end_at=None,
        )
        contract.contract_hash = _canonical_contract_hash(contract)
        db.add(contract)
        db.commit()
    return pvid


def _deliver(
    customer: str, *, at: datetime | None = None, status: str = "delivered"
) -> str:
    """A delivered engagement plus its canonical delivery audit event, as the
    QA-approval auto-advance writes them."""
    from api.db_models_field_assessment import FaEngagementAuditEvent

    eid = f"eng-{uuid.uuid4().hex[:12]}"
    at = at or (_now() + timedelta(seconds=1))
    stamp = at.isoformat().replace("+00:00", "Z")
    with _session() as db:
        db.execute(
            text(
                "INSERT INTO fa_engagements (id, tenant_id, client_name, assessor_id,"
                " assessment_type, status, engagement_metadata, schema_version,"
                " created_at, updated_at) VALUES (:id, :t, 'Synthetic', 'assessor-x',"
                " 'ai_governance', :s, '{}', '1.0', :u, :u)"
            ),
            {"id": eid, "t": customer, "s": status, "u": stamp},
        )
        if status == "delivered":
            db.add(
                FaEngagementAuditEvent(
                    id=uuid.uuid4().hex,
                    tenant_id=customer,
                    engagement_id=eid,
                    event_type="engagement.status_transitioned",
                    actor="synthetic-qa",
                    reason_code="AUTO_ADVANCE_QA_APPROVED",
                    payload={"new_status": "delivered"},
                    created_at=stamp,
                )
            )
        db.commit()
    return eid


def _produce(customer: str, engagement_id: str):
    from api.msp_billing import record_assessment_delivery_usage

    with _session() as db:
        out = record_assessment_delivery_usage(
            db, customer_tenant_id=customer, engagement_id=engagement_id
        )
        db.commit()
    return out


def _usage_rows(tenant: str | None = None) -> list:
    from api.db_models_billing import UsageEvent

    with _session() as db:
        q = db.query(UsageEvent).filter(UsageEvent.meter_code == METER)
        if tenant:
            q = q.filter(UsageEvent.tenant_id == tenant)
        return [
            (r.id, r.tenant_id, dict(r.metadata_json or {}), r.billing_status)
            for r in q.all()
        ]


def _assign(
    w: World,
    rid: str,
    *,
    mode: str = "msp_paid",
    agreement: str,
    customer: str = CUST_1,
    currency: str = "USD",
    days: int = 90,
    who=None,
):
    return w.call(
        who or w.platform,
        "POST",
        "/admin/msp/billing/payer-assignments",
        {
            "customer_tenant_id": customer,
            "relationship_id": rid,
            "billing_mode": mode,
            "product_code": PRODUCT,
            "subscription_contract_id": agreement,
            "currency": currency,
            "expires_at": (_now() + timedelta(days=days)).isoformat(),
        },
    )


def _period(at: datetime | None = None) -> str:
    return (at or _now() + timedelta(seconds=1)).strftime("%Y-%m")


def _billable_world(w: World, mode: str = "msp_paid") -> tuple[str, str]:
    """MSP_A <-> CUST_1 approved; payer agreement, price, meter and assignment."""
    rid = w.establish(w.msp_a_admin, w.c1_admin, req=READ_CAPS, auth=READ_CAPS)
    payer = MSP_A if mode == "msp_paid" else CUST_1
    agreement = _seed_agreement(payer)
    _seed_price(payer)
    _seed_meter()
    resp = _assign(w, rid, mode=mode, agreement=agreement)
    assert resp.status_code == 200, resp.text
    return rid, resp.json()["payer_assignment_id"]


def _usage(w: World, who, period: str | None = None):
    return w.call(who, "GET", f"/admin/msp/billing/usage?period={period or _period()}")


# ---------------------------------------------------------------------------
# 1-2. Payer assignment for either mode
# ---------------------------------------------------------------------------


def test_01_msp_can_receive_a_valid_payer_assignment(w):
    rid, _ = _billable_world(w, "msp_paid")
    items = w.call(w.msp_a_admin, "GET", "/admin/msp/billing/payer-assignments")
    assert items.status_code == 200, items.text
    [a] = items.json()["items"]
    assert a["payer_tenant_id"] == MSP_A and a["billing_mode"] == "msp_paid"
    assert a["relationship_id"] == rid and a["caller_is_payer"] is True


def test_02_customer_can_receive_a_valid_payer_assignment(w):
    _billable_world(w, "customer_paid")
    [a] = w.call(w.c1_admin, "GET", "/admin/msp/billing/payer-assignments").json()[
        "items"
    ]
    assert a["payer_tenant_id"] == CUST_1 and a["caller_is_payer"] is True
    # The MSP is not the payer and sees no customer-paid assignment.
    msp = w.call(w.msp_a_admin, "GET", "/admin/msp/billing/payer-assignments")
    assert msp.json()["items"] == []


# ---------------------------------------------------------------------------
# 3-4. Relationship and approval create no financial authority
# ---------------------------------------------------------------------------


def test_03_04_relationship_and_approval_alone_create_no_liability(w):
    w.establish(w.msp_a_admin, w.c1_admin, req=READ_CAPS, auth=READ_CAPS)
    _seed_agreement(MSP_A)
    _seed_price(MSP_A)
    _seed_meter()
    with _session() as db:
        assert (
            db.execute(text("SELECT COUNT(*) FROM msp_payer_assignments")).scalar() == 0
        )
    out = _produce(CUST_1, _deliver(CUST_1))
    assert (out.status, out.reason) == ("not_applicable", "NO_PAYER_ASSIGNMENT")
    assert _usage_rows() == []
    assert _usage(w, w.msp_a_admin).json()["items"] == []


# ---------------------------------------------------------------------------
# 5-7, 32. Billing visibility
# ---------------------------------------------------------------------------


def test_05_06_foreign_tenants_see_no_assignments_or_charges(w):
    _billable_world(w)
    assert _produce(CUST_1, _deliver(CUST_1)).status == "recorded"
    for outsider in (w.c2_admin, w.msp_b_admin):
        a = w.call(outsider, "GET", "/admin/msp/billing/payer-assignments")
        assert a.status_code == 200 and a.json()["items"] == []
        u = _usage(w, outsider)
        assert u.status_code == 200 and u.json()["items"] == []
        assert MSP_A not in u.text and "125000" not in u.text
    # The customer is not the payer, so it never sees the MSP's wholesale charge.
    assert _usage(w, w.c1_admin).json()["items"] == []


def test_07_32_billing_reads_require_billing_permission(w):
    _billable_world(w)
    for who in (w.msp_a_staff, w.c1_member):
        for path in (
            "/admin/msp/billing/payer-assignments",
            f"/admin/msp/billing/usage?period={_period()}",
        ):
            assert w.call(who, "GET", path).status_code == 403, (who.subject, path)
    bad = w.call(w.msp_a_admin, "GET", "/admin/msp/billing/usage?period=2026-13")
    assert bad.status_code == 422
    assert bad.json()["detail"] == {"code": "BILLING_PERIOD_INVALID"}


# ---------------------------------------------------------------------------
# 8-10, 37-40. Payer resolution and assignment authority fail closed
# ---------------------------------------------------------------------------


def test_08_unknown_or_inactive_agreement_fails_closed(w):
    rid = w.establish(w.msp_a_admin, w.c1_admin, req=READ_CAPS, auth=READ_CAPS)
    resp = _assign(w, rid, agreement="sc-does-not-exist")
    assert resp.status_code == 409
    assert resp.json()["detail"] == {"code": "BILLING_AGREEMENT_INVALID"}
    # An agreement belonging to the customer cannot make the MSP the payer.
    resp = _assign(w, rid, agreement=_seed_agreement(CUST_1))
    assert resp.status_code == 409
    # An agreement canceled after assignment stops new charges.
    rid2, _ = rid, None
    agreement = _seed_agreement(MSP_A)
    _seed_price(MSP_A)
    _seed_meter()
    assert _assign(w, rid2, agreement=agreement).status_code == 200
    with _session() as db:
        db.execute(
            text("UPDATE subscription_contracts SET status='canceled' WHERE id=:i"),
            {"i": agreement},
        )
        db.commit()
    out = _produce(CUST_1, _deliver(CUST_1))
    assert (out.status, out.reason) == ("not_billable", "PAYER_AGREEMENT_INVALID")
    assert _usage_rows() == []


def test_09_37_one_active_payer_per_product(w):
    rid, _ = _billable_world(w, "msp_paid")
    _seed_price(CUST_1)
    second = _assign(w, rid, mode="customer_paid", agreement=_seed_agreement(CUST_1))
    assert second.status_code == 409
    assert second.json()["detail"] == {"code": "BILLING_PAYER_ASSIGNMENT_EXISTS"}
    # The database refuses a second active payer even outside the API.
    from api.db_models_msp import MspPayerAssignment

    with _session() as db:
        existing = db.query(MspPayerAssignment).one()
        clone = MspPayerAssignment(
            **{
                c.name: getattr(existing, c.name)
                for c in MspPayerAssignment.__table__.columns
                if c.name != "id"
            },
            id=str(uuid.uuid4()),
        )
        clone.billing_mode, clone.payer_tenant_id = "customer_paid", CUST_1
        db.add(clone)
        with pytest.raises(IntegrityError):
            db.flush()
        db.rollback()
    # One delivery, one usage record, one payer.
    assert _produce(CUST_1, _deliver(CUST_1)).status == "recorded"
    rows = _usage_rows()
    assert len(rows) == 1 and rows[0][1] == MSP_A


def test_09b_ambiguous_payer_resolution_fails_closed(w, monkeypatch):
    rid, _ = _billable_world(w)
    import api.msp_billing as mb

    real_query = mb.Session.query

    def doubled(self, *entities, **kw):
        q = real_query(self, *entities, **kw)
        if entities and entities[0] is mb.MspPayerAssignment:

            class _Q:
                def __init__(self, q):
                    self._q = q

                def filter(self, *a, **k):
                    return _Q(self._q.filter(*a, **k))

                def all(self):
                    rows = self._q.all()
                    return rows + rows

            return _Q(q)
        return q

    monkeypatch.setattr(mb.Session, "query", doubled)
    out = _produce(CUST_1, _deliver(CUST_1))
    monkeypatch.undo()
    assert (out.status, out.reason) == ("not_billable", "PAYER_AMBIGUOUS")
    assert _usage_rows() == []


def test_10_expired_assignment_fails_closed_and_is_audited(w):
    _billable_world(w)
    from api.db_models_msp import MspPayerAssignment

    with _session() as db:
        db.query(MspPayerAssignment).update(
            {
                "effective_at": _now() - timedelta(days=10),
                "expires_at": _now() - timedelta(days=1),
            }
        )
        db.commit()
    out = _produce(CUST_1, _deliver(CUST_1))
    assert (out.status, out.reason) == (
        "not_billable",
        "PAYER_ASSIGNMENT_NOT_IN_EFFECT",
    )
    assert _usage_rows() == []
    rows = w.sql(
        "SELECT reason_code FROM tenant_identity_audit_events WHERE tenant_id = :t"
        " AND event_type = 'tenant.msp.billing_usage_not_billable'",
        t=CUST_1,
    ).fetchall()
    assert [r[0] for r in rows] == ["MSP_BILLING_PAYER_ASSIGNMENT_NOT_IN_EFFECT"]


def test_38_39_neither_party_can_assign_a_payer(w):
    rid = w.establish(w.msp_a_admin, w.c1_admin, req=READ_CAPS, auth=READ_CAPS)
    _seed_meter()
    for who, mode, payer in (
        (w.c1_admin, "msp_paid", MSP_A),
        (w.msp_a_admin, "customer_paid", CUST_1),
        (w.msp_a_admin, "msp_paid", MSP_A),
    ):
        resp = _assign(w, rid, mode=mode, agreement=_seed_agreement(payer), who=who)
        assert resp.status_code == 403, (who.subject, resp.text)
    with _session() as db:
        assert (
            db.execute(text("SELECT COUNT(*) FROM msp_payer_assignments")).scalar() == 0
        )


def test_40_failed_assignment_leaves_no_partial_authority(w):
    rid = w.establish(w.msp_a_admin, w.c1_admin, req=READ_CAPS, auth=READ_CAPS)
    for bad in (
        {"agreement": _seed_agreement(MSP_A, status="draft")},
        {"agreement": _seed_agreement(MSP_A), "days": 500},
    ):
        resp = _assign(w, rid, **bad)
        assert resp.status_code in (409, 422), resp.text
    resp = w.call(
        w.platform,
        "POST",
        "/admin/msp/billing/payer-assignments",
        {
            "customer_tenant_id": CUST_2,
            "relationship_id": rid,
            "billing_mode": "msp_paid",
            "product_code": PRODUCT,
            "subscription_contract_id": _seed_agreement(MSP_A),
            "currency": "USD",
            "expires_at": (_now() + timedelta(days=30)).isoformat(),
        },
    )
    assert resp.status_code == 404  # relationship does not belong to CUST_2
    with _session() as db:
        assert (
            db.execute(text("SELECT COUNT(*) FROM msp_payer_assignments")).scalar() == 0
        )
    assert not w.sql(
        "SELECT 1 FROM tenant_identity_audit_events"
        " WHERE event_type = 'tenant.msp.payer_assigned'"
    ).fetchall()


# ---------------------------------------------------------------------------
# 11-17. Idempotent, trusted, canonical usage
# ---------------------------------------------------------------------------


def test_11_same_delivery_twice_is_charged_once(w):
    _billable_world(w)
    eid = _deliver(CUST_1)
    first, second = _produce(CUST_1, eid), _produce(CUST_1, eid)
    assert first.status == "recorded" and second.status == "duplicate"
    assert first.usage_event_id == second.usage_event_id
    assert len(_usage_rows()) == 1


def test_12_concurrent_producer_cannot_duplicate_usage(w, monkeypatch):
    _billable_world(w)
    eid = _deliver(CUST_1)
    first = _produce(CUST_1, eid)
    import api.msp_billing as mb
    import services.billing.metering as metering

    # Simulate the race: the second producer's pre-checks see nothing, as if
    # the first had not committed yet, so it reaches the INSERT.
    real = mb._existing_usage
    calls = {"n": 0}

    def racing(db, payer, key):
        calls["n"] += 1
        return None if calls["n"] == 1 else real(db, payer, key)

    monkeypatch.setattr(mb, "_existing_usage", racing)
    real_record = metering.record_usage_event

    def insert_without_precheck(db, tenant_id, meter_code, quantity, key, **kw):
        from api.db_models_billing import UsageEvent

        db.add(
            UsageEvent(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                meter_code=meter_code,
                quantity=quantity,
                idempotency_key=key,
                source=kw.get("source", "api"),
                metadata_json=kw.get("metadata_json") or {},
            )
        )
        db.flush()

    monkeypatch.setattr(mb, "record_usage_event", insert_without_precheck)
    second = _produce(CUST_1, eid)
    monkeypatch.setattr(mb, "record_usage_event", real_record)
    assert second.status == "duplicate"
    assert second.usage_event_id == first.usage_event_id
    assert len(_usage_rows()) == 1


def test_13_same_key_different_payload_is_rejected(w):
    from api.msp_billing import UsageIdempotencyConflict

    _billable_world(w)
    eid = _deliver(CUST_1)
    assert _produce(CUST_1, eid).status == "recorded"
    with _session() as db:
        db.execute(
            text("UPDATE usage_events SET metadata_json = :m"),
            {"m": json.dumps({"payload_sha256": "f" * 64})},
        )
        db.commit()
    with pytest.raises(UsageIdempotencyConflict):
        _produce(CUST_1, eid)
    assert len(_usage_rows()) == 1


def test_14_untrusted_producer_cannot_create_billable_usage(w):
    from tests.security.test_msp_001_foundation import mint_key

    _billable_world(w)
    resp = w.client.post(
        "/billing/usage/events",
        json={"meter_code": METER, "quantity": "1", "idempotency_key": "spoof-1"},
        headers={"x-api-key": mint_key("billing:write", tenant_id=MSP_A)},
    )
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"] == {"code": "BILLING_METER_RESTRICTED"}
    assert _usage_rows() == []


def test_15_cross_tenant_source_cannot_be_billed(w):
    _billable_world(w)
    foreign = _deliver(CUST_2)  # CUST_2 has no relationship and no payer
    out = _produce(CUST_1, foreign)
    assert (out.status, out.reason) == ("not_billable", "SOURCE_NOT_COMPLETED")
    out = _produce(CUST_2, foreign)
    assert out.status == "not_applicable"
    assert _usage_rows() == []


def test_16_incomplete_operation_is_never_billed(w):
    _billable_world(w)
    out = _produce(CUST_1, _deliver(CUST_1, status="in_progress"))
    assert (out.status, out.reason) == ("not_billable", "SOURCE_NOT_COMPLETED")
    assert _produce(CUST_1, "eng-missing").reason == "SOURCE_NOT_COMPLETED"
    assert _usage_rows() == []


def test_17_usage_binds_the_canonical_completion_and_all_parties(w):
    rid, aid = _billable_world(w)
    eid = _deliver(CUST_1)
    out = _produce(CUST_1, eid)
    [(uid, tenant, md, status)] = _usage_rows()
    assert uid == out.usage_event_id and tenant == MSP_A and status == "pending"
    with _session() as db:
        ref = db.execute(
            text("SELECT id FROM fa_engagement_audit_events WHERE engagement_id = :e"),
            {"e": eid},
        ).scalar()
    assert md["source_event_id"] == eid and md["source_event_ref"] == ref
    assert md["source_service"] == "field_assessment.delivery"
    assert md["schema_version"] == "msp006.usage.v1"
    assert (md["customer_tenant_id"], md["msp_tenant_id"]) == (CUST_1, MSP_A)
    assert (md["relationship_id"], md["payer_assignment_id"]) == (rid, aid)
    assert (md["payer_tenant_id"], md["billing_mode"]) == (MSP_A, "msp_paid")
    assert md["idempotency_key"] == f"msp006:{PRODUCT}:{CUST_1}:{eid}"
    assert md["occurred_at"] and md["ingested_at"] and md["payload_sha256"]


def test_17b_producer_is_wired_to_the_qa_delivery_advance_only():
    import inspect

    import api.field_assessment as fa

    src = inspect.getsource(fa)
    assert src.count("record_delivery_usage_safely(") == 1
    route = inspect.getsource(fa.qa_approve_report_route)
    advance = route.index('eng.status = "delivered"')
    hook = route.index("record_delivery_usage_safely(")
    grant = route.index("_portal_grant_svc.create_grant(")
    assert advance < hook < grant


# ---------------------------------------------------------------------------
# 18-21. Pricing and money
# ---------------------------------------------------------------------------


def test_18_19_price_is_pinned_and_history_is_not_repriced(w):
    _billable_world(w)
    pv1 = _usage_rows() or None
    t1 = _now() + timedelta(seconds=5)
    eid1 = _deliver(CUST_1, at=t1)
    assert _produce(CUST_1, eid1).status == "recorded"
    [(_, _, md1, _)] = _usage_rows()
    assert pv1 is None and md1["amount_minor"] == RATE
    # A new price list takes effect later; the first charge keeps its price.
    _seed_price(MSP_A, rate=150_000, start=t1 + timedelta(seconds=5))
    eid2 = _deliver(CUST_1, at=t1 + timedelta(seconds=10))
    assert _produce(CUST_1, eid2).status == "recorded"
    by_source = {r[2]["source_event_id"]: r[2] for r in _usage_rows()}
    assert by_source[eid1]["amount_minor"] == RATE
    assert by_source[eid1]["pricing_version_id"] == md1["pricing_version_id"]
    assert by_source[eid2]["amount_minor"] == 150_000
    assert by_source[eid2]["pricing_version_id"] != md1["pricing_version_id"]
    report = _reconcile(w, MSP_A, _period(t1))
    assert report["ok"] is True, report
    assert report["totals_minor_by_currency"] == {"USD": RATE + 150_000}


@pytest.mark.parametrize(
    "rate",
    [12.5, True, -1, "125000", {"unit_amount_minor": 1.0, "currency": "USD"}],
)
def test_20_monetary_values_must_be_exact_integers(w, rate):
    rid = w.establish(w.msp_a_admin, w.c1_admin, req=READ_CAPS, auth=READ_CAPS)
    agreement = _seed_agreement(MSP_A)
    _seed_price(MSP_A, rate=rate)
    _seed_meter()
    assert _assign(w, rid, agreement=agreement).status_code == 200
    out = _produce(CUST_1, _deliver(CUST_1))
    assert (out.status, out.reason) == ("not_billable", "PRICING_RATE_INVALID")
    assert _usage_rows() == []


def test_20b_amounts_are_integer_minor_units_end_to_end(w):
    _billable_world(w)
    for _ in range(3):
        _produce(CUST_1, _deliver(CUST_1))
    body = _usage(w, w.msp_a_admin).json()
    assert body["estimated_total_minor_by_currency"] == {"USD": 3 * RATE}
    for item in body["items"]:
        assert isinstance(item["amount_minor"], int) and item["currency"] == "USD"
    assert body["settlement"] == "NOT_PROVEN"


def test_21_currency_mismatch_fails_closed(w):
    rid = w.establish(w.msp_a_admin, w.c1_admin, req=READ_CAPS, auth=READ_CAPS)
    agreement = _seed_agreement(MSP_A)
    _seed_price(MSP_A, currency="USD")
    _seed_meter()
    assert _assign(w, rid, agreement=agreement, currency="EUR").status_code == 200
    out = _produce(CUST_1, _deliver(CUST_1))
    assert (out.status, out.reason) == ("not_billable", "PRICING_CURRENCY_MISMATCH")


def test_21b_tampered_price_list_fails_closed(w):
    rid = w.establish(w.msp_a_admin, w.c1_admin, req=READ_CAPS, auth=READ_CAPS)
    agreement = _seed_agreement(MSP_A)
    _seed_price(MSP_A, tamper_hash=True)
    _seed_meter()
    assert _assign(w, rid, agreement=agreement).status_code == 200
    out = _produce(CUST_1, _deliver(CUST_1))
    assert (out.status, out.reason) == ("not_billable", "PRICING_HASH_MISMATCH")


# ---------------------------------------------------------------------------
# 22-24, Phase 11. Authority separation and relationship lifecycle
# ---------------------------------------------------------------------------


def test_22_billing_and_relationship_authority_stay_separate(w):
    rid, aid = _billable_world(w)
    # A payer assignment grants no customer-data access...
    assert w.context(w.msp_a_staff, CUST_1).status_code == 200  # from MSP-001
    with _session() as db:
        items = db.execute(text("SELECT COUNT(*) FROM subscription_items")).scalar()
    assert items == 0  # ...and no entitlement or subscription line item.
    # Terminating the payer leaves the relationship untouched.
    term = w.call(
        w.platform,
        "POST",
        f"/admin/msp/billing/payer-assignments/{aid}/terminate",
        {"customer_tenant_id": CUST_1, "expected_version": 1},
    )
    assert term.status_code == 200, term.text
    assert term.json()["status"] == "terminated"
    assert w.context(w.msp_a_staff, CUST_1).status_code == 200
    out = _produce(CUST_1, _deliver(CUST_1))
    assert out.status == "not_applicable"
    # Revoking the relationship never cancels the payer's commercial agreement.
    assert w.act(w.c1_admin, rid, "revoke").status_code == 200
    with _session() as db:
        statuses = {
            r[0] for r in db.execute(text("SELECT status FROM subscription_contracts"))
        }
    assert statuses == {"active"}


def _revoke(w, rid):
    assert w.act(w.c1_admin, rid, "revoke").status_code == 200


def _suspend(w, rid):
    assert w.act(w.c1_admin, rid, "suspend").status_code == 200


def _expire(w, rid):
    from api.db_models_msp import MspServiceRelationship

    with _session() as db:
        db.query(MspServiceRelationship).filter(
            MspServiceRelationship.id == rid
        ).update(
            {
                "effective_at": _now() - timedelta(days=2),
                "expires_at": _now() - timedelta(seconds=1),
            }
        )
        db.commit()


def _suspend_msp(w, rid):
    assert w.designate(MSP_A, "suspended").status_code == 200


def _disable_customer(w, rid):
    w.sql(
        "UPDATE tenants SET lifecycle_state = 'suspended' WHERE tenant_id = :t",
        t=CUST_1,
    )


def _cancel_agreement(w, rid):
    w.sql("UPDATE subscription_contracts SET status = 'canceled'")


@pytest.mark.parametrize(
    "change,reason",
    [
        (_revoke, "MSP_RELATIONSHIP_INACTIVE"),
        (_suspend, "MSP_RELATIONSHIP_INACTIVE"),
        (_expire, "MSP_RELATIONSHIP_INACTIVE"),
        (_suspend_msp, "MSP_ORGANIZATION_NOT_ACTIVE"),
        (_disable_customer, "CUSTOMER_TENANT_INACTIVE"),
        (_cancel_agreement, "PAYER_AGREEMENT_INVALID"),
    ],
)
def test_23_24_lifecycle_stops_new_charges_and_keeps_history(w, change, reason):
    rid, _ = _billable_world(w)
    assert _produce(CUST_1, _deliver(CUST_1)).status == "recorded"
    change(w, rid)
    out = _produce(CUST_1, _deliver(CUST_1, at=_now() + timedelta(seconds=2)))
    assert (out.status, out.reason) == ("not_billable", reason)
    rows = _usage_rows()
    assert len(rows) == 1  # the earlier, legitimately accrued charge remains
    hist = _usage(w, w.msp_a_admin)
    assert hist.status_code == 200 and len(hist.json()["items"]) == 1


def test_23b_resumed_relationship_resumes_billing(w):
    rid, _ = _billable_world(w)
    _suspend(w, rid)
    assert _produce(CUST_1, _deliver(CUST_1)).status == "not_billable"
    assert w.act(w.c1_admin, rid, "resume").status_code == 200
    assert _produce(
        CUST_1, _deliver(CUST_1, at=_now() + timedelta(seconds=2))
    ).status == ("recorded")


# ---------------------------------------------------------------------------
# 25-27. Payment webhooks (real signature verification, synthetic secret)
# ---------------------------------------------------------------------------

_WHSEC = "whsec_synthetic_msp006"


def _signed(payload: dict, secret: str = _WHSEC) -> tuple[bytes, str]:
    body = json.dumps(payload).encode()
    ts = int(time.time())
    sig = hmac.new(
        secret.encode(), f"{ts}.".encode() + body, hashlib.sha256
    ).hexdigest()
    return body, f"t={ts},v1={sig}"


def _event(event_id: str, event_type: str, sub_id: str) -> dict:
    return {
        "id": event_id,
        "object": "event",
        "type": event_type,
        "created": int(time.time()),
        "data": {"object": {"id": sub_id, "object": "subscription"}},
    }


def _seed_link(tenant: str, sub_id: str) -> str:
    from api.db_models_billing import BillingSubscriptionLink

    agreement = _seed_agreement(tenant)
    lid = str(uuid.uuid4())
    with _session() as db:
        db.add(
            BillingSubscriptionLink(
                id=lid,
                tenant_id=tenant,
                subscription_contract_id=agreement,
                provider="stripe",
                provider_subscription_id=sub_id,
                sync_status="synced",
            )
        )
        db.commit()
    return lid


def _link_status(lid: str) -> str:
    with _session() as db:
        return db.execute(
            text("SELECT sync_status FROM billing_subscription_links WHERE id = :i"),
            {"i": lid},
        ).scalar()


def _post_webhook(w: World, payload: dict, secret: str = _WHSEC):
    body, header = _signed(payload, secret)
    return w.client.post(
        "/billing/webhooks/stripe",
        content=body,
        headers={"Stripe-Signature": header, "Content-Type": "application/json"},
    )


def test_25_webhook_replay_is_idempotent(w, monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", _WHSEC)
    evt = _event("evt_syn_replay", "invoice.payment_succeeded", "sub_syn_1")
    assert _post_webhook(w, evt).status_code == 200
    assert _post_webhook(w, evt).status_code == 200
    with _session() as db:
        n = db.execute(
            text(
                "SELECT COUNT(*) FROM billing_event_ledger WHERE entity_type ="
                " 'stripe_webhook' AND entity_id = 'evt_syn_replay'"
            )
        ).scalar()
    assert n == 1


def test_26_invalid_webhook_signature_is_rejected(w, monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", _WHSEC)
    evt = _event("evt_syn_forged", "customer.subscription.updated", "sub_syn_2")
    resp = _post_webhook(w, evt, secret="whsec_attacker")
    assert resp.status_code == 400
    with _session() as db:
        n = db.execute(
            text(
                "SELECT COUNT(*) FROM billing_event_ledger WHERE entity_id = 'evt_syn_forged'"
            )
        ).scalar()
    assert n == 0


def test_27_out_of_order_webhook_cannot_resurrect_a_canceled_subscription(
    w, monkeypatch
):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", _WHSEC)
    lid = _seed_link(MSP_A, "sub_syn_3")
    deleted = _event("evt_syn_del", "customer.subscription.deleted", "sub_syn_3")
    assert _post_webhook(w, deleted).status_code == 200
    assert _link_status(lid) == "disabled"
    late = _event("evt_syn_late", "customer.subscription.updated", "sub_syn_3")
    assert _post_webhook(w, late).status_code == 200
    assert _link_status(lid) == "disabled"


# ---------------------------------------------------------------------------
# 28-30. Processor status and reconciliation
# ---------------------------------------------------------------------------


def _reconcile(w: World, payer: str, period: str) -> dict:
    resp = w.call(
        w.platform,
        "GET",
        f"/admin/msp/billing/reconciliation?payer_tenant_id={payer}&period={period}",
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


class _TestModeProcessor:
    """Deterministic synthetic processor. Never contacts a real processor."""

    test_mode = True

    def __init__(self, with_reference: bool = True):
        self.with_reference = with_reference
        self.keys: list[str] = []

    def report_usage(self, sub_id, meter_code, quantity, idempotency_key):
        self.keys.append(idempotency_key)
        return (
            {
                "id": "syn_ack_"
                + hashlib.sha256(idempotency_key.encode()).hexdigest()[:12]
            }
            if self.with_reference
            else {}
        )


def test_28_missing_processor_ack_remains_pending(w):
    _billable_world(w)
    _produce(CUST_1, _deliver(CUST_1))
    report = _reconcile(w, MSP_A, _period())
    [charge] = report["charges"]
    assert charge["billing_status"] == "pending"
    assert charge["settlement"] == "pending_processor_ack"
    assert report["settlement"] == "NOT_PROVEN"
    assert report["ok"] is True


def test_29_reconciliation_detects_duplicate_source_references(w):
    _billable_world(w)
    _produce(CUST_1, _deliver(CUST_1))
    [(_, _, md, _)] = _usage_rows()
    from api.db_models_billing import UsageEvent

    with _session() as db:
        db.add(
            UsageEvent(
                id=str(uuid.uuid4()),
                tenant_id=MSP_A,
                meter_code=METER,
                quantity="1",
                idempotency_key="injected-duplicate",
                source="synthetic",
                occurred_at=_now() + timedelta(seconds=1),
                metadata_json=md,
            )
        )
        db.commit()
    report = _reconcile(w, MSP_A, _period())
    assert report["ok"] is False
    [dup] = report["duplicate_source_references"]
    assert len(dup["usage_event_ids"]) == 2


def test_30_reconciliation_detects_missing_processor_reference(w):
    from api.msp_billing import LiveProcessorRefused, report_pending_usage
    from services.billing.stripe_provider import StripeProvider

    _billable_world(w)
    _produce(CUST_1, _deliver(CUST_1))
    with _session() as db, pytest.raises(LiveProcessorRefused):
        report_pending_usage(db, payer_tenant_id=MSP_A, provider=StripeProvider())
    processor = _TestModeProcessor(with_reference=False)
    with _session() as db:
        result = report_pending_usage(db, payer_tenant_id=MSP_A, provider=processor)
        db.commit()
    assert result["reported"] == 1
    [(uid, _, md, status)] = _usage_rows()
    assert status == "reported" and processor.keys == [md["idempotency_key"]]
    report = _reconcile(w, MSP_A, _period())
    assert report["charges"][0]["problems"] == ["MISSING_PROCESSOR_REFERENCE"]
    assert report["ok"] is False


def test_30b_reconciliation_detects_delivery_without_usage_and_payer_change(w):
    rid, aid = _billable_world(w)
    eid = _deliver(CUST_1)  # delivered, but the producer never ran
    report = _reconcile(w, MSP_A, _period())
    assert report["deliveries_without_usage"] == [
        {
            "customer_tenant_id": CUST_1,
            "source_event_id": eid,
            "payer_assignment_id": aid,
        }
    ]
    _produce(CUST_1, eid)
    w.sql("UPDATE msp_payer_assignments SET currency = 'EUR'")
    report = _reconcile(w, MSP_A, _period())
    assert "CURRENCY_MISMATCH" in report["charges"][0]["problems"]
    assert report["deliveries_without_usage"] == []


def test_30c_reconciliation_is_reproducible(w):
    _billable_world(w)
    _produce(CUST_1, _deliver(CUST_1))
    a, b = _reconcile(w, MSP_A, _period()), _reconcile(w, MSP_A, _period())
    assert a == b and a["report_sha256"] == b["report_sha256"]


# ---------------------------------------------------------------------------
# 33, 35, 36. Compatibility, audit and secrecy
# ---------------------------------------------------------------------------


def test_33_existing_usage_metering_still_works(w):
    from api.db_models_billing import UsageMeter
    from tests.security.test_msp_001_foundation import mint_key

    with _session() as db:
        db.add(
            UsageMeter(
                meter_code="api.calls",
                display_name="API calls",
                billing_category="usage",
                active="1",
            )
        )
        db.commit()
    resp = w.client.post(
        "/billing/usage/events",
        json={"meter_code": "api.calls", "quantity": "3", "idempotency_key": "k-1"},
        headers={"x-api-key": mint_key("billing:write", tenant_id=CUST_2)},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["tenant_id"] == CUST_2


def test_35_audit_chains_stay_verifiable(w):
    from api.identity.store import verify_identity_audit_chain

    rid, aid = _billable_world(w)
    _produce(CUST_1, _deliver(CUST_1))
    w.call(
        w.platform,
        "POST",
        f"/admin/msp/billing/payer-assignments/{aid}/terminate",
        {"customer_tenant_id": CUST_1, "expected_version": 1},
    )
    with _session() as db:
        for tenant in (CUST_1, MSP_A):
            assert verify_identity_audit_chain(db, tenant), tenant
    types = {
        r[0]
        for r in w.sql(
            "SELECT event_type FROM tenant_identity_audit_events WHERE tenant_id = :t",
            t=MSP_A,
        ).fetchall()
    }
    assert {
        "tenant.msp.payer_assigned",
        "tenant.msp.billing_usage_recorded",
        "tenant.msp.payer_assignment_terminated",
    } <= types


def test_36_no_secrets_in_billing_responses_or_logs(w, monkeypatch, caplog):
    secret = "sk_test_SYNTHETIC_DO_NOT_LEAK_0000"
    monkeypatch.setenv("STRIPE_API_KEY", secret)
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", _WHSEC)
    caplog.set_level(logging.DEBUG)
    _billable_world(w)
    _produce(CUST_1, _deliver(CUST_1))
    texts = [
        w.call(w.msp_a_admin, "GET", "/admin/msp/billing/payer-assignments").text,
        _usage(w, w.msp_a_admin).text,
        json.dumps(_reconcile(w, MSP_A, _period())),
    ]
    for body in texts + [caplog.text]:
        assert secret not in body and _WHSEC not in body
        assert "synthetic-qa" not in body  # the customer's own people stay private


# ---------------------------------------------------------------------------
# First-revenue acceptance demonstration (synthetic; no live processor)
# ---------------------------------------------------------------------------


def test_first_revenue_demonstration(w):
    # 1. The platform designated MSP Alpha (World setup). 2. Approved relationship.
    rid = w.establish(w.msp_a_admin, w.c1_admin, req=READ_CAPS, auth=READ_CAPS)
    # 3. A separately authorized commercial agreement makes MSP Alpha the payer.
    agreement = _seed_agreement(MSP_A)
    pvid = _seed_price(MSP_A)
    _seed_meter()
    assigned = _assign(w, rid, agreement=agreement)
    assert assigned.status_code == 200, assigned.text
    aid = assigned.json()["payer_assignment_id"]
    # 4-5. Customer One completes one billable assessment -> one usage record.
    eid = _deliver(CUST_1)
    first = _produce(CUST_1, eid)
    assert first.status == "recorded"
    # 6. A retry of the same completion produces no additional usage.
    assert _produce(CUST_1, eid).status == "duplicate"
    # 7. The record binds customer, MSP, payer assignment, product, price, quantity.
    [(uid, payer, md, status)] = _usage_rows()
    assert (payer, md["customer_tenant_id"], md["msp_tenant_id"]) == (
        MSP_A,
        CUST_1,
        MSP_A,
    )
    assert (md["payer_assignment_id"], md["product_code"]) == (aid, PRODUCT)
    assert (md["pricing_version_id"], md["quantity"]) == (pvid, 1)
    # 8-9. A deterministic preview shows exactly one charge, recorded once.
    preview = _usage(w, w.msp_a_admin).json()
    assert preview["estimated_total_minor_by_currency"] == {"USD": RATE}
    assert [i["usage_event_id"] for i in preview["items"]] == [uid]
    # 10. A second customer remains isolated.
    assert _usage(w, w.c2_admin).json()["items"] == []
    assert _produce(CUST_2, _deliver(CUST_2)).status == "not_applicable"
    # 11. MSP Alpha's relationship is revoked.
    assert w.act(w.c1_admin, rid, "revoke").status_code == 200
    # 12. Historical billable usage remains intact.
    assert [r[0] for r in _usage_rows()] == [uid]
    # 13. New operations cannot generate additional MSP-managed charges.
    later = _produce(CUST_1, _deliver(CUST_1, at=_now() + timedelta(seconds=2)))
    assert (later.status, later.reason) == ("not_billable", "MSP_RELATIONSHIP_INACTIVE")
    assert len(_usage_rows()) == 1
    # 14. Independent reconciliation reconstructs the original charge.
    report = _reconcile(w, MSP_A, _period())
    assert report["ok"] is True
    assert report["totals_minor_by_currency"] == {"USD": RATE}
    [charge] = report["charges"]
    assert (charge["usage_event_id"], charge["amount_minor"], charge["problems"]) == (
        uid,
        RATE,
        [],
    )
    assert report["settlement"] == "NOT_PROVEN"  # no revenue is claimed
    assert MSP_B not in json.dumps(report)


# ---------------------------------------------------------------------------
# Review fixes (PR #876): reserved key namespace; coverage ends at termination
# ---------------------------------------------------------------------------


def test_14b_public_route_cannot_squat_the_msp_idempotency_namespace(w):
    """Codex P1: an ordinary meter with an msp006: key would collide with the
    producer's (tenant_id, idempotency_key) and suppress the real charge."""
    from api.db_models_billing import UsageMeter
    from tests.security.test_msp_001_foundation import mint_key

    _billable_world(w, "customer_paid")
    with _session() as db:
        db.add(
            UsageMeter(
                meter_code="api.calls",
                display_name="API calls",
                billing_category="usage",
                active="1",
            )
        )
        db.commit()
    eid = _deliver(CUST_1)
    squat = w.client.post(
        "/billing/usage/events",
        json={
            "meter_code": "api.calls",
            "quantity": "1",
            "idempotency_key": f"msp006:{PRODUCT}:{CUST_1}:{eid}",
        },
        headers={"x-api-key": mint_key("billing:write", tenant_id=CUST_1)},
    )
    assert squat.status_code == 403, squat.text
    assert squat.json()["detail"] == {"code": "BILLING_METER_RESTRICTED"}
    out = _produce(CUST_1, eid)
    assert out.status == "recorded"
    [(_, payer, md, _)] = _usage_rows()
    assert payer == CUST_1 and md["source_event_id"] == eid


def _terminate(w: World, aid: str, version: int = 1):
    resp = w.call(
        w.platform,
        "POST",
        f"/admin/msp/billing/payer-assignments/{aid}/terminate",
        {"customer_tenant_id": CUST_1, "expected_version": version},
    )
    assert resp.status_code == 200, resp.text


def test_30d_reconciliation_coverage_ends_at_termination(w):
    """Codex P2: a delivery after termination is not missing usage for the
    former payer; one before termination still is."""
    rid, aid = _billable_world(w)
    before = _deliver(CUST_1, at=_now())  # covered, but the producer never ran
    _terminate(w, aid)
    after = _deliver(CUST_1, at=_now() + timedelta(seconds=3))
    assert _produce(CUST_1, after).status == "not_applicable"
    report = _reconcile(w, MSP_A, _period())
    assert report["deliveries_without_usage"] == [
        {
            "customer_tenant_id": CUST_1,
            "source_event_id": before,
            "payer_assignment_id": aid,
        }
    ]


def test_30e_replacement_payer_deliveries_are_not_charged_to_the_old_payer(w):
    rid, old = _billable_world(w, "msp_paid")
    _terminate(w, old)
    _seed_price(CUST_1)
    new = _assign(w, rid, mode="customer_paid", agreement=_seed_agreement(CUST_1))
    assert new.status_code == 200, new.text
    eid = _deliver(CUST_1, at=_now() + timedelta(seconds=3))
    assert _produce(CUST_1, eid).status == "recorded"
    assert _reconcile(w, MSP_A, _period())["deliveries_without_usage"] == []
    report = _reconcile(w, CUST_1, _period())
    assert report["ok"] is True and len(report["charges"]) == 1
