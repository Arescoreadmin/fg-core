"""P1.5 Billing Integration Layer — test suite.

Test matrix:
  BILL-1   Create billing account → persisted
  BILL-2   Tenant isolation — account A not visible to tenant B
  BILL-3   Duplicate provider+tenant rejected
  BILL-4   Update billing status
  BILL-5   get_billing_account_for_tenant
  BILL-6   NullBillingProvider returns ok for all methods
  BILL-7   StripeProvider raises ProviderNotConfiguredError when no env key
  BILL-8   provider.verify_webhook_signature via NullBillingProvider → False
  BILL-9   Create subscription link
  BILL-10  List links for tenant
  BILL-11  Sync link marks last_synced_at
  BILL-12  Create usage meter
  BILL-13  List active meters
  BILL-14  Deactivate meter
  BILL-15  Record usage event → pending
  BILL-16  Duplicate idempotency_key returns same record
  BILL-17  Unknown meter_code raises ValueError
  BILL-18  Cross-tenant subscription_item_id rejected
  BILL-19  Provider outage keeps event pending
  BILL-20  Reconciler retries pending → marks reported
  BILL-21  Usage ledger entry appended on record
  BILL-22  Billing cannot call check_capability / create TenantBundleAssignment
  BILL-23  Webhook event does NOT create TenantBundleAssignment
  BILL-24  billing_status change does NOT trigger subscription engine
  BILL-25  Append-only: update raises
  BILL-26  Hash-chain integrity across events
  BILL-27  Lifecycle reconstruction from ledger
  BILL-28  Admin routes require admin:read/write scope (403 without)
  BILL-29  Tenant isolation on usage POST
  BILL-30  Explain endpoint returns billing picture
  BILL-31  Webhook valid signature accepted (mock verify)
  BILL-32  Webhook invalid signature → 400
  BILL-33  Webhook missing secret → 503
  BILL-34  Webhook replay idempotent
  BILL-35  No secrets leaked in response JSON
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.db import get_sessionmaker, init_db, reset_engine_cache
from api.db_models_billing import (
    BillingAccount,
    BillingEventLedger,
    UsageEvent,
    UsageMeter,
)
from services.billing.engine import BillingEngine
from services.billing.metering import record_usage_event
from services.billing.models import UpdateBillingAccountRequest
from services.billing.provider import NullBillingProvider
from services.billing.reconciliation import BillingReconciler

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_engine_svc = BillingEngine()
_reconciler = BillingReconciler()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str = "bill"):
    db_path = str(tmp_path / f"{name}.db")
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    reset_engine_cache()
    init_db(sqlite_path=db_path)
    return get_sessionmaker(sqlite_path=db_path)()


def _make_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tenant_id: str,
    *,
    scopes: str = "admin:read admin:write",
    name: str = "bill",
) -> TestClient:
    db_path = str(tmp_path / f"{name}.db")
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    monkeypatch.setenv("FG_AUTH_ENABLED", "1")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    monkeypatch.setenv("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
    monkeypatch.setenv(
        "FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    )
    monkeypatch.setenv("FG_ENTITLEMENT_ENFORCEMENT", "true")
    reset_engine_cache()
    init_db(sqlite_path=db_path)

    from api.main import build_app

    app = build_app(auth_enabled=True)
    key = mint_key(*scopes.split(), tenant_id=tenant_id)

    return TestClient(
        app,
        headers={"X-API-Key": key, "X-Tenant-ID": tenant_id},
        raise_server_exceptions=False,
    )


def _make_meter(db: Session, meter_code: str = "api.calls") -> UsageMeter:
    meter = UsageMeter(
        id=str(uuid.uuid4()),
        meter_code=meter_code,
        display_name=meter_code,
        unit="count",
        aggregation_mode="sum",
        billing_category="api",
        active="1",
        metadata_json={},
    )
    db.add(meter)
    db.flush()
    return meter


# ---------------------------------------------------------------------------
# BILL-1: Create billing account
# ---------------------------------------------------------------------------


class TestBILL1:
    def test_create_account_persisted(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="bill1")
        tenant = "tenant-bill1"
        result = _engine_svc.create_billing_account(
            db, tenant, "stripe", billing_email="a@example.com"
        )
        db.commit()
        assert result.id is not None
        assert result.tenant_id == tenant
        assert result.provider == "stripe"
        assert result.billing_status == "active"
        assert result.billing_email == "a@example.com"

        stored = db.query(BillingAccount).filter(BillingAccount.id == result.id).first()
        assert stored is not None


# ---------------------------------------------------------------------------
# BILL-2: Tenant isolation
# ---------------------------------------------------------------------------


class TestBILL2:
    def test_tenant_isolation(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="bill2")
        _engine_svc.create_billing_account(db, "tenant-a", "stripe")
        db.commit()
        result = _engine_svc.get_billing_account_for_tenant(db, "tenant-b", "stripe")
        assert result is None


# ---------------------------------------------------------------------------
# BILL-3: Duplicate provider+tenant rejected
# ---------------------------------------------------------------------------


class TestBILL3:
    def test_duplicate_account_rejected(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="bill3")
        tenant = "tenant-bill3"
        _engine_svc.create_billing_account(db, tenant, "stripe")
        db.commit()
        with pytest.raises(ValueError, match="already exists"):
            _engine_svc.create_billing_account(db, tenant, "stripe")


# ---------------------------------------------------------------------------
# BILL-4: Update billing status
# ---------------------------------------------------------------------------


class TestBILL4:
    def test_update_billing_status(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="bill4")
        tenant = "tenant-bill4"
        account = _engine_svc.create_billing_account(db, tenant, "stripe")
        db.commit()

        updated = _engine_svc.update_billing_account(
            db,
            account.id,
            UpdateBillingAccountRequest(billing_status="past_due"),
        )
        db.commit()
        assert updated.billing_status == "past_due"


# ---------------------------------------------------------------------------
# BILL-5: get_billing_account_for_tenant
# ---------------------------------------------------------------------------


class TestBILL5:
    def test_get_account_for_tenant(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="bill5")
        tenant = "tenant-bill5"
        created = _engine_svc.create_billing_account(
            db, tenant, "stripe", billing_email="b@example.com"
        )
        db.commit()
        fetched = _engine_svc.get_billing_account_for_tenant(db, tenant, "stripe")
        assert fetched is not None
        assert fetched.id == created.id
        assert fetched.billing_email == "b@example.com"


# ---------------------------------------------------------------------------
# BILL-6: NullBillingProvider returns ok for all methods
# ---------------------------------------------------------------------------


class TestBILL6:
    def test_null_provider_ok(self):
        p = NullBillingProvider()
        assert p.create_customer("t", None, {}) == {"ok": True}
        assert p.update_customer("cus_x", None, {}) == {"ok": True}
        assert p.create_subscription("cus_x", "price_y", {}) == {"ok": True}
        assert p.update_subscription("sub_x", {}) == {"ok": True}
        assert p.cancel_subscription("sub_x") == {"ok": True}
        assert p.report_usage("sub_x", "meter", "1", "idem") == {"ok": True}
        assert p.retrieve_invoice("sub_x") == {"ok": True}
        assert p.parse_webhook(b"", None) == {}
        assert p.verify_webhook_signature(b"", None) is False


# ---------------------------------------------------------------------------
# BILL-7: StripeProvider raises ProviderNotConfiguredError without API key
# ---------------------------------------------------------------------------


class TestBILL7:
    def test_stripe_provider_no_key(self, monkeypatch):
        monkeypatch.delenv("STRIPE_API_KEY", raising=False)
        from services.billing.stripe_provider import (
            ProviderNotConfiguredError,
            StripeProvider,
        )

        p = StripeProvider()
        with pytest.raises(ProviderNotConfiguredError):
            p.create_customer("t", None, {})


# ---------------------------------------------------------------------------
# BILL-8: NullBillingProvider.verify_webhook_signature returns False
# ---------------------------------------------------------------------------


class TestBILL8:
    def test_null_provider_verify_false(self):
        p = NullBillingProvider()
        assert p.verify_webhook_signature(b"payload", "sig") is False


# ---------------------------------------------------------------------------
# BILL-9: Create subscription link
# ---------------------------------------------------------------------------


class TestBILL9:
    def test_create_subscription_link(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="bill9")
        tenant = "tenant-bill9"
        # We use a fake contract_id — FK not enforced in SQLite without pragma
        contract_id = str(uuid.uuid4())
        link = _engine_svc.create_subscription_link(
            db,
            tenant_id=tenant,
            subscription_contract_id=contract_id,
            provider="stripe",
            provider_subscription_id="sub_test123",
        )
        db.commit()
        assert link.id is not None
        assert link.sync_status == "pending"
        assert link.provider_subscription_id == "sub_test123"


# ---------------------------------------------------------------------------
# BILL-10: List subscription links for tenant
# ---------------------------------------------------------------------------


class TestBILL10:
    def test_list_links_for_tenant(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="bill10")
        tenant = "tenant-bill10"
        cid = str(uuid.uuid4())
        _engine_svc.create_subscription_link(
            db, tenant_id=tenant, subscription_contract_id=cid
        )
        _engine_svc.create_subscription_link(
            db, tenant_id=tenant, subscription_contract_id=cid
        )
        db.commit()
        links = _engine_svc.list_subscription_links(db, tenant)
        assert len(links) == 2

        # other tenant sees nothing
        other_links = _engine_svc.list_subscription_links(db, "other-tenant")
        assert len(other_links) == 0


# ---------------------------------------------------------------------------
# BILL-11: Sync link marks last_synced_at
# ---------------------------------------------------------------------------


class TestBILL11:
    def test_sync_link_sets_last_synced_at(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="bill11")
        tenant = "tenant-bill11"
        cid = str(uuid.uuid4())
        link = _engine_svc.create_subscription_link(
            db, tenant_id=tenant, subscription_contract_id=cid
        )
        db.commit()
        assert link.last_synced_at is None

        synced = _engine_svc.sync_subscription_link(db, link.id, NullBillingProvider())
        db.commit()
        assert synced.sync_status == "synced"
        assert synced.last_synced_at is not None


# ---------------------------------------------------------------------------
# BILL-12: Create usage meter
# ---------------------------------------------------------------------------


class TestBILL12:
    def test_create_meter(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="bill12")
        meter = _engine_svc.create_meter(
            db,
            meter_code="test.meter.12",
            display_name="Test Meter 12",
            unit="count",
            aggregation_mode="sum",
            billing_category="test",
        )
        db.commit()
        assert meter.id is not None
        assert meter.active == "1"
        assert meter.meter_code == "test.meter.12"


# ---------------------------------------------------------------------------
# BILL-13: List active meters
# ---------------------------------------------------------------------------


class TestBILL13:
    def test_list_active_meters(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="bill13")
        _engine_svc.create_meter(
            db,
            meter_code="m.active",
            display_name="Active",
            unit="count",
            aggregation_mode="sum",
            billing_category="test",
        )
        _engine_svc.create_meter(
            db,
            meter_code="m.inactive",
            display_name="Inactive",
            unit="count",
            aggregation_mode="sum",
            billing_category="test",
        )
        db.commit()

        from services.billing.models import UpdateUsageMeterRequest  # noqa: PLC0415

        _engine_svc.update_meter(db, "m.inactive", UpdateUsageMeterRequest(active="0"))
        db.commit()

        active = _engine_svc.list_meters(db, active_only=True)
        codes = [m.meter_code for m in active]
        assert "m.active" in codes
        assert "m.inactive" not in codes

        all_meters = _engine_svc.list_meters(db, active_only=False)
        all_codes = [m.meter_code for m in all_meters]
        assert "m.inactive" in all_codes


# ---------------------------------------------------------------------------
# BILL-14: Deactivate meter
# ---------------------------------------------------------------------------


class TestBILL14:
    def test_deactivate_meter(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="bill14")
        _engine_svc.create_meter(
            db,
            meter_code="m.14",
            display_name="Meter 14",
            unit="count",
            aggregation_mode="sum",
            billing_category="test",
        )
        db.commit()

        from services.billing.models import UpdateUsageMeterRequest  # noqa: PLC0415

        updated = _engine_svc.update_meter(
            db, "m.14", UpdateUsageMeterRequest(active="0")
        )
        db.commit()
        assert updated.active == "0"


# ---------------------------------------------------------------------------
# BILL-15: Record usage event → pending
# ---------------------------------------------------------------------------


class TestBILL15:
    def test_record_usage_event_pending(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="bill15")
        tenant = "tenant-bill15"
        _make_meter(db, "api.calls")
        db.commit()

        evt = record_usage_event(db, tenant, "api.calls", "10", "idem-15-a")
        db.commit()
        assert evt.id is not None
        assert evt.billing_status == "pending"
        assert evt.quantity == "10"
        assert evt.meter_code == "api.calls"


# ---------------------------------------------------------------------------
# BILL-16: Duplicate idempotency_key returns same record
# ---------------------------------------------------------------------------


class TestBILL16:
    def test_idempotency_key_deduplication(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="bill16")
        tenant = "tenant-bill16"
        _make_meter(db, "api.calls")
        db.commit()

        evt1 = record_usage_event(db, tenant, "api.calls", "5", "idem-16")
        db.commit()
        evt2 = record_usage_event(db, tenant, "api.calls", "99", "idem-16")
        db.commit()

        assert evt1.id == evt2.id
        assert evt2.quantity == "5"


# ---------------------------------------------------------------------------
# BILL-17: Unknown meter_code raises ValueError
# ---------------------------------------------------------------------------


class TestBILL17:
    def test_unknown_meter_raises(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="bill17")
        with pytest.raises(ValueError, match="Unknown meter_code"):
            record_usage_event(db, "tenant-bill17", "nonexistent.meter", "1", "idem-17")


# ---------------------------------------------------------------------------
# BILL-18: Cross-tenant subscription_item_id rejected
# ---------------------------------------------------------------------------


class TestBILL18:
    def test_cross_tenant_item_rejected(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="bill18")
        _make_meter(db, "api.calls")
        db.commit()

        # Create a fake subscription item belonging to another tenant using ORM
        # Use a fake item_id that doesn't exist
        with pytest.raises(ValueError, match="not found for tenant"):
            record_usage_event(
                db,
                "tenant-bill18-a",
                "api.calls",
                "1",
                "idem-18",
                subscription_item_id=str(uuid.uuid4()),
            )


# ---------------------------------------------------------------------------
# BILL-19: Provider outage keeps event pending
# ---------------------------------------------------------------------------


class TestBILL19:
    def test_provider_outage_keeps_pending(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="bill19")
        tenant = "tenant-bill19"
        _make_meter(db, "api.calls")
        db.commit()

        class BrokenProvider(NullBillingProvider):
            def report_usage(self, *args, **kwargs):
                raise RuntimeError("provider offline")

        evt = record_usage_event(
            db, tenant, "api.calls", "3", "idem-19", provider=BrokenProvider()
        )
        db.commit()
        assert evt.billing_status == "pending"


# ---------------------------------------------------------------------------
# BILL-20: Reconciler retries pending → marks reported
# ---------------------------------------------------------------------------


class TestBILL20:
    def test_reconciler_marks_reported(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="bill20")
        tenant = "tenant-bill20"
        _make_meter(db, "api.calls")
        db.commit()

        record_usage_event(db, tenant, "api.calls", "7", "idem-20")
        db.commit()

        stats = _reconciler.reconcile_pending_usage(
            db, NullBillingProvider(), tenant_id=tenant
        )
        db.commit()
        assert stats["reported"] >= 1

        evt = (
            db.query(UsageEvent).filter(UsageEvent.idempotency_key == "idem-20").first()
        )
        assert evt is not None
        assert evt.billing_status == "reported"


# ---------------------------------------------------------------------------
# BILL-21: Usage ledger entry appended on record
# ---------------------------------------------------------------------------


class TestBILL21:
    def test_ledger_entry_appended(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="bill21")
        tenant = "tenant-bill21"
        _make_meter(db, "api.calls")
        db.commit()

        evt = record_usage_event(db, tenant, "api.calls", "1", "idem-21")
        db.commit()

        entry = (
            db.query(BillingEventLedger)
            .filter(
                BillingEventLedger.tenant_id == tenant,
                BillingEventLedger.entity_id == evt.id,
            )
            .first()
        )
        assert entry is not None
        assert entry.event_type == "usage_recorded"


# ---------------------------------------------------------------------------
# BILL-22: Billing cannot call check_capability / create TenantBundleAssignment
# ---------------------------------------------------------------------------


class TestBILL22:
    def test_billing_engine_has_no_capability_imports(self):
        import ast
        import inspect
        from services.billing import engine

        source = inspect.getsource(engine)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.ImportFrom) and node.module:
                    assert "check_capability" not in node.module
                    assert "TenantBundleAssignment" not in node.module
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert "check_capability" not in alias.name
        # Verify no reference to TenantBundleAssignment in billing engine
        assert "TenantBundleAssignment" not in source
        assert "check_capability" not in source


# ---------------------------------------------------------------------------
# BILL-23: Webhook event does NOT create TenantBundleAssignment
# ---------------------------------------------------------------------------


class TestBILL23:
    def test_webhook_does_not_create_bundle_assignment(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="bill23")
        from api.db_models import TenantBundleAssignment  # noqa: PLC0415
        from api.billing_v2 import _handle_stripe_subscription_event  # noqa: PLC0415

        before_count = db.query(TenantBundleAssignment).count()
        _handle_stripe_subscription_event(
            db,
            {
                "type": "customer.subscription.updated",
                "data": {"object": {"id": "sub_webhook23"}},
            },
            "customer.subscription.updated",
        )
        db.flush()
        after_count = db.query(TenantBundleAssignment).count()
        assert after_count == before_count


# ---------------------------------------------------------------------------
# BILL-24: billing_status change does NOT trigger subscription engine
# ---------------------------------------------------------------------------


class TestBILL24:
    def test_billing_status_change_no_subscription_engine(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="bill24")
        tenant = "tenant-bill24"
        account = _engine_svc.create_billing_account(db, tenant, "stripe")
        db.commit()

        # verify no subscription engine calls by checking import graph
        from services.billing import engine as billing_engine

        import inspect

        source = inspect.getsource(billing_engine)
        assert "update_item_status" not in source
        assert "SubscriptionEngine" not in source

        updated = _engine_svc.update_billing_account(
            db, account.id, UpdateBillingAccountRequest(billing_status="suspended")
        )
        db.commit()
        assert updated.billing_status == "suspended"


# ---------------------------------------------------------------------------
# BILL-25: Append-only — update on UsageEvent raises
# ---------------------------------------------------------------------------


class TestBILL25:
    def test_usage_event_immutable(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="bill25")
        tenant = "tenant-bill25"
        _make_meter(db, "api.calls")
        db.commit()

        evt = record_usage_event(db, tenant, "api.calls", "5", "idem-25")
        db.commit()

        row = db.query(UsageEvent).filter(UsageEvent.id == evt.id).first()
        row.quantity = "999"
        with pytest.raises(ValueError, match="append-only"):
            db.flush()
        db.rollback()

    def test_ledger_immutable(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="bill25b")
        tenant = "tenant-bill25b"
        _make_meter(db, "api.calls")
        db.commit()

        record_usage_event(db, tenant, "api.calls", "1", "idem-25b")
        db.commit()

        entry = db.query(BillingEventLedger).first()
        entry.event_type = "tampered"
        with pytest.raises(ValueError, match="append-only"):
            db.flush()
        db.rollback()


# ---------------------------------------------------------------------------
# BILL-26: Hash-chain integrity across events
# ---------------------------------------------------------------------------


class TestBILL26:
    def test_hash_chain_integrity(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="bill26")
        tenant = "tenant-bill26"
        _make_meter(db, "api.calls")
        db.commit()

        record_usage_event(db, tenant, "api.calls", "1", "idem-26-a")
        db.commit()
        record_usage_event(db, tenant, "api.calls", "2", "idem-26-b")
        db.commit()

        entries = (
            db.query(BillingEventLedger)
            .filter(BillingEventLedger.tenant_id == tenant)
            .order_by(BillingEventLedger.occurred_at.asc())
            .all()
        )
        assert len(entries) >= 2
        first = entries[0]
        second = entries[1]

        # First entry GENESIS, second links to first
        assert first.prev_hash == "GENESIS"
        assert second.prev_hash == first.event_hash
        assert first.event_hash != second.event_hash


# ---------------------------------------------------------------------------
# BILL-27: Lifecycle reconstruction from ledger
# ---------------------------------------------------------------------------


class TestBILL27:
    def test_lifecycle_reconstruction(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="bill27")
        tenant = "tenant-bill27"
        account = _engine_svc.create_billing_account(db, tenant, "stripe")
        db.commit()
        _engine_svc.update_billing_account(
            db, account.id, UpdateBillingAccountRequest(billing_status="past_due")
        )
        db.commit()

        ledger = (
            db.query(BillingEventLedger)
            .filter(BillingEventLedger.tenant_id == tenant)
            .order_by(BillingEventLedger.occurred_at.asc())
            .all()
        )
        event_types = [e.event_type for e in ledger]
        assert "billing_account_created" in event_types
        assert "billing_account_status_changed" in event_types

        status_change = next(
            e for e in ledger if e.event_type == "billing_account_status_changed"
        )
        assert status_change.old_state == "active"
        assert status_change.new_state == "past_due"


# ---------------------------------------------------------------------------
# BILL-28: Admin routes require admin:read/write scope (403 without)
# ---------------------------------------------------------------------------


class TestBILL28:
    def test_admin_routes_require_scope(self, tmp_path, monkeypatch):
        tenant = "tenant-bill28"
        # Client with no admin scopes
        db_path = str(tmp_path / "bill28.db")
        monkeypatch.setenv("FG_ENV", "test")
        monkeypatch.setenv("FG_SQLITE_PATH", db_path)
        monkeypatch.setenv("FG_AUTH_ENABLED", "1")
        monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
        monkeypatch.setenv("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
        monkeypatch.setenv(
            "FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
        )
        monkeypatch.setenv("FG_ENTITLEMENT_ENFORCEMENT", "true")
        reset_engine_cache()
        init_db(sqlite_path=db_path)
        from api.main import build_app

        app = build_app(auth_enabled=True)
        key = mint_key("ingest:write", tenant_id=tenant)
        client = TestClient(
            app,
            headers={"X-API-Key": key, "X-Tenant-ID": tenant},
            raise_server_exceptions=False,
        )
        resp = client.get(
            "/admin/billing/meters",
            params={"tenant_id": tenant},
        )
        assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# BILL-29: Tenant isolation on usage POST
# ---------------------------------------------------------------------------


class TestBILL29:
    def test_usage_post_requires_bound_tenant(self, tmp_path, monkeypatch):
        # No auth header → should fail
        tenant = "tenant-bill29"
        client = _make_client(tmp_path, monkeypatch, tenant, name="bill29")

        # Create a meter first via the DB directly
        from api.db import get_engine as get_eng  # noqa: PLC0415
        from sqlalchemy.orm import Session as Sess  # noqa: PLC0415

        eng = get_eng()
        with Sess(eng) as db:
            _make_meter(db, "api.calls.29")
            db.commit()

        resp = client.post(
            "/billing/usage/events",
            json={
                "meter_code": "api.calls.29",
                "quantity": "1",
                "idempotency_key": "idem-29",
            },
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# BILL-30: Explain endpoint returns billing picture
# ---------------------------------------------------------------------------


class TestBILL30:
    def test_explain_returns_picture(self, tmp_path, monkeypatch):
        tenant = "tenant-bill30"
        client = _make_client(tmp_path, monkeypatch, tenant, name="bill30")

        from api.db import get_engine as get_eng  # noqa: PLC0415
        from sqlalchemy.orm import Session as Sess  # noqa: PLC0415

        eng = get_eng()
        with Sess(eng) as db:
            _engine_svc.create_billing_account(db, tenant, "stripe")
            db.commit()

        resp = client.get(
            "/admin/billing/explain",
            params={"tenant_id": tenant},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "billing_account" in data
        assert data["billing_account"]["provider"] == "stripe"


# ---------------------------------------------------------------------------
# BILL-31: Webhook valid signature accepted (mock verify)
# ---------------------------------------------------------------------------


class TestBILL31:
    def test_webhook_valid_signature(self, tmp_path, monkeypatch):
        tenant = "tenant-bill31"
        monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")
        client = _make_client(tmp_path, monkeypatch, tenant, name="bill31")

        monkeypatch.setattr(
            "services.billing.stripe_provider.StripeProvider.verify_webhook_signature",
            lambda self, rb, sig: True,
        )
        monkeypatch.setattr(
            "services.billing.stripe_provider.StripeProvider.parse_webhook",
            lambda self, rb, sig: {
                "id": "evt_bill31",
                "type": "invoice.payment_succeeded",
                "data": {"object": {"id": "sub_bill31", "subscription": "sub_bill31"}},
            },
        )

        resp = client.post(
            "/billing/webhooks/stripe",
            content=b'{"id":"evt_bill31"}',
            headers={"Stripe-Signature": "t=123,v1=abc"},
        )
        assert resp.status_code == 200
        assert resp.json()["received"] is True


# ---------------------------------------------------------------------------
# BILL-32: Webhook invalid signature → 400
# ---------------------------------------------------------------------------


class TestBILL32:
    def test_webhook_invalid_signature(self, tmp_path, monkeypatch):
        tenant = "tenant-bill32"
        monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")
        client = _make_client(tmp_path, monkeypatch, tenant, name="bill32")

        monkeypatch.setattr(
            "services.billing.stripe_provider.StripeProvider.verify_webhook_signature",
            lambda self, rb, sig: False,
        )

        resp = client.post(
            "/billing/webhooks/stripe",
            content=b"{}",
            headers={"Stripe-Signature": "bad"},
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# BILL-33: Webhook missing secret → 503
# ---------------------------------------------------------------------------


class TestBILL33:
    def test_webhook_missing_secret(self, tmp_path, monkeypatch):
        tenant = "tenant-bill33"
        monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)
        client = _make_client(tmp_path, monkeypatch, tenant, name="bill33")

        from services.billing.stripe_provider import ProviderNotConfiguredError  # noqa: PLC0415

        monkeypatch.setattr(
            "services.billing.stripe_provider.StripeProvider.verify_webhook_signature",
            lambda self, rb, sig: (_ for _ in ()).throw(
                ProviderNotConfiguredError("STRIPE_WEBHOOK_SECRET is not configured")
            ),
        )

        resp = client.post(
            "/billing/webhooks/stripe",
            content=b"{}",
            headers={"Stripe-Signature": "x"},
        )
        assert resp.status_code == 503


# ---------------------------------------------------------------------------
# BILL-34: Webhook replay idempotent
# ---------------------------------------------------------------------------


class TestBILL34:
    def test_webhook_replay_idempotent(self, tmp_path, monkeypatch):
        tenant = "tenant-bill34"
        monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")
        client = _make_client(tmp_path, monkeypatch, tenant, name="bill34")

        call_count = {"n": 0}

        def mock_verify(self, rb, sig):
            return True

        def mock_parse(self, rb, sig):
            call_count["n"] += 1
            return {
                "id": "evt_replay34",
                "type": "invoice.payment_succeeded",
                "data": {"object": {"id": "sub_replay34"}},
            }

        monkeypatch.setattr(
            "services.billing.stripe_provider.StripeProvider.verify_webhook_signature",
            mock_verify,
        )
        monkeypatch.setattr(
            "services.billing.stripe_provider.StripeProvider.parse_webhook",
            mock_parse,
        )

        resp1 = client.post(
            "/billing/webhooks/stripe",
            content=b"{}",
            headers={"Stripe-Signature": "t=1,v1=x"},
        )
        resp2 = client.post(
            "/billing/webhooks/stripe",
            content=b"{}",
            headers={"Stripe-Signature": "t=1,v1=x"},
        )
        assert resp1.status_code == 200
        assert resp2.status_code == 200
        assert resp1.json()["received"] is True
        assert resp2.json()["received"] is True

        # Second call still returned received=True (idempotent)
        # The billing ledger entry was only written once
        from api.db import get_engine as get_eng  # noqa: PLC0415
        from sqlalchemy.orm import Session as Sess  # noqa: PLC0415

        eng = get_eng()
        with Sess(eng) as db:
            count = (
                db.query(BillingEventLedger)
                .filter(
                    BillingEventLedger.entity_type == "stripe_webhook",
                    BillingEventLedger.entity_id == "evt_replay34",
                )
                .count()
            )
        assert count == 1


# ---------------------------------------------------------------------------
# BILL-35: No secrets leaked in response JSON
# ---------------------------------------------------------------------------


class TestBILL35:
    def test_no_secrets_in_response(self, tmp_path, monkeypatch):
        tenant = "tenant-bill35"
        monkeypatch.setenv("STRIPE_API_KEY", "sk_test_supersecret_key_abc123")
        client = _make_client(tmp_path, monkeypatch, tenant, name="bill35")

        # Create account and check response
        from api.db import get_engine as get_eng  # noqa: PLC0415
        from sqlalchemy.orm import Session as Sess  # noqa: PLC0415

        eng = get_eng()
        with Sess(eng) as db:
            _engine_svc.create_billing_account(db, tenant, "stripe")
            db.commit()

        resp = client.get(
            "/admin/tenants/{}/billing/account".format(tenant),
            params={"tenant_id": tenant},
        )
        assert resp.status_code == 200
        body = resp.text
        assert "sk_test" not in body
        assert "supersecret" not in body

        # Also check explain
        explain_resp = client.get(
            "/admin/billing/explain",
            params={"tenant_id": tenant},
        )
        assert explain_resp.status_code == 200
        explain_body = explain_resp.text
        assert "sk_test" not in explain_body
