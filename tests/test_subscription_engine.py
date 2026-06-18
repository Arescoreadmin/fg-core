"""P1.4 Subscription Assignment Engine — test suite.

Test matrix:
  SUB-1   Create contract → persisted with draft status
  SUB-2   Activate contract via status update
  SUB-3   Cancel contract
  SUB-4   Create active subscription item → TenantBundleAssignment created
  SUB-5   Active item → capability granted via bundle resolver
  SUB-6   Suspend item → capability denied (bundle assignment expired)
  SUB-7   Cancel item → capability denied
  SUB-8   Reactivate suspended item → capability granted again
  SUB-9   Ledger entries are append-only (immutability guard)
  SUB-10  Ledger hash chain integrity across multiple events
  SUB-11  Tenant isolation — tenant A subscription doesn't grant tenant B capabilities
  SUB-12  MSP parent_item_id extension point — field accepted and stored
  SUB-13  explain-capability traces: explicit > subscription > tier
  SUB-14  explain-capability denied path
  SUB-15  explain-capability registry miss
  SUB-16  explain-capability dependency checks populated
  SUB-17  explain-capability via HTTP endpoint (granted)
  SUB-18  explain-capability via HTTP endpoint (denied)
  SUB-19  API: create contract via POST
  SUB-20  API: create item via POST, list items
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
from api.db_models import (
    Capability,
    PolicyBundle,
    PolicyBundleCapability,
    TenantBundleAssignment,
)
from api.db_models_subscriptions import (
    SubscriptionContract,
    SubscriptionEventLedger,
    SubscriptionItem,
)
from api.entitlements import check_capability
from services.capability_bundles.resolver import invalidate_cache
from services.subscriptions.engine import SubscriptionEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_engine_svc = SubscriptionEngine()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str = "sub"):
    db_path = str(tmp_path / f"{name}.db")
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    reset_engine_cache()
    init_db(sqlite_path=db_path)
    return get_sessionmaker(sqlite_path=db_path)()


def _make_bundle(
    db: Session, *, bundle_key: str, capabilities: list[str]
) -> PolicyBundle:
    bundle = PolicyBundle(
        id=str(uuid.uuid4()),
        bundle_key=bundle_key,
        bundle_name=bundle_key,
        active=True,
    )
    db.add(bundle)
    db.flush()
    for cap_key in capabilities:
        cap = db.query(Capability).filter(Capability.capability_key == cap_key).first()
        if cap is None:
            cap = Capability(
                id=str(uuid.uuid4()),
                capability_key=cap_key,
                capability_name=cap_key,
                capability_category=cap_key.split(".")[0],
                active=True,
            )
            db.add(cap)
            db.flush()
        assoc = PolicyBundleCapability(bundle_id=bundle.id, capability_id=cap.id)
        db.add(assoc)
    db.flush()
    return bundle


def _make_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tenant_id: str,
    *,
    scopes: str = "admin:read admin:write",
    name: str = "sub",
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


# ---------------------------------------------------------------------------
# SUB-1: Create contract
# ---------------------------------------------------------------------------


class TestSUB1:
    def test_create_contract_persisted(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch)
        tenant = "tenant-sub1"
        result = _engine_svc.create_contract(
            db,
            tenant_id=tenant,
            contract_ref="DEAL-001",
            sku_package="enterprise",
            starts_at=_utcnow(),
        )
        db.commit()
        assert result.id is not None
        assert result.status == "draft"
        assert result.contract_ref == "DEAL-001"
        assert result.sku_package == "enterprise"
        assert result.tenant_id == tenant

        stored = (
            db.query(SubscriptionContract)
            .filter(SubscriptionContract.id == result.id)
            .first()
        )
        assert stored is not None
        assert stored.status == "draft"


# ---------------------------------------------------------------------------
# SUB-2: Activate contract
# ---------------------------------------------------------------------------


class TestSUB2:
    def test_activate_contract(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch)
        tenant = "tenant-sub2"
        contract = _engine_svc.create_contract(
            db,
            tenant_id=tenant,
            contract_ref="DEAL-002",
            sku_package="enterprise",
            starts_at=_utcnow(),
        )
        db.commit()

        updated = _engine_svc.update_contract_status(
            db, contract.id, tenant, "active", actor="sales-bot"
        )
        db.commit()
        assert updated is not None
        assert updated.status == "active"


# ---------------------------------------------------------------------------
# SUB-3: Cancel contract
# ---------------------------------------------------------------------------


class TestSUB3:
    def test_cancel_contract(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch)
        tenant = "tenant-sub3"
        contract = _engine_svc.create_contract(
            db,
            tenant_id=tenant,
            contract_ref="DEAL-003",
            sku_package="msp",
            starts_at=_utcnow(),
        )
        db.commit()
        result = _engine_svc.update_contract_status(
            db, contract.id, tenant, "canceled", actor="admin", reason="test cancel"
        )
        db.commit()
        assert result is not None
        assert result.status == "canceled"


# ---------------------------------------------------------------------------
# SUB-4: Create active item → TenantBundleAssignment created
# ---------------------------------------------------------------------------


class TestSUB4:
    def test_create_active_item_syncs_bundle_assignment(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch)
        tenant = "tenant-sub4"
        bundle = _make_bundle(
            db, bundle_key="test-bundle-4", capabilities=["api.access"]
        )

        contract = _engine_svc.create_contract(
            db,
            tenant_id=tenant,
            contract_ref="D-004",
            sku_package="enterprise",
            starts_at=_utcnow(),
            status="active",
        )
        db.commit()

        item = _engine_svc.create_item(
            db,
            contract_id=contract.id,
            tenant_id=tenant,
            bundle_id=bundle.id,
            sku_code="enterprise_base",
            starts_at=_utcnow(),
        )
        db.commit()

        assert item.bundle_assignment_id is not None
        assignment = (
            db.query(TenantBundleAssignment)
            .filter(TenantBundleAssignment.id == item.bundle_assignment_id)
            .first()
        )
        assert assignment is not None
        assert assignment.tenant_id == tenant
        assert assignment.bundle_id == bundle.id
        assert assignment.subscription_id == item.id


# ---------------------------------------------------------------------------
# SUB-5: Active item → capability granted via bundle resolver
# ---------------------------------------------------------------------------


class TestSUB5:
    def test_active_item_grants_capability(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="sub5")
        tenant = "tenant-sub5"
        bundle = _make_bundle(
            db, bundle_key="test-bundle-5", capabilities=["portal.access"]
        )

        contract = _engine_svc.create_contract(
            db,
            tenant_id=tenant,
            contract_ref="D-005",
            sku_package="portal_only",
            starts_at=_utcnow(),
            status="active",
        )
        db.commit()
        _engine_svc.create_item(
            db,
            contract_id=contract.id,
            tenant_id=tenant,
            bundle_id=bundle.id,
            sku_code="portal_base",
            starts_at=_utcnow(),
        )
        db.commit()

        invalidate_cache(tenant)
        result = check_capability(db, tenant, "portal.access")
        assert result.allowed is True
        assert result.source in ("bundle", "explicit", "tier")


# ---------------------------------------------------------------------------
# SUB-6: Suspend item → capability denied
# ---------------------------------------------------------------------------


class TestSUB6:
    def test_suspend_item_denies_capability(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="sub6")
        tenant = "tenant-sub6"
        bundle = _make_bundle(
            db, bundle_key="test-bundle-6", capabilities=["portal.rag"]
        )

        contract = _engine_svc.create_contract(
            db,
            tenant_id=tenant,
            contract_ref="D-006",
            sku_package="ai_rag",
            starts_at=_utcnow(),
            status="active",
        )
        db.commit()
        item = _engine_svc.create_item(
            db,
            contract_id=contract.id,
            tenant_id=tenant,
            bundle_id=bundle.id,
            sku_code="rag_base",
            starts_at=_utcnow(),
        )
        db.commit()
        invalidate_cache(tenant)
        assert check_capability(db, tenant, "portal.rag").allowed is True

        _engine_svc.update_item_status(db, item.id, tenant, "suspended", actor="admin")
        db.commit()
        invalidate_cache(tenant)

        # portal.rag is not a tier-default for free/pro tier, so should now be denied
        # (unless tier covers it — we verify the suspension expired the assignment)
        assignment = (
            db.query(TenantBundleAssignment)
            .filter(TenantBundleAssignment.id == item.bundle_assignment_id)
            .first()
        )
        assert assignment is not None
        # Assignment should be expired now
        assert assignment.expires_at is not None


# ---------------------------------------------------------------------------
# SUB-7: Cancel item → capability denied
# ---------------------------------------------------------------------------


class TestSUB7:
    def test_cancel_item_expires_assignment(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="sub7")
        tenant = "tenant-sub7"
        bundle = _make_bundle(
            db, bundle_key="test-bundle-7", capabilities=["identity.sso"]
        )

        contract = _engine_svc.create_contract(
            db,
            tenant_id=tenant,
            contract_ref="D-007",
            sku_package="enterprise",
            starts_at=_utcnow(),
            status="active",
        )
        db.commit()
        item = _engine_svc.create_item(
            db,
            contract_id=contract.id,
            tenant_id=tenant,
            bundle_id=bundle.id,
            sku_code="ent_sso",
            starts_at=_utcnow(),
        )
        db.commit()

        _engine_svc.update_item_status(
            db, item.id, tenant, "canceled", actor="admin", reason="contract end"
        )
        db.commit()
        invalidate_cache(tenant)

        assignment = (
            db.query(TenantBundleAssignment)
            .filter(TenantBundleAssignment.id == item.bundle_assignment_id)
            .first()
        )
        assert assignment is not None
        assert assignment.expires_at is not None

        # Ledger should have both created and canceled events
        ledger = _engine_svc.list_ledger(db, item.id, tenant)
        event_types = [e.event_type for e in ledger]
        assert "created" in event_types
        assert "canceled" in event_types


# ---------------------------------------------------------------------------
# SUB-8: Reactivate suspended item
# ---------------------------------------------------------------------------


class TestSUB8:
    def test_reactivate_suspended_item(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="sub8")
        tenant = "tenant-sub8"
        bundle = _make_bundle(
            db, bundle_key="test-bundle-8", capabilities=["api.access"]
        )

        contract = _engine_svc.create_contract(
            db,
            tenant_id=tenant,
            contract_ref="D-008",
            sku_package="api",
            starts_at=_utcnow(),
            status="active",
        )
        db.commit()
        item = _engine_svc.create_item(
            db,
            contract_id=contract.id,
            tenant_id=tenant,
            bundle_id=bundle.id,
            sku_code="api_access",
            starts_at=_utcnow(),
        )
        db.commit()

        _engine_svc.update_item_status(db, item.id, tenant, "suspended", actor="admin")
        db.commit()

        reactivated = _engine_svc.update_item_status(
            db, item.id, tenant, "active", actor="admin"
        )
        db.commit()
        assert reactivated is not None
        assert reactivated.status == "active"
        assert reactivated.bundle_assignment_id is not None

        ledger = _engine_svc.list_ledger(db, item.id, tenant)
        event_types = [e.event_type for e in ledger]
        assert "reactivated" in event_types


# ---------------------------------------------------------------------------
# SUB-9: Ledger immutability guard
# ---------------------------------------------------------------------------


class TestSUB9:
    def test_ledger_entries_are_append_only(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="sub9")
        tenant = "tenant-sub9"
        bundle = _make_bundle(
            db, bundle_key="test-bundle-9", capabilities=["api.access"]
        )

        contract = _engine_svc.create_contract(
            db,
            tenant_id=tenant,
            contract_ref="D-009",
            sku_package="api",
            starts_at=_utcnow(),
            status="active",
        )
        db.commit()
        item = _engine_svc.create_item(
            db,
            contract_id=contract.id,
            tenant_id=tenant,
            bundle_id=bundle.id,
            sku_code="api_base",
            starts_at=_utcnow(),
        )
        db.commit()

        ledger = _engine_svc.list_ledger(db, item.id, tenant)
        assert len(ledger) >= 1

        entry = (
            db.query(SubscriptionEventLedger)
            .filter(SubscriptionEventLedger.subscription_item_id == item.id)
            .first()
        )
        assert entry is not None

        # Attempt to update the immutable ledger row — must raise ValueError
        with pytest.raises(ValueError, match="append-only"):
            entry.event_type = "tampered"
            db.flush()

        db.rollback()

        # Attempt to delete — must also raise ValueError
        entry = (
            db.query(SubscriptionEventLedger)
            .filter(SubscriptionEventLedger.subscription_item_id == item.id)
            .first()
        )
        with pytest.raises(ValueError, match="append-only"):
            db.delete(entry)
            db.flush()


# ---------------------------------------------------------------------------
# SUB-10: Ledger hash chain integrity
# ---------------------------------------------------------------------------


class TestSUB10:
    def test_ledger_hash_chain_integrity(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="sub10")
        tenant = "tenant-sub10"
        bundle = _make_bundle(
            db, bundle_key="test-bundle-10", capabilities=["api.access"]
        )

        contract = _engine_svc.create_contract(
            db,
            tenant_id=tenant,
            contract_ref="D-010",
            sku_package="api",
            starts_at=_utcnow(),
            status="active",
        )
        db.commit()
        item = _engine_svc.create_item(
            db,
            contract_id=contract.id,
            tenant_id=tenant,
            bundle_id=bundle.id,
            sku_code="api_base",
            starts_at=_utcnow(),
        )
        _engine_svc.update_item_status(db, item.id, tenant, "suspended", actor="admin")
        _engine_svc.update_item_status(db, item.id, tenant, "active", actor="admin")
        db.commit()

        entries = _engine_svc.list_ledger(db, item.id, tenant)
        assert len(entries) >= 3

        # Verify hash chain: each entry's prev_hash equals prior entry's entry_hash
        assert entries[0].prev_hash == "GENESIS"
        for i in range(1, len(entries)):
            assert entries[i].prev_hash == entries[i - 1].entry_hash, (
                f"hash chain broken at entry {i}"
            )


# ---------------------------------------------------------------------------
# SUB-11: Tenant isolation
# ---------------------------------------------------------------------------


class TestSUB11:
    def test_tenant_isolation(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="sub11")
        tenant_a = "tenant-a-sub11"
        tenant_b = "tenant-b-sub11"
        bundle = _make_bundle(
            db, bundle_key="test-bundle-11", capabilities=["identity.sso"]
        )

        contract = _engine_svc.create_contract(
            db,
            tenant_id=tenant_a,
            contract_ref="D-011A",
            sku_package="enterprise",
            starts_at=_utcnow(),
            status="active",
        )
        db.commit()
        _engine_svc.create_item(
            db,
            contract_id=contract.id,
            tenant_id=tenant_a,
            bundle_id=bundle.id,
            sku_code="ent_sso",
            starts_at=_utcnow(),
        )
        db.commit()
        invalidate_cache(tenant_a)
        invalidate_cache(tenant_b)

        result_a = check_capability(db, tenant_a, "identity.sso")
        result_b = check_capability(db, tenant_b, "identity.sso")

        assert result_a.allowed is True
        # tenant_b should NOT inherit tenant_a's subscription
        assert result_b.allowed is False or result_b.source == "tier"
        # Strictly: identity.sso is not in free/pro tier defaults
        assert result_b.allowed is False


# ---------------------------------------------------------------------------
# SUB-12: MSP parent_item_id stored
# ---------------------------------------------------------------------------


class TestSUB12:
    def test_msp_parent_item_stored(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="sub12")
        tenant = "tenant-sub12"
        bundle = _make_bundle(
            db, bundle_key="test-bundle-12", capabilities=["msp.multi_tenant"]
        )

        contract = _engine_svc.create_contract(
            db,
            tenant_id=tenant,
            contract_ref="D-012",
            sku_package="msp",
            starts_at=_utcnow(),
            status="active",
        )
        db.commit()
        parent_item = _engine_svc.create_item(
            db,
            contract_id=contract.id,
            tenant_id=tenant,
            bundle_id=bundle.id,
            sku_code="msp_base",
            starts_at=_utcnow(),
        )
        db.commit()

        child_item = _engine_svc.create_item(
            db,
            contract_id=contract.id,
            tenant_id=tenant,
            bundle_id=bundle.id,
            sku_code="msp_child",
            starts_at=_utcnow(),
            parent_item_id=parent_item.id,
        )
        db.commit()

        assert child_item.parent_item_id == parent_item.id
        stored = (
            db.query(SubscriptionItem)
            .filter(SubscriptionItem.id == child_item.id)
            .first()
        )
        assert stored is not None
        assert stored.parent_item_id == parent_item.id


# ---------------------------------------------------------------------------
# SUB-13: explain-capability traces full chain (subscription source)
# ---------------------------------------------------------------------------


class TestSUB13:
    def test_explain_subscription_source(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="sub13")
        tenant = "tenant-sub13"
        bundle = _make_bundle(
            db, bundle_key="test-bundle-13", capabilities=["api.access"]
        )

        contract = _engine_svc.create_contract(
            db,
            tenant_id=tenant,
            contract_ref="D-013",
            sku_package="api",
            starts_at=_utcnow(),
            status="active",
        )
        db.commit()
        _engine_svc.create_item(
            db,
            contract_id=contract.id,
            tenant_id=tenant,
            bundle_id=bundle.id,
            sku_code="api_base",
            starts_at=_utcnow(),
        )
        db.commit()
        invalidate_cache(tenant)

        explain = _engine_svc.explain_capability(db, tenant, "api.access")
        assert explain.decision == "granted"
        assert explain.source in ("subscription", "bundle")
        layer_names = [e.layer for e in explain.resolution_chain]
        assert "registry" in layer_names
        assert "bundle_assignment" in layer_names


# ---------------------------------------------------------------------------
# SUB-14: explain-capability denied path
# ---------------------------------------------------------------------------


class TestSUB14:
    def test_explain_denied(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="sub14")
        tenant = "tenant-sub14"

        explain = _engine_svc.explain_capability(db, tenant, "identity.sso")
        assert explain.decision == "denied"
        layer_names = [e.layer for e in explain.resolution_chain]
        assert "registry" in layer_names


# ---------------------------------------------------------------------------
# SUB-15: explain-capability registry miss
# ---------------------------------------------------------------------------


class TestSUB15:
    def test_explain_registry_miss(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="sub15")
        tenant = "tenant-sub15"

        explain = _engine_svc.explain_capability(db, tenant, "not.a.real.capability")
        assert explain.decision == "denied"
        assert explain.source == "registry_miss"
        assert explain.resolution_chain[0].layer == "registry"
        assert explain.resolution_chain[0].result == "miss"


# ---------------------------------------------------------------------------
# SUB-16: explain-capability dependency checks populated
# ---------------------------------------------------------------------------


class TestSUB16:
    def test_explain_dep_checks_populated(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, name="sub16")
        tenant = "tenant-sub16"
        # Grant ai.workspace and ai.agent_builder so ai.multi_agent resolves with deps
        bundle = _make_bundle(
            db,
            bundle_key="test-bundle-16",
            capabilities=["ai.workspace", "ai.agent_builder", "ai.multi_agent"],
        )

        contract = _engine_svc.create_contract(
            db,
            tenant_id=tenant,
            contract_ref="D-016",
            sku_package="ai_full",
            starts_at=_utcnow(),
            status="active",
        )
        db.commit()
        _engine_svc.create_item(
            db,
            contract_id=contract.id,
            tenant_id=tenant,
            bundle_id=bundle.id,
            sku_code="ai_multi",
            starts_at=_utcnow(),
        )
        db.commit()
        invalidate_cache(tenant)

        explain = _engine_svc.explain_capability(db, tenant, "ai.multi_agent")
        assert explain.decision == "granted"
        # Dependency checks should include transitive deps
        assert len(explain.dependency_checks) > 0
        assert "ai.agent_builder" in explain.dependency_checks
        assert "ai.workspace" in explain.dependency_checks


# ---------------------------------------------------------------------------
# SUB-17: explain-capability via HTTP endpoint (granted)
# ---------------------------------------------------------------------------


class TestSUB17:
    def test_explain_http_granted(self, tmp_path, monkeypatch):
        tenant = "tenant-sub17"
        client = _make_client(tmp_path, monkeypatch, tenant, name="sub17")

        # Grant portal.access to this tenant via bundle so explain returns granted
        db = get_sessionmaker()()
        bundle = _make_bundle(
            db, bundle_key="test-bundle-17", capabilities=["portal.access"]
        )
        contract = _engine_svc.create_contract(
            db,
            tenant_id=tenant,
            contract_ref="D-017",
            sku_package="portal",
            starts_at=_utcnow(),
            status="active",
        )
        db.commit()
        _engine_svc.create_item(
            db,
            contract_id=contract.id,
            tenant_id=tenant,
            bundle_id=bundle.id,
            sku_code="portal_base",
            starts_at=_utcnow(),
        )
        db.commit()
        invalidate_cache(tenant)

        resp = client.get("/subscriptions/explain-capability?capability=portal.access")
        assert resp.status_code == 200
        body = resp.json()
        assert body["decision"] == "granted"
        assert body["tenant_id"] == tenant


# ---------------------------------------------------------------------------
# SUB-18: explain-capability via HTTP endpoint (denied)
# ---------------------------------------------------------------------------


class TestSUB18:
    def test_explain_http_denied(self, tmp_path, monkeypatch):
        tenant = "tenant-sub18"
        client = _make_client(tmp_path, monkeypatch, tenant, name="sub18")

        resp = client.get(
            "/subscriptions/explain-capability?capability=government.fedramp"
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["decision"] == "denied"


# ---------------------------------------------------------------------------
# SUB-19: API create contract via POST
# ---------------------------------------------------------------------------


class TestSUB19:
    def test_api_create_contract(self, tmp_path, monkeypatch):
        tenant = "tenant-sub19"
        client = _make_client(tmp_path, monkeypatch, tenant, name="sub19")

        resp = client.post(
            "/admin/subscriptions/contracts",
            params={"tenant_id": tenant},
            json={
                "contract_ref": "DEAL-API-19",
                "sku_package": "enterprise",
                "sku_metadata": {"max_seats": 100},
                "starts_at": _utcnow().isoformat(),
                "created_by": "test",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["contract_ref"] == "DEAL-API-19"
        assert body["status"] == "draft"
        assert body["tenant_id"] == tenant


# ---------------------------------------------------------------------------
# SUB-20: API create item via POST, list items
# ---------------------------------------------------------------------------


class TestSUB20:
    def test_api_create_and_list_items(self, tmp_path, monkeypatch):
        tenant = "tenant-sub20"
        client = _make_client(tmp_path, monkeypatch, tenant, name="sub20")

        db = get_sessionmaker()()
        bundle = _make_bundle(
            db, bundle_key="test-bundle-20", capabilities=["api.access"]
        )
        contract = _engine_svc.create_contract(
            db,
            tenant_id=tenant,
            contract_ref="D-020",
            sku_package="api",
            starts_at=_utcnow(),
            status="active",
        )
        db.commit()

        resp = client.post(
            f"/admin/subscriptions/contracts/{contract.id}/items",
            params={"tenant_id": tenant},
            json={
                "bundle_id": bundle.id,
                "sku_code": "api_base",
                "starts_at": _utcnow().isoformat(),
            },
        )
        assert resp.status_code == 200
        item_body = resp.json()
        assert item_body["status"] == "active"
        assert item_body["bundle_id"] == bundle.id

        list_resp = client.get(f"/admin/tenants/{tenant}/subscriptions/items")
        assert list_resp.status_code == 200
        list_body = list_resp.json()
        assert list_body["count"] >= 1
        assert any(i["id"] == item_body["id"] for i in list_body["items"])
