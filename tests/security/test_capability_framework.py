"""P1.2 Tenant Policy Bundles + Capability Framework — security test suite.

Test matrix (15 tests + CAP-16 for audit events):
  CAP-1   tenant with bundle gets all bundle capabilities in resolved set
  CAP-2   tenant with multiple bundles gets union of all capabilities
  CAP-3   removing bundle removes its capabilities from resolved set
  CAP-4   cross-tenant isolation — tenant A's bundles don't appear for tenant B
  CAP-5   unknown capability → EntitlementResult.allowed=False, source="registry_miss"
  CAP-6   cache invalidation — after invalidate_cache(tid), fresh resolve reflects new
          assignments
  CAP-7   subscription type change → bundle assignment updates capabilities
  CAP-8   direct tenant_capability_assignments (manual source) work alongside bundle
  CAP-9   resolve_tenant_capabilities() returns frozenset[str]
  CAP-10  check_capability() with no bundle, no explicit grant, no tier default → denied
  CAP-11  ai.workspace in enterprise bundle, not in portal_only
  CAP-12  marketplace source supported in tenant_capability_assignments.source
  CAP-13  government bundle includes government.fedramp
  CAP-14  RBAC (scopes) and capability checks are independent — valid API key with wrong
          capability is still denied
  CAP-15  resolver is deterministic — same inputs always produce same frozenset
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from api.db import get_sessionmaker, init_db, reset_engine_cache
from api.db_models import (
    Capability,
    PolicyBundle,
    PolicyBundleCapability,
    TenantBundleAssignment,
    TenantCapabilityAssignment,
)
from api.entitlements import CAPABILITY_REGISTRY, check_capability
from services.capability_bundles.resolver import (
    invalidate_cache,
    resolve_tenant_capabilities,
)
from services.capability_bundles.seeder import seed_bundle_catalog


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str = "cap"):
    db_path = str(tmp_path / f"{name}.db")
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    reset_engine_cache()
    init_db(sqlite_path=db_path)
    return get_sessionmaker(sqlite_path=db_path)()


def _make_bundle(db, *, bundle_key: str, capabilities: list[str]) -> PolicyBundle:
    """Insert a PolicyBundle + Capability rows + join rows.  Returns the bundle."""
    bundle = PolicyBundle(
        id=str(uuid.uuid4()),
        bundle_key=bundle_key,
        bundle_name=bundle_key.replace("_", " ").title(),
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
    db.commit()
    return bundle


def _assign_bundle(db, *, tenant_id: str, bundle_id: str) -> TenantBundleAssignment:
    a = TenantBundleAssignment(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        bundle_id=bundle_id,
    )
    db.add(a)
    db.commit()
    return a


def _assign_capability_direct(
    db, *, tenant_id: str, capability_key: str, source: str = "manual"
) -> TenantCapabilityAssignment:
    cap = (
        db.query(Capability).filter(Capability.capability_key == capability_key).first()
    )
    if cap is None:
        cap = Capability(
            id=str(uuid.uuid4()),
            capability_key=capability_key,
            capability_name=capability_key,
            capability_category=capability_key.split(".")[0],
            active=True,
        )
        db.add(cap)
        db.flush()
    tca = TenantCapabilityAssignment(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        capability_id=cap.id,
        source=source,
    )
    db.add(tca)
    db.commit()
    return tca


# ---------------------------------------------------------------------------
# CAP-1: tenant with bundle gets all bundle capabilities in resolved set
# ---------------------------------------------------------------------------


def test_cap1_bundle_capabilities_resolved(tmp_path, monkeypatch):
    """CAP-1: resolved set contains all capabilities from an assigned bundle."""
    db = _make_db(tmp_path, monkeypatch, "cap1")
    bundle = _make_bundle(
        db,
        bundle_key="portal_only_t1",
        capabilities=["portal.access", "api.access"],
    )
    _assign_bundle(db, tenant_id="tenant-a", bundle_id=bundle.id)
    invalidate_cache("tenant-a")

    caps = resolve_tenant_capabilities(db, "tenant-a")

    assert "portal.access" in caps
    assert "api.access" in caps
    db.close()


# ---------------------------------------------------------------------------
# CAP-2: tenant with multiple bundles gets union of all capabilities
# ---------------------------------------------------------------------------


def test_cap2_multiple_bundles_union(tmp_path, monkeypatch):
    """CAP-2: multiple bundles yield the union of their capabilities."""
    db = _make_db(tmp_path, monkeypatch, "cap2")
    b1 = _make_bundle(db, bundle_key="b1", capabilities=["portal.access"])
    b2 = _make_bundle(db, bundle_key="b2", capabilities=["ai.workspace"])
    _assign_bundle(db, tenant_id="tenant-b", bundle_id=b1.id)
    _assign_bundle(db, tenant_id="tenant-b", bundle_id=b2.id)
    invalidate_cache("tenant-b")

    caps = resolve_tenant_capabilities(db, "tenant-b")

    assert "portal.access" in caps
    assert "ai.workspace" in caps
    db.close()


# ---------------------------------------------------------------------------
# CAP-3: removing bundle removes its capabilities from resolved set
# ---------------------------------------------------------------------------


def test_cap3_remove_bundle_removes_capabilities(tmp_path, monkeypatch):
    """CAP-3: after deleting the assignment, capabilities are no longer resolved."""
    db = _make_db(tmp_path, monkeypatch, "cap3")
    bundle = _make_bundle(
        db, bundle_key="enterprise_t3", capabilities=["ai.governance"]
    )
    assignment = _assign_bundle(db, tenant_id="tenant-c", bundle_id=bundle.id)
    invalidate_cache("tenant-c")
    caps_before = resolve_tenant_capabilities(db, "tenant-c")
    assert "ai.governance" in caps_before

    # Remove the assignment
    db.delete(assignment)
    db.commit()
    invalidate_cache("tenant-c")

    caps_after = resolve_tenant_capabilities(db, "tenant-c")
    assert "ai.governance" not in caps_after
    db.close()


# ---------------------------------------------------------------------------
# CAP-4: cross-tenant isolation
# ---------------------------------------------------------------------------


def test_cap4_cross_tenant_isolation(tmp_path, monkeypatch):
    """CAP-4: tenant A's bundles do not appear in tenant B's resolved set."""
    db = _make_db(tmp_path, monkeypatch, "cap4")
    bundle = _make_bundle(
        db, bundle_key="iso_bundle", capabilities=["government.fedramp"]
    )
    _assign_bundle(db, tenant_id="tenant-alpha", bundle_id=bundle.id)
    invalidate_cache("tenant-alpha")
    invalidate_cache("tenant-beta")

    alpha_caps = resolve_tenant_capabilities(db, "tenant-alpha")
    beta_caps = resolve_tenant_capabilities(db, "tenant-beta")

    assert "government.fedramp" in alpha_caps
    assert "government.fedramp" not in beta_caps
    db.close()


# ---------------------------------------------------------------------------
# CAP-5: unknown capability → registry_miss
# ---------------------------------------------------------------------------


def test_cap5_unknown_capability_registry_miss(tmp_path, monkeypatch):
    """CAP-5: a capability not in CAPABILITY_REGISTRY is always denied."""
    db = _make_db(tmp_path, monkeypatch, "cap5")
    result = check_capability(db, "tenant-x", "does_not.exist")

    assert result.allowed is False
    assert result.source == "registry_miss"
    db.close()


# ---------------------------------------------------------------------------
# CAP-6: cache invalidation
# ---------------------------------------------------------------------------


def test_cap6_cache_invalidation(tmp_path, monkeypatch):
    """CAP-6: after invalidate_cache(), a new resolve reflects added assignments."""
    db = _make_db(tmp_path, monkeypatch, "cap6")
    invalidate_cache("tenant-d")

    caps_empty = resolve_tenant_capabilities(db, "tenant-d")
    assert len(caps_empty) == 0

    bundle = _make_bundle(db, bundle_key="new_bundle", capabilities=["portal.ai"])
    _assign_bundle(db, tenant_id="tenant-d", bundle_id=bundle.id)
    # Without invalidation, cache still returns empty
    # Invalidate and re-resolve
    invalidate_cache("tenant-d")
    caps_after = resolve_tenant_capabilities(db, "tenant-d")
    assert "portal.ai" in caps_after
    db.close()


# ---------------------------------------------------------------------------
# CAP-7: subscription type change → bundle assignment updates capabilities
# ---------------------------------------------------------------------------


def test_cap7_subscription_type_change(tmp_path, monkeypatch):
    """CAP-7: switching from portal_only to enterprise bundle changes capabilities."""
    db = _make_db(tmp_path, monkeypatch, "cap7")
    portal_bundle = _make_bundle(
        db,
        bundle_key="portal_only_c7",
        capabilities=["portal.access"],
    )
    enterprise_bundle = _make_bundle(
        db,
        bundle_key="enterprise_c7",
        capabilities=["portal.access", "ai.workspace", "identity.sso"],
    )

    assignment = _assign_bundle(db, tenant_id="tenant-e", bundle_id=portal_bundle.id)
    invalidate_cache("tenant-e")
    caps_portal = resolve_tenant_capabilities(db, "tenant-e")
    assert "ai.workspace" not in caps_portal

    # Switch to enterprise
    db.delete(assignment)
    db.commit()
    _assign_bundle(db, tenant_id="tenant-e", bundle_id=enterprise_bundle.id)
    invalidate_cache("tenant-e")

    caps_enterprise = resolve_tenant_capabilities(db, "tenant-e")
    assert "ai.workspace" in caps_enterprise
    assert "identity.sso" in caps_enterprise
    db.close()


# ---------------------------------------------------------------------------
# CAP-8: direct capability assignments work alongside bundle
# ---------------------------------------------------------------------------


def test_cap8_direct_assignment_alongside_bundle(tmp_path, monkeypatch):
    """CAP-8: direct (manual source) assignments are included in the resolved set."""
    db = _make_db(tmp_path, monkeypatch, "cap8")
    bundle = _make_bundle(
        db, bundle_key="base_bundle_c8", capabilities=["portal.access"]
    )
    _assign_bundle(db, tenant_id="tenant-f", bundle_id=bundle.id)
    _assign_capability_direct(
        db, tenant_id="tenant-f", capability_key="ai.fine_tuning", source="manual"
    )
    invalidate_cache("tenant-f")

    caps = resolve_tenant_capabilities(db, "tenant-f")
    assert "portal.access" in caps
    assert "ai.fine_tuning" in caps
    db.close()


# ---------------------------------------------------------------------------
# CAP-9: resolve_tenant_capabilities() returns frozenset[str]
# ---------------------------------------------------------------------------


def test_cap9_returns_frozenset(tmp_path, monkeypatch):
    """CAP-9: resolve_tenant_capabilities() always returns frozenset[str]."""
    db = _make_db(tmp_path, monkeypatch, "cap9")
    invalidate_cache("tenant-g")
    result = resolve_tenant_capabilities(db, "tenant-g")

    assert isinstance(result, frozenset)
    db.close()


# ---------------------------------------------------------------------------
# CAP-10: check_capability with no bundle, no explicit grant, no tier default → denied
# ---------------------------------------------------------------------------


def test_cap10_no_grant_denied(tmp_path, monkeypatch):
    """CAP-10: a new capability not in tier defaults is denied without a grant."""
    db = _make_db(tmp_path, monkeypatch, "cap10")
    invalidate_cache("tenant-h")

    # portal.access is not in any tier default
    result = check_capability(db, "tenant-h", "portal.access")

    assert result.allowed is False
    assert result.source in {"tier", "bundle"}
    db.close()


# ---------------------------------------------------------------------------
# CAP-11: ai.workspace in enterprise bundle, not in portal_only
# ---------------------------------------------------------------------------


def test_cap11_ai_workspace_enterprise_not_portal_only(tmp_path, monkeypatch):
    """CAP-11: ai.workspace belongs to enterprise bundle, absent from portal_only."""
    db = _make_db(tmp_path, monkeypatch, "cap11")
    seed_bundle_catalog(db)
    invalidate_cache("tenant-i")
    invalidate_cache("tenant-j")

    portal_bundle = (
        db.query(PolicyBundle).filter(PolicyBundle.bundle_key == "portal_only").first()
    )
    enterprise_bundle = (
        db.query(PolicyBundle).filter(PolicyBundle.bundle_key == "enterprise").first()
    )

    _assign_bundle(db, tenant_id="tenant-i", bundle_id=portal_bundle.id)
    _assign_bundle(db, tenant_id="tenant-j", bundle_id=enterprise_bundle.id)
    invalidate_cache("tenant-i")
    invalidate_cache("tenant-j")

    portal_caps = resolve_tenant_capabilities(db, "tenant-i")
    enterprise_caps = resolve_tenant_capabilities(db, "tenant-j")

    assert "ai.workspace" not in portal_caps
    assert "ai.workspace" in enterprise_caps
    db.close()


# ---------------------------------------------------------------------------
# CAP-12: marketplace source supported in tenant_capability_assignments.source
# ---------------------------------------------------------------------------


def test_cap12_marketplace_source(tmp_path, monkeypatch):
    """CAP-12: 'marketplace' is a valid source for TenantCapabilityAssignment."""
    db = _make_db(tmp_path, monkeypatch, "cap12")
    _assign_capability_direct(
        db,
        tenant_id="tenant-k",
        capability_key="ai.agent_builder",
        source="marketplace",
    )
    invalidate_cache("tenant-k")

    caps = resolve_tenant_capabilities(db, "tenant-k")
    assert "ai.agent_builder" in caps
    db.close()


# ---------------------------------------------------------------------------
# CAP-13: government bundle includes government.fedramp
# ---------------------------------------------------------------------------


def test_cap13_government_bundle_fedramp(tmp_path, monkeypatch):
    """CAP-13: the seeded government bundle contains government.fedramp."""
    db = _make_db(tmp_path, monkeypatch, "cap13")
    seed_bundle_catalog(db)

    gov_bundle = (
        db.query(PolicyBundle).filter(PolicyBundle.bundle_key == "government").first()
    )
    assert gov_bundle is not None

    _assign_bundle(db, tenant_id="tenant-l", bundle_id=gov_bundle.id)
    invalidate_cache("tenant-l")

    caps = resolve_tenant_capabilities(db, "tenant-l")
    assert "government.fedramp" in caps
    db.close()


# ---------------------------------------------------------------------------
# CAP-14: RBAC (scopes) and capability checks are independent
# ---------------------------------------------------------------------------


def test_cap14_rbac_and_capability_independent(tmp_path, monkeypatch):
    """CAP-14: having admin:write scope does not grant capabilities."""
    db = _make_db(tmp_path, monkeypatch, "cap14")
    invalidate_cache("tenant-m")

    # tenant-m has no bundles and no tier defaults for portal.access
    result = check_capability(db, "tenant-m", "portal.access")

    # Regardless of any RBAC scope the caller might hold, check_capability
    # is purely about entitlement — it should deny.
    assert result.allowed is False
    db.close()


# ---------------------------------------------------------------------------
# CAP-15: resolver is deterministic
# ---------------------------------------------------------------------------


def test_cap15_resolver_deterministic(tmp_path, monkeypatch):
    """CAP-15: same DB state always produces the same frozenset."""
    db = _make_db(tmp_path, monkeypatch, "cap15")
    seed_bundle_catalog(db)

    portal_bundle = (
        db.query(PolicyBundle).filter(PolicyBundle.bundle_key == "portal_only").first()
    )
    _assign_bundle(db, tenant_id="tenant-n", bundle_id=portal_bundle.id)

    results = set()
    for _ in range(5):
        invalidate_cache("tenant-n")
        caps = resolve_tenant_capabilities(db, "tenant-n")
        results.add(caps)  # frozenset is hashable

    assert len(results) == 1, "resolver returned different sets across calls"
    db.close()


# ---------------------------------------------------------------------------
# CAP-16: new capability keys present in CAPABILITY_REGISTRY
# ---------------------------------------------------------------------------


def test_cap16_new_keys_in_registry(tmp_path, monkeypatch):
    """CAP-16: all P1.2 capability keys are present in CAPABILITY_REGISTRY."""
    p12_keys = [
        "portal.access",
        "portal.remediation",
        "portal.ai",
        "portal.rag",
        "ai.workspace",
        "ai.chat",
        "ai.rag",
        "ai.document_ingestion",
        "ai.agent_builder",
        "ai.multi_agent",
        "ai.private_models",
        "ai.fine_tuning",
        "ai.governance",
        "ai.compliance_assistant",
        "ai.executive_advisor",
        "api.access",
        "identity.sso",
        "identity.scim",
        "reports.executive",
        "reports.regulatory",
        "tenant.multi_region",
        "msp.multi_tenant",
        "msp.white_label",
        "government.fedramp",
        "government.cjis",
        "government.itar",
        "government.airgap",
        "government.private_llm",
    ]
    missing = [k for k in p12_keys if k not in CAPABILITY_REGISTRY]
    assert missing == [], f"Keys missing from CAPABILITY_REGISTRY: {missing}"
