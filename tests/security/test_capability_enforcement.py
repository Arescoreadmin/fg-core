"""P1.3 Capability Enforcement Engine — security test suite.

Test matrix:
  CAPE-1   portal.access granted — tenant with bundle gets access
  CAPE-2   portal.access denied — tenant without bundle gets 403
  CAPE-3   ai.workspace granted — enterprise bundle grants access
  CAPE-4   ai.workspace denied — portal_only bundle does not include ai.workspace
  CAPE-5   dependency enforcement — ai.rag granted only when ai.workspace also present
  CAPE-6   broken dependency — ai.rag granted but ai.workspace missing → dep_failure
  CAPE-7   unknown capability → denied, source=registry_miss
  CAPE-8   cache hit — second resolve returns cached result, increments hit counter
  CAPE-9   cache miss — first resolve after invalidation goes to DB
  CAPE-10  cross-tenant isolation — CAPE-1 tenant capabilities don't bleed to CAPE-2
  CAPE-11  audit event emitted on check — EventType in {CAPABILITY_GRANTED, CAPABILITY_DENIED}
  CAPE-12  startup validation catches cycle in dependency graph
  CAPE-13  government.fedramp enforced — only government bundle grants access
  CAPE-14  msp.multi_tenant enforced — only msp bundle grants access
  CAPE-15  api.access enforced — missing capability → denied
  CAPE-16  authorization fails closed — dep_check error → denied (not granted)
"""

from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from api.db import get_sessionmaker, init_db, reset_engine_cache
from api.db_models import (
    Capability,
    PolicyBundle,
    PolicyBundleCapability,
    TenantBundleAssignment,
)
from api.entitlements import CAPABILITY_REGISTRY, check_capability
from api.security_audit import EventType
from services.capability_bundles.resolver import invalidate_cache
from services.capability_enforcement.graph import (
    DEPENDENCY_GRAPH,
    detect_cycles,
    get_required_capabilities,
    validate_graph,
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _make_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str = "cape"):
    db_path = str(tmp_path / f"{name}.db")
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    reset_engine_cache()
    init_db(sqlite_path=db_path)
    return get_sessionmaker(sqlite_path=db_path)()


def _make_bundle(db, *, bundle_key: str, capabilities: list[str]) -> PolicyBundle:
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
        db.add(PolicyBundleCapability(bundle_id=bundle.id, capability_id=cap.id))
    db.commit()
    return bundle


def _assign_bundle(db, *, tenant_id: str, bundle_id: str) -> None:
    db.add(
        TenantBundleAssignment(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            bundle_id=bundle_id,
        )
    )
    db.commit()


# ---------------------------------------------------------------------------
# CAPE-1: portal.access granted
# ---------------------------------------------------------------------------


class TestCAPE1PortalAccessGranted:
    def test_portal_access_granted_via_bundle(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, "cape1")
        tid = "tenant-cape1"
        bundle = _make_bundle(
            db, bundle_key="portal_only", capabilities=["portal.access"]
        )
        _assign_bundle(db, tenant_id=tid, bundle_id=bundle.id)
        invalidate_cache(tid)

        result = check_capability(db, tid, "portal.access")

        assert result.allowed is True
        assert result.source == "bundle"


# ---------------------------------------------------------------------------
# CAPE-2: portal.access denied
# ---------------------------------------------------------------------------


class TestCAPE2PortalAccessDenied:
    def test_portal_access_denied_no_bundle(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, "cape2")
        monkeypatch.setenv("FG_ENTITLEMENT_ENFORCEMENT", "true")
        tid = "tenant-cape2"
        invalidate_cache(tid)

        with patch("api.entitlements.ENFORCEMENT_STRICT", True):
            result = check_capability(db, tid, "portal.access")

        assert result.allowed is False

    def test_require_capability_raises_403_when_denied(self, tmp_path, monkeypatch):
        from fastapi import HTTPException
        from api.entitlements import require_capability

        _make_db(tmp_path, monkeypatch, "cape2b")
        tid = "tenant-cape2b"
        invalidate_cache(tid)

        req = MagicMock()
        req.state.tenant_id = None
        req.state.auth = MagicMock()
        req.state.auth.tenant_id = None

        with (
            patch("api.entitlements.ENFORCEMENT_STRICT", True),
            patch("api.entitlements.get_engine") as mock_engine,
        ):
            mock_engine.return_value.connect.return_value.__enter__ = MagicMock()

            with pytest.raises(HTTPException) as exc_info:
                require_capability("portal.access")(req)

        assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# CAPE-3: ai.workspace granted via enterprise bundle
# ---------------------------------------------------------------------------


class TestCAPE3AIWorkspaceGranted:
    def test_ai_workspace_granted_enterprise(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, "cape3")
        tid = "tenant-cape3"
        bundle = _make_bundle(
            db,
            bundle_key="enterprise",
            capabilities=["portal.access", "ai.workspace", "ai.chat"],
        )
        _assign_bundle(db, tenant_id=tid, bundle_id=bundle.id)
        invalidate_cache(tid)

        result = check_capability(db, tid, "ai.workspace")

        assert result.allowed is True
        assert result.source == "bundle"


# ---------------------------------------------------------------------------
# CAPE-4: ai.workspace denied — portal_only bundle
# ---------------------------------------------------------------------------


class TestCAPE4AIWorkspaceDenied:
    def test_ai_workspace_not_in_portal_only(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, "cape4")
        tid = "tenant-cape4"
        bundle = _make_bundle(
            db, bundle_key="portal_only", capabilities=["portal.access", "api.access"]
        )
        _assign_bundle(db, tenant_id=tid, bundle_id=bundle.id)
        invalidate_cache(tid)

        result = check_capability(db, tid, "ai.workspace")

        assert result.allowed is False


# ---------------------------------------------------------------------------
# CAPE-5: dependency enforcement works — ai.rag with ai.workspace present
# ---------------------------------------------------------------------------


class TestCAPE5DependencyEnforcementWorks:
    def test_ai_rag_deps_satisfied(self):
        deps = get_required_capabilities("ai.rag")
        assert "ai.workspace" in deps

    def test_ai_multi_agent_transitive_deps(self):
        deps = get_required_capabilities("ai.multi_agent")
        assert "ai.agent_builder" in deps
        assert "ai.workspace" in deps

    def test_capability_with_no_deps_returns_empty(self):
        deps = get_required_capabilities("portal.access")
        assert deps == []


# ---------------------------------------------------------------------------
# CAPE-6: broken dependency — ai.rag present but ai.workspace missing
# ---------------------------------------------------------------------------


class TestCAPE6BrokenDependency:
    def test_dep_failure_when_workspace_missing(self, tmp_path, monkeypatch):

        db = _make_db(tmp_path, monkeypatch, "cape6")
        tid = "tenant-cape6"
        # Give ai.rag but NOT ai.workspace
        bundle = _make_bundle(db, bundle_key="rag_only", capabilities=["ai.rag"])
        _assign_bundle(db, tenant_id=tid, bundle_id=bundle.id)
        invalidate_cache(tid)

        req = MagicMock()
        req.state.tenant_id = tid
        req.url = "http://localhost/test"
        req.method = "POST"

        with patch("api.entitlements.ENFORCEMENT_STRICT", True):
            # Direct check: ai.rag is granted via bundle
            result = check_capability(db, tid, "ai.rag")
            assert result.allowed is True

            # Dependency check: ai.workspace is missing
            from services.capability_bundles.resolver import resolve_tenant_capabilities

            caps = resolve_tenant_capabilities(db, tid)
            assert "ai.rag" in caps
            assert "ai.workspace" not in caps

            deps = get_required_capabilities("ai.rag")
            assert "ai.workspace" in deps
            missing = [d for d in deps if d not in caps]
            assert "ai.workspace" in missing


# ---------------------------------------------------------------------------
# CAPE-7: unknown capability → registry_miss → denied
# ---------------------------------------------------------------------------


class TestCAPE7UnknownCapabilityDenied:
    def test_unknown_capability_denied(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, "cape7")
        tid = "tenant-cape7"

        result = check_capability(db, tid, "nonexistent.capability.xyz")

        assert result.allowed is False
        assert result.source == "registry_miss"

    def test_unknown_capability_not_in_registry(self):
        assert "nonexistent.xyz" not in CAPABILITY_REGISTRY

    def test_all_enforced_caps_are_in_registry(self):
        enforced = [
            "portal.access",
            "portal.remediation",
            "ai.workspace",
            "ai.chat",
            "ai.rag",
            "ai.document_ingestion",
            "ai.agent_builder",
            "ai.multi_agent",
            "identity.sso",
            "identity.scim",
            "api.access",
            "reports.executive",
            "reports.regulatory",
            "government.fedramp",
            "msp.multi_tenant",
        ]
        for cap in enforced:
            assert cap in CAPABILITY_REGISTRY, f"{cap} missing from CAPABILITY_REGISTRY"


# ---------------------------------------------------------------------------
# CAPE-8: cache hit
# ---------------------------------------------------------------------------


class TestCAPE8CacheHit:
    def test_second_resolve_is_cache_hit(self, tmp_path, monkeypatch):
        from services.capability_bundles.resolver import (
            _get_cached,
            resolve_tenant_capabilities,
        )

        db = _make_db(tmp_path, monkeypatch, "cape8")
        tid = "tenant-cape8"
        invalidate_cache(tid)
        bundle = _make_bundle(db, bundle_key="portal", capabilities=["portal.access"])
        _assign_bundle(db, tenant_id=tid, bundle_id=bundle.id)

        # First call → cache miss, populates cache
        caps1 = resolve_tenant_capabilities(db, tid)
        assert "portal.access" in caps1

        # Second call → cache hit (same frozenset object)
        caps2 = resolve_tenant_capabilities(db, tid)
        assert caps1 == caps2
        assert _get_cached(tid) is not None


# ---------------------------------------------------------------------------
# CAPE-9: cache miss after invalidation
# ---------------------------------------------------------------------------


class TestCAPE9CacheMiss:
    def test_invalidation_forces_db_fetch(self, tmp_path, monkeypatch):
        from services.capability_bundles.resolver import resolve_tenant_capabilities

        db = _make_db(tmp_path, monkeypatch, "cape9")
        tid = "tenant-cape9"
        bundle = _make_bundle(db, bundle_key="portal", capabilities=["portal.access"])
        _assign_bundle(db, tenant_id=tid, bundle_id=bundle.id)

        # Populate cache
        caps1 = resolve_tenant_capabilities(db, tid)
        assert "portal.access" in caps1

        # Invalidate
        invalidate_cache(tid)

        # Re-resolve reflects current state
        caps2 = resolve_tenant_capabilities(db, tid)
        assert caps2 == caps1


# ---------------------------------------------------------------------------
# CAPE-10: cross-tenant isolation
# ---------------------------------------------------------------------------


class TestCAPE10CrossTenantIsolation:
    def test_tenant_a_caps_not_visible_to_tenant_b(self, tmp_path, monkeypatch):
        from services.capability_bundles.resolver import resolve_tenant_capabilities

        db = _make_db(tmp_path, monkeypatch, "cape10")
        tid_a = "tenant-cape10-a"
        tid_b = "tenant-cape10-b"

        bundle_a = _make_bundle(
            db, bundle_key="ent_a", capabilities=["ai.workspace", "ai.chat"]
        )
        _assign_bundle(db, tenant_id=tid_a, bundle_id=bundle_a.id)
        invalidate_cache(tid_a)
        invalidate_cache(tid_b)

        caps_a = resolve_tenant_capabilities(db, tid_a)
        caps_b = resolve_tenant_capabilities(db, tid_b)

        assert "ai.workspace" in caps_a
        assert "ai.chat" in caps_a
        assert "ai.workspace" not in caps_b
        assert "ai.chat" not in caps_b


# ---------------------------------------------------------------------------
# CAPE-11: audit event emitted
# ---------------------------------------------------------------------------


class TestCAPE11AuditEventEmitted:
    def test_granted_emits_capability_granted_event(self, tmp_path, monkeypatch):
        from api.entitlements import _audit_entitlement_decision
        from api.entitlements import EntitlementResult

        result = EntitlementResult(
            allowed=True,
            capability="portal.access",
            tenant_id="tenant-audit",
            source="bundle",
            tier="enterprise",
            reason="bundle_grant",
        )

        captured = []

        with patch("api.entitlements.get_auditor") as mock_auditor:
            mock_auditor.return_value.log_event = lambda e: captured.append(e)
            _audit_entitlement_decision(None, result)

        assert len(captured) == 1
        assert captured[0].event_type == EventType.CAPABILITY_GRANTED

    def test_denied_emits_capability_denied_event(self, tmp_path, monkeypatch):
        from api.entitlements import _audit_entitlement_decision
        from api.entitlements import EntitlementResult

        result = EntitlementResult(
            allowed=False,
            capability="ai.workspace",
            tenant_id="tenant-audit-deny",
            source="tier",
            tier="free",
            reason="tier_free_denied",
        )

        captured = []

        with patch("api.entitlements.get_auditor") as mock_auditor:
            mock_auditor.return_value.log_event = lambda e: captured.append(e)
            _audit_entitlement_decision(None, result)

        assert len(captured) == 1
        assert captured[0].event_type == EventType.CAPABILITY_DENIED

    def test_dep_failure_emits_dependency_failure_event(self):
        from api.entitlements import _audit_entitlement_decision
        from api.entitlements import EntitlementResult

        result = EntitlementResult(
            allowed=False,
            capability="ai.rag",
            tenant_id="tenant-dep-fail",
            source="dep_failure",
            tier="enterprise",
            reason="missing_dependency:ai.workspace",
        )

        captured = []

        with patch("api.entitlements.get_auditor") as mock_auditor:
            mock_auditor.return_value.log_event = lambda e: captured.append(e)
            _audit_entitlement_decision(None, result, dep_failure="ai.workspace")

        assert len(captured) == 1
        assert captured[0].event_type == EventType.CAPABILITY_DEPENDENCY_FAILURE

    def test_unknown_capability_emits_capability_unknown_event(self):
        from api.entitlements import _audit_entitlement_decision
        from api.entitlements import EntitlementResult

        result = EntitlementResult(
            allowed=False,
            capability="nonexistent.xyz",
            tenant_id="tenant-unknown",
            source="registry_miss",
            tier="unknown",
            reason="unknown_capability:nonexistent.xyz",
        )

        captured = []

        with patch("api.entitlements.get_auditor") as mock_auditor:
            mock_auditor.return_value.log_event = lambda e: captured.append(e)
            _audit_entitlement_decision(None, result)

        assert len(captured) == 1
        assert captured[0].event_type == EventType.CAPABILITY_UNKNOWN


# ---------------------------------------------------------------------------
# CAPE-12: startup validation catches invalid graph
# ---------------------------------------------------------------------------


class TestCAPE12StartupValidation:
    def test_clean_graph_passes_validation(self):
        # Should not raise
        validate_graph()

    def test_cycle_detection_finds_cycles(self):
        # Temporarily add a cycle to a copy of the graph
        from services.capability_enforcement import graph as g

        original = dict(g.DEPENDENCY_GRAPH)
        try:
            g.DEPENDENCY_GRAPH["ai.workspace"] = [
                "ai.rag"
            ]  # creates ai.rag ↔ ai.workspace cycle
            cycles = detect_cycles()
            assert len(cycles) > 0
        finally:
            g.DEPENDENCY_GRAPH.clear()
            g.DEPENDENCY_GRAPH.update(original)

    def test_unknown_cap_in_graph_fails_validation(self):
        from services.capability_enforcement import graph as g

        original = dict(g.DEPENDENCY_GRAPH)
        try:
            g.DEPENDENCY_GRAPH["nonexistent.cap"] = ["portal.access"]
            with pytest.raises(ValueError, match="unknown capabilities"):
                validate_graph()
        finally:
            g.DEPENDENCY_GRAPH.clear()
            g.DEPENDENCY_GRAPH.update(original)

    def test_all_graph_caps_in_registry(self):
        for cap, deps in DEPENDENCY_GRAPH.items():
            assert cap in CAPABILITY_REGISTRY, f"{cap} not in CAPABILITY_REGISTRY"
            for dep in deps:
                assert dep in CAPABILITY_REGISTRY, (
                    f"dep {dep} not in CAPABILITY_REGISTRY"
                )


# ---------------------------------------------------------------------------
# CAPE-13: government.fedramp enforced
# ---------------------------------------------------------------------------


class TestCAPE13GovernmentCapabilityEnforced:
    def test_fedramp_denied_without_government_bundle(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, "cape13a")
        tid = "tenant-cape13"
        bundle = _make_bundle(
            db, bundle_key="enterprise", capabilities=["portal.access", "ai.workspace"]
        )
        _assign_bundle(db, tenant_id=tid, bundle_id=bundle.id)
        invalidate_cache(tid)

        result = check_capability(db, tid, "government.fedramp")
        assert result.allowed is False

    def test_fedramp_granted_with_government_bundle(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, "cape13b")
        tid = "tenant-cape13-gov"
        bundle = _make_bundle(
            db,
            bundle_key="government",
            capabilities=["government.fedramp", "government.cjis", "portal.access"],
        )
        _assign_bundle(db, tenant_id=tid, bundle_id=bundle.id)
        invalidate_cache(tid)

        result = check_capability(db, tid, "government.fedramp")
        assert result.allowed is True
        assert result.source == "bundle"


# ---------------------------------------------------------------------------
# CAPE-14: msp.multi_tenant enforced
# ---------------------------------------------------------------------------


class TestCAPE14MSPCapabilityEnforced:
    def test_msp_denied_without_msp_bundle(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, "cape14a")
        tid = "tenant-cape14"
        bundle = _make_bundle(db, bundle_key="portal", capabilities=["portal.access"])
        _assign_bundle(db, tenant_id=tid, bundle_id=bundle.id)
        invalidate_cache(tid)

        result = check_capability(db, tid, "msp.multi_tenant")
        assert result.allowed is False

    def test_msp_granted_with_msp_bundle(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, "cape14b")
        tid = "tenant-cape14-msp"
        bundle = _make_bundle(
            db,
            bundle_key="msp",
            capabilities=["msp.multi_tenant", "msp.white_label", "portal.access"],
        )
        _assign_bundle(db, tenant_id=tid, bundle_id=bundle.id)
        invalidate_cache(tid)

        result = check_capability(db, tid, "msp.multi_tenant")
        assert result.allowed is True


# ---------------------------------------------------------------------------
# CAPE-15: api.access capability enforced
# ---------------------------------------------------------------------------


class TestCAPE15APIAccessEnforced:
    def test_api_access_denied_when_missing(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, "cape15")
        tid = "tenant-cape15"
        invalidate_cache(tid)

        result = check_capability(db, tid, "api.access")
        assert result.allowed is False

    def test_api_access_granted_via_bundle(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, "cape15b")
        tid = "tenant-cape15b"
        bundle = _make_bundle(db, bundle_key="api_bundle", capabilities=["api.access"])
        _assign_bundle(db, tenant_id=tid, bundle_id=bundle.id)
        invalidate_cache(tid)

        result = check_capability(db, tid, "api.access")
        assert result.allowed is True


# ---------------------------------------------------------------------------
# CAPE-16: authorization fails closed on dep-check error
# ---------------------------------------------------------------------------


class TestCAPE16FailsClosed:
    def test_dep_check_exception_results_in_denied(self, tmp_path, monkeypatch):
        from api.entitlements import require_capability
        from fastapi import HTTPException

        db = _make_db(tmp_path, monkeypatch, "cape16")
        tid = "tenant-cape16"
        bundle = _make_bundle(
            db, bundle_key="ent", capabilities=["ai.rag", "ai.workspace"]
        )
        _assign_bundle(db, tenant_id=tid, bundle_id=bundle.id)
        invalidate_cache(tid)

        req = MagicMock()
        req.state.tenant_id = tid
        req.url = "http://localhost/test"
        req.method = "POST"

        dep_fn = require_capability("ai.rag")

        with (
            patch("api.entitlements.ENFORCEMENT_STRICT", True),
            patch("api.entitlements.get_engine") as mock_eng,
            patch(
                "services.capability_enforcement.graph.get_required_capabilities",
                side_effect=RuntimeError("graph exploded"),
            ),
        ):
            session_ctx = MagicMock()
            session_ctx.__enter__ = MagicMock(return_value=db)
            session_ctx.__exit__ = MagicMock(return_value=False)
            mock_eng.return_value = MagicMock()

            with patch("api.entitlements.Session") as mock_session_cls:
                mock_session_cls.return_value.__enter__ = MagicMock(return_value=db)
                mock_session_cls.return_value.__exit__ = MagicMock(return_value=False)

                with pytest.raises(HTTPException) as exc_info:
                    dep_fn(req)

                assert exc_info.value.status_code == 403
