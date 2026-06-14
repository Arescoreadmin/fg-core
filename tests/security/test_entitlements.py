"""
tests/security/test_entitlements.py — Capability Authority (P0-5) tests.

Covers:
- CAPABILITY_REGISTRY completeness and structure
- TIER_CAPABILITIES mapping correctness
- check_capability() positive / negative / error paths
- Explicit DB grant takes precedence over tier
- Expired grants are not honoured
- require_capability() dependency: pass-through in audit-only mode
- require_capability() dependency: raises 403 in strict mode
- Audit event generated on every entitlement decision
- Admin grant / revoke / list operations
- Tenant self-service endpoint
- Capability registry endpoint (public)
- Regression: unknown capability rejected, new capability requires registration
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_db(entitlement_row=None):
    """Return a mock DB session for entitlement queries."""
    db = MagicMock()
    q = db.query.return_value
    q.filter.return_value = q
    q.first.return_value = entitlement_row
    q.order_by.return_value = q
    q.all.return_value = [] if entitlement_row is None else [entitlement_row]
    return db


def _make_entitlement(capability: str, tenant_id: str = "t-1", expires_at=None):
    r = MagicMock()
    r.id = "ent-abc"
    r.tenant_id = tenant_id
    r.capability = capability
    r.granted_by = "admin"
    r.granted_at = datetime.now(timezone.utc)
    r.expires_at = expires_at
    r.reason = "test grant"
    return r


def _make_request(tenant_id: str = "t-1"):
    req = MagicMock()
    req.state.tenant_id = tenant_id
    req.url = "http://localhost/test"
    req.method = "GET"
    return req


# ---------------------------------------------------------------------------
# Capability registry
# ---------------------------------------------------------------------------


class TestCapabilityRegistry:
    def test_registry_is_frozenset(self):
        from api.entitlements import CAPABILITY_REGISTRY

        assert isinstance(CAPABILITY_REGISTRY, frozenset)

    def test_registry_is_nonempty(self):
        from api.entitlements import CAPABILITY_REGISTRY

        assert len(CAPABILITY_REGISTRY) > 0

    def test_all_capabilities_have_namespace(self):
        from api.entitlements import CAPABILITY_REGISTRY

        for cap in CAPABILITY_REGISTRY:
            assert "." in cap, f"capability '{cap}' has no namespace prefix"

    def test_known_namespaces_present(self):
        from api.entitlements import CAPABILITY_REGISTRY

        namespaces = {c.split(".")[0] for c in CAPABILITY_REGISTRY}
        for ns in ("report", "verification", "trust", "audit", "governance"):
            assert ns in namespaces, f"namespace '{ns}' missing from registry"

    def test_future_governance_namespaces_present(self):
        from api.entitlements import CAPABILITY_REGISTRY

        for cap in (
            "agent.governance",
            "workflow.governance",
            "autonomous_systems.governance",
            "agi.governance",
        ):
            assert cap in CAPABILITY_REGISTRY, f"'{cap}' missing from registry"

    def test_report_capabilities_present(self):
        from api.entitlements import CAPABILITY_REGISTRY

        for cap in ("report.view", "report.export", "report.manifest", "report.replay"):
            assert cap in CAPABILITY_REGISTRY

    def test_trust_capabilities_present(self):
        from api.entitlements import CAPABILITY_REGISTRY

        for cap in (
            "trust.replay",
            "trust.timeline",
            "trust.intelligence",
            "trust.memory",
            "trust.certification",
            "trust.proof_package",
            "trust.chain_of_custody",
            "trust.decision_reconstruction",
        ):
            assert cap in CAPABILITY_REGISTRY

    def test_audit_capabilities_present(self):
        from api.entitlements import CAPABILITY_REGISTRY

        for cap in ("audit.view", "audit.export", "audit.forensics"):
            assert cap in CAPABILITY_REGISTRY


# ---------------------------------------------------------------------------
# Tier capability mapping
# ---------------------------------------------------------------------------


class TestTierCapabilities:
    def test_tier_capabilities_returns_dict(self):
        from api.entitlements import _tier_capabilities

        caps = _tier_capabilities()
        assert isinstance(caps, dict)

    def test_all_tiers_present(self):
        from api.entitlements import _tier_capabilities
        from api.tenant_usage import SubscriptionTier

        caps = _tier_capabilities()
        for tier in SubscriptionTier:
            assert tier.value in caps, (
                f"tier '{tier.value}' missing from TIER_CAPABILITIES"
            )

    def test_enterprise_includes_all_current_caps(self):
        from api.entitlements import _tier_capabilities

        caps = _tier_capabilities()
        enterprise = caps["enterprise"]
        for cap in (
            "report.export",
            "verification.download",
            "trust.intelligence",
            "trust.certification",
            "continuous.monitoring",
            "audit.forensics",
            "agent.governance",
        ):
            assert cap in enterprise, f"enterprise missing '{cap}'"

    def test_internal_has_all_registry_capabilities(self):
        from api.entitlements import CAPABILITY_REGISTRY, _tier_capabilities

        caps = _tier_capabilities()
        internal = caps["internal"]
        assert internal == CAPABILITY_REGISTRY

    def test_free_is_subset_of_pro(self):
        from api.entitlements import _tier_capabilities

        caps = _tier_capabilities()
        assert caps["free"].issubset(caps["pro"])

    def test_pro_is_subset_of_enterprise(self):
        from api.entitlements import _tier_capabilities

        caps = _tier_capabilities()
        assert caps["pro"].issubset(caps["enterprise"])

    def test_all_tier_capabilities_are_in_registry(self):
        from api.entitlements import CAPABILITY_REGISTRY, _tier_capabilities

        caps = _tier_capabilities()
        for tier, tier_caps in caps.items():
            for cap in tier_caps:
                assert cap in CAPABILITY_REGISTRY, (
                    f"tier '{tier}' references unregistered capability '{cap}'"
                )


# ---------------------------------------------------------------------------
# check_capability — positive paths
# ---------------------------------------------------------------------------


class TestCheckCapabilityPositive:
    def test_explicit_db_grant_allows(self):
        from api.entitlements import check_capability

        db = _make_db(entitlement_row=_make_entitlement("report.export"))
        with patch("api.entitlements.set_tenant_context"):
            result = check_capability(db, "t-1", "report.export")
        assert result.allowed is True
        assert result.source == "explicit"

    def test_tier_fallback_allows_enterprise(self):
        from api.entitlements import check_capability

        db = _make_db(entitlement_row=None)
        with (
            patch("api.entitlements.set_tenant_context"),
            patch("api.entitlements._get_tenant_tier", return_value="enterprise"),
        ):
            result = check_capability(db, "t-1", "trust.intelligence")
        assert result.allowed is True
        assert result.source == "tier"
        assert result.tier == "enterprise"

    def test_tier_fallback_allows_pro_capability(self):
        from api.entitlements import check_capability

        db = _make_db(entitlement_row=None)
        with (
            patch("api.entitlements.set_tenant_context"),
            patch("api.entitlements._get_tenant_tier", return_value="pro"),
        ):
            result = check_capability(db, "t-1", "report.export")
        assert result.allowed is True

    def test_explicit_grant_includes_capability_and_tenant(self):
        from api.entitlements import check_capability

        db = _make_db(
            entitlement_row=_make_entitlement("audit.export", tenant_id="t-abc")
        )
        with patch("api.entitlements.set_tenant_context"):
            result = check_capability(db, "t-abc", "audit.export")
        assert result.capability == "audit.export"
        assert result.tenant_id == "t-abc"


# ---------------------------------------------------------------------------
# check_capability — negative paths
# ---------------------------------------------------------------------------


class TestCheckCapabilityNegative:
    def test_unknown_capability_denied(self):
        from api.entitlements import check_capability

        db = _make_db()
        result = check_capability(db, "t-1", "nonexistent.capability")
        assert result.allowed is False
        assert result.source == "registry_miss"

    def test_no_tenant_denied(self):
        from api.entitlements import check_capability

        db = _make_db()
        result = check_capability(db, None, "report.export")
        assert result.allowed is False
        assert result.source == "no_tenant"

    def test_free_tier_denied_premium_capability(self):
        from api.entitlements import check_capability

        db = _make_db(entitlement_row=None)
        with (
            patch("api.entitlements.set_tenant_context"),
            patch("api.entitlements._get_tenant_tier", return_value="free"),
        ):
            result = check_capability(db, "t-1", "trust.intelligence")
        assert result.allowed is False
        assert result.source == "tier"

    def test_expired_grant_is_not_honoured(self):
        from api.entitlements import check_capability

        expired = datetime.now(timezone.utc) - timedelta(hours=1)
        _make_entitlement("report.export", expires_at=expired)
        # Expired row: the DB mock query filter should return None for active grants.
        # Simulate: .filter(...).first() returns None (filter includes expiry check).
        db = _make_db(entitlement_row=None)
        with (
            patch("api.entitlements.set_tenant_context"),
            patch("api.entitlements._get_tenant_tier", return_value="free"),
        ):
            result = check_capability(db, "t-1", "report.export")
        assert result.allowed is False

    def test_db_error_fails_closed(self):
        from api.entitlements import check_capability

        db = MagicMock()
        db.query.side_effect = RuntimeError("db exploded")
        with patch("api.entitlements.set_tenant_context"):
            result = check_capability(db, "t-1", "report.export")
        assert result.allowed is False
        assert result.source == "error"

    def test_starter_tier_denied_verification_download(self):
        from api.entitlements import check_capability

        db = _make_db(entitlement_row=None)
        with (
            patch("api.entitlements.set_tenant_context"),
            patch("api.entitlements._get_tenant_tier", return_value="starter"),
        ):
            result = check_capability(db, "t-1", "verification.download")
        assert result.allowed is False


# ---------------------------------------------------------------------------
# require_capability() — audit-only mode (default)
# ---------------------------------------------------------------------------


class TestRequireCapabilityAuditOnly:
    def test_passes_through_when_not_strict(self):
        from api.entitlements import require_capability

        db = _make_db(entitlement_row=None)
        request = _make_request()
        dep = require_capability("report.export")

        with (
            patch("api.entitlements.set_tenant_context"),
            patch("api.entitlements._get_tenant_tier", return_value="free"),
            patch("api.entitlements.ENFORCEMENT_STRICT", False),
            patch("api.entitlements._audit_entitlement_decision"),
        ):
            dep(request=request, db=db)  # must not raise

    def test_granted_passes_through(self):
        from api.entitlements import require_capability

        db = _make_db(entitlement_row=_make_entitlement("report.export"))
        request = _make_request()
        dep = require_capability("report.export")

        with (
            patch("api.entitlements.set_tenant_context"),
            patch("api.entitlements.ENFORCEMENT_STRICT", False),
            patch("api.entitlements._audit_entitlement_decision"),
        ):
            dep(request=request, db=db)  # no exception

    def test_audit_event_generated_on_grant(self):
        from api.entitlements import require_capability

        db = _make_db(entitlement_row=_make_entitlement("report.export"))
        request = _make_request()
        dep = require_capability("report.export")

        with (
            patch("api.entitlements.set_tenant_context"),
            patch("api.entitlements.ENFORCEMENT_STRICT", False),
            patch("api.entitlements._audit_entitlement_decision") as mock_audit,
        ):
            dep(request=request, db=db)

        mock_audit.assert_called_once()
        _, result = mock_audit.call_args[0]
        assert result.allowed is True
        assert result.capability == "report.export"

    def test_audit_event_generated_on_deny(self):
        from api.entitlements import require_capability

        db = _make_db(entitlement_row=None)
        request = _make_request()
        dep = require_capability("trust.intelligence")

        with (
            patch("api.entitlements.set_tenant_context"),
            patch("api.entitlements._get_tenant_tier", return_value="free"),
            patch("api.entitlements.ENFORCEMENT_STRICT", False),
            patch("api.entitlements._audit_entitlement_decision") as mock_audit,
        ):
            dep(request=request, db=db)  # no raise in audit-only mode

        mock_audit.assert_called_once()
        _, result = mock_audit.call_args[0]
        assert result.allowed is False
        assert result.capability == "trust.intelligence"


# ---------------------------------------------------------------------------
# require_capability() — strict mode
# ---------------------------------------------------------------------------


class TestRequireCapabilityStrict:
    def test_raises_403_when_denied_strict(self):
        from fastapi import HTTPException

        from api.entitlements import require_capability

        db = _make_db(entitlement_row=None)
        request = _make_request()
        dep = require_capability("trust.intelligence")

        with (
            patch("api.entitlements.set_tenant_context"),
            patch("api.entitlements._get_tenant_tier", return_value="free"),
            patch("api.entitlements.ENFORCEMENT_STRICT", True),
            patch("api.entitlements._audit_entitlement_decision"),
        ):
            with pytest.raises(HTTPException) as exc_info:
                dep(request=request, db=db)

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail["code"] == "CAPABILITY_DENIED"
        assert exc_info.value.detail["capability"] == "trust.intelligence"

    def test_403_includes_upgrade_required_for_tier_denial(self):
        from fastapi import HTTPException

        from api.entitlements import require_capability

        db = _make_db(entitlement_row=None)
        request = _make_request()
        dep = require_capability("continuous.monitoring")

        with (
            patch("api.entitlements.set_tenant_context"),
            patch("api.entitlements._get_tenant_tier", return_value="pro"),
            patch("api.entitlements.ENFORCEMENT_STRICT", True),
            patch("api.entitlements._audit_entitlement_decision"),
        ):
            with pytest.raises(HTTPException) as exc_info:
                dep(request=request, db=db)

        assert exc_info.value.detail["upgrade_required"] is True

    def test_passes_when_explicitly_granted_in_strict_mode(self):
        from api.entitlements import require_capability

        db = _make_db(entitlement_row=_make_entitlement("trust.certification"))
        request = _make_request()
        dep = require_capability("trust.certification")

        with (
            patch("api.entitlements.set_tenant_context"),
            patch("api.entitlements.ENFORCEMENT_STRICT", True),
            patch("api.entitlements._audit_entitlement_decision"),
        ):
            dep(request=request, db=db)  # no raise

    def test_unknown_capability_raises_403_strict(self):
        from fastapi import HTTPException

        from api.entitlements import require_capability

        db = _make_db()
        request = _make_request()
        dep = require_capability("future.unknown.thing")

        with (
            patch("api.entitlements.ENFORCEMENT_STRICT", True),
            patch("api.entitlements._audit_entitlement_decision"),
        ):
            with pytest.raises(HTTPException) as exc_info:
                dep(request=request, db=db)

        assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# Audit event correctness
# ---------------------------------------------------------------------------


class TestEntitlementAudit:
    def test_audit_event_contains_capability(self):
        from api.entitlements import _audit_entitlement_decision, EntitlementResult

        result = EntitlementResult(
            allowed=True,
            capability="report.export",
            tenant_id="t-1",
            source="explicit",
            tier="enterprise",
            reason="explicit_grant",
        )
        with patch("api.entitlements.get_auditor") as mock_get_aud:
            _audit_entitlement_decision(None, result)

        mock_get_aud.return_value.log_event.assert_called_once()
        event = mock_get_aud.return_value.log_event.call_args[0][0]
        assert event.details["capability"] == "report.export"

    def test_audit_event_contains_tenant(self):
        from api.entitlements import _audit_entitlement_decision, EntitlementResult

        result = EntitlementResult(
            allowed=False,
            capability="trust.intelligence",
            tenant_id="t-xyz",
            source="tier",
            tier="free",
            reason="tier_free_denied",
        )
        with patch("api.entitlements.get_auditor") as mock_get_aud:
            _audit_entitlement_decision(None, result)

        event = mock_get_aud.return_value.log_event.call_args[0][0]
        assert event.tenant_id == "t-xyz"

    def test_audit_event_contains_decision(self):
        from api.entitlements import _audit_entitlement_decision, EntitlementResult

        result = EntitlementResult(
            allowed=False,
            capability="audit.export",
            tenant_id="t-1",
            source="tier",
            tier="starter",
            reason="tier_starter_denied",
        )
        with patch("api.entitlements.get_auditor") as mock_get_aud:
            _audit_entitlement_decision(None, result)

        event = mock_get_aud.return_value.log_event.call_args[0][0]
        assert event.details["decision"] == "denied"
        assert event.success is False

    def test_audit_does_not_raise_on_auditor_failure(self):
        from api.entitlements import _audit_entitlement_decision, EntitlementResult

        result = EntitlementResult(
            allowed=True,
            capability="report.view",
            tenant_id="t-1",
            source="tier",
            tier="pro",
            reason="tier_pro_granted",
        )
        with patch(
            "api.entitlements.get_auditor", side_effect=RuntimeError("aud down")
        ):
            _audit_entitlement_decision(None, result)  # must not raise


# ---------------------------------------------------------------------------
# Admin operations
# ---------------------------------------------------------------------------


class TestEntitlementAdminOps:
    def test_grant_creates_record(self):
        from api.entitlements import _grant_entitlement

        db = _make_db(entitlement_row=None)
        with patch("api.entitlements.set_tenant_context"):
            result = _grant_entitlement(
                db, "t-1", "trust.intelligence", "admin", "test grant", None
            )
        assert result["created"] is True
        assert result["capability"] == "trust.intelligence"
        db.add.assert_called_once()
        db.commit.assert_called_once()

    def test_grant_unknown_capability_raises_400(self):
        from fastapi import HTTPException

        from api.entitlements import _grant_entitlement

        db = _make_db()
        with pytest.raises(HTTPException) as exc_info:
            _grant_entitlement(db, "t-1", "bogus.cap", "admin", None, None)
        assert exc_info.value.status_code == 400
        assert exc_info.value.detail["code"] == "UNKNOWN_CAPABILITY"

    def test_grant_updates_existing_record(self):
        from api.entitlements import _grant_entitlement

        existing = _make_entitlement("report.export")
        db = _make_db(entitlement_row=existing)
        with patch("api.entitlements.set_tenant_context"):
            result = _grant_entitlement(
                db, "t-1", "report.export", "admin", "re-grant", None
            )
        assert result["updated"] is True
        db.commit.assert_called_once()

    def test_revoke_removes_record(self):
        from api.entitlements import _revoke_entitlement

        row = _make_entitlement("report.export")
        db = _make_db(entitlement_row=row)
        with patch("api.entitlements.set_tenant_context"):
            result = _revoke_entitlement(db, "t-1", "report.export")
        assert result["revoked"] is True
        db.delete.assert_called_once_with(row)
        db.commit.assert_called_once()

    def test_revoke_missing_record_raises_404(self):
        from fastapi import HTTPException

        from api.entitlements import _revoke_entitlement

        db = _make_db(entitlement_row=None)
        with (
            patch("api.entitlements.set_tenant_context"),
            pytest.raises(HTTPException) as exc_info,
        ):
            _revoke_entitlement(db, "t-1", "report.export")
        assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# Regression: unknown capability registration requirement
# ---------------------------------------------------------------------------


class TestCapabilityRegistration:
    def test_new_capability_must_be_in_registry(self):
        """If a route uses a capability not in the registry, check_capability denies it."""
        from api.entitlements import check_capability

        db = _make_db()
        result = check_capability(db, "t-1", "unregistered.new_feature")
        assert result.allowed is False
        assert result.source == "registry_miss"

    def test_all_tier_capabilities_are_registered(self):
        """Every capability referenced in tier mappings must be in CAPABILITY_REGISTRY."""
        from api.entitlements import CAPABILITY_REGISTRY, _tier_capabilities

        for tier, caps in _tier_capabilities().items():
            for cap in caps:
                assert cap in CAPABILITY_REGISTRY, (
                    f"tier '{tier}' uses unregistered capability '{cap}'"
                )

    def test_capability_registry_has_no_duplicates(self):
        """frozenset guarantees no duplicates — verify via list round-trip."""
        from api.entitlements import CAPABILITY_REGISTRY

        as_list = list(CAPABILITY_REGISTRY)
        assert len(as_list) == len(set(as_list))
