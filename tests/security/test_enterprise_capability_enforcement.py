"""P1.3D Enterprise Capability Enforcement — security test suite.

Test matrix:
  ENT-1   identity.sso granted  — GET /admin/identity/tenants/{id}/config passes
  ENT-2   identity.sso denied   — GET /admin/identity/tenants/{id}/config → 403
  ENT-3   identity.sso granted  — PUT /admin/identity/tenants/{id}/config passes
  ENT-4   identity.sso denied   — PUT /admin/identity/tenants/{id}/config → 403
  ENT-5   identity.sso granted  — GET /admin/identity/tenants/{id}/readiness passes
  ENT-6   identity.sso denied   — GET /admin/identity/tenants/{id}/readiness → 403
  ENT-7   identity.sso granted  — POST /auth/federation/validate passes capability
  ENT-8   identity.sso denied   — POST /auth/federation/validate → 403
  ENT-9   identity.scim granted — POST /workforce/users passes capability check
  ENT-10  identity.scim denied  — POST /workforce/users → 403 CAPABILITY_DENIED
  ENT-11  identity.scim granted — PATCH /workforce/users/{id} passes capability check
  ENT-12  identity.scim denied  — PATCH /workforce/users/{id} → 403 CAPABILITY_DENIED
  ENT-13  dep chain: identity.scim requires identity.sso
  ENT-14  msp.multi_tenant granted  — POST /control-plane/v2/delegation passes
  ENT-15  msp.multi_tenant denied   — POST /control-plane/v2/delegation → 403
  ENT-16  msp.multi_tenant granted  — DELETE /control-plane/v2/delegation/{id} passes
  ENT-17  msp.multi_tenant denied   — DELETE /control-plane/v2/delegation/{id} → 403
  ENT-18  msp.cross_tenant_reporting granted — GET /control-plane/v2/delegation passes
  ENT-19  msp.cross_tenant_reporting denied  — GET /control-plane/v2/delegation → 403
  ENT-20  dep chain: msp.cross_tenant_reporting requires msp.multi_tenant
  ENT-21  dep chain: msp.tenant_switching requires msp.multi_tenant
  ENT-22  government.fedramp check_capability allowed
  ENT-23  government.fedramp check_capability denied (no grant)
  ENT-24  all government capabilities registered in CAPABILITY_REGISTRY
  ENT-25  new MSP capabilities registered in CAPABILITY_REGISTRY
  ENT-26  cross-tenant isolation — tenant A msp.multi_tenant does not affect tenant B
  ENT-27  route inventory: admin_identity SSO routes carry require_capability
  ENT-28  route inventory: workforce, federation, delegation routes carry require_capability
"""

from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key
from api.db import get_sessionmaker, init_db, reset_engine_cache
from api.db_models import (
    Capability,
    PolicyBundle,
    PolicyBundleCapability,
    TenantBundleAssignment,
)
from api.entitlements import CAPABILITY_REGISTRY, check_capability
from services.capability_bundles.resolver import invalidate_cache
from services.capability_enforcement.graph import get_required_capabilities


# ---------------------------------------------------------------------------
# Shared helpers (mirrors test_commercial_capability_enforcement.py)
# ---------------------------------------------------------------------------


def _make_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str):
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


def _make_enforcing_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    tenant_id: str,
    scopes: str = "admin:read admin:write",
    capabilities: list[str] | None = None,
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

    import api.entitlements as _ent

    monkeypatch.setattr(_ent, "ENFORCEMENT_STRICT", True)

    reset_engine_cache()
    init_db(sqlite_path=db_path)

    if capabilities:
        session = get_sessionmaker(sqlite_path=db_path)()
        bundle = _make_bundle(
            session, bundle_key=f"test_{name}", capabilities=capabilities
        )
        _assign_bundle(session, tenant_id=tenant_id, bundle_id=bundle.id)
        session.close()
        invalidate_cache(tenant_id)

    from api.main import build_app

    app = build_app(auth_enabled=True)
    key = mint_key(*scopes.split(), tenant_id=tenant_id)
    return TestClient(
        app,
        headers={"X-API-Key": key, "X-Tenant-ID": tenant_id},
        raise_server_exceptions=False,
    )


def _is_capability_denied(resp) -> bool:
    try:
        body = resp.json()
        detail = body.get("detail") if isinstance(body, dict) else None
        if isinstance(detail, dict):
            return detail.get("code") == "CAPABILITY_DENIED"
        return body.get("code") == "CAPABILITY_DENIED"
    except Exception:
        return False


def _capability_denied_field(resp, field: str):
    try:
        detail = resp.json().get("detail", {})
        return detail.get(field) if isinstance(detail, dict) else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# ENT-1: identity.sso granted → GET /admin/identity/tenants/{id}/config passes
# ---------------------------------------------------------------------------


class TestENT1SsoConfigGetGranted:
    def test_identity_sso_config_get_passes(self, tmp_path, monkeypatch):
        tid = "tenant-ent1"
        client = _make_enforcing_client(
            tmp_path,
            monkeypatch,
            "ent1",
            tid,
            scopes="admin:read",
            capabilities=["identity.sso"],
        )
        resp = client.get(f"/admin/identity/tenants/{tid}/config")
        assert not _is_capability_denied(resp), (
            f"Unexpected CAPABILITY_DENIED: {resp.text}"
        )


# ---------------------------------------------------------------------------
# ENT-2: identity.sso denied → GET /admin/identity/tenants/{id}/config → 403
# ---------------------------------------------------------------------------


class TestENT2SsoConfigGetDenied:
    def test_identity_sso_config_get_denied(self, tmp_path, monkeypatch):
        tid = "tenant-ent2"
        invalidate_cache(tid)
        client = _make_enforcing_client(
            tmp_path,
            monkeypatch,
            "ent2",
            tid,
            scopes="admin:read",
            capabilities=None,
        )
        resp = client.get(f"/admin/identity/tenants/{tid}/config")
        assert resp.status_code == 403
        assert _is_capability_denied(resp), (
            f"Expected CAPABILITY_DENIED, got: {resp.text}"
        )
        assert _capability_denied_field(resp, "capability") == "identity.sso"


# ---------------------------------------------------------------------------
# ENT-3: identity.sso granted → PUT /admin/identity/tenants/{id}/config passes
# ---------------------------------------------------------------------------


class TestENT3SsoConfigPutGranted:
    def test_identity_sso_config_put_passes(self, tmp_path, monkeypatch):
        tid = "tenant-ent3"
        client = _make_enforcing_client(
            tmp_path,
            monkeypatch,
            "ent3",
            tid,
            scopes="admin:write",
            capabilities=["identity.sso"],
        )
        # Body may fail validation — capability check runs first
        resp = client.put(f"/admin/identity/tenants/{tid}/config", json={})
        assert not _is_capability_denied(resp), (
            f"Unexpected CAPABILITY_DENIED: {resp.text}"
        )


# ---------------------------------------------------------------------------
# ENT-4: identity.sso denied → PUT /admin/identity/tenants/{id}/config → 403
# ---------------------------------------------------------------------------


class TestENT4SsoConfigPutDenied:
    def test_identity_sso_config_put_denied(self, tmp_path, monkeypatch):
        tid = "tenant-ent4"
        invalidate_cache(tid)
        client = _make_enforcing_client(
            tmp_path,
            monkeypatch,
            "ent4",
            tid,
            scopes="admin:write",
            capabilities=None,
        )
        resp = client.put(f"/admin/identity/tenants/{tid}/config", json={})
        assert resp.status_code == 403
        assert _is_capability_denied(resp), (
            f"Expected CAPABILITY_DENIED, got: {resp.text}"
        )
        assert _capability_denied_field(resp, "capability") == "identity.sso"


# ---------------------------------------------------------------------------
# ENT-5: identity.sso granted → GET /admin/identity/tenants/{id}/readiness passes
# ---------------------------------------------------------------------------


class TestENT5SsoReadinessGranted:
    def test_identity_sso_readiness_passes(self, tmp_path, monkeypatch):
        tid = "tenant-ent5"
        client = _make_enforcing_client(
            tmp_path,
            monkeypatch,
            "ent5",
            tid,
            scopes="admin:read",
            capabilities=["identity.sso"],
        )
        resp = client.get(f"/admin/identity/tenants/{tid}/readiness")
        assert not _is_capability_denied(resp), (
            f"Unexpected CAPABILITY_DENIED: {resp.text}"
        )


# ---------------------------------------------------------------------------
# ENT-6: identity.sso denied → GET /admin/identity/tenants/{id}/readiness → 403
# ---------------------------------------------------------------------------


class TestENT6SsoReadinessDenied:
    def test_identity_sso_readiness_denied(self, tmp_path, monkeypatch):
        tid = "tenant-ent6"
        invalidate_cache(tid)
        client = _make_enforcing_client(
            tmp_path,
            monkeypatch,
            "ent6",
            tid,
            scopes="admin:read",
            capabilities=None,
        )
        resp = client.get(f"/admin/identity/tenants/{tid}/readiness")
        assert resp.status_code == 403
        assert _is_capability_denied(resp), (
            f"Expected CAPABILITY_DENIED, got: {resp.text}"
        )
        assert _capability_denied_field(resp, "capability") == "identity.sso"


# ---------------------------------------------------------------------------
# ENT-7: identity.sso granted → POST /auth/federation/validate passes capability
# ---------------------------------------------------------------------------


class TestENT7SsoFederationGranted:
    def test_identity_sso_federation_passes_capability(self, tmp_path, monkeypatch):
        tid = "tenant-ent7"
        client = _make_enforcing_client(
            tmp_path,
            monkeypatch,
            "ent7",
            tid,
            scopes="admin:write",
            capabilities=["identity.sso"],
        )
        # No bearer token → 401 from route logic, but NOT CAPABILITY_DENIED
        resp = client.post("/auth/federation/validate")
        assert not _is_capability_denied(resp), (
            f"Unexpected CAPABILITY_DENIED: {resp.text}"
        )
        assert resp.status_code != 403 or not _is_capability_denied(resp)


# ---------------------------------------------------------------------------
# ENT-8: identity.sso denied → POST /auth/federation/validate → 403
# ---------------------------------------------------------------------------


class TestENT8SsoFederationDenied:
    def test_identity_sso_federation_denied(self, tmp_path, monkeypatch):
        tid = "tenant-ent8"
        invalidate_cache(tid)
        client = _make_enforcing_client(
            tmp_path,
            monkeypatch,
            "ent8",
            tid,
            scopes="admin:write",
            capabilities=None,
        )
        resp = client.post("/auth/federation/validate")
        assert resp.status_code == 403
        assert _is_capability_denied(resp), (
            f"Expected CAPABILITY_DENIED, got: {resp.text}"
        )
        assert _capability_denied_field(resp, "capability") == "identity.sso"


# ---------------------------------------------------------------------------
# ENT-9: identity.scim granted → POST /workforce/users passes capability check
# ---------------------------------------------------------------------------


class TestENT9ScimUserCreateGranted:
    def test_identity_scim_user_create_passes(self, tmp_path, monkeypatch):
        tid = "tenant-ent9"
        # identity.scim depends on identity.sso; grant both
        client = _make_enforcing_client(
            tmp_path,
            monkeypatch,
            "ent9",
            tid,
            scopes="admin:write",
            capabilities=["identity.scim", "identity.sso"],
        )
        resp = client.post("/workforce/users", json={})
        assert not _is_capability_denied(resp), (
            f"Unexpected CAPABILITY_DENIED: {resp.text}"
        )


# ---------------------------------------------------------------------------
# ENT-10: identity.scim denied → POST /workforce/users → 403
# ---------------------------------------------------------------------------


class TestENT10ScimUserCreateDenied:
    def test_identity_scim_user_create_denied(self, tmp_path, monkeypatch):
        tid = "tenant-ent10"
        invalidate_cache(tid)
        client = _make_enforcing_client(
            tmp_path,
            monkeypatch,
            "ent10",
            tid,
            scopes="admin:write",
            capabilities=None,
        )
        resp = client.post("/workforce/users", json={})
        assert resp.status_code == 403
        assert _is_capability_denied(resp), (
            f"Expected CAPABILITY_DENIED, got: {resp.text}"
        )
        assert _capability_denied_field(resp, "capability") == "identity.scim"


# ---------------------------------------------------------------------------
# ENT-11: identity.scim granted → PATCH /workforce/users/{id} passes
# ---------------------------------------------------------------------------


class TestENT11ScimUserUpdateGranted:
    def test_identity_scim_user_update_passes(self, tmp_path, monkeypatch):
        tid = "tenant-ent11"
        client = _make_enforcing_client(
            tmp_path,
            monkeypatch,
            "ent11",
            tid,
            scopes="admin:write",
            capabilities=["identity.scim", "identity.sso"],
        )
        resp = client.patch("/workforce/users/some-user-id", json={})
        assert not _is_capability_denied(resp), (
            f"Unexpected CAPABILITY_DENIED: {resp.text}"
        )


# ---------------------------------------------------------------------------
# ENT-12: identity.scim denied → PATCH /workforce/users/{id} → 403
# ---------------------------------------------------------------------------


class TestENT12ScimUserUpdateDenied:
    def test_identity_scim_user_update_denied(self, tmp_path, monkeypatch):
        tid = "tenant-ent12"
        invalidate_cache(tid)
        client = _make_enforcing_client(
            tmp_path,
            monkeypatch,
            "ent12",
            tid,
            scopes="admin:write",
            capabilities=None,
        )
        resp = client.patch("/workforce/users/some-user-id", json={})
        assert resp.status_code == 403
        assert _is_capability_denied(resp), (
            f"Expected CAPABILITY_DENIED, got: {resp.text}"
        )
        assert _capability_denied_field(resp, "capability") == "identity.scim"


# ---------------------------------------------------------------------------
# ENT-13: dep chain — identity.scim requires identity.sso
# ---------------------------------------------------------------------------


class TestENT13ScimDepChain:
    def test_scim_requires_sso_in_graph(self):
        deps = get_required_capabilities("identity.scim")
        assert "identity.sso" in deps, (
            f"identity.scim should require identity.sso; got: {deps}"
        )

    def test_scim_dep_fail_when_sso_missing(self, tmp_path, monkeypatch):
        """Granting identity.scim without identity.sso must be denied via dep check."""
        from fastapi import HTTPException
        from api.entitlements import require_capability

        db = _make_db(tmp_path, monkeypatch, "ent13")
        tid = "tenant-ent13"
        # Grant only identity.scim, NOT identity.sso
        bundle = _make_bundle(
            db, bundle_key="scim_only", capabilities=["identity.scim"]
        )
        _assign_bundle(db, tenant_id=tid, bundle_id=bundle.id)
        invalidate_cache(tid)

        req = MagicMock()
        req.state.tenant_id = tid
        req.state.auth = MagicMock()
        req.state.auth.tenant_id = tid
        req.state.auth.key_name = "test"

        with patch("api.entitlements.ENFORCEMENT_STRICT", True):
            monkeypatch.setenv("FG_ENTITLEMENT_ENFORCEMENT", "true")
            dep_fn = require_capability("identity.scim")
            with pytest.raises(HTTPException) as exc_info:
                dep_fn(request=req)
        assert exc_info.value.status_code == 403
        assert exc_info.value.detail.get("code") == "CAPABILITY_DENIED"


# ---------------------------------------------------------------------------
# ENT-14: msp.multi_tenant granted → POST /control-plane/v2/delegation passes
# ---------------------------------------------------------------------------


class TestENT14MspMultiTenantDelegationCreateGranted:
    def test_msp_delegation_create_passes(self, tmp_path, monkeypatch):
        tid = "tenant-ent14"
        client = _make_enforcing_client(
            tmp_path,
            monkeypatch,
            "ent14",
            tid,
            scopes="control-plane:msp:admin",
            capabilities=["msp.multi_tenant"],
        )
        resp = client.post("/control-plane/v2/delegation", json={})
        assert not _is_capability_denied(resp), (
            f"Unexpected CAPABILITY_DENIED: {resp.text}"
        )


# ---------------------------------------------------------------------------
# ENT-15: msp.multi_tenant denied → POST /control-plane/v2/delegation → 403
# ---------------------------------------------------------------------------


class TestENT15MspMultiTenantDelegationCreateDenied:
    def test_msp_delegation_create_denied(self, tmp_path, monkeypatch):
        tid = "tenant-ent15"
        invalidate_cache(tid)
        client = _make_enforcing_client(
            tmp_path,
            monkeypatch,
            "ent15",
            tid,
            scopes="control-plane:msp:admin",
            capabilities=None,
        )
        resp = client.post("/control-plane/v2/delegation", json={})
        assert resp.status_code == 403
        assert _is_capability_denied(resp), (
            f"Expected CAPABILITY_DENIED, got: {resp.text}"
        )
        assert _capability_denied_field(resp, "capability") == "msp.multi_tenant"


# ---------------------------------------------------------------------------
# ENT-16: msp.multi_tenant granted → DELETE /control-plane/v2/delegation/{id} passes
# ---------------------------------------------------------------------------


class TestENT16MspMultiTenantDelegationRevokeGranted:
    def test_msp_delegation_revoke_passes(self, tmp_path, monkeypatch):
        tid = "tenant-ent16"
        client = _make_enforcing_client(
            tmp_path,
            monkeypatch,
            "ent16",
            tid,
            scopes="control-plane:msp:admin",
            capabilities=["msp.multi_tenant"],
        )
        resp = client.delete("/control-plane/v2/delegation/fake-delegation-id")
        assert not _is_capability_denied(resp), (
            f"Unexpected CAPABILITY_DENIED: {resp.text}"
        )


# ---------------------------------------------------------------------------
# ENT-17: msp.multi_tenant denied → DELETE /control-plane/v2/delegation/{id} → 403
# ---------------------------------------------------------------------------


class TestENT17MspMultiTenantDelegationRevokeDenied:
    def test_msp_delegation_revoke_denied(self, tmp_path, monkeypatch):
        tid = "tenant-ent17"
        invalidate_cache(tid)
        client = _make_enforcing_client(
            tmp_path,
            monkeypatch,
            "ent17",
            tid,
            scopes="control-plane:msp:admin",
            capabilities=None,
        )
        resp = client.delete("/control-plane/v2/delegation/fake-delegation-id")
        assert resp.status_code == 403
        assert _is_capability_denied(resp), (
            f"Expected CAPABILITY_DENIED, got: {resp.text}"
        )
        assert _capability_denied_field(resp, "capability") == "msp.multi_tenant"


# ---------------------------------------------------------------------------
# ENT-18: msp.cross_tenant_reporting granted → GET /control-plane/v2/delegation passes
# ---------------------------------------------------------------------------


class TestENT18MspCrossTenantReportingGranted:
    def test_msp_delegation_list_passes(self, tmp_path, monkeypatch):
        tid = "tenant-ent18"
        # msp.cross_tenant_reporting depends on msp.multi_tenant; grant both
        client = _make_enforcing_client(
            tmp_path,
            monkeypatch,
            "ent18",
            tid,
            scopes="control-plane:msp:read",
            capabilities=["msp.cross_tenant_reporting", "msp.multi_tenant"],
        )
        resp = client.get("/control-plane/v2/delegation")
        assert not _is_capability_denied(resp), (
            f"Unexpected CAPABILITY_DENIED: {resp.text}"
        )


# ---------------------------------------------------------------------------
# ENT-19: msp.cross_tenant_reporting denied → GET /control-plane/v2/delegation → 403
# ---------------------------------------------------------------------------


class TestENT19MspCrossTenantReportingDenied:
    def test_msp_delegation_list_denied(self, tmp_path, monkeypatch):
        tid = "tenant-ent19"
        invalidate_cache(tid)
        client = _make_enforcing_client(
            tmp_path,
            monkeypatch,
            "ent19",
            tid,
            scopes="control-plane:msp:read",
            capabilities=None,
        )
        resp = client.get("/control-plane/v2/delegation")
        assert resp.status_code == 403
        assert _is_capability_denied(resp), (
            f"Expected CAPABILITY_DENIED, got: {resp.text}"
        )
        assert (
            _capability_denied_field(resp, "capability") == "msp.cross_tenant_reporting"
        )


# ---------------------------------------------------------------------------
# ENT-20: dep chain — msp.cross_tenant_reporting requires msp.multi_tenant
# ---------------------------------------------------------------------------


class TestENT20MspCrossReportingDepChain:
    def test_cross_reporting_requires_multi_tenant_in_graph(self):
        deps = get_required_capabilities("msp.cross_tenant_reporting")
        assert "msp.multi_tenant" in deps, (
            f"msp.cross_tenant_reporting should require msp.multi_tenant; got: {deps}"
        )

    def test_cross_reporting_dep_fail_when_multi_tenant_missing(
        self, tmp_path, monkeypatch
    ):
        from fastapi import HTTPException
        from api.entitlements import require_capability

        db = _make_db(tmp_path, monkeypatch, "ent20")
        tid = "tenant-ent20"
        # Grant only msp.cross_tenant_reporting, NOT msp.multi_tenant
        bundle = _make_bundle(
            db,
            bundle_key="cross_only",
            capabilities=["msp.cross_tenant_reporting"],
        )
        _assign_bundle(db, tenant_id=tid, bundle_id=bundle.id)
        invalidate_cache(tid)

        req = MagicMock()
        req.state.tenant_id = tid
        req.state.auth = MagicMock()
        req.state.auth.tenant_id = tid
        req.state.auth.key_name = "test"

        with patch("api.entitlements.ENFORCEMENT_STRICT", True):
            monkeypatch.setenv("FG_ENTITLEMENT_ENFORCEMENT", "true")
            dep_fn = require_capability("msp.cross_tenant_reporting")
            with pytest.raises(HTTPException) as exc_info:
                dep_fn(request=req)
        assert exc_info.value.status_code == 403
        assert exc_info.value.detail.get("code") == "CAPABILITY_DENIED"


# ---------------------------------------------------------------------------
# ENT-21: dep chain — msp.tenant_switching requires msp.multi_tenant
# ---------------------------------------------------------------------------


class TestENT21MspTenantSwitchingDepChain:
    def test_tenant_switching_requires_multi_tenant_in_graph(self):
        deps = get_required_capabilities("msp.tenant_switching")
        assert "msp.multi_tenant" in deps, (
            f"msp.tenant_switching should require msp.multi_tenant; got: {deps}"
        )

    def test_tenant_switching_dep_fail_when_multi_tenant_missing(
        self, tmp_path, monkeypatch
    ):
        from fastapi import HTTPException
        from api.entitlements import require_capability

        db = _make_db(tmp_path, monkeypatch, "ent21")
        tid = "tenant-ent21"
        bundle = _make_bundle(
            db,
            bundle_key="switching_only",
            capabilities=["msp.tenant_switching"],
        )
        _assign_bundle(db, tenant_id=tid, bundle_id=bundle.id)
        invalidate_cache(tid)

        req = MagicMock()
        req.state.tenant_id = tid
        req.state.auth = MagicMock()
        req.state.auth.tenant_id = tid
        req.state.auth.key_name = "test"

        with patch("api.entitlements.ENFORCEMENT_STRICT", True):
            monkeypatch.setenv("FG_ENTITLEMENT_ENFORCEMENT", "true")
            dep_fn = require_capability("msp.tenant_switching")
            with pytest.raises(HTTPException) as exc_info:
                dep_fn(request=req)
        assert exc_info.value.status_code == 403
        assert exc_info.value.detail.get("code") == "CAPABILITY_DENIED"


# ---------------------------------------------------------------------------
# ENT-22: government.fedramp check_capability allowed
# ---------------------------------------------------------------------------


class TestENT22GovernmentFedrampAllowed:
    def test_fedramp_check_allowed(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, "ent22")
        tid = "tenant-ent22"
        bundle = _make_bundle(
            db, bundle_key="fedramp_bundle", capabilities=["government.fedramp"]
        )
        _assign_bundle(db, tenant_id=tid, bundle_id=bundle.id)
        invalidate_cache(tid)

        result = check_capability(db, tid, "government.fedramp")
        assert result.allowed is True


# ---------------------------------------------------------------------------
# ENT-23: government.fedramp check_capability denied (no grant)
# ---------------------------------------------------------------------------


class TestENT23GovernmentFedrampDenied:
    def test_fedramp_check_denied_no_grant(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path, monkeypatch, "ent23")
        tid = "tenant-ent23"
        invalidate_cache(tid)

        result = check_capability(db, tid, "government.fedramp")
        assert result.allowed is False


# ---------------------------------------------------------------------------
# ENT-24: all government capabilities registered in CAPABILITY_REGISTRY
# ---------------------------------------------------------------------------


class TestENT24GovernmentCapabilitiesRegistered:
    @pytest.mark.parametrize(
        "cap",
        [
            "government.fedramp",
            "government.cjis",
            "government.itar",
            "government.airgap",
            "government.private_llm",
        ],
    )
    def test_government_capability_in_registry(self, cap):
        assert cap in CAPABILITY_REGISTRY, f"{cap} missing from CAPABILITY_REGISTRY"


# ---------------------------------------------------------------------------
# ENT-25: new MSP capabilities registered in CAPABILITY_REGISTRY
# ---------------------------------------------------------------------------


class TestENT25NewMspCapabilitiesRegistered:
    def test_msp_cross_tenant_reporting_registered(self):
        assert "msp.cross_tenant_reporting" in CAPABILITY_REGISTRY

    def test_msp_tenant_switching_registered(self):
        assert "msp.tenant_switching" in CAPABILITY_REGISTRY

    def test_msp_multi_tenant_registered(self):
        assert "msp.multi_tenant" in CAPABILITY_REGISTRY


# ---------------------------------------------------------------------------
# ENT-26: cross-tenant isolation — tenant A msp.multi_tenant does not affect B
# ---------------------------------------------------------------------------


class TestENT26CrossTenantIsolationMsp:
    def test_msp_grant_does_not_bleed_across_tenants(self, tmp_path, monkeypatch):
        tid_a = "tenant-ent26a"
        tid_b = "tenant-ent26b"
        invalidate_cache(tid_a)
        invalidate_cache(tid_b)

        client_b = _make_enforcing_client(
            tmp_path,
            monkeypatch,
            "ent26b",
            tid_b,
            scopes="control-plane:msp:admin",
            capabilities=None,
        )

        # Grant msp.multi_tenant to tenant A only
        db = get_sessionmaker()()
        bundle = _make_bundle(
            db, bundle_key="msp_a_only", capabilities=["msp.multi_tenant"]
        )
        _assign_bundle(db, tenant_id=tid_a, bundle_id=bundle.id)
        db.close()
        invalidate_cache(tid_a)
        invalidate_cache(tid_b)

        resp = client_b.post("/control-plane/v2/delegation", json={})
        assert resp.status_code == 403
        assert _is_capability_denied(resp), (
            f"Tenant B should be denied, got: {resp.text}"
        )


# ---------------------------------------------------------------------------
# ENT-27: route inventory — admin_identity SSO routes carry require_capability
# ---------------------------------------------------------------------------


class TestENT27RouteInventoryIdentity:
    def _route_dep_names(self, routes, path_fragment: str, method: str) -> list[str]:
        for route in routes:
            route_path = getattr(route, "path", "")
            route_methods: set[str] = getattr(route, "methods", set()) or set()
            if path_fragment not in route_path:
                continue
            if method.upper() not in route_methods:
                continue
            deps = getattr(route, "dependencies", []) or []
            return [
                getattr(getattr(d, "dependency", None), "__name__", "") for d in deps
            ]
        return []

    def test_get_identity_config_has_capability_dep(self):
        from api.admin_identity import router

        dep_names = self._route_dep_names(
            router.routes, "/tenants/{tenant_id}/config", "GET"
        )
        assert "_dep" in dep_names, (
            f"GET /admin/identity/tenants/{{id}}/config missing require_capability; deps: {dep_names}"
        )

    def test_put_identity_config_has_capability_dep(self):
        from api.admin_identity import router

        dep_names = self._route_dep_names(
            router.routes, "/tenants/{tenant_id}/config", "PUT"
        )
        assert "_dep" in dep_names, (
            f"PUT /admin/identity/tenants/{{id}}/config missing require_capability; deps: {dep_names}"
        )

    def test_get_identity_readiness_has_capability_dep(self):
        from api.admin_identity import router

        dep_names = self._route_dep_names(
            router.routes, "/tenants/{tenant_id}/readiness", "GET"
        )
        assert "_dep" in dep_names, (
            f"GET /admin/identity/tenants/{{id}}/readiness missing require_capability; deps: {dep_names}"
        )

    def test_auth_federation_has_capability_dep(self):
        from api.auth_federation import router

        dep_names = self._route_dep_names(
            router.routes, "/auth/federation/validate", "POST"
        )
        assert "_dep" in dep_names, (
            f"POST /auth/federation/validate missing require_capability; deps: {dep_names}"
        )


# ---------------------------------------------------------------------------
# ENT-28: route inventory — workforce + delegation routes carry require_capability
# ---------------------------------------------------------------------------


class TestENT28RouteInventoryMspWorkforce:
    def _route_dep_names(self, routes, path_fragment: str, method: str) -> list[str]:
        for route in routes:
            route_path = getattr(route, "path", "")
            route_methods: set[str] = getattr(route, "methods", set()) or set()
            if path_fragment not in route_path:
                continue
            if method.upper() not in route_methods:
                continue
            deps = getattr(route, "dependencies", []) or []
            return [
                getattr(getattr(d, "dependency", None), "__name__", "") for d in deps
            ]
        return []

    def test_workforce_users_post_has_capability_dep(self):
        from api.workforce import router

        dep_names = self._route_dep_names(router.routes, "/users", "POST")
        assert "_dep" in dep_names, (
            f"POST /workforce/users missing require_capability; deps: {dep_names}"
        )

    def test_workforce_users_patch_has_capability_dep(self):
        from api.workforce import router

        dep_names = self._route_dep_names(router.routes, "/users/{user_id}", "PATCH")
        assert "_dep" in dep_names, (
            f"PATCH /workforce/users/{{id}} missing require_capability; deps: {dep_names}"
        )

    def test_delegation_post_has_capability_dep(self):
        from api.control_plane_v2 import router

        dep_names = self._route_dep_names(
            router.routes, "/control-plane/v2/delegation", "POST"
        )
        assert "_dep" in dep_names, (
            f"POST /control-plane/v2/delegation missing require_capability; deps: {dep_names}"
        )

    def test_delegation_delete_has_capability_dep(self):
        from api.control_plane_v2 import router

        dep_names = self._route_dep_names(
            router.routes, "/control-plane/v2/delegation/{delegation_id}", "DELETE"
        )
        assert "_dep" in dep_names, (
            f"DELETE /control-plane/v2/delegation/{{id}} missing require_capability; deps: {dep_names}"
        )

    def test_delegation_get_has_capability_dep(self):
        from api.control_plane_v2 import router

        dep_names = self._route_dep_names(
            router.routes, "/control-plane/v2/delegation", "GET"
        )
        assert "_dep" in dep_names, (
            f"GET /control-plane/v2/delegation missing require_capability; deps: {dep_names}"
        )
