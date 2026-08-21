"""PR-CORE-002C regression suite — capability-before-tenant-binding hazard.

Background
==========

PR-CORE-002 added delegation proof + tenant lifecycle verification to
bind_tenant_id() for admin_internal_token requests. PR-CORE-002B removed the
middleware pre-binding of tenant_id for admin_internal_token. Both changes were
correct and must not be weakened.

The residual hazard closed here (PR-CORE-002C):

    require_capability() runs as a FastAPI Depends() in the router's
    ``dependencies=[...]`` list. That list fires BEFORE the route function body,
    where bind_tenant_id() is invoked. Post-002B, request.state.tenant_id was
    empty by the time capability enforcement ran, so admin-gateway routes
    protected by require_capability denied every request with
    ``CAPABILITY_DENIED / reason=no_tenant_context``.

The fix (PR-CORE-002C)
======================

require_capability() now calls a shared verified-tenant helper at the top of
its inner dependency for admin_internal_token requests. The helper invokes
bind_tenant_id() with the X-Tenant-ID header, which runs:

  1. delegation proof verification (_verify_delegation_proof)
  2. tenant existence + active-lifecycle verification (_verify_admin_gateway_tenant)

...before capability enforcement is allowed to consult the tenant. The authority
order becomes:

    authenticate gateway
      -> verify delegation proof
      -> verify requested tenant exists + active
      -> establish authoritative tenant context (bind_tenant_id completes)
      -> capability / entitlement enforcement
      -> route business logic

A second layer (bind_tenant_id itself) prevents the defense-in-depth guard from
double-verifying when the route body later re-invokes bind_tenant_id via
tenant_db_required — the request-scoped ``_admin_gateway_delegation_verified``
flag is honored only after delegation proof has actually run in this request.

Tests below are source-only invariants (verify the fix is present, correctly
ordered, and cannot be silently regressed) plus behavioral mirrors of the
capability-before-bind ordering.
"""

from __future__ import annotations

from pathlib import Path

from tests.admin_gateway_delegation import configure_delegation_env, delegation_headers

_ENTITLEMENTS_SRC = Path("api/entitlements.py").read_text(encoding="utf-8")
_RESOLUTION_SRC = Path("api/auth_scopes/resolution.py").read_text(encoding="utf-8")


# ── A: helper exists in entitlements.py ────────────────────────────────────────


def test_A_ensure_admin_gateway_tenant_bound_helper_exists() -> None:
    assert "def _ensure_admin_gateway_tenant_bound(" in _ENTITLEMENTS_SRC, (
        "PR-CORE-002C requires a shared helper that establishes verified tenant "
        "context before capability enforcement runs."
    )


# ── B: helper is invoked at the top of require_capability's inner _dep ─────────


def test_B_require_capability_invokes_verified_tenant_helper_first() -> None:
    dep_start = _ENTITLEMENTS_SRC.index("def _dep(request: Request) -> None:")
    dep_end = _ENTITLEMENTS_SRC.index("\n    return _dep", dep_start)
    dep_body = _ENTITLEMENTS_SRC[dep_start:dep_end]
    assert "_ensure_admin_gateway_tenant_bound(request)" in dep_body, (
        "require_capability's inner _dep must call the verified-tenant helper "
        "so admin_internal_token requests establish tenant context before "
        "capability enforcement (PR-CORE-002C)."
    )

    helper_pos = dep_body.index("_ensure_admin_gateway_tenant_bound(request)")
    tenant_lookup_pos = dep_body.index("tenant_id = getattr(")
    check_pos = dep_body.index("_admin_gateway_tenant_admin_satisfies_capability(")
    check_capability_pos = dep_body.index("check_capability(db, tenant_id, capability)")
    assert helper_pos < tenant_lookup_pos, (
        "verified-tenant helper must run before tenant_id is read from state"
    )
    assert helper_pos < check_pos, (
        "verified-tenant helper must run before the admin_gateway bypass check"
    )
    assert helper_pos < check_capability_pos, (
        "verified-tenant helper must run before check_capability()"
    )


# ── C: helper delegates to bind_tenant_id (single canonical authority path) ────


def test_C_helper_delegates_to_bind_tenant_id() -> None:
    helper_start = _ENTITLEMENTS_SRC.index("def _ensure_admin_gateway_tenant_bound(")
    helper_end = _ENTITLEMENTS_SRC.index("\n\ndef ", helper_start + 1)
    helper_body = _ENTITLEMENTS_SRC[helper_start:helper_end]
    assert "bind_tenant_id(request, header_tenant)" in helper_body, (
        "The helper must delegate to bind_tenant_id() rather than re-implement "
        "delegation verification. A second authority path would drift out of "
        "step with the PR-CORE-002 canonical verification."
    )


# ── D: helper only fires for admin_internal_token requests (no bypass) ─────────


def test_D_helper_scoped_to_admin_internal_token() -> None:
    helper_start = _ENTITLEMENTS_SRC.index("def _ensure_admin_gateway_tenant_bound(")
    helper_end = _ENTITLEMENTS_SRC.index("\n\ndef ", helper_start + 1)
    helper_body = _ENTITLEMENTS_SRC[helper_start:helper_end]
    assert '"admin_internal_token"' in helper_body, (
        "The helper must gate on auth.reason == 'admin_internal_token' so "
        "tenant API-key / fgk.* paths continue using the existing "
        "middleware-established tenant context."
    )
    assert "return None" in helper_body, (
        "The helper must return None (no-op) for non-admin_internal_token "
        "requests — do not weaken existing binding for other auth paths."
    )


# ── E: request-scoped verified flag exists in resolution.py ────────────────────


def test_E_resolution_uses_verified_flag_for_idempotent_binds() -> None:
    assert "_admin_gateway_delegation_verified" in _RESOLUTION_SRC, (
        "bind_tenant_id must set and consult a request-scoped verified flag "
        "so the second-hop bind (e.g. tenant_db_required in the route body) "
        "trusts the delegation proof already run by require_capability."
    )


# ── F: verified flag is only set AFTER delegation proof succeeds ───────────────


def test_F_verified_flag_set_only_after_delegation_and_tenant_verify() -> None:
    admin_branch_start = _RESOLUTION_SRC.index(
        'if getattr(auth, "reason", "") == "admin_internal_token":'
    )
    admin_branch_end = _RESOLUTION_SRC.index("\n    if requested:", admin_branch_start)
    branch = _RESOLUTION_SRC[admin_branch_start:admin_branch_end]

    proof_pos = branch.index("_verify_delegation_proof(request, requested)")
    tenant_verify_pos = branch.index("_verify_admin_gateway_tenant(requested)")
    flag_set_pos = branch.index(
        "request.state._admin_gateway_delegation_verified = True"
    )
    assert proof_pos < flag_set_pos, (
        "verified flag must not be set until _verify_delegation_proof has run"
    )
    assert tenant_verify_pos < flag_set_pos, (
        "verified flag must not be set until _verify_admin_gateway_tenant has run"
    )


# ── G: defense-in-depth guard consults the verified flag (idempotent binds) ────


def test_G_key_bound_fast_path_admin_internal_token_guard_honors_flag() -> None:
    key_bound_start = _RESOLUTION_SRC.index("if cached_tenant and key_bound_flag:")
    key_bound_end = _RESOLUTION_SRC.index("\n    auth = ", key_bound_start)
    block = _RESOLUTION_SRC[key_bound_start:key_bound_end]
    assert "_admin_gateway_delegation_verified" in block, (
        "The key_bound_flag fast-path guard for admin_internal_token must "
        "honor the request-scoped verified flag so the second bind_tenant_id "
        "call (route body) does not spuriously fall through to the "
        "delegation branch again with requested=None (PR-CORE-002C)."
    )
    assert "not _verified_flag" in block, (
        "Guard must clear pre-bound state ONLY when the request has not yet "
        "passed delegation — protecting the first bind (defense-in-depth from "
        "PR-CORE-002B) while allowing idempotent second-hop binds."
    )


# ── H: PR-CORE-002B behaviors preserved: middleware still excludes admin path ──


def test_H_authgate_middleware_still_excludes_admin_internal_token() -> None:
    # This is the PR-CORE-002B invariant — must not regress from a 002C fix.
    authgate_src = Path("api/middleware/auth_gate.py").read_text(encoding="utf-8")
    line_start = authgate_src.index("_tenant_injectable = ")
    line_end = authgate_src.index("\n", line_start)
    injectable_line = authgate_src[line_start:line_end]
    assert "admin_internal_token" not in injectable_line, (
        "PR-CORE-002B invariant: middleware must not pre-bind tenant_id for "
        "admin_internal_token — that was the original bypass. PR-CORE-002C "
        "adds the pre-capability verified-tenant step but must not weaken 002B."
    )


# ── I: X-Tenant-ID fallback wired through bind_tenant_id, not a shortcut ───────


def test_I_bind_tenant_id_falls_back_to_header_only_after_verification() -> None:
    admin_branch_start = _RESOLUTION_SRC.index(
        'if getattr(auth, "reason", "") == "admin_internal_token":'
    )
    admin_branch_end = _RESOLUTION_SRC.index("\n    if requested:", admin_branch_start)
    branch = _RESOLUTION_SRC[admin_branch_start:admin_branch_end]

    # X-Tenant-ID header fallback must exist so route-body second-hop binds
    # (which call bind_tenant_id with tenant_id=None from a query param) can
    # resolve the tenant that require_capability already verified.
    assert 'request.headers.get("X-Tenant-Id")' in branch, (
        "admin_internal_token branch must fall back to X-Tenant-ID header when "
        "the caller did not pass requested_tenant explicitly."
    )
    header_pos = branch.index('request.headers.get("X-Tenant-Id")')
    verify_pos = branch.index("_verify_delegation_proof(request, requested)")
    assert header_pos < verify_pos, (
        "Header-tenant fallback must resolve requested BEFORE delegation proof "
        "runs, so proof verification binds the effective tenant (not None)."
    )


# ── J: capability check still uses the resolved tenant_id (no wildcard bypass) ─


def test_J_capability_still_enforced_after_tenant_resolution() -> None:
    dep_start = _ENTITLEMENTS_SRC.index("def _dep(request: Request) -> None:")
    dep_end = _ENTITLEMENTS_SRC.index("\n    return _dep", dep_start)
    dep_body = _ENTITLEMENTS_SRC[dep_start:dep_end]
    # After verified-tenant helper runs, check_capability must still be called.
    assert "check_capability(db, tenant_id, capability)" in dep_body, (
        "PR-CORE-002C must not remove capability enforcement — it must only "
        "reorder verified-tenant establishment to run BEFORE it."
    )
    # And the strict-denial 403 raise must still exist.
    assert '"code": "CAPABILITY_DENIED"' in dep_body, (
        "Fail-closed capability denial must remain intact."
    )


# ── K: narrow admin-gateway bypass registry unchanged (no wildcarding) ─────────


def test_K_admin_gateway_capability_bypass_registry_is_narrow() -> None:
    reg_start = _ENTITLEMENTS_SRC.index(
        "_ADMIN_GATEWAY_TENANT_ADMIN_CAPABILITIES: dict[str, tuple[str, ...]]"
    )
    reg_end = _ENTITLEMENTS_SRC.index("\n}\n", reg_start)
    reg_block = _ENTITLEMENTS_SRC[reg_start:reg_end]
    # Only two capabilities may participate in the admin-gateway tenant-admin
    # bypass path: identity.sso and identity.scim. Any expansion here changes
    # the security posture and MUST be reviewed independently.
    assert '"identity.scim"' in reg_block
    assert '"identity.sso"' in reg_block
    # Sanity: no wildcards.
    assert '"*"' not in reg_block, (
        "Wildcard capabilities must never be added to the admin-gateway "
        "tenant-admin bypass registry."
    )
    assert '"*"' not in reg_block


# ── L: no second independent tenant-authority implementation was introduced ────


def test_L_no_shadow_delegation_verifier_in_entitlements() -> None:
    # PR-CORE-002C forbids re-implementing delegation proof / tenant lifecycle
    # verification in api/entitlements.py. The single canonical path is
    # api/auth_scopes/resolution._verify_delegation_proof +
    # _verify_admin_gateway_tenant, wrapped by bind_tenant_id.
    assert "_verify_delegation_proof" not in _ENTITLEMENTS_SRC, (
        "delegation proof verification must live only in "
        "api/auth_scopes/resolution.py — no shadow implementation in entitlements."
    )
    assert "_verify_admin_gateway_tenant" not in _ENTITLEMENTS_SRC, (
        "tenant lifecycle verification must live only in "
        "api/auth_scopes/resolution.py — no shadow implementation in entitlements."
    )


# ── M–T: behavioral end-to-end via TestClient ─────────────────────────────────


def _configure_app(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    db_path = tmp_path / "core_002c.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AUTH_ENABLED", "1")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", "test-admin-gateway-token")
    monkeypatch.setenv("FG_ENTITLEMENT_ENFORCEMENT", "true")
    monkeypatch.setenv("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")
    configure_delegation_env(monkeypatch)

    import api.entitlements as entitlements
    from api.db import init_db, reset_engine_cache
    from api.main import build_app

    monkeypatch.setattr(entitlements, "ENFORCEMENT_STRICT", True)
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    return TestClient(build_app(auth_enabled=True), raise_server_exceptions=False)


def _admin_gateway_headers(tenant_id: str) -> dict[str, str]:
    return {
        "X-API-Key": "test-admin-gateway-token",
        "X-FG-Internal-Token": "test-admin-gateway-token",
        "X-Admin-Gateway-Internal": "true",
        "X-Tenant-ID": tenant_id,
        "X-Request-ID": f"002c-{tenant_id}",
    }


def _delegated_admin_gateway_headers(
    tenant_id: str, *, method: str, path: str
) -> dict[str, str]:
    """Admin gateway headers with a valid delegation proof for tests M, N, O, Q."""
    request_id = f"002c-{tenant_id}"
    return {
        **_admin_gateway_headers(tenant_id),
        **delegation_headers(
            tenant_id=tenant_id,
            method=method,
            path=path,
            request_id=request_id,
        ),
    }


def _seed_tenant(tenant_id: str, *, lifecycle_state: str = "active") -> None:
    from sqlalchemy import text

    from api.db import get_engine

    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO tenants (tenant_id, display_name, lifecycle_state)"
                " VALUES (:tid, :name, :state)"
            ),
            {"tid": tenant_id, "name": tenant_id, "state": lifecycle_state},
        )


def _seed_suspended_tenant(tenant_id: str) -> None:
    from sqlalchemy import text

    from api.db import get_engine

    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("DELETE FROM tenants WHERE tenant_id = :tid"), {"tid": tenant_id}
        )
        conn.execute(
            text(
                "INSERT INTO tenants (tenant_id, display_name, lifecycle_state)"
                " VALUES (:tid, :name, 'suspended')"
            ),
            {"tid": tenant_id, "name": tenant_id},
        )


def test_M_admin_gateway_route_passes_capability_after_tenant_bind(
    tmp_path, monkeypatch
) -> None:
    """Regression: with a seeded active tenant, /admin/identity/.../config reaches
    business logic (200) — capability check no longer denies with no_tenant_context."""
    client = _configure_app(tmp_path, monkeypatch)
    tenant = "tenant-002c-active"
    _seed_tenant(tenant)
    resp = client.get(
        f"/admin/identity/tenants/{tenant}/config",
        headers=_delegated_admin_gateway_headers(
            tenant, method="GET", path=f"/admin/identity/tenants/{tenant}/config"
        ),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # Fresh tenant: not yet configured, but capability enforcement did not deny.
    assert body.get("configured") is False
    assert "CAPABILITY_DENIED" not in resp.text


def test_N_missing_tenant_returns_404_before_capability(tmp_path, monkeypatch) -> None:
    """Missing tenant must be rejected by _verify_admin_gateway_tenant (404),
    NOT by capability enforcement — invariant: tenant authority verification runs
    before capability enforcement."""
    client = _configure_app(tmp_path, monkeypatch)
    tenant = "tenant-002c-ghost"  # never seeded
    resp = client.get(
        f"/admin/identity/tenants/{tenant}/config",
        headers=_delegated_admin_gateway_headers(
            tenant, method="GET", path=f"/admin/identity/tenants/{tenant}/config"
        ),
    )
    assert resp.status_code == 404, resp.text
    assert "CAPABILITY_DENIED" not in resp.text


def test_O_suspended_tenant_returns_403_before_capability(
    tmp_path, monkeypatch
) -> None:
    """Suspended tenant must be rejected by lifecycle check (403), NOT by
    capability enforcement — tenant authority precedes capability."""
    client = _configure_app(tmp_path, monkeypatch)
    tenant = "tenant-002c-suspended"
    _seed_suspended_tenant(tenant)
    resp = client.get(
        f"/admin/identity/tenants/{tenant}/config",
        headers=_delegated_admin_gateway_headers(
            tenant, method="GET", path=f"/admin/identity/tenants/{tenant}/config"
        ),
    )
    assert resp.status_code == 403, resp.text
    assert "CAPABILITY_DENIED" not in resp.text


def test_P_tenant_api_key_path_unchanged_by_002c(tmp_path, monkeypatch) -> None:
    """Regression: tenant API-key auth still enforces capability strictly.
    The 002C fix must not silently grant capability for non-admin-gateway paths."""
    from api.auth_scopes import mint_key

    client = _configure_app(tmp_path, monkeypatch)
    tenant = "tenant-002c-tenant-key"
    _seed_tenant(tenant)
    key = mint_key("admin:read", "admin:write", tenant_id=tenant)
    resp = client.post(
        "/workforce/users",
        headers={"X-API-Key": key, "X-Tenant-ID": tenant},
        json={"email": "p@example.com", "display_name": "P", "role": "admin"},
    )
    assert resp.status_code == 403, resp.text
    body = resp.json()["detail"]
    assert body.get("code") == "CAPABILITY_DENIED"
    assert body.get("capability") == "identity.scim"


def test_Q_workforce_users_reaches_business_validation_after_002c(
    tmp_path, monkeypatch
) -> None:
    """Admin gateway path to /workforce/users hits IDENTITY_CONFIGURATION_REQUIRED
    (business logic 422), not CAPABILITY_DENIED, once tenant authority is bound."""
    client = _configure_app(tmp_path, monkeypatch)
    tenant = "tenant-002c-workforce"
    _seed_tenant(tenant)
    resp = client.post(
        "/workforce/users",
        headers=_delegated_admin_gateway_headers(
            tenant, method="POST", path="/workforce/users"
        ),
        json={"email": "q@example.com", "display_name": "Q", "role": "admin"},
    )
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == "IDENTITY_CONFIGURATION_REQUIRED"
    assert "CAPABILITY_DENIED" not in resp.text


def test_R_stale_admin_gateway_token_denied_before_capability(
    tmp_path, monkeypatch
) -> None:
    """Invalid internal token is denied at the middleware auth stage (401), well
    before capability enforcement — 002C must not open a bypass."""
    client = _configure_app(tmp_path, monkeypatch)
    tenant = "tenant-002c-stale"
    _seed_tenant(tenant)
    headers = _admin_gateway_headers(tenant)
    headers["X-API-Key"] = "stale-token"
    headers["X-FG-Internal-Token"] = "stale-token"
    resp = client.post(
        "/workforce/users",
        headers=headers,
        json={"email": "r@example.com", "display_name": "R", "role": "admin"},
    )
    assert resp.status_code == 401, resp.text
    assert "CAPABILITY_DENIED" not in resp.text


def test_S_no_tenant_header_returns_400_not_capability_denied(
    tmp_path, monkeypatch
) -> None:
    """admin_internal_token without X-Tenant-ID cannot bind, so bind_tenant_id
    raises 400 tenant_id-required, NOT 403 CAPABILITY_DENIED / no_tenant_context.
    This proves capability enforcement does not see an unverified context."""
    client = _configure_app(tmp_path, monkeypatch)
    headers = {
        "X-API-Key": "test-admin-gateway-token",
        "X-FG-Internal-Token": "test-admin-gateway-token",
        "X-Admin-Gateway-Internal": "true",
        "X-Request-ID": "002c-no-tenant-header",
    }
    # Path segment contains a tenant id, but the header does not
    resp = client.get(
        "/admin/identity/tenants/tenant-002c-no-header/config", headers=headers
    )
    # bind_tenant_id() falls back to X-Tenant-ID header. Without it, it raises
    # 400 tenant_id required — capability enforcement never runs on an
    # unverified tenant.
    assert resp.status_code in {400, 404}, resp.text
    assert "CAPABILITY_DENIED" not in resp.text


def test_T_admin_gateway_bypass_only_matches_registered_prefixes(
    tmp_path, monkeypatch
) -> None:
    """The admin-gateway tenant-admin bypass registry is narrow: it accepts
    identity.sso/identity.scim under specific path prefixes only. Other
    capabilities (e.g. trust.reporting) must still consult the DB — no
    global bypass for admin_internal_token."""
    from api.entitlements import _admin_gateway_tenant_admin_satisfies_capability
    from unittest.mock import MagicMock

    request = MagicMock()
    request.state.auth = MagicMock(reason="admin_internal_token")
    request.url.path = "/trust/executive/dashboard"

    # trust.executive.dashboard is NOT in the bypass registry
    assert not _admin_gateway_tenant_admin_satisfies_capability(
        request, "tenant-x", "trust.executive.dashboard"
    )
    # identity.sso IS in the bypass registry but only for /admin/identity/tenants/
    request.url.path = "/admin/identity/tenants/tenant-x/config"
    assert _admin_gateway_tenant_admin_satisfies_capability(
        request, "tenant-x", "identity.sso"
    )
    # Bypass requires tenant_id — no bypass when tenant is empty
    assert not _admin_gateway_tenant_admin_satisfies_capability(
        request, None, "identity.sso"
    )
    # Non-admin_internal_token never gets the bypass
    request.state.auth = MagicMock(reason="canonical_validated")
    assert not _admin_gateway_tenant_admin_satisfies_capability(
        request, "tenant-x", "identity.sso"
    )
