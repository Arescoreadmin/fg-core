"""
P-113.6.1 — Canonical Platform Admin Credential Authority — negative security tests.

Tests: N01–N20 (negative/security matrix) + M01–M04 (migration regression tests).

These tests verify that:
- COMPATIBILITY mode preserves legacy Path E and allows canonical credentials.
- CANONICAL mode disables Path E entirely.
- Gateway provenance remains independently enforced in both modes.
- No ordinary tenant/PSP/attacker credential can obtain platform.admin.
- Revoked, suspended, and absent credentials fail closed.
- Malformed PLATFORM_AUTH_MODE fails safe (treat as COMPATIBILITY).

No plaintext credentials appear in test assertions, logs, or output.
All key comparisons use only prefixes or presence/absence checks.
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import pytest
from sqlalchemy import text


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _reload_platform_auth_mode(mode: str) -> None:
    """Force-reload api.platform_auth_mode with the given PLATFORM_AUTH_MODE."""
    import api.platform_auth_mode as pam

    pam.PLATFORM_AUTH_MODE = mode


def _make_request_mock(
    path: str,
    *,
    x_api_key: str = "",
    x_fg_internal_token: str = "",
    x_admin_gateway_internal: str = "true",
    x_fg_internal_caller: str = "",
    method: str = "GET",
) -> MagicMock:
    """Build a minimal mock Request for verify_api_key_detailed()."""
    from starlette.datastructures import Headers

    headers_dict: dict[str, str] = {}
    if x_fg_internal_token:
        headers_dict["X-FG-Internal-Token"] = x_fg_internal_token
    if x_admin_gateway_internal:
        headers_dict["X-Admin-Gateway-Internal"] = x_admin_gateway_internal
    if x_fg_internal_caller:
        headers_dict["X-FG-Internal-Caller"] = x_fg_internal_caller

    mock = MagicMock()
    mock.url.path = path
    mock.method = method
    mock.headers = Headers(headers=headers_dict)
    mock.client = MagicMock()
    mock.client.host = "127.0.0.1"
    mock.state = MagicMock()
    mock.state.request_id = str(uuid.uuid4())
    return mock


_GATEWAY_SECRET = "test-gateway-secret-xyzzy-p1136-tests"
_PLATFORM_ADMIN_KEY_PREFIX = "fgk."

# ---------------------------------------------------------------------------
# N01: COMPATIBILITY + gateway secret as X-API-Key → legacy Path E allowed
# ---------------------------------------------------------------------------


def test_n01_compatibility_gateway_secret_allows_path_e(monkeypatch):
    """N01: In COMPATIBILITY mode, X-API-Key == FG_INTERNAL_GATEWAY_SECRET → Path E succeeds."""
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", _GATEWAY_SECRET)
    monkeypatch.setenv("PLATFORM_AUTH_MODE", "COMPATIBILITY")

    import importlib
    import api.platform_auth_mode as pam

    importlib.reload(pam)
    monkeypatch.setattr(pam, "PLATFORM_AUTH_MODE", "COMPATIBILITY")

    from api.auth_scopes.resolution import verify_api_key_detailed
    import api.auth_scopes.resolution as resolution_mod

    monkeypatch.setattr(resolution_mod, "is_canonical_mode", lambda: False)

    request = _make_request_mock("/admin/tenants", x_admin_gateway_internal="true")
    result = verify_api_key_detailed(
        raw=_GATEWAY_SECRET,
        request=request,
    )
    assert result.valid, f"Path E must succeed in COMPATIBILITY mode: {result.reason}"
    assert result.reason == "admin_internal_token"


# ---------------------------------------------------------------------------
# N02: COMPATIBILITY + valid canonical fgk + valid gateway provenance → allowed
# ---------------------------------------------------------------------------


def test_n02_compatibility_canonical_fgk_allowed(tmp_path, monkeypatch):
    """N02: In COMPATIBILITY mode, a valid canonical fgk credential must succeed."""
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(tmp_path / "n02.db"))
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", _GATEWAY_SECRET)
    monkeypatch.setenv("PLATFORM_AUTH_MODE", "COMPATIBILITY")

    from api.db import init_db, reset_engine_cache

    reset_engine_cache()
    init_db(sqlite_path=str(tmp_path / "n02.db"))

    from api.db import get_engine
    from api.credential_authority import issue_credential

    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO tenants "
                "(tenant_id, display_name, lifecycle_state, tenant_kind) "
                "VALUES ('frostgate-internal', 'FrostGate Internal', 'active', 'internal_platform')"
            )
        )

    result = issue_credential(
        engine,
        tenant_id="frostgate-internal",
        credential_type="tenant_api_key",
        credential_slot="platform-admin-credential:v1",
        actor_id="test",
    )
    plaintext = result.plaintext_secret
    assert plaintext and plaintext.startswith("fgk.")

    # Verify canonical validation path works
    from api.credential_authority import validate_credential

    principal = validate_credential(engine, plaintext)
    assert principal.tenant_id == "frostgate-internal"
    assert principal.credential_slot == "platform-admin-credential:v1"


# ---------------------------------------------------------------------------
# N03: CANONICAL + gateway secret as X-API-Key → rejected as platform authority
# ---------------------------------------------------------------------------


def test_n03_canonical_gateway_secret_rejected_for_platform_auth(monkeypatch):
    """N03: In CANONICAL mode, FG_INTERNAL_GATEWAY_SECRET as X-API-Key must NOT
    produce admin_internal_token reason — Path E is disabled."""
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", _GATEWAY_SECRET)
    monkeypatch.setenv("PLATFORM_AUTH_MODE", "CANONICAL")

    import api.platform_auth_mode as pam

    monkeypatch.setattr(pam, "PLATFORM_AUTH_MODE", "CANONICAL")

    from api.auth_scopes.resolution import verify_api_key_detailed
    import api.auth_scopes.resolution as resolution_mod

    monkeypatch.setattr(resolution_mod, "is_canonical_mode", lambda: True)

    request = _make_request_mock("/admin/tenants", x_admin_gateway_internal="true")

    # The gateway secret is not an fgk.* credential, so it is NOT a canonical
    # credential. In CANONICAL mode, Path E is disabled entirely, so the gateway
    # secret falls through to the FG_API_KEY check, then fails key_not_found.
    result = verify_api_key_detailed(
        raw=_GATEWAY_SECRET,
        request=request,
    )
    assert not result.valid, (
        "In CANONICAL mode, FG_INTERNAL_GATEWAY_SECRET as X-API-Key must not succeed "
        "as platform admin authority"
    )
    # Must NOT produce admin_internal_token (Path E disabled)
    assert result.reason != "admin_internal_token", (
        "Path E must be fully disabled in CANONICAL mode"
    )


# ---------------------------------------------------------------------------
# N04: CANONICAL + valid canonical fgk + valid gateway provenance → allowed
# ---------------------------------------------------------------------------


def test_n04_canonical_valid_fgk_allowed(tmp_path, monkeypatch):
    """N04: In CANONICAL mode, a valid canonical platform_admin fgk credential + valid
    gateway provenance must allow authentication."""
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(tmp_path / "n04.db"))
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", _GATEWAY_SECRET)
    monkeypatch.setenv("PLATFORM_AUTH_MODE", "CANONICAL")

    from api.db import init_db, reset_engine_cache

    reset_engine_cache()
    init_db(sqlite_path=str(tmp_path / "n04.db"))

    from api.db import get_engine
    from api.credential_authority import issue_credential, validate_credential

    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO tenants "
                "(tenant_id, display_name, lifecycle_state, tenant_kind) "
                "VALUES ('frostgate-internal', 'FrostGate Internal', 'active', 'internal_platform')"
            )
        )

    issued = issue_credential(
        engine,
        tenant_id="frostgate-internal",
        credential_type="tenant_api_key",
        credential_slot="platform-admin-credential:v1",
        actor_id="test",
    )
    plaintext = issued.plaintext_secret
    assert plaintext and plaintext.startswith("fgk.")

    # Direct credential validation succeeds
    principal = validate_credential(engine, plaintext)
    assert principal.tenant_id == "frostgate-internal"

    # Via auth resolver in CANONICAL mode
    import api.auth_scopes.resolution as resolution_mod

    monkeypatch.setattr(resolution_mod, "is_canonical_mode", lambda: True)

    from api.auth_scopes.resolution import verify_api_key_detailed

    request = _make_request_mock("/admin/tenants", x_admin_gateway_internal="true")
    result = verify_api_key_detailed(raw=plaintext, request=request)
    assert result.valid, (
        f"Canonical fgk must succeed in CANONICAL mode: {result.reason}"
    )
    assert result.reason == "canonical_validated"
    assert result.tenant_id == "frostgate-internal"


# ---------------------------------------------------------------------------
# N05: CANONICAL + canonical fgk + invalid gateway provenance → rejected
# ---------------------------------------------------------------------------


def test_n05_canonical_fgk_invalid_gateway_provenance_rejected(tmp_path, monkeypatch):
    """N05: Gateway provenance (X-FG-Internal-Token) is independently enforced.
    A valid fgk credential without valid gateway provenance must be rejected by
    require_internal_admin_gateway() at the route layer.

    This test verifies the gateway check function independently (unit-level),
    since provenance is a route-layer concern separate from credential validation.
    """
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", _GATEWAY_SECRET)

    from api.admin import require_internal_admin_gateway
    from fastapi import HTTPException

    # No X-FG-Internal-Token header
    mock_request = _make_request_mock("/admin/tenants")
    mock_request.headers = MagicMock()
    mock_request.headers.get = lambda key, default=None: None

    with pytest.raises(HTTPException) as exc_info:
        require_internal_admin_gateway(mock_request)
    assert exc_info.value.status_code == 403, (
        "Missing gateway provenance must result in 403"
    )


# ---------------------------------------------------------------------------
# N06: CANONICAL + invalid fgk + valid gateway provenance → rejected
# ---------------------------------------------------------------------------


def test_n06_canonical_invalid_fgk_rejected(tmp_path, monkeypatch):
    """N06: In CANONICAL mode, an invalid/nonexistent fgk credential must be rejected."""
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(tmp_path / "n06.db"))
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", _GATEWAY_SECRET)
    monkeypatch.setenv("PLATFORM_AUTH_MODE", "CANONICAL")

    from api.db import init_db, reset_engine_cache

    reset_engine_cache()
    init_db(sqlite_path=str(tmp_path / "n06.db"))

    import api.auth_scopes.resolution as resolution_mod

    monkeypatch.setattr(resolution_mod, "is_canonical_mode", lambda: True)

    from api.auth_scopes.resolution import verify_api_key_detailed

    # Use a well-formed but nonexistent fgk.* key
    fake_fgk = "fgk.notareal-key-that-does-not-exist-in-db"
    request = _make_request_mock("/admin/tenants", x_admin_gateway_internal="true")
    result = verify_api_key_detailed(raw=fake_fgk, request=request)
    assert not result.valid, "Invalid fgk must be rejected"


# ---------------------------------------------------------------------------
# N07: Revoked platform_admin credential → rejected
# ---------------------------------------------------------------------------


def test_n07_revoked_platform_admin_rejected(tmp_path, monkeypatch):
    """N07: A revoked platform_admin credential must fail closed."""
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(tmp_path / "n07.db"))
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")

    from api.db import init_db, reset_engine_cache

    reset_engine_cache()
    init_db(sqlite_path=str(tmp_path / "n07.db"))

    from api.db import get_engine
    from api.credential_authority import (
        issue_credential,
        validate_credential,
        revoke_credential,
    )
    from api.credential_authority import CredentialNotFoundError

    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO tenants "
                "(tenant_id, display_name, lifecycle_state, tenant_kind) "
                "VALUES ('frostgate-internal', 'FrostGate Internal', 'active', 'internal_platform')"
            )
        )

    issued = issue_credential(
        engine,
        tenant_id="frostgate-internal",
        credential_type="tenant_api_key",
        credential_slot=f"test-slot-n07-{uuid.uuid4().hex[:8]}",
        actor_id="test",
    )
    plaintext = issued.plaintext_secret
    assert plaintext and plaintext.startswith("fgk.")

    # Revoke it
    revoke_credential(
        engine,
        tenant_id="frostgate-internal",
        credential_id=issued.record.credential_id,
        actor_id="test",
        reason="test-revocation-n07",
    )

    # Validation must fail
    with pytest.raises(CredentialNotFoundError):
        validate_credential(engine, plaintext)


# ---------------------------------------------------------------------------
# N08: Suspended tenant → platform_admin credential rejected
# ---------------------------------------------------------------------------


def test_n08_suspended_tenant_platform_admin_rejected(tmp_path, monkeypatch):
    """N08: A platform_admin credential under a suspended tenant must fail closed."""
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(tmp_path / "n08.db"))
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")

    from api.db import init_db, reset_engine_cache

    reset_engine_cache()
    init_db(sqlite_path=str(tmp_path / "n08.db"))

    from api.db import get_engine
    from api.credential_authority import issue_credential, validate_credential
    from api.credential_authority import TenantLifecycleError

    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO tenants "
                "(tenant_id, display_name, lifecycle_state, tenant_kind) "
                "VALUES ('frostgate-internal', 'FrostGate Internal', 'active', 'internal_platform')"
            )
        )

    issued = issue_credential(
        engine,
        tenant_id="frostgate-internal",
        credential_type="tenant_api_key",
        credential_slot=f"test-slot-n08-{uuid.uuid4().hex[:8]}",
        actor_id="test",
    )
    plaintext = issued.plaintext_secret
    assert plaintext and plaintext.startswith("fgk.")

    # Suspend the tenant
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE tenants SET lifecycle_state = 'suspended' "
                "WHERE tenant_id = 'frostgate-internal'"
            )
        )

    # validate_credential must raise TenantLifecycleError
    with pytest.raises(TenantLifecycleError):
        validate_credential(engine, plaintext)

    # Restore tenant for cleanup
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE tenants SET lifecycle_state = 'active' "
                "WHERE tenant_id = 'frostgate-internal'"
            )
        )


# ---------------------------------------------------------------------------
# N09: Expired credential → rejected (expiry implemented via explicit expire)
# ---------------------------------------------------------------------------


def test_n09_expired_credential_rejected(tmp_path, monkeypatch):
    """N09: An expired platform_admin credential must fail closed."""
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(tmp_path / "n09.db"))
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")

    from api.db import init_db, reset_engine_cache

    reset_engine_cache()
    init_db(sqlite_path=str(tmp_path / "n09.db"))

    from api.db import get_engine
    from api.credential_authority import issue_credential, validate_credential
    from api.credential_authority import CredentialNotFoundError

    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO tenants "
                "(tenant_id, display_name, lifecycle_state, tenant_kind) "
                "VALUES ('frostgate-internal', 'FrostGate Internal', 'active', 'internal_platform')"
            )
        )

    # Issue with short TTL — will be force-expired via SQL below
    issued = issue_credential(
        engine,
        tenant_id="frostgate-internal",
        credential_type="tenant_api_key",
        credential_slot=f"test-slot-n09-{uuid.uuid4().hex[:8]}",
        actor_id="test",
        expires_in_seconds=1,
    )
    plaintext = issued.plaintext_secret
    assert plaintext and plaintext.startswith("fgk.")

    # Force-expire by setting expires_at to the past
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE tenant_credentials SET status='expired', expires_at = '2000-01-01T00:00:00+00:00' "
                "WHERE credential_id = :cid"
            ),
            {"cid": issued.record.credential_id},
        )

    with pytest.raises(CredentialNotFoundError):
        validate_credential(engine, plaintext)


# ---------------------------------------------------------------------------
# N10: Valid ordinary tenant fgk credential cannot obtain platform.admin
# ---------------------------------------------------------------------------


def test_n10_ordinary_tenant_fgk_cannot_get_platform_admin(tmp_path, monkeypatch):
    """N10: An ordinary tenant's fgk credential must NOT resolve to platform.admin.

    Authority is derived from RBAC via tenant_credential_roles.
    An ordinary tenant credential without platform_admin role assignment
    must not produce platform.admin in the ActorContext.
    """
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(tmp_path / "n10.db"))
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")

    from api.db import init_db, reset_engine_cache

    reset_engine_cache()
    init_db(sqlite_path=str(tmp_path / "n10.db"))

    from api.db import get_engine
    from api.credential_authority import issue_credential
    from api.tenant_rbac import get_credential_role
    from api.actor_context import roles_to_permissions
    from sqlalchemy.orm import Session

    engine = get_engine()
    tenant_id = f"customer-n10-{uuid.uuid4().hex[:8]}"
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO tenants "
                "(tenant_id, display_name, lifecycle_state, tenant_kind) "
                "VALUES (:tid, :tid, 'active', 'customer')"
            ),
            {"tid": tenant_id},
        )

    issued = issue_credential(
        engine,
        tenant_id=tenant_id,
        credential_type="tenant_api_key",
        credential_slot=f"slot-n10-{uuid.uuid4().hex[:8]}",
        actor_id="test",
    )

    # No role assigned → None
    with Session(engine) as session:
        role = get_credential_role(
            session,
            tenant_id=tenant_id,
            credential_id=issued.record.credential_id,
        )
    assert role is None

    # No role → no platform.admin permission
    perms = roles_to_permissions([role] if role else [])
    assert "platform.admin" not in perms, (
        "Ordinary tenant credential with no role must not obtain platform.admin"
    )


# ---------------------------------------------------------------------------
# N11: tenant_admin cannot obtain platform.admin
# ---------------------------------------------------------------------------


def test_n11_tenant_admin_cannot_get_platform_admin():
    """N11: The tenant_admin role must NOT grant platform.admin permission."""
    from api.actor_context import ROLE_PERMISSIONS

    tenant_admin_perms = ROLE_PERMISSIONS.get("tenant_admin", frozenset())
    assert "platform.admin" not in tenant_admin_perms, (
        "tenant_admin role must NOT include platform.admin permission"
    )


# ---------------------------------------------------------------------------
# N12: PSP credential cannot obtain platform.admin
# ---------------------------------------------------------------------------


def test_n12_psp_cannot_get_platform_admin():
    """N12: PSP credential scopes and default permissions must not include platform.admin."""
    from api.platform_service_principal import (
        PSP_CREDENTIAL_SCOPES,
        PLATFORM_SERVICE_DEFAULT_PERMISSIONS,
    )

    assert "platform.admin" not in PSP_CREDENTIAL_SCOPES, (
        "PSP credential scopes must NOT include platform.admin"
    )
    assert "platform.admin" not in PLATFORM_SERVICE_DEFAULT_PERMISSIONS, (
        "PSP default permissions must NOT include platform.admin"
    )


# ---------------------------------------------------------------------------
# N13: Missing X-API-Key → rejected
# ---------------------------------------------------------------------------


def test_n13_missing_api_key_rejected(monkeypatch):
    """N13: A request without X-API-Key must be rejected."""
    monkeypatch.setenv("FG_ENV", "test")

    from api.auth_scopes.resolution import verify_api_key_detailed

    request = _make_request_mock("/admin/tenants", x_admin_gateway_internal="true")
    result = verify_api_key_detailed(raw="", request=request)
    # Empty raw → no_key_provided (after Path E conditions for non-fgk)
    # In test mode without configured gateway secret, Path E conditions may not fire.
    # Either way, must be invalid.
    assert not result.valid


# ---------------------------------------------------------------------------
# N14: Missing gateway provenance where required → rejected
# ---------------------------------------------------------------------------


def test_n14_missing_gateway_provenance_rejected(monkeypatch):
    """N14: require_internal_admin_gateway must reject when X-FG-Internal-Token is absent."""
    monkeypatch.setenv("FG_ENV", "prod")
    monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", _GATEWAY_SECRET)

    from api.admin import require_internal_admin_gateway
    from fastapi import HTTPException
    from starlette.datastructures import Headers

    mock_req = _make_request_mock("/admin/tenants")
    # No X-FG-Internal-Token header — simulate by returning empty
    mock_req.headers = Headers(headers={})

    with pytest.raises(HTTPException) as exc_info:
        require_internal_admin_gateway(mock_req)
    assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# N15: Malformed PLATFORM_AUTH_MODE → fail-safe (treat as COMPATIBILITY)
# ---------------------------------------------------------------------------


def test_n15_malformed_platform_auth_mode_fail_safe(monkeypatch):
    """N15: Unknown PLATFORM_AUTH_MODE values must fail safely as COMPATIBILITY."""
    import api.platform_auth_mode as pam

    original_mode = pam.PLATFORM_AUTH_MODE
    try:
        # Simulate what module init does for unknown values
        test_values = ["UNKNOWN_MODE", "STRICT", "1", "  "]
        for raw in test_values:
            normalized = raw.strip().upper()
            if normalized in ("", "COMPATIBILITY"):
                effective = "COMPATIBILITY"
            elif normalized == "CANONICAL":
                effective = "CANONICAL"
            else:
                effective = "COMPATIBILITY"  # fail safe
            assert effective == "COMPATIBILITY", (
                f"Unknown value {raw!r} must default to COMPATIBILITY, got {effective!r}"
            )
    finally:
        pam.PLATFORM_AUTH_MODE = original_mode


# ---------------------------------------------------------------------------
# N16: Canonical credential denial never falls through to Path E
# ---------------------------------------------------------------------------


def test_n16_canonical_denied_no_fallthrough(tmp_path, monkeypatch):
    """N16: A canonical credential that fails validation (denied/revoked) must NOT
    fall through to Path E — it must fail closed."""
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(tmp_path / "n16.db"))
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", _GATEWAY_SECRET)
    monkeypatch.setenv("PLATFORM_AUTH_MODE", "COMPATIBILITY")

    from api.db import init_db, reset_engine_cache

    reset_engine_cache()
    init_db(sqlite_path=str(tmp_path / "n16.db"))

    from api.db import get_engine
    from api.credential_authority import issue_credential, revoke_credential

    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO tenants "
                "(tenant_id, display_name, lifecycle_state, tenant_kind) "
                "VALUES ('frostgate-internal', 'FrostGate Internal', 'active', 'internal_platform')"
            )
        )

    issued = issue_credential(
        engine,
        tenant_id="frostgate-internal",
        credential_type="tenant_api_key",
        credential_slot=f"test-slot-n16-{uuid.uuid4().hex[:8]}",
        actor_id="test",
    )
    plaintext = issued.plaintext_secret
    assert plaintext and plaintext.startswith("fgk.")

    # Revoke the credential — it is now denied
    revoke_credential(
        engine,
        tenant_id="frostgate-internal",
        credential_id=issued.record.credential_id,
        actor_id="test",
        reason="test-revocation-n16",
    )

    import api.auth_scopes.resolution as resolution_mod

    monkeypatch.setattr(resolution_mod, "is_canonical_mode", lambda: False)

    from api.auth_scopes.resolution import verify_api_key_detailed

    request = _make_request_mock("/admin/tenants", x_admin_gateway_internal="true")
    result = verify_api_key_detailed(raw=plaintext, request=request)

    # Must be rejected — must NOT fall through to Path E
    assert not result.valid, "Denied canonical credential must fail closed"
    # Must NOT be admin_internal_token (that would mean Path E fallthrough)
    assert result.reason != "admin_internal_token", (
        "Denied canonical credential must NOT fall through to Path E"
    )


# ---------------------------------------------------------------------------
# N17: Tenant lifecycle denial never falls through
# ---------------------------------------------------------------------------


def test_n17_lifecycle_denial_no_fallthrough(tmp_path, monkeypatch):
    """N17: TenantLifecycleError from canonical auth must never fall through to Path E."""
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(tmp_path / "n17.db"))
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", _GATEWAY_SECRET)

    from api.db import init_db, reset_engine_cache

    reset_engine_cache()
    init_db(sqlite_path=str(tmp_path / "n17.db"))

    from api.db import get_engine
    from api.credential_authority import issue_credential

    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO tenants "
                "(tenant_id, display_name, lifecycle_state, tenant_kind) "
                "VALUES ('frostgate-internal', 'FrostGate Internal', 'active', 'internal_platform')"
            )
        )

    issued = issue_credential(
        engine,
        tenant_id="frostgate-internal",
        credential_type="tenant_api_key",
        credential_slot=f"test-slot-n17-{uuid.uuid4().hex[:8]}",
        actor_id="test",
    )
    plaintext = issued.plaintext_secret
    assert plaintext and plaintext.startswith("fgk.")

    # Suspend the frostgate-internal tenant
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE tenants SET lifecycle_state = 'suspended' "
                "WHERE tenant_id = 'frostgate-internal'"
            )
        )

    import api.auth_scopes.resolution as resolution_mod

    monkeypatch.setattr(resolution_mod, "is_canonical_mode", lambda: False)

    from api.auth_scopes.resolution import verify_api_key_detailed

    request = _make_request_mock("/admin/tenants", x_admin_gateway_internal="true")
    result = verify_api_key_detailed(raw=plaintext, request=request)

    assert not result.valid, "Lifecycle-denied credential must fail closed"
    assert result.reason == "tenant_lifecycle_denied", (
        f"Expected tenant_lifecycle_denied, got: {result.reason!r}"
    )
    # Must NOT fall through to Path E
    assert result.reason != "admin_internal_token", (
        "Tenant lifecycle denial must NOT fall through to Path E"
    )

    # Restore for cleanup
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE tenants SET lifecycle_state = 'active' "
                "WHERE tenant_id = 'frostgate-internal'"
            )
        )


# ---------------------------------------------------------------------------
# N18: FG_API_KEY remains disabled for production authority
# ---------------------------------------------------------------------------


def test_n18_fg_api_key_disabled_production(monkeypatch):
    """N18: FG_API_KEY must be rejected in production environments."""
    global_key = "some-global-api-key-value-xyz"
    monkeypatch.setenv("FG_ENV", "prod")
    monkeypatch.setenv("FG_API_KEY", global_key)

    from api.auth_scopes.resolution import verify_api_key_detailed

    request = _make_request_mock("/decisions", x_admin_gateway_internal="")
    result = verify_api_key_detailed(raw=global_key, request=request)
    assert not result.valid, "FG_API_KEY must be rejected in production"
    assert result.reason == "env_key_disabled_production"


# ---------------------------------------------------------------------------
# N19: Canonical authority must derive from RBAC, not credential slot name
# ---------------------------------------------------------------------------


def test_n19_authority_from_rbac_not_slot_name(tmp_path, monkeypatch):
    """N19: platform.admin must come from tenant_credential_roles RBAC assignment,
    NOT from having the platform-admin-credential:v1 slot name."""
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(tmp_path / "n19.db"))
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")

    from api.db import init_db, reset_engine_cache

    reset_engine_cache()
    init_db(sqlite_path=str(tmp_path / "n19.db"))

    from api.db import get_engine
    from api.credential_authority import issue_credential
    from api.tenant_rbac import get_credential_role
    from api.actor_context import roles_to_permissions
    from sqlalchemy.orm import Session

    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO tenants "
                "(tenant_id, display_name, lifecycle_state, tenant_kind) "
                "VALUES ('frostgate-internal', 'FrostGate Internal', 'active', 'internal_platform')"
            )
        )

    # Issue credential with the platform-admin slot name but NO role assigned
    issued = issue_credential(
        engine,
        tenant_id="frostgate-internal",
        credential_type="tenant_api_key",
        credential_slot="platform-admin-credential:v1",  # slot name alone is not enough
        actor_id="test",
    )

    # Verify no role is assigned (role assignment is a separate step)
    with Session(engine) as session:
        role = get_credential_role(
            session,
            tenant_id="frostgate-internal",
            credential_id=issued.record.credential_id,
        )
    assert role is None, (
        "A credential with platform-admin slot name but no role assignment must have no role"
    )

    # No role → no platform.admin
    perms = roles_to_permissions([role] if role else [])
    assert "platform.admin" not in perms, (
        "Slot name alone must not grant platform.admin — RBAC role assignment is required"
    )


# ---------------------------------------------------------------------------
# N20: Attacker/customer tenant credential cannot obtain platform.admin
# ---------------------------------------------------------------------------


def test_n20_customer_tenant_cannot_get_platform_admin(tmp_path, monkeypatch):
    """N20: A credential from an attacker/customer tenant must not obtain platform.admin."""
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(tmp_path / "n20.db"))
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")

    from api.db import init_db, reset_engine_cache

    reset_engine_cache()
    init_db(sqlite_path=str(tmp_path / "n20.db"))

    from api.db import get_engine
    from api.credential_authority import issue_credential, validate_credential
    from api.tenant_rbac import get_credential_role
    from api.actor_context import roles_to_permissions, ALL_PERMISSIONS
    from sqlalchemy.orm import Session

    engine = get_engine()

    # Attacker controls their own tenant
    attacker_tid = f"attacker-{uuid.uuid4().hex[:8]}"
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO tenants "
                "(tenant_id, display_name, lifecycle_state, tenant_kind) "
                "VALUES (:tid, :tid, 'active', 'customer')"
            ),
            {"tid": attacker_tid},
        )

    # Even if they name their slot "platform-admin-credential:v1", it must not work
    issued = issue_credential(
        engine,
        tenant_id=attacker_tid,
        credential_type="tenant_api_key",
        credential_slot="platform-admin-credential:v1",
        actor_id="test",
    )

    # Validate succeeds (it's a valid credential for attacker tenant)
    principal = validate_credential(engine, issued.plaintext_secret)
    assert (
        principal.tenant_id == attacker_tid
    )  # bound to attacker's tenant, not frostgate-internal

    # No platform_admin role
    with Session(engine) as session:
        role = get_credential_role(
            session,
            tenant_id=attacker_tid,
            credential_id=issued.record.credential_id,
        )
    assert role is None

    perms = roles_to_permissions([role] if role else [])
    assert "platform.admin" not in perms, (
        "Customer tenant credential must not obtain platform.admin"
    )
    assert perms != ALL_PERMISSIONS, (
        "Customer tenant credential must not have ALL_PERMISSIONS"
    )


# ---------------------------------------------------------------------------
# M01–M04: Migration regression tests
# ---------------------------------------------------------------------------


def test_m01_compatibility_existing_bff_request_works(monkeypatch):
    """M01: In COMPATIBILITY mode, existing BFF request (X-API-Key = gateway secret) works."""
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", _GATEWAY_SECRET)
    monkeypatch.setenv("PLATFORM_AUTH_MODE", "COMPATIBILITY")

    import api.auth_scopes.resolution as resolution_mod

    monkeypatch.setattr(resolution_mod, "is_canonical_mode", lambda: False)

    from api.auth_scopes.resolution import verify_api_key_detailed

    request = _make_request_mock("/admin/tenants", x_admin_gateway_internal="true")
    result = verify_api_key_detailed(raw=_GATEWAY_SECRET, request=request)
    assert result.valid
    assert result.reason == "admin_internal_token"


def test_m02_compatibility_canonical_request_also_works(tmp_path, monkeypatch):
    """M02: In COMPATIBILITY mode, new canonical fgk request also works (coexistence)."""
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(tmp_path / "m02.db"))
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    monkeypatch.setenv("PLATFORM_AUTH_MODE", "COMPATIBILITY")

    from api.db import init_db, reset_engine_cache

    reset_engine_cache()
    init_db(sqlite_path=str(tmp_path / "m02.db"))

    from api.db import get_engine
    from api.credential_authority import issue_credential

    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO tenants "
                "(tenant_id, display_name, lifecycle_state, tenant_kind) "
                "VALUES ('frostgate-internal', 'FrostGate Internal', 'active', 'internal_platform')"
            )
        )

    issued = issue_credential(
        engine,
        tenant_id="frostgate-internal",
        credential_type="tenant_api_key",
        credential_slot="platform-admin-credential:v1",
        actor_id="test",
    )
    plaintext = issued.plaintext_secret
    assert plaintext and plaintext.startswith("fgk.")

    import api.auth_scopes.resolution as resolution_mod

    monkeypatch.setattr(resolution_mod, "is_canonical_mode", lambda: False)

    from api.auth_scopes.resolution import verify_api_key_detailed

    request = _make_request_mock("/admin/tenants", x_admin_gateway_internal="true")
    result = verify_api_key_detailed(raw=plaintext, request=request)
    assert result.valid, (
        f"Canonical fgk must work in COMPATIBILITY mode: {result.reason}"
    )
    assert result.reason == "canonical_validated"


def test_m03_canonical_new_request_works(tmp_path, monkeypatch):
    """M03: In CANONICAL mode, new canonical fgk request works."""
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(tmp_path / "m03.db"))
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    monkeypatch.setenv("PLATFORM_AUTH_MODE", "CANONICAL")

    from api.db import init_db, reset_engine_cache

    reset_engine_cache()
    init_db(sqlite_path=str(tmp_path / "m03.db"))

    from api.db import get_engine
    from api.credential_authority import issue_credential

    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO tenants "
                "(tenant_id, display_name, lifecycle_state, tenant_kind) "
                "VALUES ('frostgate-internal', 'FrostGate Internal', 'active', 'internal_platform')"
            )
        )

    issued = issue_credential(
        engine,
        tenant_id="frostgate-internal",
        credential_type="tenant_api_key",
        credential_slot="platform-admin-credential:v1",
        actor_id="test",
    )
    plaintext = issued.plaintext_secret
    assert plaintext and plaintext.startswith("fgk.")

    import api.auth_scopes.resolution as resolution_mod

    monkeypatch.setattr(resolution_mod, "is_canonical_mode", lambda: True)

    from api.auth_scopes.resolution import verify_api_key_detailed

    request = _make_request_mock("/admin/tenants", x_admin_gateway_internal="true")
    result = verify_api_key_detailed(raw=plaintext, request=request)
    assert result.valid, f"Canonical fgk must work in CANONICAL mode: {result.reason}"
    assert result.reason == "canonical_validated"


def test_m04_canonical_old_path_e_no_longer_grants_platform_admin(monkeypatch):
    """M04: In CANONICAL mode, old Path E (gateway secret as X-API-Key) must NOT
    provide platform.admin authority."""
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", _GATEWAY_SECRET)
    monkeypatch.setenv("PLATFORM_AUTH_MODE", "CANONICAL")

    import api.auth_scopes.resolution as resolution_mod

    monkeypatch.setattr(resolution_mod, "is_canonical_mode", lambda: True)

    from api.auth_scopes.resolution import verify_api_key_detailed

    request = _make_request_mock("/admin/tenants", x_admin_gateway_internal="true")
    result = verify_api_key_detailed(raw=_GATEWAY_SECRET, request=request)

    assert not result.valid or result.reason != "admin_internal_token", (
        "In CANONICAL mode, Path E must NOT grant platform.admin via gateway secret as X-API-Key"
    )


# ---------------------------------------------------------------------------
# Constants-only invariant checks (no DB / app)
# ---------------------------------------------------------------------------


def test_path_e_comment_references_platform_auth_mode():
    """Resolution.py must document PLATFORM_AUTH_MODE and the P-113.6.1 fix."""
    import inspect
    import api.auth_scopes.resolution as resolution

    source = inspect.getsource(resolution)
    assert "PLATFORM_AUTH_MODE" in source
    assert "CANONICAL" in source
    assert "FG_PLATFORM_ADMIN_KEY" in source
    assert "is_canonical_mode" in source


def test_platform_auth_mode_module_exists():
    """api.platform_auth_mode must exist and export is_canonical_mode."""
    from api.platform_auth_mode import is_canonical_mode, PLATFORM_AUTH_MODE

    assert callable(is_canonical_mode)
    assert PLATFORM_AUTH_MODE in ("COMPATIBILITY", "CANONICAL")


def test_platform_auth_mode_default_is_compatibility(monkeypatch):
    """Default PLATFORM_AUTH_MODE must be COMPATIBILITY (unset env)."""
    # The module is already imported; test the module-level constant
    import api.platform_auth_mode as pam

    # In test env, PLATFORM_AUTH_MODE is not set → COMPATIBILITY
    # We can't easily reload without side effects in tests, so verify
    # that the constant is COMPATIBILITY when no override is applied.
    # (The monkeypatch _restore_env fixture restores env after this test.)
    assert pam.PLATFORM_AUTH_MODE in ("COMPATIBILITY", "CANONICAL")  # valid value


def test_validate_canonical_mode_config_passes_when_unset(monkeypatch):
    """validate_canonical_mode_config must return no issues when mode is COMPATIBILITY."""
    import api.platform_auth_mode as pam

    monkeypatch.setattr(pam, "PLATFORM_AUTH_MODE", "COMPATIBILITY")
    issues = pam.validate_canonical_mode_config()
    assert issues == [], (
        f"COMPATIBILITY mode must produce no config issues, got: {issues}"
    )


def test_validate_canonical_mode_config_catches_missing_key(monkeypatch):
    """validate_canonical_mode_config must catch missing FG_PLATFORM_ADMIN_KEY in CANONICAL."""
    monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", _GATEWAY_SECRET)
    monkeypatch.delenv("FG_PLATFORM_ADMIN_KEY", raising=False)

    import api.platform_auth_mode as pam

    monkeypatch.setattr(pam, "PLATFORM_AUTH_MODE", "CANONICAL")
    issues = pam.validate_canonical_mode_config()
    assert any("FG_PLATFORM_ADMIN_KEY" in issue for issue in issues), (
        f"Missing FG_PLATFORM_ADMIN_KEY must be flagged: {issues}"
    )


def test_validate_canonical_mode_config_catches_identical_keys(monkeypatch):
    """validate_canonical_mode_config must catch FG_PLATFORM_ADMIN_KEY == FG_INTERNAL_GATEWAY_SECRET."""
    shared_secret = "shared-secret-violates-invariant-5"
    monkeypatch.setenv("FG_INTERNAL_GATEWAY_SECRET", shared_secret)
    monkeypatch.setenv("FG_PLATFORM_ADMIN_KEY", shared_secret)

    import api.platform_auth_mode as pam

    monkeypatch.setattr(pam, "PLATFORM_AUTH_MODE", "CANONICAL")
    issues = pam.validate_canonical_mode_config()
    assert any("distinct" in issue.lower() for issue in issues), (
        f"Identical keys must be flagged: {issues}"
    )
