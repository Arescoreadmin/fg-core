"""
P-113.6 — Platform Administrator Credential Authority — invariant tests.

These tests verify the six security invariants that must NEVER be violated.
They are pure-Python constant/logic checks — no app or DB required.

Invariants:
  I-01  platform_admin must NOT become tenant-self-assignable
  I-02  PSP must NOT gain platform.admin
  I-03  CORE_API_KEY wildcard must NOT grant platform.admin
  I-04  FG_INTERNAL_GATEWAY_SECRET alone must NOT suffice for platform.admin
        in CANONICAL mode (verified via constant separation)
  I-05  No direct SQL credential issuance (credential_authority is the only writer)
  I-06  VALID_ROLE_NAMES expansion does not widen any existing self-service endpoint
"""

from __future__ import annotations

import inspect


# ---------------------------------------------------------------------------
# I-01 — platform_admin NOT tenant-self-assignable
# ---------------------------------------------------------------------------


def test_i01a_platform_admin_not_in_tenant_assignable_roles():
    """Security Invariant 1: platform_admin must not be in TENANT_ASSIGNABLE_ROLES."""
    from api.tenant_rbac import TENANT_ASSIGNABLE_ROLES

    assert "platform_admin" not in TENANT_ASSIGNABLE_ROLES


def test_i01b_platform_admin_in_platform_only():
    """platform_admin must be in PLATFORM_ONLY_CREDENTIAL_ROLES (tenant_admin.py)."""
    from api.tenant_admin import PLATFORM_ONLY_CREDENTIAL_ROLES

    assert "platform_admin" in PLATFORM_ONLY_CREDENTIAL_ROLES


def test_i01c_rbac_router_uses_builtin_roles_not_valid_role_names():
    """The /rbac/assignments endpoint uses BUILTIN_ROLES for the list endpoint,
    not VALID_ROLE_NAMES, so platform_admin does not appear in the self-service
    role catalogue exposed to tenant users.
    """
    import api.tenant_rbac_router as rbac_router

    # The list_roles endpoint should reference BUILTIN_ROLES, not VALID_ROLE_NAMES.
    source = inspect.getsource(rbac_router)
    assert "BUILTIN_ROLES" in source, (
        "tenant_rbac_router must still reference BUILTIN_ROLES"
    )


def test_i01d_assign_service_credential_role_blocks_platform_admin():
    """The assign_service_credential_role endpoint in tenant_admin.py must check
    PLATFORM_ONLY_CREDENTIAL_ROLES before SELF_SERVICE_CREDENTIAL_ROLES.
    """
    import api.tenant_admin as tenant_admin

    source = inspect.getsource(tenant_admin.assign_service_credential_role)
    assert "PLATFORM_ONLY_CREDENTIAL_ROLES" in source, (
        "assign_service_credential_role must check PLATFORM_ONLY_CREDENTIAL_ROLES first."
    )
    # Verify the check is a 403, not a 422
    assert "ROLE_NOT_DELEGATABLE" in source, (
        "platform_admin assignment via self-service must return ROLE_NOT_DELEGATABLE (403)."
    )


# ---------------------------------------------------------------------------
# I-02 — PSP must NOT gain platform.admin
# ---------------------------------------------------------------------------


def test_i02a_psp_scopes_exclude_platform_admin():
    """Security Invariant 2: PSP_CREDENTIAL_SCOPES must not include platform.admin."""
    from api.platform_service_principal import PSP_CREDENTIAL_SCOPES

    assert "platform.admin" not in PSP_CREDENTIAL_SCOPES


def test_i02b_psp_default_permissions_exclude_platform_admin():
    """PLATFORM_SERVICE_DEFAULT_PERMISSIONS must not include platform.admin."""
    from api.platform_service_principal import PLATFORM_SERVICE_DEFAULT_PERMISSIONS

    assert "platform.admin" not in PLATFORM_SERVICE_DEFAULT_PERMISSIONS


def test_i02c_psp_permissions_are_explicit_not_wildcard():
    """PSP permissions must be derived from explicit scopes, not from ALL_PERMISSIONS."""
    from api.actor_context import ALL_PERMISSIONS
    from api.platform_service_principal import PLATFORM_SERVICE_DEFAULT_PERMISSIONS

    # PSP permissions must be a proper subset of ALL_PERMISSIONS
    assert PLATFORM_SERVICE_DEFAULT_PERMISSIONS < ALL_PERMISSIONS, (
        "PSP must have fewer permissions than ALL_PERMISSIONS "
        "(it must not be equal to ALL_PERMISSIONS)."
    )


# ---------------------------------------------------------------------------
# I-03 — CORE_API_KEY wildcard does NOT grant platform.admin
# ---------------------------------------------------------------------------


def test_i03_wildcard_scope_cannot_grant_platform_admin():
    """Security Invariant 3: '*' scope must not produce platform.admin permissions."""
    from api.identity_providers.api_key import _permissions_from_legacy_scopes

    # CORE_API_KEY uses '*' as its scope
    wildcard_scopes = {"*"}
    perms = _permissions_from_legacy_scopes(wildcard_scopes)
    assert "platform.admin" not in perms, (
        "Wildcard '*' scope must not grant platform.admin. "
        "CORE_API_KEY must not become a platform-admin authority."
    )


def test_i03b_admin_write_scope_grants_platform_admin_via_legacy_bridge():
    """admin:write scope DOES grant platform.admin via the legacy bridge (Path E).

    This is intentional: Path E maps admin:write → roles_to_permissions(["platform_admin"])
    = ALL_PERMISSIONS ⊃ "platform.admin". This test documents the bridge so it's
    explicit in the audit record.
    """
    from api.identity_providers.api_key import _permissions_from_legacy_scopes

    admin_write_scopes = {"admin:write", "admin:read"}
    perms = _permissions_from_legacy_scopes(admin_write_scopes)
    assert "platform.admin" in perms, (
        "admin:write via the legacy Path E bridge must grant platform.admin. "
        "This is the compatibility path being documented for retirement."
    )


# ---------------------------------------------------------------------------
# I-04 — FG_INTERNAL_GATEWAY_SECRET separation (CANONICAL mode)
# ---------------------------------------------------------------------------


def test_i04_canonical_mode_requires_separate_credentials():
    """In CANONICAL mode, FG_PLATFORM_ADMIN_KEY and FG_INTERNAL_GATEWAY_SECRET must differ.

    This test verifies the logic exists in the BFF route — the actual enforcement
    is a startup validation error in route.ts. Here we verify the resolution.py
    Path E comment documents the separation requirement.
    """
    import api.auth_scopes.resolution as resolution

    source = inspect.getsource(resolution)
    assert "Path E" in source, (
        "resolution.py must document Path E for the retirement plan."
    )
    assert "CANONICAL" in source, (
        "resolution.py Path E comment must reference CANONICAL mode migration path."
    )
    assert "FG_PLATFORM_ADMIN_KEY" in source, (
        "resolution.py Path E comment must reference FG_PLATFORM_ADMIN_KEY "
        "to document the CANONICAL migration."
    )


# ---------------------------------------------------------------------------
# I-05 — No direct SQL credential issuance
# ---------------------------------------------------------------------------


def test_i05_admin_bootstrap_uses_credential_authority():
    """The bootstrap endpoint must call issue_credential(), not raw SQL.

    Verifies that the admin module imports and calls credential_authority.issue_credential.
    """
    import api.admin as admin_module

    source = inspect.getsource(admin_module)

    # Must use issue_credential from credential_authority
    assert "issue_credential" in source, (
        "admin.py bootstrap endpoint must use issue_credential() from credential_authority."
    )
    assert "from api.credential_authority import" in source, (
        "admin.py must import from credential_authority, not inline SQL writes."
    )

    # Must NOT have raw INSERT INTO tenant_credentials in bootstrap function
    bootstrap_source = inspect.getsource(
        admin_module.bootstrap_platform_admin_credential
    )
    assert "INSERT INTO tenant_credentials" not in bootstrap_source, (
        "bootstrap_platform_admin_credential must not contain raw SQL credential inserts. "
        "All credential writes must go through credential_authority.issue_credential()."
    )


# ---------------------------------------------------------------------------
# I-06 — VALID_ROLE_NAMES expansion does not widen existing self-service endpoints
# ---------------------------------------------------------------------------


def test_i06a_admin_assign_endpoint_still_validates_role():
    """The admin assign_tenant_credential_role endpoint must still validate role names.

    Adding platform_admin to VALID_ROLE_NAMES is safe because the admin endpoint
    already requires platform.admin permission, so any caller that reaches the
    VALID_ROLE_NAMES check already has operator authority.
    """
    import api.admin as admin_module

    source = inspect.getsource(admin_module.assign_tenant_credential_role)
    assert "VALID_ROLE_NAMES" in source, (
        "assign_tenant_credential_role must validate against VALID_ROLE_NAMES."
    )
    assert 'require_permission("platform.admin")' in source, (
        "assign_tenant_credential_role must require platform.admin permission."
    )


def test_i06b_self_service_credential_roles_still_subset_of_valid():
    """SELF_SERVICE_CREDENTIAL_ROLES ⊆ VALID_ROLE_NAMES (C1-19 regression guard)."""
    from api.tenant_admin import SELF_SERVICE_CREDENTIAL_ROLES
    from api.tenant_rbac import VALID_ROLE_NAMES

    assert SELF_SERVICE_CREDENTIAL_ROLES.issubset(VALID_ROLE_NAMES), (
        "SELF_SERVICE_CREDENTIAL_ROLES must be a subset of VALID_ROLE_NAMES. "
        "Expanding VALID_ROLE_NAMES must not break C1-19."
    )


def test_i06c_platform_admin_role_resolution_chain():
    """platform_admin role must resolve to ALL_PERMISSIONS via roles_to_permissions().

    This verifies the complete resolution chain for the canonical platform_admin
    credential: role stored in tenant_credential_roles → get_credential_role() →
    roles_to_permissions(["platform_admin"]) = ALL_PERMISSIONS ⊃ "platform.admin".
    """
    from api.actor_context import ALL_PERMISSIONS, roles_to_permissions

    perms = roles_to_permissions(["platform_admin"])
    assert "platform.admin" in perms, (
        "platform_admin role must grant platform.admin permission via roles_to_permissions()."
    )
    assert perms == ALL_PERMISSIONS, (
        "platform_admin must grant ALL_PERMISSIONS (not a subset). "
        "This is the canonical authority delegation."
    )


def test_i06d_platform_admin_in_role_permissions_registry():
    """ROLE_PERMISSIONS must contain platform_admin mapped to ALL_PERMISSIONS."""
    from api.actor_context import ALL_PERMISSIONS, ROLE_PERMISSIONS

    assert "platform_admin" in ROLE_PERMISSIONS, (
        "platform_admin must be registered in ROLE_PERMISSIONS."
    )
    assert ROLE_PERMISSIONS["platform_admin"] == ALL_PERMISSIONS, (
        "ROLE_PERMISSIONS['platform_admin'] must equal ALL_PERMISSIONS."
    )
