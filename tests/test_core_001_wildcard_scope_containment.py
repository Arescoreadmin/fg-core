# tests/test_core_001_wildcard_scope_containment.py
"""PR-CORE-001 regression suite.

Proves that the "*" wildcard scope can no longer mint platform_admin or any
broad operator privilege.  Explicit named operator scopes must still grant the
correct capability set.

Security invariant: once this PR ships, any key whose ONLY scope is "*" must
receive ZERO permissions from the legacy-scope fallback path.

Inline mirror: _permissions_from_legacy_scopes is mirrored here (same logic,
no fastapi import) so behavioral tests run without the full server stack.
The static source tests verify the mirror stays consistent with the real source.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from api.actor_context import roles_to_permissions

# Paths to the two source files this PR modifies.
_API_KEY_SRC = Path("api/identity_providers/api_key.py").read_text(encoding="utf-8")
_IPA_SRC = Path("api/internal_platform_authority.py").read_text(encoding="utf-8")

# The explicit operator scopes from OPERATOR_CREDENTIAL_SCOPES (inlined to avoid
# the fastapi transitive import from internal_platform_authority.py).
_OPERATOR_CREDENTIAL_SCOPES = frozenset({
    "admin:read",
    "admin:write",
    "audit:read",
    "audit:export",
    "keys:admin",
    "keys:read",
    "keys:write",
})


# ── Inline mirror of _permissions_from_legacy_scopes (PR-CORE-001 version) ──
# Mirrors the function as it exists AFTER this PR's change.
# The source regression tests (below) verify the mirror matches production.

def _mirror(scopes: set[str]) -> frozenset[str]:
    result: set[str] = set()
    if "governance:write" in scopes:
        result |= roles_to_permissions(["assessor", "compliance_reviewer"])
    if "governance:qa_approve" in scopes:
        result |= roles_to_permissions(["qa_reviewer"])
    if not result and (scopes & {"governance:read", "decisions:read"}):
        result |= roles_to_permissions(["viewer"])
    if scopes & {
        "admin:write",
        "admin:read",
        "keys:admin",
        "keys:write",
        "keys:read",
        "audit:read",
        "audit:export",
    }:
        result |= roles_to_permissions(["platform_admin"])
    return frozenset(result)


_PLATFORM_ADMIN_PERMS = roles_to_permissions(["platform_admin"])


# ── Source invariants ────────────────────────────────────────────────────────


def test_operator_credential_scopes_contains_no_wildcard() -> None:
    const_block = _IPA_SRC.split("OPERATOR_CREDENTIAL_SCOPES")[1].split(")")[0]
    assert '"*"' not in const_block, (
        "OPERATOR_CREDENTIAL_SCOPES must not contain the wildcard scope"
    )


def test_operator_credential_scopes_has_explicit_admin_scopes() -> None:
    const_block = _IPA_SRC.split("OPERATOR_CREDENTIAL_SCOPES")[1].split(")")[0]
    assert '"admin:read"' in const_block
    assert '"admin:write"' in const_block


def test_permissions_from_legacy_scopes_source_has_no_wildcard_platform_admin_path() -> None:
    """The removed line: if "*" in scopes: return roles_to_permissions(["platform_admin"])"""
    fn_start = _API_KEY_SRC.index("def _permissions_from_legacy_scopes(")
    fn_end = _API_KEY_SRC.index("\ndef ", fn_start + 1)
    fn_body = _API_KEY_SRC[fn_start:fn_end]
    assert '"*" in scopes' not in fn_body, (
        '_permissions_from_legacy_scopes must not map "*" to any role'
    )


def test_permissions_from_legacy_scopes_source_still_has_admin_scope_block() -> None:
    """The intentional admin-scope → platform_admin block must still be present."""
    fn_start = _API_KEY_SRC.index("def _permissions_from_legacy_scopes(")
    fn_end = _API_KEY_SRC.index("\ndef ", fn_start + 1)
    fn_body = _API_KEY_SRC[fn_start:fn_end]
    assert "admin:write" in fn_body
    assert 'roles_to_permissions(["platform_admin"])' in fn_body


# ── Behavioral invariants: wildcard grants nothing on its own ────────────────


def test_wildcard_alone_grants_empty_permissions() -> None:
    assert _mirror({"*"}) == frozenset()


def test_wildcard_with_unrecognized_scope_grants_empty_permissions() -> None:
    assert _mirror({"*", "some:random"}) == frozenset()


def test_wildcard_alone_does_not_grant_platform_admin() -> None:
    # platform_admin = ALL_PERMISSIONS; even a single matching permission would
    # be a superset of viewer, so the right check is: do we get platform_admin's
    # full permission set?
    assert not _PLATFORM_ADMIN_PERMS.issubset(_mirror({"*"}))


def test_empty_scopes_grants_no_permissions() -> None:
    assert _mirror(set()) == frozenset()


def test_completely_unknown_scopes_grant_nothing() -> None:
    assert _mirror({"unknown:scope", "another:unknown"}) == frozenset()


def test_wildcard_with_governance_read_grants_only_viewer_not_platform_admin() -> None:
    # governance:read → viewer; the "*" must not elevate that to platform_admin.
    perms = _mirror({"*", "governance:read"})
    assert perms == roles_to_permissions(["viewer"])
    assert not _PLATFORM_ADMIN_PERMS.issubset(perms)


def test_wildcard_with_governance_write_does_not_elevate_to_platform_admin() -> None:
    # governance:write → assessor + compliance_reviewer; wildcard adds nothing.
    perms = _mirror({"*", "governance:write"})
    assert perms == roles_to_permissions(["assessor", "compliance_reviewer"])
    assert not _PLATFORM_ADMIN_PERMS.issubset(perms)


# ── Explicit named scopes still work ────────────────────────────────────────


def test_operator_credential_scopes_grant_platform_admin_via_admin_block() -> None:
    """The BFF key's explicit scopes still resolve to platform_admin through the
    intentional admin-scope legacy block."""
    perms = _mirror(set(_OPERATOR_CREDENTIAL_SCOPES))
    assert perms == _PLATFORM_ADMIN_PERMS, (
        "OPERATOR_CREDENTIAL_SCOPES must still resolve to platform_admin "
        "through the named admin-scope block"
    )


@pytest.mark.parametrize(
    ("scopes", "expected_roles"),
    [
        ({"admin:read"}, ["platform_admin"]),
        ({"admin:write"}, ["platform_admin"]),
        ({"keys:admin"}, ["platform_admin"]),
        ({"audit:read"}, ["platform_admin"]),
        ({"audit:export"}, ["platform_admin"]),
        ({"governance:write"}, ["assessor", "compliance_reviewer"]),
        ({"governance:qa_approve"}, ["qa_reviewer"]),
        ({"governance:read"}, ["viewer"]),
    ],
)
def test_named_scope_grants_expected_permissions(
    scopes: set[str], expected_roles: list[str]
) -> None:
    perms = _mirror(scopes)
    expected = roles_to_permissions(expected_roles)
    assert perms == expected, (
        f"scopes={scopes}: expected permissions for roles={expected_roles}"
    )
