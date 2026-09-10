"""P1-01-PR2 — Canonical Delegation acceptance matrix.

Proves the FrostGate authority chain is fail-closed on the FIAP path:

    provider validates JWT (external authentication)
        → CanonicalIdentity (identity anchor only)
        → TenantResolver reads canonical tenant_users membership row
        → canonical role → derived permissions
        → AuthorizationContext
        → ActorContext (backwards-compat)
        → permission enforcement

Architectural law enforced here (P1-01-PR2 canonical-delegation invariant):
    EXTERNAL IDENTITY PROVIDERS AUTHENTICATE.  FROSTGATE AUTHORIZES.
    JWT-declared roles or tenant_id NEVER confer authority for OIDC/human
    identities.  Only a canonical ``tenant_users`` membership row does.

Acceptance cases (21 total, matches the P1-01-PR2 test-matrix requirements):

POSITIVE (canonical-happy path):
    1. Valid FIAP-authenticated actor is accepted (identity anchor preserved)
    2. Valid canonical principal binding (tenant_users row) confers authority
    3. Valid active tenant membership resolves to the correct tenant
    4. Valid delegation returns the canonical role
    5. Required auth scope (a FrostGate permission) present after resolution
    6. Authorized same-tenant operation succeeds

NEGATIVE (fail-closed):
    7. FIAP actor without any canonical membership row → no authority
    8. Cross-tenant hint denied
    9. Foreign principal (bound to tenant B, called on tenant A) denied
    10. Inactive / revoked membership denied
    11. Missing required permission denied
    12. Malformed scope / permission denied
    13. Unknown scope / permission denied
    14. Caller-supplied elevated JWT role cannot escalate
    15. Caller-supplied actor / principal cannot override authenticated subject
    16. Tenant-admin JWT cannot manufacture platform-admin authority
    17. Delegated actor cannot exceed the canonical role's permission set
    18. Provider choice (auth0 vs entra) does not alter authorization truth

DETERMINISM:
    19. Scope ordering does not change authorization
    20. Duplicate scopes do not increase authority
    21. Repeated evaluation yields the same result
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from unittest.mock import MagicMock

import pytest

from api.actor_context import ALL_PERMISSIONS, roles_to_permissions
from api.identity_authority.authority import IdentityAuthority
from api.identity_authority.models import (
    AuthenticationContext,
    AuthorizationContext,
    CanonicalIdentity,
    IdentityProvider,
    TenantBinding,
)
from api.identity_authority.tenant_resolver import TenantResolver

_ISSUER_A = "https://tenant-a.auth0.com/"
_ISSUER_ENTRA = "https://login.microsoftonline.com/tid-x/v2.0"
_SUBJECT_A = "auth0|user-alpha-001"
_SUBJECT_B = "auth0|user-beta-001"
_TENANT_A = "tenant-alpha"
_TENANT_B = "tenant-beta"


def _now():
    return datetime.now(tz=timezone.utc)


def _make_identity(
    *,
    subject: str = _SUBJECT_A,
    provider_name: str = "auth0",
    issuer: str = _ISSUER_A,
    identity_type: str = "human",
    tenant_binding: Optional[TenantBinding] = None,
    email: str = "alpha@example.com",
    name: str = "Alpha",
) -> CanonicalIdentity:
    now = _now()
    return CanonicalIdentity(
        subject=subject,
        email=email,
        name=name,
        email_verified=True,
        provider=IdentityProvider(name=provider_name, issuer=issuer, subject=subject),
        auth_context=AuthenticationContext(
            mfa_verified=True,
            mfa_method="totp",
            auth_time=now,
            amr=["mfa", "otp"],
            acr=None,
            pkce_used=True,
            nonce_verified=True,
        ),
        tenant_binding=tenant_binding,
        subscription=None,
        identity_type=identity_type,  # type: ignore[arg-type]
        issued_at=now,
        expires_at=now,
    )


def _binding(tenant_id: str, role: str) -> TenantBinding:
    return TenantBinding(
        tenant_id=tenant_id,
        organization_id=None,
        membership_id=f"mid-{tenant_id}-{role}",
        roles=frozenset({role}),
        permissions=roles_to_permissions([role]),
    )


def _jwt_declared_binding(tenant_id: str, roles: frozenset[str]) -> TenantBinding:
    """A JWT-declared binding: as if the IdP put roles+tenant into the token."""
    return TenantBinding(
        tenant_id=tenant_id,
        organization_id=None,
        membership_id=None,
        roles=roles,
        permissions=roles_to_permissions(list(roles)),
    )


class _StubRegistry:
    def __init__(self, identity: CanonicalIdentity) -> None:
        self._identity = identity

    def resolve_jwt(self, token: str) -> CanonicalIdentity:  # noqa: ARG002
        return self._identity


class _StubResolver:
    def __init__(self, binding: Optional[TenantBinding]) -> None:
        self._binding = binding
        self.calls: list[dict] = []

    def resolve(
        self,
        *,
        identity: CanonicalIdentity,
        db,
        tenant_id_hint: Optional[str] = None,
    ) -> Optional[TenantBinding]:
        self.calls.append(
            {
                "identity_type": identity.identity_type,
                "provider": identity.provider.name,
                "subject": identity.subject,
                "hint": tenant_id_hint,
            }
        )
        return self._binding


def _authority(
    identity: CanonicalIdentity,
    resolver_binding: Optional[TenantBinding],
) -> IdentityAuthority:
    registry = _StubRegistry(identity)
    resolver = _StubResolver(resolver_binding)
    session_authority = MagicMock()
    auditor = MagicMock()
    return IdentityAuthority(
        provider_registry=registry,  # type: ignore[arg-type]
        session_authority=session_authority,
        tenant_resolver=resolver,  # type: ignore[arg-type]
        auditor=auditor,
    )


# ---------------------------------------------------------------------------
# POSITIVE cases 1–6
# ---------------------------------------------------------------------------


def test_case1_valid_fiap_actor_identity_anchor_preserved() -> None:
    """A FIAP-authenticated actor with a canonical membership is accepted;
    the identity anchor (subject / email) is preserved for audit attribution.
    """
    identity = _make_identity()
    canonical = _binding(_TENANT_A, "assessor")
    authority = _authority(identity, canonical)

    ctx = authority.authenticate_jwt("token", db=MagicMock())

    assert isinstance(ctx, AuthorizationContext)
    assert ctx.identity.subject == _SUBJECT_A
    assert ctx.identity.email == "alpha@example.com"
    assert ctx.tenant_id == _TENANT_A


def test_case2_canonical_principal_binding_confers_authority() -> None:
    """Only the canonical resolver's binding produces permissions.

    A JWT arriving without ANY tenant_binding is still authorized when
    the canonical resolver (which reads ``tenant_users``) returns a
    binding — that binding is the sole source of truth.
    """
    identity = _make_identity(tenant_binding=None)
    canonical = _binding(_TENANT_A, "tenant_admin")
    authority = _authority(identity, canonical)

    ctx = authority.authenticate_jwt("token", db=MagicMock())

    assert ctx.tenant_id == _TENANT_A
    assert "tenant.configure" in ctx.permissions
    assert ctx.identity.tenant_binding is not None
    assert ctx.identity.tenant_binding.membership_id == canonical.membership_id


def test_case3_active_tenant_membership_resolves() -> None:
    identity = _make_identity()
    canonical = _binding(_TENANT_A, "viewer")
    authority = _authority(identity, canonical)
    ctx = authority.authenticate_jwt("token", db=MagicMock())
    assert ctx.tenant_id == _TENANT_A
    assert "assessment.read" in ctx.permissions


def test_case4_valid_delegation_returns_canonical_role() -> None:
    identity = _make_identity()
    canonical = _binding(_TENANT_A, "compliance_reviewer")
    authority = _authority(identity, canonical)
    ctx = authority.authenticate_jwt("token", db=MagicMock())
    binding = ctx.identity.tenant_binding
    assert binding is not None
    assert "compliance_reviewer" in binding.roles
    # Compliance can accept risk (canonical role permission).
    assert "risk.accept" in ctx.permissions


def test_case5_required_permission_present_after_resolution() -> None:
    identity = _make_identity()
    canonical = _binding(_TENANT_A, "qa_reviewer")
    authority = _authority(identity, canonical)
    ctx = authority.authenticate_jwt("token", db=MagicMock())
    assert ctx.has_permission("finding.approve") is True


def test_case6_authorized_same_tenant_operation_succeeds() -> None:
    identity = _make_identity()
    canonical = _binding(_TENANT_A, "assessor")
    authority = _authority(identity, canonical)
    ctx = authority.authenticate_jwt("token", tenant_id_hint=_TENANT_A, db=MagicMock())
    assert ctx.tenant_id == _TENANT_A


# ---------------------------------------------------------------------------
# NEGATIVE cases 7–18
# ---------------------------------------------------------------------------


def test_case7_fiap_actor_without_canonical_membership_denied() -> None:
    """The vulnerability P1-01-PR2 closes.

    A FIAP-authenticated OIDC/human identity whose JWT carries a
    tenant_binding (e.g. IdP wrote ``roles=["platform_admin"]`` into the
    token) but NO canonical ``tenant_users`` row exists → zero authority.
    """
    hostile = _jwt_declared_binding(_TENANT_A, frozenset({"platform_admin"}))
    identity = _make_identity(tenant_binding=hostile)
    authority = _authority(identity, resolver_binding=None)

    ctx = authority.authenticate_jwt("token", db=MagicMock())

    assert ctx.tenant_id is None
    assert ctx.permissions == frozenset()
    # JWT-declared binding is scrubbed off the identity.
    assert ctx.identity.tenant_binding is None
    # Identity anchor preserved for audit even under denial.
    assert ctx.identity.subject == _SUBJECT_A


def test_case8_wrong_tenant_hint_denied() -> None:
    """A caller-supplied X-Tenant-Id hint that disagrees with the canonical
    binding is not permitted to override authority — resolver ignores the hint
    and canonical binding wins.  (Cross-tenant escalation defense.)
    """
    identity = _make_identity()
    canonical = _binding(_TENANT_A, "tenant_admin")
    authority = _authority(identity, canonical)
    ctx = authority.authenticate_jwt("token", tenant_id_hint=_TENANT_B, db=MagicMock())
    # Canonical wins.
    assert ctx.tenant_id == _TENANT_A


def test_case9_foreign_principal_denied() -> None:
    """A JWT claiming tenant B but with a canonical membership in tenant A
    is bound to tenant A only — JWT claim of tenant B is ignored.
    """
    hostile = _jwt_declared_binding(_TENANT_B, frozenset({"platform_admin"}))
    identity = _make_identity(tenant_binding=hostile)
    canonical = _binding(_TENANT_A, "viewer")
    authority = _authority(identity, canonical)

    ctx = authority.authenticate_jwt("token", db=MagicMock())

    # Canonical binding wins; JWT-declared tenant B and role are discarded.
    assert ctx.tenant_id == _TENANT_A
    assert "platform.admin" not in ctx.permissions
    # Viewer-only permissions.
    assert "assessment.read" in ctx.permissions
    assert "tenant.configure" not in ctx.permissions


def test_case10_inactive_membership_denied() -> None:
    """Resolver returns None when the membership row is inactive / revoked
    (enforced by ``_resolve_by_membership`` filter ``active.is_(True)``).
    An OIDC identity in that state has no authority even if the JWT still
    contains roles.
    """
    hostile = _jwt_declared_binding(_TENANT_A, frozenset({"tenant_admin"}))
    identity = _make_identity(tenant_binding=hostile)
    authority = _authority(identity, resolver_binding=None)  # inactive → None
    ctx = authority.authenticate_jwt("token", db=MagicMock())
    assert ctx.tenant_id is None
    assert ctx.permissions == frozenset()


def test_case11_missing_required_permission_denied() -> None:
    """Canonical role does not grant the required permission → denial."""
    identity = _make_identity()
    canonical = _binding(_TENANT_A, "viewer")
    authority = _authority(identity, canonical)
    ctx = authority.authenticate_jwt("token", db=MagicMock())

    # Viewer role does not carry risk.accept (compliance-only permission).
    assert ctx.has_permission("risk.accept") is False


def test_case12_malformed_permission_string_denied() -> None:
    """Malformed permission names never match — checking them is fail-closed."""
    identity = _make_identity()
    canonical = _binding(_TENANT_A, "tenant_admin")
    authority = _authority(identity, canonical)
    ctx = authority.authenticate_jwt("token", db=MagicMock())

    # tenant_admin has a rich permission set but no malformed one.
    assert ctx.has_permission("") is False
    assert ctx.has_permission("*") is False
    assert ctx.has_permission("platform.admin;drop table") is False
    assert ctx.has_permission("PLATFORM.ADMIN") is False  # case-sensitive


def test_case13_unknown_permission_denied() -> None:
    """A permission name not in ALL_PERMISSIONS never matches."""
    identity = _make_identity()
    canonical = _binding(_TENANT_A, "platform_admin")
    authority = _authority(identity, canonical)
    ctx = authority.authenticate_jwt("token", db=MagicMock())

    assert ctx.has_permission("fictional.permission") is False


def test_case14_caller_supplied_elevated_jwt_role_cannot_escalate() -> None:
    """A JWT with roles=["platform_admin"] but a canonical role of "viewer"
    is treated as a viewer — the JWT role is ignored entirely.
    """
    hostile = _jwt_declared_binding(_TENANT_A, frozenset({"platform_admin"}))
    identity = _make_identity(tenant_binding=hostile)
    canonical = _binding(_TENANT_A, "viewer")
    authority = _authority(identity, canonical)

    ctx = authority.authenticate_jwt("token", db=MagicMock())

    assert "platform.admin" not in ctx.permissions
    assert "tenant.configure" not in ctx.permissions
    # But viewer-baseline is still granted.
    assert "assessment.read" in ctx.permissions


def test_case15_caller_supplied_actor_cannot_override_authenticated_subject() -> None:
    """The authenticated subject on the returned context is the JWT ``sub`` —
    it is not read from any body / hint / header. The resolver receives the
    same identity anchor.
    """
    hostile = _jwt_declared_binding(_TENANT_A, frozenset({"platform_admin"}))
    identity = _make_identity(
        subject=_SUBJECT_A,
        tenant_binding=hostile,
    )
    canonical = _binding(_TENANT_A, "assessor")
    authority = _authority(identity, canonical)

    # tenant_id_hint attempts to smuggle authority
    ctx = authority.authenticate_jwt("token", tenant_id_hint=_TENANT_B, db=MagicMock())

    # Subject anchor comes from authenticated identity, NOT hint.
    assert ctx.identity.subject == _SUBJECT_A


def test_case16_tenant_admin_jwt_cannot_manufacture_platform_admin() -> None:
    """A JWT declares roles=["platform_admin"] but canonical role is
    tenant_admin → context holds tenant_admin permissions ONLY, not
    ALL_PERMISSIONS.  This is the concrete privilege-amplification defense.
    """
    hostile = _jwt_declared_binding(_TENANT_A, frozenset({"platform_admin"}))
    identity = _make_identity(tenant_binding=hostile)
    canonical = _binding(_TENANT_A, "tenant_admin")
    authority = _authority(identity, canonical)

    ctx = authority.authenticate_jwt("token", db=MagicMock())

    # tenant_admin gets its own set …
    assert "tenant.configure" in ctx.permissions
    # … but NEVER inherits platform.admin from a JWT-declared role.
    assert "platform.admin" not in ctx.permissions
    # And is NOT the platform-admin superset.
    assert ctx.permissions != ALL_PERMISSIONS


def test_case17_delegated_actor_cannot_exceed_canonical_role_set() -> None:
    """A JWT could declare 10 roles; only the roles from the canonical row
    contribute permissions.
    """
    hostile_roles = frozenset(
        {"platform_admin", "compliance_reviewer", "tenant_admin", "qa_reviewer"}
    )
    hostile = _jwt_declared_binding(_TENANT_A, hostile_roles)
    identity = _make_identity(tenant_binding=hostile)
    canonical = _binding(_TENANT_A, "assessor")  # canonical says assessor only
    authority = _authority(identity, canonical)

    ctx = authority.authenticate_jwt("token", db=MagicMock())

    assessor_perms = roles_to_permissions(["assessor"])
    # Canonical set == assessor set exactly. No inflation from JWT roles.
    assert ctx.permissions == assessor_perms


def test_case18_provider_choice_does_not_change_authorization_truth() -> None:
    """The provider (auth0 vs entra) authenticates; canonical delegation
    authorizes.  Same canonical binding → same permissions regardless of
    provider.
    """
    canonical = _binding(_TENANT_A, "assessor")

    auth0 = _make_identity(provider_name="auth0", issuer=_ISSUER_A)
    entra = _make_identity(
        provider_name="entra",
        issuer=_ISSUER_ENTRA,
        subject="entra|oid-001",
        email="entra@example.com",
    )

    ctx_auth0 = _authority(auth0, canonical).authenticate_jwt("t1", db=MagicMock())
    ctx_entra = _authority(entra, canonical).authenticate_jwt("t2", db=MagicMock())

    assert ctx_auth0.permissions == ctx_entra.permissions
    assert ctx_auth0.tenant_id == ctx_entra.tenant_id == _TENANT_A


# ---------------------------------------------------------------------------
# DETERMINISM cases 19–21
# ---------------------------------------------------------------------------


def test_case19_permission_check_order_independent() -> None:
    """``has_permission(a, b)`` is order-agnostic: same result for any
    ordering. Guarantees scope-ordering cannot alter authorization.
    """
    identity = _make_identity()
    canonical = _binding(_TENANT_A, "compliance_reviewer")
    authority = _authority(identity, canonical)
    ctx = authority.authenticate_jwt("token", db=MagicMock())

    perms = ["governance.read", "risk.accept", "finding.read"]
    a = ctx.has_permission(*perms)
    b = ctx.has_permission(*perms[::-1])
    c = ctx.has_permission(*sorted(perms))
    assert a is True
    assert a == b == c


def test_case20_duplicate_permissions_do_not_amplify() -> None:
    """Duplicate permission entries in a required list do not increase
    authority; ``has_permission`` uses set semantics.
    """
    identity = _make_identity()
    canonical = _binding(_TENANT_A, "viewer")
    authority = _authority(identity, canonical)
    ctx = authority.authenticate_jwt("token", db=MagicMock())

    # Viewer has assessment.read; duplicates just re-check that permission.
    assert (
        ctx.has_permission("assessment.read")
        == ctx.has_permission("assessment.read", "assessment.read")
        == ctx.has_permission("assessment.read", "assessment.read", "assessment.read")
        is True
    )
    # Viewer does not have risk.accept; duplicates cannot grant it.
    assert (
        ctx.has_permission("risk.accept")
        == ctx.has_permission("risk.accept", "risk.accept")
        is False
    )


def test_case21_repeated_evaluation_is_deterministic() -> None:
    """Same identity + same canonical resolver output → same authorization
    context on repeat evaluation.
    """
    identity = _make_identity()
    canonical = _binding(_TENANT_A, "tenant_admin")
    authority = _authority(identity, canonical)

    ctx1 = authority.authenticate_jwt("token", db=MagicMock())
    ctx2 = authority.authenticate_jwt("token", db=MagicMock())
    ctx3 = authority.authenticate_jwt("token", db=MagicMock())

    assert ctx1.permissions == ctx2.permissions == ctx3.permissions
    assert ctx1.tenant_id == ctx2.tenant_id == ctx3.tenant_id
    assert ctx1.identity.subject == ctx2.identity.subject == ctx3.identity.subject


# ---------------------------------------------------------------------------
# Additional TenantResolver-level defence tests (unit-level, no authority stub)
# ---------------------------------------------------------------------------


class TestResolverHintFailClosed:
    """P1-01-PR2: ``TenantResolver._resolve_by_hint`` must fail closed for
    OIDC/human identities regardless of whether the hint matches or not.
    """

    def setup_method(self) -> None:
        self.resolver = TenantResolver()
        self.db = MagicMock()

    def test_oidc_human_matching_hint_returns_none(self) -> None:
        binding = _jwt_declared_binding(_TENANT_A, frozenset({"platform_admin"}))
        identity = _make_identity(tenant_binding=binding)
        result = self.resolver._resolve_by_hint(_TENANT_A, identity, self.db)
        assert result is None

    def test_oidc_human_mismatching_hint_returns_none(self) -> None:
        binding = _jwt_declared_binding(_TENANT_A, frozenset({"viewer"}))
        identity = _make_identity(tenant_binding=binding)
        result = self.resolver._resolve_by_hint(_TENANT_B, identity, self.db)
        assert result is None

    def test_oidc_human_no_jwt_binding_returns_none(self) -> None:
        identity = _make_identity(tenant_binding=None)
        result = self.resolver._resolve_by_hint(_TENANT_A, identity, self.db)
        assert result is None

    def test_machine_matching_hint_returns_credential_binding(self) -> None:
        from dataclasses import replace

        binding = _binding(_TENANT_A, "viewer")
        identity = _make_identity(
            subject="machine|k1",
            provider_name="api_key",
            tenant_binding=binding,
        )
        identity = replace(identity, identity_type="machine")
        result = self.resolver._resolve_by_hint(_TENANT_A, identity, self.db)
        assert result is binding

    def test_machine_mismatching_hint_denies(self) -> None:
        from dataclasses import replace

        binding = _binding(_TENANT_A, "viewer")
        identity = _make_identity(
            subject="machine|k1",
            provider_name="api_key",
            tenant_binding=binding,
        )
        identity = replace(identity, identity_type="machine")
        result = self.resolver._resolve_by_hint(_TENANT_B, identity, self.db)
        assert result is None

    def test_machine_without_credential_binding_returns_none(self) -> None:
        """A machine identity without a credential-authority-validated
        binding cannot manufacture one from a hint.  Pre-fix behavior
        fabricated a TenantBinding from the hint alone.
        """
        from dataclasses import replace

        identity = _make_identity(
            subject="machine|k1",
            provider_name="api_key",
            tenant_binding=None,
        )
        identity = replace(identity, identity_type="machine")
        result = self.resolver._resolve_by_hint(_TENANT_A, identity, self.db)
        assert result is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
