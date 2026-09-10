"""tests/identity_authority/test_tenant_resolver.py — Tenant resolution tests."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from api.identity_authority.tenant_resolver import TenantResolver


@pytest.fixture
def resolver():
    return TenantResolver()


@pytest.fixture
def mock_db():
    return MagicMock()


def _make_identity(
    *,
    subject="auth0|test",
    provider="auth0",
    issuer="https://test.auth0.com/",
    tenant_binding=None,
):
    from datetime import datetime, timezone
    from api.identity_authority.models import (
        AuthenticationContext,
        CanonicalIdentity,
        IdentityProvider,
    )

    now = datetime.now(tz=timezone.utc)
    return CanonicalIdentity(
        subject=subject,
        email="test@acme.com",
        name="Test User",
        email_verified=True,
        provider=IdentityProvider(name=provider, issuer=issuer, subject=subject),
        auth_context=AuthenticationContext(
            mfa_verified=False,
            mfa_method=None,
            auth_time=now,
            amr=[],
            acr=None,
            pkce_used=False,
            nonce_verified=False,
        ),
        tenant_binding=tenant_binding,
        subscription=None,
        identity_type="human",
        issued_at=now,
        expires_at=now,
    )


def _replace_identity_type(identity, identity_type):
    """Return a copy of ``identity`` with the given ``identity_type``.

    Used to construct machine / service identities for tests that exercise
    the P1-01-PR2 canonical-delegation branch (OIDC/human vs machine paths).
    """
    from dataclasses import replace

    return replace(identity, identity_type=identity_type)


def test_resolve_returns_none_when_no_membership(resolver, mock_db):
    identity = _make_identity()
    with patch(
        "api.identity_authority.tenant_resolver.TenantResolver._resolve_by_membership",
        return_value=None,
    ):
        result = resolver.resolve(identity, mock_db)
    assert result is None


def test_resolve_returns_binding_from_membership(resolver, mock_db, canonical_identity):
    from api.identity_authority.models import TenantBinding

    expected_binding = TenantBinding(
        tenant_id="tenant-123",
        organization_id=None,
        membership_id="member-001",
        roles=frozenset(["assessor"]),
        permissions=frozenset(),
    )
    with patch.object(
        resolver, "_resolve_by_membership", return_value=expected_binding
    ):
        result = resolver.resolve(canonical_identity, mock_db)
    assert result is not None
    assert result.tenant_id == "tenant-123"


def test_resolve_falls_through_to_hint(resolver, mock_db):
    from api.identity_authority.models import TenantBinding

    identity = _make_identity(subject="machine|key1", provider="api_key")
    hint_binding = TenantBinding(
        tenant_id="tenant-from-hint",
        organization_id=None,
        membership_id=None,
        roles=frozenset(),
        permissions=frozenset(),
    )
    with patch.object(resolver, "_resolve_by_membership", return_value=None):
        with patch.object(resolver, "_resolve_by_hint", return_value=hint_binding):
            result = resolver.resolve(
                identity, mock_db, tenant_id_hint="tenant-from-hint"
            )

    assert result is not None
    assert result.tenant_id == "tenant-from-hint"


def test_resolve_by_hint_cross_tenant_denied(resolver, mock_db):
    """P1-01-PR2 invariant: machine identity with credential-bound tenant
    cannot be overridden by a mismatching hint.
    """
    from api.identity_authority.models import TenantBinding

    existing_binding = TenantBinding(
        tenant_id="tenant-a",
        organization_id=None,
        membership_id=None,
        roles=frozenset(),
        permissions=frozenset(),
    )
    identity = _make_identity(
        subject="machine|key1",
        provider="api_key",
        tenant_binding=existing_binding,
    )
    identity = _replace_identity_type(identity, "machine")

    result = resolver._resolve_by_hint("tenant-b", identity, mock_db)
    assert result is None


def test_resolve_by_hint_matching_binding_returned_for_machine(resolver, mock_db):
    """Machine identity: matching hint returns the credential-authority-validated
    binding (which was already produced by the API-key credential authority).
    """
    from api.identity_authority.models import TenantBinding

    existing_binding = TenantBinding(
        tenant_id="tenant-a",
        organization_id=None,
        membership_id=None,
        roles=frozenset(["viewer"]),
        permissions=frozenset(),
    )
    identity = _make_identity(
        subject="machine|key1",
        provider="api_key",
        tenant_binding=existing_binding,
    )
    identity = _replace_identity_type(identity, "machine")

    result = resolver._resolve_by_hint("tenant-a", identity, mock_db)
    assert result is existing_binding


def test_resolve_by_hint_oidc_human_denied_even_when_matching(resolver, mock_db):
    """P1-01-PR2 canonical delegation invariant.

    For OIDC/human identities the JWT-declared tenant_binding is NEVER
    authoritative — even when the caller-supplied hint matches the
    JWT-declared tenant.  Authority for a human identity can only come
    from a canonical ``tenant_users`` membership row resolved by
    :meth:`_resolve_by_membership`.  The hint fallback returns ``None``
    so :meth:`resolve` produces "no authority".

    Pre-fix behavior returned ``identity.tenant_binding`` here — a JWT
    with ``roles=["platform_admin"]`` and a matching ``X-Tenant-Id`` header
    would have been granted platform authority without any DB membership.
    """
    from api.identity_authority.models import TenantBinding

    existing_binding = TenantBinding(
        tenant_id="tenant-a",
        organization_id=None,
        membership_id=None,
        roles=frozenset(["platform_admin"]),
        permissions=frozenset({"platform.admin"}),
    )
    identity = _make_identity(tenant_binding=existing_binding)

    # OIDC/human identity + matching hint → still no authority.
    result = resolver._resolve_by_hint("tenant-a", identity, mock_db)
    assert result is None


def test_resolve_by_hint_machine_without_binding_denied(resolver, mock_db):
    """P1-01-PR2 invariant: a machine identity that lacks a credential-authority-validated
    tenant_binding cannot manufacture one from an ``X-Tenant-Id`` hint alone.
    """
    identity = _make_identity(
        subject="machine|key1",
        provider="api_key",
        tenant_binding=None,
    )
    identity = _replace_identity_type(identity, "machine")

    result = resolver._resolve_by_hint("tenant-a", identity, mock_db)
    assert result is None


def test_resolve_cross_tenant_hint_returns_none_for_machine(resolver, mock_db):
    """P2 fix: TenantResolver.resolve() must return None when a machine identity
    passes a hint that disagrees with its credential-bound tenant — verifying the
    full resolve() path, not just _resolve_by_hint().
    """
    from api.identity_authority.models import TenantBinding

    existing_binding = TenantBinding(
        tenant_id="tenant-a",
        organization_id=None,
        membership_id=None,
        roles=frozenset(["viewer"]),
        permissions=frozenset(),
    )
    identity = _make_identity(
        subject="machine|key1",
        provider="api_key",
        tenant_binding=existing_binding,
    )
    identity = _replace_identity_type(identity, "machine")

    with patch.object(resolver, "_resolve_by_membership", return_value=None):
        result = resolver.resolve(identity, mock_db, tenant_id_hint="tenant-b")

    assert result is None


def test_resolve_membership_import_error_returns_none(resolver, mock_db):
    identity = _make_identity()
    with patch("builtins.__import__", side_effect=ImportError("no admin_gateway")):
        # Should return None gracefully, not raise
        result = resolver._resolve_by_membership(identity, mock_db)
    assert result is None


def test_metrics_recorded_on_resolve(resolver, mock_db, canonical_identity):
    from api.identity_authority.models import TenantBinding

    binding = TenantBinding(
        tenant_id="tenant-123",
        organization_id=None,
        membership_id=None,
        roles=frozenset(["viewer"]),
        permissions=frozenset(),
    )
    with patch.object(resolver, "_resolve_by_membership", return_value=binding):
        resolver.resolve(canonical_identity, mock_db)
    # Metrics are counters/histograms — just assert no exception is raised
