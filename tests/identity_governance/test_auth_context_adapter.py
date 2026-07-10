"""Tests for the AuthorizationContext → ActorContext adapter."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from api.identity_authority.auth_context_adapter import (
    authorization_context_to_actor_context,
)
from api.identity_authority.models import (
    AuthenticationContext,
    AuthorizationContext,
    CanonicalIdentity,
    IdentityProvider,
    IdentitySubscription,
    TenantBinding,
)


NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)


def _make_context(
    *,
    provider_name: str = "auth0",
    tenant_id: str = "tenant-a",
    permissions=frozenset({"assessment.read", "finding.read"}),
    roles=frozenset({"assessor"}),
    identity_type: str = "human",
) -> AuthorizationContext:
    provider = IdentityProvider(
        name=provider_name,
        issuer="https://issuer.example.com",
        subject="sub-123",
    )
    auth_ctx = AuthenticationContext(
        mfa_verified=True,
        mfa_method="webauthn",
        auth_time=NOW,
        amr=["pwd", "mfa"],
        acr="urn:mace:incommon:iap:silver",
        pkce_used=True,
        nonce_verified=True,
    )
    binding = TenantBinding(
        tenant_id=tenant_id,
        organization_id="org-a",
        membership_id="mem-123",
        roles=roles,
        permissions=permissions,
    )
    subscription = IdentitySubscription(
        tier="pro",
        capabilities=frozenset({"assessment.run"}),
        licensed_features=frozenset(),
    )
    identity = CanonicalIdentity(
        subject="sub-123",
        email="user@example.com",
        name="User Name",
        email_verified=True,
        provider=provider,
        auth_context=auth_ctx,
        tenant_binding=binding,
        subscription=subscription,
        identity_type=identity_type,  # type: ignore[arg-type]
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=8),
    )
    return AuthorizationContext(
        identity=identity,
        permissions=permissions,
        capabilities=subscription.capabilities,
        tenant_id=tenant_id,
        organization_id="org-a",
        session_id="sess-1",
        session_risk_score=0.0,
        correlation_id="cid-1",
    )


def test_adapter_preserves_subject_email_name() -> None:
    ctx = _make_context()
    actor = authorization_context_to_actor_context(ctx)
    assert actor.subject == "sub-123"
    assert actor.email == "user@example.com"
    assert actor.name == "User Name"


def test_adapter_preserves_permissions() -> None:
    perms = frozenset({"assessment.read", "governance.read"})
    ctx = _make_context(permissions=perms)
    actor = authorization_context_to_actor_context(ctx)
    assert actor.permissions == perms


def test_adapter_preserves_roles() -> None:
    ctx = _make_context(roles=frozenset({"qa_reviewer", "assessor"}))
    actor = authorization_context_to_actor_context(ctx)
    assert set(actor.roles) == {"qa_reviewer", "assessor"}


def test_adapter_preserves_tenant_binding() -> None:
    ctx = _make_context(tenant_id="tenant-b")
    actor = authorization_context_to_actor_context(ctx)
    assert actor.tenant_id == "tenant-b"
    assert actor.membership_id == "mem-123"


def test_adapter_maps_provider_to_auth_source() -> None:
    cases = {
        "auth0": "oidc_auth0",
        "entra": "oidc_entra",
        "google": "oidc_google",
        "api_key": "api_key",
        "machine": "api_key",
        "agent": "api_key",
    }
    for provider_name, expected_source in cases.items():
        ctx = _make_context(provider_name=provider_name)
        actor = authorization_context_to_actor_context(ctx)
        assert actor.auth_source == expected_source, provider_name


def test_adapter_defaults_unknown_provider_to_oidc_prefix() -> None:
    ctx = _make_context(provider_name="custom_idp")
    actor = authorization_context_to_actor_context(ctx)
    assert actor.auth_source == "oidc_custom_idp"


def test_adapter_tenant_override() -> None:
    ctx = _make_context(tenant_id="tenant-a")
    actor = authorization_context_to_actor_context(ctx, tenant_id="tenant-override")
    assert actor.tenant_id == "tenant-override"
