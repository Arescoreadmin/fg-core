"""Regression: verified-email claim survives identity adapters.

Customer consent approval (L14-SCAN-AUTH-HARDENING-001) fails closed unless
``ActorContext.email_verified`` is true.  Both the Auth0 membership-binding path
and the canonical-identity (FIAP) path used to rebuild ActorContext without the
claim, silently resetting it to False and blocking every real approval.  The
check must stay fail-closed: an unverified claim must still be rejected.
"""

from __future__ import annotations

import sys
import types
from datetime import datetime, timedelta, timezone

import pytest

from api.actor_context import ActorContext
from api.identity_authority.models import (
    AuthenticationContext,
    CanonicalIdentity,
    IdentityProvider,
    TenantBinding,
)
from services.field_assessment import customer_authorization as ca


def _canonical(email_verified: bool) -> CanonicalIdentity:
    now = datetime.now(timezone.utc)
    return CanonicalIdentity(
        subject="auth0|ciso",
        email="ciso@alpha.example",
        name="CISO",
        email_verified=email_verified,
        provider=IdentityProvider(
            name="auth0", issuer="https://idp/", subject="auth0|ciso"
        ),
        auth_context=AuthenticationContext(
            mfa_verified=True,
            mfa_method="totp",
            auth_time=now,
            amr=["pwd", "otp"],
            acr=None,
            pkce_used=True,
            nonce_verified=True,
        ),
        tenant_binding=TenantBinding(
            tenant_id="tenant-alpha",
            organization_id=None,
            membership_id="mem-1",
            roles=frozenset({"client_security_owner"}),
            permissions=frozenset({"scan.consent.approve"}),
        ),
        subscription=None,
        identity_type="human",
        issued_at=now,
        expires_at=now + timedelta(hours=1),
    )


@pytest.mark.parametrize("verified", [True, False])
def test_canonical_identity_preserves_email_verified(verified):
    actor = _canonical(verified).to_actor_context()
    assert actor.email_verified is verified


def test_canonical_identity_actor_can_approve_only_when_verified():
    ok = _canonical(True).to_actor_context()
    assert ca.validate_approver(
        ok, tenant_id="tenant-alpha", requested_by_subject="auth0|assessor"
    )
    bad = _canonical(False).to_actor_context()
    with pytest.raises(ca.CustomerAuthorizationError) as ei:
        ca.validate_approver(
            bad, tenant_id="tenant-alpha", requested_by_subject="auth0|assessor"
        )
    assert ei.value.audit_code == "APPROVER_EMAIL_UNVERIFIED"


@pytest.mark.parametrize("verified", [True, False])
def test_bind_membership_preserves_email_verified(monkeypatch, verified):
    import api.auth_dispatch as ad

    principal = types.SimpleNamespace(
        tenant_id="tenant-alpha", roles=["client_security_owner"], membership_id="mem-1"
    )

    class _Resolver:
        def resolve_or_deny(self, conn, **kw):
            return principal

    class IdentityResolutionError(Exception):
        code = "X"

    fake = types.ModuleType("services.identity_resolver")
    fake.IdentityResolver = _Resolver
    fake.IdentityResolutionError = IdentityResolutionError
    monkeypatch.setitem(sys.modules, "services.identity_resolver", fake)
    monkeypatch.setenv("FG_AUTH0_DOMAIN", "idp.example")
    monkeypatch.setattr(ad, "_check_tenant_lifecycle", lambda *a, **k: None)

    jwt_actor = ActorContext(
        subject="auth0|ciso",
        email="ciso@alpha.example",
        name="CISO",
        permissions=frozenset(),
        roles=[],
        auth_source="oidc_auth0",
        tenant_id="tenant-alpha",
        email_verified=verified,
    )
    bound = ad._bind_membership(jwt_actor, conn=object())
    assert bound.membership_id == "mem-1"
    assert bound.email_verified is verified
