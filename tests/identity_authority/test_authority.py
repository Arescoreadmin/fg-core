"""tests/identity_authority/test_authority.py — IdentityAuthority integration tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from api.identity_authority.audit import IdentityAuditor
from api.identity_authority.authority import IdentityAuthority
from api.identity_authority.models import AuthorizationContext
from api.identity_authority.providers.base import (
    IdentityProviderError,
    IdentityValidationError,
)
from api.identity_authority.providers.registry import IdentityProviderRegistry
from api.identity_authority.session_authority import SessionAuthority
from api.identity_authority.tenant_resolver import TenantResolver


@pytest.fixture
def mock_registry():
    return MagicMock(spec=IdentityProviderRegistry)


@pytest.fixture
def mock_session():
    return MagicMock(spec=SessionAuthority)


@pytest.fixture
def mock_resolver():
    return MagicMock(spec=TenantResolver)


@pytest.fixture
def mock_auditor():
    return MagicMock(spec=IdentityAuditor)


@pytest.fixture
def authority(mock_registry, mock_session, mock_resolver, mock_auditor):
    return IdentityAuthority(
        provider_registry=mock_registry,
        session_authority=mock_session,
        tenant_resolver=mock_resolver,
        auditor=mock_auditor,
    )


def test_authenticate_jwt_success(
    authority, mock_registry, mock_resolver, mock_auditor, canonical_identity
):
    mock_registry.resolve_jwt.return_value = canonical_identity
    mock_resolver.resolve.return_value = canonical_identity.tenant_binding

    ctx = authority.authenticate_jwt("valid.token.here", db=MagicMock())

    assert isinstance(ctx, AuthorizationContext)
    assert ctx.tenant_id == "tenant-123"
    mock_auditor.emit.assert_called()


def test_authenticate_jwt_validation_failure_raises(
    authority, mock_registry, mock_auditor
):
    mock_registry.resolve_jwt.side_effect = IdentityValidationError(
        "bad token", "INVALID", "auth0"
    )

    with pytest.raises(IdentityValidationError):
        authority.authenticate_jwt("bad.token")

    mock_auditor.emit.assert_called()


def test_authenticate_jwt_provider_error_raises(authority, mock_registry, mock_auditor):
    mock_registry.resolve_jwt.side_effect = IdentityProviderError("down", "auth0")

    with pytest.raises(IdentityProviderError):
        authority.authenticate_jwt("token")

    mock_auditor.emit.assert_called()


def test_authenticate_jwt_no_db_skips_resolver(
    authority, mock_registry, mock_resolver, canonical_identity
):
    mock_registry.resolve_jwt.return_value = canonical_identity

    ctx = authority.authenticate_jwt("token", db=None)

    mock_resolver.resolve.assert_not_called()
    assert ctx.tenant_id == "tenant-123"  # from identity's own binding


def test_create_session_issues_token(authority, mock_session, canonical_identity):
    from api.identity_authority.models import AuthorizationContext

    mock_session.create_session.return_value = MagicMock(
        token="signed.session.token",
        session_id="sid-001",
    )

    ctx = AuthorizationContext(
        identity=canonical_identity,
        permissions=frozenset(["assessment.read"]),
        capabilities=frozenset(),
        tenant_id="tenant-123",
        organization_id=None,
        session_id="",
        session_risk_score=0.0,
        correlation_id="cid-001",
    )

    token = authority.create_session(ctx)
    assert token == "signed.session.token"
    mock_session.create_session.assert_called_once()


def test_logout_revokes_session(authority, mock_session, mock_auditor):
    authority.logout("sid-001", subject="user|001")
    mock_session.revoke_session.assert_called_once_with("sid-001")
    mock_auditor.emit.assert_called()


def test_logout_all_revokes_multiple(authority, mock_session, mock_auditor):
    mock_session.revoke_all_for_subject.return_value = 3
    count = authority.logout_all("user|001", ["sid-a", "sid-b", "sid-c"])
    assert count == 3
    mock_auditor.emit.assert_called()


def test_to_actor_context_compat(canonical_identity):
    actor = canonical_identity.to_actor_context()
    assert actor.subject == "auth0|test-subject-001"
    assert actor.email == "user@acme.com"
    assert actor.auth_source == "oidc_auth0"
    assert "assessment.read" in actor.permissions


def test_authorization_context_has_permission(canonical_identity):
    from api.identity_authority.models import AuthorizationContext

    ctx = AuthorizationContext(
        identity=canonical_identity,
        permissions=frozenset(["assessment.read", "finding.create"]),
        capabilities=frozenset(),
        tenant_id="tenant-123",
        organization_id=None,
        session_id="sid-001",
        session_risk_score=0.0,
        correlation_id="cid",
    )

    assert ctx.has_permission("assessment.read") is True
    assert ctx.has_permission("assessment.read", "finding.create") is True
    assert ctx.has_permission("platform.admin") is False


def test_get_identity_authority_returns_singleton(monkeypatch):
    monkeypatch.delenv("FG_AUTH0_DOMAIN", raising=False)
    monkeypatch.delenv("FG_ENTRA_TENANT_ID", raising=False)
    monkeypatch.setenv("FG_SESSION_SECRET", "test-secret-32-bytes-exactly!!!!")
    monkeypatch.delenv("FG_REDIS_URL", raising=False)

    from api.identity_authority.authority import get_identity_authority

    a1 = get_identity_authority()
    a2 = get_identity_authority()
    assert a1 is a2
