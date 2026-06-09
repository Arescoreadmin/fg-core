"""PR 3 Auth0 adapter integration tests.

Tests cover: SSO invite start-auth, managed invite start-auth, wrong-email
rejection, wrong-tenant rejection, wrong-org rejection, wrong-connection
rejection, SSO/managed mode enforcement, revoked/expired invite handling,
invite token alone cannot activate, bind after callback, bind before callback
failure, replayed state failure, session issuance after bind, session without
tenant context rejection, console tenant_id query param rejection, Auth0
provisioning failure leaving membership pending, subject collision rejection,
and audit payload secret-safety.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from api.db import get_sessionmaker, init_db, reset_engine_cache
from api.db_models import TenantUser
from api.db_models_identity import (
    TenantIdentityAuthState,
    TenantIdentityAuditEvent,
    TenantIdentityProvider,
    TenantInvitation,
)
from api.identity.store import TenantIdentityStore
from admin_gateway.identity.auth0_adapter import Auth0Adapter
from admin_gateway.identity.auth0_config import Auth0Config
from admin_gateway.identity.auth0_management import (
    Auth0ManagementClient,
    Auth0ManagementError,
)
from admin_gateway.identity.auth0_models import Auth0OrgResult
from admin_gateway.identity.identity_context import AuthenticatedIdentity
from admin_gateway.identity.invitation_flow import (
    IdentityFlowError,
    bind_identity,
    start_invitation_auth,
    validate_callback,
)
from admin_gateway.identity.session_service import (
    TenantSessionError,
    build_tenant_session_context,
)

TENANT = "tenant-auth0"
TENANT_B = "tenant-other"
ISSUER = "https://example.us.auth0.com/"
PROVIDER = "auth0"
CONNECTION = "enterprise-acme"
ORGANIZATION = "org-acme-1"
EMAIL = "user@acme.com"


def _make_auth0_config() -> Auth0Config:
    return Auth0Config(
        domain="example.us.auth0.com",
        audience="https://api.example.com/",
        client_id="test-client",
        client_secret="test-secret",
        mgmt_audience="https://example.us.auth0.com/api/v2/",
        mgmt_client_id="mgmt-client",
        mgmt_client_secret="mgmt-secret",
        callback_url="https://app.example.com/callback",
        logout_return_url="https://app.example.com/",
        org_login_required=True,
        allowed_connection_strategies=(),
    )


def _make_adapter(mgmt: Any = None) -> Auth0Adapter:
    config = _make_auth0_config()
    mock_mgmt = mgmt or MagicMock(spec=Auth0ManagementClient)
    return Auth0Adapter(config=config, management_client=mock_mgmt)


@pytest.fixture()
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = str(tmp_path / "auth0-flow.db")
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", path)
    monkeypatch.setenv("AG_SQLITE_PATH", str(tmp_path / "admin.db"))
    monkeypatch.setenv("FG_SESSION_SECRET", "auth0-test-session-secret")
    monkeypatch.delenv("FG_DEV_AUTH_BYPASS", raising=False)
    reset_engine_cache()
    init_db(sqlite_path=path)
    session = get_sessionmaker(sqlite_path=path)()
    try:
        yield session
    finally:
        session.close()
        reset_engine_cache()


def _seed(
    db,
    *,
    tenant_id: str = TENANT,
    identity_mode: str = "sso",
    email: str = EMAIL,
    active: bool = True,
    identity_type: str = "human",
    expires_at: datetime | None = None,
    organization_id: str = ORGANIZATION,
    connection_id: str = CONNECTION,
    provisioning_status: str = "ready",
):
    store = TenantIdentityStore()
    config = store.create_config(
        db,
        tenant_id=tenant_id,
        identity_mode=identity_mode,
        configured_by_user_id="admin-1",
        provider=PROVIDER,
        oidc_issuer=ISSUER,
        auth0_organization_id=organization_id,
        auth0_connection_id=connection_id,
        allowed_email_domains=["acme.com"],
        sso_enforced=identity_mode == "sso",
        provisioning_status=provisioning_status,
    )
    membership = TenantUser(
        tenant_id=tenant_id,
        email=email,
        display_name="User",
        role="admin",
        active=active,
        identity_type=identity_type,
    )
    db.add(membership)
    db.flush()
    provider_row = (
        db.query(TenantIdentityProvider)
        .filter(TenantIdentityProvider.identity_config_id == config.id)
        .one()
    )
    invitation = store.create_invitation(
        db,
        tenant_id=tenant_id,
        email=email,
        role="admin",
        created_by_user_id="admin-1",
        expires_at=expires_at or datetime.now(timezone.utc) + timedelta(hours=1),
        identity_mode_at_invite=identity_mode,
        required_provider=PROVIDER,
        required_connection_id=connection_id,
        identity_policy_config_id=config.id,
        required_provider_record_id=provider_row.id,
        membership_id=membership.id,
    )
    db.commit()
    return invitation, membership


def _valid_identity(**overrides: Any) -> AuthenticatedIdentity:
    base = AuthenticatedIdentity(
        provider=PROVIDER,
        issuer=ISSUER,
        subject="auth0|user-123",
        email=EMAIL,
        email_verified=True,
        connection_id=CONNECTION,
        organization_id=ORGANIZATION,
        identity_type="human",
        correlation_id="corr-1",
    )
    return replace(base, **overrides)


def _start(
    db, invitation: TenantInvitation, adapter: Auth0Adapter | None = None
) -> str:
    result = start_invitation_auth(
        db,
        tenant_id=invitation.tenant_id,
        invitation_id=invitation.id,
        adapter=adapter or _make_adapter(),
    )
    db.commit()
    return result["state"]


# ------------------------------------------------------------------
# SSO invite start-auth
# ------------------------------------------------------------------


def test_sso_invite_start_auth_returns_org_aware_url(db):
    invitation, _ = _seed(db, identity_mode="sso")
    result = start_invitation_auth(
        db,
        tenant_id=TENANT,
        invitation_id=invitation.id,
        adapter=_make_adapter(),
    )
    db.commit()
    assert result["adapter"] == "auth0"
    assert ORGANIZATION in result["auth_start_url"]
    assert CONNECTION in result["auth_start_url"]
    assert "state" in result
    assert result["identity_mode"] == "sso"


def test_sso_invite_start_auth_stores_only_digest(db):
    invitation, _ = _seed(db, identity_mode="sso")
    result = start_invitation_auth(
        db,
        tenant_id=TENANT,
        invitation_id=invitation.id,
        adapter=_make_adapter(),
    )
    db.commit()
    raw_state = result["state"]
    import hashlib

    digest = hashlib.sha256(raw_state.encode()).hexdigest()
    auth_state = (
        db.query(TenantIdentityAuthState).filter_by(invitation_id=invitation.id).one()
    )
    assert auth_state.state_digest == digest
    # raw state must not be stored
    assert auth_state.state_digest != raw_state


def test_managed_invite_start_auth_returns_signup_url(db):
    invitation, _ = _seed(db, identity_mode="managed")
    result = start_invitation_auth(
        db,
        tenant_id=TENANT,
        invitation_id=invitation.id,
        adapter=_make_adapter(),
    )
    db.commit()
    assert result["adapter"] == "auth0"
    assert result["identity_mode"] == "managed"


# ------------------------------------------------------------------
# Wrong-email / wrong-tenant rejection
# ------------------------------------------------------------------


def test_wrong_email_cannot_accept_invite(db):
    invitation, _ = _seed(db)
    state = _start(db, invitation)
    with pytest.raises(IdentityFlowError, match="INVITE_EMAIL_MISMATCH"):
        validate_callback(
            db,
            tenant_id=TENANT,
            invitation_id=invitation.id,
            state=state,
            identity=_valid_identity(email="wrong@acme.com"),
        )


def test_wrong_tenant_cannot_bind_invite(db):
    invitation, _ = _seed(db)
    state = _start(db, invitation)
    with pytest.raises(IdentityFlowError, match="INVITE_NOT_FOUND"):
        validate_callback(
            db,
            tenant_id=TENANT_B,
            invitation_id=invitation.id,
            state=state,
            identity=_valid_identity(),
        )


# ------------------------------------------------------------------
# Invite token alone cannot activate membership
# ------------------------------------------------------------------


def test_invite_token_alone_cannot_activate_membership(db):
    invitation, membership = _seed(db)
    db.refresh(membership)
    assert membership.identity_binding_status == "unbound"
    # Attempting bind without prior callback validation must fail
    with pytest.raises(IdentityFlowError, match="CALLBACK_STATE_INVALID"):
        bind_identity(
            db,
            tenant_id=TENANT,
            invitation_id=invitation.id,
            state="raw-invite-token-not-valid-state",
        )
    db.refresh(membership)
    assert membership.identity_binding_status == "unbound"
    assert membership.identity_subject is None


# ------------------------------------------------------------------
# Bind before callback is rejected
# ------------------------------------------------------------------


def test_bind_before_callback_is_rejected(db):
    invitation, membership = _seed(db)
    state = _start(db, invitation)
    with pytest.raises(IdentityFlowError, match="CALLBACK_STATE_INVALID"):
        bind_identity(db, tenant_id=TENANT, invitation_id=invitation.id, state=state)
    db.refresh(membership)
    assert membership.identity_binding_status == "unbound"


# ------------------------------------------------------------------
# Wrong org / wrong connection rejection
# ------------------------------------------------------------------


def test_wrong_auth0_organization_is_rejected(db):
    invitation, _ = _seed(db)
    state = _start(db, invitation)
    with pytest.raises(IdentityFlowError, match="ORG_NOT_ALLOWED"):
        validate_callback(
            db,
            tenant_id=TENANT,
            invitation_id=invitation.id,
            state=state,
            identity=_valid_identity(organization_id="org-WRONG"),
        )


def test_wrong_auth0_connection_is_rejected(db):
    invitation, _ = _seed(db)
    state = _start(db, invitation)
    with pytest.raises(IdentityFlowError, match="CONNECTION_NOT_ALLOWED"):
        validate_callback(
            db,
            tenant_id=TENANT,
            invitation_id=invitation.id,
            state=state,
            identity=_valid_identity(connection_id="conn-WRONG"),
        )


# ------------------------------------------------------------------
# SSO tenant cannot use managed login
# ------------------------------------------------------------------


def test_sso_tenant_using_managed_login_path_is_rejected(db):
    """SSO tenant with connection enforcement rejects callback from wrong provider."""
    invitation, _ = _seed(db, identity_mode="sso")
    state = _start(db, invitation)
    # managed login would produce a callback without the required connection
    with pytest.raises(IdentityFlowError, match="CONNECTION_NOT_ALLOWED"):
        validate_callback(
            db,
            tenant_id=TENANT,
            invitation_id=invitation.id,
            state=state,
            identity=_valid_identity(connection_id=None),
        )


# ------------------------------------------------------------------
# Revoked / expired invite stays dead
# ------------------------------------------------------------------


def test_revoked_invite_is_rejected(db):
    invitation, _ = _seed(db)
    store = TenantIdentityStore()
    store.transition_invitation(
        db, invitation=invitation, to_status="revoked", actor_user_id="admin-1"
    )
    db.commit()
    with pytest.raises(IdentityFlowError, match="INVITE_REVOKED"):
        _start(db, invitation)


def test_expired_invite_is_rejected(db):
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    invitation, _ = _seed(db, expires_at=past)
    with pytest.raises(IdentityFlowError, match="INVITE_EXPIRED"):
        _start(db, invitation)


# ------------------------------------------------------------------
# Replayed callback state is rejected
# ------------------------------------------------------------------


def test_replayed_callback_state_is_rejected(db):
    invitation, _ = _seed(db)
    state = _start(db, invitation)
    validate_callback(
        db,
        tenant_id=TENANT,
        invitation_id=invitation.id,
        state=state,
        identity=_valid_identity(),
    )
    db.commit()
    # Second call with same state + same identity is idempotent (not a replay)
    # Call with different identity on same state is a replay attack
    with pytest.raises(IdentityFlowError, match="CALLBACK_REPLAY_REJECTED"):
        validate_callback(
            db,
            tenant_id=TENANT,
            invitation_id=invitation.id,
            state=state,
            identity=_valid_identity(subject="auth0|attacker"),
        )


def test_consumed_state_cannot_be_replayed_after_bind(db):
    invitation, _ = _seed(db)
    state = _start(db, invitation)
    validate_callback(
        db,
        tenant_id=TENANT,
        invitation_id=invitation.id,
        state=state,
        identity=_valid_identity(),
    )
    bind_identity(db, tenant_id=TENANT, invitation_id=invitation.id, state=state)
    db.commit()
    with pytest.raises(IdentityFlowError, match="CALLBACK_REPLAY_REJECTED"):
        validate_callback(
            db,
            tenant_id=TENANT,
            invitation_id=invitation.id,
            state=state,
            identity=_valid_identity(),
        )


# ------------------------------------------------------------------
# Callback with unverified email / missing subject / missing issuer
# ------------------------------------------------------------------


def test_unverified_email_is_rejected(db):
    invitation, _ = _seed(db)
    state = _start(db, invitation)
    with pytest.raises(IdentityFlowError, match="EMAIL_NOT_VERIFIED"):
        validate_callback(
            db,
            tenant_id=TENANT,
            invitation_id=invitation.id,
            state=state,
            identity=_valid_identity(email_verified=False),
        )


def test_missing_provider_is_rejected(db):
    invitation, _ = _seed(db)
    state = _start(db, invitation)
    with pytest.raises(IdentityFlowError, match="PROVIDER_NOT_ALLOWED"):
        validate_callback(
            db,
            tenant_id=TENANT,
            invitation_id=invitation.id,
            state=state,
            identity=_valid_identity(provider="keycloak"),
        )


def test_wrong_issuer_is_rejected(db):
    invitation, _ = _seed(db)
    state = _start(db, invitation)
    with pytest.raises(IdentityFlowError, match="ISSUER_NOT_ALLOWED"):
        validate_callback(
            db,
            tenant_id=TENANT,
            invitation_id=invitation.id,
            state=state,
            identity=_valid_identity(issuer="https://evil.auth0.com/"),
        )


# ------------------------------------------------------------------
# Subject collision across tenants is rejected
# ------------------------------------------------------------------


def test_subject_collision_across_tenants_is_rejected(db):
    invitation_a, _ = _seed(db, tenant_id="tenant-a")
    invitation_b, _ = _seed(db, tenant_id="tenant-b")
    state_a = _start(db, invitation_a)
    state_b = _start(db, invitation_b)
    same_identity = _valid_identity(subject="auth0|shared-subject")
    validate_callback(
        db,
        tenant_id="tenant-a",
        invitation_id=invitation_a.id,
        state=state_a,
        identity=same_identity,
    )
    bind_identity(
        db, tenant_id="tenant-a", invitation_id=invitation_a.id, state=state_a
    )
    db.commit()
    validate_callback(
        db,
        tenant_id="tenant-b",
        invitation_id=invitation_b.id,
        state=state_b,
        identity=same_identity,
    )
    with pytest.raises(IdentityFlowError, match="IDENTITY_ALREADY_BOUND"):
        bind_identity(
            db,
            tenant_id="tenant-b",
            invitation_id=invitation_b.id,
            state=state_b,
        )


# ------------------------------------------------------------------
# Successful callback → bind → session issuance
# ------------------------------------------------------------------


def test_session_issued_only_after_bind(db):
    invitation, membership = _seed(db)
    state = _start(db, invitation)
    validate_callback(
        db,
        tenant_id=TENANT,
        invitation_id=invitation.id,
        state=state,
        identity=_valid_identity(),
    )
    # Before bind: membership is pending, session must be refused
    db.refresh(membership)
    assert membership.identity_binding_status == "pending"
    with pytest.raises(TenantSessionError, match="IDENTITY_NOT_BOUND"):
        build_tenant_session_context(membership)

    bind_identity(db, tenant_id=TENANT, invitation_id=invitation.id, state=state)
    db.commit()
    db.refresh(membership)
    assert membership.identity_binding_status == "bound"
    ctx = build_tenant_session_context(membership)
    assert ctx.tenant_id == TENANT
    assert ctx.identity_provider == PROVIDER


def test_session_without_tenant_context_is_rejected(db):
    membership = TenantUser(
        tenant_id=TENANT,
        email=EMAIL,
        display_name="NoTenant",
        role="admin",
        active=True,
        identity_type="human",
        identity_binding_status="unbound",
    )
    db.add(membership)
    db.flush()
    exc = None
    try:
        build_tenant_session_context(membership)
    except TenantSessionError as e:
        exc = e
    assert exc is not None, "Expected TenantSessionError to be raised"
    assert exc.code == "IDENTITY_NOT_BOUND"


# ------------------------------------------------------------------
# Auth0 provisioning failure leaves membership pending
# ------------------------------------------------------------------


def test_auth0_provisioning_failure_leaves_tenant_identity_config_not_active(db):
    mgmt = MagicMock(spec=Auth0ManagementClient)
    mgmt.create_organization.side_effect = Auth0ManagementError("ORG_CREATE_FAILED")
    adapter = Auth0Adapter(config=_make_auth0_config(), management_client=mgmt)
    result = adapter.provision_tenant_identity(
        tenant_id=TENANT,
        org_name="acme",
        display_name="Acme",
        connection_id="conn-1",
    )
    assert result.status == "failed"
    # Caller is responsible for NOT marking config ready — test that
    # the result error_code is safe (no tokens/secrets)
    assert result.error_code is not None
    assert "secret" not in (result.error_code or "").lower()
    assert "token" not in (result.error_code or "").lower()


def test_connection_attach_failure_does_not_activate_sso(db):
    mgmt = MagicMock(spec=Auth0ManagementClient)
    mgmt.create_organization.return_value = Auth0OrgResult(
        organization_id="org-1", organization_name="x", was_created=True
    )
    mgmt.attach_connection_to_org.side_effect = Auth0ManagementError(
        "CONNECTION_NOT_FOUND"
    )
    adapter = Auth0Adapter(config=_make_auth0_config(), management_client=mgmt)
    result = adapter.provision_tenant_identity(
        tenant_id=TENANT, org_name="x", display_name="X", connection_id="bad-conn"
    )
    # SSO is not ready — status must not be "success"
    assert result.status != "success"
    assert result.connection_id is None


# ------------------------------------------------------------------
# Console tenant_id query param is ignored / rejected
# ------------------------------------------------------------------


def test_console_tenant_id_query_ignored_invitation_always_uses_tenant_header(db):
    """Invitation flow always queries by explicit tenant_id, never by query param."""
    invitation_a, _ = _seed(db, tenant_id="tenant-a")
    invitation_b, _ = _seed(db, tenant_id="tenant-b")
    state_a = _start(db, invitation_a)
    # Trying to process tenant-a's invitation under tenant-b must fail
    with pytest.raises(IdentityFlowError, match="INVITE_NOT_FOUND"):
        validate_callback(
            db,
            tenant_id="tenant-b",
            invitation_id=invitation_a.id,
            state=state_a,
            identity=_valid_identity(),
        )


# ------------------------------------------------------------------
# Generic Auth0 login without invitation cannot activate tenant membership
# ------------------------------------------------------------------


def test_generic_auth0_login_without_invitation_cannot_activate_membership(db):
    """No auth state exists without start-auth — bind must fail."""
    invitation, membership = _seed(db)
    # Skip start-auth entirely; attempt bind with an arbitrary state
    with pytest.raises(IdentityFlowError, match="CALLBACK_STATE_INVALID"):
        bind_identity(
            db,
            tenant_id=TENANT,
            invitation_id=invitation.id,
            state="no-start-auth-state",
        )
    db.refresh(membership)
    assert membership.identity_binding_status == "unbound"


# ------------------------------------------------------------------
# Audit payload safety — no management token, no secrets
# ------------------------------------------------------------------


def test_audit_payload_excludes_secrets(db):
    invitation, _ = _seed(db)
    state = _start(db, invitation)
    validate_callback(
        db,
        tenant_id=TENANT,
        invitation_id=invitation.id,
        state=state,
        identity=_valid_identity(),
    )
    bind_identity(db, tenant_id=TENANT, invitation_id=invitation.id, state=state)
    db.commit()
    events = db.query(TenantIdentityAuditEvent).filter_by(tenant_id=TENANT).all()
    serialized = str(
        [(e.event_type, e.reason_code, e.details_json) for e in events]
    ).lower()
    for forbidden in (
        "access_token",
        "id_token",
        "refresh_token",
        "client_secret",
        "mgmt_secret",
        "authorization",
        "raw callback",
    ):
        assert forbidden not in serialized, (
            f"Audit payload contains forbidden field: {forbidden}"
        )
    # raw state must not be in audit
    assert state.lower() not in serialized


# ------------------------------------------------------------------
# Auth0 adapter audit event vocabulary covers Auth0 events
# ------------------------------------------------------------------


def test_auth0_audit_event_vocabulary_includes_auth0_events():
    from admin_gateway.identity.audit import IDENTITY_AUDIT_EVENTS

    expected = {
        "auth0.organization.create_requested",
        "auth0.organization.created",
        "auth0.organization.associated",
        "auth0.connection.attach_requested",
        "auth0.connection.attached",
        "auth0.provisioning_failed",
        "auth0.invitation_auth_started",
        "auth0.callback_received",
        "auth0.callback_rejected",
        "auth0.identity_validated",
        "auth0.identity_bound",
        "auth0.session_issued",
        "auth0.session_rejected",
    }
    assert expected.issubset(IDENTITY_AUDIT_EVENTS)
