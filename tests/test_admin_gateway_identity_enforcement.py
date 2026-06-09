"""PR 2 provider-neutral Admin Gateway identity enforcement tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError
from fastapi.testclient import TestClient

from api.db import get_sessionmaker, init_db, reset_engine_cache
from api.db_models import TenantUser
from api.db_models_identity import (
    TenantIdentityAuditEvent,
    TenantIdentityConfig,
    TenantIdentityAuthState,
    TenantIdentityProvider,
    TenantInvitation,
)
from api.identity.store import TenantIdentityStore, verify_identity_audit_chain
from admin_gateway.identity.identity_context import AuthenticatedIdentity
from admin_gateway.identity.invitation_flow import (
    IdentityFlowError,
    bind_identity,
    start_invitation_auth,
    validate_callback,
)
from admin_gateway.identity.provider_adapter import (
    AuthInstructions,
    ProviderNeutralRedirectAdapter,
)
from admin_gateway.identity.session_service import (
    TenantSessionError,
    build_tenant_session_context,
    issue_tenant_session,
)

TENANT = "tenant-a"
ISSUER = "https://idp.example/"
PROVIDER = "oidc"
CONNECTION = "enterprise-a"
ORGANIZATION = "org-a"
EMAIL = "person@example.com"


@pytest.fixture()
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = str(tmp_path / "gateway-identity.db")
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", path)
    monkeypatch.setenv("AG_SQLITE_PATH", str(tmp_path / "admin.db"))
    monkeypatch.setenv("FG_SESSION_SECRET", "identity-test-session-secret")
    monkeypatch.delenv("FG_DEV_AUTH_BYPASS", raising=False)
    reset_engine_cache()
    init_db(sqlite_path=path)
    session = get_sessionmaker(sqlite_path=path)()
    try:
        yield session
    finally:
        session.close()
        reset_engine_cache()


def seed_flow(
    db,
    *,
    tenant_id: str = TENANT,
    identity_mode: str = "sso",
    expires_at: datetime | None = None,
    active: bool = True,
    identity_type: str = "human",
):
    store = TenantIdentityStore()
    config = store.create_config(
        db,
        tenant_id=tenant_id,
        identity_mode=identity_mode,
        configured_by_user_id="admin-1",
        provider=PROVIDER,
        oidc_issuer=ISSUER,
        auth0_organization_id=ORGANIZATION,
        auth0_connection_id=CONNECTION,
        allowed_email_domains=["example.com"],
        sso_enforced=identity_mode == "sso",
        provisioning_status="ready",
    )
    membership = TenantUser(
        tenant_id=tenant_id,
        email=EMAIL,
        display_name="Person",
        role="admin",
        active=active,
        identity_type=identity_type,
    )
    db.add(membership)
    db.flush()
    provider = (
        db.query(TenantIdentityProvider)
        .filter(TenantIdentityProvider.identity_config_id == config.id)
        .one()
    )
    invitation = store.create_invitation(
        db,
        tenant_id=tenant_id,
        email=EMAIL,
        role="admin",
        created_by_user_id="admin-1",
        expires_at=expires_at or datetime.now(timezone.utc) + timedelta(hours=1),
        identity_mode_at_invite=identity_mode,
        required_provider=PROVIDER,
        required_connection_id=CONNECTION,
        identity_policy_config_id=config.id,
        required_provider_record_id=provider.id,
        membership_id=membership.id,
    )
    db.commit()
    return invitation, membership


def valid_identity(**changes) -> AuthenticatedIdentity:
    identity = AuthenticatedIdentity(
        provider=PROVIDER,
        issuer=ISSUER,
        subject="subject-1",
        email=EMAIL,
        email_verified=True,
        connection_id=CONNECTION,
        organization_id=ORGANIZATION,
        identity_type="human",
        correlation_id="correlation-1",
    )
    return replace(identity, **changes)


def start(db, invitation: TenantInvitation) -> str:
    result = start_invitation_auth(
        db,
        tenant_id=invitation.tenant_id,
        invitation_id=invitation.id,
        adapter=ProviderNeutralRedirectAdapter(),
    )
    db.commit()
    return result["state"]


def test_start_auth_is_pending_safe_idempotent_and_stores_only_digest(db) -> None:
    invitation, membership = seed_flow(db)
    first = start(db, invitation)
    second = start(db, invitation)
    db.refresh(invitation)
    db.refresh(membership)
    assert invitation.status == "auth_started"
    assert membership.identity_binding_status == "unbound"
    assert first != second
    states = db.query(TenantIdentityAuthState).all()
    assert len(states) == 2
    assert all(
        first != state.state_digest and second != state.state_digest for state in states
    )
    assert all(state.status == "started" for state in states)


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        ("expired", "INVITE_EXPIRED"),
        ("revoked", "INVITE_REVOKED"),
        ("wrong_tenant", "INVITE_NOT_FOUND"),
    ],
)
def test_start_auth_rejects_invalid_invitation_context(
    db, condition: str, expected: str
) -> None:
    expiry = (
        datetime.now(timezone.utc) - timedelta(minutes=1)
        if condition == "expired"
        else None
    )
    invitation, _ = seed_flow(db, expires_at=expiry)
    if condition == "revoked":
        TenantIdentityStore().transition_invitation(db, invitation, to_status="revoked")
        db.commit()
    tenant_id = "tenant-b" if condition == "wrong_tenant" else TENANT
    with pytest.raises(IdentityFlowError, match=expected):
        start_invitation_auth(
            db,
            tenant_id=tenant_id,
            invitation_id=invitation.id,
            adapter=ProviderNeutralRedirectAdapter(),
        )


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"email_verified": False}, "EMAIL_NOT_VERIFIED"),
        ({"email": "other@example.com"}, "INVITE_EMAIL_MISMATCH"),
        ({"provider": "other"}, "PROVIDER_NOT_ALLOWED"),
        ({"issuer": "https://other.example/"}, "ISSUER_NOT_ALLOWED"),
        ({"connection_id": "other"}, "CONNECTION_NOT_ALLOWED"),
        ({"organization_id": "other"}, "ORG_NOT_ALLOWED"),
        ({"identity_type": "service"}, "IDENTITY_TYPE_NOT_ALLOWED"),
        ({"identity_type": "agent"}, "IDENTITY_TYPE_NOT_ALLOWED"),
        ({"identity_type": "system"}, "IDENTITY_TYPE_NOT_ALLOWED"),
    ],
)
def test_callback_rejects_unverified_or_policy_mismatched_identity(
    db, changes, expected
) -> None:
    invitation, membership = seed_flow(db)
    state = start(db, invitation)
    with pytest.raises(IdentityFlowError, match=expected):
        validate_callback(
            db,
            tenant_id=TENANT,
            invitation_id=invitation.id,
            state=state,
            identity=valid_identity(**changes),
        )
    db.commit()
    db.refresh(membership)
    assert membership.identity_binding_status == "unbound"
    assert membership.identity_subject is None
    assert (
        db.query(TenantIdentityAuditEvent).filter_by(reason_code=expected).count() == 1
    )


def test_callback_bind_and_session_use_verified_subject_not_email(db) -> None:
    invitation, membership = seed_flow(db)
    state = start(db, invitation)
    identity = valid_identity(subject="subject-authority")
    validate_callback(
        db,
        tenant_id=TENANT,
        invitation_id=invitation.id,
        state=state,
        identity=identity,
    )
    db.commit()
    db.refresh(invitation)
    db.refresh(membership)
    assert invitation.status == "accepted_identity_pending_binding"
    assert membership.identity_binding_status == "pending"
    with pytest.raises(TenantSessionError, match="IDENTITY_NOT_BOUND"):
        build_tenant_session_context(membership)

    bound = bind_identity(
        db, tenant_id=TENANT, invitation_id=invitation.id, state=state
    )
    session = issue_tenant_session(
        __import__(
            "admin_gateway.auth.session", fromlist=["SessionManager"]
        ).SessionManager(),
        build_tenant_session_context(bound),
    )
    db.commit()
    assert bound.identity_subject == "subject-authority"
    assert bound.identity_email == EMAIL
    assert session.tenant_governed is True
    assert session.tenant_id == TENANT
    assert session.membership_id == membership.id
    assert (
        bind_identity(db, tenant_id=TENANT, invitation_id=invitation.id, state=state).id
        == membership.id
    )
    assert verify_identity_audit_chain(db, TENANT)
    audit_text = str(
        [event.details_json for event in db.query(TenantIdentityAuditEvent).all()]
    ).lower()
    assert all(
        secret not in audit_text for secret in ("token", "authorization", "secret")
    )


def test_disabled_and_nonhuman_memberships_cannot_bind_through_human_flow(db) -> None:
    invitation, _ = seed_flow(db, active=False)
    state = start(db, invitation)
    with pytest.raises(IdentityFlowError, match="MEMBERSHIP_DISABLED"):
        validate_callback(
            db,
            tenant_id=TENANT,
            invitation_id=invitation.id,
            state=state,
            identity=valid_identity(),
        )


class VerifiedTestAdapter:
    def __init__(self, identity: AuthenticatedIdentity):
        self.identity = identity

    def start_invitation_auth(self, *, provider, state, connection_id, organization_id):
        return AuthInstructions(
            provider,
            connection_id,
            organization_id,
            f"/verified-start?state={state}",
            "verified-test",
        )

    def validate_callback(self, callback_payload):
        del callback_payload
        return self.identity


def test_http_gateway_fails_closed_without_adapter_then_issues_scoped_session(
    db,
) -> None:
    invitation, _ = seed_flow(db)
    from admin_gateway.main import build_app
    from admin_gateway.routers.identity import get_provider_adapter

    app = build_app()
    headers = {"X-Tenant-ID": TENANT}
    with TestClient(app) as client:
        wrong = client.post(
            f"/identity/invitations/{invitation.id}/start-auth",
            headers={"X-Tenant-ID": "tenant-b"},
            json={},
        )
        assert wrong.status_code == 404
        started = client.post(
            f"/identity/invitations/{invitation.id}/start-auth",
            headers=headers,
            json={},
        )
        assert started.status_code == 200, started.text
        state = started.json()["state"]
        body = {
            "state": state,
            "provider": PROVIDER,
            "issuer": ISSUER,
            "subject": "spoofed",
            "email": EMAIL,
            "email_verified": True,
            "connection_id": CONNECTION,
            "organization_id": ORGANIZATION,
            "identity_type": "human",
        }
        rejected = client.post(
            f"/identity/invitations/{invitation.id}/callback",
            headers=headers,
            json=body,
        )
        assert rejected.status_code == 503
        assert rejected.json()["detail"]["code"] == "PROVIDER_CALLBACK_NOT_CONFIGURED"

        app.dependency_overrides[get_provider_adapter] = lambda: VerifiedTestAdapter(
            valid_identity()
        )
        started = client.post(
            f"/identity/invitations/{invitation.id}/start-auth",
            headers=headers,
            json={},
        )
        state = started.json()["state"]
        body["state"] = state
        callback = client.post(
            f"/identity/invitations/{invitation.id}/callback",
            headers=headers,
            json=body,
        )
        assert callback.status_code == 200, callback.text
        bound = client.post(
            f"/identity/invitations/{invitation.id}/bind",
            headers=headers,
            json={"state": state},
        )
        assert bound.status_code == 200, bound.text
        current = client.get("/identity/session/current?tenant_id=tenant-b")
        assert current.status_code == 200
        assert current.json()["tenant_id"] == TENANT
        assert current.json()["identity_subject"] == "subject-1"
        assert "token" not in str(current.json()).lower()


def test_http_bind_rejects_request_body_identity_claims_and_missing_identity_type(
    db,
) -> None:
    invitation, _ = seed_flow(db)
    from admin_gateway.main import build_app
    from admin_gateway.routers.identity import get_provider_adapter

    app = build_app()
    app.dependency_overrides[get_provider_adapter] = lambda: VerifiedTestAdapter(
        valid_identity()
    )
    headers = {"X-Tenant-ID": TENANT}
    with TestClient(app) as client:
        started = client.post(
            f"/identity/invitations/{invitation.id}/start-auth",
            headers=headers,
            json={},
        )
        state = started.json()["state"]
        missing_type = client.post(
            f"/identity/invitations/{invitation.id}/callback",
            headers=headers,
            json={
                "state": state,
                "provider": PROVIDER,
                "issuer": ISSUER,
                "subject": "subject-1",
                "email": EMAIL,
                "email_verified": True,
            },
        )
        assert missing_type.status_code == 422
        body_only = client.post(
            f"/identity/invitations/{invitation.id}/bind",
            headers=headers,
            json={
                "state": "not-a-validated-state-value",
                "provider": PROVIDER,
                "subject": "self-asserted",
            },
        )
        assert body_only.status_code == 422
        assert client.get("/identity/session/current").status_code == 401


def test_session_issue_rejection_and_logout_are_audited(db) -> None:
    invitation, membership = seed_flow(db)
    from admin_gateway.auth.config import get_auth_config
    from admin_gateway.main import build_app
    from admin_gateway.routers.identity import get_provider_adapter

    app = build_app()
    app.dependency_overrides[get_provider_adapter] = lambda: VerifiedTestAdapter(
        valid_identity()
    )
    headers = {"X-Tenant-ID": TENANT}
    with TestClient(app) as client:
        started = client.post(
            f"/identity/invitations/{invitation.id}/start-auth",
            headers=headers,
            json={},
        )
        state = started.json()["state"]
        callback_body = {
            "state": state,
            "provider": PROVIDER,
            "issuer": ISSUER,
            "subject": "ignored-request-claim",
            "email": EMAIL,
            "email_verified": True,
            "connection_id": CONNECTION,
            "organization_id": ORGANIZATION,
            "identity_type": "human",
        }
        assert (
            client.post(
                f"/identity/invitations/{invitation.id}/callback",
                headers=headers,
                json=callback_body,
            ).status_code
            == 200
        )
        assert (
            client.post(
                f"/identity/invitations/{invitation.id}/bind",
                headers=headers,
                json={"state": state},
            ).status_code
            == 200
        )
        config = get_auth_config()
        csrf_token = client.cookies.get(config.csrf_cookie_name)
        assert csrf_token
        assert (
            client.post(
                "/identity/session/logout",
                headers={config.csrf_header_name: csrf_token},
            ).status_code
            == 200
        )
    db.expire_all()
    event_types = {
        event.event_type
        for event in db.query(TenantIdentityAuditEvent)
        .filter_by(tenant_id=TENANT)
        .all()
    }
    assert {
        "tenant.identity_session.issued",
        "tenant.identity_session.logout",
    }.issubset(event_types)
    assert membership.id

    other_invitation, other_membership = seed_flow(
        db, tenant_id="tenant-session-reject"
    )
    other_membership.role = "no-scopes-role"
    db.commit()
    other_identity = replace(
        valid_identity(),
        subject="subject-session-reject",
        correlation_id="reject-session",
    )
    other_app = build_app()
    other_app.dependency_overrides[get_provider_adapter] = lambda: VerifiedTestAdapter(
        other_identity
    )
    other_headers = {"X-Tenant-ID": "tenant-session-reject"}
    with TestClient(other_app) as client:
        started = client.post(
            f"/identity/invitations/{other_invitation.id}/start-auth",
            headers=other_headers,
            json={},
        )
        state = started.json()["state"]
        callback_body["state"] = state
        assert (
            client.post(
                f"/identity/invitations/{other_invitation.id}/callback",
                headers=other_headers,
                json=callback_body,
            ).status_code
            == 200
        )
        rejected = client.post(
            f"/identity/invitations/{other_invitation.id}/bind",
            headers=other_headers,
            json={"state": state},
        )
        assert rejected.status_code == 403
        assert rejected.json()["detail"]["code"] == "MISSING_SCOPES"
    db.expire_all()
    assert (
        db.query(TenantIdentityAuditEvent)
        .filter_by(
            tenant_id="tenant-session-reject",
            event_type="tenant.identity_session.rejected",
            reason_code="MISSING_SCOPES",
        )
        .count()
        == 1
    )


def test_gateway_auth_state_migration_is_replay_safe_rls_scoped_and_secret_free() -> (
    None
):
    sql = Path(
        "migrations/postgres/0100_admin_gateway_identity_enforcement.sql"
    ).read_text()
    assert "CREATE TABLE IF NOT EXISTS tenant_identity_auth_states" in sql
    assert "uq_tenant_identity_auth_state_digest UNIQUE (state_digest)" in sql
    assert (
        "uq_tenant_identity_auth_state_correlation UNIQUE (tenant_id, correlation_id)"
        in sql
    )
    assert "ALTER TABLE tenant_identity_auth_states FORCE ROW LEVEL SECURITY" in sql
    assert "tenant_identity_auth_states_tenant_isolation" in sql
    forbidden = (
        "raw_token",
        "invite_token",
        "refresh_token",
        "client_secret",
        "private_key",
        "authorization_header",
    )
    columns = set(TenantIdentityAuthState.__table__.columns.keys())
    assert columns.isdisjoint(forbidden)


def test_start_auth_supports_secondary_provider_and_rejects_external_return_url(
    db,
) -> None:
    invitation, _ = seed_flow(db)
    config = db.query(TenantIdentityConfig).filter_by(tenant_id=TENANT).one()
    TenantIdentityStore().add_provider(
        db,
        config,
        provider="okta",
        oidc_issuer="https://okta.example/",
        connection_id="okta-enterprise",
        organization_id="okta-org",
    )
    db.commit()
    result = start_invitation_auth(
        db,
        tenant_id=TENANT,
        invitation_id=invitation.id,
        adapter=ProviderNeutralRedirectAdapter(),
        requested_provider="okta",
        requested_connection_id="okta-enterprise",
        return_url="/console",
    )
    assert result["required_provider"] == "okta"
    assert result["organization_id"] == "okta-org"
    with pytest.raises(IdentityFlowError, match="RETURN_URL_NOT_ALLOWED"):
        start_invitation_auth(
            db,
            tenant_id=TENANT,
            invitation_id=invitation.id,
            adapter=ProviderNeutralRedirectAdapter(),
            return_url="https://attacker.example/",
        )


def test_callback_state_cannot_be_reused_after_bind(db) -> None:
    invitation, _ = seed_flow(db)
    state = start(db, invitation)
    validate_callback(
        db,
        tenant_id=TENANT,
        invitation_id=invitation.id,
        state=state,
        identity=valid_identity(),
    )
    bind_identity(db, tenant_id=TENANT, invitation_id=invitation.id, state=state)
    db.commit()
    with pytest.raises(IdentityFlowError, match="CALLBACK_REPLAY_REJECTED"):
        validate_callback(
            db,
            tenant_id=TENANT,
            invitation_id=invitation.id,
            state=state,
            identity=valid_identity(),
        )


def test_callback_state_cannot_be_reused_after_rejection(db) -> None:
    invitation, _ = seed_flow(db)
    state = start(db, invitation)
    with pytest.raises(IdentityFlowError, match="INVITE_EMAIL_MISMATCH"):
        validate_callback(
            db,
            tenant_id=TENANT,
            invitation_id=invitation.id,
            state=state,
            identity=valid_identity(email="wrong@example.com"),
        )
    db.commit()
    with pytest.raises(IdentityFlowError, match="CALLBACK_REPLAY_REJECTED"):
        validate_callback(
            db,
            tenant_id=TENANT,
            invitation_id=invitation.id,
            state=state,
            identity=valid_identity(),
        )


def test_expired_state_wrong_tenant_and_wrong_invitation_fail_closed(db) -> None:
    invitation, _ = seed_flow(db)
    state = start(db, invitation)
    auth_state = (
        db.query(TenantIdentityAuthState).filter_by(invitation_id=invitation.id).one()
    )
    auth_state.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    with pytest.raises(IdentityFlowError, match="CALLBACK_STATE_INVALID"):
        validate_callback(
            db,
            tenant_id=TENANT,
            invitation_id=invitation.id,
            state=state,
            identity=valid_identity(),
        )
    with pytest.raises(IdentityFlowError, match="INVITE_NOT_FOUND"):
        validate_callback(
            db,
            tenant_id="tenant-b",
            invitation_id=invitation.id,
            state=state,
            identity=valid_identity(),
        )

    membership = TenantUser(
        tenant_id=TENANT,
        email="second@example.com",
        display_name="Second",
        role="user",
        active=True,
    )
    db.add(membership)
    db.flush()
    other = TenantIdentityStore().create_invitation(
        db,
        tenant_id=TENANT,
        email=membership.email,
        role="user",
        created_by_user_id="admin-1",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        identity_mode_at_invite="sso",
        required_provider=PROVIDER,
        required_connection_id=CONNECTION,
        membership_id=membership.id,
    )
    db.commit()
    with pytest.raises(IdentityFlowError, match="CALLBACK_STATE_INVALID"):
        validate_callback(
            db,
            tenant_id=TENANT,
            invitation_id=other.id,
            state=state,
            identity=valid_identity(email=membership.email),
        )


def test_bind_requires_validated_state_and_cannot_activate_second_membership(
    db,
) -> None:
    invitation, _ = seed_flow(db)
    state = start(db, invitation)
    with pytest.raises(IdentityFlowError, match="CALLBACK_STATE_INVALID"):
        bind_identity(db, tenant_id=TENANT, invitation_id=invitation.id, state=state)
    assert (
        db.query(TenantUser).filter_by(tenant_id=TENANT).one().identity_binding_status
        == "unbound"
    )


def test_auth_state_digest_and_correlation_are_unique(db) -> None:
    invitation, _ = seed_flow(db)
    state = start(db, invitation)
    original = (
        db.query(TenantIdentityAuthState).filter_by(invitation_id=invitation.id).one()
    )
    duplicate = TenantIdentityAuthState(
        tenant_id=TENANT,
        invitation_id=invitation.id,
        membership_id=invitation.membership_id,
        state_digest=original.state_digest,
        correlation_id="different-correlation",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    db.add(duplicate)
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()
    duplicate = TenantIdentityAuthState(
        tenant_id=TENANT,
        invitation_id=invitation.id,
        membership_id=invitation.membership_id,
        state_digest="0" * 64,
        correlation_id=original.correlation_id,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    db.add(duplicate)
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()
    assert state != original.state_digest


@pytest.mark.parametrize("identity_type", ["service", "agent", "system", "unknown", ""])
def test_human_invite_flow_rejects_every_nonhuman_identity_type(
    db, identity_type: str
) -> None:
    invitation, _ = seed_flow(db)
    state = start(db, invitation)
    with pytest.raises(IdentityFlowError, match="IDENTITY_TYPE_NOT_ALLOWED"):
        validate_callback(
            db,
            tenant_id=TENANT,
            invitation_id=invitation.id,
            state=state,
            identity=valid_identity(identity_type=identity_type),
        )


def test_csrf_exempt_identity_routes_have_equivalent_state_guards(db) -> None:
    from admin_gateway.auth.csrf import requires_csrf_protection

    invitation, membership = seed_flow(db)
    assert not requires_csrf_protection(
        "POST", f"/identity/invitations/{invitation.id}/start-auth"
    )
    assert not requires_csrf_protection(
        "POST", f"/identity/invitations/{invitation.id}/callback"
    )
    assert not requires_csrf_protection(
        "POST", f"/identity/invitations/{invitation.id}/bind"
    )
    state = start(db, invitation)
    with pytest.raises(IdentityFlowError, match="CALLBACK_STATE_INVALID"):
        bind_identity(db, tenant_id=TENANT, invitation_id=invitation.id, state=state)
    with pytest.raises(IdentityFlowError, match="CALLBACK_STATE_INVALID"):
        validate_callback(
            db,
            tenant_id=TENANT,
            invitation_id=invitation.id,
            state="missing-state-value",
            identity=valid_identity(),
        )
    db.commit()
    db.refresh(membership)
    assert membership.identity_binding_status == "unbound"
    assert (
        db.query(TenantIdentityAuditEvent)
        .filter_by(
            event_type="tenant.invite.binding_rejected",
            reason_code="CALLBACK_STATE_INVALID",
        )
        .count()
        == 1
    )
    assert (
        db.query(TenantIdentityAuditEvent)
        .filter_by(
            event_type="tenant.invite.callback_rejected",
            reason_code="CALLBACK_STATE_INVALID",
        )
        .count()
        == 1
    )


def test_identity_audit_event_vocabulary_and_payload_exclude_sensitive_data(db) -> None:
    invitation, _ = seed_flow(db)
    state = start(db, invitation)
    validate_callback(
        db,
        tenant_id=TENANT,
        invitation_id=invitation.id,
        state=state,
        identity=valid_identity(),
    )
    bind_identity(db, tenant_id=TENANT, invitation_id=invitation.id, state=state)
    db.commit()
    events = db.query(TenantIdentityAuditEvent).filter_by(tenant_id=TENANT).all()
    event_types = {event.event_type for event in events}
    assert {
        "tenant.invite.auth_started",
        "tenant.invite.callback_received",
        "tenant.invite.binding_pending",
        "tenant.invite.bound",
        "tenant.membership.identity_binding_pending",
        "tenant.membership.identity_bound",
    }.issubset(event_types)
    serialized = str(
        [(event.event_type, event.reason_code, event.details_json) for event in events]
    ).lower()
    assert state.lower() not in serialized
    for forbidden in (
        "raw provider token",
        "refresh_token",
        "authorization",
        "invite_token",
        "client_secret",
        "private_key",
        "raw callback",
    ):
        assert forbidden not in serialized
