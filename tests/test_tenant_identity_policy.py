"""PR 1 tenant identity schema and provider-neutral policy foundation tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError

from api.db import get_sessionmaker, init_db, reset_engine_cache
from api.db_models import TenantUser
from api.db_models_identity import (
    TenantIdentityAuditEvent,
    TenantIdentityConfig,
    TenantIdentityDomain,
    TenantIdentityProvider,
    TenantIdentityRoleAssignment,
    TenantInvitation,
)
from api.identity.store import TenantIdentityStore, verify_identity_audit_chain
from api.identity.tenant_identity_policy import (
    IdentityPolicyError,
    TenantIdentityPolicy,
    can_membership_be_activated_from_identity,
    get_tenant_identity_policy,
    is_email_domain_allowed,
    is_provider_allowed_for_tenant,
    require_identity_configured,
    validate_invite_email_matches_identity,
)


@pytest.fixture()
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = str(tmp_path / "identity.db")
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", path)
    reset_engine_cache()
    init_db(sqlite_path=path)
    session = get_sessionmaker(sqlite_path=path)()
    try:
        yield session
    finally:
        session.close()
        reset_engine_cache()


def test_create_config_and_audit(db) -> None:
    row = TenantIdentityStore().create_config(
        db,
        tenant_id="tenant-a",
        identity_mode="managed",
        configured_by_user_id="admin-1",
        provisioning_status="ready",
    )
    db.commit()
    assert row.provider == "auth0"
    event = db.query(TenantIdentityAuditEvent).one()
    assert event.event_type == "tenant.identity_config.created"
    assert event.tenant_id == "tenant-a"


def test_config_status_change_emits_audit(db) -> None:
    store = TenantIdentityStore()
    config = store.create_config(
        db,
        tenant_id="tenant-a",
        identity_mode="sso",
        configured_by_user_id="admin-1",
        provisioning_status="pending",
    )
    store.set_provisioning_status(
        db, config, provisioning_status="ready", actor_user_id="admin-1"
    )
    db.commit()
    assert [
        event.event_type
        for event in db.query(TenantIdentityAuditEvent).order_by(
            TenantIdentityAuditEvent.created_at
        )
    ] == ["tenant.identity_config.created", "tenant.identity_config.provisioning_ready"]


def test_one_config_per_tenant(db) -> None:
    store = TenantIdentityStore()
    store.create_config(
        db, tenant_id="tenant-a", identity_mode="managed", configured_by_user_id=None
    )
    db.flush()
    with pytest.raises(IdentityPolicyError, match="TENANT_IDENTITY_CONFIG_EXISTS"):
        store.create_config(
            db, tenant_id="tenant-a", identity_mode="sso", configured_by_user_id=None
        )


def test_unknown_or_not_ready_policy_fails_closed(db) -> None:
    with pytest.raises(IdentityPolicyError, match="TENANT_IDENTITY_NOT_CONFIGURED"):
        require_identity_configured(db, "unknown")
    TenantIdentityStore().create_config(
        db, tenant_id="tenant-a", identity_mode="managed", configured_by_user_id=None
    )
    db.flush()
    with pytest.raises(IdentityPolicyError, match="TENANT_IDENTITY_NOT_READY"):
        require_identity_configured(db, "tenant-a")


def test_wrong_email_fails_policy_validation() -> None:
    decision = validate_invite_email_matches_identity(
        "person@example.com", "other@example.com"
    )
    assert not decision.allowed and decision.code == "INVITE_EMAIL_MISMATCH"


def test_domain_policy_allows_and_denies() -> None:
    policy = TenantIdentityPolicy(
        "t", "sso", "auth0", "ready", ("example.com",), "conn-1", sso_enforced=True
    )
    assert is_email_domain_allowed(policy, "Person@Example.com")
    assert not is_email_domain_allowed(policy, "person@outside.com")


def test_pending_invite_cannot_activate_membership() -> None:
    policy = TenantIdentityPolicy("t", "managed", "auth0", "ready")
    decision = can_membership_be_activated_from_identity(
        invitation_status="pending",
        membership_binding_status="bound",
        identity_email_verified=True,
        invite_email="person@example.com",
        authenticated_email="person@example.com",
        policy=policy,
        authenticated_provider="auth0",
        connection_id=None,
    )
    assert not decision.allowed and decision.code == "INVITATION_NOT_BOUND"


def test_invitation_created_pending_with_audit(db) -> None:
    invitation = TenantIdentityStore().create_invitation(
        db,
        tenant_id="tenant-a",
        email=" Person@Example.COM ",
        role="admin",
        created_by_user_id="admin-1",
        expires_at=datetime.now(timezone.utc) + timedelta(days=3),
        identity_mode_at_invite="managed",
        required_provider="auth0",
    )
    db.commit()
    assert invitation.status == "pending"
    assert invitation.normalized_email == "person@example.com"
    event = db.query(TenantIdentityAuditEvent).one()
    assert event.event_type == "tenant.invite.created"
    assert "token" not in str(event.details_json).lower()


def test_invitation_lifecycle_audited_and_cannot_skip_binding(db) -> None:
    store = TenantIdentityStore()
    invitation = store.create_invitation(
        db,
        tenant_id="tenant-a",
        email="person@example.com",
        role="user",
        created_by_user_id=None,
        expires_at=None,
        identity_mode_at_invite="sso",
        required_provider="auth0",
        required_connection_id="conn-1",
    )
    db.flush()
    with pytest.raises(IdentityPolicyError, match="INVITATION_TRANSITION_INVALID"):
        store.transition_invitation(db, invitation, to_status="bound")
    store.transition_invitation(db, invitation, to_status="auth_started")
    store.transition_invitation(
        db, invitation, to_status="accepted_identity_pending_binding"
    )
    store.transition_invitation(db, invitation, to_status="bound")
    db.commit()
    assert [
        e.event_type
        for e in db.query(TenantIdentityAuditEvent).order_by(
            TenantIdentityAuditEvent.created_at
        )
    ] == [
        "tenant.invite.created",
        "tenant.invite.auth_started",
        "tenant.invite.binding_pending",
        "tenant.invite.bound",
    ]


def test_existing_membership_remains_unbound_not_rebound(db) -> None:
    user = TenantUser(
        tenant_id="tenant-a",
        email="person@example.com",
        display_name="Person",
        role="user",
        active=True,
    )
    db.add(user)
    db.commit()
    assert user.active is True
    assert user.identity_binding_status == "unbound"
    assert user.identity_subject is None


def test_bound_identity_subject_is_globally_unique(db) -> None:
    for tenant in ("tenant-a", "tenant-b"):
        db.add(
            TenantUser(
                tenant_id=tenant,
                email=f"{tenant}@example.com",
                display_name=tenant,
                role="user",
                active=True,
                identity_provider="auth0",
                identity_issuer="https://issuer.example/",
                identity_subject="auth0|same",
                identity_binding_status="bound",
            )
        )
        if tenant == "tenant-a":
            db.flush()
    with pytest.raises(IntegrityError):
        db.flush()


def test_unbound_identity_subject_is_not_reserved_before_binding(db) -> None:
    for tenant in ("tenant-a", "tenant-b"):
        db.add(
            TenantUser(
                tenant_id=tenant,
                email=f"{tenant}@example.com",
                display_name=tenant,
                role="user",
                active=True,
                identity_provider="auth0",
                identity_issuer="https://issuer.example/",
                identity_subject="auth0|pending",
                identity_binding_status="pending",
            )
        )
    db.commit()


def test_identity_config_schema_contains_no_secret_fields() -> None:
    column_sets = [
        set(model.__table__.columns.keys())
        for model in (
            TenantIdentityConfig,
            TenantIdentityProvider,
            TenantIdentityDomain,
            TenantIdentityRoleAssignment,
        )
    ]
    forbidden = {
        "client_secret",
        "private_key",
        "refresh_token",
        "invite_token",
        "authorization_header",
    }
    assert all(columns.isdisjoint(forbidden) for columns in column_sets)


def test_migration_is_idempotent_safe_and_demo_explicit() -> None:
    sql = Path(
        "migrations/postgres/0099_tenant_identity_policy_foundation.sql"
    ).read_text()
    assert "CREATE TABLE IF NOT EXISTS tenant_identity_configs" in sql
    assert "ADD COLUMN IF NOT EXISTS identity_subject" in sql
    assert "ON CONFLICT (tenant_id) DO NOTHING" in sql
    assert "'demo-bank','managed'" in sql and "'demo-healthcare','managed'" in sql
    assert "WHERE u.invite_token IS NOT NULL" in sql
    assert "'pending'" in sql
    assert "u.invite_token," not in sql
    assert "identity_binding_status VARCHAR(32) NOT NULL DEFAULT 'unbound'" in sql


def test_identity_audit_event_schema_has_required_context() -> None:
    columns = set(TenantIdentityAuditEvent.__table__.columns.keys())
    assert {
        "tenant_id",
        "event_type",
        "actor_user_id",
        "affected_email",
        "invitation_id",
        "identity_mode",
        "provider",
        "connection_id",
        "reason_code",
        "created_at",
    } <= columns
    assert "invite_token" not in columns


def test_invitation_schema_has_required_lifecycle_fields() -> None:
    columns = set(TenantInvitation.__table__.columns.keys())
    assert {
        "tenant_id",
        "normalized_email",
        "status",
        "identity_mode_at_invite",
        "required_provider",
        "identity_policy_config_id",
        "required_provider_record_id",
        "required_connection_id",
        "auth0_invitation_id",
        "expires_at",
        "revoked_at",
        "accepted_at",
        "approved_by_user_id",
        "approved_at",
        "bound_at",
    } <= columns
    assert "invite_token" not in columns


def test_maturity_capability_and_primary_provider_foundation(db) -> None:
    config = TenantIdentityStore().create_config(
        db,
        tenant_id="tenant-a",
        identity_mode="hybrid",
        configured_by_user_id="admin-1",
        provisioning_status="ready",
        maturity_level="level_3",
        capability_flags={"managed_identities": True, "enterprise_sso": True},
        auth0_connection_id="conn-primary",
        allowed_email_domains=["Example.com", "example.com"],
    )
    db.commit()
    assert config.maturity_level == "level_3"
    assert config.capability_flags["enterprise_sso"] is True
    provider = db.query(TenantIdentityProvider).one()
    assert provider.is_primary is True
    assert provider.connection_id == "conn-primary"
    domain = db.query(TenantIdentityDomain).one()
    assert domain.domain == "example.com"
    assert domain.domain_type == "trusted"


def test_multiple_provider_readiness_is_policy_supported(db) -> None:
    store = TenantIdentityStore()
    config = store.create_config(
        db,
        tenant_id="tenant-a",
        identity_mode="hybrid",
        configured_by_user_id="admin-1",
        provisioning_status="ready",
        provider="auth0",
        oidc_issuer="https://issuer-a.example/",
        auth0_connection_id="conn-a",
    )
    store.add_provider(
        db,
        config,
        provider="entra-id",
        oidc_issuer="https://login.microsoftonline.com/tenant/v2.0",
        connection_id="conn-b",
        actor_user_id="admin-1",
    )
    db.commit()
    policy = get_tenant_identity_policy(db, "tenant-a")
    assert policy is not None
    assert len(policy.providers) == 2
    assert is_provider_allowed_for_tenant(
        policy,
        "entra-id",
        issuer="https://login.microsoftonline.com/tenant/v2.0",
        connection_id="conn-b",
    )
    assert not is_provider_allowed_for_tenant(
        policy,
        "entra-id",
        issuer="https://evil.example/",
        connection_id="conn-b",
    )


def test_multiple_domain_governance_allows_trusted_and_blocks_denied(db) -> None:
    store = TenantIdentityStore()
    config = store.create_config(
        db,
        tenant_id="tenant-a",
        identity_mode="hybrid",
        configured_by_user_id="admin-1",
        provisioning_status="ready",
    )
    store.add_domain(db, config, domain="trusted.example", domain_type="trusted")
    store.add_domain(db, config, domain="blocked.example", domain_type="blocked")
    store.add_domain(db, config, domain="federated.example", domain_type="federated")
    db.commit()
    policy = require_identity_configured(db, "tenant-a")
    assert is_email_domain_allowed(policy, "person@trusted.example")
    assert is_email_domain_allowed(policy, "person@federated.example")
    assert not is_email_domain_allowed(policy, "person@blocked.example")
    assert not is_email_domain_allowed(policy, "person@unknown.example")


def test_identity_type_and_risk_readiness_fields_support_non_humans(db) -> None:
    agent = TenantUser(
        tenant_id="tenant-a",
        email="agent-runner@example.com",
        display_name="Assessment Agent",
        role="agent",
        active=True,
        identity_type="agent",
        identity_provider="frostgate-agent",
        identity_subject="agent:assessment-runner:001",
        identity_issuer="fg-core",
        identity_binding_status="pending",
        identity_trust_level="verified",
        identity_verification_level="device-attested",
        identity_risk_state="restricted",
    )
    db.add(agent)
    db.commit()
    assert agent.identity_type == "agent"
    assert agent.identity_risk_state == "restricted"


def test_role_assignment_lineage_record_and_audit(db) -> None:
    assignment = TenantIdentityStore().record_role_assignment(
        db,
        tenant_id="tenant-a",
        membership_id="membership-1",
        role="tenant_admin",
        assignment_source="governance",
        approval_source="manual",
        assigned_by_user_id="admin-1",
        approved_by_user_id="approver-1",
        source_reference="decision-123",
        policy_config_id="policy-1",
    )
    db.commit()
    row = db.query(TenantIdentityRoleAssignment).one()
    assert row.id == assignment.id
    assert row.assignment_source == "governance"
    event = db.query(TenantIdentityAuditEvent).one()
    assert event.event_type == "tenant.membership.role_assigned"
    assert event.role_assignment_id == assignment.id
    assert event.details_json["assignment_source"] == "governance"


def test_identity_audit_events_are_hash_linked_and_context_rich(db) -> None:
    store = TenantIdentityStore()
    config = store.create_config(
        db,
        tenant_id="tenant-a",
        identity_mode="managed",
        configured_by_user_id="admin-1",
        provisioning_status="ready",
    )
    store.set_provisioning_status(
        db, config, provisioning_status="pending", actor_user_id="admin-1"
    )
    db.commit()
    events = (
        db.query(TenantIdentityAuditEvent)
        .order_by(TenantIdentityAuditEvent.created_at, TenantIdentityAuditEvent.id)
        .all()
    )
    assert len(events) == 2
    assert events[0].event_hash and len(events[0].event_hash) == 64
    assert events[1].previous_event_hash == events[0].event_hash
    assert events[1].event_hash != events[0].event_hash
    assert events[0].policy_config_id == config.id
    assert verify_identity_audit_chain(db, "tenant-a")


def test_identity_audit_chain_detects_tampered_event_payload(db) -> None:
    store = TenantIdentityStore()
    store.create_config(
        db,
        tenant_id="tenant-a",
        identity_mode="managed",
        configured_by_user_id="admin-1",
        provisioning_status="ready",
    )
    db.commit()
    event = db.query(TenantIdentityAuditEvent).one()
    event.details_json = {"provisioning_status": "failed"}
    assert not verify_identity_audit_chain(db, "tenant-a")


def test_wrong_tenant_policy_lookup_does_not_leak_identity_records(db) -> None:
    TenantIdentityStore().create_config(
        db,
        tenant_id="tenant-b",
        identity_mode="sso",
        configured_by_user_id="admin-b",
        provisioning_status="ready",
    )
    db.commit()
    assert get_tenant_identity_policy(db, "tenant-a") is None
    assert require_identity_configured(db, "tenant-b").tenant_id == "tenant-b"


def test_hardened_schema_contains_governance_graph_and_risk_fields() -> None:
    assert {
        "maturity_level",
        "capability_flags",
    } <= set(TenantIdentityConfig.__table__.columns.keys())
    assert {
        "identity_type",
        "identity_provider_record_id",
        "identity_policy_config_id",
        "identity_connection_id",
        "identity_trust_level",
        "identity_verification_level",
        "identity_risk_state",
        "identity_approved_by_user_id",
        "identity_approved_at",
        "identity_revoked_at",
    } <= set(TenantUser.__table__.columns.keys())
    assert {
        "provider_record_id",
        "policy_config_id",
        "role_assignment_id",
        "correlation_id",
        "previous_event_hash",
        "event_hash",
    } <= set(TenantIdentityAuditEvent.__table__.columns.keys())


def test_migration_contains_rls_append_only_and_federation_safe_tables() -> None:
    sql = Path(
        "migrations/postgres/0099_tenant_identity_policy_foundation.sql"
    ).read_text()
    for table in (
        "tenant_identity_providers",
        "tenant_identity_domains",
        "tenant_identity_role_assignments",
        "tenant_identity_audit_events",
    ):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in sql
        assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY" in sql
        assert f"CREATE POLICY {table}_tenant_isolation" in sql
    assert "ALTER TABLE tenant_users ENABLE ROW LEVEL SECURITY" in sql
    assert "CREATE POLICY tenant_users_tenant_isolation" in sql
    assert "tenant_identity_audit_events_append_only_update" in sql
    assert "tenant_identity_audit_events_append_only_delete" in sql
    assert "previous_event_hash VARCHAR(64)" in sql
    assert "event_hash VARCHAR(64)" in sql
    assert "tenant_identity_canonical_jsonb" in sql
    assert "ADD COLUMN IF NOT EXISTS identity_type" in sql
    assert "CHECK (identity_type IN ('human','service','agent','system'))" in sql


def test_invitation_lineage_references_policy_provider_and_approver(db) -> None:
    store = TenantIdentityStore()
    config = store.create_config(
        db,
        tenant_id="tenant-a",
        identity_mode="sso",
        configured_by_user_id="admin-1",
        provisioning_status="ready",
        auth0_connection_id="conn-1",
    )
    db.flush()
    provider = db.query(TenantIdentityProvider).one()
    invitation = store.create_invitation(
        db,
        tenant_id="tenant-a",
        email="person@example.com",
        role="user",
        created_by_user_id="admin-1",
        expires_at=None,
        identity_mode_at_invite="sso",
        required_provider="auth0",
        required_connection_id="conn-1",
        identity_policy_config_id=config.id,
        required_provider_record_id=provider.id,
    )
    store.transition_invitation(db, invitation, to_status="auth_started")
    store.transition_invitation(
        db,
        invitation,
        to_status="accepted_identity_pending_binding",
        actor_user_id="approver-1",
    )
    db.commit()
    assert invitation.identity_policy_config_id == config.id
    assert invitation.required_provider_record_id == provider.id
    assert invitation.approved_by_user_id == "approver-1"
    assert invitation.approved_at is not None
    event = (
        db.query(TenantIdentityAuditEvent)
        .filter(TenantIdentityAuditEvent.event_type == "tenant.invite.binding_pending")
        .one()
    )
    assert event.policy_config_id == config.id
    assert event.provider_record_id == provider.id
