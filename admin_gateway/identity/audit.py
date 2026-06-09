"""Hash-chain-compatible identity audit writes owned by Admin Gateway."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from admin_gateway.identity.models import TenantIdentityAuditEvent, TenantInvitation
from admin_gateway.identity.policy import IdentityPolicyError, normalize_invite_email

IDENTITY_AUDIT_EVENTS = frozenset(
    {
        "tenant.invite.auth_started",
        "tenant.invite.binding_pending",
        "tenant.invite.bound",
        "tenant.membership.identity_binding_pending",
        "tenant.membership.identity_bound",
        "tenant.membership.identity_binding_failed",
        "tenant.invite.callback_received",
        "tenant.invite.callback_rejected",
        "tenant.invite.binding_rejected",
        "tenant.identity_session.issued",
        "tenant.identity_session.rejected",
        "tenant.identity_session.logout",
        # Auth0 adapter provisioning events (PR 3)
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
)
INVITATION_TRANSITIONS = {
    "pending": frozenset({"auth_started", "expired", "revoked", "failed"}),
    "auth_started": frozenset(
        {"accepted_identity_pending_binding", "expired", "revoked", "failed"}
    ),
    "accepted_identity_pending_binding": frozenset(
        {"bound", "expired", "revoked", "failed"}
    ),
    "bound": frozenset(),
    "expired": frozenset(),
    "revoked": frozenset(),
    "failed": frozenset(),
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _canonical_timestamp(value: datetime) -> str:
    timestamp = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _canonical_hash(payload: Any) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def emit_identity_audit_event(
    db: Session,
    *,
    tenant_id: str,
    event_type: str,
    actor_user_id: str | None = None,
    affected_email: str | None = None,
    invitation_id: str | None = None,
    membership_id: str | None = None,
    identity_mode: str | None = None,
    provider: str | None = None,
    connection_id: str | None = None,
    reason_code: str | None = None,
    identity_type: str | None = None,
    identity_subject: str | None = None,
    provider_record_id: str | None = None,
    policy_config_id: str | None = None,
    role_assignment_id: str | None = None,
    correlation_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> TenantIdentityAuditEvent:
    if event_type not in IDENTITY_AUDIT_EVENTS:
        raise IdentityPolicyError("IDENTITY_AUDIT_EVENT_INVALID", event_type)
    safe_keys = {
        "invitation_status",
        "membership_binding_status",
        "role",
        "session_status",
    }
    safe_details = {k: v for k, v in (details or {}).items() if k in safe_keys}
    created_at, event_id = _now(), str(uuid.uuid4())
    previous = (
        db.query(TenantIdentityAuditEvent)
        .filter(TenantIdentityAuditEvent.tenant_id == tenant_id)
        .order_by(
            TenantIdentityAuditEvent.created_at.desc(),
            TenantIdentityAuditEvent.id.desc(),
        )
        .first()
    )
    previous_hash = previous.event_hash if previous else None
    normalized_email = (
        normalize_invite_email(affected_email) if affected_email else None
    )
    payload = {
        "id": event_id,
        "tenant_id": tenant_id,
        "event_type": event_type,
        "actor_user_id": actor_user_id,
        "affected_email": normalized_email,
        "invitation_id": invitation_id,
        "membership_id": membership_id,
        "identity_mode": identity_mode,
        "provider": provider,
        "connection_id": connection_id,
        "reason_code": reason_code,
        "identity_type": identity_type,
        "identity_subject": identity_subject,
        "provider_record_id": provider_record_id,
        "policy_config_id": policy_config_id,
        "role_assignment_id": role_assignment_id,
        "correlation_id": correlation_id,
        "details": safe_details,
        "created_at": _canonical_timestamp(created_at),
        "previous_event_hash": previous_hash,
    }
    row = TenantIdentityAuditEvent(
        id=event_id,
        tenant_id=tenant_id,
        event_type=event_type,
        actor_user_id=actor_user_id,
        affected_email=normalized_email,
        invitation_id=invitation_id,
        membership_id=membership_id,
        identity_mode=identity_mode,
        provider=provider,
        connection_id=connection_id,
        reason_code=reason_code,
        identity_type=identity_type,
        identity_subject=identity_subject,
        provider_record_id=provider_record_id,
        policy_config_id=policy_config_id,
        role_assignment_id=role_assignment_id,
        correlation_id=correlation_id,
        previous_event_hash=previous_hash,
        event_hash=_canonical_hash(payload),
        details_json=safe_details,
        created_at=created_at,
    )
    db.add(row)
    db.flush()
    return row


def transition_invitation(
    db: Session,
    invitation: TenantInvitation,
    *,
    to_status: str,
    actor_user_id: str | None = None,
    reason_code: str | None = None,
) -> TenantInvitation:
    if to_status not in INVITATION_TRANSITIONS.get(invitation.status, frozenset()):
        raise IdentityPolicyError(
            "INVITATION_TRANSITION_INVALID",
            f"{invitation.status!r} cannot transition to {to_status!r}",
        )
    events = {
        "auth_started": "tenant.invite.auth_started",
        "accepted_identity_pending_binding": "tenant.invite.binding_pending",
        "bound": "tenant.invite.bound",
        "expired": "tenant.invite.expired",
        "revoked": "tenant.invite.revoked",
        "failed": "tenant.membership.identity_binding_failed",
    }
    now = _now()
    invitation.status = to_status
    invitation.updated_at = now
    if to_status == "accepted_identity_pending_binding":
        invitation.accepted_at = now
        invitation.approved_by_user_id = actor_user_id
        invitation.approved_at = now
    if to_status == "bound":
        invitation.bound_at = now
    if to_status == "revoked":
        invitation.revoked_at = now
        invitation.revoked_by_user_id = actor_user_id
    emit_identity_audit_event(
        db,
        tenant_id=invitation.tenant_id,
        event_type=events[to_status],
        actor_user_id=actor_user_id,
        affected_email=invitation.normalized_email,
        invitation_id=invitation.id,
        membership_id=invitation.membership_id,
        identity_mode=invitation.identity_mode_at_invite,
        provider=invitation.required_provider,
        connection_id=invitation.required_connection_id,
        provider_record_id=invitation.required_provider_record_id,
        policy_config_id=invitation.identity_policy_config_id,
        reason_code=reason_code,
        details={"invitation_status": to_status},
    )
    return invitation
