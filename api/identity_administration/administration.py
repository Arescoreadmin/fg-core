"""api/identity_administration/administration.py — Admin operations service.

Wraps governance services + identity repository for admin-level lifecycle
management: invite, transition, terminate session, revoke/trust device.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from typing import Optional

from api.identity_administration.invitation import InvitationService
from api.identity_administration.models import (
    AdminActionType,
    AdminAuditRecord,
    IdentityRecord,
    Invitation,
    NotificationEvent,
    NotificationEventType,
)
from api.identity_administration.notification import NotificationPublisher
from api.identity_administration.repositories.base import (
    AuditRepository,
    IdentityRepository,
)
from api.identity_governance.models import (
    IdentityLifecycleState,
    IdentityTimelineEventType,
)
from api.identity_governance.services import GovernanceServices, get_services
from api.identity_governance.snapshots import (
    SnapshotMeta,
    IdentitySnapshot,
    compute_replay_version,
)

log = logging.getLogger("frostgate.identity_administration")


def _build_identity_snapshot(
    record: IdentityRecord,
    roles: tuple[str, ...],
    permissions: tuple[str, ...],
) -> IdentitySnapshot:
    """Build a canonical IdentitySnapshot for digital twin export."""
    now = datetime.now(tz=timezone.utc)
    replay = compute_replay_version(
        record.subject, record.lifecycle_state.value, *sorted(roles)
    )
    data_fields_for_fp: dict[str, object] = {
        "identity_id": record.subject,
        "lifecycle_state": record.lifecycle_state.value,
        "roles": sorted(roles),
        "permissions": sorted(permissions),
        "capabilities": [],
    }
    fp = hashlib.sha256(
        json.dumps(data_fields_for_fp, sort_keys=True).encode()
    ).hexdigest()
    meta = SnapshotMeta(
        tenant_id=record.tenant_id,
        generated_at=now,
        fingerprint=fp,
        schema_version="identity/1.0",
        replay_version=replay,
        source_version="identity_administration/1.0.0",
        generated_by="identity_administration_service",
    )
    return IdentitySnapshot(
        meta=meta,
        identity_id=record.subject,
        lifecycle_state=record.lifecycle_state,
        roles=tuple(sorted(roles)),
        permissions=tuple(sorted(permissions)),
        capabilities=(),
    )


class IdentityAdministrationService:
    """Admin operations service for identity lifecycle management."""

    def __init__(
        self,
        identity_repo: IdentityRepository,
        invitation_service: InvitationService,
        audit_repo: AuditRepository,
        notification_publisher: NotificationPublisher,
    ) -> None:
        self._repo = identity_repo
        self._invitation_svc = invitation_service
        self._audit_repo = audit_repo
        self._publisher = notification_publisher

    def _gov(self) -> GovernanceServices:
        return get_services()

    # ------------------------------------------------------------------
    # Invitation flow
    # ------------------------------------------------------------------

    def invite_user(
        self,
        tenant_id: str,
        email: str,
        actor: str,
        *,
        display_name: str = "",
        custom_message: str = "",
        assigned_roles: tuple[str, ...] = (),
        assigned_capabilities: tuple[str, ...] = (),
        expiry_days: int = 7,
        correlation_id: Optional[str] = None,
    ) -> tuple[IdentityRecord, Invitation, str]:
        """Create or update identity record + create invitation.

        Creates identity in CREATED→INVITED state.
        Emits INVITATION_CREATED notification.
        Returns (identity_record, invitation, raw_token).
        """
        now = datetime.now(tz=timezone.utc)

        # Check if identity record already exists for this email
        existing_record = self._repo.get_by_email(tenant_id, email)
        if existing_record is not None:
            identity_record = existing_record
        else:
            # Create identity in CREATED state first, then transition to INVITED
            subject = str(uuid.uuid4())
            identity_record = IdentityRecord(
                record_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                subject=subject,
                email=email,
                display_name=display_name or email,
                lifecycle_state=IdentityLifecycleState.CREATED,
                created_at=now,
                updated_at=now,
                invited_by=actor,
            )
            self._repo.create(identity_record)

        # Transition to INVITED via lifecycle manager (validates transition)
        gov = self._gov()
        gov.lifecycle_manager.transition(
            subject=identity_record.subject,
            tenant_id=tenant_id,
            current_state=identity_record.lifecycle_state,
            next_state=IdentityLifecycleState.INVITED,
            reason=f"invited by {actor}",
            actor=actor,
        )
        identity_record = replace(
            identity_record,
            lifecycle_state=IdentityLifecycleState.INVITED,
            updated_at=now,
            invited_by=actor,
        )
        self._repo.update(identity_record)

        # Create invitation
        invitation, raw_token = self._invitation_svc.create_invitation(
            tenant_id=tenant_id,
            email=email,
            invited_by=actor,
            custom_message=custom_message,
            assigned_roles=assigned_roles,
            assigned_capabilities=assigned_capabilities,
            expiry_days=expiry_days,
            correlation_id=correlation_id,
        )

        # Link invitation to identity record
        identity_record = replace(
            identity_record,
            invitation_id=invitation.invitation_id,
        )
        self._repo.update(identity_record)

        # Emit timeline event (best-effort)
        self._emit_timeline_event(
            event_type=IdentityTimelineEventType.ADMIN_ACTION,
            subject=identity_record.subject,
            tenant_id=tenant_id,
            actor=actor,
            details={
                "action": "user.invited",
                "email": email,
                "invitation_id": invitation.invitation_id,
            },
            correlation_id=correlation_id,
            gov=gov,
        )

        # Emit notification
        self._publisher.publish(
            NotificationEvent(
                event_type=NotificationEventType.INVITATION_CREATED,
                tenant_id=tenant_id,
                subject=identity_record.subject,
                actor=actor,
                occurred_at=now,
                correlation_id=correlation_id,
                payload=(("email", email), ("invitation_id", invitation.invitation_id)),
            )
        )

        # Audit record
        self._create_audit_record(
            tenant_id=tenant_id,
            action=AdminActionType.INVITE,
            actor=actor,
            subject=identity_record.subject,
            reason=f"invited user {email}",
            previous_state=IdentityLifecycleState.CREATED.value,
            new_state=IdentityLifecycleState.INVITED.value,
            correlation_id=correlation_id,
            object_id=invitation.invitation_id,
            object_type="invitation",
        )

        return identity_record, invitation, raw_token

    # ------------------------------------------------------------------
    # Lifecycle transitions
    # ------------------------------------------------------------------

    def transition_lifecycle(
        self,
        tenant_id: str,
        subject: str,
        target_state: IdentityLifecycleState,
        actor: str,
        reason: str,
        *,
        correlation_id: Optional[str] = None,
    ) -> IdentityRecord:
        """Transition identity lifecycle state.

        Emits timeline event + notification + audit record.
        """
        record = self._repo.get(tenant_id, subject)
        if record is None:
            raise ValueError(f"Identity not found for subject {subject!r} in tenant")

        gov = self._gov()
        previous_state = record.lifecycle_state

        # Validate transition via lifecycle manager
        gov.lifecycle_manager.transition(
            subject=subject,
            tenant_id=tenant_id,
            current_state=previous_state,
            next_state=target_state,
            reason=reason,
            actor=actor,
        )

        # Update identity record
        now = datetime.now(tz=timezone.utc)
        updated_record = replace(
            record,
            lifecycle_state=target_state,
            updated_at=now,
        )
        self._repo.update(updated_record)

        # Emit timeline event (best-effort)
        self._emit_timeline_event(
            event_type=IdentityTimelineEventType.ADMIN_ACTION,
            subject=subject,
            tenant_id=tenant_id,
            actor=actor,
            details={
                "action": "lifecycle.transition",
                "from_state": previous_state.value,
                "to_state": target_state.value,
                "reason": reason,
            },
            correlation_id=correlation_id,
            gov=gov,
        )

        # Update digital twin (best-effort)
        self._update_digital_twin(updated_record, gov=gov)

        # Determine notification type
        notification_type = self._lifecycle_notification_type(target_state)
        if notification_type is not None:
            self._publisher.publish(
                NotificationEvent(
                    event_type=notification_type,
                    tenant_id=tenant_id,
                    subject=subject,
                    actor=actor,
                    occurred_at=now,
                    correlation_id=correlation_id,
                    payload=(
                        ("from_state", previous_state.value),
                        ("to_state", target_state.value),
                    ),
                )
            )

        # Audit record
        action = self._lifecycle_action_type(target_state)
        self._create_audit_record(
            tenant_id=tenant_id,
            action=action,
            actor=actor,
            subject=subject,
            reason=reason,
            previous_state=previous_state.value,
            new_state=target_state.value,
            correlation_id=correlation_id,
        )

        return updated_record

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def terminate_session(
        self,
        tenant_id: str,
        subject: str,
        session_id: str,
        actor: str,
        reason: str,
        *,
        correlation_id: Optional[str] = None,
    ) -> None:
        """Terminate a session via SessionAuthority. Emits notification + audit."""
        from api.identity_authority.authority import get_identity_authority

        authority = get_identity_authority()
        authority.logout(session_id, subject=subject, correlation_id=correlation_id)

        now = datetime.now(tz=timezone.utc)
        self._publisher.publish(
            NotificationEvent(
                event_type=NotificationEventType.SESSION_REVOKED,
                tenant_id=tenant_id,
                subject=subject,
                actor=actor,
                occurred_at=now,
                correlation_id=correlation_id,
                payload=(("session_id", session_id), ("reason", reason)),
            )
        )

        self._create_audit_record(
            tenant_id=tenant_id,
            action=AdminActionType.TERMINATE_SESSION,
            actor=actor,
            subject=subject,
            reason=reason,
            previous_state="",
            new_state="",
            correlation_id=correlation_id,
            object_id=session_id,
            object_type="session",
        )

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def revoke_device(
        self,
        tenant_id: str,
        subject: str,
        device_id: str,
        actor: str,
        reason: str,
        *,
        correlation_id: Optional[str] = None,
    ) -> None:
        """Revoke a device via DeviceTrustRegistry. Emits notification + audit."""
        gov = self._gov()
        gov.device_registry.revoke_device(
            device_id=device_id,
            tenant_id=tenant_id,
            reason=reason,
            actor=actor,
        )

        now = datetime.now(tz=timezone.utc)
        self._publisher.publish(
            NotificationEvent(
                event_type=NotificationEventType.DEVICE_REVOKED,
                tenant_id=tenant_id,
                subject=subject,
                actor=actor,
                occurred_at=now,
                correlation_id=correlation_id,
                payload=(("device_id", device_id), ("reason", reason)),
            )
        )

        self._create_audit_record(
            tenant_id=tenant_id,
            action=AdminActionType.REVOKE_DEVICE,
            actor=actor,
            subject=subject,
            reason=reason,
            previous_state="",
            new_state="REVOKED",
            correlation_id=correlation_id,
            object_id=device_id,
            object_type="device",
        )

    def trust_device(
        self,
        tenant_id: str,
        subject: str,
        device_id: str,
        actor: str,
        *,
        correlation_id: Optional[str] = None,
    ) -> None:
        """Mark device as TRUSTED via DeviceTrustRegistry. Emits notification + audit."""
        from api.identity_governance.models import DeviceTrustState

        gov = self._gov()
        gov.device_registry.update_trust_state(
            device_id=device_id,
            tenant_id=tenant_id,
            new_state=DeviceTrustState.TRUSTED,
            reason="admin trust action",
            actor=actor,
        )

        now = datetime.now(tz=timezone.utc)
        self._publisher.publish(
            NotificationEvent(
                event_type=NotificationEventType.DEVICE_TRUSTED,
                tenant_id=tenant_id,
                subject=subject,
                actor=actor,
                occurred_at=now,
                correlation_id=correlation_id,
                payload=(("device_id", device_id),),
            )
        )

        self._create_audit_record(
            tenant_id=tenant_id,
            action=AdminActionType.TRUST_DEVICE,
            actor=actor,
            subject=subject,
            reason="admin trust action",
            previous_state="",
            new_state="TRUSTED",
            correlation_id=correlation_id,
            object_id=device_id,
            object_type="device",
        )

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_identity(self, tenant_id: str, subject: str) -> Optional[IdentityRecord]:
        """Return identity record or None."""
        return self._repo.get(tenant_id, subject)

    def list_identities(
        self, tenant_id: str, limit: int, offset: int
    ) -> tuple[list[IdentityRecord], int]:
        """Return paginated identity list and total count."""
        records = self._repo.list_for_tenant(tenant_id, limit=limit, offset=offset)
        total = self._repo.count_for_tenant(tenant_id)
        return records, total

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _emit_timeline_event(
        self,
        event_type: IdentityTimelineEventType,
        subject: str,
        tenant_id: str,
        actor: str,
        details: dict[str, object],
        correlation_id: Optional[str],
        gov: GovernanceServices,
    ) -> None:
        """Emit timeline event (best-effort — never raises)."""
        try:
            gov.timeline.emit(
                event_type=event_type,
                subject=subject,
                tenant_id=tenant_id,
                actor=actor,
                details=details,
                correlation_id=correlation_id,
            )
        except Exception as exc:
            log.warning(
                "identity_administration.timeline_emit_failed",
                extra={"exc": str(exc)},
            )

    def _update_digital_twin(
        self, record: IdentityRecord, gov: GovernanceServices
    ) -> None:
        """Update digital twin snapshot (best-effort — never raises)."""
        try:
            from api.identity_governance.digital_twin import IdentityDigitalTwinExporter

            exporter = IdentityDigitalTwinExporter()
            exporter.export(
                subject=record.subject,
                tenant_id=record.tenant_id,
                lifecycle_state=record.lifecycle_state,
            )
        except Exception as exc:
            log.warning(
                "identity_administration.digital_twin_update_failed",
                extra={"exc": str(exc)},
            )

    def _create_audit_record(
        self,
        *,
        tenant_id: str,
        action: AdminActionType,
        actor: str,
        subject: str,
        reason: str,
        previous_state: str,
        new_state: str,
        correlation_id: Optional[str] = None,
        object_id: Optional[str] = None,
        object_type: Optional[str] = None,
    ) -> None:
        """Persist audit record (best-effort — never raises)."""
        try:
            audit = AdminAuditRecord(
                audit_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                action=action,
                actor=actor,
                subject=subject,
                occurred_at=datetime.now(tz=timezone.utc),
                reason=reason,
                previous_state=previous_state,
                new_state=new_state,
                correlation_id=correlation_id,
                object_id=object_id,
                object_type=object_type,
            )
            self._audit_repo.create(audit)
        except Exception as exc:
            log.warning(
                "identity_administration.audit_create_failed",
                extra={"exc": str(exc)},
            )

    @staticmethod
    def _lifecycle_notification_type(
        state: IdentityLifecycleState,
    ) -> Optional[NotificationEventType]:
        """Map lifecycle state to notification type."""
        mapping: dict[IdentityLifecycleState, NotificationEventType] = {
            IdentityLifecycleState.ACTIVE: NotificationEventType.USER_ACTIVATED,
            IdentityLifecycleState.SUSPENDED: NotificationEventType.USER_SUSPENDED,
            IdentityLifecycleState.DISABLED: NotificationEventType.USER_DISABLED,
            IdentityLifecycleState.LOCKED: NotificationEventType.USER_LOCKED,
        }
        return mapping.get(state)

    @staticmethod
    def _lifecycle_action_type(
        state: IdentityLifecycleState,
    ) -> AdminActionType:
        """Map lifecycle state to audit action type."""
        mapping: dict[IdentityLifecycleState, AdminActionType] = {
            IdentityLifecycleState.SUSPENDED: AdminActionType.SUSPEND,
            IdentityLifecycleState.DISABLED: AdminActionType.DISABLE,
            IdentityLifecycleState.ARCHIVED: AdminActionType.ARCHIVE,
            IdentityLifecycleState.DELETED: AdminActionType.DELETE,
            IdentityLifecycleState.ACTIVE: AdminActionType.RESTORE,
            IdentityLifecycleState.LOCKED: AdminActionType.FORCE_MFA,
        }
        return mapping.get(state, AdminActionType.RESTORE)


__all__ = [
    "IdentityAdministrationService",
]
