"""api/identity_administration/self_service.py — Self-service operations.

Users acting on their own identity: profile view/update, devices, timeline.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from typing import Optional

from api.identity_administration.models import (
    IdentityRecord,
)
from api.identity_administration.repositories.base import IdentityRepository
from api.identity_governance.models import DeviceRecord, IdentityTimelineEvent
from api.identity_governance.services import GovernanceServices


class SelfServiceError(Exception):
    """Base class for self-service errors."""


class SelfService:
    """Self-service operations for authenticated users."""

    def __init__(
        self,
        identity_repo: IdentityRepository,
        gov_services: GovernanceServices,
    ) -> None:
        self._repo = identity_repo
        self._gov = gov_services

    def get_profile(self, tenant_id: str, subject: str) -> Optional[IdentityRecord]:
        """Return own identity record."""
        return self._repo.get(tenant_id, subject)

    def update_profile(
        self,
        tenant_id: str,
        subject: str,
        display_name: str,
        actor: str,
        *,
        correlation_id: Optional[str] = None,
    ) -> IdentityRecord:
        """Update own display name. Actor must match subject."""
        if actor != subject:
            raise SelfServiceError("Subjects can only update their own profile")
        record = self._repo.get(tenant_id, subject)
        if record is None:
            raise SelfServiceError(f"Identity not found for subject {subject!r}")
        updated = replace(
            record,
            display_name=display_name,
            updated_at=datetime.now(tz=timezone.utc),
        )
        result = self._repo.update(updated)
        # Emit timeline event (best-effort)
        try:
            self._gov.timeline.emit(
                event_type=__import__(
                    "api.identity_governance.models",
                    fromlist=["IdentityTimelineEventType"],
                ).IdentityTimelineEventType.ADMIN_ACTION,
                subject=subject,
                tenant_id=tenant_id,
                actor=actor,
                details={"action": "profile.updated", "display_name": display_name},
                correlation_id=correlation_id,
            )
        except Exception:
            pass
        return result

    def get_own_devices(self, tenant_id: str, subject: str) -> list[DeviceRecord]:
        """Return devices registered for this subject in this tenant."""
        return self._gov.device_registry.list_devices_for_subject(
            subject=subject, tenant_id=tenant_id
        )

    def revoke_own_device(
        self,
        tenant_id: str,
        subject: str,
        device_id: str,
        *,
        correlation_id: Optional[str] = None,
    ) -> None:
        """Revoke own device."""
        device = self._gov.device_registry.get_device(device_id, tenant_id)
        if device is None:
            raise SelfServiceError(f"Device {device_id!r} not found")
        if device.subject != subject:
            raise SelfServiceError("Cannot revoke another user's device")
        self._gov.device_registry.revoke_device(
            device_id=device_id,
            tenant_id=tenant_id,
            reason="self-service revocation",
            actor=subject,
        )

    def get_own_timeline(
        self, tenant_id: str, subject: str, limit: int
    ) -> list[IdentityTimelineEvent]:
        """Return recent timeline events for this subject."""
        return self._gov.timeline.query(
            tenant_id=tenant_id,
            subject=subject,
            limit=limit,
        )


__all__ = ["SelfService", "SelfServiceError"]
