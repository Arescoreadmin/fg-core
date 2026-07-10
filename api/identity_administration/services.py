"""api/identity_administration/services.py — Administration service singletons.

Mirrors the pattern from api.identity_governance.services:
- Process-wide singleton container
- Double-checked locking for thread safety
- reset_admin_services() for test teardown
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Optional

from api.identity_administration.administration import IdentityAdministrationService
from api.identity_administration.groups import GroupService
from api.identity_administration.invitation import InvitationService
from api.identity_administration.notification import NotificationPublisher
from api.identity_administration.repositories.base import (
    AuditRepository,
    GroupRepository,
    IdentityRepository,
    InvitationRepository,
)
from api.identity_administration.search import SearchService
from api.identity_administration.self_service import SelfService


@dataclass
class AdministrationServices:
    """Container for the runtime administration service singletons."""

    identity_repo: IdentityRepository
    invitation_repo: InvitationRepository
    group_repo: GroupRepository
    audit_repo: AuditRepository
    invitation_service: InvitationService
    administration_service: IdentityAdministrationService
    self_service: SelfService
    group_service: GroupService
    search_service: SearchService
    notification_publisher: NotificationPublisher


_lock = threading.Lock()
_services: Optional[AdministrationServices] = None


def get_admin_services() -> AdministrationServices:
    """Return the process-wide administration services, initializing on first call."""
    global _services
    if _services is None:
        with _lock:
            if _services is None:
                _services = _build_admin_services()
    return _services


def reset_admin_services() -> None:
    """Reset the singletons. Test-only."""
    global _services
    with _lock:
        _services = None


def _build_admin_services() -> AdministrationServices:
    from api.identity_governance.services import get_services as get_gov_services
    from api.identity_administration.repositories.memory import (
        InMemoryAuditRepository,
        InMemoryGroupRepository,
        InMemoryIdentityRepository,
        InMemoryInvitationRepository,
    )

    gov = get_gov_services()

    identity_repo = InMemoryIdentityRepository()
    invitation_repo = InMemoryInvitationRepository()
    group_repo = InMemoryGroupRepository()
    audit_repo = InMemoryAuditRepository()

    publisher = NotificationPublisher(timeline=gov.timeline)
    invitation_svc = InvitationService(invitation_repo=invitation_repo)
    admin_svc = IdentityAdministrationService(
        identity_repo=identity_repo,
        invitation_service=invitation_svc,
        audit_repo=audit_repo,
        notification_publisher=publisher,
    )
    self_svc = SelfService(
        identity_repo=identity_repo,
        gov_services=gov,
    )
    group_svc = GroupService(group_repo=group_repo)
    search_svc = SearchService(identity_repo=identity_repo)

    return AdministrationServices(
        identity_repo=identity_repo,
        invitation_repo=invitation_repo,
        group_repo=group_repo,
        audit_repo=audit_repo,
        invitation_service=invitation_svc,
        administration_service=admin_svc,
        self_service=self_svc,
        group_service=group_svc,
        search_service=search_svc,
        notification_publisher=publisher,
    )


__all__ = [
    "AdministrationServices",
    "get_admin_services",
    "reset_admin_services",
]
