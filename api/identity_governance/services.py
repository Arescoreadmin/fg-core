"""api/identity_governance/services.py — Runtime service singletons.

Governance services are stateless-except-for-persistence. The runtime path
imports singletons from here so every request sees the same in-memory
registry / timeline chain. Tests can call :func:`reset_services` to clear
state between tests.

The services returned here are ready to be called by the auth dispatch
layer. Callers must never re-instantiate them locally.

When ``FG_IDENTITY_PERSISTENCE_ENABLED=1``, the four repository fields are
backed by SQLAlchemy repositories using the tables from migration 0148.
Otherwise the in-memory repositories are used (default).
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Optional

from api.identity_governance.break_glass import BreakGlassAuthority
from api.identity_governance.devices import DeviceTrustRegistry
from api.identity_governance.lifecycle import IdentityLifecycleManager
from api.identity_governance.policy_engine import ConditionalAccessPolicyEngine
from api.identity_governance.repositories.base import (
    BreakGlassRepository,
    DeviceRepository,
    LifecycleRepository,
    TimelineRepository,
)
from api.identity_governance.repositories.memory import (
    InMemoryBreakGlassRepository,
    InMemoryDeviceRepository,
    InMemoryLifecycleRepository,
    InMemoryTimelineRepository,
)
from api.identity_governance.risk import IdentityRiskEngine
from api.identity_governance.session_evaluation import SessionEvaluator
from api.identity_governance.timeline import IdentityTimeline

log = logging.getLogger("frostgate.identity_governance.services")


@dataclass
class GovernanceServices:
    """Container for the runtime governance service singletons."""

    lifecycle_manager: IdentityLifecycleManager
    device_registry: DeviceTrustRegistry
    session_evaluator: SessionEvaluator
    policy_engine: ConditionalAccessPolicyEngine
    timeline: IdentityTimeline
    risk_engine: IdentityRiskEngine
    break_glass: BreakGlassAuthority
    # Repositories — used for DB persistence when FG_IDENTITY_PERSISTENCE_ENABLED=1.
    # Default to in-memory so governance works without a database.
    lifecycle_repo: LifecycleRepository
    device_repo: DeviceRepository
    timeline_repo: TimelineRepository
    break_glass_repo: BreakGlassRepository


_services_lock = threading.Lock()
_services: Optional[GovernanceServices] = None


def _build_memory_repos() -> tuple[
    LifecycleRepository, DeviceRepository, TimelineRepository, BreakGlassRepository
]:
    return (
        InMemoryLifecycleRepository(),
        InMemoryDeviceRepository(),
        InMemoryTimelineRepository(),
        InMemoryBreakGlassRepository(),
    )


def _build_db_repos() -> tuple[
    LifecycleRepository, DeviceRepository, TimelineRepository, BreakGlassRepository
]:
    """Return DB-backed repositories using the app session factory.

    Falls back to in-memory and logs a warning if the DB is unavailable.
    """
    from api.db import get_sessionmaker
    from api.identity_governance.repositories.db import (
        DbBreakGlassRepository,
        DbDeviceRepository,
        DbLifecycleRepository,
        DbTimelineRepository,
    )

    factory = get_sessionmaker()
    return (
        DbLifecycleRepository(factory),
        DbDeviceRepository(factory),
        DbTimelineRepository(factory),
        DbBreakGlassRepository(factory),
    )


def _build_services() -> GovernanceServices:
    from api.config.identity_runtime import get_flags

    flags = get_flags()
    if flags.FG_IDENTITY_PERSISTENCE_ENABLED:
        try:
            lifecycle_repo, device_repo, timeline_repo, break_glass_repo = (
                _build_db_repos()
            )
            log.info("governance_services.using_db_repositories")
        except Exception as exc:
            log.warning(
                "governance_services.db_repos_unavailable_using_memory",
                extra={"exc": str(exc)},
            )
            lifecycle_repo, device_repo, timeline_repo, break_glass_repo = (
                _build_memory_repos()
            )
    else:
        lifecycle_repo, device_repo, timeline_repo, break_glass_repo = (
            _build_memory_repos()
        )

    timeline = IdentityTimeline()
    return GovernanceServices(
        lifecycle_manager=IdentityLifecycleManager(),
        device_registry=DeviceTrustRegistry(),
        session_evaluator=SessionEvaluator(),
        policy_engine=ConditionalAccessPolicyEngine(),
        timeline=timeline,
        risk_engine=IdentityRiskEngine(),
        # Share the timeline so break-glass events land on the same chain.
        break_glass=BreakGlassAuthority(timeline=timeline),
        lifecycle_repo=lifecycle_repo,
        device_repo=device_repo,
        timeline_repo=timeline_repo,
        break_glass_repo=break_glass_repo,
    )


def get_services() -> GovernanceServices:
    """Return the process-wide governance services, initializing on first call."""
    global _services
    if _services is None:
        with _services_lock:
            if _services is None:
                _services = _build_services()
    return _services


def reset_services() -> None:
    """Reset the singletons. Test-only."""
    global _services
    with _services_lock:
        _services = None


__all__ = [
    "GovernanceServices",
    "get_services",
    "reset_services",
]
