"""api/identity_governance/services.py — Runtime service singletons.

Governance services are stateless-except-for-persistence. The runtime path
imports singletons from here so every request sees the same in-memory
registry / timeline chain. Tests can call :func:`reset_services` to clear
state between tests.

The services returned here are ready to be called by the auth dispatch
layer. Callers must never re-instantiate them locally.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Optional

from api.identity_governance.break_glass import BreakGlassAuthority
from api.identity_governance.devices import DeviceTrustRegistry
from api.identity_governance.lifecycle import IdentityLifecycleManager
from api.identity_governance.policy_engine import ConditionalAccessPolicyEngine
from api.identity_governance.risk import IdentityRiskEngine
from api.identity_governance.session_evaluation import SessionEvaluator
from api.identity_governance.timeline import IdentityTimeline


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


_services_lock = threading.Lock()
_services: Optional[GovernanceServices] = None


def _build_services() -> GovernanceServices:
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
