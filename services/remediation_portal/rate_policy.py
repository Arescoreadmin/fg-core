# services/remediation_portal/rate_policy.py
"""Portal remediation rate-limit policy definitions and tier resolution.

Default limits are read from environment variables on every call (not cached)
so operators can reconfigure at runtime and tests can override via os.environ.

Extension point: resolve_portal_limits() accepts a subscription_tier argument.
Add tier multipliers here when P1.5 billing tiers are wired — no schema
redesign required.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum


class PortalOperation(str, Enum):
    COMMENT_CREATE = "comment_create"
    COMMENT_EDIT = "comment_edit"
    EVIDENCE_UPLOAD = "evidence_upload"
    ACKNOWLEDGEMENT = "acknowledgement"


@dataclass(frozen=True)
class PortalRatePolicy:
    """Resolved rate policy for a single portal operation."""

    limit: int
    window_seconds: int


def _env_int(key: str, default: int) -> int:
    try:
        v = (os.getenv(key) or "").strip()
        return int(v) if v else default
    except ValueError:
        return default


def _env_window(key: str, default: int) -> int:
    """Like _env_int but clamps to >= 1 — window_seconds=0 causes ZeroDivisionError."""
    v = _env_int(key, default)
    return v if v >= 1 else default


# Subscription-tier write-limit multipliers.
# Extend this mapping when billing subscription tiers are implemented (P1.5).
# Tier names must match the billing system's tier identifier strings.
_TIER_MULTIPLIERS: dict[str, float] = {
    "starter": 1.0,
    "professional": 2.0,
    "enterprise": 5.0,
    "government": 5.0,
}


def resolve_portal_limits(
    operation: PortalOperation,
    *,
    subscription_tier: str | None = None,
    tenant_id: str | None = None,
) -> PortalRatePolicy:
    """Resolve the effective rate policy for a portal write operation.

    Args:
        operation: The portal write operation being checked.
        subscription_tier: Optional billing tier identifier. When provided,
            the base limit is scaled by the tier multiplier. Pass None for
            the default (Starter) behaviour.
        tenant_id: Reserved for per-tenant custom overrides. Not used today;
            the parameter is stable so callers need not change when per-tenant
            overrides are added.

    Returns:
        PortalRatePolicy with the effective (limit, window_seconds).
    """
    _ = tenant_id

    _defaults: dict[PortalOperation, PortalRatePolicy] = {
        PortalOperation.COMMENT_CREATE: PortalRatePolicy(
            limit=_env_int("FG_PORTAL_RL_COMMENT_CREATE_LIMIT", 60),
            window_seconds=_env_window("FG_PORTAL_RL_COMMENT_CREATE_WINDOW", 3600),
        ),
        PortalOperation.COMMENT_EDIT: PortalRatePolicy(
            limit=_env_int("FG_PORTAL_RL_COMMENT_EDIT_LIMIT", 60),
            window_seconds=_env_window("FG_PORTAL_RL_COMMENT_EDIT_WINDOW", 3600),
        ),
        PortalOperation.EVIDENCE_UPLOAD: PortalRatePolicy(
            limit=_env_int("FG_PORTAL_RL_EVIDENCE_UPLOAD_LIMIT", 30),
            window_seconds=_env_window("FG_PORTAL_RL_EVIDENCE_UPLOAD_WINDOW", 3600),
        ),
        PortalOperation.ACKNOWLEDGEMENT: PortalRatePolicy(
            limit=_env_int("FG_PORTAL_RL_ACKNOWLEDGEMENT_LIMIT", 30),
            window_seconds=_env_window("FG_PORTAL_RL_ACKNOWLEDGEMENT_WINDOW", 3600),
        ),
    }

    base = _defaults[operation]

    if subscription_tier is None:
        return base

    multiplier = _TIER_MULTIPLIERS.get(subscription_tier.lower(), 1.0)
    return PortalRatePolicy(
        limit=int(base.limit * multiplier),
        window_seconds=base.window_seconds,
    )
