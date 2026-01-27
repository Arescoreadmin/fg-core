# api/tenant_usage.py
"""
Tenant Usage Metering and Quota Enforcement.

SaaS-ready features:
- Track API usage per tenant for billing
- Enforce quota limits per tenant/tier
- Usage analytics and reporting
- Graceful quota enforcement with warnings
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Optional, Tuple

log = logging.getLogger("frostgate.usage")

# =============================================================================
# Configuration
# =============================================================================


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None or v.strip() == "":
        return default
    try:
        return int(v)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


# Default quotas per tier (requests per day)
QUOTA_FREE_DAILY = _env_int("FG_QUOTA_FREE_DAILY", 1000)
QUOTA_STARTER_DAILY = _env_int("FG_QUOTA_STARTER_DAILY", 10000)
QUOTA_PRO_DAILY = _env_int("FG_QUOTA_PRO_DAILY", 100000)
QUOTA_ENTERPRISE_DAILY = _env_int("FG_QUOTA_ENTERPRISE_DAILY", 0)  # 0 = unlimited
QUOTA_WARNING_THRESHOLD_PCT = _env_int("FG_QUOTA_WARNING_THRESHOLD_PCT", 80)
QUOTA_ENFORCEMENT_ENABLED = _env_bool("FG_QUOTA_ENFORCEMENT_ENABLED", True)


class SubscriptionTier(str, Enum):
    """Subscription tiers for SaaS billing."""

    FREE = "free"
    STARTER = "starter"
    PRO = "pro"
    ENTERPRISE = "enterprise"
    INTERNAL = "internal"  # Internal/admin accounts


TIER_QUOTAS: Dict[SubscriptionTier, int] = {
    SubscriptionTier.FREE: QUOTA_FREE_DAILY,
    SubscriptionTier.STARTER: QUOTA_STARTER_DAILY,
    SubscriptionTier.PRO: QUOTA_PRO_DAILY,
    SubscriptionTier.ENTERPRISE: QUOTA_ENTERPRISE_DAILY,
    SubscriptionTier.INTERNAL: 0,  # unlimited
}


@dataclass
class UsageRecord:
    """Usage record for a tenant."""

    tenant_id: str
    period: str  # YYYY-MM-DD format
    request_count: int
    decision_count: int
    bytes_processed: int
    last_request_at: int  # Unix timestamp
    quota_limit: int
    quota_remaining: int
    tier: str


@dataclass
class QuotaCheckResult:
    """Result of a quota check."""

    allowed: bool
    remaining: int
    limit: int
    usage_pct: float
    warning: bool
    message: Optional[str] = None


class TenantUsageTracker:
    """
    In-memory tenant usage tracker with persistence hooks.

    For production, this should be backed by Redis or a database
    for distributed tracking across multiple instances.
    """

    def __init__(self):
        # In-memory storage: {tenant_id: {period: UsageRecord}}
        self._usage: Dict[str, Dict[str, UsageRecord]] = {}
        self._tenant_tiers: Dict[str, SubscriptionTier] = {}
        self._tenant_custom_quotas: Dict[str, int] = {}
        self._suspended_tenants: set = set()

    def _get_current_period(self) -> str:
        """Get current billing period (daily by default)."""
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def _get_quota_for_tenant(self, tenant_id: str) -> int:
        """Get the quota limit for a tenant."""
        # Check for custom quota override
        if tenant_id in self._tenant_custom_quotas:
            return self._tenant_custom_quotas[tenant_id]

        # Get tier-based quota
        tier = self._tenant_tiers.get(tenant_id, SubscriptionTier.FREE)
        return TIER_QUOTAS.get(tier, QUOTA_FREE_DAILY)

    def set_tenant_tier(self, tenant_id: str, tier: SubscriptionTier) -> None:
        """Set the subscription tier for a tenant."""
        self._tenant_tiers[tenant_id] = tier
        log.info(f"Tenant {tenant_id[:8]}... tier set to {tier.value}")

    def set_custom_quota(self, tenant_id: str, quota: int) -> None:
        """Set a custom quota override for a tenant."""
        self._tenant_custom_quotas[tenant_id] = quota
        log.info(f"Tenant {tenant_id[:8]}... custom quota set to {quota}")

    def suspend_tenant(self, tenant_id: str) -> None:
        """Suspend a tenant (block all requests)."""
        self._suspended_tenants.add(tenant_id)
        log.warning(f"Tenant {tenant_id[:8]}... suspended")

    def activate_tenant(self, tenant_id: str) -> None:
        """Activate a suspended tenant."""
        self._suspended_tenants.discard(tenant_id)
        log.info(f"Tenant {tenant_id[:8]}... activated")

    def is_tenant_suspended(self, tenant_id: str) -> bool:
        """Check if a tenant is suspended."""
        return tenant_id in self._suspended_tenants

    def record_usage(
        self,
        tenant_id: str,
        request_count: int = 1,
        decision_count: int = 0,
        bytes_processed: int = 0,
    ) -> UsageRecord:
        """
        Record API usage for a tenant.

        Returns the updated usage record.
        """
        period = self._get_current_period()
        quota_limit = self._get_quota_for_tenant(tenant_id)

        if tenant_id not in self._usage:
            self._usage[tenant_id] = {}

        if period not in self._usage[tenant_id]:
            self._usage[tenant_id][period] = UsageRecord(
                tenant_id=tenant_id,
                period=period,
                request_count=0,
                decision_count=0,
                bytes_processed=0,
                last_request_at=0,
                quota_limit=quota_limit,
                quota_remaining=quota_limit,
                tier=self._tenant_tiers.get(tenant_id, SubscriptionTier.FREE).value,
            )

        record = self._usage[tenant_id][period]
        record.request_count += request_count
        record.decision_count += decision_count
        record.bytes_processed += bytes_processed
        record.last_request_at = int(time.time())
        record.quota_limit = quota_limit
        record.quota_remaining = max(0, quota_limit - record.request_count)

        return record

    def check_quota(self, tenant_id: str) -> QuotaCheckResult:
        """
        Check if a tenant is within their quota.

        Returns a QuotaCheckResult with:
        - allowed: Whether the request should be allowed
        - remaining: Remaining requests in the period
        - limit: Total quota limit
        - usage_pct: Percentage of quota used
        - warning: Whether to show a quota warning
        - message: Human-readable message
        """
        # Check if tenant is suspended
        if self.is_tenant_suspended(tenant_id):
            return QuotaCheckResult(
                allowed=False,
                remaining=0,
                limit=0,
                usage_pct=100.0,
                warning=False,
                message="Tenant account is suspended",
            )

        period = self._get_current_period()
        quota_limit = self._get_quota_for_tenant(tenant_id)

        # Unlimited quota
        if quota_limit <= 0:
            return QuotaCheckResult(
                allowed=True,
                remaining=-1,  # Indicates unlimited
                limit=0,
                usage_pct=0.0,
                warning=False,
                message=None,
            )

        # Get current usage
        current_usage = 0
        if tenant_id in self._usage and period in self._usage[tenant_id]:
            current_usage = self._usage[tenant_id][period].request_count

        remaining = max(0, quota_limit - current_usage)
        usage_pct = (current_usage / quota_limit) * 100 if quota_limit > 0 else 0

        # Check if over quota
        if remaining <= 0 and QUOTA_ENFORCEMENT_ENABLED:
            return QuotaCheckResult(
                allowed=False,
                remaining=0,
                limit=quota_limit,
                usage_pct=usage_pct,
                warning=False,
                message=f"Quota exceeded. Limit: {quota_limit} requests/day",
            )

        # Check for warning threshold
        warning = usage_pct >= QUOTA_WARNING_THRESHOLD_PCT
        message = None
        if warning:
            message = f"Approaching quota limit: {usage_pct:.1f}% used"

        return QuotaCheckResult(
            allowed=True,
            remaining=remaining,
            limit=quota_limit,
            usage_pct=usage_pct,
            warning=warning,
            message=message,
        )

    def get_usage_summary(
        self, tenant_id: str, period: Optional[str] = None
    ) -> Optional[UsageRecord]:
        """Get usage summary for a tenant."""
        period = period or self._get_current_period()

        if tenant_id not in self._usage:
            return None

        return self._usage[tenant_id].get(period)

    def get_all_usage(self, period: Optional[str] = None) -> Dict[str, UsageRecord]:
        """Get usage for all tenants (admin endpoint)."""
        period = period or self._get_current_period()
        result = {}

        for tenant_id, periods in self._usage.items():
            if period in periods:
                result[tenant_id] = periods[period]

        return result

    def reset_usage(self, tenant_id: str, period: Optional[str] = None) -> None:
        """Reset usage for a tenant (admin operation)."""
        if tenant_id not in self._usage:
            return

        if period:
            self._usage[tenant_id].pop(period, None)
        else:
            self._usage[tenant_id] = {}

        log.info(f"Usage reset for tenant {tenant_id[:8]}... period={period or 'all'}")


# Global tracker instance
_usage_tracker: Optional[TenantUsageTracker] = None


def get_usage_tracker() -> TenantUsageTracker:
    """Get the global usage tracker instance."""
    global _usage_tracker
    if _usage_tracker is None:
        _usage_tracker = TenantUsageTracker()
    return _usage_tracker


def check_tenant_quota(tenant_id: Optional[str]) -> Tuple[bool, Optional[str]]:
    """
    Convenience function to check tenant quota.

    Returns (allowed, error_message).
    Used by middleware/endpoints.
    """
    if not tenant_id:
        return True, None

    tracker = get_usage_tracker()
    result = tracker.check_quota(tenant_id)

    if not result.allowed:
        return False, result.message

    return True, None


def record_tenant_request(
    tenant_id: Optional[str],
    decision_count: int = 0,
    bytes_processed: int = 0,
) -> Optional[UsageRecord]:
    """
    Convenience function to record a tenant request.

    Returns the updated usage record.
    """
    if not tenant_id:
        return None

    tracker = get_usage_tracker()
    return tracker.record_usage(
        tenant_id,
        request_count=1,
        decision_count=decision_count,
        bytes_processed=bytes_processed,
    )


__all__ = [
    "SubscriptionTier",
    "UsageRecord",
    "QuotaCheckResult",
    "TenantUsageTracker",
    "get_usage_tracker",
    "check_tenant_quota",
    "record_tenant_request",
    "TIER_QUOTAS",
]
