"""Governance Asset Registry — attestation TTL management.

Attestation intervals by risk tier (Trust-but-Verify cadence):
  critical  → 30 days
  high      → 60 days
  medium    → 90 days
  low       → 90 days
  minimal   → 90 days
  unclassified → 90 days

Overdue assets accrue +2 risk score points per day (capped at 100).
Assets with no attestation ever submitted carry the full discovery_penalty.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from services.governance_asset_registry.models import (
    ATTESTATION_INTERVAL_BY_TIER,
    RiskTier,
)


def interval_days_for_tier(risk_tier: str) -> int:
    try:
        tier = RiskTier(risk_tier)
    except ValueError:
        return 90
    return ATTESTATION_INTERVAL_BY_TIER.get(tier, 90)


def compute_next_due_at(risk_tier: str, last_attested_at: str | None = None) -> str:
    """Compute the next attestation due date as ISO8601Z string.

    If last_attested_at is None (never attested), the due date is NOW minus
    one interval — meaning the asset is already overdue from day one.
    This intentionally penalises assets whose owners have never attested.
    """
    interval = interval_days_for_tier(risk_tier)
    if last_attested_at is None:
        base = datetime.now(UTC) - timedelta(days=interval)
    else:
        base = datetime.fromisoformat(last_attested_at.replace("Z", "+00:00"))
    due = base + timedelta(days=interval)
    return due.isoformat().replace("+00:00", "Z")


def days_overdue(next_due_at: str | None) -> int:
    """Return days past due (0 if not overdue or no due date set)."""
    if not next_due_at:
        return 0
    due = datetime.fromisoformat(next_due_at.replace("Z", "+00:00"))
    now = datetime.now(UTC)
    delta = (now - due).days
    return max(0, delta)
