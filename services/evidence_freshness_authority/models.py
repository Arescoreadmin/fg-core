"""services/evidence_freshness_authority/models.py — Domain models for Evidence Freshness Authority.

Pure Python. No I/O. No SQLAlchemy.

Design principles:
  - Deterministic: all state/score computations are pure functions.
  - Fail-safe: CURRENT is the default (optimistic freshness).
  - Tenant-isolated: no cross-tenant data in any model.
  - AGI-forward: supports autonomous re-verification scheduling.

PR 14.6.7 — Evidence Freshness Authority
"""

from __future__ import annotations

from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class FreshnessCriticality(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FreshnessState(str, Enum):
    CURRENT = "CURRENT"
    DUE_SOON = "DUE_SOON"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    VERIFICATION_REQUIRED = "VERIFICATION_REQUIRED"
    STALE = "STALE"
    EXPIRED = "EXPIRED"


class FreshnessExceptionStatus(str, Enum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class FreshnessAuditEventType(str, Enum):
    POLICY_CREATED = "POLICY_CREATED"
    POLICY_UPDATED = "POLICY_UPDATED"
    RECORD_CREATED = "RECORD_CREATED"
    RECORD_UPDATED = "RECORD_UPDATED"
    STATE_CHANGED = "STATE_CHANGED"
    EXCEPTION_CREATED = "EXCEPTION_CREATED"
    EXCEPTION_REVOKED = "EXCEPTION_REVOKED"
    SCORE_RECOMPUTED = "SCORE_RECOMPUTED"


# ---------------------------------------------------------------------------
# Pure deterministic functions
# ---------------------------------------------------------------------------

_THIRTY_DAYS_SECONDS = 30 * 24 * 3600


def _parse_iso(ts: str) -> float:
    """Parse an ISO 8601 string to a float (Unix timestamp-equivalent seconds)."""
    from datetime import datetime, timezone

    ts = ts.strip()
    if ts.endswith("Z"):
        dt = datetime.fromisoformat(ts[:-1] + "+00:00")
    else:
        dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def compute_freshness_state(
    review_due_at: Optional[str],
    verification_due_at: Optional[str],
    expiration_due_at: Optional[str],
    now_iso: str,
) -> FreshnessState:
    """Deterministic state from due dates.

    Rules (checked in order, first match wins):
    1. If expiration_due_at is set and now >= expiration_due_at → EXPIRED
    2. If verification_due_at is set and now >= verification_due_at → VERIFICATION_REQUIRED
    3. If review_due_at is set and now >= review_due_at → REVIEW_REQUIRED
    4. If review_due_at is set and (review_due_at - now) <= 30 days → DUE_SOON
    5. Otherwise → CURRENT
    """
    now_ts = _parse_iso(now_iso)

    if expiration_due_at is not None:
        exp_ts = _parse_iso(expiration_due_at)
        if now_ts >= exp_ts:
            return FreshnessState.EXPIRED

    if verification_due_at is not None:
        ver_ts = _parse_iso(verification_due_at)
        if now_ts >= ver_ts:
            return FreshnessState.VERIFICATION_REQUIRED

    if review_due_at is not None:
        rev_ts = _parse_iso(review_due_at)
        if now_ts >= rev_ts:
            return FreshnessState.REVIEW_REQUIRED
        if (rev_ts - now_ts) <= _THIRTY_DAYS_SECONDS:
            return FreshnessState.DUE_SOON

    return FreshnessState.CURRENT


def compute_freshness_score(
    freshness_state: FreshnessState,
    criticality: str,
    days_since_last_verified: Optional[float],
    days_since_last_reviewed: Optional[float],
    has_active_exception: bool,
) -> int:
    """Deterministic scoring 0-100.

    Base score from state:
      CURRENT:                90
      DUE_SOON:               75
      REVIEW_REQUIRED:        55
      VERIFICATION_REQUIRED:  35
      STALE:                  15
      EXPIRED:                 0

    Criticality modifier (applied to base):
      CRITICAL: base × 0.95 if < CURRENT (penalize harder)
      HIGH:     base × 0.97 if < CURRENT
      MEDIUM:   no modifier
      LOW:      no modifier

    Age penalty (on top of state base):
      days_since_last_verified > 180: -10
      days_since_last_verified > 365: -20 (cumulative)
      days_since_last_reviewed > 90:  -5
      days_since_last_reviewed > 180: -10 (cumulative)

    Exception bonus:
      has_active_exception: +5 (capped at 100)

    Final: clamp(0, 100)
    """
    _BASE_SCORES = {
        FreshnessState.CURRENT: 90,
        FreshnessState.DUE_SOON: 75,
        FreshnessState.REVIEW_REQUIRED: 55,
        FreshnessState.VERIFICATION_REQUIRED: 35,
        FreshnessState.STALE: 15,
        FreshnessState.EXPIRED: 0,
    }

    base = _BASE_SCORES.get(freshness_state, 0)

    # Criticality modifier — only penalize non-CURRENT states
    if freshness_state != FreshnessState.CURRENT:
        if criticality == FreshnessCriticality.CRITICAL:
            base = int(base * 0.95)
        elif criticality == FreshnessCriticality.HIGH:
            base = int(base * 0.97)

    score = base

    # Age penalty — verification
    if days_since_last_verified is not None:
        if days_since_last_verified > 365:
            score -= 20
        elif days_since_last_verified > 180:
            score -= 10

    # Age penalty — review
    if days_since_last_reviewed is not None:
        if days_since_last_reviewed > 180:
            score -= 10
        elif days_since_last_reviewed > 90:
            score -= 5

    # Exception bonus
    if has_active_exception:
        score += 5

    return max(0, min(100, score))
