"""services/evidence_authority/quality.py — Deterministic quality scoring for Evidence Authority.

All scores are integers in [0, 100]. No probabilistic or AI-generated values.
Inputs are the canonical fa_evidence fields. No external I/O.

Scores:
  freshness_score       — how current the evidence is relative to its lifecycle/expiry
  verification_score    — confidence in the evidence's verified status
  completeness_score    — how complete the evidence metadata is
  trust_score           — managed by the engine (stored on fa_evidence.trust_score);
                          not recomputed here; read-through only

All computations are pure functions. The engine owns persisting the results.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


def _parse_iso(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _clamp(value: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, value))


def compute_freshness_score(
    lifecycle_state: str,
    collected_at: str,
    expires_at: Optional[str],
) -> int:
    """Compute freshness score (0-100) deterministically.

    Zero for terminal/inactive states. Linear decay otherwise.
    """
    _ZERO_STATES = {"REVOKED", "EXPIRED", "ARCHIVED"}
    if lifecycle_state in _ZERO_STATES:
        return 0

    now = datetime.now(tz=timezone.utc)
    collected_dt = _parse_iso(collected_at)
    expires_dt = _parse_iso(expires_at)

    if expires_dt is not None:
        if now >= expires_dt:
            return 0
        days_remaining = (expires_dt - now).total_seconds() / 86400
        if collected_dt is not None:
            total_lifetime_days = (expires_dt - collected_dt).total_seconds() / 86400
            if total_lifetime_days <= 0:
                return 100
            score = int((days_remaining / total_lifetime_days) * 100)
        else:
            # No collection date — use 365-day decay from expiry window
            if days_remaining >= 365:
                return 100
            score = int(days_remaining / 365 * 100)
        return _clamp(score)

    # No expiry set — linear decay from collected_at
    if collected_dt is None:
        return 50  # cannot compute; return mid-range

    age_days = (now - collected_dt).total_seconds() / 86400
    if age_days <= 30:
        return 100
    if age_days <= 180:
        # 100 → 40 over 150 days
        score = 100 - int((age_days - 30) / 150 * 60)
        return _clamp(score)
    if age_days <= 365:
        # 40 → 0 over 185 days
        score = 40 - int((age_days - 180) / 185 * 40)
        return _clamp(score)
    return 0


def compute_verification_score(
    trust_state: str,
    verification_count: int,
    last_verification_source: Optional[str],
) -> int:
    """Compute verification score (0-100) from trust state and verification history.

    Base from trust-state floor, plus a bonus for repeated verifications.
    """
    from services.evidence_authority.models import (
        EvidenceTrustState,
        TRUST_STATE_SCORE_FLOOR,
    )

    try:
        state = EvidenceTrustState(trust_state)
        base = TRUST_STATE_SCORE_FLOOR[state]
    except (ValueError, KeyError):
        base = 0

    count_bonus = min((verification_count or 0) * 5, 15)
    source_bonus = 5 if last_verification_source else 0

    return _clamp(base + count_bonus + source_bonus)


def compute_completeness_score(
    description: Optional[str],
    owner_id: Optional[str],
    source_system: Optional[str],
    expires_at: Optional[str],
    engagement_id: Optional[str],
    source_ref: Optional[str],
) -> int:
    """Compute completeness score (0-100) from optional metadata field presence.

    Points (max 100):
      description    +20
      owner_id       +25
      source_system  +15
      expires_at     +20
      engagement_id  +10
      source_ref     +10
    """
    score = 0
    if description and description.strip():
        score += 20
    if owner_id:
        score += 25
    if source_system:
        score += 15
    if expires_at:
        score += 20
    if engagement_id:
        score += 10
    if source_ref:
        score += 10
    return _clamp(score)


@dataclass(frozen=True)
class QualityScores:
    """Immutable bundle of all four quality scores for a single evidence record."""

    freshness_score: int
    verification_score: int
    completeness_score: int
    trust_score: Optional[int]


def compute_quality_scores(
    *,
    lifecycle_state: str,
    trust_state: str,
    collected_at: str,
    expires_at: Optional[str],
    description: Optional[str],
    owner_id: Optional[str],
    source_system: Optional[str],
    source_ref: Optional[str],
    engagement_id: Optional[str],
    verification_count: int,
    last_verification_source: Optional[str],
    trust_score: Optional[int],
) -> QualityScores:
    """Compute all deterministic quality scores for an evidence record.

    Pure function — no I/O. The caller is responsible for persisting results.
    """
    return QualityScores(
        freshness_score=compute_freshness_score(lifecycle_state, collected_at, expires_at),
        verification_score=compute_verification_score(
            trust_state, verification_count, last_verification_source
        ),
        completeness_score=compute_completeness_score(
            description=description,
            owner_id=owner_id,
            source_system=source_system,
            expires_at=expires_at,
            engagement_id=engagement_id,
            source_ref=source_ref,
        ),
        trust_score=trust_score,
    )
