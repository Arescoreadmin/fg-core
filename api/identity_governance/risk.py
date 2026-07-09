"""api/identity_governance/risk.py — Deterministic identity risk engine.

Given a :class:`RiskContext` the engine emits a :class:`RiskScore` that is:

- **Deterministic** — identical inputs always yield identical outputs.
- **Explainable** — every non-zero contribution appears in ``factors``.
- **Bounded** — the score is capped at 1.0.

Scoring model
-------------
- lifecycle:  DISABLED / DELETED = 0.9, SUSPENDED = 0.6, else 0.0
- device:     COMPROMISED = +0.5, UNKNOWN = +0.2, TRUSTED = 0.0
- mfa:        tenant requires MFA and not verified = +0.3
- break-glass: active count > 0 = +0.2

Bands: < 0.25 = LOW, < 0.5 = MEDIUM, < 0.75 = HIGH, >= 0.75 = CRITICAL.
"""

from __future__ import annotations

from api.identity_governance.models import (
    DeviceTrustState,
    IdentityLifecycleState,
    RiskBand,
    RiskContext,
    RiskScore,
)

EVALUATOR_VERSION = "1.0.0"


class IdentityRiskEngine:
    """Deterministic identity risk engine."""

    def score_identity(self, context: RiskContext) -> RiskScore:
        """Compute a deterministic risk score for ``context``."""
        factors: list[tuple[str, float]] = []

        lc = self._score_lifecycle(context.lifecycle_state)
        if lc > 0.0:
            factors.append(("lifecycle_state", lc))

        dev = self._score_device(context.device_state)
        if dev > 0.0:
            factors.append(("device_state", dev))

        mfa = self._score_mfa(context.mfa_verified, context.tenant_requires_mfa)
        if mfa > 0.0:
            factors.append(("missing_mfa", mfa))

        bg = self._score_break_glass(context.active_break_glass)
        if bg > 0.0:
            factors.append(("active_break_glass", bg))

        score = min(1.0, lc + dev + mfa + bg)
        band = self._to_band(score)

        return RiskScore(
            subject=context.subject,
            tenant_id=context.tenant_id,
            score=score,
            band=band,
            factors=tuple(factors),
            evaluator_version=EVALUATOR_VERSION,
            evaluated_at=context.evaluated_at,
        )

    # ------------------------------------------------------------------
    # Component scorers
    # ------------------------------------------------------------------

    def _score_lifecycle(self, state: IdentityLifecycleState) -> float:
        if state in (
            IdentityLifecycleState.DISABLED,
            IdentityLifecycleState.DELETED,
            IdentityLifecycleState.ARCHIVED,
        ):
            return 0.9
        if state == IdentityLifecycleState.SUSPENDED:
            return 0.6
        return 0.0

    def _score_device(self, device_state: DeviceTrustState | None) -> float:
        if device_state is None:
            return 0.0
        if device_state == DeviceTrustState.COMPROMISED:
            return 0.5
        if device_state == DeviceTrustState.SUSPICIOUS:
            return 0.35
        if device_state == DeviceTrustState.UNKNOWN:
            return 0.2
        if device_state == DeviceTrustState.REVOKED:
            return 0.5
        return 0.0

    def _score_mfa(self, mfa_verified: bool, tenant_requires_mfa: bool) -> float:
        if tenant_requires_mfa and not mfa_verified:
            return 0.3
        return 0.0

    def _score_break_glass(self, active_break_glass: int) -> float:
        return 0.2 if active_break_glass > 0 else 0.0

    def _to_band(self, score: float) -> RiskBand:
        if score < 0.25:
            return RiskBand.LOW
        if score < 0.5:
            return RiskBand.MEDIUM
        if score < 0.75:
            return RiskBand.HIGH
        return RiskBand.CRITICAL
