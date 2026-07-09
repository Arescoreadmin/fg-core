"""api/identity_governance/session_evaluation.py — Continuous session evaluation.

Deterministic pipeline that evaluates a session context against six checks
in a fixed order and returns the first non-ALLOW decision (or ALLOW if all
checks pass). The pipeline is intentionally stateless so callers can invoke
it on every request without coordination.

Evaluation order
----------------
1. identity_state       — SUSPENDED / DISABLED / DELETED  -> DENY
2. session_expiry       — expired                          -> DENY
3. session_revocation   — revoked                          -> DENY
4. device_state         — REVOKED -> DENY, COMPROMISED -> STEP_UP_REQUIRED
5. mfa                  — MFA required but not verified    -> STEP_UP_REQUIRED
6. risk                 — CRITICAL band                    -> DENY
"""

from __future__ import annotations

from datetime import datetime, timezone

from api.identity_governance.models import (
    DeviceTrustState,
    IdentityLifecycleState,
    RiskBand,
    SessionEvaluationContext,
    SessionEvaluationDecision,
    SessionEvaluationResult,
)

_CHECK_ORDER: tuple[str, ...] = (
    "identity_state",
    "session_expiry",
    "session_revocation",
    "device_state",
    "mfa",
    "risk",
)


class SessionEvaluator:
    """Deterministic continuous session evaluation."""

    def evaluate(self, context: SessionEvaluationContext) -> SessionEvaluationResult:
        """Run the pipeline and return the first non-ALLOW result."""
        now = context.evaluated_at or datetime.now(tz=timezone.utc)

        # 1. Identity state
        if context.identity_state in (
            IdentityLifecycleState.SUSPENDED,
            IdentityLifecycleState.DISABLED,
            IdentityLifecycleState.DELETED,
            IdentityLifecycleState.ARCHIVED,
        ):
            return self._result(
                SessionEvaluationDecision.DENY,
                f"identity state {context.identity_state.value} disallows session",
                "identity_state",
                now,
            )

        # 2. Session expiry
        if context.session_expires_at <= now:
            return self._result(
                SessionEvaluationDecision.DENY,
                "session expired",
                "session_expiry",
                now,
            )

        # 3. Session revocation
        if context.session_revoked:
            return self._result(
                SessionEvaluationDecision.DENY,
                "session has been revoked",
                "session_revocation",
                now,
            )

        # 4. Device state
        if context.device is not None:
            if context.device.trust_state == DeviceTrustState.REVOKED:
                return self._result(
                    SessionEvaluationDecision.DENY,
                    "device trust revoked",
                    "device_state",
                    now,
                )
            if context.device.trust_state == DeviceTrustState.COMPROMISED:
                return self._result(
                    SessionEvaluationDecision.STEP_UP_REQUIRED,
                    "device flagged compromised — step-up required",
                    "device_state",
                    now,
                )

        # 5. MFA
        if context.tenant_requires_mfa and not context.mfa_verified:
            return self._result(
                SessionEvaluationDecision.STEP_UP_REQUIRED,
                "tenant requires MFA — verification missing",
                "mfa",
                now,
            )

        # 6. Risk
        if context.risk_score.band == RiskBand.CRITICAL:
            return self._result(
                SessionEvaluationDecision.DENY,
                f"risk score {context.risk_score.score:.2f} in CRITICAL band",
                "risk",
                now,
            )

        return SessionEvaluationResult(
            decision=SessionEvaluationDecision.ALLOW,
            reason="all checks passed",
            checks_run=_CHECK_ORDER,
            stopped_at_check="",
            evaluated_at=now,
        )

    # ------------------------------------------------------------------

    def _result(
        self,
        decision: SessionEvaluationDecision,
        reason: str,
        stopped_at: str,
        now: datetime,
    ) -> SessionEvaluationResult:
        # Include every check up to and including the one that stopped us,
        # for auditability.
        checks: list[str] = []
        for c in _CHECK_ORDER:
            checks.append(c)
            if c == stopped_at:
                break
        return SessionEvaluationResult(
            decision=decision,
            reason=reason,
            checks_run=tuple(checks),
            stopped_at_check=stopped_at,
            evaluated_at=now,
        )
