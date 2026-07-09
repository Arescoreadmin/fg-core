"""api/identity_governance/policy_engine.py — Conditional access policy engine.

Deterministic policy evaluation over a fixed set of condition kinds. All
policies for a request are sorted by ``priority`` (lower = higher priority),
then by ``policy_id`` for stable ordering. For policies at the same
priority, DENY overrides ALLOW.
"""

from __future__ import annotations

from api.identity_governance.models import (
    IdentityLifecycleState,
    PolicyCondition,
    PolicyDecision,
    PolicyEvaluationContext,
    PolicyEvaluationResult,
    PolicyRecord,
)

# Ordering of decisions when multiple policies apply at the same priority.
# DENY has the highest weight (overrides everything else at the same tier).
_DECISION_STRENGTH: dict[PolicyDecision, int] = {
    PolicyDecision.DENY: 5,
    PolicyDecision.APPROVAL_REQUIRED: 4,
    PolicyDecision.JUSTIFICATION_REQUIRED: 3,
    PolicyDecision.STEP_UP_REQUIRED: 2,
    PolicyDecision.ALLOW: 1,
}


class ConditionalAccessPolicyEngine:
    """Deterministic conditional-access policy engine."""

    def evaluate(
        self,
        policies: list[PolicyRecord],
        context: PolicyEvaluationContext,
    ) -> PolicyEvaluationResult:
        """Evaluate an ordered list of policies against a request context.

        Only policies belonging to ``context.tenant_id`` are considered —
        this enforces tenant isolation. The result is deterministic: given
        the same policies and context, ``evaluate`` always returns the
        same decision.
        """
        # Filter to tenant + enabled, then sort deterministically:
        # priority ASC, decision strength DESC (deny beats allow), then id.
        applicable: list[PolicyRecord] = [
            p for p in policies if p.enabled and p.tenant_id == context.tenant_id
        ]
        applicable.sort(
            key=lambda p: (
                p.priority,
                -_DECISION_STRENGTH.get(p.on_match, 0),
                p.policy_id,
            )
        )

        evaluated: list[str] = []
        for policy in applicable:
            evaluated.append(policy.policy_id)
            if all(
                self._matches_condition(cond, context) for cond in policy.conditions
            ):
                return PolicyEvaluationResult(
                    decision=policy.on_match,
                    matched_policy_id=policy.policy_id,
                    reason=f"policy {policy.name!r} matched",
                    evaluated_policies=tuple(evaluated),
                )

        # No policy matched — default ALLOW. Explicit deny policies must be
        # authored to block access.
        return PolicyEvaluationResult(
            decision=PolicyDecision.ALLOW,
            matched_policy_id=None,
            reason="no policy matched — default allow",
            evaluated_policies=tuple(evaluated),
        )

    # ------------------------------------------------------------------
    # Condition evaluation
    # ------------------------------------------------------------------

    def _matches_condition(
        self,
        condition: PolicyCondition,
        context: PolicyEvaluationContext,
    ) -> bool:
        """Evaluate a single condition. Unknown ``kind`` never matches."""
        params = dict(condition.params)
        kind = condition.kind

        if kind == "requires_mfa":
            return context.mfa_verified

        if kind == "requires_role":
            required = params.get("role", "")
            return required in context.roles

        if kind == "requires_capability":
            required = params.get("capability", "")
            return required in context.capabilities

        if kind == "deny_suspended":
            return context.identity_state == IdentityLifecycleState.SUSPENDED

        if kind == "requires_break_glass_reason":
            return bool(context.break_glass_reason)

        if kind == "ip_allowlist":
            allowed_csv = params.get("cidrs", "")
            allowed = [x.strip() for x in allowed_csv.split(",") if x.strip()]
            return context.ip in allowed

        if kind == "time_window":
            try:
                start = int(params.get("start_hour_utc", "0"))
                end = int(params.get("end_hour_utc", "23"))
            except ValueError:
                return False
            return start <= context.now_hour_utc <= end

        # Unknown condition kinds never match.
        return False
