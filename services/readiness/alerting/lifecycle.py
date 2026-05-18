"""Alert lifecycle FSM — deterministic state transitions.

All functions are pure Python: no I/O, no side effects, no randomness.

FSM contract:
  - VALID_TRANSITIONS is an explicit FSM; no implicit or catch-all transitions.
  - Invalid transitions raise InvalidAlertTransition (never silently succeed).
  - validate_transition() is pure and raises nothing; returns bool.
  - apply_transition() returns an immutable AlertLifecycleTransition record.
  - CRITICAL and BLOCKING alerts cannot transition to SUPPRESSED — enforced here.

Lifecycle states:
  ACTIVE → ACKNOWLEDGED, SUPPRESSED, RESOLVED, ESCALATED, EXPIRED
  ACKNOWLEDGED → RESOLVED, ESCALATED, SUPPRESSED, EXPIRED
  SUPPRESSED → ACTIVE (re-open after suppression expires), RESOLVED
  ESCALATED → RESOLVED, ACKNOWLEDGED
  EXPIRED → RESOLVED (allow manual close of expired alerts)
  RESOLVED → (terminal)

Note: CRITICAL and BLOCKING are never allowed to transition to SUPPRESSED.
This is enforced in apply_transition() via severity check on the alert.
"""

from __future__ import annotations

from .identity import derive_transition_id
from .models import (
    AlertInstance,
    AlertLifecycleState,
    AlertLifecycleTransition,
    AlertSeverity,
)

# Explicit FSM — all valid transitions documented here.
VALID_TRANSITIONS: dict[AlertLifecycleState, set[AlertLifecycleState]] = {
    AlertLifecycleState.ACTIVE: {
        AlertLifecycleState.ACKNOWLEDGED,
        AlertLifecycleState.SUPPRESSED,
        AlertLifecycleState.RESOLVED,
        AlertLifecycleState.ESCALATED,
        AlertLifecycleState.EXPIRED,
    },
    AlertLifecycleState.ACKNOWLEDGED: {
        AlertLifecycleState.RESOLVED,
        AlertLifecycleState.ESCALATED,
        AlertLifecycleState.SUPPRESSED,
        AlertLifecycleState.EXPIRED,
    },
    AlertLifecycleState.SUPPRESSED: {
        AlertLifecycleState.ACTIVE,
        AlertLifecycleState.RESOLVED,
    },
    AlertLifecycleState.ESCALATED: {
        AlertLifecycleState.RESOLVED,
        AlertLifecycleState.ACKNOWLEDGED,
    },
    AlertLifecycleState.EXPIRED: {
        AlertLifecycleState.RESOLVED,
    },
    AlertLifecycleState.RESOLVED: set(),  # terminal state
}

_NEVER_SUPPRESS_SEVERITIES = {AlertSeverity.CRITICAL, AlertSeverity.BLOCKING}


class InvalidAlertTransition(Exception):
    """Raised when an invalid lifecycle transition is attempted."""


def validate_transition(
    from_state: AlertLifecycleState,
    to_state: AlertLifecycleState,
) -> bool:
    """Return True if the transition from_state → to_state is valid.

    Pure function; raises nothing. Use apply_transition() for enforcement.
    """
    valid_targets = VALID_TRANSITIONS.get(from_state, set())
    return to_state in valid_targets


def apply_transition(
    alert: AlertInstance,
    from_state: AlertLifecycleState,
    to_state: AlertLifecycleState,
    actor: str,
    reason: str,
    timestamp_iso: str,
) -> AlertLifecycleTransition:
    """Apply a lifecycle transition and return an immutable transition record.

    Raises InvalidAlertTransition if:
      - from_state → to_state is not a valid FSM transition.
      - The alert is CRITICAL/BLOCKING and to_state is SUPPRESSED.

    # escalation_routing_seam: when to_state is ESCALATED, downstream escalation
    # routing (SOC queue, PagerDuty, Jira, ServiceNow, compliance incident) is
    # triggered at this boundary. The AlertLifecycleTransition record carries all
    # metadata needed to route: (tenant_id, alert_rule_class, severity, actor, reason).
    # Routing plug-ins receive the transition record and dispatch asynchronously.
    """
    if not validate_transition(from_state, to_state):
        raise InvalidAlertTransition(
            f"Invalid transition {from_state.value} → {to_state.value} "
            f"for alert {alert.alert_instance_id}"
        )

    # CRITICAL and BLOCKING alerts cannot be suppressed.
    if (
        to_state == AlertLifecycleState.SUPPRESSED
        and alert.severity in _NEVER_SUPPRESS_SEVERITIES
    ):
        raise InvalidAlertTransition(
            f"Alert {alert.alert_instance_id} has severity {alert.severity.value} "
            f"and cannot be transitioned to SUPPRESSED."
        )

    transition_id = derive_transition_id(
        alert_instance_id=alert.alert_instance_id,
        from_state=from_state.value,
        to_state=to_state.value,
        transitioned_at_iso=timestamp_iso,
    )

    return AlertLifecycleTransition(
        transition_id=transition_id,
        alert_instance_id=alert.alert_instance_id,
        tenant_id=alert.tenant_id,
        from_state=from_state,
        to_state=to_state,
        actor=actor,
        reason=reason,
        transitioned_at_iso=timestamp_iso,
        replay_safe_metadata=(
            ("alert_rule_id", alert.alert_rule_id),
            ("alert_rule_class", alert.alert_rule_class.value),
            ("severity", alert.severity.value),
        ),
    )
