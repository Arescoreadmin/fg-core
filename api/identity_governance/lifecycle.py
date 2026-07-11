"""api/identity_governance/lifecycle.py — Identity lifecycle state machine.

Deterministic state machine covering the full lifecycle of a subject:
CREATED -> ARCHIVED/DELETED. Only ACTIVE subjects can authenticate.

The manager is stateless — it validates and constructs immutable
``IdentityLifecycleRecord`` instances. Callers are responsible for
persistence.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone

from api.identity_governance.models import (
    IdentityLifecycleRecord,
    IdentityLifecycleState,
)

# ---------------------------------------------------------------------------
# Valid transitions
# ---------------------------------------------------------------------------

VALID_TRANSITIONS: dict[IdentityLifecycleState, set[IdentityLifecycleState]] = {
    IdentityLifecycleState.CREATED: {
        IdentityLifecycleState.INVITED,
        IdentityLifecycleState.ACTIVE,
        IdentityLifecycleState.DISABLED,
    },
    IdentityLifecycleState.INVITED: {
        IdentityLifecycleState.INVITATION_SENT,
        IdentityLifecycleState.ACCEPTED,
        IdentityLifecycleState.DISABLED,
        IdentityLifecycleState.ARCHIVED,
    },
    IdentityLifecycleState.INVITATION_SENT: {
        IdentityLifecycleState.INVITATION_OPENED,
        IdentityLifecycleState.INVITED,
        IdentityLifecycleState.DISABLED,
    },
    IdentityLifecycleState.INVITATION_OPENED: {
        IdentityLifecycleState.ACCEPTED,
        IdentityLifecycleState.INVITATION_SENT,
    },
    IdentityLifecycleState.ACCEPTED: {
        IdentityLifecycleState.PROVISIONED,
        IdentityLifecycleState.ACTIVE,
        IdentityLifecycleState.SUSPENDED,
        IdentityLifecycleState.DISABLED,
    },
    IdentityLifecycleState.PROVISIONED: {
        IdentityLifecycleState.ACTIVE,
        IdentityLifecycleState.MFA_ENROLLMENT_REQUIRED,
        IdentityLifecycleState.PASSWORD_RESET_PENDING,
    },
    IdentityLifecycleState.ACTIVE: {
        IdentityLifecycleState.PASSWORD_RESET_PENDING,
        IdentityLifecycleState.MFA_ENROLLMENT_REQUIRED,
        IdentityLifecycleState.SUSPENDED,
        IdentityLifecycleState.LOCKED,
        IdentityLifecycleState.DISABLED,
        IdentityLifecycleState.ARCHIVED,
    },
    IdentityLifecycleState.PASSWORD_RESET_PENDING: {
        IdentityLifecycleState.ACTIVE,
        IdentityLifecycleState.VERIFIED,
        IdentityLifecycleState.SUSPENDED,
        IdentityLifecycleState.DISABLED,
    },
    IdentityLifecycleState.MFA_ENROLLMENT_REQUIRED: {
        IdentityLifecycleState.ACTIVE,
        IdentityLifecycleState.VERIFIED,
        IdentityLifecycleState.SUSPENDED,
        IdentityLifecycleState.DISABLED,
    },
    IdentityLifecycleState.VERIFIED: {
        IdentityLifecycleState.ACTIVE,
        IdentityLifecycleState.SUSPENDED,
        IdentityLifecycleState.DISABLED,
    },
    IdentityLifecycleState.SUSPENDED: {
        IdentityLifecycleState.ACTIVE,
        IdentityLifecycleState.LOCKED,
        IdentityLifecycleState.DISABLED,
        IdentityLifecycleState.ARCHIVED,
    },
    IdentityLifecycleState.LOCKED: {
        IdentityLifecycleState.ACTIVE,
        IdentityLifecycleState.SUSPENDED,
        IdentityLifecycleState.DISABLED,
    },
    IdentityLifecycleState.DISABLED: {
        IdentityLifecycleState.ARCHIVED,
        IdentityLifecycleState.DELETED,
    },
    IdentityLifecycleState.ARCHIVED: {
        IdentityLifecycleState.DELETED,
    },
    IdentityLifecycleState.DELETED: set(),
}


class IdentityLifecycleManager:
    """Governed identity lifecycle state machine.

    Every transition must be a member of :data:`VALID_TRANSITIONS`. Only
    ``ACTIVE`` subjects may authenticate.
    """

    def transition(
        self,
        subject: str,
        tenant_id: str,
        current_state: IdentityLifecycleState,
        next_state: IdentityLifecycleState,
        reason: str,
        actor: str,
    ) -> IdentityLifecycleRecord:
        """Validate and record a lifecycle transition.

        Raises:
            ValueError: when the transition is not allowed, or when the
                ``subject``, ``tenant_id``, ``reason``, or ``actor`` fields
                are empty.
        """
        if not subject:
            raise ValueError("subject is required")
        if not tenant_id:
            raise ValueError("tenant_id is required")
        if not reason:
            raise ValueError("reason is required for lifecycle transition")
        if not actor:
            raise ValueError("actor is required for lifecycle transition")
        self._validate_transition(current_state, next_state)
        return IdentityLifecycleRecord(
            record_id=secrets.token_hex(16),
            subject=subject,
            tenant_id=tenant_id,
            from_state=current_state,
            to_state=next_state,
            reason=reason,
            actor=actor,
            occurred_at=datetime.now(tz=timezone.utc),
        )

    def can_authenticate(self, state: IdentityLifecycleState) -> bool:
        """Return True iff the subject is in ACTIVE state."""
        return state == IdentityLifecycleState.ACTIVE

    def _validate_transition(
        self,
        current: IdentityLifecycleState,
        next_state: IdentityLifecycleState,
    ) -> None:
        allowed = VALID_TRANSITIONS.get(current, set())
        if next_state not in allowed:
            raise ValueError(
                f"invalid lifecycle transition: {current.value} -> {next_state.value}"
            )
