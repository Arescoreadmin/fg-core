"""
Triage Workflow — Task 14.2

Converts high-value behavior events (from api/behavior_logging.py) into
deterministic triage decisions: severity classification, action requirements,
and backlog escalation rules.

Design goals:
- Deterministic: same event → same decision, always.
- Closed mapping: every registered event type has an explicit severity.
- No randomness, no time-based drift, no operator-dependent logic.
- No mutation of source EventRecord objects.
- No cross-tenant aggregation — pattern detection is strictly per-tenant.

Severity levels:
  LOW    — non-blocking; informational; no immediate action required.
  MEDIUM — degraded experience or repeated signal; requires investigation.
  HIGH   — security risk, billing impact, data integrity risk, or systemic failure.

Backlog rule:
  HIGH severity   → always backlog_required = True
  MEDIUM severity → backlog_required = True only when the same (tenant, event_type)
                    has occurred >= MEDIUM_REPEAT_THRESHOLD times in stored events
                    up to and including the current event, ordered by
                    (created_at, event_id).
  LOW severity    → backlog_required = False

Determinism guarantee:
  Pattern detection counts only events with (created_at, event_id) <=
  (event.created_at, event.event_id).  Events added after the current event
  are excluded, preventing retroactive escalation.
  Same input → same output, always — regardless of when classify_event() runs.
"""

from __future__ import annotations

from dataclasses import dataclass

from api.behavior_logging import (
    EVENT_AUTH_CREDENTIAL_REJECTED,
    EVENT_AUTH_REPEATED_FAILURE,
    EVENT_BILLING_INVOICE_GENERATED,
    EVENT_RAG_GUARDRAIL_TRIGGERED,
    EVENT_RAG_INJECTION_DETECTED,
    EVENT_RAG_LOW_CONFIDENCE,
    EVENT_RAG_NO_ANSWER,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    EventRecord,
    query_events,
)

# ---------------------------------------------------------------------------
# Backlog threshold for MEDIUM repeated patterns
# ---------------------------------------------------------------------------

# A MEDIUM event triggers backlog when the same (tenant, event_type) has
# occurred this many times or more in the stored event log.
MEDIUM_REPEAT_THRESHOLD: int = 3

# ---------------------------------------------------------------------------
# Event → severity mapping (closed set, exhaustive, deterministic)
#
# Every registered event type must appear here.
# Default for unknown types = LOW (safe fallback; never silently escalates).
# ---------------------------------------------------------------------------

_EVENT_SEVERITY_MAP: dict[str, str] = {
    # RAG signals
    EVENT_RAG_NO_ANSWER: SEVERITY_LOW,
    # A grounded answer with low confidence is informational — single instance
    # is expected noise; repeated pattern escalates via MEDIUM backlog rule.
    EVENT_RAG_LOW_CONFIDENCE: SEVERITY_MEDIUM,
    # Prompt injection is a security signal — always HIGH.
    EVENT_RAG_INJECTION_DETECTED: SEVERITY_HIGH,
    # Guardrail trigger indicates a budget or safety limit was hit.
    # MEDIUM because a single trigger may be normal; repeated → backlog.
    EVENT_RAG_GUARDRAIL_TRIGGERED: SEVERITY_MEDIUM,
    # Billing invoice generation is a normal success event.
    EVENT_BILLING_INVOICE_GENERATED: SEVERITY_LOW,
    # A single credential rejection may be a user mistake — MEDIUM.
    EVENT_AUTH_CREDENTIAL_REJECTED: SEVERITY_MEDIUM,
    # Repeated auth failure is a security pattern — HIGH.
    EVENT_AUTH_REPEATED_FAILURE: SEVERITY_HIGH,
}

# Stable reason codes for triage decisions (never change meaning once published)
REASON_HIGH_SEVERITY = "high_severity_event"
REASON_MEDIUM_REPEATED = "medium_severity_repeated_pattern"
REASON_MEDIUM_SINGLE = "medium_severity_single_instance"
REASON_LOW_SEVERITY = "low_severity_informational"
REASON_UNKNOWN_TYPE = "unknown_event_type_default_low"

# ---------------------------------------------------------------------------
# Triage decision model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TriageDecision:
    """Deterministic triage decision for a single behavior event.

    Fields:
        event_id:        Source EventRecord.event_id.
        tenant_id:       Tenant this decision applies to.
        event_type:      The classified event type.
        severity:        Assigned severity: "low", "medium", or "high".
        action_required: True if the event warrants operator attention.
        backlog_required: True if the event should be escalated to the backlog.
        reason_code:     Stable code explaining the decision.

    Invariants:
        - HIGH   → action_required=True,  backlog_required=True
        - MEDIUM → action_required=True,  backlog_required=True (repeated) or False (single)
        - LOW    → action_required=False, backlog_required=False
    """

    event_id: str
    tenant_id: str
    event_type: str
    severity: str
    action_required: bool
    backlog_required: bool
    reason_code: str


# ---------------------------------------------------------------------------
# Core classification logic
# ---------------------------------------------------------------------------


def _classify_severity(event_type: str) -> tuple[str, str]:
    """Return (severity, reason_code) for the given event_type.

    Unknown event types default to LOW — never silently escalate noise.
    """
    if event_type in _EVENT_SEVERITY_MAP:
        sev = _EVENT_SEVERITY_MAP[event_type]
        reason = REASON_HIGH_SEVERITY if sev == SEVERITY_HIGH else REASON_LOW_SEVERITY
        return sev, reason
    return SEVERITY_LOW, REASON_UNKNOWN_TYPE


def _count_events_up_to(event: EventRecord) -> int:
    """Return the number of stored events with the same (tenant_id, event_type)
    that were recorded at or before the given event, using the composite key
    (created_at, event_id) for ordering.

    This is the same ordering used by query_events() sort — deterministic and
    stable.  Events with a later (created_at, event_id) pair are excluded,
    preventing retroactive escalation: adding new events after this event
    cannot change its triage decision on reclassification.

    Same input → same output, always — regardless of when classify_event()
    is called relative to other event ingestion.

    Strictly tenant-scoped via query_events() — no cross-tenant aggregation.
    """
    boundary = (event.created_at, event.event_id)
    return sum(
        1
        for r in query_events(event.tenant_id, event_type=event.event_type)
        if (r.created_at, r.event_id) <= boundary
    )


def classify_event(event: EventRecord) -> TriageDecision:
    """Classify a behavior event into a deterministic triage decision.

    Args:
        event: An EventRecord produced by api/behavior_logging.log_event().
               The record is never mutated.

    Returns:
        TriageDecision with severity, action_required, backlog_required,
        and a stable reason_code.

    Invariants:
        - HIGH:   action_required=True, backlog_required=True
        - MEDIUM: action_required=True; backlog_required depends on repeat count
        - LOW:    action_required=False, backlog_required=False
        - No cross-tenant data accessed
        - Source event is never mutated
        - Count is bounded by event_id order — no retroactive escalation
    """
    sev, _ = _classify_severity(event.event_type)

    if sev == SEVERITY_HIGH:
        return TriageDecision(
            event_id=event.event_id,
            tenant_id=event.tenant_id,
            event_type=event.event_type,
            severity=SEVERITY_HIGH,
            action_required=True,
            backlog_required=True,
            reason_code=REASON_HIGH_SEVERITY,
        )

    if sev == SEVERITY_MEDIUM:
        count = _count_events_up_to(event)
        repeated = count >= MEDIUM_REPEAT_THRESHOLD
        return TriageDecision(
            event_id=event.event_id,
            tenant_id=event.tenant_id,
            event_type=event.event_type,
            severity=SEVERITY_MEDIUM,
            action_required=True,
            backlog_required=repeated,
            reason_code=REASON_MEDIUM_REPEATED if repeated else REASON_MEDIUM_SINGLE,
        )

    # LOW (including unknown type fallback)
    reason = (
        REASON_UNKNOWN_TYPE
        if event.event_type not in _EVENT_SEVERITY_MAP
        else REASON_LOW_SEVERITY
    )
    return TriageDecision(
        event_id=event.event_id,
        tenant_id=event.tenant_id,
        event_type=event.event_type,
        severity=SEVERITY_LOW,
        action_required=False,
        backlog_required=False,
        reason_code=reason,
    )


def should_create_backlog(decision: TriageDecision) -> bool:
    """Return True if this triage decision warrants a backlog entry.

    This is the single source of truth for backlog escalation.
    Delegates to decision.backlog_required — no additional logic.
    """
    return decision.backlog_required
