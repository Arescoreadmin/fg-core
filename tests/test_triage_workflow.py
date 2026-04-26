"""
Task 14.2 — Triage Workflow

Tests proving:
1)  HIGH severity event triggers action_required=True and backlog_required=True
2)  MEDIUM severity single event requires action but not backlog
3)  LOW severity event does not trigger action or backlog
4)  Event classification is deterministic (same event → same decision)
5)  Unknown event type defaults to LOW (safe fallback)
6)  Repeated MEDIUM events (>= threshold) trigger backlog
7)  Single MEDIUM event below threshold does not trigger backlog
8)  Cross-tenant events do not mix patterns
9)  No sensitive data appears in triage decision fields
10) Triage does not mutate source EventRecord objects
11) should_create_backlog() is consistent with decision.backlog_required
12) All registered event types have an explicit severity mapping
"""

from __future__ import annotations

import pytest

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
    _reset_store,
    log_event,
    query_events,
)
from api.triage import (
    MEDIUM_REPEAT_THRESHOLD,
    REASON_HIGH_SEVERITY,
    REASON_LOW_SEVERITY,
    REASON_MEDIUM_REPEATED,
    REASON_MEDIUM_SINGLE,
    REASON_UNKNOWN_TYPE,
    TriageDecision,
    _EVENT_SEVERITY_MAP,
    classify_event,
    should_create_backlog,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clean_behavior_store():
    """Reset behavior event store before each test."""
    _reset_store()
    yield
    _reset_store()


def _log(
    tenant_id: str,
    event_type: str,
    source: str = "api.test",
    idempotency_key: str = "evt-001",
    now: int = 1_000_000,
):
    return log_event(
        trusted_tenant_id=tenant_id,
        event_type=event_type,
        source=source,
        idempotency_key=idempotency_key,
        now=now,
    ).record


# ---------------------------------------------------------------------------
# 1) test_high_severity_event_triggers_action_and_backlog
# ---------------------------------------------------------------------------


def test_high_severity_event_triggers_action_and_backlog():
    """HIGH severity events must set action_required=True and backlog_required=True."""
    event = _log("tenant-a", EVENT_RAG_INJECTION_DETECTED)
    decision = classify_event(event)

    assert isinstance(decision, TriageDecision)
    assert decision.severity == SEVERITY_HIGH
    assert decision.action_required is True
    assert decision.backlog_required is True
    assert decision.reason_code == REASON_HIGH_SEVERITY
    assert decision.event_id == event.event_id
    assert decision.tenant_id == "tenant-a"
    assert decision.event_type == EVENT_RAG_INJECTION_DETECTED


def test_auth_repeated_failure_is_high():
    """auth.repeated_failure must classify as HIGH."""
    event = _log("tenant-a", EVENT_AUTH_REPEATED_FAILURE)
    decision = classify_event(event)
    assert decision.severity == SEVERITY_HIGH
    assert decision.action_required is True
    assert decision.backlog_required is True


# ---------------------------------------------------------------------------
# 2) test_medium_severity_requires_action
# ---------------------------------------------------------------------------


def test_medium_severity_requires_action():
    """MEDIUM severity must require action even on first occurrence."""
    event = _log("tenant-a", EVENT_AUTH_CREDENTIAL_REJECTED)
    decision = classify_event(event)

    assert decision.severity == SEVERITY_MEDIUM
    assert decision.action_required is True
    # Single occurrence — no backlog yet
    assert decision.backlog_required is False
    assert decision.reason_code == REASON_MEDIUM_SINGLE


# ---------------------------------------------------------------------------
# 3) test_low_severity_does_not_trigger_action
# ---------------------------------------------------------------------------


def test_low_severity_does_not_trigger_action():
    """LOW severity must not require action or backlog."""
    event = _log("tenant-a", EVENT_RAG_NO_ANSWER)
    decision = classify_event(event)

    assert decision.severity == SEVERITY_LOW
    assert decision.action_required is False
    assert decision.backlog_required is False
    assert decision.reason_code == REASON_LOW_SEVERITY


def test_billing_invoice_generated_is_low():
    """billing.invoice_generated is a success event — must be LOW."""
    event = _log("tenant-a", EVENT_BILLING_INVOICE_GENERATED)
    decision = classify_event(event)
    assert decision.severity == SEVERITY_LOW
    assert decision.action_required is False
    assert decision.backlog_required is False


# ---------------------------------------------------------------------------
# 4) test_event_classification_is_deterministic
# ---------------------------------------------------------------------------


def test_event_classification_is_deterministic():
    """Classifying the same event twice must produce identical decisions."""
    event = _log("tenant-a", EVENT_RAG_INJECTION_DETECTED)
    d1 = classify_event(event)
    d2 = classify_event(event)

    assert d1 == d2
    assert d1.severity == d2.severity
    assert d1.action_required == d2.action_required
    assert d1.backlog_required == d2.backlog_required
    assert d1.reason_code == d2.reason_code


# ---------------------------------------------------------------------------
# 5) test_unknown_event_defaults_to_low
# ---------------------------------------------------------------------------


def test_unknown_event_defaults_to_low():
    """An EventRecord with an unregistered event_type must classify as LOW (safe fallback)."""
    from dataclasses import replace

    # Build a synthetic EventRecord with an unregistered event_type
    real_event = _log("tenant-a", EVENT_RAG_NO_ANSWER)
    synthetic = replace(real_event, event_type="some.unknown.event.type")

    decision = classify_event(synthetic)

    assert decision.severity == SEVERITY_LOW
    assert decision.action_required is False
    assert decision.backlog_required is False
    assert decision.reason_code == REASON_UNKNOWN_TYPE


# ---------------------------------------------------------------------------
# 6) test_repeated_medium_events_trigger_backlog
# ---------------------------------------------------------------------------


def test_repeated_medium_events_trigger_backlog():
    """MEDIUM event at or above MEDIUM_REPEAT_THRESHOLD must set backlog_required=True."""
    # Log MEDIUM_REPEAT_THRESHOLD events (all distinct idempotency keys)
    for i in range(MEDIUM_REPEAT_THRESHOLD):
        log_event(
            "tenant-a",
            EVENT_AUTH_CREDENTIAL_REJECTED,
            "api.credentials",
            idempotency_key=f"cred-fail-{i}",
            now=1_000_000 + i,
        )

    events = query_events("tenant-a", event_type=EVENT_AUTH_CREDENTIAL_REJECTED)
    assert len(events) == MEDIUM_REPEAT_THRESHOLD

    # Classify the last event — count should now be >= threshold
    decision = classify_event(events[-1])
    assert decision.severity == SEVERITY_MEDIUM
    assert decision.action_required is True
    assert decision.backlog_required is True
    assert decision.reason_code == REASON_MEDIUM_REPEATED


# ---------------------------------------------------------------------------
# 7) test_single_medium_event_does_not_trigger_backlog
# ---------------------------------------------------------------------------


def test_single_medium_event_does_not_trigger_backlog():
    """A single MEDIUM event (below threshold) must not trigger backlog."""
    event = _log("tenant-a", EVENT_RAG_GUARDRAIL_TRIGGERED, idempotency_key="guard-1")
    decision = classify_event(event)

    assert decision.severity == SEVERITY_MEDIUM
    assert decision.action_required is True
    assert decision.backlog_required is False
    assert decision.reason_code == REASON_MEDIUM_SINGLE


# ---------------------------------------------------------------------------
# 8) test_cross_tenant_events_do_not_mix_patterns
# ---------------------------------------------------------------------------


def test_cross_tenant_events_do_not_mix_patterns():
    """Events from tenant-b must not contribute to tenant-a's repeat count."""
    # Log MEDIUM_REPEAT_THRESHOLD - 1 events for tenant-a
    for i in range(MEDIUM_REPEAT_THRESHOLD - 1):
        log_event(
            "tenant-a",
            EVENT_AUTH_CREDENTIAL_REJECTED,
            "api.credentials",
            idempotency_key=f"a-fail-{i}",
            now=1_000_000 + i,
        )

    # Log additional events for tenant-b (should not affect tenant-a's count)
    for i in range(MEDIUM_REPEAT_THRESHOLD + 5):
        log_event(
            "tenant-b",
            EVENT_AUTH_CREDENTIAL_REJECTED,
            "api.credentials",
            idempotency_key=f"b-fail-{i}",
            now=1_000_000 + i,
        )

    events_a = query_events("tenant-a", event_type=EVENT_AUTH_CREDENTIAL_REJECTED)
    assert len(events_a) == MEDIUM_REPEAT_THRESHOLD - 1

    # tenant-a is still below threshold — no backlog
    decision = classify_event(events_a[-1])
    assert decision.tenant_id == "tenant-a"
    assert decision.backlog_required is False
    assert decision.reason_code == REASON_MEDIUM_SINGLE


# ---------------------------------------------------------------------------
# 9) test_no_sensitive_data_in_triage_decision
# ---------------------------------------------------------------------------


def test_no_sensitive_data_in_triage_decision():
    """TriageDecision fields must not expose secrets, tokens, raw queries, or metadata."""
    event = _log(
        "tenant-a",
        EVENT_RAG_INJECTION_DETECTED,
        idempotency_key="inject-001",
    )
    decision = classify_event(event)

    # TriageDecision must only contain: event_id, tenant_id, event_type,
    # severity, action_required, backlog_required, reason_code
    decision_dict = {
        "event_id": decision.event_id,
        "tenant_id": decision.tenant_id,
        "event_type": decision.event_type,
        "severity": decision.severity,
        "action_required": decision.action_required,
        "backlog_required": decision.backlog_required,
        "reason_code": decision.reason_code,
    }

    # No metadata field
    assert not hasattr(decision, "metadata")
    # No raw content, secrets, or tokens in string fields
    decision_str = str(decision_dict)
    for forbidden in ("token", "secret", "password", "raw_query", "embedding"):
        assert forbidden not in decision_str.lower()


# ---------------------------------------------------------------------------
# 10) test_triage_does_not_mutate_event_records
# ---------------------------------------------------------------------------


def test_triage_does_not_mutate_event_records():
    """classify_event() must not modify the source EventRecord."""
    event = _log(
        "tenant-a",
        EVENT_RAG_LOW_CONFIDENCE,
        idempotency_key="low-conf-001",
    )
    original_event_id = event.event_id
    original_tenant_id = event.tenant_id
    original_event_type = event.event_type
    original_severity = event.severity
    original_metadata = dict(event.metadata)

    classify_event(event)

    # All fields unchanged after classification
    assert event.event_id == original_event_id
    assert event.tenant_id == original_tenant_id
    assert event.event_type == original_event_type
    assert event.severity == original_severity
    assert event.metadata == original_metadata


# ---------------------------------------------------------------------------
# 11) test_should_create_backlog_consistent_with_decision
# ---------------------------------------------------------------------------


def test_should_create_backlog_consistent_with_decision():
    """should_create_backlog() must always equal decision.backlog_required."""
    cases = [
        ("tenant-a", EVENT_RAG_INJECTION_DETECTED, "inject-1"),
        ("tenant-a", EVENT_AUTH_CREDENTIAL_REJECTED, "cred-1"),
        ("tenant-a", EVENT_RAG_NO_ANSWER, "no-ans-1"),
        ("tenant-a", EVENT_BILLING_INVOICE_GENERATED, "bill-1"),
    ]
    for tid, etype, ikey in cases:
        event = _log(tid, etype, idempotency_key=ikey)
        decision = classify_event(event)
        assert should_create_backlog(decision) == decision.backlog_required


# ---------------------------------------------------------------------------
# 12) test_all_registered_event_types_have_explicit_severity_mapping
# ---------------------------------------------------------------------------


def test_all_registered_event_types_have_explicit_severity_mapping():
    """Every event type registered in behavior_logging must have an entry in the severity map."""
    from api.behavior_logging import _VALID_EVENT_TYPES

    for event_type in _VALID_EVENT_TYPES:
        assert event_type in _EVENT_SEVERITY_MAP, (
            f"Event type {event_type!r} is registered in behavior_logging "
            f"but missing from triage._EVENT_SEVERITY_MAP"
        )
        assert _EVENT_SEVERITY_MAP[event_type] in (
            SEVERITY_LOW,
            SEVERITY_MEDIUM,
            SEVERITY_HIGH,
        )
