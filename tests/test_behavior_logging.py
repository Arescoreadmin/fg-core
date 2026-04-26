"""
Task 14.1 — High-Value User Behavior Logging

Tests proving:
1)  High-value event is logged and returned correctly
2)  Events are tenant-scoped (tenant-a events not visible to tenant-b)
3)  Raw query text is never stored in event metadata
4)  Secrets/tokens are never stored in event metadata
5)  Metadata is sanitized (forbidden keys dropped, long values truncated)
6)  query_events returns only events for the trusted tenant
7)  Cross-tenant query returns empty (no leakage)
8)  Event logging does not break core flows (usage attribution, billing)
9)  event_id is deterministic: same inputs → same id
10) Unregistered (low-value / noise) event types are rejected
11) Missing tenant fails closed with structured error
12) Idempotency: same (tenant, event_type, idempotency_key) → existing record
13) All seven registered event types are accepted
14) export_events produces safe output (no metadata, no secrets)
"""

from __future__ import annotations

import json

import pytest
from fastapi import HTTPException

from api.behavior_logging import (
    ERR_EVENT_IDEMPOTENCY_REQUIRED,
    ERR_EXPORT_INVALID_FORMAT,
    ERR_INVALID_EVENT_TYPE,
    ERR_TENANT_REQUIRED,
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
    _reset_store,
    export_events,
    log_event,
    query_events,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clean_store():
    """Reset behavior event store before each test."""
    _reset_store()
    yield
    _reset_store()


# ---------------------------------------------------------------------------
# 1) test_high_value_event_logged
# ---------------------------------------------------------------------------


def test_high_value_event_logged():
    """log_event records a valid high-value event and returns it correctly."""
    result = log_event(
        trusted_tenant_id="tenant-a",
        event_type=EVENT_RAG_NO_ANSWER,
        source="api.rag",
        severity=SEVERITY_HIGH,
        idempotency_key="evt-001",
        metadata={"reason_code": "insufficient_evidence", "score": 0},
        now=1_000_000,
    )
    assert result.created is True
    r = result.record
    assert isinstance(r, EventRecord)
    assert r.tenant_id == "tenant-a"
    assert r.event_type == EVENT_RAG_NO_ANSWER
    assert r.source == "api.rag"
    assert r.severity == SEVERITY_HIGH
    assert r.created_at == 1_000_000
    assert r.event_id  # non-empty


# ---------------------------------------------------------------------------
# 2) test_event_is_tenant_scoped
# ---------------------------------------------------------------------------


def test_event_is_tenant_scoped():
    """Events logged for tenant-a must not appear in tenant-b's query."""
    log_event(
        "tenant-a", EVENT_RAG_NO_ANSWER, "api.rag", idempotency_key="e1", now=1_000_000
    )
    log_event(
        "tenant-b", EVENT_RAG_NO_ANSWER, "api.rag", idempotency_key="e1", now=1_000_000
    )

    results_a = query_events("tenant-a")
    results_b = query_events("tenant-b")

    assert len(results_a) == 1
    assert results_a[0].tenant_id == "tenant-a"

    assert len(results_b) == 1
    assert results_b[0].tenant_id == "tenant-b"

    # tenant-a event_id is distinct from tenant-b event_id (same ikey, different tenant)
    assert results_a[0].event_id != results_b[0].event_id


# ---------------------------------------------------------------------------
# 3) test_event_does_not_store_raw_query
# ---------------------------------------------------------------------------


def test_event_does_not_store_raw_query():
    """Metadata keys containing 'query' must be silently dropped."""
    result = log_event(
        "tenant-a",
        EVENT_RAG_NO_ANSWER,
        "api.rag",
        idempotency_key="e1",
        metadata={
            "raw_query": "what is the capital of france?",
            "user_query": "sensitive user input here",
            "query": "another form",
            "reason_code": "low_score",  # this is safe and should be kept
        },
        now=1_000_000,
    )
    meta = result.record.metadata
    assert "raw_query" not in meta
    assert "user_query" not in meta
    assert "query" not in meta
    assert meta.get("reason_code") == "low_score"  # safe key preserved


# ---------------------------------------------------------------------------
# 4) test_event_does_not_store_secrets
# ---------------------------------------------------------------------------


def test_event_does_not_store_secrets():
    """Metadata keys containing secret/token/credential/password/hash are dropped."""
    result = log_event(
        "tenant-a",
        EVENT_AUTH_CREDENTIAL_REJECTED,
        "api.credentials",
        idempotency_key="e1",
        metadata={
            "token": "fgk.abc.verysecret",
            "secret": "super-secret-value",
            "api_key": "some-key",
            "password": "hunter2",
            "key_hash": "$argon2id$...",
            "credential_id": "1234abcd",
            "rejection_reason": "revoked",  # safe — should be kept
            "failure_count": 3,  # safe integer
        },
        now=1_000_000,
    )
    meta = result.record.metadata
    assert "token" not in meta
    assert "secret" not in meta
    assert "api_key" not in meta
    assert "password" not in meta
    assert "key_hash" not in meta
    assert "credential_id" not in meta
    assert meta.get("rejection_reason") == "revoked"
    assert meta.get("failure_count") == 3


# ---------------------------------------------------------------------------
# 5) test_event_metadata_is_sanitized
# ---------------------------------------------------------------------------


def test_event_metadata_is_sanitized():
    """Metadata is sanitized: complex types dropped, oversized strings truncated, copy on write."""
    long_value = "x" * 300  # > _MAX_METADATA_VALUE_LEN (256)
    original_meta = {
        "score": 0.42,
        "chunk_count": 5,
        "long_string": long_value,
        "nested": {"inner": "value"},  # dict → dropped
        "items": [1, 2, 3],  # list → dropped
        "flag": True,
    }

    result = log_event(
        "tenant-a",
        EVENT_RAG_LOW_CONFIDENCE,
        "api.rag",
        idempotency_key="e1",
        metadata=original_meta,
        now=1_000_000,
    )
    meta = result.record.metadata

    assert meta["score"] == 0.42
    assert meta["chunk_count"] == 5
    assert meta["long_string"] == "[truncated]"
    assert "nested" not in meta
    assert "items" not in meta
    assert meta["flag"] is True

    # Caller mutation after write does not alter stored record
    original_meta["score"] = 999.0
    original_meta["new_key"] = "injected"
    assert result.record.metadata["score"] == 0.42
    assert "new_key" not in result.record.metadata


# ---------------------------------------------------------------------------
# 6) test_query_returns_only_tenant_events
# ---------------------------------------------------------------------------


def test_query_returns_only_tenant_events():
    """query_events must filter strictly to the supplied trusted_tenant_id."""
    log_event(
        "tenant-a", EVENT_RAG_NO_ANSWER, "api.rag", idempotency_key="e1", now=1_000_000
    )
    log_event(
        "tenant-a",
        EVENT_RAG_LOW_CONFIDENCE,
        "api.rag",
        idempotency_key="e2",
        now=1_000_001,
    )
    log_event(
        "tenant-b", EVENT_RAG_NO_ANSWER, "api.rag", idempotency_key="e3", now=1_000_002
    )

    results = query_events("tenant-a")
    assert len(results) == 2
    assert all(r.tenant_id == "tenant-a" for r in results)


# ---------------------------------------------------------------------------
# 7) test_cross_tenant_query_returns_empty
# ---------------------------------------------------------------------------


def test_cross_tenant_query_returns_empty():
    """query_events for a tenant with no events returns empty list, not an error."""
    log_event(
        "tenant-z", EVENT_RAG_NO_ANSWER, "api.rag", idempotency_key="e1", now=1_000_000
    )

    results = query_events("tenant-other")
    assert results == []


# ---------------------------------------------------------------------------
# 8) test_event_logging_does_not_break_core_flow
# ---------------------------------------------------------------------------


def test_event_logging_does_not_break_core_flow():
    """Logging behavior events must not interfere with usage attribution or billing."""
    from api.billing_integration import _reset_store as _reset_billing
    from api.billing_integration import generate_invoice
    from api.usage_attribution import _reset_store as _reset_usage
    from api.usage_attribution import record_usage

    _reset_usage()
    _reset_billing()
    try:
        # Core flow: record usage
        ur = record_usage(
            "tenant-a", "cust-1", "rag_query", units=2, idempotency_key="u1"
        )
        assert ur.created is True

        # Log the billing invoice generated event
        ev = log_event(
            "tenant-a",
            EVENT_BILLING_INVOICE_GENERATED,
            "api.billing",
            severity=SEVERITY_LOW,
            idempotency_key="bill-evt-1",
            metadata={"source_usage_count": 1},
            now=1_000_000,
        )
        assert ev.created is True

        # Core flow: generate invoice — must still work
        inv = generate_invoice("tenant-a", "cust-1", idempotency_key="inv-1")
        assert inv.created is True
        assert inv.invoice.source_usage_count == 1

        # Events and invoices are independent
        events = query_events("tenant-a")
        assert len(events) == 1
        assert events[0].event_type == EVENT_BILLING_INVOICE_GENERATED
    finally:
        _reset_usage()
        _reset_billing()


# ---------------------------------------------------------------------------
# 9) test_event_id_deterministic
# ---------------------------------------------------------------------------


def test_event_id_deterministic():
    """Same (tenant, event_type, idempotency_key, now) always produces the same event_id."""
    r1 = log_event(
        "tenant-a",
        EVENT_RAG_NO_ANSWER,
        "api.rag",
        idempotency_key="det-key",
        now=1_000_000,
    )
    # Reset store so the second call creates a new record (not idempotent return)
    _reset_store()
    r2 = log_event(
        "tenant-a",
        EVENT_RAG_NO_ANSWER,
        "api.rag",
        idempotency_key="det-key",
        now=1_000_000,
    )
    assert r1.record.event_id == r2.record.event_id

    # Different tenant → different event_id
    _reset_store()
    r3 = log_event(
        "tenant-b",
        EVENT_RAG_NO_ANSWER,
        "api.rag",
        idempotency_key="det-key",
        now=1_000_000,
    )
    assert r1.record.event_id != r3.record.event_id


# ---------------------------------------------------------------------------
# 10) test_no_event_for_low_value_noise
# ---------------------------------------------------------------------------


def test_no_event_for_low_value_noise():
    """Unregistered event types must be rejected — noise is not logged."""
    for noise_type in (
        "request.received",
        "page.view",
        "heartbeat",
        "debug.trace",
        "",
        None,
        "rag.every_query",
    ):
        with pytest.raises(HTTPException) as exc:
            log_event(
                "tenant-a", noise_type, "api.rag", idempotency_key="n1", now=1_000_000
            )
        assert exc.value.status_code == 400
        assert exc.value.detail["code"] == ERR_INVALID_EVENT_TYPE

    # No events should have been stored
    assert query_events("tenant-a") == []


# ---------------------------------------------------------------------------
# 11) test_missing_tenant_fails_closed
# ---------------------------------------------------------------------------


def test_missing_tenant_fails_closed():
    """Missing or blank trusted_tenant_id must raise BEHAVIOR_TENANT_REQUIRED (400)."""
    for bad in (None, "", "  "):
        with pytest.raises(HTTPException) as exc:
            log_event(bad, EVENT_RAG_NO_ANSWER, "api.rag", idempotency_key="e1")
        assert exc.value.status_code == 400
        assert exc.value.detail["code"] == ERR_TENANT_REQUIRED


# ---------------------------------------------------------------------------
# 12) test_idempotency_returns_existing_event
# ---------------------------------------------------------------------------


def test_idempotency_returns_existing_event():
    """Same (tenant, event_type, idempotency_key) returns the existing event."""
    r1 = log_event(
        "tenant-a",
        EVENT_RAG_NO_ANSWER,
        "api.rag",
        idempotency_key="idem-key",
        now=1_000_000,
    )
    r2 = log_event(
        "tenant-a",
        EVENT_RAG_NO_ANSWER,
        "api.rag",
        idempotency_key="idem-key",
        now=1_000_000,
    )
    assert r1.created is True
    assert r2.created is False
    assert r1.record.event_id == r2.record.event_id
    assert len(query_events("tenant-a")) == 1


# ---------------------------------------------------------------------------
# 13) test_all_registered_event_types_accepted
# ---------------------------------------------------------------------------


def test_all_registered_event_types_accepted():
    """All seven registered high-value event types must be accepted."""
    registered = [
        EVENT_RAG_NO_ANSWER,
        EVENT_RAG_LOW_CONFIDENCE,
        EVENT_RAG_INJECTION_DETECTED,
        EVENT_RAG_GUARDRAIL_TRIGGERED,
        EVENT_BILLING_INVOICE_GENERATED,
        EVENT_AUTH_CREDENTIAL_REJECTED,
        EVENT_AUTH_REPEATED_FAILURE,
    ]
    for i, etype in enumerate(registered):
        result = log_event(
            "tenant-a",
            etype,
            "api.test",
            idempotency_key=f"e{i}",
            now=1_000_000 + i,
        )
        assert result.created is True
        assert result.record.event_type == etype

    assert len(query_events("tenant-a")) == 7


# ---------------------------------------------------------------------------
# 14) test_export_events_produces_safe_output
# ---------------------------------------------------------------------------


def test_export_events_produces_safe_output():
    """export_events JSON must not contain metadata, secrets, or raw content."""
    log_event(
        "tenant-a",
        EVENT_RAG_NO_ANSWER,
        "api.rag",
        idempotency_key="e1",
        metadata={
            "reason_code": "low_score",
            "score": 0,
        },
        now=1_000_000,
    )

    out = export_events("tenant-a", fmt="json")
    rows = json.loads(out)
    assert len(rows) == 1
    row = rows[0]

    # Required fields
    for col in (
        "event_id",
        "tenant_id",
        "event_type",
        "source",
        "severity",
        "created_at",
    ):
        assert col in row

    # Metadata must NOT appear in flat export
    assert "metadata" not in row
    assert "reason_code" not in row

    # Tenant isolation
    assert row["tenant_id"] == "tenant-a"

    # Invalid format rejected
    with pytest.raises(HTTPException) as exc:
        export_events("tenant-a", fmt="xml")
    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == ERR_EXPORT_INVALID_FORMAT


# ---------------------------------------------------------------------------
# Extra: query_events filtering works correctly
# ---------------------------------------------------------------------------


def test_query_events_filters_by_event_type_severity_source():
    """query_events filters work independently."""
    log_event(
        "tenant-a",
        EVENT_RAG_NO_ANSWER,
        "api.rag",
        severity=SEVERITY_HIGH,
        idempotency_key="e1",
        now=1_000_000,
    )
    log_event(
        "tenant-a",
        EVENT_RAG_LOW_CONFIDENCE,
        "api.rag",
        severity=SEVERITY_MEDIUM,
        idempotency_key="e2",
        now=1_000_001,
    )
    log_event(
        "tenant-a",
        EVENT_AUTH_CREDENTIAL_REJECTED,
        "api.credentials",
        severity=SEVERITY_HIGH,
        idempotency_key="e3",
        now=1_000_002,
    )

    # Filter by event_type
    no_answers = query_events("tenant-a", event_type=EVENT_RAG_NO_ANSWER)
    assert len(no_answers) == 1
    assert no_answers[0].event_type == EVENT_RAG_NO_ANSWER

    # Filter by source
    rag_events = query_events("tenant-a", source="api.rag")
    assert len(rag_events) == 2

    # Filter by severity
    high_events = query_events("tenant-a", severity=SEVERITY_HIGH)
    assert len(high_events) == 2

    # Time range
    ranged = query_events("tenant-a", from_ts=1_000_001, to_ts=1_000_001)
    assert len(ranged) == 1
    assert ranged[0].event_type == EVENT_RAG_LOW_CONFIDENCE


# ---------------------------------------------------------------------------
# Hardening tests — Task 14.1 addendum
# ---------------------------------------------------------------------------


def test_behavior_logging_rejects_missing_idempotency_key():
    """None idempotency_key must raise BEHAVIOR_EVENT_IDEMPOTENCY_REQUIRED (400)."""
    with pytest.raises(HTTPException) as exc:
        log_event(
            "tenant-a",
            EVENT_RAG_NO_ANSWER,
            "api.rag",
            idempotency_key=None,
            now=1_000_000,
        )
    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == ERR_EVENT_IDEMPOTENCY_REQUIRED


def test_behavior_logging_rejects_blank_idempotency_key():
    """Blank/whitespace idempotency_key must raise BEHAVIOR_EVENT_IDEMPOTENCY_REQUIRED (400)."""
    for bad in ("", "   ", "\t"):
        with pytest.raises(HTTPException) as exc:
            log_event(
                "tenant-a",
                EVENT_RAG_NO_ANSWER,
                "api.rag",
                idempotency_key=bad,
                now=1_000_000,
            )
        assert exc.value.status_code == 400
        assert exc.value.detail["code"] == ERR_EVENT_IDEMPOTENCY_REQUIRED


def test_behavior_logging_same_second_events_do_not_silently_dedupe():
    """Two distinct events with unique idempotency_keys must both be stored,
    even when they share the same tenant, event_type, source, and timestamp."""
    r1 = log_event(
        "tenant-a",
        EVENT_RAG_NO_ANSWER,
        "api.rag",
        idempotency_key="occurrence-001",
        now=1_000_000,
    )
    r2 = log_event(
        "tenant-a",
        EVENT_RAG_NO_ANSWER,
        "api.rag",
        idempotency_key="occurrence-002",
        now=1_000_000,  # same second
    )
    assert r1.created is True
    assert r2.created is True
    assert r1.record.event_id != r2.record.event_id

    # Both events are stored and queryable
    events = query_events("tenant-a")
    assert len(events) == 2


def test_behavior_logging_query_returns_detached_metadata():
    """Mutating metadata on a queried EventRecord must not alter the stored record."""
    log_event(
        "tenant-a",
        EVENT_RAG_NO_ANSWER,
        "api.rag",
        idempotency_key="det-001",
        metadata={"reason_code": "low_score", "score": 0},
        now=1_000_000,
    )

    # First query — get a copy
    results1 = query_events("tenant-a")
    assert len(results1) == 1
    copy1 = results1[0]

    # Mutate the returned metadata
    copy1.metadata["reason_code"] = "MUTATED"
    copy1.metadata["injected"] = "bad_value"

    # Second query — stored record must be unchanged
    results2 = query_events("tenant-a")
    assert results2[0].metadata["reason_code"] == "low_score"
    assert "injected" not in results2[0].metadata
