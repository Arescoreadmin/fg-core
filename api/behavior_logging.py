"""
High-Value User Behavior Logging — Task 14.1

Captures curated, tenant-scoped behavioral signals to support triage,
product decisions, and operational observability.

This is NOT an analytics firehose. Only log events that answer:
  "What happened, where, for which tenant, and how severe?"

High-value event types (exhaustive — not extensible without review):
  rag.no_answer           — RAG returned no answer (low context / insufficient evidence)
  rag.low_confidence      — Grounded answer with low confidence score
  rag.injection_detected  — Prompt injection flagged in retrieval context
  rag.guardrail_triggered — Guardrail applied (cost, latency, or injection budget)
  billing.invoice_generated — Billing invoice successfully generated
  auth.credential_rejected  — Credential rejected (invalid, revoked, or missing scope)
  auth.repeated_failure     — Same tenant/failure pattern repeated above threshold

Guarantees:
- Tenant-scoped: every event is bound to a validated tenant_id.
- Non-leaky: raw queries, document contents, tokens, and secrets are never logged.
- Deterministic: event_id = SHA-256(tenant_id + ":" + event_type + ":" + idempotency_key)[:32].
- Metadata safety: shallow-copied and sanitized on write; forbidden keys stripped.
- Idempotent: same (tenant, event_type, idempotency_key) → same event_id; repeated
  calls return the existing record.
- Structured error contract via api/error_contracts.py (Task 11.1).
- No external calls, no DB migrations, no new dependencies.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import time
from dataclasses import dataclass, field, replace
from typing import Any

from fastapi import HTTPException

from api.error_contracts import api_error

log = logging.getLogger("frostgate.behavior_logging")

# ---------------------------------------------------------------------------
# Stable error codes (never change meaning once published)
# ---------------------------------------------------------------------------

ERR_TENANT_REQUIRED = "BEHAVIOR_TENANT_REQUIRED"
ERR_INVALID_EVENT_TYPE = "BEHAVIOR_INVALID_EVENT_TYPE"
ERR_EXPORT_INVALID_FORMAT = "BEHAVIOR_EXPORT_INVALID_FORMAT"
ERR_EVENT_IDEMPOTENCY_REQUIRED = "BEHAVIOR_EVENT_IDEMPOTENCY_REQUIRED"

_VALID_EXPORT_FORMATS = frozenset({"json", "csv"})

# ---------------------------------------------------------------------------
# High-value event type registry (exhaustive — not extensible without review)
# ---------------------------------------------------------------------------

# RAG signals
EVENT_RAG_NO_ANSWER = "rag.no_answer"
EVENT_RAG_LOW_CONFIDENCE = "rag.low_confidence"
EVENT_RAG_INJECTION_DETECTED = "rag.injection_detected"
EVENT_RAG_GUARDRAIL_TRIGGERED = "rag.guardrail_triggered"

# Billing signals
EVENT_BILLING_INVOICE_GENERATED = "billing.invoice_generated"

# Auth signals
EVENT_AUTH_CREDENTIAL_REJECTED = "auth.credential_rejected"
EVENT_AUTH_REPEATED_FAILURE = "auth.repeated_failure"

_VALID_EVENT_TYPES = frozenset(
    {
        EVENT_RAG_NO_ANSWER,
        EVENT_RAG_LOW_CONFIDENCE,
        EVENT_RAG_INJECTION_DETECTED,
        EVENT_RAG_GUARDRAIL_TRIGGERED,
        EVENT_BILLING_INVOICE_GENERATED,
        EVENT_AUTH_CREDENTIAL_REJECTED,
        EVENT_AUTH_REPEATED_FAILURE,
    }
)

# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------

SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"

_VALID_SEVERITIES = frozenset({SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH})

# ---------------------------------------------------------------------------
# Metadata safety — forbidden key substrings
#
# Any metadata key containing one of these substrings is silently dropped.
# This prevents accidental leakage of raw content, credentials, or tokens
# into the behavior log — even when callers pass them by mistake.
# ---------------------------------------------------------------------------

_FORBIDDEN_KEY_FRAGMENTS = frozenset(
    {
        "query",
        "content",
        "text",
        "document",
        "token",
        "secret",
        "password",
        "hash",
        "credential",
        "embedding",
        "raw",
        "key",  # catches api_key, private_key, key_id — not chunk_count
    }
)

_MAX_METADATA_VALUE_LEN = 256


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EventRecord:
    """Immutable high-value behavioral signal record.

    Fields:
        event_id:      SHA-256(tenant_id + ":" + event_type + ":" + idempotency_key)[:32].
                       Deterministic and cross-tenant collision-free.
        tenant_id:     Trusted tenant this event belongs to.
        event_type:    One of the registered high-value event types.
        source:        System component that produced the event
                       (e.g. "api.rag", "api.billing", "api.credentials").
        severity:      "low", "medium", or "high".
        created_at:    Unix timestamp of first write.
        metadata:      Sanitized, shallow-copied safe metadata dict.
                       No secrets, no raw content, no hashes, no foreign tenant data.
        idempotency_key: Caller-supplied or server-derived key.
    """

    event_id: str
    tenant_id: str
    event_type: str
    source: str
    severity: str
    created_at: int
    metadata: dict = field(default_factory=dict)
    idempotency_key: str = ""


@dataclass(frozen=True)
class EventWriteResult:
    """Result of a log_event() call."""

    record: EventRecord
    created: bool  # True = new event; False = idempotent no-op (returned existing)


# ---------------------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------------------

# event_id → EventRecord
_store: dict[str, EventRecord] = {}


def _reset_store() -> None:
    """Reset in-memory store. For test isolation only."""
    _store.clear()


# ---------------------------------------------------------------------------
# Deterministic event_id
# ---------------------------------------------------------------------------


def _derive_event_id(tenant_id: str, event_type: str, idempotency_key: str) -> str:
    """Derive a deterministic, cross-tenant-safe event_id.

    event_id = hex(SHA-256(tenant_id + ":" + event_type + ":" + idempotency_key))[:32]

    Including tenant_id ensures the same (event_type, idempotency_key) under
    two different tenants maps to distinct event_ids.
    """
    payload = f"{tenant_id}:{event_type}:{idempotency_key}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Validation and sanitization helpers
# ---------------------------------------------------------------------------


def _require_tenant(tenant_id: Any) -> str:
    if not tenant_id or not str(tenant_id).strip():
        raise HTTPException(
            status_code=400,
            detail=api_error(
                ERR_TENANT_REQUIRED,
                "trusted_tenant_id is required for behavior logging",
                action="supply tenant_id from validated credential/session context",
            ),
        )
    return str(tenant_id).strip()


def _require_idempotency_key(idempotency_key: Any) -> str:
    if not isinstance(idempotency_key, str) or not idempotency_key.strip():
        raise HTTPException(
            status_code=400,
            detail=api_error(
                ERR_EVENT_IDEMPOTENCY_REQUIRED,
                "idempotency_key is required for behavior event logging",
                action="supply a stable caller-assigned idempotency_key; do not use timestamps or random values",
            ),
        )
    return idempotency_key.strip()


def _require_event_type(event_type: Any) -> str:
    if not isinstance(event_type, str) or event_type not in _VALID_EVENT_TYPES:
        raise HTTPException(
            status_code=400,
            detail=api_error(
                ERR_INVALID_EVENT_TYPE,
                f"event_type {event_type!r} is not a registered high-value event type",
                action=f"use one of: {', '.join(sorted(_VALID_EVENT_TYPES))}",
            ),
        )
    return event_type


def _sanitize_metadata(metadata: Any) -> dict:
    """Return a sanitized shallow copy of metadata.

    Rules:
    - None or non-dict → {}
    - Keys containing a forbidden fragment are dropped silently
    - String values longer than _MAX_METADATA_VALUE_LEN are replaced with "[truncated]"
    - Only str, int, float, bool scalar values are kept; complex types are dropped
    - Caller mutation after write cannot alter the stored record
    """
    if not isinstance(metadata, dict):
        return {}

    safe: dict[str, Any] = {}
    for k, v in metadata.items():
        if not isinstance(k, str):
            continue
        k_lower = k.lower()
        if any(frag in k_lower for frag in _FORBIDDEN_KEY_FRAGMENTS):
            continue
        if isinstance(v, bool):
            safe[k] = v
        elif isinstance(v, (int, float)):
            safe[k] = v
        elif isinstance(v, str):
            safe[k] = v if len(v) <= _MAX_METADATA_VALUE_LEN else "[truncated]"
        # drop dicts, lists, bytes, and other complex types
    return safe


# ---------------------------------------------------------------------------
# Record copy helper — detaches mutable metadata from stored record
# ---------------------------------------------------------------------------


def _copy_event(record: EventRecord) -> EventRecord:
    """Return a shallow copy of record with a detached metadata dict.

    EventRecord is a frozen dataclass, but its metadata field is a plain dict
    and therefore mutable. Returning the stored object directly would allow
    callers to modify metadata after query, bypassing sanitization.

    This helper produces a new EventRecord with a copied metadata dict so
    callers cannot affect the canonical stored record.
    """
    return replace(record, metadata=dict(record.metadata))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def log_event(
    trusted_tenant_id: str,
    event_type: str,
    source: str,
    severity: str = SEVERITY_MEDIUM,
    idempotency_key: str | None = None,
    metadata: dict | None = None,
    now: int | None = None,
) -> EventWriteResult:
    """Record a high-value behavioral signal for a tenant.

    Args:
        trusted_tenant_id: Pre-validated tenant from credential/session context.
                           Must NOT be sourced from request body.
        event_type:        One of the registered high-value event type constants.
                           Unregistered types are rejected — no noise logging.
        source:            Originating component (e.g. "api.rag", "api.billing").
        severity:          "low", "medium", or "high". Default "medium".
        idempotency_key:   Required caller-supplied idempotency key. Must be a
                           non-empty string. No timestamp fallback is provided —
                           callers must supply a stable, unique key per event
                           occurrence to prevent silent deduplication of distinct
                           events that share the same tenant/type/source/second.
        metadata:          Safe key/value pairs only. Sanitized on write.
                           NEVER pass raw queries, content, tokens, or secrets here.
        now:               Unix timestamp override for tests.

    Returns:
        EventWriteResult(record, created=True) for new events.
        EventWriteResult(record, created=False) for idempotent no-ops.

    Raises:
        HTTPException 400 BEHAVIOR_TENANT_REQUIRED          — missing tenant.
        HTTPException 400 BEHAVIOR_INVALID_EVENT_TYPE       — unregistered event type.
        HTTPException 400 BEHAVIOR_EVENT_IDEMPOTENCY_REQUIRED — missing/blank key.

    Security invariants:
        - trusted_tenant_id required; missing → structured 400
        - event_type validated against registered set; noise rejected
        - idempotency_key required; timestamp fallback removed to prevent silent dedup
        - metadata sanitized: forbidden keys dropped, long values truncated
        - metadata shallow-copied: caller mutation cannot alter stored record
        - event_id is deterministic: same (tenant, event_type, idempotency_key) → same id
        - cross-tenant idempotency_key collision impossible by construction
    """
    tid = _require_tenant(trusted_tenant_id)
    etype = _require_event_type(event_type)
    ikey = _require_idempotency_key(idempotency_key)
    sev = severity if severity in _VALID_SEVERITIES else SEVERITY_MEDIUM
    src = str(source).strip() or "unknown"
    meta = _sanitize_metadata(metadata)
    ts = int(now) if now is not None else int(time.time())

    event_id = _derive_event_id(tid, etype, ikey)

    if event_id in _store:
        existing = _store[event_id]
        log.debug("behavior.idempotent tenant=%s event_id=%s", tid, event_id[:8])
        return EventWriteResult(record=_copy_event(existing), created=False)

    record = EventRecord(
        event_id=event_id,
        tenant_id=tid,
        event_type=etype,
        source=src,
        severity=sev,
        created_at=ts,
        metadata=meta,
        idempotency_key=ikey,
    )
    _store[event_id] = record
    log.debug(
        "behavior.event tenant=%s type=%s severity=%s source=%s",
        tid,
        etype,
        sev,
        src,
    )
    return EventWriteResult(record=record, created=True)


def query_events(
    trusted_tenant_id: str,
    *,
    event_type: str | None = None,
    source: str | None = None,
    severity: str | None = None,
    from_ts: int | None = None,
    to_ts: int | None = None,
) -> list[EventRecord]:
    """Query behavior events for a single trusted tenant.

    Only returns events for trusted_tenant_id. Foreign tenant events are
    never accessible — not even an empty result reveals their existence.

    Returns:
        List of EventRecord ordered by (created_at ASC, event_id ASC).
        Empty list if no matching records.
    """
    tid = _require_tenant(trusted_tenant_id)

    # Return detached copies — EventRecord is frozen but metadata is a mutable dict.
    # Returning stored references directly would allow callers to modify metadata
    # after query, bypassing sanitization on the canonical stored record.
    results = [_copy_event(r) for r in _store.values() if r.tenant_id == tid]

    if event_type is not None:
        results = [r for r in results if r.event_type == event_type]
    if source is not None:
        results = [r for r in results if r.source == source]
    if severity is not None:
        results = [r for r in results if r.severity == severity]
    if from_ts is not None:
        results = [r for r in results if r.created_at >= from_ts]
    if to_ts is not None:
        results = [r for r in results if r.created_at <= to_ts]

    results.sort(key=lambda r: (r.created_at, r.event_id))
    return results


def export_events(
    trusted_tenant_id: str,
    fmt: str = "json",
) -> str:
    """Export behavior events for a trusted tenant.

    Args:
        trusted_tenant_id: Pre-validated tenant.
        fmt:               "json" or "csv". Default "json".

    Returns:
        String in the requested format. Deterministic for same input set.
        Safe columns only; metadata excluded from flat export.

    Raises:
        HTTPException 400 BEHAVIOR_EXPORT_INVALID_FORMAT — unknown format.
    """
    tid = _require_tenant(trusted_tenant_id)

    if fmt not in _VALID_EXPORT_FORMATS:
        raise HTTPException(
            status_code=400,
            detail=api_error(
                ERR_EXPORT_INVALID_FORMAT,
                f"export format {fmt!r} is not supported",
                action=f"use one of: {', '.join(sorted(_VALID_EXPORT_FORMATS))}",
            ),
        )

    events = query_events(tid)

    _EXPORT_COLUMNS = (
        "event_id",
        "tenant_id",
        "event_type",
        "source",
        "severity",
        "created_at",
        "idempotency_key",
    )

    def _row(r: EventRecord) -> dict:
        return {c: getattr(r, c) for c in _EXPORT_COLUMNS}

    if fmt == "json":
        return json.dumps(
            [_row(r) for r in events],
            separators=(",", ":"),
            sort_keys=True,
        )

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(_EXPORT_COLUMNS))
    writer.writeheader()
    for r in events:
        writer.writerow(_row(r))
    return buf.getvalue()
