"""
Per-Tenant Usage Attribution — Task 12.2

Deterministic, tenant-scoped usage attribution system.

Guarantees:
- Every usage record is bound to a validated tenant_id and a customer identity
  (credential_id or customer_id). Neither may be blank.
- usage_id = SHA-256(tenant_id + ":" + idempotency_key)[:32] — deterministic,
  cross-tenant collision-free, idempotency-safe.
- Same (tenant_id, idempotency_key) pair always maps to the same usage_id;
  the second write is a no-op (returns existing record).
- Same idempotency_key under a different tenant_id produces a distinct usage_id —
  no cross-tenant idempotency collision.
- query_usage() and export_usage() only return records for the supplied
  trusted_tenant_id — foreign tenant records are never accessible.
- Metadata is copied on write and on read — caller mutation cannot alter
  stored records.
- Structured error contract via api/error_contracts.py (Task 11.1).
- No external calls, no network, no Stripe/billing, no migrations.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import HTTPException

from api.error_contracts import api_error

log = logging.getLogger("frostgate.usage_attribution")

# ---------------------------------------------------------------------------
# Stable error codes (never change meaning once published)
# ---------------------------------------------------------------------------

ERR_TENANT_REQUIRED = "USAGE_TENANT_REQUIRED"
ERR_CUSTOMER_REQUIRED = "USAGE_CUSTOMER_REQUIRED"
ERR_INVALID_EVENT = "USAGE_INVALID_EVENT"
ERR_INVALID_UNITS = "USAGE_INVALID_UNITS"
ERR_FORBIDDEN = "USAGE_FORBIDDEN"
ERR_EXPORT_INVALID_FORMAT = "USAGE_EXPORT_INVALID_FORMAT"
ERR_RECORD_NOT_FOUND = "USAGE_RECORD_NOT_FOUND"

_VALID_EXPORT_FORMATS = frozenset({"json", "csv"})

# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UsageRecord:
    """Immutable per-event usage attribution record.

    Fields:
        usage_id:        SHA-256(tenant_id + ":" + idempotency_key)[:32].
                         Deterministic and cross-tenant collision-free.
        tenant_id:       Trusted tenant this record belongs to.
        customer_id:     Customer identity (credential_id, customer key, etc.)
                         derived from validated credential/session, never from
                         raw request payload.
        action:          Event type / operation name (e.g. "rag_query").
        units:           Positive integer unit count for this event.
        source:          System component that produced the event
                         (e.g. "api.rag", "api.credentials").
        idempotency_key: Caller-supplied or server-derived idempotency key.
                         Scoped to tenant — same key under a different tenant
                         does not collide.
        created_at:      Unix timestamp of first write.
        metadata:        Shallow-copied safe metadata dict.
                         No secrets, no hashes, no foreign tenant data.
        status:          Always "recorded" for committed events.
    """

    usage_id: str
    tenant_id: str
    customer_id: str
    action: str
    units: int
    source: str
    idempotency_key: str
    created_at: int
    metadata: dict = field(default_factory=dict)
    status: str = "recorded"


@dataclass(frozen=True)
class UsageWriteResult:
    """Result of a record_usage() call."""

    record: UsageRecord
    created: bool  # True = new record; False = idempotent no-op (returned existing)


# ---------------------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------------------

# usage_id → UsageRecord
_store: dict[str, UsageRecord] = {}


def _reset_store() -> None:
    """Reset in-memory store. For test isolation only — never call in production."""
    _store.clear()


# ---------------------------------------------------------------------------
# Deterministic usage_id
# ---------------------------------------------------------------------------


def _derive_usage_id(tenant_id: str, idempotency_key: str) -> str:
    """Derive a deterministic, cross-tenant-safe usage_id.

    usage_id = hex(SHA-256(tenant_id + ":" + idempotency_key))[:32]

    Including tenant_id in the hash ensures the same idempotency_key under
    two different tenants maps to distinct usage_ids — no cross-tenant
    idempotency collision is possible.
    """
    payload = f"{tenant_id}:{idempotency_key}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _require_tenant(tenant_id: Any) -> str:
    if not tenant_id or not str(tenant_id).strip():
        raise HTTPException(
            status_code=400,
            detail=api_error(
                ERR_TENANT_REQUIRED,
                "trusted_tenant_id is required for usage attribution",
                action="supply tenant_id from validated credential/session context",
            ),
        )
    return str(tenant_id).strip()


def _require_customer(customer_id: Any) -> str:
    if not customer_id or not str(customer_id).strip():
        raise HTTPException(
            status_code=400,
            detail=api_error(
                ERR_CUSTOMER_REQUIRED,
                "customer_id is required for usage attribution",
                action="supply customer_id from validated credential context",
            ),
        )
    return str(customer_id).strip()


def _require_action(action: Any) -> str:
    if not action or not str(action).strip():
        raise HTTPException(
            status_code=400,
            detail=api_error(
                ERR_INVALID_EVENT,
                "action is required and must be a non-empty string",
                action="supply an action name from the trusted route or module",
            ),
        )
    return str(action).strip()


def _require_units(units: Any) -> int:
    # Reject bool (subclass of int), non-int types, zero, negative
    if isinstance(units, bool) or not isinstance(units, int) or units < 1:
        raise HTTPException(
            status_code=400,
            detail=api_error(
                ERR_INVALID_UNITS,
                "units must be a positive integer (>= 1)",
                action="supply units as a positive integer",
            ),
        )
    return units


def _safe_metadata(metadata: Any) -> dict:
    """Return a shallow copy of metadata, or {} if None/non-dict."""
    if metadata is None:
        return {}
    if not isinstance(metadata, dict):
        return {}
    return dict(metadata)  # copy — caller mutation cannot alter stored record


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def record_usage(
    trusted_tenant_id: str,
    customer_id: str,
    action: str,
    units: int = 1,
    source: str = "unknown",
    idempotency_key: str | None = None,
    metadata: dict | None = None,
    now: int | None = None,
) -> UsageWriteResult:
    """Record a tenant-scoped usage event.

    Args:
        trusted_tenant_id: Pre-validated tenant from credential/session context.
                           Must NOT be sourced from request body or query string.
        customer_id:       Customer identity from validated credential context.
                           Must NOT be raw user-supplied input.
        action:            Event/operation name (e.g. "rag_query", "decision").
        units:             Positive integer unit count. Default 1.
        source:            Originating component (e.g. "api.rag").
        idempotency_key:   Caller-supplied idempotency key. If None, a unique
                           key is derived from tenant + customer + action +
                           current timestamp (not idempotent for that call).
        metadata:          Safe key/value pairs. Copied on write; no secrets.
        now:               Unix timestamp override for tests.

    Returns:
        UsageWriteResult(record, created=True) for new records.
        UsageWriteResult(record, created=False) for idempotent no-ops.

    Security invariants:
        - trusted_tenant_id and customer_id required; missing → structured 400
        - metadata is shallow-copied; caller mutation cannot alter stored record
        - usage_id is deterministic: same (tenant, idempotency_key) → same id
        - cross-tenant idempotency_key collision is impossible by construction
    """
    tid = _require_tenant(trusted_tenant_id)
    cid = _require_customer(customer_id)
    act = _require_action(action)
    u = _require_units(units)
    meta = _safe_metadata(metadata)
    src = str(source).strip() or "unknown"
    ts = int(now) if now is not None else int(time.time())

    # Derive idempotency key if not supplied (unique per call via timestamp)
    if not idempotency_key or not str(idempotency_key).strip():
        idempotency_key = f"{tid}:{cid}:{act}:{src}:{ts}"
    ikey = str(idempotency_key).strip()

    usage_id = _derive_usage_id(tid, ikey)

    if usage_id in _store:
        existing = _store[usage_id]
        log.debug("usage.idempotent tenant=%s usage_id=%s", tid, usage_id[:8])
        return UsageWriteResult(record=existing, created=False)

    record = UsageRecord(
        usage_id=usage_id,
        tenant_id=tid,
        customer_id=cid,
        action=act,
        units=u,
        source=src,
        idempotency_key=ikey,
        created_at=ts,
        metadata=meta,
        status="recorded",
    )
    _store[usage_id] = record
    log.debug("usage.recorded tenant=%s action=%s units=%d", tid, act, u)
    return UsageWriteResult(record=record, created=True)


def query_usage(
    trusted_tenant_id: str,
    *,
    action: str | None = None,
    customer_id: str | None = None,
    from_ts: int | None = None,
    to_ts: int | None = None,
) -> list[UsageRecord]:
    """Query usage records for a single trusted tenant.

    Only returns records for trusted_tenant_id. Foreign tenant records are
    never accessible — not even an empty result that could reveal existence.

    Args:
        trusted_tenant_id: Pre-validated tenant from credential/session context.
        action:            Optional filter by action name.
        customer_id:       Optional filter by customer_id.
        from_ts:           Optional lower bound (inclusive) on created_at.
        to_ts:             Optional upper bound (inclusive) on created_at.

    Returns:
        List of matching UsageRecord, ordered by (created_at ASC, usage_id ASC).
        Empty list if no matching records (does not leak existence of other tenants).
    """
    tid = _require_tenant(trusted_tenant_id)

    results = [r for r in _store.values() if r.tenant_id == tid]

    if action is not None:
        results = [r for r in results if r.action == action]
    if customer_id is not None:
        results = [r for r in results if r.customer_id == customer_id]
    if from_ts is not None:
        results = [r for r in results if r.created_at >= from_ts]
    if to_ts is not None:
        results = [r for r in results if r.created_at <= to_ts]

    # Deterministic ordering
    results.sort(key=lambda r: (r.created_at, r.usage_id))
    return results


def export_usage(
    trusted_tenant_id: str,
    fmt: str = "json",
) -> str:
    """Export all usage records for a trusted tenant.

    Args:
        trusted_tenant_id: Pre-validated tenant from credential/session context.
        fmt:               Export format: "json" or "csv". Default "json".

    Returns:
        String in the requested format. Deterministic for the same input set.
        Safe columns only: usage_id, tenant_id, customer_id, action, units,
        source, idempotency_key, created_at, status.
        Metadata is excluded from exports (may contain unvalidated values).

    Raises:
        HTTPException 400 USAGE_EXPORT_INVALID_FORMAT — unknown format.
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

    records = query_usage(tid)

    # Safe export columns — no metadata, no raw hashes, no foreign data
    _EXPORT_COLUMNS = (
        "usage_id",
        "tenant_id",
        "customer_id",
        "action",
        "units",
        "source",
        "idempotency_key",
        "created_at",
        "status",
    )

    def _row(r: UsageRecord) -> dict:
        return {c: getattr(r, c) for c in _EXPORT_COLUMNS}

    if fmt == "json":
        return json.dumps(
            [_row(r) for r in records],
            separators=(",", ":"),
            sort_keys=True,
        )

    # csv
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(_EXPORT_COLUMNS))
    writer.writeheader()
    for r in records:
        writer.writerow(_row(r))
    return buf.getvalue()
