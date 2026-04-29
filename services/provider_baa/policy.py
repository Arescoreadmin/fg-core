"""
Provider BAA Enforcement Boundary.

This module is the SINGLE enforcement point for provider BAA (Business
Associate Agreement) checks. All provider routing code MUST call
enforce_provider_baa_for_route() before dispatching to any AI provider.

Design contract:
- Fail-closed on every regulated-provider path.
- DB lookup exception → deny, never allow.
- Unknown/malformed status → deny.
- No tenant_id → ValueError (programming error, not a user error).
- Audit events emitted for every decision (allow and deny).
- Audit payload never contains raw contract text, secrets, PHI, or expiry_date.

Future evolution:
  To replace the DB lookup with a policy plane (OPA, remote config, etc.),
  replace _lookup_baa_record() only. enforce_provider_baa_for_route() and
  check_provider_baa() are the stable external interface.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date
from typing import TYPE_CHECKING

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from api.security_audit import AuditEvent, EventType, Severity, get_auditor

if TYPE_CHECKING:
    from fastapi import Request

log = logging.getLogger("frostgate.provider_baa")

# ---------------------------------------------------------------------------
# Stable error codes — never change meaning once published
# ---------------------------------------------------------------------------

_REASON_NOT_REQUIRED = "PROVIDER_BAA_NOT_REQUIRED"
_REASON_ACTIVE = "PROVIDER_BAA_ACTIVE"
_REASON_REQUIRED = "PROVIDER_BAA_REQUIRED"
_REASON_MISSING = "PROVIDER_BAA_MISSING"
_REASON_EXPIRED = "PROVIDER_BAA_EXPIRED"
_REASON_REVOKED = "PROVIDER_BAA_REVOKED"
_REASON_PENDING = "PROVIDER_BAA_PENDING"
_REASON_LOOKUP_FAILED = "PROVIDER_BAA_LOOKUP_FAILED"
_REASON_STATUS_UNKNOWN = "PROVIDER_BAA_STATUS_UNKNOWN"

# ---------------------------------------------------------------------------
# Regulated providers
# ---------------------------------------------------------------------------

# Providers that may process regulated data (PHI/ePHI) and therefore require
# an active, non-expired BAA from each tenant before routing.
#
# "simulated" is not in this set — it never dispatches to an external system
# and never processes real patient data.
#
# When adding a new external AI provider, add its canonical provider_id here.
_REGULATED_PROVIDERS: frozenset[str] = frozenset(
    {
        "openai",
        "anthropic",
        "azure_openai",
        "google_vertex",
        "cohere",
        "aws_bedrock",
    }
)

_ALLOWED_STATUSES: frozenset[str] = frozenset(
    {"active", "expired", "missing", "revoked", "pending"}
)

_NON_ACTIVE_REASON: dict[str, str] = {
    "expired": _REASON_EXPIRED,
    "revoked": _REASON_REVOKED,
    "pending": _REASON_PENDING,
    "missing": _REASON_MISSING,
}

# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProviderBaaCheckResult:
    """
    Result of a BAA enforcement check.

    `allowed` is the single routing gate signal. True iff the request may
    proceed to the specified provider.

    `expiry_date` is for internal/audit logging only. It MUST NOT appear in
    user-facing error responses or external API payloads.
    """

    allowed: bool
    reason_code: str
    provider_id: str
    tenant_id: str
    baa_status: str  # canonical status from DB, or sentinel values below
    expiry_date: str | None  # ISO-8601 date string; internal use only


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _denied(
    reason_code: str,
    provider_id: str,
    tenant_id: str,
    baa_status: str,
    expiry_date: str | None = None,
) -> ProviderBaaCheckResult:
    return ProviderBaaCheckResult(
        allowed=False,
        reason_code=reason_code,
        provider_id=provider_id,
        tenant_id=tenant_id,
        baa_status=baa_status,
        expiry_date=expiry_date,
    )


def _lookup_baa_record(db: Session, tenant_id: str, provider_id: str) -> dict | None:
    """
    Fetch the BAA record for (tenant_id, provider_id).

    Returns a mapping with at least {baa_status, expiry_date} on success,
    or raises an exception on DB error (caller must treat exception as deny).
    Returns None when no record exists.
    """
    row = (
        db.execute(
            text(
                "SELECT baa_status, expiry_date "
                "FROM provider_baa_records "
                "WHERE tenant_id = :tenant_id "
                "  AND provider_id = :provider_id"
            ),
            {"tenant_id": tenant_id, "provider_id": provider_id},
        )
        .mappings()
        .first()
    )
    return dict(row) if row is not None else None


def _coerce_expiry(raw: object) -> str | None:
    """Coerce DB-returned date/string to ISO-8601 string, or None."""
    if raw is None:
        return None
    if isinstance(raw, date):
        return raw.isoformat()
    s = str(raw).strip()
    return s if s else None


def _emit_audit(
    result: ProviderBaaCheckResult,
    request: "Request | None" = None,
) -> None:
    """
    Emit a BAA enforcement audit event.

    Payload: provider_id, baa_status, enforcement_result, reason_code.
    Excluded: expiry_date, document_ref, contract text, secrets, PHI.
    """
    event_type = (
        EventType.PROVIDER_BAA_ALLOWED
        if result.allowed
        else EventType.PROVIDER_BAA_DENIED
    )

    request_id: str | None = None
    request_path: str | None = None
    request_method: str | None = None
    if request is not None:
        request_id = getattr(getattr(request, "state", None), "request_id", None)
        request_path = str(request.url.path) if request.url else None
        request_method = request.method

    get_auditor().log_event(
        AuditEvent(
            event_type=event_type,
            success=result.allowed,
            severity=Severity.INFO if result.allowed else Severity.WARNING,
            tenant_id=result.tenant_id,
            reason=result.reason_code,
            request_id=request_id,
            request_path=request_path,
            request_method=request_method,
            details={
                "provider_id": result.provider_id,
                "baa_status": result.baa_status,
                "enforcement_result": "allowed" if result.allowed else "denied",
                "reason_code": result.reason_code,
            },
        )
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def requires_baa(provider_id: str) -> bool:
    """Return True iff provider_id is a regulated provider requiring a BAA."""
    return provider_id in _REGULATED_PROVIDERS


def check_provider_baa(
    db: Session,
    *,
    tenant_id: str,
    provider_id: str,
) -> ProviderBaaCheckResult:
    """
    Check whether tenant_id holds an active BAA for provider_id.

    This function performs the lookup and evaluation only. It does NOT emit
    audit events and does NOT raise HTTPException. Use enforce_provider_baa_for_route()
    for the enforcement path.

    Enforcement rules (in order):
    1. Blank/missing tenant_id or provider_id → ValueError (programming error)
    2. Non-regulated provider → allowed immediately, no DB lookup
    3. DB exception on regulated-provider lookup → denied (LOOKUP_FAILED)
    4. No record found → denied (MISSING)
    5. Record with unknown/malformed status → denied (STATUS_UNKNOWN)
    6. Status = active, expiry_date non-null and past → denied (EXPIRED)
    7. Status = active, expiry_date null or future → allowed
    8. Any other status (expired, revoked, pending, missing) → denied

    Security invariants:
    - tenant_id is mandatory; blank or None raises before any DB access
    - Cross-tenant lookup is structurally impossible: the caller's trusted
      tenant_id is always the lookup key, never sourced from DB row content
    - DB exception on regulated path → fail-closed, never allow
    - Unknown status → fail-closed, never allow
    """
    if not tenant_id or not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError("tenant_id is required and must not be blank")
    if not provider_id or not isinstance(provider_id, str) or not provider_id.strip():
        raise ValueError("provider_id is required and must not be blank")

    tenant_id = tenant_id.strip()
    provider_id = provider_id.strip()

    if not requires_baa(provider_id):
        return ProviderBaaCheckResult(
            allowed=True,
            reason_code=_REASON_NOT_REQUIRED,
            provider_id=provider_id,
            tenant_id=tenant_id,
            baa_status="not_applicable",
            expiry_date=None,
        )

    try:
        row = _lookup_baa_record(db, tenant_id, provider_id)
    except Exception:
        log.exception(
            "provider_baa.check: DB lookup failed — failing closed",
            extra={"tenant_id": tenant_id, "provider_id": provider_id},
        )
        return _denied(_REASON_LOOKUP_FAILED, provider_id, tenant_id, "lookup_failed")

    if row is None:
        return _denied(_REASON_MISSING, provider_id, tenant_id, "missing")

    raw_status = (row.get("baa_status") or "").strip().lower()

    if raw_status not in _ALLOWED_STATUSES:
        log.warning(
            "provider_baa.check: unrecognised baa_status — failing closed",
            extra={
                "tenant_id": tenant_id,
                "provider_id": provider_id,
                "raw_status": raw_status,
            },
        )
        return _denied(
            _REASON_STATUS_UNKNOWN, provider_id, tenant_id, raw_status or "unknown"
        )

    expiry_date = _coerce_expiry(row.get("expiry_date"))

    if raw_status == "active":
        if expiry_date is not None:
            try:
                if date.fromisoformat(expiry_date) < date.today():
                    return _denied(
                        _REASON_EXPIRED,
                        provider_id,
                        tenant_id,
                        "expired",
                        expiry_date,
                    )
            except ValueError:
                log.warning(
                    "provider_baa.check: unparseable expiry_date — treating as expired",
                    extra={"tenant_id": tenant_id, "provider_id": provider_id},
                )
                return _denied(_REASON_EXPIRED, provider_id, tenant_id, "expired")

        return ProviderBaaCheckResult(
            allowed=True,
            reason_code=_REASON_ACTIVE,
            provider_id=provider_id,
            tenant_id=tenant_id,
            baa_status="active",
            expiry_date=expiry_date,
        )

    reason_code = _NON_ACTIVE_REASON.get(raw_status, _REASON_REQUIRED)
    return _denied(reason_code, provider_id, tenant_id, raw_status, expiry_date)


def enforce_provider_baa_for_route(
    db: Session,
    *,
    tenant_id: str,
    provider_id: str,
    request: "Request | None" = None,
) -> None:
    """
    Enforce BAA compliance for a provider routing decision.

    This is the ONLY call site routing code should use. It:
    1. Calls check_provider_baa() for the decision
    2. Emits an audit event (both allow and deny)
    3. Raises HTTPException(403) on denial

    Callers MUST call this before dispatching any request to an AI provider.
    Callers MUST NOT catch and suppress the 403 or retry with a different
    provider after denial — the denial is final.

    Args:
        db:          Tenant-bound DB session
        tenant_id:   Caller's trusted tenant identity (not from request body)
        provider_id: Provider being routed to
        request:     FastAPI request (optional; used for audit context only)

    Raises:
        HTTPException(403): On any BAA denial.
            detail contains: error_code (stable), message (safe), provider_id.
            detail NEVER contains: expiry_date, document_ref, contract text,
            secrets, PHI, or internal stack traces.
        ValueError: On blank/missing tenant_id or provider_id.
    """
    result = check_provider_baa(db, tenant_id=tenant_id, provider_id=provider_id)
    _emit_audit(result, request=request)

    if not result.allowed:
        log.warning(
            "provider_baa.enforce: routing denied",
            extra={
                "tenant_id": result.tenant_id,
                "provider_id": result.provider_id,
                "reason_code": result.reason_code,
                "baa_status": result.baa_status,
            },
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": result.reason_code,
                "message": "provider routing denied by BAA enforcement policy",
                "provider_id": result.provider_id,
            },
        )
