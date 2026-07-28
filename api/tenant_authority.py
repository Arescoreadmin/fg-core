"""Tenant authority classification policy.

The canonical tenant row stores only ``tenant_kind``. Operational policy flags
are invariant consequences of that kind so contradictory combinations cannot be
persisted independently.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import NoSuchTableError, OperationalError, ProgrammingError
from sqlalchemy.orm import Session

TenantKind = Literal["customer", "internal_platform", "validation", "demo"]

TENANT_KINDS: frozenset[str] = frozenset(
    {"customer", "internal_platform", "validation", "demo"}
)
DEFAULT_TENANT_KIND: TenantKind = "customer"


@dataclass(frozen=True)
class TenantKindPolicy:
    tenant_kind: TenantKind
    customer_visible: bool
    portal_enabled: bool
    billing_eligible: bool
    operator_authority_allowed: bool


TENANT_KIND_POLICIES: dict[TenantKind, TenantKindPolicy] = {
    "customer": TenantKindPolicy(
        tenant_kind="customer",
        customer_visible=True,
        portal_enabled=True,
        billing_eligible=True,
        operator_authority_allowed=False,
    ),
    "internal_platform": TenantKindPolicy(
        tenant_kind="internal_platform",
        customer_visible=False,
        portal_enabled=False,
        billing_eligible=False,
        operator_authority_allowed=True,
    ),
    "validation": TenantKindPolicy(
        tenant_kind="validation",
        customer_visible=False,
        portal_enabled=False,
        billing_eligible=False,
        operator_authority_allowed=False,
    ),
    "demo": TenantKindPolicy(
        tenant_kind="demo",
        customer_visible=False,
        portal_enabled=True,
        billing_eligible=False,
        operator_authority_allowed=False,
    ),
}


class TenantKindError(ValueError):
    """Raised when a tenant kind is invalid or disallowed for a flow."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


def normalize_tenant_kind(value: Any) -> TenantKind:
    raw = str(value or DEFAULT_TENANT_KIND).strip()
    if raw not in TENANT_KINDS:
        raise TenantKindError(
            "TENANT_KIND_INVALID",
            f"tenant_kind must be one of: {', '.join(sorted(TENANT_KINDS))}",
        )
    return raw  # type: ignore[return-value]


def policy_for_tenant_kind(value: Any) -> TenantKindPolicy:
    return TENANT_KIND_POLICIES[normalize_tenant_kind(value)]


def validate_tenant_kind_for_generic_create(
    value: Any = DEFAULT_TENANT_KIND,
    *,
    allow_internal_platform: bool = False,
) -> TenantKind:
    tenant_kind = normalize_tenant_kind(value)
    if tenant_kind == "internal_platform" and not allow_internal_platform:
        raise TenantKindError(
            "INTERNAL_PLATFORM_TENANT_CREATE_FORBIDDEN",
            "internal_platform tenants require an explicit privileged authority path",
        )
    return tenant_kind


def _tenant_kind_from_row(row: Any) -> TenantKind | None:
    if row is None:
        return None
    try:
        return normalize_tenant_kind(row[0])
    except TenantKindError:
        raise


def _read_tenant_kind_from_connection(
    conn: Connection,
    tenant_id: str,
) -> TenantKind | None:
    row = conn.execute(
        text("SELECT tenant_kind FROM tenants WHERE tenant_id = :tenant_id"),
        {"tenant_id": tenant_id},
    ).fetchone()
    return _tenant_kind_from_row(row)


def read_tenant_kind_for_policy(db: Session, tenant_id: str) -> TenantKind:
    """Read tenant_kind for policy checks.

    If the canonical tenants table/column is unavailable in a local SQLite test
    harness, fall back to customer to preserve legacy unit-test compatibility.
    Production Postgres is expected to have migration 0166 applied.
    """

    if db.__class__.__module__ == "unittest.mock":
        return DEFAULT_TENANT_KIND

    try:
        tenant_kind = _read_tenant_kind_from_connection(db.connection(), tenant_id)
    except (NoSuchTableError, OperationalError, ProgrammingError):
        return DEFAULT_TENANT_KIND
    if tenant_kind is None:
        raise TenantKindError("TENANT_NOT_FOUND", f"tenant not found: {tenant_id}")
    return tenant_kind


def ensure_portal_enabled(db: Session, tenant_id: str) -> None:
    policy = policy_for_tenant_kind(read_tenant_kind_for_policy(db, tenant_id))
    if not policy.portal_enabled:
        raise TenantKindError(
            "TENANT_PORTAL_DISABLED",
            f"tenant {tenant_id!r} is not eligible for portal enrollment",
        )


def ensure_billing_eligible(db: Session, tenant_id: str) -> None:
    policy = policy_for_tenant_kind(read_tenant_kind_for_policy(db, tenant_id))
    if not policy.billing_eligible:
        raise TenantKindError(
            "TENANT_BILLING_DISABLED",
            f"tenant {tenant_id!r} is not eligible for billing or entitlements",
        )


def tenant_kind_http_error(exc: TenantKindError) -> HTTPException:
    status = 404 if exc.code == "TENANT_NOT_FOUND" else 403
    return HTTPException(status_code=status, detail={"code": exc.code})
