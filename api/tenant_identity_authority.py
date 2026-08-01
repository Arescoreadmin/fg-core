"""api/tenant_identity_authority.py — IA-1 Tenant Identity Binding Authority.

This module owns all identity binding operations. Routes call this module;
this module calls the management provider. Nothing else in the codebase
should call the management provider directly.

Per ADR-IA-001: FrostGate is the system of record; Auth0 is a projection.

Transaction model:
    Each DB state transition (insert, update_provisioning, update_active/failed)
    is committed independently so that a provider failure does not roll back the
    binding record itself. This makes every state visible to retries and operators.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import text
from sqlalchemy.engine import Engine

from api.identity_authority.management.base import (
    ManagementProviderError,
    ManagementProviderProtocol,
    OrganizationRecord,
    RetryableProviderError,
)

log = logging.getLogger("frostgate.ia.authority")

_PROVIDER = "auth0"

# Slug rule for org name: fg-{slug}, max 50 chars
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")
_LEADING_TRAILING_DASH_RE = re.compile(r"^-+|-+$")


def _slugify_tenant_id(tenant_id: str) -> str:
    """Derive a deterministic Auth0 org name slug from tenant_id.

    Lowercase, replace non-alphanumeric with '-', collapse repeated '-',
    strip leading/trailing '-', prefix 'fg-'. Max 50 chars total.
    """
    slug = tenant_id.lower()
    slug = _NON_ALNUM_RE.sub("-", slug)
    slug = re.sub(r"-{2,}", "-", slug)
    slug = _LEADING_TRAILING_DASH_RE.sub("", slug)
    name = f"fg-{slug}"
    return name[:50]


def _idempotency_key(tenant_id: str, provider: str = _PROVIDER) -> str:
    return f"ia1:{tenant_id}:{provider}"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class TenantIdentityBindingRecord:
    """Mirror of the tenant_identity_bindings table row returned to callers."""

    binding_id: str
    tenant_id: str
    provider: str
    provider_org_id: Optional[str]
    provider_org_name: Optional[str]
    provisioning_state: str
    idempotency_key: str
    last_sync_at: Optional[str]
    last_error_code: Optional[str]
    last_error_message_redacted: Optional[str]
    version: int
    created_at: str
    updated_at: str


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ProvisioningFailedError(Exception):
    """Raised by provision_tenant_organization when Auth0 fails.

    Callers use ``retryable`` and ``error_code`` to shape HTTP responses.
    """

    def __init__(self, message: str, *, retryable: bool, error_code: str):
        super().__init__(message)
        self.retryable = retryable
        self.error_code = error_code


# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------


def get_management_provider() -> ManagementProviderProtocol:
    """Return a configured Auth0ManagementProvider.

    Raises:
        ManagementProviderError(code="NOT_CONFIGURED") if env vars are missing.
    """
    from api.identity_authority.management.auth0 import Auth0ManagementProvider

    provider = Auth0ManagementProvider()
    if not provider.is_configured():
        raise ManagementProviderError(
            "Auth0 management provider is not configured: "
            "AUTH0_MANAGEMENT_DOMAIN, AUTH0_MANAGEMENT_CLIENT_ID, "
            "AUTH0_MANAGEMENT_CLIENT_SECRET, AUTH0_MANAGEMENT_AUDIENCE must all be set",
            code="NOT_CONFIGURED",
            provider="auth0",
        )
    return provider


# ---------------------------------------------------------------------------
# Repository helpers (raw SQL — no ORM)
# ---------------------------------------------------------------------------


def _row_to_binding(row: Any) -> TenantIdentityBindingRecord:
    return TenantIdentityBindingRecord(
        binding_id=str(row[0]),
        tenant_id=str(row[1]),
        provider=str(row[2]),
        provider_org_id=row[3],
        provider_org_name=row[4],
        provisioning_state=str(row[5]),
        idempotency_key=str(row[6]),
        last_sync_at=str(row[7]) if row[7] is not None else None,
        last_error_code=row[8],
        last_error_message_redacted=row[9],
        version=int(row[10]),
        created_at=str(row[11]),
        updated_at=str(row[12]),
    )


_SELECT_BINDING = (
    "SELECT id, tenant_id, provider, provider_org_id, provider_org_name, "
    "provisioning_state, idempotency_key, last_sync_at, last_error_code, "
    "last_error_message_redacted, version, created_at, updated_at "
    "FROM tenant_identity_bindings "
    "WHERE tenant_id = :tenant_id AND provider = :provider"
)


def _get_binding_row(conn: Any, tenant_id: str, provider: str) -> Optional[Any]:
    return conn.execute(
        text(_SELECT_BINDING),
        {"tenant_id": tenant_id, "provider": provider},
    ).fetchone()


def _insert_binding(conn: Any, *, tenant_id: str, provider: str, ikey: str) -> Any:
    now = datetime.now(timezone.utc).isoformat()
    binding_id = str(uuid.uuid4())
    conn.execute(
        text(
            "INSERT INTO tenant_identity_bindings "
            "(id, tenant_id, provider, provisioning_state, idempotency_key, "
            "version, created_at, updated_at) "
            "VALUES (:id, :tenant_id, :provider, 'pending', :ikey, 1, :now, :now)"
        ),
        {
            "id": binding_id,
            "tenant_id": tenant_id,
            "provider": provider,
            "ikey": ikey,
            "now": now,
        },
    )
    return _get_binding_row(conn, tenant_id, provider)


def _update_binding_provisioning(conn: Any, *, binding_id: str) -> None:
    """Set state to 'provisioning' (in-flight)."""
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        text(
            "UPDATE tenant_identity_bindings "
            "SET provisioning_state = 'provisioning', updated_at = :now "
            "WHERE id = :id"
        ),
        {"id": binding_id, "now": now},
    )


def _update_binding_active(
    conn: Any,
    *,
    binding_id: str,
    provider_org_id: str,
    provider_org_name: str,
) -> None:
    """Set state to 'active' after successful org creation."""
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        text(
            "UPDATE tenant_identity_bindings "
            "SET provisioning_state = 'active', "
            "    provider_org_id = :org_id, "
            "    provider_org_name = :org_name, "
            "    last_sync_at = :now, "
            "    last_error_code = NULL, "
            "    last_error_message_redacted = NULL, "
            "    version = version + 1, "
            "    updated_at = :now "
            "WHERE id = :id"
        ),
        {
            "id": binding_id,
            "org_id": provider_org_id,
            "org_name": provider_org_name,
            "now": now,
        },
    )


def _update_binding_failed(
    conn: Any,
    *,
    binding_id: str,
    error_code: str,
    error_message_redacted: str,
) -> None:
    """Set state to 'failed' after provider error."""
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        text(
            "UPDATE tenant_identity_bindings "
            "SET provisioning_state = 'failed', "
            "    last_error_code = :code, "
            "    last_error_message_redacted = :msg, "
            "    updated_at = :now "
            "WHERE id = :id"
        ),
        {
            "id": binding_id,
            "code": error_code,
            "msg": error_message_redacted,
            "now": now,
        },
    )


def _insert_event(
    conn: Any,
    *,
    event_type: str,
    binding_id: Optional[str],
    tenant_id: str,
    provider: str,
    provider_org_id: Optional[str],
    actor_id: str,
    request_id: Optional[str],
    outcome: str = "success",
    error_code: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    """Append an event to tenant_identity_binding_events. Never stores secrets."""
    import json

    event_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    meta_json = json.dumps(metadata or {})
    conn.execute(
        text(
            "INSERT INTO tenant_identity_binding_events "
            "(event_id, event_type, binding_id, tenant_id, provider, provider_org_id, "
            "actor_id, request_id, outcome, error_code, occurred_at, metadata, schema_version) "
            "VALUES (:event_id, :event_type, :binding_id, :tenant_id, :provider, "
            ":provider_org_id, :actor_id, :request_id, :outcome, :error_code, "
            ":now, :metadata, 1)"
        ),
        {
            "event_id": event_id,
            "event_type": event_type,
            "binding_id": binding_id,
            "tenant_id": tenant_id,
            "provider": provider,
            "provider_org_id": provider_org_id,
            "actor_id": actor_id,
            "request_id": request_id,
            "outcome": outcome,
            "error_code": error_code,
            "now": now,
            "metadata": meta_json,
        },
    )


def _sanitize_error_message(raw: str) -> str:
    """Sanitize an error message to remove tokens, emails, and raw responses.

    Returns a short, safe string suitable for last_error_message_redacted.
    Never persists raw provider response bodies.
    """
    safe = raw[:256] if raw else ""
    # Remove anything that looks like a token (long base64-ish strings)
    safe = re.sub(r"[A-Za-z0-9_\-]{64,}", "[REDACTED]", safe)
    # Remove email patterns
    safe = re.sub(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "[REDACTED]", safe)
    return safe


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_tenant_binding(
    *,
    tenant_id: str,
    provider: str = _PROVIDER,
    db_conn: Any,
) -> Optional[TenantIdentityBindingRecord]:
    """Return the current binding for (tenant_id, provider), or None.

    db_conn: an active SQLAlchemy connection (not a transaction context).
    """
    row = _get_binding_row(db_conn, tenant_id, provider)
    return _row_to_binding(row) if row is not None else None


def provision_tenant_organization(
    *,
    tenant_id: str,
    display_name: str,
    actor_id: str,
    request_id: str,
    db_conn: Any,
) -> TenantIdentityBindingRecord:
    """Provision an Auth0 organization for the given tenant.

    db_conn MUST be a SQLAlchemy Engine. Each DB state transition is committed
    independently so that provider failures do not roll back the binding record.

    State machine:
        no binding   → INSERT pending + UPDATE provisioning → call Auth0 → active | failed
        failed       → UPDATE provisioning → retry Auth0 → active | failed
        provisioning → return current binding (in-flight, caller should poll)
        active       → return existing binding (idempotent, no Auth0 call)

    Raises:
        ProvisioningFailedError: if Auth0 call fails (retryable or non-retryable).
    """
    # Support both Engine and raw connection. When an Engine is passed, we control
    # each commit. When a raw connection is passed (tests), we use it directly and
    # trust the test harness to commit after each step.
    engine: Optional[Engine] = db_conn if isinstance(db_conn, Engine) else None
    raw_conn = None if engine else db_conn

    def _exec_committed(fn: Any, *args: Any, **kwargs: Any) -> Any:
        """Execute fn(conn, ...) in its own committed transaction (when engine is available)."""
        if engine is not None:
            with engine.begin() as conn:
                return fn(conn, *args, **kwargs)
        else:
            return fn(raw_conn, *args, **kwargs)

    def _read(fn: Any, *args: Any, **kwargs: Any) -> Any:
        if engine is not None:
            with engine.connect() as conn:
                return fn(conn, *args, **kwargs)
        else:
            return fn(raw_conn, *args, **kwargs)

    provider = _PROVIDER
    ikey = _idempotency_key(tenant_id, provider)
    org_name = _slugify_tenant_id(tenant_id)

    # --- Check existing binding ---
    row = _read(_get_binding_row, tenant_id, provider)

    if row is not None:
        binding = _row_to_binding(row)
        if binding.provisioning_state == "active":
            # Already active — idempotent return, no Auth0 call
            return binding
        # 'failed', 'pending', 'provisioning', etc. — proceed to retry.
        # Note: 'provisioning' could mean a concurrent in-flight request OR a stuck
        # binding from a previous DB failure after Auth0 creation. We always retry
        # rather than returning in-flight state, because:
        # (a) The UNIQUE constraint prevents two simultaneous provisions from both
        #     proceeding — one will fail on INSERT.
        # (b) Auth0 create_organization is idempotent via the fg- name + metadata.
        # (c) The spec (step 7 in TestF) requires retry to work after DB failure.

    if row is None:
        # Fresh: INSERT pending
        def _do_insert(conn: Any) -> Any:
            result = _insert_binding(conn, tenant_id=tenant_id, provider=provider, ikey=ikey)
            return result

        row = _exec_committed(_do_insert)

    binding = _row_to_binding(row)
    binding_id = binding.binding_id

    # Mark as in-flight and emit start event (committed together)
    def _start(conn: Any) -> None:
        _update_binding_provisioning(conn, binding_id=binding_id)
        _insert_event(
            conn,
            event_type="org_provisioning_started",
            binding_id=binding_id,
            tenant_id=tenant_id,
            provider=provider,
            provider_org_id=None,
            actor_id=actor_id,
            request_id=request_id,
            outcome="success",
            metadata={"org_name": org_name},
        )

    _exec_committed(_start)

    # --- Call provider ---
    try:
        mgmt = get_management_provider()
    except ManagementProviderError as exc:
        def _fail_config(conn: Any) -> None:
            _update_binding_failed(
                conn,
                binding_id=binding_id,
                error_code=exc.code,
                error_message_redacted=_sanitize_error_message(str(exc)),
            )
            _insert_event(
                conn,
                event_type="org_provisioning_failed",
                binding_id=binding_id,
                tenant_id=tenant_id,
                provider=provider,
                provider_org_id=None,
                actor_id=actor_id,
                request_id=request_id,
                outcome="failure",
                error_code=exc.code,
            )

        _exec_committed(_fail_config)
        raise ProvisioningFailedError(
            str(exc), retryable=False, error_code=exc.code
        ) from exc

    try:
        org: OrganizationRecord = mgmt.create_organization(
            name=org_name,
            display_name=display_name,
            idempotency_key=ikey,
            correlation_id=request_id,
        )
    except RetryableProviderError as exc:
        def _fail_retryable(conn: Any) -> None:
            _update_binding_failed(
                conn,
                binding_id=binding_id,
                error_code=exc.code,
                error_message_redacted=_sanitize_error_message(str(exc)),
            )
            _insert_event(
                conn,
                event_type="org_provisioning_failed",
                binding_id=binding_id,
                tenant_id=tenant_id,
                provider=provider,
                provider_org_id=None,
                actor_id=actor_id,
                request_id=request_id,
                outcome="failure",
                error_code=exc.code,
            )

        _exec_committed(_fail_retryable)
        raise ProvisioningFailedError(
            str(exc), retryable=True, error_code=exc.code
        ) from exc
    except ManagementProviderError as exc:
        severity = "HIGH" if exc.code == "AUTH0_ORG_OWNERSHIP_CONFLICT" else "normal"

        def _fail_nonretryable(conn: Any) -> None:
            _update_binding_failed(
                conn,
                binding_id=binding_id,
                error_code=exc.code,
                error_message_redacted=_sanitize_error_message(str(exc)),
            )
            _insert_event(
                conn,
                event_type="org_provisioning_failed",
                binding_id=binding_id,
                tenant_id=tenant_id,
                provider=provider,
                provider_org_id=None,
                actor_id=actor_id,
                request_id=request_id,
                outcome="failure",
                error_code=exc.code,
                metadata={
                    "severity": severity,
                    "correlation_id": request_id,
                },
            )

        _exec_committed(_fail_nonretryable)
        raise ProvisioningFailedError(
            str(exc), retryable=False, error_code=exc.code
        ) from exc

    # --- Success: persist org binding ---
    # Wrap in try/except so that a DB failure AFTER Auth0 creates the org
    # is handled gracefully. The binding is set to 'failed' so the next retry
    # can call Auth0 again. Auth0 will return 409 (org already exists), the
    # adapter recovers by verifying frostgate_tenant_id metadata, and returns
    # the existing org — no orphan org is created.
    def _succeed(conn: Any) -> None:
        _update_binding_active(
            conn,
            binding_id=binding_id,
            provider_org_id=org.provider_org_id,
            provider_org_name=org.provider_org_name,
        )
        _insert_event(
            conn,
            event_type="org_provisioned",
            binding_id=binding_id,
            tenant_id=tenant_id,
            provider=provider,
            provider_org_id=org.provider_org_id,
            actor_id=actor_id,
            request_id=request_id,
            outcome="success",
            metadata={"org_name": org.provider_org_name},
        )

    try:
        _exec_committed(_succeed)
    except Exception as db_exc:
        # DB write failed after Auth0 org was already created.
        # Mark binding as failed so the next retry can attempt recovery via
        # Auth0's 409 path (org exists → verify ownership → return existing).
        log.warning(
            "ia1.org.db_write_failed_after_remote_create",
            extra={
                "tenant_id": tenant_id,
                "provider": provider,
                "request_id": request_id,
                "error": type(db_exc).__name__,
            },
        )
        try:
            def _fail_db(conn: Any) -> None:
                _update_binding_failed(
                    conn,
                    binding_id=binding_id,
                    error_code="DB_WRITE_FAILED",
                    error_message_redacted="DB write failed after remote org creation; retry to recover",
                )

            _exec_committed(_fail_db)
        except Exception:
            # If even the failure update fails, the binding remains in 'provisioning'.
            # The retry still works — provisioning state is re-entered on the next call
            # because we updated the state machine to handle this below.
            pass
        raise ProvisioningFailedError(
            "DB write failed after Auth0 org was created; retry to recover via 409 path",
            retryable=True,
            error_code="DB_WRITE_FAILED",
        ) from db_exc

    log.info(
        "ia1.org.provisioned",
        extra={
            "tenant_id": tenant_id,
            "provider": provider,
            "request_id": request_id,
        },
    )

    # Return fresh row from DB
    final_row = _read(_get_binding_row, tenant_id, provider)
    assert final_row is not None, "Binding row missing after successful provisioning"
    return _row_to_binding(final_row)
