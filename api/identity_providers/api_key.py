"""API key identity provider — adapts the existing key infrastructure (H14).

Reads the authenticated key context from request.state.auth (populated by
the auth middleware and require_scopes()) and resolves the API key's RBAC
role via tenant_rbac.py.

Legacy role names from the original 5-role model are mapped to the new
enterprise role names so that existing key assignments continue to work.

Backward-compat fallback: keys minted before RBAC roles were introduced have
scopes (governance:write, governance:read, governance:qa_approve) but no DB role.
_permissions_from_legacy_scopes() maps those scopes to a capability set so that
existing service keys continue to function during the migration period.
"""

from __future__ import annotations

import logging
from typing import Optional, Tuple

from fastapi import Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from api.actor_context import ActorContext, roles_to_permissions

log = logging.getLogger("frostgate.identity.api_key")

# Imported lazily inside _resolve_psp_fields to avoid circular imports at
# module load time.  The constant value is duplicated here so the check is
# free (no import) on every non-PSP request.
_PSP_CREDENTIAL_SLOT = "platform-service-principal:v1"


def _resolve_psp_fields(
    tenant_id: str,
) -> Tuple[Optional[str], Optional[str]]:
    """Return (service_principal_id, authority_tenant_id) for the canonical PSP.

    Binding by BOTH credential_slot AND authority_tenant_id is intentional:
    the slot name alone is not sufficient to establish PSP identity.  A key
    issued under a different authority tenant with the same slot string must
    not resolve as the canonical platform service principal.

    The partial unique index uq_psp_authority_kind_active guarantees at most
    one non-revoked PSP per authority+kind combination, so LIMIT 1 is
    defensive (the DB cannot return duplicates).  lifecycle_state='active'
    further narrows to excludes suspended/revoked PSPs, which should not
    receive attribution.

    Fail-open: returns (None, None) on ANY failure — DB unavailable, query
    error, unexpected schema.  Attribution gaps must never invalidate an
    otherwise correctly validated API key.  Callers relying on non-None
    service_principal_id (e.g. require_psp_actor) will correctly deny such
    requests via their own fail-closed path.
    """
    try:
        from api.db import get_engine as _get_engine

        engine = _get_engine()
        with engine.connect() as conn:
            if engine.dialect.name == "postgresql":
                conn.execute(
                    text("SELECT pg_catalog.set_config('app.tenant_id', :tid, true)"),
                    {"tid": tenant_id},
                )
            row = conn.execute(
                text(
                    "SELECT id, authority_tenant_id"
                    " FROM platform_service_principals"
                    " WHERE credential_slot = :slot"
                    "   AND authority_tenant_id = :tid"
                    "   AND lifecycle_state = 'active'"
                    " LIMIT 1"
                ),
                {"slot": _PSP_CREDENTIAL_SLOT, "tid": tenant_id},
            ).fetchone()
        if row:
            return str(row[0]), str(row[1])
    except Exception as exc:
        log.warning(
            "psp_resolve.failed",
            extra={"tenant_id": tenant_id, "exc": str(exc)},
        )
    return None, None


def _emit_psp_auth_event(
    service_principal_id: str,
    authority_tenant_id: str,
    request_id: Optional[str],
) -> None:
    """Emit per-request authentication_success to platform_service_principal_events.

    Audit design intent: this is REQUEST authentication — one event per
    incoming API request authenticated as the PSP.  It is distinct from
    LIFECYCLE authentication (authenticate_service_principal(), which is called
    explicitly when a route needs to verify PSP state and emits its own event).
    Both paths use event_type='authentication_success'; request_id provides
    per-request correlation.

    Retention note: this table is append-only with no automated archival.
    Event volume scales with PSP request rate.  Operators should define a
    retention policy (e.g. pg_partman rolling partition or periodic archival)
    before deploying workloads that make PSP-authenticated requests at high
    frequency.  The ix_pspe_principal_occurred index covers the primary query
    pattern (audit queries by principal + time window).

    Session behaviour: uses engine.begin() (application singleton engine),
    which auto-commits on exit and rolls back + closes on any exception.
    No credential material (key prefix, token, secret) is ever included.

    Best-effort: failures are logged and swallowed.  A telemetry problem must
    not invalidate an otherwise valid authenticated request.
    """
    try:
        from api.db import get_engine as _get_engine
        from api.platform_service_principal import (
            PSP_ACTOR,
            PSP_SERVICE,
            emit_service_principal_event,
        )

        engine = _get_engine()
        with engine.begin() as conn:
            emit_service_principal_event(
                conn,
                event_type="authentication_success",
                service_principal_id=service_principal_id,
                actor_id=PSP_ACTOR,
                service_id=PSP_SERVICE,
                authority_tenant_id=authority_tenant_id,
                request_id=request_id,
                outcome="success",
            )
    except Exception as exc:
        log.warning(
            "psp_auth_event.failed",
            extra={"service_principal_id": service_principal_id, "exc": str(exc)},
        )


# Maps legacy tenant_rbac.py role names → new enterprise role names.
# Existing key assignments are honoured without requiring re-assignment.
_LEGACY_ROLE_MAP: dict[str, str] = {
    "tenant_admin": "tenant_admin",
    "governance_admin": "compliance_reviewer",
    "analyst": "assessor",
    "auditor": "qa_reviewer",
    "read_only": "viewer",
}


def _permissions_from_legacy_scopes(scopes: set[str]) -> frozenset[str]:
    """Derive permissions from legacy API key scopes for backward compat.

    Keys created before RBAC role assignment was enforced have scopes but no
    tenant_rbac role. This maps the three field-assessment scopes to their
    equivalent capability sets so those keys remain functional during migration.

    Uses enterprise role names (assessor, qa_reviewer, viewer) from ROLE_PERMISSIONS,
    NOT the legacy tenant_rbac names (analyst, auditor, read_only).

    This fallback is skipped once a key has an explicit DB role.
    """
    result: set[str] = set()
    if "governance:write" in scopes:
        # Pre-RBAC write keys had full write access across FA mutations (assessor)
        # and governance decision routes (compliance_reviewer). Both are needed so
        # legacy keys retain access to POST /intelligence/... and /orchestration/...
        # mutation routes that now require governance.decision.
        result |= roles_to_permissions(["assessor", "compliance_reviewer"])
    if "governance:qa_approve" in scopes:
        result |= roles_to_permissions(["qa_reviewer"])
    if not result and (scopes & {"governance:read", "decisions:read"}):
        # decisions:read is the historical read scope for the /decisions endpoint;
        # it carries the same read-only intent as governance:read and maps to viewer.
        result |= roles_to_permissions(["viewer"])
    # Admin and key-management scopes used by legacy service keys and test fixtures.
    # These keys already pass require_internal_admin_gateway; the fallback ensures
    # they also satisfy the new require_permission("platform.admin"/"key.manage") gates.
    if scopes & {
        "admin:write",
        "admin:read",
        "keys:admin",
        "keys:write",
        "keys:read",
        "audit:read",
        "audit:export",
    }:
        result |= roles_to_permissions(["platform_admin"])
    return frozenset(result)


def extract_api_key_actor(request: Request, conn: Session) -> Optional[ActorContext]:
    """Build an ActorContext from an authenticated API key.

    Returns None if no valid auth context is present (unauthenticated request).
    """
    auth = getattr(getattr(request, "state", None), "auth", None)
    if not auth or not getattr(auth, "valid", False):
        return None

    tenant_id: str = getattr(auth, "tenant_id", None) or ""
    key_prefix: str = getattr(auth, "key_prefix", None) or ""
    credential_id: Optional[str] = getattr(auth, "credential_id", None)
    credential_slot: Optional[str] = getattr(auth, "credential_slot", None)

    # The global service-account key (FG_API_KEY env var) carries no DB row or
    # scopes, so no fallback fires without this explicit check. Treat it as
    # platform_admin — it already bypasses scope guards in auth_gate middleware.
    if getattr(auth, "reason", None) == "global_key":
        return ActorContext(
            subject=key_prefix or "global_key",
            email="",
            name="",
            permissions=roles_to_permissions(["platform_admin"]),
            roles=["platform_admin"],
            auth_source="api_key",
            tenant_id=tenant_id or None,
        )

    # PSP attribution: if this credential belongs to the platform service
    # principal, resolve its identity and populate the ActorContext fields.
    # This makes PSP-authenticated requests distinguishable in the audit trail.
    service_principal_id: Optional[str] = None
    psp_authority_tenant_id: Optional[str] = None
    if credential_slot == _PSP_CREDENTIAL_SLOT and tenant_id:
        request_id: Optional[str] = getattr(
            getattr(request, "state", None), "request_id", None
        )
        service_principal_id, psp_authority_tenant_id = _resolve_psp_fields(tenant_id)
        if service_principal_id:
            _emit_psp_auth_event(
                service_principal_id, psp_authority_tenant_id or tenant_id, request_id
            )

    raw_role: Optional[str] = None
    if credential_id is not None and tenant_id:
        # Canonical path: credential_id set by R4.7+ dual-validation.
        try:
            from api.tenant_rbac import get_credential_role

            raw_role = get_credential_role(
                conn, tenant_id=tenant_id, credential_id=str(credential_id)
            )
        except Exception as exc:
            log.warning(
                "api_key_actor.role_lookup_failed",
                extra={"key_prefix": key_prefix[:8], "exc": str(exc)},
            )

    mapped_role = _LEGACY_ROLE_MAP.get(raw_role or "", raw_role)
    if mapped_role:
        roles = [mapped_role]
        permissions = roles_to_permissions(roles)
    else:
        # No DB role: derive permissions from legacy scopes for transition period.
        key_scopes: set[str] = getattr(auth, "scopes", set()) or set()
        permissions = _permissions_from_legacy_scopes(key_scopes)
        roles = []

    return ActorContext(
        subject=key_prefix,
        email="",
        name="",
        permissions=permissions,
        roles=roles,
        auth_source="api_key",
        tenant_id=tenant_id or None,
        service_principal_id=service_principal_id,
        authority_tenant_id=psp_authority_tenant_id,
    )
