"""PR-AUTH-001 / PR-AUTH-004: Principal and ExternalIdentity authority.

Write authority for fg_principals and fg_external_identities. Both tables are
written only during invitation binding (PR-AUTH-002+). This module exposes the
read path needed immediately: resolving an external identity claim to a
principal + lifecycle state, which is the foundation for session issuance.

PR-AUTH-004 adds the canonical resolver
`resolve_or_create_principal_for_external_identity` that the invitation flow
must call to atomically obtain a principal_id before flipping
`tenant_users.identity_binding_status` to 'bound'. The resolver is idempotent,
race-safe on the `uq_fg_external_identities_binding` unique constraint, and
returns an existing principal for an already-bound external identity — never
duplicates.

Ownership boundary: this module is the only permitted writer of fg_principals
and fg_external_identities. Console BFF, portal, and Auth0 must not write
these tables directly.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Union

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

log = logging.getLogger("frostgate.principal_authority")

_VALID_PROVIDERS = frozenset({"auth0", "entra", "okta", "saml", "oidc_generic"})
_VALID_LIFECYCLE_STATES = frozenset({"active", "suspended", "deactivated"})


ConnOrSession = Union[Connection, Session]


class PrincipalResolutionError(RuntimeError):
    """Raised when the canonical resolver cannot produce a usable principal.

    Never carries raw provider_subject or provider_issuer values in its
    message — callers can safely surface `.code` and message to logs and API
    responses without leaking IdP identity material.
    """

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


@dataclass(frozen=True)
class PrincipalRecord:
    id: str
    principal_type: str
    lifecycle_state: str
    primary_email: Optional[str]
    display_name: Optional[str]
    mfa_verified: bool
    authority_version: int
    created_at: datetime


@dataclass(frozen=True)
class ExternalIdentityRecord:
    id: str
    principal_id: str
    provider: str
    provider_issuer: str
    provider_subject: str
    provider_email: Optional[str]
    created_at: datetime
    last_seen_at: Optional[datetime]


def resolve_external_identity(
    conn: Connection,
    *,
    provider: str,
    provider_issuer: str,
    provider_subject: str,
) -> Optional[tuple[ExternalIdentityRecord, PrincipalRecord]]:
    """Look up an external identity and its active principal by IdP claim triple.

    Returns (ExternalIdentityRecord, PrincipalRecord) if and only if the
    external identity exists AND the bound principal is lifecycle_state='active'.
    Returns None for unknown identities or principals in any other lifecycle state.

    Per the canonical authority graph: an inactive node at any position → DENY.
    Callers must not treat None as the only denial signal — they should also
    verify the returned principal is appropriate for their context.

    Called at session issuance. Does not update last_seen_at — callers that
    need staleness tracking should call touch_external_identity_seen() separately.
    """
    if provider not in _VALID_PROVIDERS:
        raise ValueError(f"Unknown provider: {provider!r}")

    row = conn.execute(
        text(
            """
            SELECT
                ei.id          AS ei_id,
                ei.principal_id,
                ei.provider,
                ei.provider_issuer,
                ei.provider_subject,
                ei.provider_email,
                ei.created_at  AS ei_created_at,
                ei.last_seen_at,
                p.id           AS p_id,
                p.principal_type,
                p.lifecycle_state,
                p.primary_email,
                p.display_name,
                p.mfa_verified,
                p.authority_version,
                p.created_at   AS p_created_at
            FROM fg_external_identities ei
            JOIN fg_principals p ON p.id = ei.principal_id
            WHERE ei.provider         = :provider
              AND ei.provider_issuer  = :issuer
              AND ei.provider_subject = :subject
              AND p.lifecycle_state   = 'active'
            """
        ),
        {
            "provider": provider,
            "issuer": provider_issuer,
            "subject": provider_subject,
        },
    ).fetchone()

    if row is None:
        return None

    ei = ExternalIdentityRecord(
        id=row.ei_id,
        principal_id=row.principal_id,
        provider=row.provider,
        provider_issuer=row.provider_issuer,
        provider_subject=row.provider_subject,
        provider_email=row.provider_email,
        created_at=row.ei_created_at,
        last_seen_at=row.last_seen_at,
    )
    principal = PrincipalRecord(
        id=row.p_id,
        principal_type=row.principal_type,
        lifecycle_state=row.lifecycle_state,
        primary_email=row.primary_email,
        display_name=row.display_name,
        mfa_verified=bool(row.mfa_verified),
        authority_version=row.authority_version,
        created_at=row.p_created_at,
    )
    return ei, principal


def create_principal(
    conn: Connection,
    *,
    display_name: Optional[str] = None,
    primary_email: Optional[str] = None,
    principal_type: str = "human",
) -> PrincipalRecord:
    """Create a new principal. Called during invitation binding only."""
    if principal_type != "human":
        raise ValueError(f"Unsupported principal_type: {principal_type!r}")

    principal_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    conn.execute(
        text(
            """
            INSERT INTO fg_principals
                (id, display_name, primary_email, principal_type,
                 lifecycle_state, mfa_verified, authority_version,
                 created_at, updated_at)
            VALUES
                (:id, :display_name, :primary_email, :principal_type,
                 'active', :mfa_verified, 1, :now, :now)
            """
        ),
        {
            "id": principal_id,
            "display_name": display_name,
            "primary_email": primary_email,
            "principal_type": principal_type,
            "mfa_verified": False,
            "now": now.isoformat(),
        },
    )
    return PrincipalRecord(
        id=principal_id,
        principal_type=principal_type,
        lifecycle_state="active",
        primary_email=primary_email,
        display_name=display_name,
        mfa_verified=False,
        authority_version=1,
        created_at=now,
    )


def bind_external_identity(
    conn: Connection,
    *,
    principal_id: str,
    provider: str,
    provider_issuer: str,
    provider_subject: str,
    provider_email: Optional[str] = None,
) -> ExternalIdentityRecord:
    """Bind an external IdP identity to an existing principal.

    Called during invitation binding, after create_principal(). The
    uq_fg_external_identities_binding constraint enforces global uniqueness
    — a given IdP account can only be bound to one principal.
    """
    if provider not in _VALID_PROVIDERS:
        raise ValueError(f"Unknown provider: {provider!r}")

    eid = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    conn.execute(
        text(
            """
            INSERT INTO fg_external_identities
                (id, principal_id, provider, provider_issuer,
                 provider_subject, provider_email, created_at)
            VALUES
                (:id, :principal_id, :provider, :provider_issuer,
                 :provider_subject, :provider_email, :now)
            """
        ),
        {
            "id": eid,
            "principal_id": principal_id,
            "provider": provider,
            "provider_issuer": provider_issuer,
            "provider_subject": provider_subject,
            "provider_email": provider_email,
            "now": now.isoformat(),
        },
    )
    return ExternalIdentityRecord(
        id=eid,
        principal_id=principal_id,
        provider=provider,
        provider_issuer=provider_issuer,
        provider_subject=provider_subject,
        provider_email=provider_email,
        created_at=now,
        last_seen_at=None,
    )


def touch_external_identity_seen(
    conn: Connection,
    *,
    provider: str,
    provider_issuer: str,
    provider_subject: str,
) -> None:
    """Update last_seen_at for an external identity. Best-effort — does not raise."""
    try:
        conn.execute(
            text(
                """
                UPDATE fg_external_identities
                   SET last_seen_at = :now
                 WHERE provider         = :provider
                   AND provider_issuer  = :issuer
                   AND provider_subject = :subject
                """
            ),
            {
                "now": datetime.now(timezone.utc).isoformat(),
                "provider": provider,
                "issuer": provider_issuer,
                "subject": provider_subject,
            },
        )
    except Exception:
        log.warning("touch_external_identity_seen: update failed (non-fatal)")


# ---------------------------------------------------------------------------
# PR-AUTH-004 — Canonical resolver
# ---------------------------------------------------------------------------


def _validate_canonical_triple(
    provider: str, issuer: str | None, subject: str | None
) -> None:
    """Validate the canonical triple; raises PrincipalResolutionError on failure.

    Never embeds `subject` in the exception message — that is credential-adjacent
    material and cannot appear in logs.
    """
    if provider not in _VALID_PROVIDERS:
        raise PrincipalResolutionError(
            "UNKNOWN_PROVIDER",
            "Provider not recognized by canonical identity authority.",
        )
    if not issuer or not str(issuer).strip():
        raise PrincipalResolutionError(
            "INVALID_ISSUER",
            "Provider issuer is required for canonical binding.",
        )
    if not subject or not str(subject).strip():
        raise PrincipalResolutionError(
            "INVALID_SUBJECT",
            "Provider subject is required for canonical binding.",
        )


def _lookup_external_identity(
    conn: ConnOrSession,
    *,
    provider: str,
    provider_issuer: str,
    provider_subject: str,
) -> Optional[tuple[str, str, str]]:
    """Return (external_identity_id, principal_id, lifecycle_state) or None."""
    row = conn.execute(
        text(
            """
            SELECT ei.id           AS ei_id,
                   ei.principal_id AS principal_id,
                   p.lifecycle_state AS lifecycle_state
              FROM fg_external_identities ei
              JOIN fg_principals p ON p.id = ei.principal_id
             WHERE ei.provider         = :provider
               AND ei.provider_issuer  = :issuer
               AND ei.provider_subject = :subject
            """
        ),
        {
            "provider": provider,
            "issuer": provider_issuer,
            "subject": provider_subject,
        },
    ).fetchone()
    if row is None:
        return None
    return str(row.ei_id), str(row.principal_id), str(row.lifecycle_state)


@dataclass(frozen=True)
class PrincipalResolution:
    """Outcome of resolve_or_create_principal_for_external_identity.

    - `principal_id`: canonical fg_principals.id ready to be written to
      tenant_users.principal_id atomically with identity_binding_status='bound'.
    - `external_identity_id`: canonical fg_external_identities.id row that
      binds the IdP triple to the principal.
    - `created`: True iff a new principal + external identity were inserted
      in this call. False iff an existing binding was returned.
    """

    principal_id: str
    external_identity_id: str
    created: bool


def resolve_or_create_principal_for_external_identity(
    conn: ConnOrSession,
    *,
    provider: str,
    issuer: str,
    subject: str,
    display_name: Optional[str] = None,
    primary_email: Optional[str] = None,
    provider_email: Optional[str] = None,
) -> PrincipalResolution:
    """Canonical resolver: return a principal_id for a given IdP triple.

    Behavior:
      1. Validate the canonical triple. Raises PrincipalResolutionError
         (INVALID_ISSUER / INVALID_SUBJECT / UNKNOWN_PROVIDER) if invalid.
      2. Lookup fg_external_identities by (provider, issuer, subject).
         - If found and the linked principal is 'active' → return existing
           principal_id (created=False).
         - If found but principal is 'suspended' or 'deactivated' → raise
           PRINCIPAL_INACTIVE (fail-closed per ADR-IDENTITY-003).
      3. If not found: INSERT fg_principals (lifecycle_state='active') +
         fg_external_identities atomically. Return created=True.
      4. If the INSERT races with a concurrent binder and hits
         uq_fg_external_identities_binding, resolve the winner via a second
         lookup and return that principal_id.

    Idempotency: repeatedly calling with the same triple produces the same
    principal_id (unless the principal is deactivated between calls).

    Never logs raw subject. Errors carry `.code`, never the subject.

    Called only from the invitation binding flow after the callback has been
    validated. The caller owns the DB transaction; this function does not
    commit.
    """
    _validate_canonical_triple(provider, issuer, subject)

    existing = _lookup_external_identity(
        conn,
        provider=provider,
        provider_issuer=issuer,
        provider_subject=subject,
    )
    if existing is not None:
        ei_id, principal_id, lifecycle_state = existing
        if lifecycle_state != "active":
            log.warning(
                "principal_authority.resolve.inactive_principal",
                extra={"lifecycle_state": lifecycle_state},
            )
            raise PrincipalResolutionError(
                "PRINCIPAL_INACTIVE",
                "Bound principal is not in active lifecycle state.",
            )
        return PrincipalResolution(
            principal_id=principal_id,
            external_identity_id=ei_id,
            created=False,
        )

    new_principal_id = str(uuid.uuid4())
    new_ei_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    try:
        conn.execute(
            text(
                """
                INSERT INTO fg_principals
                    (id, display_name, primary_email, principal_type,
                     lifecycle_state, mfa_verified, authority_version,
                     created_at, updated_at)
                VALUES
                    (:id, :display_name, :primary_email, 'human',
                     'active', :mfa_verified, 1, :now, :now)
                """
            ),
            {
                "id": new_principal_id,
                "display_name": display_name,
                "primary_email": primary_email,
                "mfa_verified": False,
                "now": now,
            },
        )
        conn.execute(
            text(
                """
                INSERT INTO fg_external_identities
                    (id, principal_id, provider, provider_issuer,
                     provider_subject, provider_email, created_at)
                VALUES
                    (:id, :principal_id, :provider, :provider_issuer,
                     :provider_subject, :provider_email, :now)
                """
            ),
            {
                "id": new_ei_id,
                "principal_id": new_principal_id,
                "provider": provider,
                "provider_issuer": issuer,
                "provider_subject": subject,
                "provider_email": provider_email,
                "now": now,
            },
        )
    except IntegrityError:
        # Race: a concurrent binder inserted first. Resolve the winner.
        log.info("principal_authority.resolve.race_resolved")
        try:
            existing = _lookup_external_identity(
                conn,
                provider=provider,
                provider_issuer=issuer,
                provider_subject=subject,
            )
        except Exception:
            existing = None
        if existing is None:
            # Extremely unlikely: unique violation without a visible winner.
            # Fail closed rather than silently create a duplicate.
            raise PrincipalResolutionError(
                "RESOLVER_RACE_UNRESOLVED",
                "Canonical binding race could not be resolved deterministically.",
            )
        ei_id, principal_id, lifecycle_state = existing
        if lifecycle_state != "active":
            raise PrincipalResolutionError(
                "PRINCIPAL_INACTIVE",
                "Bound principal is not in active lifecycle state.",
            )
        return PrincipalResolution(
            principal_id=principal_id,
            external_identity_id=ei_id,
            created=False,
        )

    return PrincipalResolution(
        principal_id=new_principal_id,
        external_identity_id=new_ei_id,
        created=True,
    )
