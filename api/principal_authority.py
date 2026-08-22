"""PR-AUTH-001: Principal and ExternalIdentity authority.

Write authority for fg_principals and fg_external_identities. Both tables are
written only during invitation binding (PR-AUTH-002+). This module exposes the
read path needed immediately: resolving an external identity claim to a
principal + lifecycle state, which is the foundation for session issuance.

Ownership boundary: this module is the only permitted writer of fg_principals
and fg_external_identities. Console BFF, portal, and Auth0 must not write
these tables directly.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import text
from sqlalchemy.engine import Connection

log = logging.getLogger("frostgate.principal_authority")

_VALID_PROVIDERS = frozenset({"auth0", "entra", "okta", "saml", "oidc_generic"})
_VALID_LIFECYCLE_STATES = frozenset({"active", "suspended", "deactivated"})


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
