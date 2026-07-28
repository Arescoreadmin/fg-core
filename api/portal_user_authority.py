"""
portal_user_authority.py — Portal Named-User Identity Authority

Manages the PORTAL identity population: external client-facing humans who
access the portal via OIDC and invitation-based enrollment.

This is DISTINCT from tenant_users (workforce/operator identity).  Do NOT
share authorization rows or build on the workforce authority.

Token format (version-discriminated, never prefix-sniffed by heuristic):
  INVITATION_TOKEN_PREFIX = "pni1."   portal named invitation v1
  SESSION_TOKEN_PREFIX    = "pnu1."   portal named user session v1

All public functions accept a SQLAlchemy Session as first positional argument.
The caller controls the transaction — this module never commits or rolls back.

Pepper source: FG_KEY_PEPPER environment variable (same as credential_authority).
Fingerprint:   HMAC-SHA256(raw_token_hex, pepper) — stored in DB, never the raw token.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import logging
import os
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import text

from api.tenant_authority import ensure_portal_enabled

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Token format constants
# ---------------------------------------------------------------------------

INVITATION_TOKEN_PREFIX = "pni1."  # portal named invitation v1
SESSION_TOKEN_PREFIX = "pnu1."  # portal named user session v1

DEFAULT_INVITATION_TTL_SECONDS = 7 * 24 * 3600  # 7 days
DEFAULT_SESSION_TTL_SECONDS = 14 * 24 * 3600  # 14 days

# ---------------------------------------------------------------------------
# Error classes
# ---------------------------------------------------------------------------


class PortalUserSuspendedError(Exception):
    """Raised when a portal_user record has status='suspended' or 'deactivated'."""

    def __init__(self, portal_user_id: str, status: str) -> None:
        self.portal_user_id = portal_user_id
        self.status = status
        super().__init__(
            f"Portal user {portal_user_id} is not active (status={status!r})"
        )


class PortalInvitationInvalidError(Exception):
    """Raised when a token is not found, has an invalid format, or is expired."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"Invitation invalid: {reason}")


class PortalInvitationAlreadyAcceptedError(Exception):
    """Raised when an invitation has already been accepted."""

    def __init__(self, invitation_id: str) -> None:
        self.invitation_id = invitation_id
        super().__init__(f"Invitation {invitation_id} has already been accepted")


class PortalInvitationRevokedError(Exception):
    """Raised when an invitation has been explicitly revoked."""

    def __init__(self, invitation_id: str) -> None:
        self.invitation_id = invitation_id
        super().__init__(f"Invitation {invitation_id} has been revoked")


# ---------------------------------------------------------------------------
# Return-value dataclasses (frozen — immutable after creation)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PortalUserRecord:
    id: str
    tenant_id: str
    oidc_provider: str
    oidc_issuer: str
    oidc_subject: str
    email: str
    display_name: str | None
    status: str


@dataclass(frozen=True)
class PortalMembershipRecord:
    id: str
    portal_user_id: str
    tenant_id: str
    engagement_id: str | None
    portal_role: str
    auth_version: int
    active: bool


@dataclass(frozen=True)
class PortalInvitationRecord:
    id: str
    tenant_id: str
    email: str
    portal_role: str
    engagement_id: str | None
    status: str
    expires_at: str
    raw_token: str | None  # only set at issuance; never stored in DB


@dataclass(frozen=True)
class PortalSessionRecord:
    id: str
    tenant_id: str
    portal_user_id: str
    portal_membership_id: str | None
    auth_version_snapshot: int
    session_type: str
    status: str
    expires_at: str
    raw_token: str | None  # only set at issuance; never stored in DB


@dataclass(frozen=True)
class SessionValidationResult:
    ok: bool
    session_id: str | None = None
    portal_user_id: str | None = None
    portal_membership_id: str | None = None
    tenant_id: str | None = None
    engagement_id: str | None = None
    portal_role: str | None = None
    denial_reason: str | None = None
    denial_code: str | None = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_pepper() -> str:
    """Read FG_KEY_PEPPER from environment; raise if absent."""
    pepper = os.environ.get("FG_KEY_PEPPER", "")
    if not pepper:
        raise RuntimeError(
            "FG_KEY_PEPPER not configured; cannot issue or validate portal tokens."
        )
    return pepper


def _compute_lookup_fingerprint(secret_part: str, pepper: str) -> str:
    """HMAC-SHA256(secret_part, pepper) — deterministic, indexed, non-secret."""
    return _hmac.new(
        key=pepper.encode("utf-8"),
        msg=secret_part.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()


def _now_iso() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(tz=UTC).isoformat()


def _coerce_uuid(val) -> str | None:
    """Coerce uuid.UUID → str; leave str/None unchanged."""
    if val is None:
        return None
    if isinstance(val, uuid.UUID):
        return str(val)
    return str(val)


def _emit_audit(
    db,
    *,
    event_type: str,
    tenant_id: str,
    portal_user_id: str | None = None,
    actor_id: str | None = None,
    request_id: str | None = None,
    outcome: str = "success",
    metadata: str | None = None,
) -> None:
    """Best-effort INSERT into portal_user_audit_events.  Never raises."""
    try:
        event_id = secrets.token_hex(16)
        db.execute(
            text(
                """
                INSERT INTO portal_user_audit_events
                    (event_id, tenant_id, event_type, portal_user_id,
                     actor_id, request_id, occurred_at, outcome, metadata, schema_version)
                VALUES
                    (:event_id, :tenant_id, :event_type, :portal_user_id,
                     :actor_id, :request_id, :occurred_at, :outcome, :metadata, 1)
                """
            ),
            {
                "event_id": event_id,
                "tenant_id": tenant_id,
                "event_type": event_type,
                "portal_user_id": portal_user_id,
                "actor_id": actor_id,
                "request_id": request_id,
                "occurred_at": _now_iso(),
                "outcome": outcome,
                "metadata": metadata,
            },
        )
    except Exception:
        log.exception(
            "portal_user_authority: failed to emit audit event %s for tenant %s",
            event_type,
            tenant_id,
        )


def _set_tenant_rls(db, tenant_id: str) -> None:
    """Set app.tenant_id for RLS.  Uses set_config() — SET LOCAL rejects bound params."""
    db.execute(
        text("SELECT pg_catalog.set_config('app.tenant_id', :tid, true)"),
        {"tid": tenant_id},
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def find_or_create_portal_user(
    db,
    *,
    tenant_id: str,
    oidc_provider: str,
    oidc_issuer: str,
    oidc_subject: str,
    email: str,
    display_name: str | None = None,
    request_id: str | None = None,
) -> PortalUserRecord:
    """
    UPSERT a portal_user row by (tenant_id, oidc_issuer, oidc_subject).

    On conflict: updates email, display_name, and updated_at.
    Raises PortalUserSuspendedError if the resulting status is not 'active'.
    """
    _set_tenant_rls(db, tenant_id)

    row = db.execute(
        text(
            """
            INSERT INTO portal_users
                (tenant_id, oidc_provider, oidc_issuer, oidc_subject,
                 email, display_name, status)
            VALUES
                (:tenant_id, :oidc_provider, :oidc_issuer, :oidc_subject,
                 :email, :display_name, 'active')
            ON CONFLICT (tenant_id, oidc_issuer, oidc_subject)
            DO UPDATE SET
                email        = EXCLUDED.email,
                display_name = EXCLUDED.display_name,
                updated_at   = now()
            RETURNING
                id, tenant_id, oidc_provider, oidc_issuer, oidc_subject,
                email, display_name, status
            """
        ),
        {
            "tenant_id": tenant_id,
            "oidc_provider": oidc_provider,
            "oidc_issuer": oidc_issuer,
            "oidc_subject": oidc_subject,
            "email": email,
            "display_name": display_name,
        },
    ).fetchone()

    record = PortalUserRecord(
        id=_coerce_uuid(row.id) or "",
        tenant_id=str(row.tenant_id),
        oidc_provider=str(row.oidc_provider),
        oidc_issuer=str(row.oidc_issuer),
        oidc_subject=str(row.oidc_subject),
        email=str(row.email),
        display_name=row.display_name,
        status=str(row.status),
    )

    if record.status in ("suspended", "deactivated"):
        raise PortalUserSuspendedError(record.id, record.status)

    _emit_audit(
        db,
        event_type="portal_user_created",
        tenant_id=tenant_id,
        portal_user_id=record.id,
        request_id=request_id,
    )

    return record


def _create_membership(
    db,
    *,
    portal_user_id: str,
    tenant_id: str,
    portal_role: str,
    engagement_id: str | None = None,
    granted_by_actor_id: str | None = None,
    invitation_id: str | None = None,
    request_id: str | None = None,
) -> PortalMembershipRecord:
    """
    Insert a portal_user_memberships row.  Caller must have already set RLS.
    Internal helper used by accept_invitation.
    """
    row = db.execute(
        text(
            """
            INSERT INTO portal_user_memberships
                (portal_user_id, tenant_id, engagement_id, portal_role,
                 auth_version, active, granted_by_actor_id, invitation_id)
            VALUES
                (:portal_user_id, :tenant_id, :engagement_id, :portal_role,
                 1, TRUE, :granted_by_actor_id, :invitation_id)
            RETURNING
                id, portal_user_id, tenant_id, engagement_id,
                portal_role, auth_version, active
            """
        ),
        {
            "portal_user_id": portal_user_id,
            "tenant_id": tenant_id,
            "engagement_id": engagement_id,
            "portal_role": portal_role,
            "granted_by_actor_id": granted_by_actor_id,
            "invitation_id": invitation_id,
        },
    ).fetchone()

    membership = PortalMembershipRecord(
        id=_coerce_uuid(row.id) or "",
        portal_user_id=_coerce_uuid(row.portal_user_id) or "",
        tenant_id=str(row.tenant_id),
        engagement_id=row.engagement_id,
        portal_role=str(row.portal_role),
        auth_version=int(row.auth_version),
        active=bool(row.active),
    )

    _emit_audit(
        db,
        event_type="portal_membership_created",
        tenant_id=tenant_id,
        portal_user_id=portal_user_id,
        request_id=request_id,
    )

    return membership


def get_active_membership(
    db,
    *,
    portal_user_id: str,
    tenant_id: str,
    engagement_id: str | None = None,
) -> PortalMembershipRecord | None:
    """Return the active membership for a portal user, or None.

    If engagement_id is None, returns the tenant-wide membership (engagement_id IS NULL).
    If engagement_id is provided, returns the matching engagement-scoped membership.
    """
    _set_tenant_rls(db, tenant_id)

    if engagement_id is None:
        where_clause = "engagement_id IS NULL"
        params: dict = {"portal_user_id": portal_user_id, "tenant_id": tenant_id}
    else:
        where_clause = "engagement_id = :engagement_id"
        params = {
            "portal_user_id": portal_user_id,
            "tenant_id": tenant_id,
            "engagement_id": engagement_id,
        }

    row = db.execute(
        text(
            f"""
            SELECT id, portal_user_id, tenant_id, engagement_id,
                   portal_role, auth_version, active
            FROM   portal_user_memberships
            WHERE  portal_user_id = :portal_user_id
              AND  tenant_id      = :tenant_id
              AND  active         = true
              AND  {where_clause}
            LIMIT 1
            """
        ),
        params,
    ).fetchone()

    if row is None:
        return None

    return PortalMembershipRecord(
        id=_coerce_uuid(row.id) or "",
        portal_user_id=_coerce_uuid(row.portal_user_id) or "",
        tenant_id=str(row.tenant_id),
        engagement_id=row.engagement_id,
        portal_role=str(row.portal_role),
        auth_version=int(row.auth_version),
        active=bool(row.active),
    )


def get_best_active_membership(
    db,
    *,
    portal_user_id: str,
    tenant_id: str,
) -> PortalMembershipRecord | None:
    """Return the best active membership for a portal user, or None.

    Used at SSO/enrollment time when the specific engagement is not yet known.
    Priority order:
      1. Tenant-wide membership (engagement_id IS NULL)
      2. Most recently created engagement-scoped membership

    Returns None if no active membership exists. Callers that need an exact
    engagement-scoped lookup should use ``get_active_membership`` with the
    ``engagement_id`` argument.
    """
    _set_tenant_rls(db, tenant_id)
    row = db.execute(
        text(
            """
            SELECT id, portal_user_id, tenant_id, engagement_id,
                   portal_role, auth_version, active
            FROM   portal_user_memberships
            WHERE  portal_user_id = :portal_user_id
              AND  tenant_id      = :tenant_id
              AND  active         = true
            ORDER BY
                   (engagement_id IS NULL) DESC,
                   created_at DESC
            LIMIT 1
            """
        ),
        {"portal_user_id": portal_user_id, "tenant_id": tenant_id},
    ).fetchone()

    if row is None:
        return None

    return PortalMembershipRecord(
        id=_coerce_uuid(row.id) or "",
        portal_user_id=_coerce_uuid(row.portal_user_id) or "",
        tenant_id=str(row.tenant_id),
        engagement_id=row.engagement_id,
        portal_role=str(row.portal_role),
        auth_version=int(row.auth_version),
        active=bool(row.active),
    )


def create_invitation(
    db,
    *,
    tenant_id: str,
    email: str,
    portal_role: str = "viewer",
    engagement_id: str | None = None,
    invited_by_actor_id: str | None = None,
    ttl_seconds: int = DEFAULT_INVITATION_TTL_SECONDS,
    request_id: str | None = None,
    idempotency_key: str | None = None,
) -> PortalInvitationRecord:
    """
    Issue a new portal invitation.

    The raw_token is returned in the PortalInvitationRecord and MUST be
    delivered to the invitee by the caller (e.g. via email).  It is never
    stored in the database.
    """
    ensure_portal_enabled(db, tenant_id)
    _set_tenant_rls(db, tenant_id)

    token_hex = secrets.token_hex(32)
    raw_token = INVITATION_TOKEN_PREFIX + token_hex
    fingerprint = _compute_lookup_fingerprint(token_hex, _get_pepper())
    token_prefix = token_hex[:8]

    row = db.execute(
        text(
            """
            INSERT INTO portal_user_invitations
                (tenant_id, email, portal_role, engagement_id,
                 token_fingerprint, token_prefix, token_version,
                 status, invited_by_actor_id, request_id, idempotency_key,
                 expires_at)
            VALUES
                (:tenant_id, :email, :portal_role, :engagement_id,
                 :token_fingerprint, :token_prefix, 1,
                 'pending', :invited_by_actor_id, :request_id, :idempotency_key,
                 now() + (:ttl_seconds || ' seconds')::interval)
            RETURNING
                id, tenant_id, email, portal_role, engagement_id,
                status, expires_at
            """
        ),
        {
            "tenant_id": tenant_id,
            "email": email,
            "portal_role": portal_role,
            "engagement_id": engagement_id,
            "token_fingerprint": fingerprint,
            "token_prefix": token_prefix,
            "invited_by_actor_id": invited_by_actor_id,
            "request_id": request_id,
            "idempotency_key": idempotency_key,
            "ttl_seconds": ttl_seconds,
        },
    ).fetchone()

    record = PortalInvitationRecord(
        id=_coerce_uuid(row.id) or "",
        tenant_id=str(row.tenant_id),
        email=str(row.email),
        portal_role=str(row.portal_role),
        engagement_id=row.engagement_id,
        status=str(row.status),
        expires_at=str(row.expires_at),
        raw_token=raw_token,
    )

    _emit_audit(
        db,
        event_type="portal_invitation_issued",
        tenant_id=tenant_id,
        actor_id=invited_by_actor_id,
        request_id=request_id,
    )

    return record


def get_invitation_by_token(
    db,
    *,
    raw_token: str,
    tenant_id: str,
) -> PortalInvitationRecord | None:
    """
    Look up an invitation by raw token.  Returns None if not found.
    Does NOT validate status or expiry — callers should check those fields.
    """
    if not raw_token.startswith(INVITATION_TOKEN_PREFIX):
        return None

    token_hex = raw_token[len(INVITATION_TOKEN_PREFIX) :]
    fingerprint = _compute_lookup_fingerprint(token_hex, _get_pepper())

    _set_tenant_rls(db, tenant_id)

    row = db.execute(
        text(
            """
            SELECT id, tenant_id, email, portal_role, engagement_id,
                   status, expires_at
            FROM   portal_user_invitations
            WHERE  token_fingerprint = :fp
              AND  tenant_id = :tenant_id
            """
        ),
        {"fp": fingerprint, "tenant_id": tenant_id},
    ).fetchone()

    if row is None:
        return None

    return PortalInvitationRecord(
        id=_coerce_uuid(row.id) or "",
        tenant_id=str(row.tenant_id),
        email=str(row.email),
        portal_role=str(row.portal_role),
        engagement_id=row.engagement_id,
        status=str(row.status),
        expires_at=str(row.expires_at),
        raw_token=None,  # never re-exposed after issuance
    )


def accept_invitation(
    db,
    *,
    raw_token: str,
    tenant_id: str,
    oidc_provider: str,
    oidc_issuer: str,
    oidc_subject: str,
    email: str,
    display_name: str | None = None,
    request_id: str | None = None,
) -> tuple:
    """
    Accept a portal invitation.

    Strategy: SELECT FOR UPDATE within a transaction to serialize concurrent
    acceptance attempts, then validate state, create user+membership, and
    atomically UPDATE the invitation status (rowcount guard for idempotency).

    Returns: (PortalUserRecord, PortalMembershipRecord, PortalInvitationRecord)

    Raises:
      PortalInvitationInvalidError  — format invalid, not found, or expired
      PortalInvitationAlreadyAcceptedError — status='accepted'
      PortalInvitationRevokedError  — status='revoked'
    """
    if not raw_token.startswith(INVITATION_TOKEN_PREFIX):
        raise PortalInvitationInvalidError("token format invalid: wrong prefix")

    token_hex = raw_token[len(INVITATION_TOKEN_PREFIX) :]
    fingerprint = _compute_lookup_fingerprint(token_hex, _get_pepper())

    _set_tenant_rls(db, tenant_id)

    # Step 1: SELECT FOR UPDATE — serializes concurrent acceptance attempts
    inv_row = db.execute(
        text(
            """
            SELECT id, email, portal_role, engagement_id, status, expires_at
            FROM   portal_user_invitations
            WHERE  tenant_id = :tenant_id
              AND  token_fingerprint = :fp
            FOR UPDATE
            """
        ),
        {"tenant_id": tenant_id, "fp": fingerprint},
    ).fetchone()

    if inv_row is None:
        raise PortalInvitationInvalidError("token not found")

    inv_status = str(inv_row.status)

    if inv_status == "accepted":
        raise PortalInvitationAlreadyAcceptedError(_coerce_uuid(inv_row.id) or "")

    if inv_status == "revoked":
        raise PortalInvitationRevokedError(_coerce_uuid(inv_row.id) or "")

    if inv_status == "expired":
        raise PortalInvitationInvalidError("invitation has expired")

    # Check expiry (belt-and-suspenders — DB query could race across connections)
    expires_at = inv_row.expires_at
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if expires_at <= datetime.now(tz=UTC):
        raise PortalInvitationInvalidError("invitation has expired")

    invitation_id = _coerce_uuid(inv_row.id) or ""

    # Step 2: find or create the portal user
    portal_user = find_or_create_portal_user(
        db,
        tenant_id=tenant_id,
        oidc_provider=oidc_provider,
        oidc_issuer=oidc_issuer,
        oidc_subject=oidc_subject,
        email=email,
        display_name=display_name,
        request_id=request_id,
    )

    # Step 3: create membership
    membership = _create_membership(
        db,
        portal_user_id=portal_user.id,
        tenant_id=tenant_id,
        portal_role=str(inv_row.portal_role),
        engagement_id=inv_row.engagement_id,
        invitation_id=invitation_id,
        request_id=request_id,
    )

    # Step 4: atomic CAS UPDATE — rowcount=0 means something changed under us
    result = db.execute(
        text(
            """
            UPDATE portal_user_invitations
            SET    status                     = 'accepted',
                   accepted_at               = now(),
                   accepted_by_portal_user_id = :user_id
            WHERE  id         = :id
              AND  tenant_id  = :tenant_id
              AND  status     = 'pending'
            RETURNING id
            """
        ),
        {"user_id": portal_user.id, "id": invitation_id, "tenant_id": tenant_id},
    )
    updated_ids = result.fetchall()
    if len(updated_ids) == 0:
        # Another concurrent request won the CAS race
        raise PortalInvitationAlreadyAcceptedError(invitation_id)

    invitation_record = PortalInvitationRecord(
        id=invitation_id,
        tenant_id=tenant_id,
        email=str(inv_row.email),
        portal_role=str(inv_row.portal_role),
        engagement_id=inv_row.engagement_id,
        status="accepted",
        expires_at=str(inv_row.expires_at),
        raw_token=None,
    )

    _emit_audit(
        db,
        event_type="portal_invitation_accepted",
        tenant_id=tenant_id,
        portal_user_id=portal_user.id,
        request_id=request_id,
    )

    return portal_user, membership, invitation_record


def revoke_invitation(
    db,
    *,
    invitation_id: str,
    tenant_id: str,
    actor_id: str | None = None,
    request_id: str | None = None,
) -> bool:
    """
    Revoke a pending invitation.

    Returns True if the invitation was revoked, False if it was already in a
    terminal state (accepted, revoked, expired).
    """
    _set_tenant_rls(db, tenant_id)

    result = db.execute(
        text(
            """
            UPDATE portal_user_invitations
            SET    status     = 'revoked',
                   revoked_at = now()
            WHERE  id        = :id
              AND  tenant_id = :tenant_id
              AND  status    = 'pending'
            RETURNING id
            """
        ),
        {"id": invitation_id, "tenant_id": tenant_id},
    )
    revoked = result.fetchall()

    if revoked:
        _emit_audit(
            db,
            event_type="portal_invitation_revoked",
            tenant_id=tenant_id,
            actor_id=actor_id,
            request_id=request_id,
        )
        return True

    return False


def create_session(
    db,
    *,
    portal_user_id: str,
    tenant_id: str,
    auth_version_snapshot: int,
    portal_membership_id: str | None = None,
    ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
    ip_address: str | None = None,
    user_agent: str | None = None,
    request_id: str | None = None,
) -> PortalSessionRecord:
    """
    Issue a new portal session token.

    The raw_token is returned in the PortalSessionRecord and MUST be delivered
    to the client by the caller.  It is never stored in the database.
    """
    _set_tenant_rls(db, tenant_id)

    token_hex = secrets.token_hex(32)
    raw_token = SESSION_TOKEN_PREFIX + token_hex
    fingerprint = _compute_lookup_fingerprint(token_hex, _get_pepper())
    token_prefix = token_hex[:8]

    row = db.execute(
        text(
            """
            INSERT INTO portal_user_sessions
                (portal_user_id, portal_membership_id, tenant_id,
                 token_fingerprint, token_prefix, token_version,
                 session_type, auth_version_snapshot, status,
                 expires_at, ip_address, user_agent)
            VALUES
                (:portal_user_id, :portal_membership_id, :tenant_id,
                 :token_fingerprint, :token_prefix, 1,
                 'named_user_v1', :auth_version_snapshot, 'active',
                 now() + (:ttl_seconds || ' seconds')::interval,
                 :ip_address, :user_agent)
            RETURNING
                id, tenant_id, portal_user_id, portal_membership_id,
                auth_version_snapshot, session_type, status, expires_at
            """
        ),
        {
            "portal_user_id": portal_user_id,
            "portal_membership_id": portal_membership_id,
            "tenant_id": tenant_id,
            "token_fingerprint": fingerprint,
            "token_prefix": token_prefix,
            "auth_version_snapshot": auth_version_snapshot,
            "ttl_seconds": ttl_seconds,
            "ip_address": ip_address,
            "user_agent": user_agent,
        },
    ).fetchone()

    record = PortalSessionRecord(
        id=_coerce_uuid(row.id) or "",
        tenant_id=str(row.tenant_id),
        portal_user_id=_coerce_uuid(row.portal_user_id) or "",
        portal_membership_id=_coerce_uuid(row.portal_membership_id),
        auth_version_snapshot=int(row.auth_version_snapshot),
        session_type=str(row.session_type),
        status=str(row.status),
        expires_at=str(row.expires_at),
        raw_token=raw_token,
    )

    _emit_audit(
        db,
        event_type="portal_session_created",
        tenant_id=tenant_id,
        portal_user_id=portal_user_id,
        request_id=request_id,
    )

    return record


def validate_session(
    db,
    *,
    raw_token: str,
    tenant_id: str,
    check_membership_version: bool = True,
) -> SessionValidationResult:
    """
    Validate a portal session token.

    Returns SessionValidationResult(ok=True, ...) on success.
    Returns SessionValidationResult(ok=False, denial_code=...) on failure.
    Never raises (errors are returned as ok=False).
    """
    if not raw_token.startswith(SESSION_TOKEN_PREFIX):
        return SessionValidationResult(
            ok=False,
            denial_reason="token format invalid: wrong prefix",
            denial_code="PORTAL_SESSION_INVALID",
        )

    token_hex = raw_token[len(SESSION_TOKEN_PREFIX) :]

    try:
        fingerprint = _compute_lookup_fingerprint(token_hex, _get_pepper())
    except RuntimeError as exc:
        return SessionValidationResult(
            ok=False,
            denial_reason=str(exc),
            denial_code="PORTAL_SESSION_INVALID",
        )

    try:
        _set_tenant_rls(db, tenant_id)

        row = db.execute(
            text(
                """
                SELECT
                    pus.id                    AS session_id,
                    pus.tenant_id             AS tenant_id,
                    pus.portal_user_id        AS portal_user_id,
                    pus.portal_membership_id  AS portal_membership_id,
                    pus.auth_version_snapshot AS auth_version_snapshot,
                    pus.session_type          AS session_type,
                    pus.status                AS status,
                    pus.expires_at            AS expires_at,
                    pum.engagement_id         AS engagement_id,
                    pum.portal_role           AS portal_role,
                    pum.auth_version          AS membership_auth_version,
                    pum.active                AS membership_active,
                    pu.status                 AS portal_user_status
                FROM   portal_user_sessions pus
                JOIN   portal_users pu
                       ON pu.id = pus.portal_user_id
                LEFT JOIN portal_user_memberships pum
                       ON pum.id = pus.portal_membership_id
                WHERE  pus.token_fingerprint = :fp
                  AND  pus.tenant_id         = :tenant_id
                  AND  pus.status            = 'active'
                  AND  pus.expires_at        > now()
                """
            ),
            {"fp": fingerprint, "tenant_id": tenant_id},
        ).fetchone()

    except Exception as exc:
        log.exception("validate_session: DB error during lookup: %s", exc)
        return SessionValidationResult(
            ok=False,
            denial_reason="internal error during session lookup",
            denial_code="PORTAL_SESSION_ERROR",
        )

    if row is None:
        _emit_audit(
            db,
            event_type="portal_session_rejected_version_mismatch",
            tenant_id=tenant_id,
            outcome="denied",
            metadata="session not found or expired",
        )
        return SessionValidationResult(
            ok=False,
            denial_reason="session not found, expired, or revoked",
            denial_code="PORTAL_SESSION_NOT_FOUND",
        )

    session_id = _coerce_uuid(row.session_id)
    portal_user_id = _coerce_uuid(row.portal_user_id)
    portal_membership_id = _coerce_uuid(row.portal_membership_id)

    # Portal user must still be active (suspension/deactivation post-issuance).
    if row.portal_user_status != "active":
        _emit_audit(
            db,
            event_type="portal_session_rejected_version_mismatch",
            tenant_id=tenant_id,
            portal_user_id=portal_user_id,
            outcome="denied",
            metadata=f"portal_user status={row.portal_user_status}",
        )
        return SessionValidationResult(
            ok=False,
            portal_user_id=portal_user_id,
            tenant_id=tenant_id,
            denial_reason="portal user is suspended or deactivated",
            denial_code="PORTAL_USER_SUSPENDED",
        )

    # Membership must still be active (explicit deactivation invalidates sessions).
    if (
        portal_membership_id is not None
        and row.membership_active is not None
        and not row.membership_active
    ):
        _emit_audit(
            db,
            event_type="portal_session_rejected_version_mismatch",
            tenant_id=tenant_id,
            portal_user_id=portal_user_id,
            outcome="denied",
            metadata="membership deactivated",
        )
        return SessionValidationResult(
            ok=False,
            portal_user_id=portal_user_id,
            portal_membership_id=portal_membership_id,
            tenant_id=tenant_id,
            denial_reason="membership has been deactivated",
            denial_code="MEMBERSHIP_INACTIVE",
        )

    # Version-mismatch check (auth_version bump invalidates all existing sessions)
    if (
        check_membership_version
        and portal_membership_id is not None
        and row.membership_auth_version is not None
    ):
        if int(row.auth_version_snapshot) != int(row.membership_auth_version):
            _emit_audit(
                db,
                event_type="portal_session_rejected_version_mismatch",
                tenant_id=tenant_id,
                portal_user_id=portal_user_id,
                outcome="denied",
                metadata=(
                    f"snapshot={row.auth_version_snapshot} "
                    f"current={row.membership_auth_version}"
                ),
            )
            return SessionValidationResult(
                ok=False,
                portal_user_id=portal_user_id,
                portal_membership_id=portal_membership_id,
                tenant_id=tenant_id,
                denial_reason="session invalidated by membership auth_version bump",
                denial_code="SESSION_REVOKED_VERSION_MISMATCH",
            )

    # Best-effort touch last_validated_at
    try:
        db.execute(
            text(
                """
                UPDATE portal_user_sessions
                SET    last_validated_at = now()
                WHERE  id = :id
                """
            ),
            {"id": session_id},
        )
    except Exception:
        log.exception(
            "validate_session: failed to update last_validated_at for session %s",
            session_id,
        )

    _emit_audit(
        db,
        event_type="portal_session_validated",
        tenant_id=tenant_id,
        portal_user_id=portal_user_id,
        outcome="success",
    )

    return SessionValidationResult(
        ok=True,
        session_id=session_id,
        portal_user_id=portal_user_id,
        portal_membership_id=portal_membership_id,
        tenant_id=tenant_id,
        engagement_id=row.engagement_id,
        portal_role=row.portal_role,
    )


def revoke_session(
    db,
    *,
    session_id: str,
    tenant_id: str,
    request_id: str | None = None,
) -> bool:
    """
    Revoke an active session.

    Returns True if the session was revoked, False if already terminal.
    """
    _set_tenant_rls(db, tenant_id)

    result = db.execute(
        text(
            """
            UPDATE portal_user_sessions
            SET    status     = 'revoked',
                   revoked_at = now()
            WHERE  id        = :id
              AND  tenant_id = :tenant_id
              AND  status    = 'active'
            RETURNING id, portal_user_id
            """
        ),
        {"id": session_id, "tenant_id": tenant_id},
    )
    revoked_rows = result.fetchall()

    if revoked_rows:
        portal_user_id = _coerce_uuid(revoked_rows[0].portal_user_id)
        _emit_audit(
            db,
            event_type="portal_session_revoked",
            tenant_id=tenant_id,
            portal_user_id=portal_user_id,
            request_id=request_id,
        )
        return True

    return False


@dataclass(frozen=True)
class SessionRevocationResult:
    """Outcome of a token-authenticated self-revocation."""

    # True if an active row was flipped to revoked; False if already terminal or unknown.
    revoked: bool
    session_id: str | None = None
    portal_user_id: str | None = None
    tenant_id: str | None = None


def revoke_session_by_token(
    db,
    *,
    raw_token: str,
    request_id: str | None = None,
) -> SessionRevocationResult:
    """
    Revoke an active portal_user_sessions row identified by its raw pnu1. token.

    The token itself is the credential — this function is intended for
    browser-driven logout where the BFF holds only the token (not the
    session_id UUID). Tenant is resolved from the session record itself, so no
    caller-supplied tenant_id is trusted.

    Idempotent: if the token has an invalid format, matches no row, or matches
    a row already in a terminal state, returns revoked=False without raising.

    RLS note
    --------
    portal_user_sessions has tenant-scoped RLS. Self-revocation arrives without
    a known tenant context, so a plain UPDATE would find zero rows. The UPDATE
    is delegated to revoke_portal_session_by_fingerprint(), a SECURITY DEFINER
    function (migration 0165) that runs as the table owner and therefore bypasses
    RLS for this single atomic operation. The resolved tenant_id is then bound
    via _set_tenant_rls() before the audit INSERT so audit-event RLS is satisfied.
    """
    if not raw_token.startswith(SESSION_TOKEN_PREFIX):
        return SessionRevocationResult(revoked=False)

    token_hex = raw_token[len(SESSION_TOKEN_PREFIX) :]

    try:
        fingerprint = _compute_lookup_fingerprint(token_hex, _get_pepper())
    except RuntimeError:
        # Pepper not configured — treat as no-op so logout still clears the cookie.
        return SessionRevocationResult(revoked=False)

    try:
        # Delegate the UPDATE to the SECURITY DEFINER function so the
        # fingerprint lookup is not hidden by the unscoped RLS policy.
        rows = db.execute(
            text(
                "SELECT session_id, tenant_id, portal_user_id"
                " FROM revoke_portal_session_by_fingerprint(:fp)"
            ),
            {"fp": fingerprint},
        ).fetchall()
    except Exception as exc:
        log.exception("revoke_session_by_token: DB error during revoke: %s", exc)
        return SessionRevocationResult(revoked=False)

    if not rows:
        return SessionRevocationResult(revoked=False)

    session_id = _coerce_uuid(rows[0].session_id)
    portal_user_id = _coerce_uuid(rows[0].portal_user_id)
    tenant_id = str(rows[0].tenant_id) if rows[0].tenant_id is not None else None

    if tenant_id is not None:
        # Set RLS context before the audit INSERT (portal_user_audit_events also
        # has RLS). The tenant was resolved server-side from the session record.
        _set_tenant_rls(db, tenant_id)
        _emit_audit(
            db,
            event_type="portal_session_revoked",
            tenant_id=tenant_id,
            portal_user_id=portal_user_id,
            request_id=request_id,
        )

    return SessionRevocationResult(
        revoked=True,
        session_id=session_id,
        portal_user_id=portal_user_id,
        tenant_id=tenant_id,
    )


# ---------------------------------------------------------------------------
# Module-level singleton (stateless — all state lives in the DB session)
# ---------------------------------------------------------------------------


class PortalUserAuthority:
    """
    Thin stateless wrapper exposing the portal user authority public API.

    All methods delegate to module-level functions.  The class exists so
    callers can hold a typed reference and for future DI if needed.
    """

    find_or_create_portal_user = staticmethod(find_or_create_portal_user)
    create_invitation = staticmethod(create_invitation)
    get_invitation_by_token = staticmethod(get_invitation_by_token)
    accept_invitation = staticmethod(accept_invitation)
    revoke_invitation = staticmethod(revoke_invitation)
    create_session = staticmethod(create_session)
    validate_session = staticmethod(validate_session)
    revoke_session = staticmethod(revoke_session)
    revoke_session_by_token = staticmethod(revoke_session_by_token)


portal_user_svc = PortalUserAuthority()
