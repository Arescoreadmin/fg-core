"""Portal Grant Service — C7 secure portal authorization.

Replaces plaintext client_access_code with hashed, expiring, revocable,
engagement-bound portal grants backed by Argon2id.

Security invariants:
- Secrets are NEVER stored. Only Argon2id hashes are persisted.
- Grant secrets are 32-byte URL-safe random tokens (~43 chars).
- Session IDs are 32-byte hex random tokens (64 chars, 256-bit entropy).
- All validation fails closed on any exception.
- Argon2id params: time_cost=3, memory=64MiB, parallelism=4 (OWASP compliant).
- Rate limiting: 10 per IP / 50 per tenant per 15-minute window.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models_portal import PortalGrant, PortalGrantAuditEvent, PortalGrantSession

_PH = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MiB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

_GRANT_TTL_DAYS = 14
_SESSION_TTL_HOURS = 8
_RATE_LIMIT_WINDOW_S = 900  # 15 minutes
_RATE_LIMIT_MAX_PER_IP = 10
_RATE_LIMIT_MAX_PER_TENANT = 50

_rl_lock = threading.Lock()
_rl_buckets: dict[str, tuple[int, float]] = {}  # key → (count, reset_at_monotonic)


def _check_rate_limit(key: str, max_count: int) -> bool:
    now = time.monotonic()
    with _rl_lock:
        entry = _rl_buckets.get(key)
        if entry is None or now >= entry[1]:
            _rl_buckets[key] = (1, now + _RATE_LIMIT_WINDOW_S)
            return True
        count, reset_at = entry
        if count >= max_count:
            return False
        _rl_buckets[key] = (count + 1, reset_at)
        return True


@dataclass(frozen=True)
class GrantCreated:
    grant: PortalGrant
    raw_secret: str  # Shown once to operator — never persisted


@dataclass(frozen=True)
class AuthenticateResult:
    ok: bool
    session_id: str | None
    expires_at: str | None
    client_id: str | None
    engagement_ids: list[str] = field(default_factory=list)
    denial_reason: str | None = None


@dataclass(frozen=True)
class SessionValidationResult:
    ok: bool
    client_id: str | None
    engagement_id: str | None
    denial_code: str | None
    denial_reason: str | None


class PortalGrantService:
    """Single source of truth for all portal authorization decisions.

    No alternate authorization paths. No bypasses. No fallback access logic.
    """

    # ------------------------------------------------------------------
    # Grant lifecycle
    # ------------------------------------------------------------------

    def create_grant(
        self,
        db: Session,
        *,
        tenant_id: str,
        client_id: str,
        engagement_id: str,
        created_by: str,
        ttl_days: int = _GRANT_TTL_DAYS,
        portal_role: str = "general",
    ) -> GrantCreated:
        """Create a portal grant. Returns (grant, raw_secret). Raw secret is shown once."""
        raw_secret = secrets.token_urlsafe(32)
        grant_hash = _PH.hash(raw_secret)
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=ttl_days)
        # Encode view type in grant_type so the portal can route to the right layout.
        # "general" maps to the legacy "client_portal" value for backwards compat.
        _role = (portal_role or "general").lower().strip()
        _grant_type = (
            "client_portal" if _role == "general" else f"client_portal.{_role}"
        )

        grant = PortalGrant(
            id=secrets.token_hex(16),
            tenant_id=tenant_id,
            client_id=client_id,
            engagement_id=engagement_id,
            grant_type=_grant_type,
            grant_hash=grant_hash,
            created_by=created_by,
            created_at=now.isoformat(),
            expires_at=expires.isoformat(),
            status="active",
            rotation_counter=0,
        )
        db.add(grant)
        db.flush()
        self._audit(
            db,
            tenant_id=tenant_id,
            grant_id=grant.id,
            client_id=client_id,
            engagement_id=engagement_id,
            event_type="grant.created",
            actor_id=created_by,
        )
        return GrantCreated(grant=grant, raw_secret=raw_secret)

    def revoke_grant(
        self,
        db: Session,
        *,
        grant_id: str,
        tenant_id: str,
        revoked_by: str,
        reason: str = "manual_revoke",
    ) -> bool:
        """Revoke a grant immediately. Returns True if found."""
        grant = db.execute(
            select(PortalGrant).where(
                PortalGrant.id == grant_id,
                PortalGrant.tenant_id == tenant_id,
            )
        ).scalar_one_or_none()
        if grant is None:
            return False
        if grant.status == "revoked":
            return True
        now_iso = datetime.now(timezone.utc).isoformat()
        grant.status = "revoked"
        grant.revoked_at = now_iso
        grant.revoked_by = revoked_by
        db.flush()
        self._audit(
            db,
            tenant_id=tenant_id,
            grant_id=grant_id,
            client_id=grant.client_id,
            engagement_id=grant.engagement_id,
            event_type="grant.revoked",
            actor_id=revoked_by,
            reason=reason,
        )
        return True

    def rotate_grant(
        self,
        db: Session,
        *,
        grant_id: str,
        tenant_id: str,
        rotated_by: str,
        ttl_days: int = _GRANT_TTL_DAYS,
    ) -> GrantCreated | None:
        """Rotate: revoke old grant, create new one with incremented rotation_counter.

        Old secret is immediately invalid. Returns new (grant, raw_secret) or None if not found.
        """
        old = db.execute(
            select(PortalGrant).where(
                PortalGrant.id == grant_id,
                PortalGrant.tenant_id == tenant_id,
                PortalGrant.status == "active",
            )
        ).scalar_one_or_none()
        if old is None:
            return None

        now_iso = datetime.now(timezone.utc).isoformat()
        old.status = "revoked"
        old.revoked_at = now_iso
        old.revoked_by = rotated_by
        db.flush()
        self._audit(
            db,
            tenant_id=tenant_id,
            grant_id=grant_id,
            client_id=old.client_id,
            engagement_id=old.engagement_id,
            event_type="grant.rotated",
            actor_id=rotated_by,
        )

        raw_secret = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        new_grant = PortalGrant(
            id=secrets.token_hex(16),
            tenant_id=tenant_id,
            client_id=old.client_id,
            engagement_id=old.engagement_id,
            grant_type=old.grant_type,
            grant_hash=_PH.hash(raw_secret),
            created_by=rotated_by,
            created_at=now.isoformat(),
            expires_at=(now + timedelta(days=ttl_days)).isoformat(),
            status="active",
            rotation_counter=old.rotation_counter + 1,
        )
        db.add(new_grant)
        db.flush()
        self._audit(
            db,
            tenant_id=tenant_id,
            grant_id=new_grant.id,
            client_id=new_grant.client_id,
            engagement_id=new_grant.engagement_id,
            event_type="grant.created",
            actor_id=rotated_by,
            reason=f"rotation_of:{grant_id}",
        )
        return GrantCreated(grant=new_grant, raw_secret=raw_secret)

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate(
        self,
        db: Session,
        *,
        tenant_id: str,
        raw_secret: str,
        ip_address: str,
        user_agent: str,
    ) -> AuthenticateResult:
        """Verify a raw secret against all active grants for the tenant.

        Creates a server-side session on success. Writes audit event on both
        success and failure. Rate-limits by IP and tenant.
        """
        _denied = AuthenticateResult(
            ok=False,
            session_id=None,
            expires_at=None,
            client_id=None,
            denial_reason="invalid_secret",
        )

        if not _check_rate_limit(f"pg_ip:{ip_address}", _RATE_LIMIT_MAX_PER_IP):
            self._audit(
                db,
                tenant_id=tenant_id,
                event_type="grant.denied",
                ip_address=ip_address,
                user_agent=user_agent,
                reason="rate_limit_ip",
            )
            return AuthenticateResult(
                ok=False,
                session_id=None,
                expires_at=None,
                client_id=None,
                denial_reason="rate_limited",
            )

        if not _check_rate_limit(f"pg_ten:{tenant_id}", _RATE_LIMIT_MAX_PER_TENANT):
            self._audit(
                db,
                tenant_id=tenant_id,
                event_type="grant.denied",
                ip_address=ip_address,
                user_agent=user_agent,
                reason="rate_limit_tenant",
            )
            return AuthenticateResult(
                ok=False,
                session_id=None,
                expires_at=None,
                client_id=None,
                denial_reason="rate_limited",
            )

        now_iso = datetime.now(timezone.utc).isoformat()
        active_grants = (
            db.execute(
                select(PortalGrant).where(
                    PortalGrant.tenant_id == tenant_id,
                    PortalGrant.status == "active",
                    PortalGrant.expires_at > now_iso,
                    PortalGrant.revoked_at.is_(None),
                )
            )
            .scalars()
            .all()
        )

        matched: PortalGrant | None = None
        for g in active_grants:
            try:
                _PH.verify(g.grant_hash, raw_secret)
                matched = g
                break
            except (VerifyMismatchError, VerificationError, InvalidHashError):
                continue

        if matched is None:
            self._audit(
                db,
                tenant_id=tenant_id,
                event_type="grant.denied",
                ip_address=ip_address,
                user_agent=user_agent,
                reason="no_matching_grant",
            )
            return _denied

        # All grants for this client (accessible engagement_ids)
        client_grants = (
            db.execute(
                select(PortalGrant).where(
                    PortalGrant.tenant_id == tenant_id,
                    PortalGrant.client_id == matched.client_id,
                    PortalGrant.status == "active",
                    PortalGrant.expires_at > now_iso,
                    PortalGrant.revoked_at.is_(None),
                )
            )
            .scalars()
            .all()
        )
        engagement_ids = [g.engagement_id for g in client_grants]

        now = datetime.now(timezone.utc)
        session_expires = now + timedelta(hours=_SESSION_TTL_HOURS)
        session_id = secrets.token_hex(32)

        db.add(
            PortalGrantSession(
                id=session_id,
                tenant_id=tenant_id,
                client_id=matched.client_id,
                auth_grant_id=matched.id,
                created_at=now.isoformat(),
                expires_at=session_expires.isoformat(),
                ip_address=ip_address[:64],
                user_agent=user_agent[:512],
            )
        )
        matched.last_used_at = now.isoformat()
        db.flush()

        self._audit(
            db,
            tenant_id=tenant_id,
            grant_id=matched.id,
            client_id=matched.client_id,
            engagement_id=matched.engagement_id,
            event_type="grant.used",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        return AuthenticateResult(
            ok=True,
            session_id=session_id,
            expires_at=session_expires.isoformat(),
            client_id=matched.client_id,
            engagement_ids=engagement_ids,
        )

    # ------------------------------------------------------------------
    # Session validation
    # ------------------------------------------------------------------

    def validate_session(
        self,
        db: Session,
        *,
        session_id: str,
        tenant_id: str,
        engagement_id: str | None = None,
    ) -> SessionValidationResult:
        """Validate a portal session.

        If engagement_id is supplied, also verifies that an active grant exists
        for (client_id, engagement_id). Fails closed on any exception.
        """
        _invalid = SessionValidationResult(
            ok=False,
            client_id=None,
            engagement_id=None,
            denial_code="PORTAL_SESSION_INVALID",
            denial_reason="Invalid or expired session",
        )
        if not session_id:
            return _invalid

        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            session = db.execute(
                select(PortalGrantSession).where(
                    PortalGrantSession.id == session_id,
                    PortalGrantSession.tenant_id == tenant_id,
                    PortalGrantSession.revoked_at.is_(None),
                    PortalGrantSession.expires_at > now_iso,
                )
            ).scalar_one_or_none()
        except Exception:
            return _invalid

        if session is None:
            return _invalid

        # Best-effort last_seen update
        try:
            session.last_seen_at = now_iso
            db.flush()
        except Exception:
            pass

        if engagement_id is None:
            return SessionValidationResult(
                ok=True,
                client_id=session.client_id,
                engagement_id=None,
                denial_code=None,
                denial_reason=None,
            )

        # Verify active grant for this engagement
        try:
            grant = db.execute(
                select(PortalGrant).where(
                    PortalGrant.tenant_id == tenant_id,
                    PortalGrant.client_id == session.client_id,
                    PortalGrant.engagement_id == engagement_id,
                    PortalGrant.status == "active",
                    PortalGrant.revoked_at.is_(None),
                    PortalGrant.expires_at > now_iso,
                )
            ).scalar_one_or_none()
        except Exception:
            return _invalid

        if grant is None:
            return SessionValidationResult(
                ok=False,
                client_id=session.client_id,
                engagement_id=None,
                denial_code="PORTAL_ENGAGEMENT_ACCESS_DENIED",
                denial_reason="No active portal grant for this engagement",
            )

        return SessionValidationResult(
            ok=True,
            client_id=session.client_id,
            engagement_id=engagement_id,
            denial_code=None,
            denial_reason=None,
        )

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def revoke_session(
        self,
        db: Session,
        *,
        session_id: str,
        tenant_id: str,
    ) -> bool:
        """Revoke a portal session (logout). Returns True if found."""
        session = db.execute(
            select(PortalGrantSession).where(
                PortalGrantSession.id == session_id,
                PortalGrantSession.tenant_id == tenant_id,
            )
        ).scalar_one_or_none()
        if session is None:
            return False
        session.revoked_at = datetime.now(timezone.utc).isoformat()
        db.flush()
        return True

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def list_grants(
        self,
        db: Session,
        *,
        tenant_id: str,
        engagement_id: str,
    ) -> list[PortalGrant]:
        return list(
            db.execute(
                select(PortalGrant)
                .where(
                    PortalGrant.tenant_id == tenant_id,
                    PortalGrant.engagement_id == engagement_id,
                )
                .order_by(PortalGrant.created_at.desc())
            )
            .scalars()
            .all()
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _audit(
        self,
        db: Session,
        *,
        tenant_id: str,
        event_type: str,
        grant_id: str | None = None,
        client_id: str | None = None,
        engagement_id: str | None = None,
        actor_id: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        reason: str | None = None,
    ) -> None:
        db.add(
            PortalGrantAuditEvent(
                id=secrets.token_hex(16),
                tenant_id=tenant_id,
                grant_id=grant_id,
                client_id=client_id,
                engagement_id=engagement_id,
                event_type=event_type,
                actor_id=actor_id,
                ip_address=(ip_address or "")[:64] or None,
                user_agent=(user_agent or "")[:512] or None,
                reason=reason,
                created_at=datetime.now(timezone.utc).isoformat(),
            )
        )
        db.flush()


portal_grant_svc = PortalGrantService()
