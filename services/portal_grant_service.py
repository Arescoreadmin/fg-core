"""Portal Grant Service — C7 secure portal authorization.

R4.9: New portal grants are issued through credential_authority and stored in
tenant_credentials.  Existing portal_grants rows remain as the read-only
legacy compatibility source during the 14-day transition window.

Security invariants:
- Secrets are NEVER stored. Only Argon2id hashes are persisted.
- Grant secrets are raw opaque tokens (~43 chars, no fgk. prefix).
- Session IDs are 32-byte hex random tokens (64 chars, 256-bit entropy).
- All validation fails closed on any exception.
- Legacy fallback triggers ONLY on CredentialNotFoundError.absent=True.
- Revoked/expired canonical credentials do NOT fall through to legacy.
- Rate limiting: 10 per IP / 50 per tenant per 15-minute window.

Legacy fallback removal condition:
  Remove _authenticate_legacy_portal_grant and the portal_grants table scan
  after all pre-migration grants have expired.
  Portal grant TTL = 14 days.
  Removal target: migration deployment date + 15 days.
  See also: migrations/postgres/0161_portal_access_migration.sql
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import select
from sqlalchemy.orm import Session

import api.credential_authority as ca
from api.credential_authority import (
    CredentialNotFoundError,
    PortalAccessMetadata,
)
from api.db import get_engine
from api.db_models_portal import PortalGrant, PortalGrantAuditEvent, PortalGrantSession

log = logging.getLogger("frostgate.portal_grant_service")

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
    credential_id: str
    client_id: str
    engagement_id: str
    grant_type: str
    status: str
    expires_at: str
    raw_secret: str  # Shown once to operator — never persisted
    # Legacy field: set only when the underlying record is from portal_grants.
    legacy_grant_id: Optional[str] = None


@dataclass(frozen=True)
class AuthenticateResult:
    ok: bool
    session_id: Optional[str]
    expires_at: Optional[str]
    client_id: Optional[str]
    engagement_ids: list[str] = field(default_factory=list)
    denial_reason: Optional[str] = None


@dataclass(frozen=True)
class SessionValidationResult:
    ok: bool
    client_id: Optional[str]
    engagement_id: Optional[str]
    denial_code: Optional[str]
    denial_reason: Optional[str]


def _portal_role_to_grant_type(portal_role: str) -> str:
    role = (portal_role or "general").lower().strip()
    return "client_portal" if role == "general" else f"client_portal.{role}"


def _grant_type_to_role(grant_type: str) -> str:
    if not grant_type or grant_type == "client_portal":
        return "general"
    if grant_type.startswith("client_portal."):
        return grant_type[len("client_portal.") :]
    return "general"


class PortalGrantService:
    """Single source of truth for all portal authorization decisions.

    No alternate authorization paths. No bypasses. No fallback access logic
    beyond the documented 14-day legacy transition window.
    """

    # ------------------------------------------------------------------
    # Grant lifecycle — canonical (R4.9+)
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
        """Create a portal grant backed by credential_authority.

        Returns a GrantCreated with raw_secret set exactly once.
        The caller must store the secret immediately; it is not re-retrievable.
        """
        meta = PortalAccessMetadata(client_id=client_id, engagement_id=engagement_id)
        credential_slot = f"{client_id}:{engagement_id}"
        grant_type = _portal_role_to_grant_type(portal_role)

        engine = get_engine()
        result = ca.issue_credential(
            engine,
            tenant_id=tenant_id,
            credential_type="portal_access",
            credential_slot=credential_slot,
            scopes=["credential:use"],
            metadata=meta.model_dump(),
            expires_in_seconds=ttl_days * 86400,
            actor_id=created_by,
        )

        self._audit(
            db,
            tenant_id=tenant_id,
            grant_id=result.record.credential_id,
            client_id=client_id,
            engagement_id=engagement_id,
            event_type="grant.created",
            actor_id=created_by,
        )

        exp = result.record.expires_at
        expires_str = exp.isoformat() if isinstance(exp, datetime) else str(exp or "")

        assert result.plaintext_secret is not None, (
            "issuance must return plaintext_secret"
        )
        return GrantCreated(
            credential_id=result.record.credential_id,
            client_id=client_id,
            engagement_id=engagement_id,
            grant_type=grant_type,
            status="active",
            expires_at=expires_str,
            raw_secret=result.plaintext_secret,
        )

    def revoke_grant(
        self,
        db: Session,
        *,
        grant_id: str,
        tenant_id: str,
        revoked_by: str,
        reason: str = "manual_revoke",
    ) -> bool:
        """Revoke a grant. grant_id is the canonical credential_id.

        For legacy grants (portal_grants.id), also revoke in portal_grants.
        Returns True if found.
        """
        engine = get_engine()

        # Try canonical first.
        try:
            ca.revoke_credential(
                engine,
                credential_id=grant_id,
                tenant_id=tenant_id,
                actor_id=revoked_by,
                reason=reason,
            )
            self._audit(
                db,
                tenant_id=tenant_id,
                grant_id=grant_id,
                event_type="grant.revoked",
                actor_id=revoked_by,
                reason=reason,
            )
            return True
        except CredentialNotFoundError:
            pass

        # Legacy fallback: try portal_grants table.
        legacy = db.execute(
            select(PortalGrant).where(
                PortalGrant.id == grant_id,
                PortalGrant.tenant_id == tenant_id,
            )
        ).scalar_one_or_none()
        if legacy is None:
            return False
        if legacy.status == "revoked":
            return True
        now_iso = datetime.now(timezone.utc).isoformat()
        legacy.status = "revoked"
        legacy.revoked_at = now_iso
        legacy.revoked_by = revoked_by
        db.flush()
        self._audit(
            db,
            tenant_id=tenant_id,
            grant_id=grant_id,
            client_id=legacy.client_id,
            engagement_id=legacy.engagement_id,
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
    ) -> Optional[GrantCreated]:
        """Rotate a portal grant via credential_authority.

        grant_id is the canonical credential_id.  Locates the active credential
        by tenant_id + credential_type + credential_slot derived from metadata,
        then calls rotate_credential.

        For legacy grants: revokes the legacy grant and issues a new canonical
        credential, creating a clean canonical record for the replacement.

        Returns the new GrantCreated, or None if the grant is not found.
        """
        engine = get_engine()

        # Try canonical path: find the credential to get its slot.
        try:
            rec = ca.get_credential(engine, grant_id, tenant_id)
        except CredentialNotFoundError:
            rec = None

        if rec is not None and rec.credential_type == "portal_access":
            result = ca.rotate_credential(
                engine,
                tenant_id=tenant_id,
                credential_type="portal_access",
                credential_slot=rec.credential_slot,
                actor_id=rotated_by,
                expires_in_seconds=ttl_days * 86400,
            )
            self._audit(
                db,
                tenant_id=tenant_id,
                grant_id=result.record.credential_id,
                event_type="grant.rotated",
                actor_id=rotated_by,
                reason=f"rotation_of:{grant_id}",
            )
            meta = result.record.metadata or {}
            exp = result.record.expires_at
            expires_str = (
                exp.isoformat() if isinstance(exp, datetime) else str(exp or "")
            )
            assert result.plaintext_secret is not None
            return GrantCreated(
                credential_id=result.record.credential_id,
                client_id=meta.get("client_id", ""),
                engagement_id=meta.get("engagement_id", ""),
                grant_type=_portal_role_to_grant_type("general"),
                status="active",
                expires_at=expires_str,
                raw_secret=result.plaintext_secret,
            )

        # Legacy path: find in portal_grants, revoke, and create new canonical.
        legacy = db.execute(
            select(PortalGrant).where(
                PortalGrant.id == grant_id,
                PortalGrant.tenant_id == tenant_id,
                PortalGrant.status == "active",
            )
        ).scalar_one_or_none()
        if legacy is None:
            return None

        now_iso = datetime.now(timezone.utc).isoformat()
        legacy.status = "revoked"
        legacy.revoked_at = now_iso
        legacy.revoked_by = rotated_by
        db.flush()
        self._audit(
            db,
            tenant_id=tenant_id,
            grant_id=grant_id,
            client_id=legacy.client_id,
            engagement_id=legacy.engagement_id,
            event_type="grant.rotated",
            actor_id=rotated_by,
        )

        return self.create_grant(
            db,
            tenant_id=tenant_id,
            client_id=legacy.client_id,
            engagement_id=legacy.engagement_id,
            created_by=rotated_by,
            ttl_days=ttl_days,
        )

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
        """Verify a raw portal secret and create a server-side session.

        Canonical path: validate_credential(portal_access) → indexed lookup.
        Legacy fallback: triggered ONLY on CredentialNotFoundError.absent=True.
        Do NOT fall back on: revoked, expired, hash mismatch, or any exception
        other than explicit "absent" — that would grant a second life to an
        invalid credential.
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

        engine = get_engine()
        principal: ca.CredentialPrincipal | None = None
        use_legacy = False

        try:
            principal = ca.validate_credential(
                engine,
                raw_secret,
                credential_type="portal_access",
            )
        except CredentialNotFoundError as exc:
            if exc.absent:
                # Canonical store has no record → try legacy portal_grants.
                use_legacy = True
            else:
                # Found but invalid (revoked, expired, hash mismatch).
                # Do NOT fall through — fail closed.
                self._audit(
                    db,
                    tenant_id=tenant_id,
                    event_type="grant.denied",
                    ip_address=ip_address,
                    user_agent=user_agent,
                    reason="canonical_rejected",
                )
                return _denied
        except Exception:
            # Internal authority failure — fail closed, no legacy fallback.
            log.exception(
                "credential_authority.validate_credential raised unexpectedly"
            )
            return _denied

        if principal is not None:
            # Canonical credential found — validate tenant binding.
            if principal.tenant_id != tenant_id:
                self._audit(
                    db,
                    tenant_id=tenant_id,
                    event_type="grant.denied",
                    ip_address=ip_address,
                    user_agent=user_agent,
                    reason="tenant_mismatch",
                )
                return _denied

            meta = principal.metadata or {}
            client_id = meta.get("client_id", "")
            engagement_id = (meta or {}).get("engagement_id", "")

            return self._create_session(
                db,
                tenant_id=tenant_id,
                client_id=client_id,
                engagement_id=engagement_id,
                grant_id=principal.credential_id,
                ip_address=ip_address,
                user_agent=user_agent,
            )

        if use_legacy:
            return self._authenticate_legacy_portal_grant(
                db,
                tenant_id=tenant_id,
                raw_secret=raw_secret,
                ip_address=ip_address,
                user_agent=user_agent,
            )

        return _denied

    def _authenticate_legacy_portal_grant(
        self,
        db: Session,
        *,
        tenant_id: str,
        raw_secret: str,
        ip_address: str,
        user_agent: str,
    ) -> AuthenticateResult:
        """Legacy Argon2id scan against portal_grants.

        TRANSITION WINDOW ONLY — remove after migration deployment + 15 days.
        See: migrations/postgres/0161_portal_access_migration.sql
        """
        _denied = AuthenticateResult(
            ok=False,
            session_id=None,
            expires_at=None,
            client_id=None,
            denial_reason="invalid_secret",
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

        return self._create_session(
            db,
            tenant_id=tenant_id,
            client_id=matched.client_id,
            engagement_id=matched.engagement_id,
            grant_id=matched.id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    def _create_session(
        self,
        db: Session,
        *,
        tenant_id: str,
        client_id: str,
        engagement_id: str,
        grant_id: str,
        ip_address: str,
        user_agent: str,
    ) -> AuthenticateResult:
        """Create a server-side portal session and return the result."""
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        session_expires = now + timedelta(hours=_SESSION_TTL_HOURS)
        session_id = secrets.token_hex(32)

        db.add(
            PortalGrantSession(
                id=session_id,
                tenant_id=tenant_id,
                client_id=client_id,
                auth_grant_id=grant_id,
                created_at=now_iso,
                expires_at=session_expires.isoformat(),
                ip_address=ip_address[:64],
                user_agent=user_agent[:512],
            )
        )
        db.flush()

        self._audit(
            db,
            tenant_id=tenant_id,
            grant_id=grant_id,
            client_id=client_id,
            engagement_id=engagement_id,
            event_type="grant.used",
            ip_address=ip_address,
            user_agent=user_agent,
        )

        # Collect all active engagements for this client.
        active_canonical = _list_canonical_engagement_ids(
            client_id=client_id,
            tenant_id=tenant_id,
        )
        active_legacy = _list_legacy_engagement_ids(
            db, client_id=client_id, tenant_id=tenant_id, now_iso=now_iso
        )
        engagement_ids = sorted(set(active_canonical) | set(active_legacy))
        if engagement_id and engagement_id not in engagement_ids:
            engagement_ids.append(engagement_id)

        return AuthenticateResult(
            ok=True,
            session_id=session_id,
            expires_at=session_expires.isoformat(),
            client_id=client_id,
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
        engagement_id: Optional[str] = None,
    ) -> SessionValidationResult:
        """Validate a portal session.

        If engagement_id is supplied, also verifies that an active grant exists
        for (client_id, engagement_id) in either canonical or legacy store.
        Fails closed on any exception.
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

        # Verify active grant for this engagement in canonical or legacy store.
        has_canonical = _has_canonical_grant(
            client_id=session.client_id,
            engagement_id=engagement_id,
            tenant_id=tenant_id,
        )
        if not has_canonical:
            try:
                legacy_grant = db.execute(
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
                legacy_grant = None

            if legacy_grant is None:
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
        grant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        engagement_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        reason: Optional[str] = None,
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


# ---------------------------------------------------------------------------
# Module-level helpers (avoid repeated engine/db queries in hot paths)
# ---------------------------------------------------------------------------


def _list_canonical_engagement_ids(
    *,
    client_id: str,
    tenant_id: str,
) -> list[str]:
    """Return engagement_ids from active canonical portal_access credentials for client."""
    try:
        engine = get_engine()
        creds = ca.list_credentials(
            engine,
            tenant_id,
            credential_type="portal_access",
            status="active",
        )
        ids = []
        for cred in creds:
            meta = cred.metadata or {}
            if (
                meta.get("client_id") == client_id
                and meta.get("validation_mode") != "legacy_fallback_only"
            ):
                eid = meta.get("engagement_id")
                if eid:
                    ids.append(eid)
        return ids
    except Exception:
        return []


def _list_legacy_engagement_ids(
    db: Session,
    *,
    client_id: str,
    tenant_id: str,
    now_iso: str,
) -> list[str]:
    """Return engagement_ids from active legacy portal_grants for client."""
    try:
        grants = (
            db.execute(
                select(PortalGrant).where(
                    PortalGrant.tenant_id == tenant_id,
                    PortalGrant.client_id == client_id,
                    PortalGrant.status == "active",
                    PortalGrant.expires_at > now_iso,
                    PortalGrant.revoked_at.is_(None),
                )
            )
            .scalars()
            .all()
        )
        return [g.engagement_id for g in grants]
    except Exception:
        return []


def _has_canonical_grant(
    *,
    client_id: str,
    engagement_id: str,
    tenant_id: str,
) -> bool:
    """Return True if an active canonical portal_access credential exists for the binding."""
    try:
        engine = get_engine()
        creds = ca.list_credentials(
            engine,
            tenant_id,
            credential_type="portal_access",
            status="active",
        )
        for cred in creds:
            meta = cred.metadata or {}
            if (
                meta.get("client_id") == client_id
                and meta.get("engagement_id") == engagement_id
                and meta.get("validation_mode") != "legacy_fallback_only"
            ):
                return True
        return False
    except Exception:
        return False
