"""api/identity_authority/audit.py — Hash-chained identity audit log.

Every identity event is logged with a SHA-256 hash chain, extending the
pattern established in admin_gateway/identity/audit.py to the unified
identity authority.

Events are written to the SecurityAuditLog table when a DB session is
available, and always emitted as structured log lines.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import threading
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

log = logging.getLogger("frostgate.identity_authority.audit")


class IdentityEventType(str, Enum):
    # Authentication
    AUTH_SUCCESS = "identity.auth.success"
    AUTH_FAILED = "identity.auth.failed"
    AUTH_PROVIDER_ERROR = "identity.auth.provider_error"
    AUTH_TENANT_MISMATCH = "identity.auth.tenant_mismatch"
    AUTH_MFA_REQUIRED = "identity.auth.mfa_required"
    # Session
    SESSION_CREATED = "identity.session.created"
    SESSION_REFRESHED = "identity.session.refreshed"
    SESSION_EXPIRED = "identity.session.expired"
    SESSION_REVOKED = "identity.session.revoked"
    SESSION_ALL_REVOKED = "identity.session.all_revoked"
    SESSION_INVALID = "identity.session.invalid"
    # MFA
    MFA_VERIFIED = "identity.mfa.verified"
    MFA_MISSING_REQUIRED = "identity.mfa.missing_required"
    # Provider
    PROVIDER_REGISTERED = "identity.provider.registered"
    OIDC_DISCOVERY_FAILED = "identity.oidc.discovery_failed"
    JWKS_REFRESH = "identity.jwks.refresh"
    # Logout
    LOGOUT = "identity.logout"
    LOGOUT_ALL = "identity.logout.all_sessions"
    # Tenant
    TENANT_RESOLVED = "identity.tenant.resolved"
    TENANT_RESOLUTION_FAILED = "identity.tenant.resolution_failed"
    TENANT_CROSS_ACCESS_DENIED = "identity.tenant.cross_access_denied"
    # Machine / agent
    MACHINE_AUTH_SUCCESS = "identity.machine.auth_success"
    MACHINE_AUTH_FAILED = "identity.machine.auth_failed"
    AGENT_AUTH_SUCCESS = "identity.agent.auth_success"
    AGENT_AUTH_FAILED = "identity.agent.auth_failed"
    # Migration
    LEGACY_SESSION_MIGRATED = "identity.migration.session_migrated"
    LEGACY_TOKEN_MIGRATED = "identity.migration.token_migrated"
    LEGACY_MIGRATION_FAILED = "identity.migration.failed"
    # Invitation (unified)
    INVITATION_CREATED = "identity.invitation.created"
    INVITATION_ACCEPTED = "identity.invitation.accepted"
    INVITATION_EXPIRED = "identity.invitation.expired"
    INVITATION_REVOKED = "identity.invitation.revoked"
    # Role / permission
    ROLE_CHANGED = "identity.role.changed"
    PERMISSION_GRANTED = "identity.permission.granted"
    PERMISSION_REVOKED = "identity.permission.revoked"


def _sha256(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode())
    return h.hexdigest()


class IdentityAuditor:
    """Hash-chained identity audit log.

    Maintains a per-process chain of audit events. Each event includes the
    hash of the previous event for tamper-evidence.

    When a DB session factory is injected (via set_db_factory), events are
    persisted to SecurityAuditLog. Otherwise they are log-only.
    """

    def __init__(self) -> None:
        self._prev_hash: str = "genesis"
        self._lock = threading.Lock()
        self._db_factory: Optional[object] = None

    def set_db_factory(self, factory: object) -> None:
        """Inject a DB session factory for persistence."""
        self._db_factory = factory

    def emit(
        self,
        event_type: IdentityEventType,
        *,
        subject: Optional[str] = None,
        tenant_id: Optional[str] = None,
        provider: Optional[str] = None,
        correlation_id: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> str:
        """Emit a hash-chained audit event. Returns event_id."""
        event_id = secrets.token_hex(16)
        ts = datetime.now(tz=timezone.utc).isoformat()
        details_str = json.dumps(details or {}, sort_keys=True)

        with self._lock:
            event_hash = _sha256(
                self._prev_hash,
                event_id,
                ts,
                event_type.value,
                subject or "",
                tenant_id or "",
                details_str,
            )
            prev = self._prev_hash
            self._prev_hash = event_hash

        safe_details = _sanitize(details or {})

        log.info(
            event_type.value,
            extra={
                "event_id": event_id,
                "event_hash": event_hash[:16],
                "prev_hash": prev[:16],
                "subject_prefix": (subject or "")[:16],
                "tenant_id": tenant_id,
                "provider": provider,
                "correlation_id": correlation_id,
                **safe_details,
            },
        )

        # Persist to DB when factory available
        if self._db_factory:
            self._persist(
                event_id=event_id,
                event_type=event_type,
                event_hash=event_hash,
                prev_hash=prev,
                ts=ts,
                subject=subject,
                tenant_id=tenant_id,
                provider=provider,
                correlation_id=correlation_id,
                details=safe_details,
            )

        return event_id

    def _persist(self, **kwargs: object) -> None:
        """Persist to SecurityAuditLog via the DB factory."""
        try:
            from api.security_audit import get_auditor as _get_core_auditor

            auditor = _get_core_auditor()
            auditor.log_event(
                action=str(kwargs.get("event_type", "")),
                actor_id=str(kwargs.get("subject") or "system"),
                tenant_id=str(kwargs.get("tenant_id") or ""),
                resource_type="identity",
                resource_id=str(kwargs.get("event_id", "")),
                scope=str(kwargs.get("provider") or "identity_authority"),
                request_id=str(kwargs.get("correlation_id") or ""),
                details=kwargs.get("details", {}),
            )
        except Exception as exc:
            log.warning(
                "identity_auditor.persist_failed",
                extra={"exc": str(exc)},
            )


def _sanitize(details: dict) -> dict:
    """Strip any secrets from audit detail dicts."""
    _REDACTED_KEYS = frozenset(
        {
            "token",
            "secret",
            "password",
            "key",
            "access_token",
            "refresh_token",
            "id_token",
            "client_secret",
            "authorization",
            "cookie",
        }
    )
    return {
        k: "[REDACTED]" if k.lower() in _REDACTED_KEYS else v
        for k, v in details.items()
    }


# Module-level singleton
_auditor = IdentityAuditor()


def get_identity_auditor() -> IdentityAuditor:
    return _auditor
