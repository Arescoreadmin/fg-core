"""api/identity_authority/migration.py — Legacy session migration.

Bridges legacy portal HMAC sessions and admin_gateway sessions to the
unified IdentityAuthority session format.

Migration is transparent: callers validate a legacy token and receive
a new unified session token. The legacy token is invalidated.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from api.identity_authority.audit import (
    IdentityAuditor,
    IdentityEventType,
    get_identity_auditor,
)
from api.identity_authority.metrics import LEGACY_MIGRATION_TOTAL
from api.identity_authority.models import (
    AuthenticationContext,
    CanonicalIdentity,
    IdentityProvider,
    TenantBinding,
)

log = logging.getLogger("frostgate.identity_authority.migration")


@dataclass(frozen=True)
class LegacySessionPayload:
    """Parsed payload from a legacy portal or admin_gateway session."""

    subject: str
    email: str
    tenant_id: Optional[str]
    roles: list[str]
    issued_at: int
    expires_at: int
    session_id: Optional[str]
    legacy_format: str  # "portal_v1" | "admin_gw_v1"


class LegacyMigrationError(Exception):
    """Legacy token is invalid, expired, or format is unrecognised."""

    def __init__(self, message: str, code: str = "MIGRATION_FAILED"):
        super().__init__(message)
        self.code = code


class LegacySessionMigrator:
    """Validates and migrates legacy session tokens to unified sessions.

    Supports:
      - Portal v1: `base64(json).hmac_sha256` signed with PORTAL_PASSWORD
      - Admin gateway v1: same format, signed with FG_SESSION_SECRET or ADMIN_SESSION_SECRET
    """

    def __init__(self, auditor: Optional[IdentityAuditor] = None) -> None:
        self._auditor = auditor or get_identity_auditor()
        self._portal_secret: bytes = (os.getenv("PORTAL_PASSWORD") or "").encode()
        self._session_secret: bytes = (os.getenv("FG_SESSION_SECRET") or "").encode()
        admin_raw = os.getenv("ADMIN_SESSION_SECRET")
        self._admin_secret: bytes = (
            admin_raw.encode() if isinstance(admin_raw, str) else self._session_secret
        )

    def migrate(
        self,
        legacy_token: str,
        *,
        correlation_id: Optional[str] = None,
    ) -> LegacySessionPayload:
        """Validate a legacy token and return its payload.

        The caller is responsible for issuing a new unified session token
        via IdentityAuthority.create_session().

        Raises:
            LegacyMigrationError: token invalid, expired, or unknown format
        """
        payload = self._try_portal_v1(legacy_token)
        if payload is not None:
            self._emit_success(payload, correlation_id)
            return payload

        payload = self._try_admin_gw_v1(legacy_token)
        if payload is not None:
            self._emit_success(payload, correlation_id)
            return payload

        LEGACY_MIGRATION_TOTAL.labels(result="invalid").inc()
        self._auditor.emit(
            IdentityEventType.LEGACY_MIGRATION_FAILED,
            correlation_id=correlation_id,
            details={"reason": "unknown_format"},
        )
        raise LegacyMigrationError(
            "unrecognised legacy token format", code="UNKNOWN_FORMAT"
        )

    def build_identity_from_legacy(
        self, payload: LegacySessionPayload
    ) -> CanonicalIdentity:
        """Construct a CanonicalIdentity from a validated legacy payload."""
        from api.actor_context import roles_to_permissions

        perms = roles_to_permissions(payload.roles)

        issued_at = datetime.fromtimestamp(payload.issued_at, tz=timezone.utc)
        expires_at = datetime.fromtimestamp(payload.expires_at, tz=timezone.utc)

        binding = (
            TenantBinding(
                tenant_id=payload.tenant_id,
                organization_id=None,
                membership_id=None,
                roles=frozenset(payload.roles),
                permissions=perms,
            )
            if payload.tenant_id
            else None
        )

        provider_name = (
            "portal_legacy" if payload.legacy_format == "portal_v1" else "admin_legacy"
        )
        provider = IdentityProvider(
            name=provider_name,
            issuer="frostgate.internal.legacy",
            subject=payload.subject,
        )
        auth_ctx = AuthenticationContext(
            mfa_verified=False,
            mfa_method=None,
            auth_time=issued_at,
            amr=["legacy"],
            acr=None,
            pkce_used=False,
            nonce_verified=False,
        )

        return CanonicalIdentity(
            subject=payload.subject,
            email=payload.email,
            name=payload.email,
            email_verified=False,
            provider=provider,
            auth_context=auth_ctx,
            tenant_binding=binding,
            subscription=None,
            identity_type="human",
            issued_at=issued_at,
            expires_at=expires_at,
        )

    # ------------------------------------------------------------------
    # Format-specific parsers
    # ------------------------------------------------------------------

    def _try_portal_v1(self, token: str) -> Optional[LegacySessionPayload]:
        """Try to parse a portal v1 token (signed with PORTAL_PASSWORD)."""
        if not self._portal_secret:
            return None
        return self._parse_hmac_token(token, self._portal_secret, "portal_v1")

    def _try_admin_gw_v1(self, token: str) -> Optional[LegacySessionPayload]:
        """Try to parse an admin_gateway v1 token."""
        for secret in (self._admin_secret, self._session_secret):
            if not secret:
                continue
            result = self._parse_hmac_token(token, secret, "admin_gw_v1")
            if result is not None:
                return result
        return None

    def _parse_hmac_token(
        self, token: str, secret: bytes, format_name: str
    ) -> Optional[LegacySessionPayload]:
        """Parse and verify a base64(json).hmac_sha256 token."""
        try:
            b64, sig = token.rsplit(".", 1)
        except ValueError:
            return None

        expected = hmac.new(secret, b64.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return None

        try:
            raw = base64.urlsafe_b64decode(b64.encode() + b"==").decode()
            data = json.loads(raw)
        except Exception:
            return None

        now = int(time.time())
        exp = int(data.get("exp", 0) or data.get("expires_at", 0))
        iat = int(data.get("iat", 0) or data.get("issued_at", 0))

        if exp and now > exp:
            LEGACY_MIGRATION_TOTAL.labels(result="invalid").inc()
            raise LegacyMigrationError(
                f"legacy session expired at {exp}", code="LEGACY_TOKEN_EXPIRED"
            )

        subject = (
            data.get("sub")
            or data.get("subject")
            or data.get("user_id")
            or data.get("email")
            or ""
        )
        email = data.get("email") or ""
        tenant_id = data.get("tid") or data.get("tenant_id") or None
        roles_raw = data.get("roles") or []
        if isinstance(roles_raw, str):
            roles_raw = [roles_raw]
        session_id = data.get("sid") or data.get("session_id") or None

        return LegacySessionPayload(
            subject=str(subject),
            email=str(email),
            tenant_id=str(tenant_id) if tenant_id else None,
            roles=list(roles_raw),
            issued_at=iat,
            expires_at=exp,
            session_id=session_id,
            legacy_format=format_name,
        )

    def _emit_success(
        self, payload: LegacySessionPayload, correlation_id: Optional[str]
    ) -> None:
        LEGACY_MIGRATION_TOTAL.labels(result="success").inc()
        self._auditor.emit(
            IdentityEventType.LEGACY_SESSION_MIGRATED,
            subject=payload.subject,
            tenant_id=payload.tenant_id,
            correlation_id=correlation_id,
            details={"format": payload.legacy_format},
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_migrator: Optional[LegacySessionMigrator] = None


def get_legacy_migrator() -> LegacySessionMigrator:
    global _migrator
    if _migrator is None:
        _migrator = LegacySessionMigrator()
    return _migrator
