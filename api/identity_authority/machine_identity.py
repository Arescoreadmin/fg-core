"""api/identity_authority/machine_identity.py — Machine and service identity.

Handles authentication for non-human principals:
  - API keys (tenant service accounts, CI/CD integrations)
  - Agent tokens (autonomous governance agents)

Machine identities are validated against the tenant_api_keys table.
They never go through OIDC and have no session TTL.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from api.identity_authority.audit import (
    IdentityAuditor,
    IdentityEventType,
    get_identity_auditor,
)
from api.identity_authority.metrics import AUTH_FAILED_TOTAL, AUTH_SUCCESS_TOTAL
from api.identity_authority.models import (
    AuthenticationContext,
    CanonicalIdentity,
    IdentityProvider,
    TenantBinding,
)

log = logging.getLogger("frostgate.identity_authority.machine")


@dataclass(frozen=True)
class MachineIdentityRecord:
    """Resolved machine identity from the database."""

    key_id: str
    key_prefix: str
    tenant_id: str
    roles: frozenset[str]
    scopes: frozenset[str]
    is_active: bool
    key_hash: Optional[str] = None
    hash_alg: Optional[str] = None
    created_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None


class MachineIdentityAuthority:
    """Authenticates machine principals (API keys, agent tokens).

    Validates HMAC-SHA256 key secrets against stored hashed secrets.
    """

    def __init__(self, auditor: Optional[IdentityAuditor] = None) -> None:
        self._auditor = auditor or get_identity_auditor()

    def authenticate_api_key(
        self,
        key_id: str,
        key_secret: str,
        *,
        db: Optional[Session] = None,
        correlation_id: Optional[str] = None,
    ) -> CanonicalIdentity:
        """Validate an API key and return a CanonicalIdentity.

        Raises:
            ValueError: key not found, inactive, or secret mismatch
        """
        if db is None:
            raise ValueError("database session required for API key authentication")

        record = self._load_key_record(key_id, key_secret, db)
        if record is None:
            AUTH_FAILED_TOTAL.labels(provider="api_key", reason="not_found").inc()
            self._auditor.emit(
                IdentityEventType.MACHINE_AUTH_FAILED,
                provider="api_key",
                correlation_id=correlation_id,
                details={"reason": "key_not_found", "key_id_prefix": key_id[:8]},
            )
            raise ValueError("API key not found")

        if not record.is_active:
            AUTH_FAILED_TOTAL.labels(provider="api_key", reason="inactive").inc()
            raise ValueError("API key is inactive")

        if not self._verify_secret(key_id, key_secret, record):
            AUTH_FAILED_TOTAL.labels(provider="api_key", reason="invalid_secret").inc()
            self._auditor.emit(
                IdentityEventType.MACHINE_AUTH_FAILED,
                subject=key_id,
                tenant_id=record.tenant_id,
                provider="api_key",
                correlation_id=correlation_id,
                details={"reason": "secret_mismatch"},
            )
            raise ValueError("API key secret is invalid")

        AUTH_SUCCESS_TOTAL.labels(provider="api_key", identity_type="machine").inc()

        self._touch_last_used(record.key_prefix, db)

        return self._build_identity(record)

    def authenticate_api_key_from_state(
        self,
        request_state,
        db: Optional[Session] = None,
    ) -> Optional[CanonicalIdentity]:
        """Extract and validate an API key from request.state.auth (middleware path).

        Returns None if no API key context is present on the request.
        """
        auth_state = getattr(request_state, "auth", None)
        if auth_state is None:
            return None

        key_id = getattr(auth_state, "key_id", None)
        key_prefix = getattr(auth_state, "key_prefix", None)
        tenant_id = getattr(auth_state, "tenant_id", None)
        roles = getattr(auth_state, "roles", [])

        if not key_id:
            return None

        from api.actor_context import roles_to_permissions

        perms = roles_to_permissions(list(roles))

        now = datetime.now(tz=timezone.utc)
        provider = IdentityProvider(
            name="api_key",
            issuer="frostgate.internal",
            subject=key_prefix or key_id,
        )
        auth_ctx = AuthenticationContext(
            mfa_verified=False,
            mfa_method=None,
            auth_time=now,
            amr=[],
            acr=None,
            pkce_used=False,
            nonce_verified=False,
        )
        binding = TenantBinding(
            tenant_id=str(tenant_id or ""),
            organization_id=None,
            membership_id=None,
            roles=frozenset(roles),
            permissions=perms,
        )

        return CanonicalIdentity(
            subject=key_prefix or key_id,
            email="",
            name=f"api-key:{key_prefix or key_id[:8]}",
            email_verified=False,
            provider=provider,
            auth_context=auth_ctx,
            tenant_binding=binding,
            subscription=None,
            identity_type="machine",
            issued_at=now,
            expires_at=now,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _load_key_record(
        self, key_prefix: str, key_secret: str, db: Session
    ) -> Optional[MachineIdentityRecord]:
        """Look up an ApiKey by prefix + key_lookup hash, then verify secret.

        Uses the fast HMAC lookup path (key_lookup column) and falls back to
        the legacy SHA-256 hash path for keys minted before key_lookup existed.
        """
        from api.db_models import ApiKey
        from api.auth_scopes.helpers import (
            _key_lookup_hash,
            _get_key_pepper,
            _sha256_hex,
        )

        row = None

        # Fast path: prefix + pepper-HMAC lookup (O(1) indexed query)
        try:
            pepper = _get_key_pepper()
            lookup = _key_lookup_hash(key_secret, pepper)
            row = (
                db.query(ApiKey)
                .filter(
                    ApiKey.prefix == key_prefix,
                    ApiKey.key_lookup == lookup,
                    ApiKey.enabled.is_(True),
                )
                .first()
            )
        except Exception as exc:
            log.warning("machine_identity.lookup_error", extra={"exc": str(exc)})

        # Fallback: legacy SHA-256 lookup (pre-argon2 keys without key_lookup)
        if row is None:
            try:
                legacy_hash = _sha256_hex(key_secret)
                row = (
                    db.query(ApiKey)
                    .filter(
                        ApiKey.prefix == key_prefix,
                        ApiKey.key_hash == legacy_hash,
                        ApiKey.enabled.is_(True),
                    )
                    .first()
                )
            except Exception as exc:
                log.warning(
                    "machine_identity.legacy_lookup_error", extra={"exc": str(exc)}
                )

        if row is None:
            return None

        scopes = frozenset(filter(None, (row.scopes_csv or "").split(",")))
        return MachineIdentityRecord(
            key_id=str(row.id),
            key_prefix=str(row.prefix),
            tenant_id=str(row.tenant_id or ""),
            roles=frozenset(),
            scopes=scopes,
            is_active=bool(row.enabled),
            key_hash=row.key_hash,
            hash_alg=row.hash_alg,
            created_at=row.created_at,
            last_used_at=row.last_used_at,
        )

    def _verify_secret(
        self, key_prefix: str, secret: str, record: MachineIdentityRecord
    ) -> bool:
        """Verify the raw secret against the stored argon2id or SHA-256 hash."""
        if not record.key_hash:
            raise ValueError(
                f"API key {key_prefix!r} has no stored hash — cannot verify secret"
            )
        from api.auth_scopes.helpers import verify_key

        return verify_key(secret, record.key_hash, record.hash_alg)

    def _touch_last_used(self, key_prefix: str, db: Session) -> None:
        try:
            from api.db_models import ApiKey

            db.query(ApiKey).filter(ApiKey.prefix == key_prefix).update(
                {"last_used_at": datetime.now(tz=timezone.utc)}
            )
        except Exception:
            pass  # last_used_at update is best-effort

    def _build_identity(self, record: MachineIdentityRecord) -> CanonicalIdentity:
        from api.actor_context import roles_to_permissions

        now = datetime.now(tz=timezone.utc)
        perms = roles_to_permissions(list(record.roles))

        provider = IdentityProvider(
            name="api_key",
            issuer="frostgate.internal",
            subject=record.key_prefix,
        )
        auth_ctx = AuthenticationContext(
            mfa_verified=False,
            mfa_method=None,
            auth_time=now,
            amr=[],
            acr=None,
            pkce_used=False,
            nonce_verified=False,
        )
        binding = TenantBinding(
            tenant_id=record.tenant_id,
            organization_id=None,
            membership_id=None,
            roles=record.roles,
            permissions=perms,
        )

        return CanonicalIdentity(
            subject=record.key_prefix,
            email="",
            name=f"api-key:{record.key_prefix}",
            email_verified=False,
            provider=provider,
            auth_context=auth_ctx,
            tenant_binding=binding,
            subscription=None,
            identity_type="machine",
            issued_at=now,
            expires_at=now,
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_machine_authority: Optional[MachineIdentityAuthority] = None


def get_machine_authority() -> MachineIdentityAuthority:
    global _machine_authority
    if _machine_authority is None:
        _machine_authority = MachineIdentityAuthority()
    return _machine_authority
