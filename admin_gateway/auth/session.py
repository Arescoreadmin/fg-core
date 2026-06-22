"""Session management with secure cookies.

Handles session creation, validation, and cookie management.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Set

from fastapi import Request, Response

from admin_gateway.auth.config import AuthConfig, get_auth_config
from admin_gateway.auth.scopes import expand_scopes

log = logging.getLogger("admin-gateway.session")


@dataclass
class Session:
    """User session data.

    Attributes:
        user_id: Unique user identifier (from OIDC sub claim)
        email: User email address
        name: User display name
        scopes: Set of authorization scopes
        claims: Raw OIDC token claims
        tenant_id: Current active tenant
        tenant_governed: True only for a tenant session issued after verified membership binding.
        created_at: Session creation timestamp
        expires_at: Session expiration timestamp
        session_id: Unique session identifier
    """

    user_id: str
    email: Optional[str] = None
    name: Optional[str] = None
    scopes: Set[str] = field(default_factory=set)
    claims: dict[str, Any] = field(default_factory=dict)
    tenant_id: Optional[str] = None
    membership_id: Optional[str] = None
    membership_version: int = 0
    identity_provider: Optional[str] = None
    identity_issuer: Optional[str] = None
    identity_subject: Optional[str] = None
    identity_type: Optional[str] = None
    role: Optional[str] = None
    binding_status: Optional[str] = None
    tenant_governed: bool = False
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0
    session_id: str = field(default_factory=lambda: secrets.token_urlsafe(16))

    def __post_init__(self) -> None:
        """Initialize derived fields."""
        if self.expires_at == 0:
            config = get_auth_config()
            self.expires_at = self.created_at + config.session_ttl_seconds
        self.scopes = expand_scopes(self.scopes)

    @property
    def is_expired(self) -> bool:
        """Check if session is expired."""
        return time.time() >= self.expires_at

    @property
    def remaining_ttl(self) -> int:
        """Get remaining TTL in seconds."""
        return max(0, int(self.expires_at - time.time()))

    def to_dict(self) -> dict[str, Any]:
        """Serialize session to dictionary."""
        return {
            "user_id": self.user_id,
            "email": self.email,
            "name": self.name,
            "scopes": list(self.scopes),
            "claims": self.claims,
            "tenant_id": self.tenant_id,
            "membership_id": self.membership_id,
            "membership_version": self.membership_version,
            "identity_provider": self.identity_provider,
            "identity_issuer": self.identity_issuer,
            "identity_subject": self.identity_subject,
            "identity_type": self.identity_type,
            "role": self.role,
            "binding_status": self.binding_status,
            "tenant_governed": self.tenant_governed,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "session_id": self.session_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Session:
        """Deserialize session from dictionary."""
        return cls(
            user_id=data["user_id"],
            email=data.get("email"),
            name=data.get("name"),
            scopes=set(data.get("scopes", [])),
            claims=data.get("claims", {}),
            tenant_id=data.get("tenant_id"),
            membership_id=data.get("membership_id"),
            membership_version=int(data.get("membership_version", 0)),
            identity_provider=data.get("identity_provider"),
            identity_issuer=data.get("identity_issuer"),
            identity_subject=data.get("identity_subject"),
            identity_type=data.get("identity_type"),
            role=data.get("role"),
            binding_status=data.get("binding_status"),
            tenant_governed=bool(data.get("tenant_governed", False)),
            created_at=data.get("created_at", time.time()),
            expires_at=data.get("expires_at", 0),
            session_id=data.get("session_id", secrets.token_urlsafe(16)),
        )


class SessionManager:
    """Manages session creation, validation, and cookie handling."""

    def __init__(self, config: Optional[AuthConfig] = None):
        """Initialize session manager.

        Args:
            config: Auth configuration (uses default if not provided)
        """
        self.config = config or get_auth_config()
        self._secret = self.config.session_secret.encode()

    def _sign(self, data: bytes) -> str:
        """Create HMAC signature for data."""
        return hmac.new(self._secret, data, hashlib.sha256).hexdigest()

    def _verify(self, data: bytes, signature: str) -> bool:
        """Verify HMAC signature using constant-time comparison."""
        expected = self._sign(data)
        return hmac.compare_digest(expected, signature)

    def encode_session(self, session: Session) -> str:
        """Encode session to signed cookie value.

        Format: base64(json) + "." + hmac_signature
        """
        data = json.dumps(session.to_dict(), separators=(",", ":")).encode()
        encoded = base64.urlsafe_b64encode(data).decode()
        signature = self._sign(data)
        return f"{encoded}.{signature}"

    def decode_session(self, cookie_value: str) -> Optional[Session]:
        """Decode and validate session from cookie value.

        Returns:
            Session if valid, None if invalid or expired
        """
        try:
            parts = cookie_value.rsplit(".", 1)
            if len(parts) != 2:
                log.warning("Invalid session cookie format")
                return None

            encoded, signature = parts
            data = base64.urlsafe_b64decode(encoded)

            if not self._verify(data, signature):
                log.warning("Session signature verification failed")
                return None

            session = Session.from_dict(json.loads(data))

            if session.is_expired:
                log.debug("Session expired: %s", session.session_id)
                return None

            return session

        except (ValueError, json.JSONDecodeError, KeyError) as e:
            log.warning("Failed to decode session: %s", e)
            return None

    def get_session(self, request: Request) -> Optional[Session]:
        """Extract and validate session from request.

        Args:
            request: FastAPI request object

        Returns:
            Session if valid, None otherwise
        """
        cookie_value = request.cookies.get(self.config.session_cookie_name)
        if not cookie_value:
            return None
        return self.decode_session(cookie_value)

    def set_session_cookie(
        self,
        response: Response,
        session: Session,
    ) -> None:
        """Set session cookie on response.

        Args:
            response: FastAPI response object
            session: Session to set
        """
        cookie_value = self.encode_session(session)

        response.set_cookie(
            key=self.config.session_cookie_name,
            value=cookie_value,
            httponly=True,
            secure=self.config.is_prod,
            samesite="strict",
            path="/",
            max_age=session.remaining_ttl,
        )

    def clear_session_cookie(self, response: Response) -> None:
        """Clear session cookie from response."""
        response.delete_cookie(
            key=self.config.session_cookie_name,
            path="/",
            httponly=True,
            secure=self.config.is_prod,
            samesite="strict",
        )

    def create_session(
        self,
        user_id: str,
        email: Optional[str] = None,
        name: Optional[str] = None,
        scopes: Optional[Set[str]] = None,
        claims: Optional[dict[str, Any]] = None,
        tenant_id: Optional[str] = None,
        membership_id: Optional[str] = None,
        membership_version: int = 0,
        identity_provider: Optional[str] = None,
        identity_issuer: Optional[str] = None,
        identity_subject: Optional[str] = None,
        identity_type: Optional[str] = None,
        role: Optional[str] = None,
        binding_status: Optional[str] = None,
        tenant_governed: bool = False,
    ) -> Session:
        """Create a new session.

        Args:
            user_id: Unique user identifier
            email: User email
            name: User display name
            scopes: Authorization scopes
            claims: OIDC token claims
            tenant_id: Default tenant
            tenant_governed: Whether verified membership binding authorized tenant access.

        Returns:
            New Session object
        """
        now = time.time()
        return Session(
            user_id=user_id,
            email=email,
            name=name,
            scopes=scopes or set(),
            claims=claims or {},
            tenant_id=tenant_id,
            membership_id=membership_id,
            membership_version=membership_version,
            identity_provider=identity_provider,
            identity_issuer=identity_issuer,
            identity_subject=identity_subject,
            identity_type=identity_type,
            role=role,
            binding_status=binding_status,
            tenant_governed=tenant_governed,
            created_at=now,
            expires_at=now + self.config.session_ttl_seconds,
        )
