"""api/identity_authority/session_authority.py — Unified session lifecycle management.

Single session authority for all FrostGate applications: console, portal, APIs.
Replaces the separate HMAC session implementations in admin_gateway and portal.

Session tokens are HMAC-SHA256 signed blobs (same as existing implementation).
Revocation is backed by Redis when available, in-memory otherwise.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

log = logging.getLogger("frostgate.identity_authority.session")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SESSION_TTL_SECONDS: int = int(os.getenv("FG_SESSION_TTL_SECONDS", "28800"))  # 8 hours
IDLE_TIMEOUT_SECONDS: int = int(os.getenv("FG_SESSION_IDLE_TIMEOUT", "3600"))  # 1 hour
REFRESH_WINDOW_SECONDS: int = 1800  # refresh in last 30 min of absolute TTL
MAX_CONCURRENT_SESSIONS: int = int(os.getenv("FG_MAX_CONCURRENT_SESSIONS", "5"))

_SESSION_VERSION = "v2"  # bump on incompatible changes


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SessionToken:
    """Issued session token."""

    token: str  # HMAC-SHA256 signed session blob
    session_id: str  # stable session identifier
    expires_at: datetime
    issued_at: datetime


@dataclass(frozen=True)
class SessionContext:
    """Validated session context."""

    session_id: str
    subject: str
    email: str
    tenant_id: Optional[str]
    identity_type: str
    provider: str
    issued_at: datetime
    expires_at: datetime
    idle_expires_at: datetime
    device_hint: Optional[str]
    revoked: bool
    mfa_verified: bool


class SessionExpiredError(Exception):
    """Session TTL has passed."""


class SessionRevokedError(Exception):
    """Session was explicitly revoked."""


class SessionInvalidError(Exception):
    """Session token is malformed or has invalid signature."""


# ---------------------------------------------------------------------------
# Revocation store — Redis-backed with in-memory fallback
# ---------------------------------------------------------------------------


class _RevocationStore:
    """Stores revoked session IDs. Thread-safe."""

    def __init__(self) -> None:
        self._mem: dict[str, float] = {}  # session_id → revoked_at_monotonic
        self._lock = threading.Lock()
        # Typed as Any because redis-py's type stubs vary by version and the
        # optional import path makes precise typing brittle. Concrete methods
        # used (setex, exists) are wrapped in try/except.
        self._redis: Any = None
        self._connect_redis()

    def _connect_redis(self) -> None:
        redis_url = os.getenv("FG_REDIS_URL", "")
        if not redis_url:
            return
        try:
            import redis as redis_lib

            self._redis = redis_lib.from_url(redis_url, decode_responses=True)
            log.info("session_authority.redis_revocation_store_connected")
        except Exception as exc:
            log.warning(
                "session_authority.redis_unavailable_using_memory",
                extra={"exc": str(exc)},
            )

    def revoke(self, session_id: str, ttl_seconds: int = SESSION_TTL_SECONDS) -> None:
        if self._redis is not None:
            try:
                key = f"fg:session:revoked:{session_id}"
                self._redis.setex(key, ttl_seconds, "1")
                return
            except Exception as exc:
                log.warning(
                    "session_authority.redis_revoke_failed", extra={"exc": str(exc)}
                )
        with self._lock:
            self._mem[session_id] = time.monotonic()
            # Prune old entries (TTL-based cleanup)
            cutoff = time.monotonic() - SESSION_TTL_SECONDS
            self._mem = {k: v for k, v in self._mem.items() if v > cutoff}

    def is_revoked(self, session_id: str) -> bool:
        if self._redis is not None:
            try:
                key = f"fg:session:revoked:{session_id}"
                return bool(self._redis.exists(key))
            except Exception as exc:
                log.warning(
                    "session_authority.redis_check_failed", extra={"exc": str(exc)}
                )
        with self._lock:
            if session_id not in self._mem:
                return False
            age = time.monotonic() - self._mem[session_id]
            return age < SESSION_TTL_SECONDS


# ---------------------------------------------------------------------------
# Session authority
# ---------------------------------------------------------------------------


class SessionAuthority:
    """Unified session lifecycle management for all FrostGate applications."""

    def __init__(self) -> None:
        self._secret = self._load_secret()
        self._store = _RevocationStore()

    @staticmethod
    def _load_secret() -> bytes:
        secret = os.getenv("FG_SESSION_SECRET", "")
        if not secret:
            log.warning(
                "session_authority.no_session_secret_using_random",
                extra={"hint": "Set FG_SESSION_SECRET in production"},
            )
            return secrets.token_bytes(32)
        return secret.encode()

    # ------------------------------------------------------------------
    # Token construction
    # ------------------------------------------------------------------

    def _sign(self, payload: str) -> str:
        """Return HMAC-SHA256 hex digest of the payload."""
        return hmac.new(self._secret, payload.encode(), hashlib.sha256).hexdigest()

    def _build_token(self, payload: dict) -> str:
        """Encode and sign a session payload."""
        import base64

        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        b64 = base64.urlsafe_b64encode(raw.encode()).decode()
        sig = self._sign(b64)
        return f"{b64}.{sig}"

    def _verify_token(self, token: str) -> dict:
        """Verify token signature and return payload dict.

        Raises SessionInvalidError on any tamper or malformation.
        """
        import base64

        try:
            b64, sig = token.rsplit(".", 1)
        except ValueError:
            raise SessionInvalidError("malformed session token")

        expected = self._sign(b64)
        if not hmac.compare_digest(expected, sig):
            raise SessionInvalidError("invalid session signature")

        try:
            raw = base64.urlsafe_b64decode(b64.encode()).decode()
            return json.loads(raw)
        except Exception as exc:
            raise SessionInvalidError(f"session payload decode failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_session(
        self,
        *,
        subject: str,
        email: str,
        tenant_id: Optional[str],
        identity_type: str = "human",
        provider: str = "unknown",
        mfa_verified: bool = False,
        device_hint: Optional[str] = None,
    ) -> SessionToken:
        """Create a new session. Returns a signed, tamper-evident session token."""
        session_id = secrets.token_urlsafe(24)
        now = int(time.time())
        expires_at_ts = now + SESSION_TTL_SECONDS
        idle_expires_at_ts = now + IDLE_TIMEOUT_SECONDS

        payload = {
            "v": _SESSION_VERSION,
            "sid": session_id,
            "sub": subject,
            "email": email,
            "tid": tenant_id,
            "it": identity_type,
            "prov": provider,
            "mfa": mfa_verified,
            "dev": device_hint,
            "iat": now,
            "exp": expires_at_ts,
            "idle_exp": idle_expires_at_ts,
        }

        token = self._build_token(payload)

        log.debug(
            "session_authority.session_created",
            extra={"sid": session_id, "provider": provider, "mfa": mfa_verified},
        )

        return SessionToken(
            token=token,
            session_id=session_id,
            issued_at=datetime.fromtimestamp(now, tz=timezone.utc),
            expires_at=datetime.fromtimestamp(expires_at_ts, tz=timezone.utc),
        )

    def validate_session(self, token: str) -> SessionContext:
        """Validate a session token and return its context.

        Raises:
            SessionInvalidError: token is malformed or has invalid signature
            SessionExpiredError: session has passed its absolute TTL
            SessionRevokedError: session was explicitly revoked
        """
        payload = self._verify_token(token)

        now = int(time.time())

        # Absolute expiry
        exp = payload.get("exp", 0)
        if now > exp:
            raise SessionExpiredError(f"session expired at {exp}")

        # Idle timeout
        idle_exp = payload.get("idle_exp", 0)
        if idle_exp and now > idle_exp:
            raise SessionExpiredError("session idle timeout reached")

        session_id: str = payload.get("sid", "")

        # Revocation check
        if self._store.is_revoked(session_id):
            raise SessionRevokedError(f"session {session_id} has been revoked")

        issued_at = payload.get("iat", 0)
        idle_expires_at_ts = payload.get("idle_exp", exp)

        return SessionContext(
            session_id=session_id,
            subject=payload.get("sub", ""),
            email=payload.get("email", ""),
            tenant_id=payload.get("tid"),
            identity_type=payload.get("it", "human"),
            provider=payload.get("prov", "unknown"),
            mfa_verified=bool(payload.get("mfa", False)),
            device_hint=payload.get("dev"),
            issued_at=datetime.fromtimestamp(issued_at, tz=timezone.utc),
            expires_at=datetime.fromtimestamp(exp, tz=timezone.utc),
            idle_expires_at=datetime.fromtimestamp(idle_expires_at_ts, tz=timezone.utc),
            revoked=False,
        )

    def refresh_session(self, token: str) -> SessionToken:
        """Rotate a session token within the refresh window.

        Returns a new token only if within the last REFRESH_WINDOW_SECONDS of TTL.
        Always revokes the old token to prevent replay.
        """
        ctx = self.validate_session(token)  # raises if invalid/expired/revoked

        now = int(time.time())
        exp_ts = int(ctx.expires_at.timestamp())
        time_remaining = exp_ts - now

        if time_remaining > REFRESH_WINDOW_SECONDS:
            raise ValueError(
                f"session not yet in refresh window ({time_remaining}s remaining, "
                f"window opens at {REFRESH_WINDOW_SECONDS}s)"
            )

        # Revoke old session before issuing new one (replay prevention)
        self._store.revoke(ctx.session_id, ttl_seconds=REFRESH_WINDOW_SECONDS + 60)

        return self.create_session(
            subject=ctx.subject,
            email=ctx.email,
            tenant_id=ctx.tenant_id,
            identity_type=ctx.identity_type,
            provider=ctx.provider,
            mfa_verified=ctx.mfa_verified,
            device_hint=ctx.device_hint,
        )

    def revoke_session(self, session_id: str) -> None:
        """Immediately invalidate a session (logout, role change, security event)."""
        self._store.revoke(session_id)
        log.info("session_authority.session_revoked", extra={"sid": session_id})

    def revoke_all_for_subject(self, subject: str, session_ids: list[str]) -> int:
        """Revoke a list of known session IDs for a subject.

        Returns count of revoked sessions.
        Note: without a session index, callers must provide known session IDs.
        Full cross-session revocation requires a session registry (future work).
        """
        for sid in session_ids:
            self._store.revoke(sid)
        log.info(
            "session_authority.all_sessions_revoked",
            extra={"subject_prefix": subject[:16], "count": len(session_ids)},
        )
        return len(session_ids)

    def extract_session_id(self, token: str) -> Optional[str]:
        """Extract session_id from a token without full validation (for logging)."""
        try:
            payload = self._verify_token(token)
            return payload.get("sid")
        except Exception:
            return None
