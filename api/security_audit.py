"""
Security Audit Logging for FrostGate Core.

Production-grade security event logging for SaaS compliance:
- Authentication events (success, failure, rate limits)
- Key management events (create, revoke, rotate)
- Suspicious activity detection
- Structured logging for SIEM integration
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from fastapi import Request

log = logging.getLogger("frostgate.security")


_TRUE = {"1", "true", "yes", "y", "on"}


class AuditPersistenceError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}:{message}")
        self.code = code
        self.message = message


def _is_prod_like() -> bool:
    return (os.getenv("FG_ENV") or "").strip().lower() in {
        "prod",
        "production",
        "staging",
    }


def _canonical_event_payload(record: dict[str, Any]) -> bytes:
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _compute_entry_hash(prev_hash: str, record: dict[str, Any]) -> str:
    return hashlib.sha256(
        prev_hash.encode("utf-8") + b"|" + _canonical_event_payload(record)
    ).hexdigest()


class EventType(str, Enum):
    """Security event types for audit logging."""

    # Authentication events
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    AUTH_KEY_EXPIRED = "auth_key_expired"
    AUTH_KEY_DISABLED = "auth_key_disabled"
    AUTH_SCOPE_DENIED = "auth_scope_denied"
    AUTH_TENANT_INVALID = "auth_tenant_invalid"

    # Rate limiting events
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    RATE_LIMIT_WARNING = "rate_limit_warning"

    # Key management events
    KEY_CREATED = "key_created"
    KEY_REVOKED = "key_revoked"
    KEY_ROTATED = "key_rotated"
    KEY_EXPIRED = "key_expired"

    # Suspicious activity
    SUSPICIOUS_IP = "suspicious_ip"
    BRUTE_FORCE_DETECTED = "brute_force_detected"
    ANOMALOUS_PATTERN = "anomalous_pattern"

    # System events
    CONFIG_CHANGED = "config_changed"
    STARTUP = "startup"
    SHUTDOWN = "shutdown"

    # Admin actions
    ADMIN_ACTION = "admin_action"


class Severity(str, Enum):
    """Severity levels for audit events."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """Structured security audit event."""

    event_type: EventType
    success: bool = True
    severity: Severity = Severity.INFO

    # Actor information
    tenant_id: Optional[str] = None
    key_prefix: Optional[str] = None
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None

    # Request context
    request_id: Optional[str] = None
    request_path: Optional[str] = None
    request_method: Optional[str] = None

    # Event details
    reason: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)

    # Timing
    timestamp: Optional[int] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = int(time.time())

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging/persistence."""
        return {
            "event_type": self.event_type.value
            if isinstance(self.event_type, EventType)
            else self.event_type,
            "success": self.success,
            "severity": self.severity.value
            if isinstance(self.severity, Severity)
            else self.severity,
            "tenant_id": self.tenant_id,
            "key_prefix": self.key_prefix[:16]
            if self.key_prefix
            else None,  # Truncate for security
            "client_ip": self.client_ip,
            "user_agent": self.user_agent[:256]
            if self.user_agent
            else None,  # Truncate
            "request_id": self.request_id,
            "request_path": self.request_path,
            "request_method": self.request_method,
            "reason": self.reason,
            "details": self.details,
            "timestamp": self.timestamp,
            "timestamp_iso": datetime.fromtimestamp(
                self.timestamp, tz=timezone.utc
            ).isoformat()
            if self.timestamp
            else None,
        }


class SecurityAuditor:
    """
    Security auditor for recording and analyzing security events.

    Provides:
    - Structured event logging
    - Database persistence (optional)
    - Brute force detection
    - Rate limit tracking
    """

    def __init__(self, persist_to_db: bool = True):
        self.persist_to_db = persist_to_db
        self._failed_auth_cache: dict[str, list[int]] = {}  # IP -> [timestamps]
        self._brute_force_threshold = int(os.getenv("FG_BRUTE_FORCE_THRESHOLD", "10"))
        self._brute_force_window = int(
            os.getenv("FG_BRUTE_FORCE_WINDOW", "300")
        )  # 5 minutes

    def log_event(self, event: AuditEvent) -> None:
        """Log a security event."""
        event_dict = event.to_dict()

        # Log to structured logger
        if event.success:
            log.info(f"security_event: {event.event_type.value}", extra=event_dict)
        elif event.severity == Severity.CRITICAL:
            log.critical(f"security_event: {event.event_type.value}", extra=event_dict)
        elif event.severity == Severity.ERROR:
            log.error(f"security_event: {event.event_type.value}", extra=event_dict)
        elif event.severity == Severity.WARNING:
            log.warning(f"security_event: {event.event_type.value}", extra=event_dict)
        else:
            log.info(f"security_event: {event.event_type.value}", extra=event_dict)

        # Persist to database if enabled
        if self.persist_to_db:
            self._persist_event(event)

    def _persist_event(self, event: AuditEvent) -> None:
        """Persist event to database (best effort)."""
        try:
            from api.db import get_engine
            from api.db_models import SecurityAuditLog
            from sqlalchemy.orm import Session

            engine = get_engine()
            with Session(engine) as session:
                tenant_id = event.tenant_id or "global"
                prev = (
                    session.query(SecurityAuditLog)
                    .filter(SecurityAuditLog.chain_id == tenant_id)
                    .order_by(SecurityAuditLog.id.desc())
                    .limit(1)
                    .one_or_none()
                )
                prev_hash = prev.entry_hash if prev is not None else "GENESIS"
                ts = datetime.fromtimestamp(
                    event.timestamp or int(time.time()), tz=timezone.utc
                )
                payload = {
                    "event_type": event.event_type.value
                    if isinstance(event.event_type, EventType)
                    else event.event_type,
                    "success": event.success,
                    "severity": event.severity.value
                    if isinstance(event.severity, Severity)
                    else event.severity,
                    "tenant_id": event.tenant_id,
                    "key_prefix": event.key_prefix[:16] if event.key_prefix else None,
                    "client_ip": event.client_ip,
                    "user_agent": event.user_agent[:512] if event.user_agent else None,
                    "request_id": event.request_id,
                    "request_path": event.request_path,
                    "request_method": event.request_method,
                    "reason": event.reason,
                    "details": event.details if event.details else {},
                    "timestamp": int(ts.timestamp()),
                    "timestamp_iso": ts.isoformat(),
                }
                entry_hash = _compute_entry_hash(prev_hash, payload)

                record = SecurityAuditLog(
                    event_type=payload["event_type"],
                    event_category="security",
                    severity=payload["severity"],
                    tenant_id=event.tenant_id,
                    key_prefix=event.key_prefix[:16] if event.key_prefix else None,
                    client_ip=event.client_ip,
                    user_agent=event.user_agent[:512] if event.user_agent else None,
                    request_id=event.request_id,
                    request_path=event.request_path,
                    request_method=event.request_method,
                    success=event.success,
                    reason=event.reason,
                    details_json=event.details if event.details else None,
                    created_at=ts,
                    chain_id=tenant_id,
                    prev_hash=prev_hash,
                    entry_hash=entry_hash,
                )
                session.add(record)
                session.commit()
        except Exception as e:
            if _is_prod_like():
                raise AuditPersistenceError(
                    "FG-AUDIT-001", f"audit persistence failed: {e}"
                ) from e
            log.debug(f"Failed to persist audit event: {e}")

    def log_auth_success(
        self,
        request: Optional[Request] = None,
        key_prefix: Optional[str] = None,
        tenant_id: Optional[str] = None,
        **kwargs,
    ) -> None:
        """Log successful authentication."""
        event = AuditEvent(
            event_type=EventType.AUTH_SUCCESS,
            success=True,
            severity=Severity.INFO,
            key_prefix=key_prefix,
            tenant_id=tenant_id,
            **self._extract_request_context(request),
            details=kwargs,
        )
        self.log_event(event)

    def log_auth_failure(
        self,
        reason: str,
        request: Optional[Request] = None,
        key_prefix: Optional[str] = None,
        tenant_id: Optional[str] = None,
        **kwargs,
    ) -> None:
        """Log failed authentication and check for brute force."""
        event = AuditEvent(
            event_type=EventType.AUTH_FAILURE,
            success=False,
            severity=Severity.WARNING,
            reason=reason,
            key_prefix=key_prefix,
            tenant_id=tenant_id,
            **self._extract_request_context(request),
            details=kwargs,
        )
        self.log_event(event)

        # Check for brute force
        client_ip = event.client_ip
        if client_ip:
            self._track_failed_auth(client_ip)

    def _track_failed_auth(self, client_ip: str) -> None:
        """Track failed auth attempts for brute force detection."""
        now = int(time.time())
        cutoff = now - self._brute_force_window

        # Initialize or clean old entries
        if client_ip not in self._failed_auth_cache:
            self._failed_auth_cache[client_ip] = []

        # Remove old entries
        self._failed_auth_cache[client_ip] = [
            ts for ts in self._failed_auth_cache[client_ip] if ts > cutoff
        ]

        # Add current attempt
        self._failed_auth_cache[client_ip].append(now)

        # Check threshold
        if len(self._failed_auth_cache[client_ip]) >= self._brute_force_threshold:
            self.log_event(
                AuditEvent(
                    event_type=EventType.BRUTE_FORCE_DETECTED,
                    success=False,
                    severity=Severity.CRITICAL,
                    client_ip=client_ip,
                    reason=f"Exceeded {self._brute_force_threshold} failed auth attempts in {self._brute_force_window}s",
                    details={
                        "attempt_count": len(self._failed_auth_cache[client_ip]),
                        "window_seconds": self._brute_force_window,
                    },
                )
            )

    def log_key_created(
        self,
        key_prefix: str,
        scopes: list[str],
        tenant_id: Optional[str] = None,
        request: Optional[Request] = None,
        **kwargs,
    ) -> None:
        """Log API key creation."""
        self.log_event(
            AuditEvent(
                event_type=EventType.KEY_CREATED,
                success=True,
                severity=Severity.INFO,
                key_prefix=key_prefix,
                tenant_id=tenant_id,
                **self._extract_request_context(request),
                details={"scopes": scopes, **kwargs},
            )
        )

    def log_key_revoked(
        self,
        key_prefix: str,
        tenant_id: Optional[str] = None,
        request: Optional[Request] = None,
        **kwargs,
    ) -> None:
        """Log API key revocation."""
        self.log_event(
            AuditEvent(
                event_type=EventType.KEY_REVOKED,
                success=True,
                severity=Severity.WARNING,
                key_prefix=key_prefix,
                tenant_id=tenant_id,
                **self._extract_request_context(request),
                details=kwargs,
            )
        )

    def log_key_rotated(
        self,
        old_prefix: str,
        new_prefix: str,
        tenant_id: Optional[str] = None,
        request: Optional[Request] = None,
        **kwargs,
    ) -> None:
        """Log API key rotation."""
        self.log_event(
            AuditEvent(
                event_type=EventType.KEY_ROTATED,
                success=True,
                severity=Severity.INFO,
                key_prefix=new_prefix,
                tenant_id=tenant_id,
                **self._extract_request_context(request),
                details={"old_prefix": old_prefix[:16], **kwargs},
            )
        )

    def log_rate_limit(
        self,
        request: Optional[Request] = None,
        key_prefix: Optional[str] = None,
        tenant_id: Optional[str] = None,
        limit: int = 0,
        remaining: int = 0,
        **kwargs,
    ) -> None:
        """Log rate limit exceeded."""
        self.log_event(
            AuditEvent(
                event_type=EventType.RATE_LIMIT_EXCEEDED,
                success=False,
                severity=Severity.WARNING,
                key_prefix=key_prefix,
                tenant_id=tenant_id,
                **self._extract_request_context(request),
                details={"limit": limit, "remaining": remaining, **kwargs},
            )
        )

    def log_admin_action(
        self,
        *,
        action: str,
        tenant_id: Optional[str] = None,
        request: Optional[Request] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        """Log state-changing admin actions."""
        self.log_event(
            AuditEvent(
                event_type=EventType.ADMIN_ACTION,
                success=True,
                severity=Severity.INFO,
                tenant_id=tenant_id,
                reason=action,
                **self._extract_request_context(request),
                details=details or {},
            )
        )

    def _extract_request_context(self, request: Optional[Request]) -> dict[str, Any]:
        """Extract context from FastAPI request."""
        if request is None:
            return {}

        # Extract client IP with proxy header handling
        client_ip = None
        for header in (
            "x-forwarded-for",
            "x-real-ip",
            "cf-connecting-ip",
            "true-client-ip",
        ):
            value = request.headers.get(header)
            if value:
                client_ip = value.split(",")[0].strip()
                break
        if not client_ip and request.client:
            client_ip = request.client.host

        # Extract request ID from state or headers
        request_id = None
        if hasattr(request, "state") and hasattr(request.state, "request_id"):
            request_id = request.state.request_id
        if not request_id:
            request_id = request.headers.get("x-request-id")

        return {
            "client_ip": client_ip,
            "user_agent": request.headers.get("user-agent"),
            "request_id": request_id,
            "request_path": str(request.url.path) if request.url else None,
            "request_method": request.method,
        }


def verify_audit_chain(tenant_id: str | None = None) -> dict[str, Any]:
    from api.db import get_engine
    from api.db_models import SecurityAuditLog
    from sqlalchemy.orm import Session

    engine = get_engine()
    chain = tenant_id or "global"
    with Session(engine) as session:
        rows = (
            session.query(SecurityAuditLog)
            .filter(SecurityAuditLog.chain_id == chain)
            .order_by(SecurityAuditLog.id.asc())
            .all()
        )

    expected_prev = "GENESIS"
    for row in rows:
        if row.prev_hash != expected_prev:
            return {"ok": False, "reason": "prev_hash_mismatch", "bad_id": row.id}
        row_ts = row.created_at
        if row_ts is not None and row_ts.tzinfo is None:
            row_ts = row_ts.replace(tzinfo=timezone.utc)
        payload = {
            "event_type": row.event_type,
            "success": row.success,
            "severity": row.severity,
            "tenant_id": row.tenant_id,
            "key_prefix": row.key_prefix,
            "client_ip": row.client_ip,
            "user_agent": row.user_agent,
            "request_id": row.request_id,
            "request_path": row.request_path,
            "request_method": row.request_method,
            "reason": row.reason,
            "details": row.details_json or {},
            "timestamp": int(row_ts.timestamp()) if row_ts else 0,
            "timestamp_iso": row_ts.isoformat() if row_ts else None,
        }
        expected_hash = _compute_entry_hash(expected_prev, payload)
        if row.entry_hash != expected_hash:
            return {"ok": False, "reason": "entry_hash_mismatch", "bad_id": row.id}
        expected_prev = expected_hash

    return {"ok": True, "reason": "", "checked": len(rows)}


# Global auditor instance
_auditor: Optional[SecurityAuditor] = None


def get_auditor() -> SecurityAuditor:
    """Get the global security auditor instance."""
    global _auditor
    if _auditor is None:
        persist_to_db = os.getenv("FG_AUDIT_PERSIST_DB", "1").strip().lower() in (
            "1",
            "true",
            "yes",
        )
        _auditor = SecurityAuditor(persist_to_db=persist_to_db)
    return _auditor


def reset_auditor() -> None:
    """Reset the global auditor (for testing)."""
    global _auditor
    _auditor = None


# Convenience functions for common audit events
def audit_auth_success(**kwargs) -> None:
    """Log successful authentication."""
    get_auditor().log_auth_success(**kwargs)


def audit_auth_failure(reason: str, **kwargs) -> None:
    """Log failed authentication."""
    get_auditor().log_auth_failure(reason=reason, **kwargs)


def audit_key_created(key_prefix: str, scopes: list[str], **kwargs) -> None:
    """Log API key creation."""
    get_auditor().log_key_created(key_prefix=key_prefix, scopes=scopes, **kwargs)


def audit_key_revoked(key_prefix: str, **kwargs) -> None:
    """Log API key revocation."""
    get_auditor().log_key_revoked(key_prefix=key_prefix, **kwargs)


def audit_key_rotated(old_prefix: str, new_prefix: str, **kwargs) -> None:
    """Log API key rotation."""
    get_auditor().log_key_rotated(
        old_prefix=old_prefix, new_prefix=new_prefix, **kwargs
    )


def audit_rate_limit(**kwargs) -> None:
    """Log rate limit exceeded."""
    get_auditor().log_rate_limit(**kwargs)


def audit_admin_action(
    *,
    action: str,
    tenant_id: Optional[str] = None,
    request: Optional[Request] = None,
    details: Optional[dict[str, Any]] = None,
) -> None:
    """Log state-changing admin actions."""
    enriched_details = dict(details or {})
    auth_ctx = getattr(getattr(request, "state", None), "auth", None) if request else None
    actor_id = getattr(auth_ctx, "key_prefix", None) or getattr(auth_ctx, "subject", None)
    scope_values = sorted(getattr(auth_ctx, "scopes", set()) or [])
    correlation_id = (
        getattr(getattr(request, "state", None), "request_id", None) if request else None
    ) or enriched_details.get("correlation_id")

    enriched_details.setdefault("actor_id", actor_id)
    enriched_details.setdefault("scope", scope_values)
    enriched_details.setdefault("action", action)
    enriched_details.setdefault("correlation_id", correlation_id)
    enriched_details.setdefault("timestamp", datetime.now(timezone.utc).isoformat())

    required_admin_fields = ("actor_id", "scope", "action", "correlation_id", "timestamp")
    missing = [field for field in required_admin_fields if not enriched_details.get(field)]
    if missing:
        raise AuditPersistenceError(
            "FG-AUDIT-ADMIN-001",
            f"missing required admin audit fields: {','.join(missing)}",
        )

    get_auditor().log_admin_action(
        action=action,
        tenant_id=tenant_id,
        request=request,
        details=enriched_details,
    )
