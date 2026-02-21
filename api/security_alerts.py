# api/security_alerts.py
"""
Security Event Alerting System.

Provides real-time security event alerting with:
- Multiple alert channels (log, webhook, metrics)
- Alert severity levels and filtering
- Rate limiting to prevent alert fatigue
- Alert aggregation for repeated events
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Mapping, Optional
from urllib.parse import urlsplit
from api.config.env import is_production_env
from api.security.outbound_policy import (
    MAX_REDIRECT_HOPS,
    OutboundPolicyError,
    safe_post_with_redirects,
    sanitize_header_value,
    sanitize_outbound_headers,
    sanitize_url_for_log,
)

log = logging.getLogger("frostgate.security.alerts")

# =============================================================================
# Configuration
# =============================================================================


def _env_str(name: str, default: str) -> str:
    return os.getenv(name, default).strip()


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None or v.strip() == "":
        return default
    try:
        return int(v)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


# Alert configuration
ALERT_ENABLED = _env_bool("FG_ALERT_ENABLED", True)
ALERT_WEBHOOK_URL = _env_str("FG_ALERT_WEBHOOK_URL", "")
ALERT_MIN_SEVERITY = _env_str("FG_ALERT_MIN_SEVERITY", "warning")
ALERT_RATE_LIMIT_WINDOW = _env_int("FG_ALERT_RATE_LIMIT_WINDOW", 60)  # seconds
ALERT_RATE_LIMIT_MAX = _env_int("FG_ALERT_RATE_LIMIT_MAX", 10)  # max alerts per window
ALERT_AGGREGATION_WINDOW = _env_int("FG_ALERT_AGGREGATION_WINDOW", 300)  # 5 minutes
ALLOWED_EXCEPTION_HEADERS = {"retry-after"}


class SSRFBlocked(OutboundPolicyError):
    """Raised when webhook target violates SSRF policy."""


def filter_exception_headers(headers: Mapping[str, str]) -> Dict[str, str]:
    """Return only explicit allowlisted exception headers with safe values."""
    filtered: Dict[str, str] = {}
    for key, value in headers.items():
        key_lower = key.lower()
        if key_lower in ALLOWED_EXCEPTION_HEADERS:
            filtered[key] = sanitize_header_value(value)
    return filtered



def _validate_alert_webhook_url(url: str) -> bool:
    """Validate webhook URL to reduce SSRF risk."""
    try:
        validate_target(url)
    except SSRFBlocked:
        return False
    return True


async def _safe_post_with_redirects(
    client: Any,
    url: str,
    *,
    json_body: Dict[str, Any],
    headers: Dict[str, str],
    timeout: float,
    max_redirect_hops: int = MAX_REDIRECT_HOPS,
) -> Any:
    try:
        return await safe_post_with_redirects(
            client,
            url,
            json_body=json_body,
            headers=sanitize_outbound_headers(headers),
            timeout=timeout,
            max_redirect_hops=max_redirect_hops,
        )
    except OutboundPolicyError as exc:
        raise SSRFBlocked(str(exc)) from exc


class AlertSeverity(str, Enum):
    """Alert severity levels (ascending order)."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

    @classmethod
    def from_string(cls, s: str) -> "AlertSeverity":
        s = s.lower().strip()
        for severity in cls:
            if severity.value == s:
                return severity
        return cls.WARNING

    def __ge__(self, other: "AlertSeverity") -> bool:
        order = [self.INFO, self.WARNING, self.ERROR, self.CRITICAL]
        return order.index(self) >= order.index(other)

    def __gt__(self, other: "AlertSeverity") -> bool:
        order = [self.INFO, self.WARNING, self.ERROR, self.CRITICAL]
        return order.index(self) > order.index(other)


class AlertCategory(str, Enum):
    """Categories of security alerts."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    RATE_LIMIT = "rate_limit"
    BRUTE_FORCE = "brute_force"
    QUOTA = "quota"
    CONFIGURATION = "configuration"
    SYSTEM = "system"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    KEY_MANAGEMENT = "key_management"
    DATA_ACCESS = "data_access"


@dataclass
class SecurityAlert:
    """A security alert."""

    id: str
    timestamp: datetime
    severity: AlertSeverity
    category: AlertCategory
    title: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    tenant_id: Optional[str] = None
    source_ip: Optional[str] = None
    request_id: Optional[str] = None
    count: int = 1  # For aggregated alerts

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.value,
            "category": self.category.value,
            "title": self.title,
            "message": self.message,
            "details": self.details,
            "tenant_id": self.tenant_id,
            "source_ip": self.source_ip,
            "request_id": self.request_id,
            "count": self.count,
        }

    def fingerprint(self) -> str:
        """Generate fingerprint for deduplication/aggregation."""
        key = f"{self.category.value}:{self.title}:{self.tenant_id or ''}:{self.source_ip or ''}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]


class AlertChannel:
    """Base class for alert channels."""

    async def send(self, alert: SecurityAlert) -> bool:
        """Send alert. Returns True if successful."""
        raise NotImplementedError


class LogAlertChannel(AlertChannel):
    """Alert channel that logs to the security logger."""

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or log

    async def send(self, alert: SecurityAlert) -> bool:
        """Log the alert."""
        log_method = {
            AlertSeverity.INFO: self.logger.info,
            AlertSeverity.WARNING: self.logger.warning,
            AlertSeverity.ERROR: self.logger.error,
            AlertSeverity.CRITICAL: self.logger.critical,
        }.get(alert.severity, self.logger.warning)

        log_method(
            f"[{alert.category.value.upper()}] {alert.title}: {alert.message}",
            extra={
                "alert_id": alert.id,
                "tenant_id": alert.tenant_id,
                "source_ip": alert.source_ip,
                "details": alert.details,
            },
        )
        return True


class WebhookAlertChannel(AlertChannel):
    """Alert channel that sends webhooks."""

    def __init__(self, url: str, headers: Optional[Dict[str, str]] = None):
        self.url = url
        self.headers = sanitize_outbound_headers(
            headers or {"Content-Type": "application/json"}
        )

    async def send(self, alert: SecurityAlert) -> bool:
        """Send webhook alert."""
        if not self.url:
            return False
        if not _validate_alert_webhook_url(self.url):
            log.error(
                "Blocked security alert webhook URL by egress policy: %s",
                sanitize_url_for_log(self.url),
            )
            return False

        try:
            import httpx

            async with httpx.AsyncClient(follow_redirects=False) as client:
                response = await _safe_post_with_redirects(
                    client,
                    self.url,
                    json_body=alert.to_dict(),
                    headers=self.headers,
                    timeout=10.0,
                )
                return response.is_success
        except ImportError:
            log.warning("httpx not installed, webhook alerts disabled")
            return False
        except Exception as e:
            log.error(
                "Failed to send webhook alert to %s: %s",
                sanitize_url_for_log(self.url),
                sanitize_header_value(str(e)),
                extra={
                    "exception_headers": filter_exception_headers(
                        getattr(getattr(e, "response", None), "headers", {}) or {}
                    )
                },
            )
            return False


class MetricsAlertChannel(AlertChannel):
    """Alert channel that updates Prometheus metrics."""

    def __init__(self):
        self._alert_counts: Dict[str, int] = {}

    async def send(self, alert: SecurityAlert) -> bool:
        """Update metrics counter."""
        key = f"{alert.severity.value}:{alert.category.value}"
        self._alert_counts[key] = self._alert_counts.get(key, 0) + alert.count

        # Try to update Prometheus metrics if available
        try:
            from prometheus_client import Counter

            counter = Counter(
                "frostgate_security_alerts_total",
                "Total security alerts",
                ["severity", "category"],
            )
            counter.labels(
                severity=alert.severity.value,
                category=alert.category.value,
            ).inc(alert.count)
        except ImportError:
            pass

        return True

    def get_counts(self) -> Dict[str, int]:
        """Get alert counts."""
        return dict(self._alert_counts)


class SecurityAlertManager:
    """
    Manages security alerts with rate limiting and aggregation.

    Features:
    - Multiple alert channels (log, webhook, metrics)
    - Rate limiting to prevent alert fatigue
    - Alert aggregation for repeated events
    - Severity filtering
    """

    def __init__(
        self,
        min_severity: AlertSeverity = AlertSeverity.WARNING,
        rate_limit_window: int = ALERT_RATE_LIMIT_WINDOW,
        rate_limit_max: int = ALERT_RATE_LIMIT_MAX,
        aggregation_window: int = ALERT_AGGREGATION_WINDOW,
    ):
        self.min_severity = min_severity
        self.rate_limit_window = rate_limit_window
        self.rate_limit_max = rate_limit_max
        self.aggregation_window = aggregation_window

        self._channels: List[AlertChannel] = []
        self._alert_times: List[float] = []
        self._aggregated_alerts: Dict[str, SecurityAlert] = {}
        self._suppressed_count = 0
        self._total_alerts = 0
        self._callbacks: List[Callable[[SecurityAlert], None]] = []

    def add_channel(self, channel: AlertChannel) -> None:
        """Add an alert channel."""
        self._channels.append(channel)

    def add_callback(self, callback: Callable[[SecurityAlert], None]) -> None:
        """Add a callback for new alerts."""
        self._callbacks.append(callback)

    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limits."""
        now = time.time()
        cutoff = now - self.rate_limit_window

        # Clean old entries
        self._alert_times = [t for t in self._alert_times if t > cutoff]

        if len(self._alert_times) >= self.rate_limit_max:
            return False

        self._alert_times.append(now)
        return True

    def _try_aggregate(self, alert: SecurityAlert) -> Optional[SecurityAlert]:
        """Try to aggregate with existing alert."""
        fingerprint = alert.fingerprint()
        now = time.time()

        if fingerprint in self._aggregated_alerts:
            existing = self._aggregated_alerts[fingerprint]
            age = now - existing.timestamp.timestamp()

            if age <= self.aggregation_window:
                # Aggregate: increment count, update timestamp
                existing.count += 1
                existing.timestamp = alert.timestamp
                return None  # Suppressed, aggregated into existing

        # New or expired aggregate
        self._aggregated_alerts[fingerprint] = alert
        return alert

    async def alert(
        self,
        severity: AlertSeverity,
        category: AlertCategory,
        title: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        tenant_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Optional[SecurityAlert]:
        """
        Create and send a security alert.

        Returns the alert if sent, None if suppressed.
        """
        if not ALERT_ENABLED:
            return None

        # Check severity filter
        if not (severity >= self.min_severity):
            return None

        self._total_alerts += 1

        # Create alert
        alert = SecurityAlert(
            id=f"alert_{int(time.time() * 1000)}_{self._total_alerts}",
            timestamp=datetime.now(timezone.utc),
            severity=severity,
            category=category,
            title=title,
            message=message,
            details=details or {},
            tenant_id=tenant_id,
            source_ip=source_ip,
            request_id=request_id,
        )

        # Try aggregation
        alert = self._try_aggregate(alert)
        if alert is None:
            self._suppressed_count += 1
            return None

        # Check rate limit
        if not self._check_rate_limit():
            self._suppressed_count += 1
            log.warning(f"Alert rate limited: {title}")
            return None

        # Send to all channels
        for channel in self._channels:
            try:
                await channel.send(alert)
            except Exception as e:
                log.exception(f"Alert channel error: {e}")

        # Call callbacks
        for callback in self._callbacks:
            try:
                callback(alert)
            except Exception as e:
                log.exception(f"Alert callback error: {e}")

        return alert

    def get_stats(self) -> Dict[str, Any]:
        """Get alert statistics."""
        return {
            "total_alerts": self._total_alerts,
            "suppressed_count": self._suppressed_count,
            "active_aggregates": len(self._aggregated_alerts),
            "channels": len(self._channels),
            "rate_limit_window": self.rate_limit_window,
            "rate_limit_max": self.rate_limit_max,
        }


# =============================================================================
# Global alert manager and convenience functions
# =============================================================================

_alert_manager: Optional[SecurityAlertManager] = None


def get_alert_manager() -> SecurityAlertManager:
    """Get or create the global alert manager."""
    global _alert_manager
    if _alert_manager is None:
        min_severity = AlertSeverity.from_string(ALERT_MIN_SEVERITY)
        _alert_manager = SecurityAlertManager(min_severity=min_severity)

        # Add default channels
        _alert_manager.add_channel(LogAlertChannel())
        _alert_manager.add_channel(MetricsAlertChannel())

        # Add webhook channel if configured
        if ALERT_WEBHOOK_URL:
            _alert_manager.add_channel(WebhookAlertChannel(ALERT_WEBHOOK_URL))

    return _alert_manager


async def send_alert(
    severity: AlertSeverity,
    category: AlertCategory,
    title: str,
    message: str,
    **kwargs,
) -> Optional[SecurityAlert]:
    """Convenience function to send an alert."""
    manager = get_alert_manager()
    return await manager.alert(severity, category, title, message, **kwargs)


# Pre-defined alert functions for common events
async def alert_brute_force(
    source_ip: str,
    attempts: int,
    tenant_id: Optional[str] = None,
) -> Optional[SecurityAlert]:
    """Alert for brute force attempt detected."""
    return await send_alert(
        severity=AlertSeverity.WARNING if attempts < 20 else AlertSeverity.ERROR,
        category=AlertCategory.BRUTE_FORCE,
        title="Brute force attempt detected",
        message=f"Multiple failed auth attempts ({attempts}) from {source_ip}",
        details={"attempts": attempts},
        source_ip=source_ip,
        tenant_id=tenant_id,
    )


async def alert_quota_exceeded(
    tenant_id: str,
    usage: int,
    limit: int,
) -> Optional[SecurityAlert]:
    """Alert for tenant quota exceeded."""
    return await send_alert(
        severity=AlertSeverity.WARNING,
        category=AlertCategory.QUOTA,
        title="Tenant quota exceeded",
        message=f"Tenant {tenant_id[:8]}... exceeded quota ({usage}/{limit})",
        details={"usage": usage, "limit": limit},
        tenant_id=tenant_id,
    )


async def alert_key_revoked(
    key_prefix: str,
    reason: str,
    tenant_id: Optional[str] = None,
) -> Optional[SecurityAlert]:
    """Alert for API key revocation."""
    return await send_alert(
        severity=AlertSeverity.INFO,
        category=AlertCategory.KEY_MANAGEMENT,
        title="API key revoked",
        message=f"Key {key_prefix} revoked: {reason}",
        details={"key_prefix": key_prefix, "reason": reason},
        tenant_id=tenant_id,
    )


async def alert_suspicious_activity(
    activity_type: str,
    description: str,
    source_ip: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> Optional[SecurityAlert]:
    """Alert for suspicious activity."""
    return await send_alert(
        severity=AlertSeverity.WARNING,
        category=AlertCategory.SUSPICIOUS_ACTIVITY,
        title=f"Suspicious activity: {activity_type}",
        message=description,
        source_ip=source_ip,
        tenant_id=tenant_id,
    )


async def alert_system_error(
    error_type: str,
    description: str,
    details: Optional[Dict[str, Any]] = None,
) -> Optional[SecurityAlert]:
    """Alert for system errors."""
    return await send_alert(
        severity=AlertSeverity.ERROR,
        category=AlertCategory.SYSTEM,
        title=f"System error: {error_type}",
        message=description,
        details=details,
    )


__all__ = [
    "AlertSeverity",
    "AlertCategory",
    "SecurityAlert",
    "AlertChannel",
    "LogAlertChannel",
    "WebhookAlertChannel",
    "MetricsAlertChannel",
    "SecurityAlertManager",
    "get_alert_manager",
    "send_alert",
    "alert_brute_force",
    "alert_quota_exceeded",
    "alert_key_revoked",
    "alert_suspicious_activity",
    "alert_system_error",
]
def resolve_host(host: str) -> List[str]:
    """Backward-compatible alias for tests and legacy callers."""
    from api.security.outbound_policy import _resolve_host

    return _resolve_host(host)


def is_ip_blocked(ip_raw: str) -> bool:
    from api.security.outbound_policy import _is_ip_blocked

    return _is_ip_blocked(ip_raw)


def validate_target(url: str) -> tuple[str, list[str]]:
    """Compatibility wrapper that preserves monkeypatch points in tests."""
    cleaned = str(url)
    try:
        parsed = urlsplit(cleaned)
    except Exception as exc:
        raise SSRFBlocked("malformed_url") from exc
    if parsed.scheme not in {"http", "https"}:
        raise SSRFBlocked("scheme_not_allowed")
    if is_production_env() and parsed.scheme != "https":
        raise SSRFBlocked("https_required_in_production")
    if parsed.username is not None or parsed.password is not None:
        raise SSRFBlocked("userinfo_not_allowed")
    host = parsed.hostname
    if not host:
        raise SSRFBlocked("host_required")
    ips = resolve_host(host)
    if any(is_ip_blocked(ip) for ip in ips):
        raise SSRFBlocked("resolved_ip_blocked")
    rebound_ips = resolve_host(host)
    if rebound_ips != ips:
        raise SSRFBlocked("dns_rebinding_detected")
    normalized_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
    return normalized_url, ips
