"""
Tripwire Detection and Alert Delivery for FrostGate Core.

Implements early breach detection mechanisms:
- Canary token detection (honeypot API keys)
- Anomaly signals for suspicious activity
- REAL async webhook delivery with configurable retry policy
- Failures recorded to audit log

Security principle: Assume breach, detect early, alert fast.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

log = logging.getLogger("frostgate.tripwire")
_security_log = logging.getLogger("frostgate.security")

# Canary key prefix - any key starting with this triggers an alert
# These keys should be seeded in the database but NEVER used legitimately
CANARY_KEY_PREFIX = "fgk_canary_"

# Webhook configuration via environment
WEBHOOK_MAX_ATTEMPTS = int(os.getenv("FG_WEBHOOK_MAX_ATTEMPTS", "3"))
WEBHOOK_BACKOFF_BASE = float(os.getenv("FG_WEBHOOK_BACKOFF_BASE", "2.0"))
WEBHOOK_TIMEOUT = float(os.getenv("FG_WEBHOOK_TIMEOUT", "10.0"))

# In-memory queue for async delivery (production would use Redis/NATS)
_delivery_queue: asyncio.Queue["WebhookDelivery"] = asyncio.Queue()
_delivery_task: Optional[asyncio.Task] = None


@dataclass
class TripwireAlert:
    """Structured tripwire alert for security events."""

    alert_type: str
    severity: str  # CRITICAL, HIGH, WARNING
    message: str
    details: dict[str, Any]
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        # Note: 'message' is reserved by Python logging, use 'alert_message'
        return {
            "alert_type": self.alert_type,
            "severity": self.severity,
            "alert_message": self.message,
            "details": self.details,
            "alert_timestamp": self.timestamp,
        }


@dataclass
class WebhookDelivery:
    """Represents a webhook delivery attempt."""

    url: str
    payload: dict[str, Any]
    alert_type: str
    severity: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    attempt: int = 0
    max_attempts: int = WEBHOOK_MAX_ATTEMPTS
    last_error: Optional[str] = None
    delivered: bool = False
    delivery_time: Optional[datetime] = None


@dataclass
class DeliveryResult:
    """Result of a webhook delivery attempt."""

    success: bool
    status_code: Optional[int] = None
    error: Optional[str] = None
    attempt: int = 0
    response_time_ms: float = 0


class WebhookDeliveryService:
    """
    Async webhook delivery service with retry and backoff.

    Features:
    - Non-blocking request path (queues delivery)
    - Configurable retry policy with exponential backoff
    - Failure logging to audit log
    - Circuit breaker pattern (optional)
    """

    def __init__(
        self,
        max_attempts: int = WEBHOOK_MAX_ATTEMPTS,
        backoff_base: float = WEBHOOK_BACKOFF_BASE,
        timeout: float = WEBHOOK_TIMEOUT,
        audit_logger: Optional[Callable[[dict], None]] = None,
    ):
        self.max_attempts = max_attempts
        self.backoff_base = backoff_base
        self.timeout = timeout
        self.audit_logger = audit_logger or self._default_audit_logger
        self._http_client: Optional[Any] = None

    def _default_audit_logger(self, event: dict) -> None:
        """Default audit logger - logs to security logger."""
        _security_log.info(
            f"WEBHOOK_AUDIT: {event.get('event_type', 'unknown')}",
            extra=event,
        )

    async def _get_http_client(self):
        """Lazy-initialize HTTP client."""
        if self._http_client is None:
            try:
                import httpx

                self._http_client = httpx.AsyncClient(
                    timeout=self.timeout,
                    follow_redirects=True,
                )
            except ImportError:
                # Fallback to aiohttp if httpx not available
                try:
                    import aiohttp

                    self._http_client = aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=self.timeout)
                    )
                except ImportError:
                    raise RuntimeError(
                        "No HTTP client available (install httpx or aiohttp)"
                    )
        return self._http_client

    async def close(self):
        """Close HTTP client."""
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    async def deliver(
        self,
        url: str,
        payload: dict[str, Any],
        alert_type: str = "unknown",
        severity: str = "INFO",
    ) -> DeliveryResult:
        """
        Attempt to deliver webhook with retries.

        Returns DeliveryResult with success status and details.
        """
        last_error = None
        last_status = None

        for attempt in range(1, self.max_attempts + 1):
            start_time = time.time()
            try:
                client = await self._get_http_client()

                # Determine client type and make request
                if hasattr(client, "post"):  # httpx
                    response = await client.post(
                        url,
                        json=payload,
                        headers={
                            "Content-Type": "application/json",
                            "User-Agent": "FrostGate-Tripwire/1.0",
                            "X-Alert-Type": alert_type,
                            "X-Alert-Severity": severity,
                        },
                    )
                    status_code = response.status_code
                    response_time = (time.time() - start_time) * 1000
                else:  # aiohttp
                    async with client.post(
                        url,
                        json=payload,
                        headers={
                            "Content-Type": "application/json",
                            "User-Agent": "FrostGate-Tripwire/1.0",
                            "X-Alert-Type": alert_type,
                            "X-Alert-Severity": severity,
                        },
                    ) as response:
                        status_code = response.status
                        response_time = (time.time() - start_time) * 1000

                last_status = status_code

                # 2xx = success
                if 200 <= status_code < 300:
                    self.audit_logger(
                        {
                            "event_type": "webhook_delivered",
                            "url": url,
                            "alert_type": alert_type,
                            "severity": severity,
                            "status_code": status_code,
                            "attempt": attempt,
                            "response_time_ms": response_time,
                            "success": True,
                        }
                    )
                    return DeliveryResult(
                        success=True,
                        status_code=status_code,
                        attempt=attempt,
                        response_time_ms=response_time,
                    )

                # 4xx = client error, don't retry
                if 400 <= status_code < 500:
                    error = f"Client error: {status_code}"
                    self.audit_logger(
                        {
                            "event_type": "webhook_failed",
                            "url": url,
                            "alert_type": alert_type,
                            "severity": severity,
                            "status_code": status_code,
                            "attempt": attempt,
                            "error": error,
                            "success": False,
                            "permanent_failure": True,
                        }
                    )
                    return DeliveryResult(
                        success=False,
                        status_code=status_code,
                        error=error,
                        attempt=attempt,
                        response_time_ms=response_time,
                    )

                # 5xx = server error, retry
                last_error = f"Server error: {status_code}"

            except asyncio.TimeoutError:
                last_error = "Request timeout"
            except Exception as e:
                last_error = str(e)

            # Log retry attempt
            if attempt < self.max_attempts:
                backoff = self.backoff_base ** (attempt - 1)
                log.warning(
                    f"Webhook delivery failed (attempt {attempt}/{self.max_attempts}), "
                    f"retrying in {backoff}s: {last_error}"
                )
                self.audit_logger(
                    {
                        "event_type": "webhook_retry",
                        "url": url,
                        "alert_type": alert_type,
                        "attempt": attempt,
                        "max_attempts": self.max_attempts,
                        "error": last_error,
                        "backoff_seconds": backoff,
                    }
                )
                await asyncio.sleep(backoff)

        # All attempts exhausted
        self.audit_logger(
            {
                "event_type": "webhook_failed",
                "url": url,
                "alert_type": alert_type,
                "severity": severity,
                "status_code": last_status,
                "attempt": self.max_attempts,
                "error": last_error,
                "success": False,
                "permanent_failure": True,
            }
        )

        return DeliveryResult(
            success=False,
            status_code=last_status,
            error=last_error,
            attempt=self.max_attempts,
        )


# Singleton delivery service instance
_delivery_service: Optional[WebhookDeliveryService] = None


def get_delivery_service() -> WebhookDeliveryService:
    """Get or create the webhook delivery service."""
    global _delivery_service
    if _delivery_service is None:
        _delivery_service = WebhookDeliveryService()
    return _delivery_service


async def _process_delivery_queue():
    """Background task to process webhook delivery queue."""
    service = get_delivery_service()

    while True:
        try:
            delivery = await _delivery_queue.get()
            await service.deliver(
                url=delivery.url,
                payload=delivery.payload,
                alert_type=delivery.alert_type,
                severity=delivery.severity,
            )
            _delivery_queue.task_done()
        except asyncio.CancelledError:
            break
        except Exception as e:
            log.exception(f"Error processing delivery queue: {e}")


def start_delivery_worker():
    """Start the background delivery worker task."""
    global _delivery_task
    if _delivery_task is None or _delivery_task.done():
        _delivery_task = asyncio.create_task(_process_delivery_queue())
        log.info("Started webhook delivery worker")


def stop_delivery_worker():
    """Stop the background delivery worker task."""
    global _delivery_task
    if _delivery_task is not None and not _delivery_task.done():
        _delivery_task.cancel()
        _delivery_task = None
        log.info("Stopped webhook delivery worker")


def queue_webhook_delivery(
    url: str,
    payload: dict[str, Any],
    alert_type: str = "unknown",
    severity: str = "INFO",
) -> None:
    """
    Queue a webhook for async delivery (non-blocking).

    Call this from request handlers to avoid blocking.
    """
    delivery = WebhookDelivery(
        url=url,
        payload=payload,
        alert_type=alert_type,
        severity=severity,
    )

    try:
        _delivery_queue.put_nowait(delivery)
        log.debug(f"Queued webhook delivery to {url}")
    except asyncio.QueueFull:
        log.error(f"Webhook delivery queue full, dropping alert to {url}")
        _security_log.error(
            "WEBHOOK_QUEUE_FULL",
            extra={
                "event_type": "webhook_queue_full",
                "url": url,
                "alert_type": alert_type,
            },
        )


async def deliver_webhook_async(
    url: str,
    payload: dict[str, Any],
    alert_type: str = "unknown",
    severity: str = "INFO",
) -> DeliveryResult:
    """
    Deliver webhook asynchronously with retry (awaitable).

    Use this when you need to know the delivery result.
    """
    service = get_delivery_service()
    return await service.deliver(url, payload, alert_type, severity)


def _emit_alert(alert: TripwireAlert) -> None:
    """
    Emit a tripwire alert.

    Logs to security logger and delivers via webhook if configured.
    """
    alert_dict = alert.to_dict()

    if alert.severity == "CRITICAL":
        _security_log.critical(f"TRIPWIRE_ALERT: {alert.alert_type}", extra=alert_dict)
    elif alert.severity == "HIGH":
        _security_log.error(f"TRIPWIRE_ALERT: {alert.alert_type}", extra=alert_dict)
    else:
        _security_log.warning(f"TRIPWIRE_ALERT: {alert.alert_type}", extra=alert_dict)

    # Webhook delivery
    webhook_url = os.getenv("FG_ALERT_WEBHOOK_URL", "").strip()
    if webhook_url:
        queue_webhook_delivery(
            url=webhook_url,
            payload=alert_dict,
            alert_type=alert.alert_type,
            severity=alert.severity,
        )


def check_canary_key(key_prefix: Optional[str]) -> bool:
    """
    Check if a key prefix matches a canary token.

    If a canary key is accessed, it indicates:
    - Credential theft (attacker found the key)
    - Insider threat (someone using honeypot key)
    - Breach in progress

    Returns True if canary detected (caller should proceed with caution).
    """
    if not key_prefix:
        return False

    if str(key_prefix).startswith(CANARY_KEY_PREFIX):
        _emit_alert(
            TripwireAlert(
                alert_type="CANARY_TOKEN_ACCESSED",
                severity="CRITICAL",
                message="Canary API key was used - potential breach detected",
                details={
                    "key_prefix": key_prefix[:20],  # Truncate for safety
                    "action": "Key access attempted",
                    "recommendation": "Investigate immediately - rotate all credentials",
                },
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
        )
        return True

    return False


def check_honeypot_path(request_path: str) -> bool:
    """
    Check if request is to a honeypot endpoint.

    Honeypot paths are fake endpoints that should never receive
    legitimate traffic. Any access indicates reconnaissance or breach.
    """
    honeypot_paths = {
        "/admin/backup",
        "/admin/export",
        "/.git/config",
        "/.env",
        "/wp-admin",
        "/phpmyadmin",
        "/actuator/env",
        "/debug/vars",
    }

    normalized_path = request_path.lower().rstrip("/")

    if normalized_path in honeypot_paths:
        _emit_alert(
            TripwireAlert(
                alert_type="HONEYPOT_PATH_ACCESSED",
                severity="HIGH",
                message="Honeypot endpoint accessed - potential reconnaissance",
                details={
                    "path": request_path,
                    "action": "Reconnaissance attempt detected",
                    "recommendation": "Review source IP and block if malicious",
                },
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
        )
        return True

    return False


def check_auth_anomaly(
    client_ip: Optional[str],
    failed_attempts: int,
    window_seconds: int = 300,
    threshold: int = 10,
) -> bool:
    """
    Check for authentication anomalies.

    High failure rate from a single IP indicates brute force or credential stuffing.
    """
    if failed_attempts >= threshold:
        _emit_alert(
            TripwireAlert(
                alert_type="AUTH_ANOMALY_DETECTED",
                severity="HIGH",
                message=f"High auth failure rate from {client_ip}",
                details={
                    "client_ip": client_ip,
                    "failed_attempts": failed_attempts,
                    "window_seconds": window_seconds,
                    "threshold": threshold,
                    "action": "Brute force or credential stuffing suspected",
                    "recommendation": "Consider blocking IP or enforcing CAPTCHA",
                },
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
        )
        return True

    return False


def seed_canary_key_if_missing() -> Optional[str]:
    """
    Seed a canary API key into the database if one doesn't exist.

    Returns the canary key prefix if seeded, None if already exists.

    This should be called during application startup.
    """
    import sqlite3

    sqlite_path = os.getenv("FG_SQLITE_PATH", "").strip()
    if not sqlite_path:
        log.debug("No SQLite path configured, skipping canary seed")
        return None

    try:
        con = sqlite3.connect(sqlite_path)
        try:
            # Check if canary key already exists
            row = con.execute(
                "SELECT prefix FROM api_keys WHERE prefix LIKE ? LIMIT 1",
                (f"{CANARY_KEY_PREFIX}%",),
            ).fetchone()

            if row:
                log.debug(f"Canary key already exists: {row[0]}")
                return None

            # Seed a new canary key (disabled, but present)
            import secrets
            import json
            from api.auth_scopes import hash_key

            canary_prefix = f"{CANARY_KEY_PREFIX}{secrets.token_hex(4)}"
            canary_secret = secrets.token_urlsafe(32)
            canary_hash, hash_alg, hash_params, key_lookup = hash_key(canary_secret)
            hash_params_json = json.dumps(
                hash_params, separators=(",", ":"), sort_keys=True
            )

            # Check schema for required columns
            cols = con.execute("PRAGMA table_info(api_keys)").fetchall()
            col_names = {r[1] for r in cols}

            if {"key_lookup", "hash_alg", "hash_params"}.issubset(col_names):
                con.execute(
                    "INSERT INTO api_keys (name, prefix, key_hash, key_lookup, hash_alg, hash_params, scopes_csv, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        "CANARY_DO_NOT_USE",
                        canary_prefix,
                        canary_hash,
                        key_lookup,
                        hash_alg,
                        hash_params_json,
                        "",
                        0,
                    ),
                )
            elif "name" in col_names:
                con.execute(
                    "INSERT INTO api_keys (name, prefix, key_hash, scopes_csv, enabled) VALUES (?, ?, ?, ?, ?)",
                    (
                        "CANARY_DO_NOT_USE",
                        canary_prefix,
                        canary_hash,
                        "",  # No scopes
                        0,  # Disabled
                    ),
                )
            else:
                con.execute(
                    "INSERT INTO api_keys (prefix, key_hash, scopes_csv, enabled) VALUES (?, ?, ?, ?)",
                    (canary_prefix, canary_hash, "", 0),
                )

            con.commit()
            log.info(f"Seeded canary API key: {canary_prefix}")
            return canary_prefix

        finally:
            con.close()

    except Exception as e:
        log.warning(f"Failed to seed canary key: {e}")
        return None


__all__ = [
    "CANARY_KEY_PREFIX",
    "TripwireAlert",
    "WebhookDelivery",
    "WebhookDeliveryService",
    "DeliveryResult",
    "check_canary_key",
    "check_honeypot_path",
    "check_auth_anomaly",
    "seed_canary_key_if_missing",
    "queue_webhook_delivery",
    "deliver_webhook_async",
    "get_delivery_service",
    "start_delivery_worker",
    "stop_delivery_worker",
]
