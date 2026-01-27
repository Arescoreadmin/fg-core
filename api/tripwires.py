"""
Tripwire Detection for FrostGate Core.

Implements early breach detection mechanisms:
- Canary token detection (honeypot API keys)
- Anomaly signals for suspicious activity
- Alert emission for security events

Security principle: Assume breach, detect early, alert fast.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

log = logging.getLogger("frostgate.tripwire")
_security_log = logging.getLogger("frostgate.security")

# Canary key prefix - any key starting with this triggers an alert
# These keys should be seeded in the database but NEVER used legitimately
CANARY_KEY_PREFIX = "fgk_canary_"


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


def _emit_alert(alert: TripwireAlert) -> None:
    """
    Emit a tripwire alert.

    Currently logs to security logger. Future: webhook delivery.
    """
    alert_dict = alert.to_dict()

    if alert.severity == "CRITICAL":
        _security_log.critical(f"TRIPWIRE_ALERT: {alert.alert_type}", extra=alert_dict)
    elif alert.severity == "HIGH":
        _security_log.error(f"TRIPWIRE_ALERT: {alert.alert_type}", extra=alert_dict)
    else:
        _security_log.warning(f"TRIPWIRE_ALERT: {alert.alert_type}", extra=alert_dict)

    # Future: webhook delivery
    webhook_url = os.getenv("FG_ALERT_WEBHOOK_URL", "").strip()
    if webhook_url:
        _deliver_webhook_async(webhook_url, alert_dict)


def _deliver_webhook_async(url: str, payload: dict) -> None:
    """
    Deliver alert via webhook (best-effort, non-blocking).

    TODO: Implement async delivery with retry logic.
    """
    # Stub for future implementation
    log.debug(f"Webhook delivery stub: {url}")


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
            import hashlib

            canary_prefix = f"{CANARY_KEY_PREFIX}{secrets.token_hex(4)}"
            canary_secret = secrets.token_urlsafe(32)
            canary_hash = hashlib.sha256(canary_secret.encode()).hexdigest()

            # Check schema for required columns
            cols = con.execute("PRAGMA table_info(api_keys)").fetchall()
            col_names = {r[1] for r in cols}

            if "name" in col_names:
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
    "check_canary_key",
    "check_honeypot_path",
    "check_auth_anomaly",
    "seed_canary_key_if_missing",
]
