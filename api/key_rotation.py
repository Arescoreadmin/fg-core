# api/key_rotation.py
"""
API Key Rotation Scheduling and Management.

Provides automated key rotation with:
- Scheduled rotation reminders
- Grace periods for key migration
- Rotation audit trail
- Automatic expiration warnings
"""

from __future__ import annotations

import logging
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable, List, Optional

from api.db import _resolve_sqlite_path

log = logging.getLogger("frostgate.key_rotation")

# =============================================================================
# Configuration
# =============================================================================


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


# Rotation configuration
KEY_ROTATION_ENABLED = _env_bool("FG_KEY_ROTATION_ENABLED", True)
KEY_ROTATION_WARNING_DAYS = _env_int("FG_KEY_ROTATION_WARNING_DAYS", 7)
KEY_ROTATION_GRACE_PERIOD_HOURS = _env_int("FG_KEY_ROTATION_GRACE_PERIOD_HOURS", 24)
KEY_MAX_AGE_DAYS = _env_int("FG_KEY_MAX_AGE_DAYS", 90)
KEY_DEFAULT_TTL_SECONDS = _env_int("FG_KEY_DEFAULT_TTL", 24 * 3600)


class KeyRotationStatus(str, Enum):
    """Status of a key's rotation lifecycle."""

    ACTIVE = "active"  # Key is active and within normal age
    WARNING = "warning"  # Key is approaching expiration
    EXPIRING = "expiring"  # Key is in grace period after rotation
    EXPIRED = "expired"  # Key has expired
    ROTATED = "rotated"  # Key has been rotated (superseded)
    REVOKED = "revoked"  # Key has been manually revoked


@dataclass
class KeyRotationInfo:
    """Information about a key's rotation status."""

    prefix: str
    status: KeyRotationStatus
    created_at: datetime
    expires_at: Optional[datetime]
    days_until_expiration: Optional[int]
    rotation_recommended: bool
    successor_prefix: Optional[str] = None
    predecessor_prefix: Optional[str] = None
    message: Optional[str] = None


@dataclass
class RotationResult:
    """Result of a key rotation operation."""

    success: bool
    old_key_prefix: str
    new_key: Optional[str]  # The new full key (only returned once!)
    new_key_prefix: Optional[str]
    grace_period_until: Optional[datetime]
    message: str


class KeyRotationManager:
    """
    Manages API key rotation lifecycle.

    Features:
    - Check key rotation status
    - Perform key rotation with grace period
    - Track rotation chain
    - Expiration warnings
    """

    def __init__(
        self,
        warning_days: int = KEY_ROTATION_WARNING_DAYS,
        grace_period_hours: int = KEY_ROTATION_GRACE_PERIOD_HOURS,
        max_age_days: int = KEY_MAX_AGE_DAYS,
    ):
        self.warning_days = warning_days
        self.grace_period_hours = grace_period_hours
        self.max_age_days = max_age_days
        self._rotation_callbacks: List[Callable[[RotationResult], None]] = []

    def add_rotation_callback(self, callback: Callable[[RotationResult], None]) -> None:
        """Add a callback for rotation events."""
        self._rotation_callbacks.append(callback)

    def _get_sqlite_path(self) -> str:
        """Get the SQLite database path."""
        sqlite_path = (os.getenv("FG_SQLITE_PATH") or "").strip()
        if not sqlite_path:
            sqlite_path = str(_resolve_sqlite_path())
        return sqlite_path

    def get_key_info(self, key_prefix: str) -> Optional[KeyRotationInfo]:
        """Get rotation info for a specific key."""
        sqlite_path = self._get_sqlite_path()

        con = sqlite3.connect(sqlite_path)
        try:
            # Check table schema
            cols = con.execute("PRAGMA table_info(api_keys)").fetchall()
            col_names = {r[1] for r in cols}

            # Build query based on available columns
            select = ["prefix", "enabled", "created_at"]
            if "expires_at" in col_names:
                select.append("expires_at")
            if "rotated_from" in col_names:
                select.append("rotated_from")

            row = con.execute(
                f"SELECT {','.join(select)} FROM api_keys WHERE prefix = ?",
                (key_prefix,),
            ).fetchone()

            if not row:
                return None

            data = dict(zip(select, row))
            enabled = bool(data.get("enabled", 1))

            # Parse timestamps
            created_at = None
            if data.get("created_at"):
                try:
                    if isinstance(data["created_at"], (int, float)):
                        created_at = datetime.fromtimestamp(
                            data["created_at"], tz=timezone.utc
                        )
                    else:
                        created_at = datetime.fromisoformat(
                            str(data["created_at"]).replace("Z", "+00:00")
                        )
                except Exception:
                    created_at = datetime.now(timezone.utc)

            expires_at = None
            if data.get("expires_at"):
                try:
                    if isinstance(data["expires_at"], (int, float)):
                        expires_at = datetime.fromtimestamp(
                            data["expires_at"], tz=timezone.utc
                        )
                    else:
                        expires_at = datetime.fromisoformat(
                            str(data["expires_at"]).replace("Z", "+00:00")
                        )
                except Exception:
                    pass

            # Determine status
            now = datetime.now(timezone.utc)
            days_until_expiration = None
            rotation_recommended = False
            status = KeyRotationStatus.ACTIVE
            message = None

            if not enabled:
                status = KeyRotationStatus.REVOKED
                message = "Key has been revoked"
            elif expires_at:
                delta = expires_at - now
                days_until_expiration = delta.days

                if delta.total_seconds() <= 0:
                    status = KeyRotationStatus.EXPIRED
                    message = "Key has expired"
                elif delta.days <= self.warning_days:
                    status = KeyRotationStatus.WARNING
                    rotation_recommended = True
                    message = f"Key expires in {delta.days} days"
            elif created_at:
                age = now - created_at
                if age.days >= self.max_age_days:
                    status = KeyRotationStatus.WARNING
                    rotation_recommended = True
                    message = f"Key is {age.days} days old (max recommended: {self.max_age_days})"

            # Check for successor (if this key was rotated)
            successor_prefix = None
            if "rotated_from" in col_names:
                successor = con.execute(
                    "SELECT prefix FROM api_keys WHERE rotated_from = ?",
                    (key_prefix,),
                ).fetchone()
                if successor:
                    successor_prefix = successor[0]
                    if enabled:
                        status = KeyRotationStatus.EXPIRING
                        message = "Key has been rotated, in grace period"

            return KeyRotationInfo(
                prefix=key_prefix,
                status=status,
                created_at=created_at or now,
                expires_at=expires_at,
                days_until_expiration=days_until_expiration,
                rotation_recommended=rotation_recommended,
                successor_prefix=successor_prefix,
                predecessor_prefix=data.get("rotated_from"),
                message=message,
            )

        finally:
            con.close()

    def get_keys_needing_rotation(self) -> List[KeyRotationInfo]:
        """Get all keys that need rotation or are expiring soon."""
        sqlite_path = self._get_sqlite_path()
        results = []

        con = sqlite3.connect(sqlite_path)
        try:
            rows = con.execute(
                "SELECT prefix FROM api_keys WHERE enabled = 1"
            ).fetchall()

            for (prefix,) in rows:
                info = self.get_key_info(prefix)
                if info and info.rotation_recommended:
                    results.append(info)

        finally:
            con.close()

        return results

    def rotate_key(
        self,
        old_key_prefix: str,
        new_scopes: Optional[List[str]] = None,
        new_ttl_seconds: Optional[int] = None,
        tenant_id: Optional[str] = None,
    ) -> RotationResult:
        """
        Rotate an API key.

        Creates a new key and marks the old key for expiration
        after the grace period.
        """
        from api.auth_scopes import mint_key

        sqlite_path = self._get_sqlite_path()

        # Get old key info
        old_info = self.get_key_info(old_key_prefix)
        if not old_info:
            return RotationResult(
                success=False,
                old_key_prefix=old_key_prefix,
                new_key=None,
                new_key_prefix=None,
                grace_period_until=None,
                message=f"Key not found: {old_key_prefix}",
            )

        if old_info.status == KeyRotationStatus.REVOKED:
            return RotationResult(
                success=False,
                old_key_prefix=old_key_prefix,
                new_key=None,
                new_key_prefix=None,
                grace_period_until=None,
                message="Cannot rotate a revoked key",
            )

        # Get old key's scopes if not specified
        con = sqlite3.connect(sqlite_path)
        try:
            row = con.execute(
                "SELECT scopes_csv, tenant_id FROM api_keys WHERE prefix = ?",
                (old_key_prefix,),
            ).fetchone()

            if not row:
                return RotationResult(
                    success=False,
                    old_key_prefix=old_key_prefix,
                    new_key=None,
                    new_key_prefix=None,
                    grace_period_until=None,
                    message=f"Key not found in database: {old_key_prefix}",
                )

            old_scopes_csv, old_tenant_id = row
            scopes = (
                new_scopes
                if new_scopes is not None
                else [s.strip() for s in (old_scopes_csv or "").split(",") if s.strip()]
            )
            tenant = tenant_id or old_tenant_id

        finally:
            con.close()

        # Mint new key
        ttl = new_ttl_seconds or KEY_DEFAULT_TTL_SECONDS
        try:
            new_key = mint_key(*scopes, ttl_seconds=ttl, tenant_id=tenant)
        except Exception as e:
            log.exception(f"Failed to mint new key: {e}")
            return RotationResult(
                success=False,
                old_key_prefix=old_key_prefix,
                new_key=None,
                new_key_prefix=None,
                grace_period_until=None,
                message=f"Failed to create new key: {e}",
            )

        # Get new key prefix
        new_key_prefix = new_key.split(".")[0] if "." in new_key else new_key[:16]

        # Update new key to link to old key (rotation chain)
        grace_period_until = datetime.now(timezone.utc) + timedelta(
            hours=self.grace_period_hours
        )

        con = sqlite3.connect(sqlite_path)
        try:
            # Check if rotated_from column exists
            cols = con.execute("PRAGMA table_info(api_keys)").fetchall()
            col_names = {r[1] for r in cols}

            if "rotated_from" in col_names:
                con.execute(
                    "UPDATE api_keys SET rotated_from = ? WHERE prefix = ?",
                    (old_key_prefix, new_key_prefix),
                )
                con.commit()

        finally:
            con.close()

        result = RotationResult(
            success=True,
            old_key_prefix=old_key_prefix,
            new_key=new_key,
            new_key_prefix=new_key_prefix,
            grace_period_until=grace_period_until,
            message=f"Key rotated successfully. Old key valid until {grace_period_until.isoformat()}",
        )

        # Call rotation callbacks
        for callback in self._rotation_callbacks:
            try:
                callback(result)
            except Exception as e:
                log.exception(f"Rotation callback error: {e}")

        log.info(
            f"Key rotated: {old_key_prefix} -> {new_key_prefix}, "
            f"grace period until {grace_period_until.isoformat()}"
        )

        return result

    def expire_old_keys(self) -> List[str]:
        """
        Disable keys that are past their grace period after rotation.

        Returns list of expired key prefixes.
        """
        sqlite_path = self._get_sqlite_path()
        expired = []

        con = sqlite3.connect(sqlite_path)
        try:
            # Check table schema
            cols = con.execute("PRAGMA table_info(api_keys)").fetchall()
            col_names = {r[1] for r in cols}

            if "rotated_from" not in col_names:
                return []

            # Find keys that have been rotated (have successors)
            # and are past grace period
            now = datetime.now(timezone.utc)
            grace_cutoff = now - timedelta(hours=self.grace_period_hours)

            # Get all active keys that have successors
            rows = con.execute(
                """
                SELECT DISTINCT old.prefix
                FROM api_keys old
                INNER JOIN api_keys new ON new.rotated_from = old.prefix
                WHERE old.enabled = 1
                AND old.created_at < ?
                """,
                (grace_cutoff.timestamp(),),
            ).fetchall()

            for (prefix,) in rows:
                con.execute(
                    "UPDATE api_keys SET enabled = 0 WHERE prefix = ?",
                    (prefix,),
                )
                expired.append(prefix)
                log.info(f"Expired rotated key: {prefix}")

            if expired:
                con.commit()

        finally:
            con.close()

        return expired


# Global manager instance
_rotation_manager: Optional[KeyRotationManager] = None


def get_rotation_manager() -> KeyRotationManager:
    """Get the global key rotation manager."""
    global _rotation_manager
    if _rotation_manager is None:
        _rotation_manager = KeyRotationManager()
    return _rotation_manager


def check_key_rotation_status(key_prefix: str) -> Optional[KeyRotationInfo]:
    """Check rotation status for a key."""
    return get_rotation_manager().get_key_info(key_prefix)


def rotate_api_key(
    old_key_prefix: str,
    new_scopes: Optional[List[str]] = None,
    new_ttl_seconds: Optional[int] = None,
) -> RotationResult:
    """Rotate an API key."""
    return get_rotation_manager().rotate_key(
        old_key_prefix, new_scopes, new_ttl_seconds
    )


__all__ = [
    "KeyRotationStatus",
    "KeyRotationInfo",
    "RotationResult",
    "KeyRotationManager",
    "get_rotation_manager",
    "check_key_rotation_status",
    "rotate_api_key",
]
