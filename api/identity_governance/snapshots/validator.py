"""api/identity_governance/snapshots/validator.py — Secret detection validator."""

from __future__ import annotations

import re
from typing import Any

from api.identity_governance.snapshots.serializer import _to_serializable


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

_SECRET_KEY_PATTERNS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "token",
        "secret",
        "api_key",
        "apikey",
        "private_key",
        "privatekey",
        "refresh_token",
        "refreshtoken",
        "session_cookie",
        "sessioncookie",
        "device_fingerprint",
        "devicefingerprint",
        "raw_jwt",
        "rawjwt",
        "authorization",
        "cookie",
        "credential",
        "credentials",
        "access_token",
        "accesstoken",
        "client_secret",
        "clientsecret",
    }
)

_SECRET_VALUE_PATTERNS: frozenset[str] = frozenset(
    {
        "eyj",  # JWT prefix (base64 "ey...")
        "sk-",  # API key prefix
        "bearer ",  # Bearer token
        "basic ",  # Basic auth
    }
)

# Known-safe keys that hold hashes, not secrets
_SAFE_KEYS: frozenset[str] = frozenset(
    {
        "fingerprint",
        "event_hash",
        "previous_hash",
        "fingerprint_hash",
        "user_agent_hash",
    }
)

# JWT pattern: 3 base64url segments separated by dots, minimum 50 chars total
_JWT_RE = re.compile(r"^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$")


def _normalize_key(key: str) -> str:
    """Normalize a key for pattern matching: lowercase, strip underscores."""
    return key.lower().replace("_", "").replace("-", "")


def _is_secret_key(key: str) -> bool:
    """Return True if the key name matches a known secret pattern."""
    if key in _SAFE_KEYS:
        return False
    normalized = _normalize_key(key)
    # Direct match against pattern set (normalized)
    for pattern in _SECRET_KEY_PATTERNS:
        if _normalize_key(pattern) == normalized:
            return True
    return False


def _looks_like_jwt(value: str) -> bool:
    """Return True if value looks like a raw JWT token."""
    if len(value) < 50:
        return False
    return bool(_JWT_RE.match(value))


def _is_secret_value(value: str) -> bool:
    """Return True if a string value looks like a secret."""
    lower = value.lower()
    for prefix in _SECRET_VALUE_PATTERNS:
        if lower.startswith(prefix):
            return True
    if _looks_like_jwt(value):
        return True
    return False


# ---------------------------------------------------------------------------
# SnapshotValidationError
# ---------------------------------------------------------------------------


class SnapshotValidationError(Exception):
    """Raised when a snapshot contains secret-shaped data."""

    def __init__(self, message: str, *, field_path: str = "") -> None:
        super().__init__(message)
        self.field_path = field_path


# ---------------------------------------------------------------------------
# SecretValidator
# ---------------------------------------------------------------------------


class SecretValidator:
    """Validate that a snapshot contains no secret-shaped fields or values."""

    def validate(self, snapshot: Any) -> None:
        """Raise SnapshotValidationError if snapshot contains secret-shaped fields."""
        serializable = _to_serializable(snapshot)
        self._walk(serializable, path="")

    def is_safe(self, snapshot: Any) -> bool:
        """Return True if snapshot passes secret validation."""
        try:
            self.validate(snapshot)
            return True
        except SnapshotValidationError:
            return False

    # ------------------------------------------------------------------
    # Internal walker
    # ------------------------------------------------------------------

    def _walk(self, obj: Any, path: str) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                child_path = f"{path}.{key}" if path else key
                # Check key name — but skip if in safe list
                if isinstance(key, str) and _is_secret_key(key):
                    raise SnapshotValidationError(
                        f"Snapshot contains a secret-shaped field name: {key!r}",
                        field_path=child_path,
                    )
                # Recurse into value
                self._walk(value, child_path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                self._walk(item, f"{path}[{i}]")
        elif isinstance(obj, str):
            if _is_secret_value(obj):
                raise SnapshotValidationError(
                    f"Snapshot contains a secret-shaped value at {path!r}",
                    field_path=path,
                )
