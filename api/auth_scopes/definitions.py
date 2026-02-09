from __future__ import annotations

from typing import Optional, Set

ERR_INVALID = "Invalid or missing API key"
DEFAULT_TTL_SECONDS = 24 * 3600


class AuthResult:
    """Result of API key verification with details for proper status codes."""

    __slots__ = ("valid", "reason", "key_prefix", "tenant_id", "scopes")

    def __init__(
        self,
        valid: bool,
        reason: str = "",
        key_prefix: Optional[str] = None,
        tenant_id: Optional[str] = None,
        scopes: Optional[Set[str]] = None,
    ):
        self.valid = valid
        self.reason = reason
        self.key_prefix = key_prefix
        self.tenant_id = tenant_id
        self.scopes = scopes or set()

    @property
    def is_missing_key(self) -> bool:
        return self.reason == "no_key_provided"

    @property
    def is_invalid_key(self) -> bool:
        return not self.valid and not self.is_missing_key
