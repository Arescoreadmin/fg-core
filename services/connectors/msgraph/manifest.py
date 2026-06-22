"""Connector constants — scope list, version pins, execution bounds.

The AUTHORIZED_SCOPES list is immutable at runtime.  Any deviation causes
UnauthorizedScopeError and connector abort.
"""

from __future__ import annotations

SCHEMA_VERSION: str = "1.0"
CONNECTOR_VERSION: str = "1.0"
SCAN_TYPE: str = "msgraph_v1"

# Immutable authorized scope list — cannot be extended at runtime
AUTHORIZED_SCOPES: tuple[str, ...] = (
    "User.Read.All",
    "Directory.Read.All",
    "Policy.Read.All",
    "Application.Read.All",
    "AuditLog.Read.All",
    "Reports.Read.All",
    "InformationProtectionPolicy.Read",
)

AUTHORIZED_SCOPES_SET: frozenset[str] = frozenset(AUTHORIZED_SCOPES)

# Pagination bounds
MAX_PAGES_PER_ENDPOINT: int = 10
MAX_RECORDS_PER_PAGE: int = 999

# Timeouts
REQUEST_TIMEOUT_SECONDS: int = 30
SCAN_TOTAL_TIMEOUT_SECONDS: int = 900  # 15 minutes

# Retry
MAX_RETRIES: int = 3
RETRY_BACKOFF_BASE_SECONDS: int = 2
RETRY_ON_STATUS: frozenset[int] = frozenset({429, 500, 502, 503, 504})
RETRY_AFTER_MAX_SECONDS: int = 30

GRAPH_BASE_URL: str = "https://graph.microsoft.com/v1.0"
GRAPH_REVOCATION_URL: str = "https://graph.microsoft.com/v1.0/me/revokeSignInSessions"


class UnauthorizedScopeError(Exception):
    """Raised when the token contains scopes not on the authorized list."""


class AcknowledgmentVerificationError(Exception):
    """Raised when the operator acknowledgment HMAC fails verification."""


class TenantIsolationError(Exception):
    """Raised when a Graph response context does not match the authorized tenant."""


class ScanTimeoutError(Exception):
    """Raised when the scan wall-clock limit is exceeded."""
