"""Pure validation helpers for the Engagement Portal."""

from __future__ import annotations

from services.engagement_portal.schemas import PortalAccessDenied, PortalSearchError


def validate_tenant_id(tenant_id: str) -> None:
    """Reject empty/whitespace tenant identifiers."""
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise PortalAccessDenied("tenant_id is required and must be non-empty")


def validate_search_query(query: str) -> None:
    """Reject empty or pathological search queries."""
    if not isinstance(query, str):
        raise PortalSearchError("search query must be a string")
    stripped = query.strip()
    if not stripped:
        raise PortalSearchError("search query must not be empty")
    if len(stripped) > 512:
        raise PortalSearchError("search query exceeds 512 characters")


def validate_limit_offset(limit: int, offset: int) -> None:
    """Reject invalid pagination arguments."""
    if not isinstance(limit, int) or limit < 1 or limit > 500:
        raise PortalSearchError("limit must be an integer in [1, 500]")
    if not isinstance(offset, int) or offset < 0:
        raise PortalSearchError("offset must be a non-negative integer")
