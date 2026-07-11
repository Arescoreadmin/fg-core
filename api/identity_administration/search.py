"""api/identity_administration/search.py — Identity search service."""

from __future__ import annotations

from api.identity_administration.models import IdentityRecord
from api.identity_administration.repositories.base import IdentityRepository


class SearchService:
    """Search service for identities within a tenant."""

    def __init__(self, identity_repo: IdentityRepository) -> None:
        self._repo = identity_repo

    def search_users(
        self,
        tenant_id: str,
        *,
        query: str = "",
        lifecycle_states: list[str] | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[IdentityRecord], int]:
        """Search users by name/email/state. Returns (results, total_count)."""
        results = self._repo.search(
            tenant_id=tenant_id,
            query=query,
            lifecycle_states=lifecycle_states or [],
            limit=limit,
            offset=offset,
        )
        return results, len(results)  # total_count from repo in real impl


__all__ = ["SearchService"]
