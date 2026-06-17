"""services/capability_bundles/resolver.py — Tenant capability resolution (P1.2).

Resolves which capabilities a tenant has through bundle and direct assignments.
Results are TTL-cached to avoid per-request DB round trips.

Cache:
    TTL controlled by FG_CAPABILITY_CACHE_TTL_SECONDS (default 60).
    Cache key = tenant_id.
    Explicit invalidation via invalidate_cache(tenant_id).
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

log = logging.getLogger("frostgate.capability_bundles.resolver")

# ---------------------------------------------------------------------------
# TTL cache (dict-based, thread-safe for CPython GIL)
# ---------------------------------------------------------------------------

_CACHE_TTL: int = int(os.getenv("FG_CAPABILITY_CACHE_TTL_SECONDS", "60"))

# { tenant_id: (frozenset[str], expiry_timestamp) }
_cache: dict[str, tuple[frozenset[str], float]] = {}


def invalidate_cache(tenant_id: str) -> None:
    """Remove the cached capability set for *tenant_id*."""
    _cache.pop(tenant_id, None)
    log.debug("capability_cache.invalidated tenant_id=%s", tenant_id)


def _get_cached(tenant_id: str) -> frozenset[str] | None:
    entry = _cache.get(tenant_id)
    if entry is None:
        return None
    caps, expiry = entry
    if time.monotonic() > expiry:
        _cache.pop(tenant_id, None)
        return None
    return caps


def _set_cached(tenant_id: str, caps: frozenset[str]) -> None:
    _cache[tenant_id] = (caps, time.monotonic() + _CACHE_TTL)


# ---------------------------------------------------------------------------
# Resolution queries
# ---------------------------------------------------------------------------

_BUNDLE_CAPS_SQL = text(
    """
    SELECT c.capability_key
    FROM   tenant_bundle_assignments tba
    JOIN   policy_bundle_capabilities pbc ON pbc.bundle_id = tba.bundle_id
    JOIN   capabilities c ON c.id = pbc.capability_id
    JOIN   policy_bundles pb ON pb.id = tba.bundle_id
    WHERE  tba.tenant_id = :tenant_id
      AND  pb.active = 1
      AND  c.active = 1
      AND  (tba.expires_at IS NULL OR tba.expires_at > :now)
    """
)

_DIRECT_CAPS_SQL = text(
    """
    SELECT c.capability_key
    FROM   tenant_capability_assignments tca
    JOIN   capabilities c ON c.id = tca.capability_id
    WHERE  tca.tenant_id = :tenant_id
      AND  c.active = 1
      AND  (tca.expires_at IS NULL OR tca.expires_at > :now)
    """
)


def resolve_tenant_capabilities(db: Session, tenant_id: str) -> frozenset[str]:
    """Return the full set of capability keys for *tenant_id*.

    Sources combined (union):
      1. Capabilities from all active, non-expired bundle assignments.
      2. Direct capability assignments (manual/trial/promotion/marketplace).

    Results are TTL-cached per tenant_id.

    Returns:
        frozenset[str] — always a frozenset, even if empty.
    """
    cached = _get_cached(tenant_id)
    if cached is not None:
        return cached

    # Postgres uses TRUE/FALSE; SQLite uses 1/0.  The ORM layer handles this
    # for model queries but raw SQL needs an explicit param.  We use 1 here —
    # Postgres coerces 1 → true for boolean columns, so this is portable.
    try:
        now_iso = _utcnow_iso()

        bundle_rows: list[Any] = db.execute(
            _BUNDLE_CAPS_SQL, {"tenant_id": tenant_id, "now": now_iso}
        ).fetchall()

        direct_rows: list[Any] = db.execute(
            _DIRECT_CAPS_SQL, {"tenant_id": tenant_id, "now": now_iso}
        ).fetchall()

        caps: frozenset[str] = frozenset(
            {row[0] for row in bundle_rows} | {row[0] for row in direct_rows}
        )
    except Exception:
        log.exception("capability_resolver.db_error tenant_id=%s", tenant_id)
        return frozenset()

    _set_cached(tenant_id, caps)
    log.debug(
        "capability_resolver.resolved tenant_id=%s count=%d", tenant_id, len(caps)
    )
    return caps


def _utcnow_iso() -> str:
    """Return current UTC time as an ISO-8601 string (portable across DB dialects)."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()
